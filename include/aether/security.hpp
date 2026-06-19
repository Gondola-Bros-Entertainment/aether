// aether - packet integrity, rate limiting, and connect tokens. CRC32C (Castagnoli) detects
// corruption; the rate limiter throttles connection requests per source; connect tokens
// authenticate clients with replay defense. The CRC table is built at compile time (software);
// a SIMD path is a later speed concern.
#pragma once

#include "aether/types.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace aether {

inline constexpr int crc32Size = 4;

namespace detail {
inline constexpr std::array<std::uint32_t, 256> makeCrc32cTable() noexcept {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0x82F63B78u & (~(c & 1u) + 1u));   // reflected Castagnoli poly
        t[i] = c;
    }
    return t;
}
inline constexpr std::array<std::uint32_t, 256> crc32cTable = makeCrc32cTable();
} // namespace detail

// CRC32C (Castagnoli). Check value: crc32c("123456789") == 0xE3069283.
inline std::uint32_t crc32c(const std::uint8_t* data, std::size_t len) noexcept {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) crc = detail::crc32cTable[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// Append the little-endian CRC32C of `data` to it.
inline Bytes appendCrc32(const Bytes& data) {
    const std::uint32_t crc = crc32c(data.data(), data.size());
    Bytes out = data;
    out.push_back(static_cast<std::uint8_t>(crc));
    out.push_back(static_cast<std::uint8_t>(crc >> 8));
    out.push_back(static_cast<std::uint8_t>(crc >> 16));
    out.push_back(static_cast<std::uint8_t>(crc >> 24));
    return out;
}

// Verify and strip a trailing CRC32C; nullopt if too short or corrupt.
inline std::optional<Bytes> validateAndStripCrc32(const Bytes& data) {
    if (data.size() < static_cast<std::size_t>(crc32Size)) return std::nullopt;
    const std::size_t   payloadLen = data.size() - crc32Size;
    const std::uint32_t expected   = static_cast<std::uint32_t>(data[payloadLen]) |
                                     (static_cast<std::uint32_t>(data[payloadLen + 1]) << 8) |
                                     (static_cast<std::uint32_t>(data[payloadLen + 2]) << 16) |
                                     (static_cast<std::uint32_t>(data[payloadLen + 3]) << 24);
    if (crc32c(data.data(), payloadLen) != expected) return std::nullopt;
    return Bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(payloadLen));
}

// --- rate limiter (per-source connection-request throttle, self-cleaning) ---
inline constexpr double cleanupIntervalMs = 5000.0;

struct RateLimiter {
    std::map<std::uint64_t, std::vector<MonoTime>> requests;
    int      maxRequestsPerSecond = 0;
    double   windowMs             = 1000.0;
    MonoTime lastCleanup{};
};

inline RateLimiter newRateLimiter(int maxReqs, MonoTime now) {
    RateLimiter rl;
    rl.maxRequestsPerSecond = maxReqs;
    rl.lastCleanup          = now;
    return rl;
}

inline void maybeCleanup(RateLimiter& rl, MonoTime now) {
    if (elapsedMs(rl.lastCleanup, now) < cleanupIntervalMs) return;
    const double window = rl.windowMs;
    for (auto it = rl.requests.begin(); it != rl.requests.end();) {
        std::vector<MonoTime>& v = it->second;
        v.erase(std::remove_if(v.begin(), v.end(), [&](MonoTime t) { return !(elapsedMs(t, now) < window); }), v.end());
        if (v.empty()) it = rl.requests.erase(it);
        else           ++it;
    }
    rl.lastCleanup = now;
}

// Allow a request if fewer than the cap occurred within the window; records it either way.
inline bool rateLimiterAllow(RateLimiter& rl, std::uint64_t addrKey, MonoTime now) {
    maybeCleanup(rl, now);
    const double          window = rl.windowMs;
    std::vector<MonoTime> recent;
    if (const auto it = rl.requests.find(addrKey); it != rl.requests.end())
        for (const MonoTime t : it->second)
            if (elapsedMs(t, now) < window) recent.push_back(t);

    if (static_cast<int>(recent.size()) >= rl.maxRequestsPerSecond) {
        rl.requests[addrKey] = std::move(recent);
        return false;
    }
    recent.push_back(now);
    rl.requests[addrKey] = std::move(recent);
    return true;
}

// --- connect tokens ---
struct ConnectToken {
    std::uint64_t clientId         = 0;
    MonoTime      createTime{};
    double        expireDurationMs = 0.0;
    Bytes         userData;
};

inline ConnectToken newConnectToken(std::uint64_t clientId, double expireMs, const Bytes& userData, MonoTime now) {
    return ConnectToken{ clientId, now, expireMs, userData };
}
inline bool isTokenExpired(MonoTime now, const ConnectToken& t) {
    return elapsedMs(t.createTime, now) > t.expireDurationMs;
}

enum class TokenError { Expired, Replayed, Invalid };

struct TokenValidator {
    std::map<std::pair<std::uint64_t, std::uint64_t>, MonoTime> usedTokens;  // (clientId, createTime.ns) -> usedAt
    double tokenLifetimeMs  = 0.0;
    int    maxTrackedTokens = 0;
};

inline TokenValidator newTokenValidator(double lifetimeMs, int maxTracked) {
    TokenValidator tv;
    tv.tokenLifetimeMs  = lifetimeMs;
    tv.maxTrackedTokens = maxTracked;
    return tv;
}

inline void cleanupExpired(TokenValidator& tv, MonoTime now) {
    for (auto it = tv.usedTokens.begin(); it != tv.usedTokens.end();)
        if (!(elapsedMs(it->second, now) < tv.tokenLifetimeMs)) it = tv.usedTokens.erase(it);
        else                                                    ++it;
}
inline void evictOldest(TokenValidator& tv) {
    if (tv.usedTokens.empty()) return;
    const auto oldest = std::min_element(tv.usedTokens.begin(), tv.usedTokens.end(),
                                         [](const auto& a, const auto& b) { return a.second.ns < b.second.ns; });
    tv.usedTokens.erase(oldest);
}
inline void enforceLimit(TokenValidator& tv, MonoTime now) {
    if (static_cast<int>(tv.usedTokens.size()) <= tv.maxTrackedTokens) return;
    cleanupExpired(tv, now);
    if (static_cast<int>(tv.usedTokens.size()) <= tv.maxTrackedTokens) return;
    evictOldest(tv);
}

struct TokenResult { std::optional<TokenError> error; std::uint64_t clientId = 0; };

// Validate a token: rejects expired or replayed tokens, else records and accepts it.
inline TokenResult validateToken(TokenValidator& tv, const ConnectToken& token, MonoTime now) {
    if (isTokenExpired(now, token))            return { TokenError::Expired, 0 };
    const auto key = std::make_pair(token.clientId, token.createTime.ns);
    if (tv.usedTokens.count(key))              return { TokenError::Replayed, 0 };   // key on (id, createTime): a fresh token reconnect is not a replay
    tv.usedTokens[key] = now;
    enforceLimit(tv, now);
    return { std::nullopt, token.clientId };
}

} // namespace aether
