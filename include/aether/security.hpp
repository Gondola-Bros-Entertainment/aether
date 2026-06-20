// aether - packet integrity, rate limiting, and connect tokens. CRC32C (Castagnoli) detects
// corruption; the rate limiter throttles connection requests per source; connect tokens are
// AEAD-sealed credentials that authenticate a client's identity (with replay defense). The CRC table
// is built at compile time (software); a SIMD path is a later speed concern.
#pragma once

#include "aether/crypto.hpp"
#include "aether/random.hpp"
#include "aether/serialize.hpp"
#include "aether/types.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
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

// --- connect tokens (AEAD-sealed) ---
// A connect token authenticates a client's IDENTITY. Your auth backend -- which holds the secret key
// K, shared with the game servers -- seals one after a login (sealConnectToken); the game server
// opens it with K (validateConnectToken) to learn the verified player id. Sealing is
// ChaCha20-Poly1305, so only a key-holder can mint a token and any tampering is detected. aether
// stays auth-provider-agnostic: the provider only ever touches your backend's seal step.
inline constexpr std::uint32_t connectTokenDomain = 0x544f4b4eu;   // "TOKN": nonce domain for the seal

struct ConnectToken {
    std::uint64_t playerId{};    // your verified player identity (e.g. a Firebase UID)
    MonoTime      expiresAt{};   // absolute expiry; the server rejects the token at/after this
    Bytes         userData;      // opaque app data carried to the server (role, region, ...)
};

// Seal a token under the server key -- call this in your backend, after the player authenticates.
// Output is [nonce:8][ciphertext][tag:16]; the fresh random nonce per token keys replay defense.
inline Bytes sealConnectToken(const EncryptionKey& key, const ConnectToken& t) {
    Bytes pt(16 + t.userData.size());
    putU64(pt.data(),     t.playerId);
    putU64(pt.data() + 8, t.expiresAt.ns);
    if (!t.userData.empty()) std::memcpy(pt.data() + 16, t.userData.data(), t.userData.size());
    return encrypt(key, NonceCounter{ secureRandom64() }, connectTokenDomain, nullptr, 0, pt.data(), pt.size());
}

// A token whose seal + expiry checked out, plus the nonce that identifies it for replay defense.
struct OpenedToken { ConnectToken token; std::uint64_t nonce{}; };

// Verify a sealed token: seal authentic AND not expired. nullopt = forged, corrupt, or expired.
// Replay is the caller's job (validateConnectToken does it).
inline std::optional<OpenedToken> openConnectToken(const EncryptionKey& key, const Bytes& sealed, MonoTime now) {
    const auto dec = decrypt(key, connectTokenDomain, nullptr, 0, sealed.data(), sealed.size());
    if (!dec || dec->plaintext.size() < 16) return std::nullopt;
    const std::uint8_t* p = dec->plaintext.data();
    ConnectToken t;
    t.playerId  = getU64(p);
    t.expiresAt = MonoTime{ getU64(p + 8) };
    t.userData.assign(dec->plaintext.begin() + 16, dec->plaintext.end());
    if (now.ns >= t.expiresAt.ns) return std::nullopt;   // expired
    return OpenedToken{ std::move(t), dec->counter.value };
}

enum class TokenError { Invalid, Replayed };

// Replay tracker: remembers each accepted token's nonce so a captured token cannot be reused.
// Bounded + self-cleaning.
struct TokenValidator {
    std::map<std::uint64_t, MonoTime> usedNonces;   // token nonce -> when first accepted
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
    for (auto it = tv.usedNonces.begin(); it != tv.usedNonces.end();)
        if (!(elapsedMs(it->second, now) < tv.tokenLifetimeMs)) it = tv.usedNonces.erase(it);
        else                                                    ++it;
}
inline void evictOldest(TokenValidator& tv) {
    if (tv.usedNonces.empty()) return;
    const auto oldest = std::min_element(tv.usedNonces.begin(), tv.usedNonces.end(),
                                         [](const auto& a, const auto& b) { return a.second.ns < b.second.ns; });
    tv.usedNonces.erase(oldest);
}
inline void enforceLimit(TokenValidator& tv, MonoTime now) {
    if (static_cast<int>(tv.usedNonces.size()) <= tv.maxTrackedTokens) return;
    cleanupExpired(tv, now);
    if (static_cast<int>(tv.usedNonces.size()) <= tv.maxTrackedTokens) return;
    evictOldest(tv);
}

struct TokenResult { std::optional<TokenError> error; std::uint64_t playerId = 0; Bytes userData; };

// Full server-side check: open + authenticate the sealed token, then reject replays. Records it on
// success and returns the verified player id. This is what the handshake calls.
inline TokenResult validateConnectToken(const EncryptionKey& key, TokenValidator& tv, const Bytes& sealed, MonoTime now) {
    const auto opened = openConnectToken(key, sealed, now);
    if (!opened)                            return { TokenError::Invalid, 0, {} };   // forged / corrupt / expired
    if (tv.usedNonces.count(opened->nonce)) return { TokenError::Replayed, 0, {} };
    tv.usedNonces[opened->nonce] = now;
    enforceLimit(tv, now);
    return { std::nullopt, opened->token.playerId, opened->token.userData };
}

} // namespace aether
