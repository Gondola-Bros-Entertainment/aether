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
inline constexpr double cleanupIntervalMs     = 5000.0;
inline constexpr int    rateLimiterMaxSources = 4096;   // hard cap on tracked sources (spoof-flood memory shield)

struct RateLimiter {
    std::map<std::uint64_t, std::vector<MonoTime>> requests;
    int      maxRequestsPerSecond = 0;
    int      maxTrackedSources    = rateLimiterMaxSources;
    double   windowMs             = 1000.0;
    MonoTime lastCleanup{};
};

inline RateLimiter newRateLimiter(int maxReqs, MonoTime now) {
    RateLimiter rl;
    rl.maxRequestsPerSecond = maxReqs;
    rl.lastCleanup          = now;
    return rl;
}

inline void pruneRateLimiter(RateLimiter& rl, MonoTime now) {
    const double window = rl.windowMs;
    for (auto it = rl.requests.begin(); it != rl.requests.end();) {
        std::vector<MonoTime>& v = it->second;
        v.erase(std::remove_if(v.begin(), v.end(), [&](MonoTime t) { return !(elapsedMs(t, now) < window); }), v.end());
        if (v.empty()) it = rl.requests.erase(it);
        else           ++it;
    }
    rl.lastCleanup = now;
}
inline void maybeCleanup(RateLimiter& rl, MonoTime now) {
    if (elapsedMs(rl.lastCleanup, now) >= cleanupIntervalMs) pruneRateLimiter(rl, now);
}

// Allow a request if fewer than the cap occurred within the window; records it either way. Bounds
// the table at maxTrackedSources so a spoofed-source flood cannot grow it without limit (a memory
// shield distinct from the per-source rate check; the return-routability cookie is the full fix).
inline bool rateLimiterAllow(RateLimiter& rl, std::uint64_t addrKey, MonoTime now) {
    maybeCleanup(rl, now);
    auto it = rl.requests.find(addrKey);
    if (it == rl.requests.end() && static_cast<int>(rl.requests.size()) >= rl.maxTrackedSources) {
        pruneRateLimiter(rl, now);   // at the cap: drop stale sources now, ignoring the 5s interval
        if (static_cast<int>(rl.requests.size()) >= rl.maxTrackedSources) return false;   // still full -> shed
        // addrKey is new, so prune did not create it -- it stays end(), and the filter below is skipped
    }
    const double          window = rl.windowMs;
    std::vector<MonoTime> recent;
    if (it != rl.requests.end())
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
inline constexpr std::size_t connectTokenNonceBytes = 12;   // 96-bit random nonce (IETF ChaCha20-Poly1305 width)
// "TOKN" -- the domain separator, bound as AEAD AAD so a token sealed for this purpose cannot be
// confused with other ciphertext minted under the same key.
inline constexpr std::array<std::uint8_t, 4> connectTokenDomainBytes = { 'T', 'O', 'K', 'N' };
using TokenNonce = std::array<std::uint8_t, connectTokenNonceBytes>;

struct ConnectToken {
    std::uint64_t playerId{};    // your verified player identity (e.g. a Firebase UID)
    MonoTime      expiresAt{};   // absolute expiry; the server rejects the token at/after this
    Bytes         userData;      // opaque app data carried to the server (role, region, ...)
};

// Seal a token under the server key -- call this in your backend, after the player authenticates.
// Output is [nonce:12][ciphertext][tag:16]. The nonce is a 96-bit CSPRNG draw (the IETF
// ChaCha20-Poly1305 width): random-nonce collision stays negligible to ~2^32 tokens per key, and
// the nonce doubles as the token's identity for replay defense.
inline Bytes sealConnectToken(const EncryptionKey& key, const ConnectToken& t) {
    std::uint8_t nonce[connectTokenNonceBytes];
    secureRandomBytes(nonce, sizeof nonce);
    Bytes pt(16 + t.userData.size());
    putU64(pt.data(),     t.playerId);
    putU64(pt.data() + 8, t.expiresAt.ns);
    if (!t.userData.empty()) std::memcpy(pt.data() + 16, t.userData.data(), t.userData.size());
    Bytes        ct(pt.size());
    std::uint8_t tag[16];
    aeadSeal(key.data(), nonce, connectTokenDomainBytes.data(), connectTokenDomainBytes.size(),
             pt.data(), pt.size(), ct.data(), tag);
    Bytes out;
    out.reserve(sizeof nonce + ct.size() + static_cast<std::size_t>(authTagSize));
    out.insert(out.end(), nonce, nonce + sizeof nonce);
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag, tag + authTagSize);
    return out;
}

// A token whose seal + expiry checked out, plus the nonce that identifies it for replay defense.
struct OpenedToken { ConnectToken token; TokenNonce nonce{}; };

// Verify a sealed token: seal authentic AND not expired. nullopt = forged, corrupt, or expired.
// Replay is the caller's job (validateConnectToken does it).
inline std::optional<OpenedToken> openConnectToken(const EncryptionKey& key, const Bytes& sealed, MonoTime now) {
    if (sealed.size() < connectTokenNonceBytes + static_cast<std::size_t>(authTagSize)) return std::nullopt;
    TokenNonce nonce{};
    std::memcpy(nonce.data(), sealed.data(), connectTokenNonceBytes);
    const std::size_t   ctLen = sealed.size() - connectTokenNonceBytes - authTagSize;
    const std::uint8_t* ct    = sealed.data() + connectTokenNonceBytes;
    const std::uint8_t* tag   = sealed.data() + connectTokenNonceBytes + ctLen;
    const auto pt = aeadOpen(key.data(), nonce.data(), connectTokenDomainBytes.data(),
                             connectTokenDomainBytes.size(), ct, ctLen, tag);
    if (!pt || pt->size() < 16) return std::nullopt;
    const std::uint8_t* p = pt->data();
    ConnectToken t;
    t.playerId  = getU64(p);
    t.expiresAt = MonoTime{ getU64(p + 8) };
    t.userData.assign(pt->begin() + 16, pt->end());
    if (now.ns >= t.expiresAt.ns) return std::nullopt;   // expired
    return OpenedToken{ std::move(t), nonce };
}

enum class TokenError { Invalid, Replayed };

// Replay tracker: remembers each accepted token's nonce so a captured token cannot be reused.
// Bounded + self-cleaning. tokenLifetimeMs should be >= the longest token validity window you mint
// (expiresAt - issuedAt): a nonce is forgotten this long after first use, so a shorter lifetime
// would let a still-valid token replay once its nonce ages out.
struct TokenValidator {
    std::map<TokenNonce, MonoTime> usedNonces;   // token nonce -> when first accepted
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
