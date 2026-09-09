// aether - packet integrity, rate limiting, and connect tokens. CRC32C (Castagnoli) detects
// corruption; the rate limiter throttles connection requests per source; connect tokens are
// AEAD-sealed credentials that authenticate a client's identity (with replay defense). The CRC table
// is built at compile time (software).
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
#include <stdexcept>
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

// Verify a trailing CRC32C over data[0,len); return the payload length (len - crc32Size) on success,
// nullopt if too short or corrupt. Alloc-free: the caller keeps its buffer and treats [0, returned)
// as the payload -- the recv-path form of validateAndStripCrc32.
inline std::optional<std::size_t> crc32StrippedLen(const std::uint8_t* data, std::size_t len) noexcept {
    if (len < static_cast<std::size_t>(crc32Size)) return std::nullopt;
    const std::size_t   payloadLen = len - crc32Size;
    const std::uint32_t expected   = static_cast<std::uint32_t>(data[payloadLen]) |
                                     (static_cast<std::uint32_t>(data[payloadLen + 1]) << 8) |
                                     (static_cast<std::uint32_t>(data[payloadLen + 2]) << 16) |
                                     (static_cast<std::uint32_t>(data[payloadLen + 3]) << 24);
    return crc32c(data, payloadLen) == expected ? std::optional<std::size_t>(payloadLen) : std::nullopt;
}

// Verify and strip a trailing CRC32C; nullopt if too short or corrupt. The owning form of crc32StrippedLen.
inline std::optional<Bytes> validateAndStripCrc32(const Bytes& data) {
    const auto payloadLen = crc32StrippedLen(data.data(), data.size());
    if (!payloadLen) return std::nullopt;
    return Bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(*payloadLen));
}

// --- rate limiter (per-source connection-request throttle, self-cleaning) ---
inline constexpr double cleanupIntervalMs     = 5000.0;
// Minimum gap between the extra prunes taken when the table is AT capacity. Short enough to reclaim
// space promptly under a flood, long enough that the prune cannot run once per arriving packet.
inline constexpr double capacityPruneIntervalMs = 100.0;
inline constexpr int    rateLimiterMaxSources = 4096;   // hard cap on tracked sources (spoof-flood memory shield)
// How many tracked sources one eviction looks at. A full walk per arriving datagram costs more than
// the flood does, so the search for something to drop is a bounded sample taken from a rotating
// cursor: successive evictions cover the whole table without any single packet paying for it.
inline constexpr int    rateLimiterEvictScan  = 64;

struct RateLimiter {
    std::map<std::uint64_t, std::vector<MonoTime>> requests;
    int           maxRequestsPerSecond = 0;
    int           maxTrackedSources    = rateLimiterMaxSources;
    double        windowMs             = 1000.0;
    MonoTime      lastCleanup{};
    std::uint64_t evictCursor          = 0;   // where the next capacity eviction starts scanning
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

// When a source was last seen. Timestamps are appended in arrival order, so the last one is the most
// recent; a source whose timestamps have all aged out is maximally stale.
inline MonoTime rateLimiterLastSeen(const std::vector<MonoTime>& seen) noexcept {
    return seen.empty() ? MonoTime{ 0 } : seen.back();
}

// Free one slot by dropping the stalest source in a bounded sample. The cursor rotates so the samples
// sweep the table rather than re-examining one arbitrary prefix of it.
inline void evictStalestSource(RateLimiter& rl) {
    if (rl.requests.empty()) return;
    auto it = rl.requests.lower_bound(rl.evictCursor);
    if (it == rl.requests.end()) it = rl.requests.begin();
    auto stalest = it;
    for (int n = 1; n < rateLimiterEvictScan; ++n) {
        if (++it == rl.requests.end()) it = rl.requests.begin();
        if (rateLimiterLastSeen(it->second).ns < rateLimiterLastSeen(stalest->second).ns) stalest = it;
    }
    rl.evictCursor = stalest->first + 1;   // wrapping past the top of the keyspace is fine: lower_bound(0) is begin()
    rl.requests.erase(stalest);
}

// Allow a request if fewer than the cap occurred within the window; records it either way. Bounds
// the table at maxTrackedSources so a spoofed-source flood cannot grow it without limit (a memory
// shield distinct from the per-source rate check; the return-routability cookie is the full fix).
inline bool rateLimiterAllow(RateLimiter& rl, std::uint64_t addrKey, MonoTime now) {
    maybeCleanup(rl, now);
    auto it = rl.requests.find(addrKey);
    if (it == rl.requests.end() && static_cast<int>(rl.requests.size()) >= rl.maxTrackedSources) {
        // At the cap, with this source untracked. Which source gets dropped must not be decided by
        // whoever is flooding: a prune reclaims only entries that fell out of the window, and a flood
        // keeps all of its own inside it, so pruning alone sheds every NEW source for as long as the
        // flood lasts -- and since this gate runs ahead of the retry cookie, a shed source cannot
        // prove routability to earn its way back. So reclaim dead space when it is cheap (the full
        // walk is held to capacityPruneIntervalMs, because paying for one per arriving datagram is
        // more work than the flood costs the attacker), then evict to make room regardless. The cap
        // still holds exactly: one entry out, one in.
        if (elapsedMs(rl.lastCleanup, now) >= capacityPruneIntervalMs) pruneRateLimiter(rl, now);
        if (static_cast<int>(rl.requests.size()) >= rl.maxTrackedSources) evictStalestSource(rl);
        // addrKey is new, so neither step created it -- it stays end(), and the filter below is skipped
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
// Connect tokens seal application-issued claims under a key shared by the issuer and admitting
// servers. The sealed claims contain a per-client PSK and protocol/audience scope.
// Network admission also proves possession through Noise. Account integration belongs to the application.
inline constexpr std::size_t connectTokenNonceBytes = 12;   // 96-bit random nonce (IETF ChaCha20-Poly1305 width)
// "TKN2" -- the versioned domain separator, bound as AEAD AAD so a token sealed for this purpose cannot be
// confused with other ciphertext minted under the same key.
inline constexpr std::array<std::uint8_t, 4> connectTokenDomainBytes = { 'T', 'K', 'N', '2' };
using TokenNonce = std::array<std::uint8_t, connectTokenNonceBytes>;
inline constexpr std::size_t connectTokenClaimsBytes = 60;
inline constexpr std::size_t maxConnectTokenUserData = 256;
inline constexpr std::size_t maxSealedConnectTokenBytes = connectTokenNonceBytes + connectTokenClaimsBytes
    + maxConnectTokenUserData + authTagSize;

struct TokenScope {
    std::uint32_t protocolId = 0;
    std::uint64_t audience = 0; // application-assigned server or admission authority
    friend bool operator==(const TokenScope&, const TokenScope&) = default;
};

struct ConnectToken {
    std::uint64_t playerId{};    // application-issued numeric identity; no account-provider dependency
    UnixTime      expiresAt{};   // shared Unix epoch expiry; distinct from the transport's monotonic clock
    Bytes         userData;      // opaque app data carried to the server (role, region, ...)
    TokenScope    scope{};
    EncryptionKey proofKey{};   // issuer/server only; the client receives its own copy separately
    ~ConnectToken() { detail::secureZero(proofKey.data(), proofKey.size()); }
};

struct ConnectCredential {
    Bytes token;
    EncryptionKey proofKey{};
    TokenScope scope{};
    UnixTime expiresAt{};
    ~ConnectCredential() { detail::secureZero(proofKey.data(), proofKey.size()); }
};

inline bool nonzeroKey(const EncryptionKey& key) noexcept {
    std::uint8_t combined = 0;
    for (const auto byte : key) combined |= byte;
    return combined != 0;
}

// Seal a token under the server key -- call this in your backend, after the player authenticates.
// Output is [nonce:12][ciphertext][tag:16]. The nonce is a 96-bit CSPRNG draw (the IETF
// ChaCha20-Poly1305 width): random-nonce collision stays negligible to ~2^32 tokens per key, and
// the nonce doubles as the token's identity for replay defense.
inline Bytes sealConnectToken(const EncryptionKey& key, const ConnectToken& t) {
    if (t.userData.size() > maxConnectTokenUserData) throw std::invalid_argument("Connect token user data exceeds limit");
    std::uint8_t nonce[connectTokenNonceBytes];
    secureRandomBytes(nonce, sizeof nonce);
    Bytes pt(connectTokenClaimsBytes + t.userData.size());
    putU64(pt.data(),     t.playerId);
    putU64(pt.data() + 8, t.expiresAt.ns);
    for (std::size_t i = 0; i < 4; ++i) pt[16 + i] = static_cast<std::uint8_t>(t.scope.protocolId >> (i * 8));
    putU64(pt.data() + 20, t.scope.audience);
    std::copy(t.proofKey.begin(), t.proofKey.end(), pt.begin() + 28);
    if (!t.userData.empty()) std::memcpy(pt.data() + connectTokenClaimsBytes, t.userData.data(), t.userData.size());
    Bytes        ct(pt.size());
    std::uint8_t tag[16];
    aeadSeal(key.data(), nonce, connectTokenDomainBytes.data(), connectTokenDomainBytes.size(),
             pt.data(), pt.size(), ct.data(), tag);
    detail::secureZero(pt.data(), pt.size());
    Bytes out;
    out.reserve(sizeof nonce + ct.size() + static_cast<std::size_t>(authTagSize));
    out.insert(out.end(), nonce, nonce + sizeof nonce);
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag, tag + authTagSize);
    return out;
}

// Run on the trusted credential issuer. Deliver the complete result over an authenticated,
// confidential channel. Only credential.token goes onto the UDP wire; proofKey never does.
inline ConnectCredential issueConnectCredential(const EncryptionKey& key, ConnectToken claims) {
    if (!nonzeroKey(key) || claims.scope.protocolId == 0 || claims.scope.audience == 0 || claims.expiresAt.ns == 0)
        throw std::invalid_argument("Connect credentials require a nonzero issuer key, protocol, audience and expiry");
    do { secureRandomBytes(claims.proofKey.data(), claims.proofKey.size()); } while (!nonzeroKey(claims.proofKey));
    ConnectCredential credential{sealConnectToken(key, claims), claims.proofKey, claims.scope, claims.expiresAt};
    detail::secureZero(claims.proofKey.data(), claims.proofKey.size());
    return credential;
}

// A token whose seal + expiry checked out, plus the nonce that identifies it for replay defense.
struct OpenedToken { ConnectToken token; TokenNonce nonce{}; };

// Verify a sealed token: seal authentic AND not expired. nullopt = forged, corrupt, or expired.
// Replay is the caller's job (validateConnectToken does it).
inline std::optional<OpenedToken> openConnectToken(const EncryptionKey& key, const Bytes& sealed, UnixTime now) {
    if (sealed.size() < connectTokenNonceBytes + connectTokenClaimsBytes + authTagSize
        || sealed.size() > maxSealedConnectTokenBytes) return std::nullopt;
    TokenNonce nonce{};
    std::memcpy(nonce.data(), sealed.data(), connectTokenNonceBytes);
    const std::size_t   ctLen = sealed.size() - connectTokenNonceBytes - authTagSize;
    const std::uint8_t* ct    = sealed.data() + connectTokenNonceBytes;
    const std::uint8_t* tag   = sealed.data() + connectTokenNonceBytes + ctLen;
    auto pt = aeadOpen(key.data(), nonce.data(), connectTokenDomainBytes.data(),
                             connectTokenDomainBytes.size(), ct, ctLen, tag);
    if (!pt || pt->size() < connectTokenClaimsBytes) return std::nullopt;
    const std::uint8_t* p = pt->data();
    ConnectToken t;
    t.playerId  = getU64(p);
    t.expiresAt = UnixTime{ getU64(p + 8) };
    for (std::size_t i = 0; i < 4; ++i) t.scope.protocolId |= std::uint32_t(p[16 + i]) << (i * 8);
    t.scope.audience = getU64(p + 20);
    std::copy_n(pt->begin() + 28, t.proofKey.size(), t.proofKey.begin());
    t.userData.assign(pt->begin() + connectTokenClaimsBytes, pt->end());
    detail::secureZero(pt->data(), pt->size());
    if (now.ns >= t.expiresAt.ns) return std::nullopt;   // expired
    return OpenedToken{ std::move(t), nonce };
}

enum class TokenError { Invalid, Replayed, ReplayCapacity };

// Keep replay evidence until the token's actual expiry. Capacity exhaustion rejects NEW tokens;
// it never discards a live nonce. This table belongs to one admission authority: persist it across
// restarts, or rotate the sealing key so old tokens cannot authenticate after the table is lost.
struct TokenValidator {
    std::map<TokenNonce, UnixTime> usedNonces; // nonce -> token expiry
    int maxTrackedTokens = 65536;
    UnixTime latestTime{}; // a backward wall-clock correction must not revive expired credentials
};
inline TokenValidator newTokenValidator(int maxTracked) {
    TokenValidator tv;
    tv.maxTrackedTokens = maxTracked;
    return tv;
}
inline UnixTime advanceTokenTime(TokenValidator& tv, UnixTime now) noexcept {
    if (now.ns > tv.latestTime.ns) tv.latestTime = now;
    return tv.latestTime;
}
inline void cleanupExpired(TokenValidator& tv, UnixTime now) {
    now = advanceTokenTime(tv, now);
    for (auto it = tv.usedNonces.begin(); it != tv.usedNonces.end();)
        if (now.ns >= it->second.ns) it = tv.usedNonces.erase(it);
        else ++it;
}
inline bool tokenNonceSpent(const TokenValidator& tv, const TokenNonce& nonce) {
    return tv.usedNonces.count(nonce) != 0;
}
// Spend only once admission is otherwise possible. A rejected admission leaves its token usable.
inline std::optional<TokenError> consumeTokenNonce(TokenValidator& tv, const TokenNonce& nonce,
                                                  UnixTime expiresAt, UnixTime now) {
    now = advanceTokenTime(tv, now);
    if (expiresAt.ns <= now.ns) return TokenError::Invalid;
    if (tokenNonceSpent(tv, nonce)) return TokenError::Replayed;
    if (tv.maxTrackedTokens <= 0) return TokenError::ReplayCapacity;
    if (tv.usedNonces.size() >= static_cast<std::size_t>(tv.maxTrackedTokens)) cleanupExpired(tv, now);
    if (tv.usedNonces.size() >= static_cast<std::size_t>(tv.maxTrackedTokens)) return TokenError::ReplayCapacity;
    tv.usedNonces.emplace(nonce, expiresAt);
    return std::nullopt;
}

struct TokenResult { std::optional<TokenError> error; std::uint64_t playerId = 0; Bytes userData; };

// Low-level claim validation plus spending, for authorities that already verified possession.
// This function alone does not authenticate a network client; use peerConnectWithToken/peerProcess
// for session admission. Explicit expected scope prevents cross-application validation.
inline TokenResult validateConnectToken(const EncryptionKey& key, TokenValidator& tv, const Bytes& sealed, UnixTime now, TokenScope expectedScope) {
    now = advanceTokenTime(tv, now);
    const auto opened = openConnectToken(key, sealed, now);
    if (!opened || expectedScope.protocolId == 0 || expectedScope.audience == 0
        || opened->token.scope != expectedScope) return { TokenError::Invalid, 0, {} };
    if (const auto err = consumeTokenNonce(tv, opened->nonce, opened->token.expiresAt, now)) return { *err, 0, {} };
    return { std::nullopt, opened->token.playerId, opened->token.userData };
}

} // namespace aether
