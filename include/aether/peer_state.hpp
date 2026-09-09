// aether - the unified peer API. A NetPeer can accept and initiate connections (server, client, or
// P2P). The core is pure: peerProcess(now, incoming) advances every connection, runs the
// handshake, encrypts/decrypts, reassembles fragments, handles migration, and returns events
// plus packets to send. The socket IO loop that feeds it lives in net.hpp. Data-first.
#pragma once

#include "aether/congestion.hpp"
#include "aether/connection.hpp"
#include "aether/fragment.hpp"
#include "aether/packet.hpp"
#include "aether/random.hpp"
#include "aether/security.hpp"
#include "aether/serialize.hpp"
#include "aether/socket.hpp"
#include "aether/types.hpp"
#include "aether/x25519.hpp"

#include <array>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace aether {

// --- peer identity (a remote address, usable as an ordered map key) ---
struct PeerId { Address addr{}; };
inline bool operator==(const PeerId& a, const PeerId& b) noexcept { return addrEqual(a.addr, b.addr); }
inline bool operator!=(const PeerId& a, const PeerId& b) noexcept { return !(a == b); }
inline bool operator<(const PeerId& a, const PeerId& b) noexcept {
    if (a.addr.len != b.addr.len) return a.addr.len < b.addr.len;
    return std::memcmp(a.addr.storage.data(), b.addr.storage.data(), std::min<std::size_t>(a.addr.len, addrStorageSize)) < 0;
}
inline PeerId peerIdFromAddr(const Address& a) { return PeerId{ a }; }

enum class ConnectionDirection { Inbound, Outbound };

// --- events emitted by peer processing ---
struct PeerEvent {
    enum Kind { Connected, Disconnected, Message, Migrated, Reconnected };
    Kind                kind      = Connected;
    PeerId              peer{};
    ConnectionDirection direction = ConnectionDirection::Inbound;   // Connected
    DisconnectReason    reason    = DisconnectReason::Requested;     // Disconnected
    ChannelId           channel   = ChannelId{};                     // Message
    Bytes               data{};                                      // Message
    PeerId              other{};                                     // Migrated: new id (peer = old)
    std::uint64_t       playerId = 0;                                // Connected / Reconnected: verified connect-token identity (server side)
    Bytes               userData;                                    // verified application claims (server side)
};
inline PeerEvent evConnected(const PeerId& p, ConnectionDirection d, std::uint64_t playerId = 0) { return { .kind = PeerEvent::Connected, .peer = p, .direction = d, .playerId = playerId }; }
inline PeerEvent evDisconnected(const PeerId& p, DisconnectReason r) { return { .kind = PeerEvent::Disconnected, .peer = p, .reason = r }; }
inline PeerEvent evMessage(const PeerId& p, ChannelId ch, Bytes d)   { return { .kind = PeerEvent::Message, .peer = p, .channel = ch, .data = std::move(d) }; }
inline PeerEvent evMigrated(const PeerId& oldP, const PeerId& newP)  { return { .kind = PeerEvent::Migrated, .peer = oldP, .other = newP }; }
inline PeerEvent evReconnected(const PeerId& p, std::uint64_t playerId = 0) { return { .kind = PeerEvent::Reconnected, .peer = p, .playerId = playerId }; }

struct IncomingPacket { PeerId from; Bytes data; };
struct RawPacket      { PeerId to;   Bytes data; };

struct PendingConnection {
    ConnectionDirection direction = ConnectionDirection::Inbound;
    std::uint64_t       serverSalt = 0;
    std::uint64_t       clientSalt = 0;
    MonoTime            createdAt{};
    int                 retryCount = 0;
    MonoTime            lastRetry{};
    X25519Key                    ephemeralPriv{};         // server: our ephemeral secret, zeroed once the response consumes it
    X25519Key                    ephemeralPub{};          // our ephemeral X25519 public key
    X25519Key                    peerEphemeralPub{};      // client: the challenge key sessionShared was derived from
    std::optional<X25519Key>     sessionShared;           // ECDH shared secret (client side; keyed at Accepted)
    bool                         isReconnect   = false;   // this pending is a token reconnect, not a fresh handshake
    bool                         ephemeralReady = false;  // our keypair exists (server: with the pending; client: at the committed challenge)
    bool                         localInitiated = false;  // this side called peerConnect, whatever role it ended up in
    int                          challengeKeyAttempts = 0;    // client: challenges keyed from; bounded separately from retryCount
    Bytes                        retryCookie;             // client: the stateless cookie to echo (empty until the server issues one)
    int                          cookieHandoffs = 0;      // cookies accepted; bounded separately from retryCount
    std::uint64_t                playerId = 0;            // server: the verified identity from the client's token
    std::optional<AuthHandshake> auth;
    std::optional<ConnectCredential> fallbackCredential;
    MonoTime challengeBudgetAt{};
    MonoTime cookieBudgetAt{};

    ~PendingConnection() {
        detail::secureZero(ephemeralPriv.data(), ephemeralPriv.size());
        if (sessionShared) detail::secureZero(sessionShared->data(), sessionShared->size());
    }
};

// --- pure protocol helpers (salts, deny reasons, payload header, FNV hash) ---
inline constexpr std::size_t saltBytes = 8;      // a salt / session token is a 64-bit value on the wire
inline constexpr double      nsPerMs   = 1.0e6;  // nanoseconds per millisecond (clock-sync timestamps)

inline Bytes encodeSalt(std::uint64_t salt) {
    Bytes b(saltBytes);
    putU64(b.data(), salt);   // little-endian (saltBytes == 8)
    return b;
}
inline std::optional<std::uint64_t> decodeSalt(const Bytes& b) {
    if (b.size() < saltBytes) return std::nullopt;
    return getU64(b.data());
}

// salt + ephemeral public key -- the CHALLENGE payload (8-byte salt + 32-byte key).
inline Bytes encodeSaltAndKey(std::uint64_t salt, const X25519Key& pub) {
    Bytes b = encodeSalt(salt);
    b.insert(b.end(), pub.begin(), pub.end());
    return b;
}
inline std::optional<std::pair<std::uint64_t, X25519Key>> decodeSaltAndKey(const Bytes& b) {
    if (b.size() < saltBytes + static_cast<std::size_t>(x25519KeySize)) return std::nullopt;
    const auto salt = decodeSalt(b);
    if (!salt) return std::nullopt;
    X25519Key pub{};
    for (std::size_t i = 0; i < static_cast<std::size_t>(x25519KeySize); ++i) pub[i] = b[saltBytes + i];
    return std::pair<std::uint64_t, X25519Key>{ *salt, pub };
}

// The RESPONSE payload: the client's salt + ephemeral key, plus the server's challenge salt echoed
// back. The echo is the return-routability proof and the reason the challenge round-trip exists at
// all: serverSalt is a 64-bit CSPRNG draw that only ever travelled to the client's claimed address,
// so a source-spoofing peer that never received the challenge cannot produce it, and cannot make the
// server commit a keypair and a connection slot to an address it has never actually reached.
struct ConnectionResponsePayload {
    std::uint64_t clientSalt{};
    X25519Key     pub{};
    std::uint64_t serverSaltEcho{};
};
inline Bytes encodeConnectionResponse(std::uint64_t clientSalt, const X25519Key& pub, std::uint64_t serverSaltEcho) {
    Bytes b = encodeSaltAndKey(clientSalt, pub);
    const Bytes echo = encodeSalt(serverSaltEcho);
    b.insert(b.end(), echo.begin(), echo.end());
    return b;
}
inline std::optional<ConnectionResponsePayload> decodeConnectionResponse(const Bytes& b) {
    if (b.size() < 2 * saltBytes + static_cast<std::size_t>(x25519KeySize)) return std::nullopt;
    const auto sk = decodeSaltAndKey(b);
    if (!sk) return std::nullopt;
    ConnectionResponsePayload r;
    r.clientSalt     = sk->first;
    r.pub            = sk->second;
    r.serverSaltEcho = getU64(b.data() + saltBytes + x25519KeySize);
    return r;
}
// An ephemeral keypair from the OS CSPRNG, and the X25519 shared secret used as the session key.
inline void genEphemeralKeypair(X25519Key& priv, X25519Key& pub) {
    secureRandomBytes(priv.data(), priv.size());
    x25519Base(pub, priv);
}
// The raw X25519 shared secret (a curve point); fed to the KDF below, never used as a key directly.
//
// RFC 7748 section 6.1's all-zero check IS performed, and nullopt means the handshake dies. All seven
// low-order points produce an all-zero shared secret, so without it a peer could force the master to a
// constant every party can compute -- and since resumeMaster caches that master, the resume MAC key
// derived from it would be globally computable too, letting anyone mint a resume for such a session.
// Cheap (one comparison) against a failure that is total, so this fails closed rather than reasoning
// about whether ephemeral keys make it survivable.
inline std::optional<X25519Key> x25519Shared(const X25519Key& priv, const X25519Key& peerPub) {
    X25519Key shared{};
    x25519(shared, priv, peerPub);
    std::uint8_t acc = 0;
    for (const std::uint8_t b : shared) acc = static_cast<std::uint8_t>(acc | b);   // branch-free: no timing signal
    if (acc == 0) return std::nullopt;
    return shared;
}
// Split one shared secret into two independent directional keys via HChaCha20, domain-separated by
// a direction byte and bound to a per-session salt. Distinct keys per direction mean the two halves
// of the connection never share a (key, nonce). A fresh salt per session separates reconnects from
// the original -- but the salt alone is not what guarantees it, because the salt travels in cleartext
// and can be replayed. Resumption uses a fresh Noise handshake, never this initial-key KDF.
struct DirectionalKeys { EncryptionKey clientToServer{}; EncryptionKey serverToClient{}; };
inline DirectionalKeys deriveDirectionalKeys(const X25519Key& shared, std::uint64_t salt) {
    const auto sub = [&](std::uint8_t dir) {
        std::uint8_t in[16] = {};
        putU64(in, salt);
        in[8] = dir;
        EncryptionKey k{};
        detail::hchacha20(shared.data(), in, k.data());
        return k;
    };
    return { sub(0), sub(1) };
}
// Key a connection: the server sends with s2c and receives c2s; the client mirrors. The shared
// secret is cached (resumeMaster) so a reconnect can re-key from it with a fresh salt.
inline void applySessionKeys(Connection& conn, const X25519Key& shared, std::uint64_t salt, bool isServer) {
    const DirectionalKeys k = deriveDirectionalKeys(shared, salt);
    conn.sendKey      = isServer ? k.serverToClient : k.clientToServer;
    conn.recvKey      = isServer ? k.clientToServer : k.serverToClient;
    conn.resumeMaster = shared;
    conn.authScope = {conn.config.protocolId, 0};
    // Routing uses a separate domain from anonymous directional traffic keys (0/1).
    // Only a public routing identifier is exposed; it reveals no traffic-key bytes. Authentication
    // still requires opening the complete datagram under the selected connection's key.
    std::uint8_t routingInput[16]{};
    putU64(routingInput, salt);
    routingInput[8] = 4;
    EncryptionKey routing{};
    detail::hchacha20(shared.data(), routingInput, routing.data());
    conn.connectionId = getU64(routing.data());
    detail::secureZero(routing.data(), routing.size());
}
// --- stateless retry cookie (return routability before the server allocates anything) ---
//
// The challenge echo stops a spoofed source COMPLETING a handshake, but not from making the server
// hold a half-open slot and an X25519 keypair until it times out. So an uncookied request is answered
// with a cookie the server does not remember, and only a request echoing a valid one reaches the token
// check, the pending table, or the keygen.
//
// The cookie is an AEAD tag over (source address, time epoch) under a per-peer CSPRNG secret: only
// this server could have minted it, it is useless from any other address, and it expires on its own.
// The nonce is a fresh random draw carried NEXT TO the tag rather than derived from the address,
// because the tag is a Poly1305 one-time MAC -- sealing two different addresses under one (key,
// nonce) pair would leak the MAC key and let anyone mint a cookie for any address.
inline constexpr std::uint64_t cookieEpochNs   = 10ull * 1000000000ull;   // accepted in its own epoch or the one before, so a cookie lives 10-20s
inline constexpr std::size_t   retryCookieSize = connectTokenNonceBytes + 16;   // [nonce:12][tag:16]

inline std::uint64_t cookieEpochAt(MonoTime now) noexcept { return now.ns / cookieEpochNs; }

// AAD = the raw source address bytes || the epoch. Binding the address is what makes a cookie
// unusable from anywhere else; binding the epoch is what expires it.
inline std::size_t buildCookieAad(const Address& addr, std::uint64_t epoch, std::uint8_t* out) noexcept {
    const std::size_t n = addr.len <= addrStorageSize ? addr.len : addrStorageSize;
    std::memcpy(out, addr.storage.data(), n);
    putU64(out + n, epoch);
    return n + saltBytes;
}

inline Bytes makeRetryCookie(const EncryptionKey& secret, const Address& addr, MonoTime now) {
    Bytes cookie(retryCookieSize);
    secureRandomBytes(cookie.data(), connectTokenNonceBytes);   // unique per cookie: never reuse a (key, nonce)
    std::uint8_t      aad[addrStorageSize + saltBytes];
    const std::size_t aadLen = buildCookieAad(addr, cookieEpochAt(now), aad);
    aeadSeal(secret.data(), cookie.data(), aad, aadLen, nullptr, 0, nullptr, cookie.data() + connectTokenNonceBytes);
    return cookie;
}

inline bool retryCookieValid(const EncryptionKey& secret, const Address& addr, const Bytes& cookie, MonoTime now) {
    if (cookie.size() != retryCookieSize) return false;
    const std::uint64_t epoch = cookieEpochAt(now);
    for (std::uint64_t back = 0; back < 2; ++back) {   // the previous epoch too, so a cookie does not die at a boundary
        if (back > epoch) break;
        std::uint8_t      aad[addrStorageSize + saltBytes];
        const std::size_t aadLen = buildCookieAad(addr, epoch - back, aad);
        std::uint8_t      tag[16];
        aeadSeal(secret.data(), cookie.data(), aad, aadLen, nullptr, 0, nullptr, tag);
        if (detail::constTimeEq(tag, cookie.data() + connectTokenNonceBytes, 16)) return true;
    }
    return false;
}

// A Retry is the largest reply an address that has proven nothing can draw out of the server, so a
// request must be at least as big as the Retry it earns or the exchange amplifies -- an unpadded
// short request answered by a larger cookie would reflect amplified traffic at whatever address the
// request claimed. QUIC imposes the same constraint with a 1200-byte minimum on an Initial; the
// figure here is sized to what aether actually replies with.
inline constexpr std::size_t retryDatagramBytes        = packetHeaderBytes + retryCookieSize + static_cast<std::size_t>(crc32Size);
inline constexpr std::size_t minConnectionRequestBytes = retryDatagramBytes;
inline constexpr std::size_t minRequestPayloadBytes    = minConnectionRequestBytes - packetHeaderBytes - static_cast<std::size_t>(crc32Size);

// Requests carry an optional retry cookie, then an authenticated envelope (or an
// empty anonymous body). Only the empty body needs padding to pay for a retry.
static_assert(1 + authRequestPrefixBytes + authNoiseMessageBytes >= minRequestPayloadBytes);


inline Bytes encodeConnectionRequest(const Bytes& cookie, const Bytes& body) {
    Bytes b;
    b.reserve(1 + cookie.size() + body.size());
    b.push_back(static_cast<std::uint8_t>(cookie.size()));
    b.insert(b.end(), cookie.begin(), cookie.end());
    b.insert(b.end(), body.begin(), body.end());
    if (b.size() < minRequestPayloadBytes) b.resize(minRequestPayloadBytes, 0);
    return b;
}
// The datagram a request payload arrives in, which is what the anti-amplification minimum is measured
// against: the CRC is validated and stripped before the payload reaches the handshake, so it has to be
// counted back in.
inline std::size_t requestDatagramBytes(const Bytes& payload) noexcept {
    return packetHeaderBytes + payload.size() + static_cast<std::size_t>(crc32Size);
}
// Retry the same Noise attempt; only its outer cookie may change.
inline Bytes pendingRequestBody(const PendingConnection& p) {
    return p.auth ? p.auth->request : Bytes{};
}

struct ConnectionRequestPayload { Bytes cookie; Bytes body; };
inline std::optional<ConnectionRequestPayload> decodeConnectionRequest(const Bytes& p) {
    if (p.empty()) return std::nullopt;
    const std::size_t n = p[0];
    if (n != 0 && n != retryCookieSize) return std::nullopt;   // only the two lengths the encoder ever emits
    if (p.size() < 1 + n) return std::nullopt;
    return ConnectionRequestPayload{ Bytes(p.begin() + 1, p.begin() + 1 + static_cast<std::ptrdiff_t>(n)),
                                     Bytes(p.begin() + 1 + static_cast<std::ptrdiff_t>(n), p.end()) };
}

enum class DenyReason : std::uint8_t { ServerFull = 1, InvalidChallenge = 2, InvalidToken = 3 };
inline Bytes encodeDenyReason(DenyReason r) { return Bytes{ static_cast<std::uint8_t>(r) }; }
inline DenyReason decodeDenyReason(const Bytes& d) { return static_cast<DenyReason>(d.empty() ? 0 : d[0]); }
inline DisconnectReason denyToDisconnectReason(DenyReason r) {
    switch (r) {
        case DenyReason::ServerFull:       return DisconnectReason::ServerFull;
        case DenyReason::InvalidChallenge: return DisconnectReason::ProtocolMismatch;
        case DenyReason::InvalidToken:     return DisconnectReason::ProtocolMismatch;
        default:                           return static_cast<DisconnectReason>(static_cast<std::uint8_t>(r));
    }
}

inline constexpr int minPayloadSize = 3;

inline std::pair<ChannelId, bool> decodePayloadHeader(std::uint8_t b) {   // channelWire* constants live in connection.hpp
    return { static_cast<ChannelId>(b & channelWireChannelMask), (b & channelWireFragmentFlag) != 0 };
}
inline std::optional<std::pair<SequenceNum, ByteSpan>> decodeChannelSeq(ByteSpan b) {
    if (b.size() < 2) return std::nullopt;
    const SequenceNum chSeq{ getU16BE(b.data()) };
    return std::pair<SequenceNum, ByteSpan>{ chSeq, b.subspan(2) };
}

// --- path validation (prove a candidate address can RECEIVE, before anything is committed to it) ---
//
// Decrypting proves the sender holds the session key. It does NOT prove the sender is at the address
// the datagram claims: that address is unverified attacker-controlled data, and a replayed genuine
// packet decrypts perfectly. Moving a connection on decryption alone therefore hands it to anyone who
// captures one packet and races their copy in first.
//
// So send fresh unpredictable bytes to the candidate, ENCRYPTED, and move nothing until they come back
// from it (QUIC's PATH_CHALLENGE). A replayer cannot read the challenge, so it cannot answer. Costs one
// round trip per migration.
inline constexpr std::size_t pathChallengeBytes    = 8;
inline constexpr double      pathValidationTimeoutMs = 3000.0;   // a challenge older than this is abandoned
inline constexpr std::size_t maxPathValidations    = 64;         // bounded like every other attacker-reachable table

struct PendingPathValidation {
    PeerId                                     current{};      // where the connection lives while we validate
    std::array<std::uint8_t, pathChallengeBytes> challenge{};   // CSPRNG, never reused
    std::uint64_t                              token = 0;      // migration candidate token, for the cooldown
    MonoTime                                   sentAt{};
};

// --- peer state ---
inline constexpr double migrationCooldownMs       = 5000.0;
inline constexpr double resumeGraceMs             = 30000.0;   // window a dropped session token can reconnect in

// A recently-dropped session kept briefly for a fast reconnect: when it dropped, plus the key it
// negotiated -- restored on reconnect so a resumed session stays encrypted, not downgraded to plaintext.
// The table is keyed by clientSalt, which comes off the wire, so two live sessions can carry the same
// one; `owner` is what tells them apart, so the second to drop cannot overwrite the first's master and
// leave the real holder's correctly-MAC'd resume being rejected.
struct ResumableSession {
    MonoTime                 at{};
    std::optional<X25519Key> master;     // ECDH shared secret, to re-key a resumed session with a fresh salt
    std::uint64_t            playerId{}; // the connect-token identity the original handshake verified
    PeerId                   owner{};    // the connection this entry was armed from
    bool                     authenticated = false;
    TokenScope               scope{};
    Bytes                    userData;
    ~ResumableSession() { if (master) detail::secureZero(master->data(), master->size()); }
};

inline constexpr int    tokenReplayMaxTracked = 65536;        // cap on tracked token nonces (bounded memory)

struct NetPeer {
    Address                              localAddr{};
    std::map<PeerId, Connection>         connections;
    std::map<PeerId, PendingConnection>  pending;
    NetworkConfig                        config;
    RateLimiter                          rateLimiter{};
    std::map<PeerId, FragmentAssembler>  fragmentAssemblers;
    std::map<std::uint64_t, MonoTime>    migrationCooldowns;
    std::map<std::uint64_t, ResumableSession> resumableTokens; // recently-dropped sessions (clientSalt -> drop time + key)
    std::vector<RawPacket>               sendQueue;
    std::uint64_t                        rateLimitDrops = 0;
    TokenValidator                       tokenValidator{};   // connect-token replay defense (server side)
    std::optional<UnixTime>              tokenTime;          // supplied for this processing call, never inferred from MonoTime
    EncryptionKey                        cookieSecret{};     // per-peer secret behind the stateless retry cookie
    std::uint64_t                        addrHashSeed = 0;   // per-peer seed so rate-limit buckets cannot be targeted
    std::map<PeerId, PendingPathValidation> pathValidations; // candidate address -> outstanding challenge

    NetPeer() = default;
    NetPeer(const NetPeer&) = default;
    NetPeer& operator=(const NetPeer&) = default;
    NetPeer(NetPeer&&) noexcept = default;
    NetPeer& operator=(NetPeer&&) noexcept = default;
    ~NetPeer() {
        detail::secureZero(cookieSecret.data(), cookieSecret.size());
        if (config.tokenKey) detail::secureZero(config.tokenKey->data(), config.tokenKey->size());
    }
};

inline NetPeer newPeerState(const Address& localAddr, const NetworkConfig& config, MonoTime now) {
    NetPeer peer;
    peer.localAddr      = localAddr;
    peer.config         = config;
    peer.rateLimiter    = newRateLimiter(config.rateLimitPerSecond, now);
    peer.tokenValidator = newTokenValidator(tokenReplayMaxTracked);
    secureRandomBytes(peer.cookieSecret.data(), peer.cookieSecret.size());   // CSPRNG: a guessable secret would let anyone forge routability
    peer.addrHashSeed = secureRandom64();   // unpredictable, so bucket collisions cannot be computed
    return peer;
}

// --- internal helpers ---
inline void cleanupPeer(NetPeer& peer, const PeerId& pid)   { peer.fragmentAssemblers.erase(pid); }
inline void removePending(NetPeer& peer, const PeerId& pid) { peer.pending.erase(pid); }
inline bool isPostHandshake(PacketType t) noexcept { return t == PacketType::Payload || t == PacketType::PayloadBatch || t == PacketType::Keepalive || t == PacketType::Disconnect || t == PacketType::TimeSyncPing || t == PacketType::TimeSyncPong || t == PacketType::MtuProbe || t == PacketType::WindowUpdate || t == PacketType::PathChallenge || t == PacketType::PathResponse; }

inline void writeCrc32Trailer(Bytes& datagram) noexcept {
    const std::size_t body = datagram.size() - crc32Size;
    putU32(datagram.data() + body, crc32c(datagram.data(), body));   // little-endian, matching appendCrc32
}

inline Bytes frameCleartextDatagram(const PacketHeader& header, const Bytes& payload) {
    Bytes out(packetHeaderBytes + payload.size() + static_cast<std::size_t>(crc32Size));
    Writer w{ out.data(), packetHeaderBytes, 0, true };
    writeHeader(w, header);
    if (!payload.empty()) std::memcpy(out.data() + packetHeaderBytes, payload.data(), payload.size());
    writeCrc32Trailer(out);
    return out;
}

inline Bytes sealDatagram(const EncryptionKey& key, NonceCounter counter, std::uint32_t protocolId,
                          const PacketHeader& header, const Bytes& payload);

// Handshake and control packets are cleartext by definition (there is no session key yet).
inline void queueControlPacket(NetPeer& peer, PacketType ptype, const Bytes& payload, const PeerId& pid) {
    const PacketHeader header{ ptype, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    peer.sendQueue.push_back(RawPacket{ pid, frameCleartextDatagram(header, payload) });
}


} // namespace aether
