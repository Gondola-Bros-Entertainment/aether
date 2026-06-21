// aether - the unified peer API. A NetPeer can accept and initiate connections (server, client, or
// P2P). The core is pure: peerProcess(now, incoming) advances every connection, runs the
// handshake, encrypts/decrypts, reassembles fragments, handles migration, and returns events
// plus packets to send. The socket IO loop that feeds it lives in net.hpp. Data-first.
#pragma once

#include "aether/connection.hpp"
#include "aether/fragment.hpp"
#include "aether/random.hpp"
#include "aether/security.hpp"
#include "aether/socket.hpp"
#include "aether/x25519.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace aether {

// --- peer identity (a remote address, usable as an ordered map key) ---
struct PeerId { Address addr{}; };
inline bool operator==(const PeerId& a, const PeerId& b) noexcept { return addrEqual(a.addr, b.addr); }
inline bool operator!=(const PeerId& a, const PeerId& b) noexcept { return !(a == b); }
inline bool operator<(const PeerId& a, const PeerId& b) noexcept {
    if (a.addr.len != b.addr.len) return a.addr.len < b.addr.len;
    return std::memcmp(a.addr.storage, b.addr.storage, a.addr.len) < 0;
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
    std::uint64_t       playerId = 0;                                // Connected: verified connect-token identity (server side)
};
inline PeerEvent evConnected(const PeerId& p, ConnectionDirection d, std::uint64_t playerId = 0) { return { .kind = PeerEvent::Connected, .peer = p, .direction = d, .playerId = playerId }; }
inline PeerEvent evDisconnected(const PeerId& p, DisconnectReason r) { return { .kind = PeerEvent::Disconnected, .peer = p, .reason = r }; }
inline PeerEvent evMessage(const PeerId& p, ChannelId ch, Bytes d)   { return { .kind = PeerEvent::Message, .peer = p, .channel = ch, .data = std::move(d) }; }
inline PeerEvent evMigrated(const PeerId& oldP, const PeerId& newP)  { return { .kind = PeerEvent::Migrated, .peer = oldP, .other = newP }; }
inline PeerEvent evReconnected(const PeerId& p)                      { return { .kind = PeerEvent::Reconnected, .peer = p }; }

struct IncomingPacket { PeerId from; Bytes data; };
struct RawPacket      { PeerId to;   Bytes data; };

struct PendingConnection {
    ConnectionDirection direction = ConnectionDirection::Inbound;
    std::uint64_t       serverSalt = 0;
    std::uint64_t       clientSalt = 0;
    MonoTime            createdAt{};
    int                 retryCount = 0;
    MonoTime            lastRetry{};
    X25519Key                    ephemeralPriv{};         // our ephemeral X25519 secret
    X25519Key                    ephemeralPub{};          // our ephemeral X25519 public key
    std::optional<X25519Key>     sessionShared;           // ECDH shared secret (client side; keyed at Accepted)
    std::uint64_t                reconnectSalt = 0;       // fresh per-reconnect salt, mixed into the resumed keys
    std::array<std::uint8_t, 16> resumeMac{};             // proof-of-master MAC on the resume request (retransmit-stable)
    bool                         isReconnect   = false;   // this pending is a token reconnect, not a fresh handshake
    bool                         ephemeralReady = false;  // generate the keypair once (retransmit-stable)
    Bytes                        connectToken;            // client: the sealed token to present (and retransmit)
    std::uint64_t                playerId = 0;            // server: the verified identity from the client's token
};

// --- pure protocol helpers (salts, deny reasons, payload header, FNV hash) ---
inline constexpr std::size_t saltBytes = 8;      // a salt / session token is a 64-bit value on the wire
inline constexpr double      nsPerMs   = 1.0e6;  // nanoseconds per millisecond (clock-sync timestamps)

inline Bytes encodeSalt(std::uint64_t salt) {
    Bytes b(saltBytes);
    for (std::size_t i = 0; i < saltBytes; ++i) b[i] = static_cast<std::uint8_t>(salt >> (8 * i));   // little-endian
    return b;
}
inline std::optional<std::uint64_t> decodeSalt(const Bytes& b) {
    if (b.size() < saltBytes) return std::nullopt;
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < saltBytes; ++i) v |= static_cast<std::uint64_t>(b[i]) << (8 * i);
    return v;
}

// reconnect request payload: the resume token (the original clientSalt) + a fresh salt that re-keys
// the resumed session (so a resume never reuses the original keystream) + a MAC proving possession of
// the session master (so a passive observer of the plaintext token cannot forge a resume; see resumeMac).
inline Bytes encodeResume(std::uint64_t token, std::uint64_t freshSalt, const std::array<std::uint8_t, 16>& mac) {
    Bytes b = encodeSalt(token);
    const Bytes s = encodeSalt(freshSalt);
    b.insert(b.end(), s.begin(), s.end());
    b.insert(b.end(), mac.begin(), mac.end());
    return b;
}
struct ResumeRequest { std::uint64_t token{}; std::uint64_t freshSalt{}; std::array<std::uint8_t, 16> mac{}; };
inline std::optional<ResumeRequest> decodeResume(const Bytes& b) {
    if (b.size() < 2 * saltBytes + 16) return std::nullopt;
    ResumeRequest r;
    for (std::size_t i = 0; i < saltBytes; ++i) r.token     |= static_cast<std::uint64_t>(b[i])             << (8 * i);
    for (std::size_t i = 0; i < saltBytes; ++i) r.freshSalt |= static_cast<std::uint64_t>(b[saltBytes + i]) << (8 * i);
    for (std::size_t i = 0; i < 16; ++i)        r.mac[i]     = b[2 * saltBytes + i];
    return r;
}

// salt + ephemeral public key -- the handshake key-exchange payload (8-byte salt + 32-byte key).
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
// An ephemeral keypair from the OS CSPRNG, and the X25519 shared secret used as the session key.
inline void genEphemeralKeypair(X25519Key& priv, X25519Key& pub) {
    secureRandomBytes(priv.data(), priv.size());
    x25519Base(pub, priv);
}
// The raw X25519 shared secret (a curve point); fed to the KDF below, never used as a key directly.
// We deliberately skip RFC 7748's optional all-zero (low-order point) check: keys are ephemeral and
// single-use, so the contributory-behaviour check buys nothing here (it matters for static keys),
// and HChaCha20 mixes the secret before it ever keys a cipher.
inline X25519Key x25519Shared(const X25519Key& priv, const X25519Key& peerPub) {
    X25519Key shared{};
    x25519(shared, priv, peerPub);
    return shared;
}
// Split one shared secret into two independent directional keys via HChaCha20, domain-separated by
// a direction byte and bound to a per-session salt. Distinct keys per direction mean the two halves
// of the connection never share a (key, nonce); a fresh salt per session (every reconnect included)
// means a resumed session never replays the original session's keystream.
struct DirectionalKeys { EncryptionKey clientToServer{}; EncryptionKey serverToClient{}; };
inline DirectionalKeys deriveDirectionalKeys(const X25519Key& shared, std::uint64_t salt) {
    const auto sub = [&](std::uint8_t dir) {
        std::uint8_t in[16] = {};
        for (int i = 0; i < 8; ++i) in[i] = static_cast<std::uint8_t>(salt >> (8 * i));
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
}
// Resume authenticator. The fast-reconnect token (clientSalt) travels in cleartext during the original
// handshake, so on its own it is a bearer credential a passive observer could replay to burn a victim's
// resume. The MAC binds the request to the ECDH master (which never touches the wire): only a holder of
// the master can mint a valid resume, so a token-only observer cannot. (It does NOT stop replay of a
// captured live resume request -- that needs a challenge round-trip, which would defeat 0-RTT resume;
// the residual lands in the documented unauthenticated-handshake trade-off.) The MAC key is HChaCha20
// over the master with a domain byte distinct from the directional KDF.
inline EncryptionKey deriveResumeKey(const X25519Key& master) {
    std::uint8_t in[16] = {};
    in[8] = 2;   // deriveDirectionalKeys puts the direction (0/1) here; 2 keeps this subkey independent
    EncryptionKey k{};
    detail::hchacha20(master.data(), in, k.data());
    return k;
}
inline std::array<std::uint8_t, 16> resumeMac(const X25519Key& master, std::uint64_t token, std::uint64_t freshSalt) {
    const EncryptionKey k = deriveResumeKey(master);
    std::uint8_t nonce[12] = {};
    for (int i = 0; i < 8; ++i) nonce[i] = static_cast<std::uint8_t>(freshSalt >> (8 * i));   // fresh per resume -> unique (key, nonce)
    std::uint8_t aad[16];
    for (int i = 0; i < 8; ++i) aad[i]     = static_cast<std::uint8_t>(token     >> (8 * i));
    for (int i = 0; i < 8; ++i) aad[8 + i] = static_cast<std::uint8_t>(freshSalt >> (8 * i));
    std::array<std::uint8_t, 16> tag{};
    aeadSeal(k.data(), nonce, aad, sizeof aad, nullptr, 0, nullptr, tag.data());   // empty plaintext: the tag is a MAC over (token, freshSalt)
    return tag;
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
inline std::optional<std::pair<SequenceNum, Bytes>> decodeChannelSeq(const Bytes& b) {
    if (b.size() < 2) return std::nullopt;
    const SequenceNum chSeq{ static_cast<std::uint16_t>((static_cast<std::uint16_t>(b[0]) << 8) | b[1]) };
    return std::pair<SequenceNum, Bytes>{ chSeq, Bytes(b.begin() + 2, b.end()) };
}

inline constexpr std::uint64_t fnvOffsetBasis = 14695981039346656037ull;
inline constexpr std::uint64_t fnvPrime       = 1099511628211ull;
inline std::uint64_t fnvMix(std::uint64_t h, std::uint64_t v) noexcept { return (h ^ v) * fnvPrime; }
// Hash a remote address to a rate-limit key (FNV-1a over the raw address bytes).
inline std::uint64_t sockAddrToKey(const Address& addr) noexcept {
    std::uint64_t h = fnvOffsetBasis;
    for (std::uint32_t i = 0; i < addr.len; ++i) h = fnvMix(h, addr.storage[i]);
    return h;
}

// --- peer state ---
inline constexpr double peerFragmentTimeoutMs     = 5000.0;
inline constexpr int    peerFragmentMaxBufferSize = 1024 * 1024;
inline constexpr double migrationCooldownMs       = 5000.0;
inline constexpr double resumeGraceMs             = 30000.0;   // window a dropped session token can reconnect in

// A recently-dropped session kept briefly for a fast reconnect: when it dropped, plus the key it
// negotiated -- restored on reconnect so a resumed session stays encrypted, not downgraded to plaintext.
struct ResumableSession {
    MonoTime                 at{};
    std::optional<X25519Key> master;   // ECDH shared secret, to re-key a resumed session with a fresh salt
};

inline constexpr double tokenReplayLifetimeMs = 86400000.0;   // remember a used token nonce this long (replay defense)
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
};

inline NetPeer newPeerState(const Address& localAddr, const NetworkConfig& config, MonoTime now) {
    NetPeer peer;
    peer.localAddr      = localAddr;
    peer.config         = config;
    peer.rateLimiter    = newRateLimiter(config.rateLimitPerSecond, now);
    peer.tokenValidator = newTokenValidator(tokenReplayLifetimeMs, tokenReplayMaxTracked);
    return peer;
}

// --- internal helpers ---
inline void cleanupPeer(NetPeer& peer, const PeerId& pid)   { peer.fragmentAssemblers.erase(pid); }
inline void removePending(NetPeer& peer, const PeerId& pid) { peer.pending.erase(pid); }
inline bool isPostHandshake(PacketType t) noexcept { return t == PacketType::Payload || t == PacketType::PayloadBatch || t == PacketType::Keepalive || t == PacketType::Disconnect || t == PacketType::TimeSyncPing || t == PacketType::TimeSyncPong; }

inline void queueControlPacket(NetPeer& peer, PacketType ptype, const Bytes& payload, const PeerId& pid) {
    const PacketHeader header{ ptype, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    peer.sendQueue.push_back(RawPacket{ pid, appendCrc32(serializePacket(Packet{ header, payload })) });
}

// --- handshake handlers ---
inline std::vector<PeerEvent> handleNewConnectionRequest(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    // Cheapest gate first: a per-source rate check, so a flood is shed before paying for the token
    // decrypt and the X25519 keygen below.
    if (!rateLimiterAllow(peer.rateLimiter, sockAddrToKey(pid.addr), now)) { peer.rateLimitDrops += 1; return {}; }
    std::uint64_t playerId = 0;
    if (peer.config.tokenKey) {   // auth on: a valid sealed token gates everything below (incl. keygen) -- the DoS shield
        const auto tr = validateConnectToken(*peer.config.tokenKey, peer.tokenValidator, pkt.payload, now);
        if (tr.error) { queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::InvalidToken), pid); return {}; }
        playerId = tr.playerId;
    }
    if (static_cast<int>(peer.pending.size()) >= peer.config.maxClients) { peer.rateLimitDrops += 1; return {}; }
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::ServerFull), pid);
        return {};
    }
    PendingConnection pend;
    pend.direction  = ConnectionDirection::Inbound;
    pend.playerId   = playerId;
    pend.serverSalt = secureRandom64();   // anti-spoof challenge salt, from the CSPRNG (not the game PRNG)
    pend.createdAt  = now;
    pend.lastRetry  = now;
    genEphemeralKeypair(pend.ephemeralPriv, pend.ephemeralPub);   // server's ephemeral X25519 keypair
    pend.ephemeralReady = true;
    peer.pending[pid] = pend;
    queueControlPacket(peer, PacketType::ConnectionChallenge, encodeSaltAndKey(pend.serverSalt, pend.ephemeralPub), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionRequest(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    if (peer.connections.count(pid)) { queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid); return {}; }
    // reconnect: a request carrying a recently-dropped session token re-establishes that session
    // fast, skipping the challenge -- the token (the original clientSalt) is the credential. The
    // token is a resumption ticket: it also restores the key the session negotiated, so a resume
    // stays encrypted and skips the key exchange too -- true QUIC-style 0-RTT resume.
    if (const auto resume = decodeResume(pkt.payload)) {
        const auto rit = peer.resumableTokens.find(resume->token);
        if (rit != peer.resumableTokens.end() && rit->second.master && elapsedMs(rit->second.at, now) < resumeGraceMs
            && detail::constTimeEq(resumeMac(*rit->second.master, resume->token, resume->freshSalt).data(), resume->mac.data(), 16)) {
            const X25519Key master = *rit->second.master;
            peer.resumableTokens.erase(rit);   // burn only on a MAC-authenticated resume (proof of master possession)
            peer.pending.erase(pid);
            Connection conn = newConnection(peer.config, resume->token, now);
            applySessionKeys(conn, master, resume->freshSalt, /*isServer=*/true);   // re-key from the client's fresh salt
            touchRecvTime(conn, now);
            markConnected(conn, now);
            peer.connections[pid] = std::move(conn);
            queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid);
            return { evReconnected(pid) };
        }
        // No entry / expired / bad MAC falls through to a normal handshake. A bad MAC does NOT burn the
        // resumable, so a token-only observer cannot deny the real client its fast reconnect.
    }
    if (const auto it = peer.pending.find(pid); it != peer.pending.end()) {
        queueControlPacket(peer, PacketType::ConnectionChallenge, encodeSaltAndKey(it->second.serverSalt, it->second.ephemeralPub), pid);
        return {};
    }
    return handleNewConnectionRequest(peer, pid, pkt, now);
}
inline std::vector<PeerEvent> handleConnectionChallenge(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    const auto sk = decodeSaltAndKey(pkt.payload);
    if (!sk) return {};
    it->second.serverSalt = sk->first;
    if (!it->second.ephemeralReady) {   // generate our keypair once + capture the shared secret
        genEphemeralKeypair(it->second.ephemeralPriv, it->second.ephemeralPub);
        it->second.sessionShared  = x25519Shared(it->second.ephemeralPriv, sk->second);
        it->second.ephemeralReady = true;
    }
    queueControlPacket(peer, PacketType::ConnectionResponse, encodeSaltAndKey(it->second.clientSalt, it->second.ephemeralPub), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionResponse(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Inbound) return {};
    const auto sk = decodeSaltAndKey(pkt.payload);
    if (!sk) return {};
    const std::uint64_t clientSalt = sk->first;
    if (clientSalt == 0 || clientSalt == it->second.serverSalt) {
        removePending(peer, pid);
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::InvalidChallenge), pid);
        return {};
    }
    Connection conn = newConnection(peer.config, clientSalt, now);
    conn.playerId = it->second.playerId;   // the identity validated from the client's connect token (0 if auth off)
    const X25519Key shared = x25519Shared(it->second.ephemeralPriv, sk->second);
    applySessionKeys(conn, shared, clientSalt, /*isServer=*/true);   // salt = the client's fresh salt
    touchRecvTime(conn, now);
    markConnected(conn, now);
    const std::uint64_t playerId = conn.playerId;
    peer.connections[pid] = std::move(conn);
    peer.pending.erase(pid);
    queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid);
    return { evConnected(pid, ConnectionDirection::Inbound, playerId) };
}
inline std::vector<PeerEvent> handleConnectionAccepted(NetPeer& peer, const PeerId& pid, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    Connection conn = newConnection(peer.config, it->second.clientSalt, now);
    if (it->second.sessionShared) {
        applySessionKeys(conn, *it->second.sessionShared, it->second.clientSalt, /*isServer=*/false);
    } else if (const auto rit = peer.resumableTokens.find(it->second.clientSalt);
               rit != peer.resumableTokens.end() && rit->second.master) {
        applySessionKeys(conn, *rit->second.master, it->second.reconnectSalt, /*isServer=*/false);   // re-key the resume
        peer.resumableTokens.erase(rit);
    }
    // Fail closed: never bring up an unkeyed connection. This is reachable only when a reconnect
    // races its own resume-grace eviction (the client dropped its cached master before the accept
    // arrived); coming up without keys would be a plaintext/broken zombie. Drop it and surface a
    // disconnect so the caller can re-initiate a fresh (full-handshake) connect.
    if (!conn.sendKey || !conn.recvKey) {
        peer.pending.erase(pid);
        return { evDisconnected(pid, DisconnectReason::Timeout) };
    }
    touchRecvTime(conn, now);
    markConnected(conn, now);
    peer.connections[pid] = std::move(conn);
    peer.pending.erase(pid);
    return { evConnected(pid, ConnectionDirection::Outbound) };
}
inline std::vector<PeerEvent> handleDisconnect(NetPeer& peer, const PeerId& pid, const Packet& pkt) {
    if (peer.connections.count(pid)) {
        peer.connections.erase(pid);
        cleanupPeer(peer, pid);
        const DisconnectReason reason = pkt.payload.empty() ? DisconnectReason::Requested
                                                            : parseDisconnectReason(pkt.payload[0]);
        return { evDisconnected(pid, reason) };
    }
    removePending(peer, pid);
    return {};
}

// --- migration ---
inline std::uint64_t migrationTokenFor(const Connection& conn) noexcept { return conn.clientSalt; }
struct MigrationCandidate { PeerId oldPeer; std::uint64_t token = 0; };
// The keyed connection whose remote sequence is CLOSEST to the incoming packet's -- a hint for
// which connection a packet from a new address might belong to. Picking the closest (not just the
// first in-range match) avoids handing the packet to a different nearby connection. Only a hint:
// the caller proves ownership by decrypting under that connection's key.
inline std::optional<MigrationCandidate> findMigrationCandidate(const NetPeer& peer, const Packet& pkt, MonoTime) {
    const int maxDistance = peer.config.maxSequenceDistance;
    std::optional<MigrationCandidate> best;
    int bestDist = 0;
    for (const auto& [pid, conn] : peer.connections) {
        if (!conn.recvKey) continue;
        const int dist = std::abs(sequenceDiff(pkt.header.sequence, connRemoteSeq(conn)));   // wraparound-aware (RFC 1982), not a linear diff
        if (dist > maxDistance) continue;
        if (!best || dist < bestDist) { best = MigrationCandidate{ pid, migrationTokenFor(conn) }; bestDist = dist; }
    }
    return best;
}

// --- payload / fragment / migration dispatch ---
inline std::vector<PeerEvent> handleFragment(NetPeer& peer, const PeerId& pid, ChannelId channel, const Bytes& fragData, MonoTime now) {
    FragmentAssembler& assembler =
        peer.fragmentAssemblers.try_emplace(pid, newFragmentAssembler(peerFragmentTimeoutMs, peerFragmentMaxBufferSize, peer.config.maxFragments)).first->second;
    const auto complete = processFragment(assembler, fragData.data(), fragData.size(), now);
    if (!complete) return {};
    const auto cs = decodeChannelSeq(*complete);
    if (!cs) return {};
    if (const auto it = peer.connections.find(pid); it != peer.connections.end())
        receiveIncomingPayload(it->second, channel, cs->first, cs->second, now);
    return {};
}
// Route one channel-wire ([channel/fragment byte][seq][data]) into the connection's channels.
inline void receiveChannelWire(NetPeer& peer, const PeerId& pid, Connection& conn, const Bytes& wire, MonoTime now) {
    if (wire.empty()) return;
    const auto [channel, isFragment] = decodePayloadHeader(wire[0]);
    const Bytes rest(wire.begin() + 1, wire.end());
    if (isFragment) { handleFragment(peer, pid, channel, rest, now); return; }
    if (static_cast<int>(wire.size()) < minPayloadSize) return;
    if (const auto cs = decodeChannelSeq(rest))
        receiveIncomingPayload(conn, channel, cs->first, cs->second, now);
}
inline std::vector<PeerEvent> handlePayload(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return {};
    processIncomingHeader(it->second, pkt.header, now);
    touchRecvTime(it->second, now);
    receiveChannelWire(peer, pid, it->second, pkt.payload, now);
    return {};
}
// A coalesced payload: one packet (one sequence) carrying several channel-wires.
inline std::vector<PeerEvent> handlePayloadBatch(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return {};
    processIncomingHeader(it->second, pkt.header, now);
    touchRecvTime(it->second, now);
    if (const auto wires = unbatchMessages(pkt.payload))
        for (const Bytes& wire : *wires) receiveChannelWire(peer, pid, it->second, wire, now);
    return {};
}
inline std::vector<PeerEvent> handleMigration(NetPeer& peer, const PeerId& newPid, const Packet& pkt, MonoTime now) {
    if (!peer.config.enableConnectionMigration) return {};
    const auto cand = findMigrationCandidate(peer, pkt, now);
    if (!cand) return {};
    if (const auto it = peer.migrationCooldowns.find(cand->token);
        it != peer.migrationCooldowns.end() && elapsedMs(it->second, now) < migrationCooldownMs) return {};
    const auto connIt = peer.connections.find(cand->oldPeer);
    if (connIt == peer.connections.end() || !connIt->second.recvKey) return {};

    // Path validation: only a peer that holds the session key may move a connection to a new address.
    // Authenticate by decrypting with the candidate's key (an off-path attacker cannot forge a valid
    // tag); the sequence match above is only a hint for WHICH connection to test, never the proof.
    std::uint8_t hdr[packetHeaderBytes];
    { Writer w{ hdr, sizeof hdr, 0, true }; writeHeader(w, pkt.header); }
    const auto dec = decrypt(*connIt->second.recvKey, peer.config.protocolId, hdr, packetHeaderBytes,
                             pkt.payload.data(), pkt.payload.size());
    if (!dec || !replayAccept(connIt->second.recvReplay, dec->counter.value)) return {};

    Connection migrated = std::move(connIt->second);
    peer.connections.erase(connIt);
    resetTransportMetrics(migrated, now);
    peer.connections[newPid] = std::move(migrated);
    peer.migrationCooldowns[cand->token] = now;
    if (const auto fa = peer.fragmentAssemblers.find(cand->oldPeer); fa != peer.fragmentAssemblers.end()) {
        peer.fragmentAssemblers[newPid] = std::move(fa->second);
        peer.fragmentAssemblers.erase(fa);
    }
    // Process the now-decrypted payload on the migrated connection (handlePayload* expect plaintext).
    const Packet plain{ pkt.header, dec->plaintext };
    std::vector<PeerEvent> events{ evMigrated(cand->oldPeer, newPid) };
    auto more = (pkt.header.type == PacketType::PayloadBatch)
                  ? handlePayloadBatch(peer, newPid, plain, now)
                  : handlePayload(peer, newPid, plain, now);
    for (auto& e : more) events.push_back(std::move(e));
    return events;
}

// clock sync: echo a peer's ping back with our timestamp; feed their pong into our offset estimate.
inline std::vector<PeerEvent> handleTimeSyncPing(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end() || pkt.payload.size() < 8) return {};
    processIncomingHeader(it->second, pkt.header, now);
    touchRecvTime(it->second, now);
    sendTimeSyncPong(it->second, getU64(pkt.payload.data()), now);
    return {};
}
inline std::vector<PeerEvent> handleTimeSyncPong(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end() || pkt.payload.size() < 16) return {};
    processIncomingHeader(it->second, pkt.header, now);
    touchRecvTime(it->second, now);
    const double t0ms = static_cast<double>(getU64(pkt.payload.data()))     / nsPerMs;   // our send (echoed)
    const double t1ms = static_cast<double>(getU64(pkt.payload.data() + 8)) / nsPerMs;   // peer's time
    const double t2ms = static_cast<double>(now.ns) / nsPerMs;                           // our recv
    clockSyncObserve(it->second.clockSync, t0ms, t1ms, t2ms);
    return {};
}
inline std::vector<PeerEvent> handlePacketByType(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now, PacketType ptype) {
    switch (ptype) {
        case PacketType::ConnectionRequest:   return handleConnectionRequest(peer, pid, pkt, now);
        case PacketType::ConnectionChallenge: return handleConnectionChallenge(peer, pid, pkt, now);
        case PacketType::ConnectionResponse:  return handleConnectionResponse(peer, pid, pkt, now);
        case PacketType::ConnectionAccepted:  return handleConnectionAccepted(peer, pid, now);
        case PacketType::ConnectionDenied: {
            const auto pend = peer.pending.find(pid);   // only a connect WE initiated can be denied -- ignore a stray/spoofed deny
            if (pend == peer.pending.end() || pend->second.direction != ConnectionDirection::Outbound) return {};
            removePending(peer, pid);
            return { evDisconnected(pid, denyToDisconnectReason(decodeDenyReason(pkt.payload))) };
        }
        case PacketType::Disconnect:          return handleDisconnect(peer, pid, pkt);
        case PacketType::Payload:
            return peer.connections.count(pid) ? handlePayload(peer, pid, pkt, now) : handleMigration(peer, pid, pkt, now);
        case PacketType::PayloadBatch:
            return peer.connections.count(pid) ? handlePayloadBatch(peer, pid, pkt, now) : handleMigration(peer, pid, pkt, now);
        case PacketType::TimeSyncPing: return handleTimeSyncPing(peer, pid, pkt, now);
        case PacketType::TimeSyncPong: return handleTimeSyncPong(peer, pid, pkt, now);
        case PacketType::Keepalive:
            if (const auto it = peer.connections.find(pid); it != peer.connections.end()) {
                processIncomingHeader(it->second, pkt.header, now);
                touchRecvTime(it->second, now);
            }
            return {};
    }
    return {};
}

// --- incoming packet handling (decrypt + anti-replay for post-handshake) ---
inline std::vector<PeerEvent> handlePacket(NetPeer& peer, const PeerId& pid, const Bytes& dat, MonoTime now) {
    const auto parsed = deserializePacket(dat);
    if (!parsed) return {};
    Packet           pkt   = *parsed;
    const PacketType ptype = pkt.header.type;
    const int        bytes = static_cast<int>(dat.size());

    const auto connIt = peer.connections.find(pid);
    const bool keyed  = connIt != peer.connections.end() && connIt->second.recvKey.has_value();

    if (isPostHandshake(ptype) && keyed) {
        Connection& conn = connIt->second;
        recordBytesReceived(conn, bytes, now);
        const auto dec = decrypt(*conn.recvKey, peer.config.protocolId,
                                 dat.data(), packetHeaderBytes,   // the cleartext header, authenticated as AAD
                                 pkt.payload.data(), pkt.payload.size());
        if (!dec) { conn.stats.decryptionFailures += 1; return {}; }
        if (!replayAccept(conn.recvReplay, dec->counter.value)) return {};   // replayed or outside the window
        pkt.payload = dec->plaintext;
        return handlePacketByType(peer, pid, pkt, now, ptype);
    }
    if (connIt != peer.connections.end()) recordBytesReceived(connIt->second, bytes, now);
    return handlePacketByType(peer, pid, pkt, now, ptype);
}

// --- outgoing: encrypt post-handshake payloads, append CRC ---
inline std::vector<RawPacket> encryptOutgoing(NetPeer& peer, const PeerId& pid, Connection& conn, const std::vector<OutgoingPacket>& packets) {
    std::vector<RawPacket> out;
    out.reserve(packets.size());
    for (const OutgoingPacket& op : packets) {
        PacketHeader header = op.header;
        header.type = op.type;
        const Bytes serialized = serializePacket(Packet{ header, op.payload });
        if (conn.sendKey && isPostHandshake(op.type)) {
            const NonceCounter nonce = conn.sendNonce;
            Bytes combined(serialized.begin(), serialized.begin() + static_cast<std::ptrdiff_t>(packetHeaderBytes));
            const Bytes enc = encrypt(*conn.sendKey, nonce, peer.config.protocolId,
                                      serialized.data(), packetHeaderBytes,   // the cleartext header, authenticated as AAD
                                      serialized.data() + packetHeaderBytes, serialized.size() - packetHeaderBytes);
            combined.insert(combined.end(), enc.begin(), enc.end());
            out.push_back(RawPacket{ pid, appendCrc32(combined) });
            conn.sendNonce = NonceCounter{ nonce.value + 1 };
        } else {
            out.push_back(RawPacket{ pid, appendCrc32(serialized) });
        }
    }
    return out;
}
inline void drainAllConnectionQueues(NetPeer& peer, MonoTime now) {
    for (auto& [pid, conn] : peer.connections) {
        const std::vector<OutgoingPacket> connPackets = drainSendQueue(conn);
        std::vector<RawPacket>            raws        = encryptOutgoing(peer, pid, conn, connPackets);
        int bytesSent = 0;
        for (const RawPacket& r : raws) bytesSent += static_cast<int>(r.data.size());
        if (bytesSent > 0) recordBytesSent(conn, bytesSent, now);   // zero would reset the keepalive timer
        for (RawPacket& r : raws) peer.sendQueue.push_back(std::move(r));
    }
}

// --- per-tick connection update + pending maintenance ---
inline std::vector<PeerEvent> updateConnections(NetPeer& peer, MonoTime now) {
    std::vector<PeerEvent> events;
    std::vector<PeerId>    disconnected;
    for (auto& [pid, conn] : peer.connections) {
        if (updateTick(conn, now)) {
            peer.resumableTokens[conn.clientSalt] = { now, conn.resumeMaster };   // token + shared secret, to re-key a reconnect
            events.push_back(evDisconnected(pid, DisconnectReason::Timeout));
            disconnected.push_back(pid);
        } else if (connectionState(conn) == ConnectionState::Disconnected) {
            events.push_back(evDisconnected(pid, DisconnectReason::Requested));
            disconnected.push_back(pid);
        } else {
            const std::uint8_t numCh = channelCount(conn);
            for (std::uint8_t ch = 0; ch < numCh; ++ch)
                for (Bytes& m : receiveMessage(conn, static_cast<ChannelId>(ch)))
                    events.push_back(evMessage(pid, static_cast<ChannelId>(ch), std::move(m)));
        }
    }
    for (const PeerId& pid : disconnected) { peer.connections.erase(pid); cleanupPeer(peer, pid); }
    for (auto it = peer.migrationCooldowns.begin(); it != peer.migrationCooldowns.end();)
        if (!(elapsedMs(it->second, now) < migrationCooldownMs)) it = peer.migrationCooldowns.erase(it);
        else                                                     ++it;
    for (auto it = peer.resumableTokens.begin(); it != peer.resumableTokens.end();)
        if (elapsedMs(it->second.at, now) >= resumeGraceMs) it = peer.resumableTokens.erase(it);
        else                                             ++it;
    return events;
}
inline void retryPendingConnections(NetPeer& peer, MonoTime now) {
    const NetworkConfig& cfg           = peer.config;
    const double         retryInterval = cfg.connectionRequestTimeoutMs / static_cast<double>(cfg.connectionRequestMaxRetries + 1);
    for (auto& [pid, pending] : peer.pending) {
        if (pending.direction != ConnectionDirection::Outbound) continue;
        if (elapsedMs(pending.lastRetry, now) > retryInterval && pending.retryCount < cfg.connectionRequestMaxRetries) {
            pending.retryCount += 1;
            pending.lastRetry   = now;
            const Bytes payload = pending.isReconnect ? encodeResume(pending.clientSalt, pending.reconnectSalt, pending.resumeMac) : pending.connectToken;
            queueControlPacket(peer, PacketType::ConnectionRequest, payload, pid);
        }
    }
}
inline std::vector<PeerEvent> cleanupPending(NetPeer& peer, MonoTime now) {
    const double           timeout = peer.config.connectionRequestTimeoutMs;
    std::vector<PeerEvent> events;
    for (auto it = peer.pending.begin(); it != peer.pending.end();) {
        if (elapsedMs(it->second.createdAt, now) > timeout) {
            events.push_back(evDisconnected(it->first, DisconnectReason::Timeout));
            it = peer.pending.erase(it);
        } else {
            ++it;
        }
    }
    return events;
}

// --- the pure game-loop core ---
struct PeerProcessResult { std::vector<PeerEvent> events; std::vector<RawPacket> outgoing; };

inline PeerProcessResult peerProcess(NetPeer& peer, MonoTime now, const std::vector<IncomingPacket>& packets) {
    std::vector<PeerEvent> events;
    for (const IncomingPacket& ip : packets)
        for (auto& e : handlePacket(peer, ip.from, ip.data, now)) events.push_back(std::move(e));
    for (auto& e : updateConnections(peer, now)) events.push_back(std::move(e));
    drainAllConnectionQueues(peer, now);
    retryPendingConnections(peer, now);
    for (auto& e : cleanupPending(peer, now)) events.push_back(std::move(e));

    std::vector<RawPacket> outgoing = std::move(peer.sendQueue);
    peer.sendQueue.clear();
    return { std::move(events), std::move(outgoing) };
}

// --- connection management + sending ---
inline void peerConnect(NetPeer& peer, const PeerId& pid, MonoTime now) {
    if (peer.connections.count(pid) || peer.pending.count(pid)) return;
    PendingConnection pend;
    pend.direction  = ConnectionDirection::Outbound;
    pend.clientSalt = secureRandom64();   // the session token / resume credential, from the CSPRNG
    pend.createdAt  = now;
    pend.lastRetry  = now;
    peer.pending[pid] = pend;
    queueControlPacket(peer, PacketType::ConnectionRequest, {}, pid);
}
// Connect presenting a sealed connect token (minted by your auth backend). The server validates it
// before doing any work; the verified playerId arrives on the server-side Connected event.
inline void peerConnectWithToken(NetPeer& peer, const PeerId& pid, const Bytes& token, MonoTime now) {
    if (peer.connections.count(pid) || peer.pending.count(pid)) return;
    PendingConnection pend;
    pend.direction    = ConnectionDirection::Outbound;
    pend.clientSalt   = secureRandom64();
    pend.connectToken = token;
    pend.createdAt    = now;
    pend.lastRetry    = now;
    peer.pending[pid] = pend;
    queueControlPacket(peer, PacketType::ConnectionRequest, token, pid);
}
// Reconnect a dropped session: present the token (captured while connected via peerSessionToken).
// The server fast-paths it if still within the resume grace window; otherwise it is a normal connect.
inline void peerReconnect(NetPeer& peer, const PeerId& pid, std::uint64_t token, MonoTime now) {
    if (peer.connections.count(pid) || peer.pending.count(pid)) return;
    const auto rit = peer.resumableTokens.find(token);
    if (rit == peer.resumableTokens.end() || !rit->second.master) { peerConnect(peer, pid, now); return; }   // session secret gone -> full handshake
    const std::uint64_t freshSalt = secureRandom64();   // a fresh salt to re-key the resume (unique, not secret)
    const std::array<std::uint8_t, 16> mac = resumeMac(*rit->second.master, token, freshSalt);   // prove we hold the master
    PendingConnection pend;
    pend.direction     = ConnectionDirection::Outbound;
    pend.clientSalt    = token;
    pend.reconnectSalt = freshSalt;
    pend.resumeMac     = mac;
    pend.isReconnect   = true;
    pend.createdAt     = now;
    pend.lastRetry     = now;
    peer.pending[pid] = pend;
    queueControlPacket(peer, PacketType::ConnectionRequest, encodeResume(token, freshSalt, mac), pid);
}
inline void peerDisconnect(NetPeer& peer, const PeerId& pid, MonoTime now) {
    if (const auto it = peer.connections.find(pid); it != peer.connections.end()) disconnect(it->second, DisconnectReason::Requested, now);
}
// Gracefully shut the whole peer down: move every connection to Disconnecting and drain the
// resulting Disconnect packets, returned for the caller to flush before closing the socket.
// Without this, a process that exits right after disconnect skips the Disconnect, so remote
// peers wait out the full connection timeout instead of dropping promptly.
inline std::vector<RawPacket> peerShutdown(NetPeer& peer, MonoTime now) {
    for (auto& [pid, conn] : peer.connections) { (void)pid; disconnect(conn, DisconnectReason::Requested, now); }
    drainAllConnectionQueues(peer, now);
    std::vector<RawPacket> outgoing = std::move(peer.sendQueue);
    peer.sendQueue.clear();
    return outgoing;
}
inline std::optional<ConnectionError> peerSend(NetPeer& peer, const PeerId& pid, ChannelId channel, const Bytes& dat, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return ConnectionError{ ConnectionError::NotConnected };
    return sendMessage(it->second, channel, dat, now);
}
inline void peerBroadcast(NetPeer& peer, ChannelId channel, const Bytes& dat, const std::optional<PeerId>& except, MonoTime now) {
    for (auto& [pid, conn] : peer.connections) {
        if (except && *except == pid) continue;
        sendMessage(conn, channel, dat, now);   // best-effort: ignore per-peer failures
    }
    drainAllConnectionQueues(peer, now);
}

// --- queries ---
inline int  peerCount(const NetPeer& peer) noexcept { return static_cast<int>(peer.connections.size()); }
inline bool peerIsConnected(const NetPeer& peer, const PeerId& pid) { return peer.connections.count(pid) > 0; }
// The session token (clientSalt) for a live connection. Capture it while connected; pass it to
// peerReconnect after a drop to re-establish fast.
inline std::optional<std::uint64_t> peerSessionToken(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.connections.find(pid);
    return it == peer.connections.end() ? std::nullopt : std::optional<std::uint64_t>(it->second.clientSalt);
}
inline std::optional<NetworkStats> peerStats(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return std::nullopt;
    return connectionStats(it->second);
}
inline const Address& peerLocalAddr(const NetPeer& peer) noexcept { return peer.localAddr; }
inline std::vector<PeerId> peerConnectedIds(const NetPeer& peer) {
    std::vector<PeerId> ids;
    ids.reserve(peer.connections.size());
    for (const auto& kv : peer.connections) ids.push_back(kv.first);
    return ids;
}

} // namespace aether
