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
    std::uint64_t       playerId = 0;                                // Connected / Reconnected: verified connect-token identity (server side)
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
    putU64(b.data(), salt);   // little-endian (saltBytes == 8)
    return b;
}
inline std::optional<std::uint64_t> decodeSalt(const Bytes& b) {
    if (b.size() < saltBytes) return std::nullopt;
    return getU64(b.data());
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
    r.token     = getU64(b.data());
    r.freshSalt = getU64(b.data() + saltBytes);
    std::memcpy(r.mac.data(), b.data() + 2 * saltBytes, r.mac.size());
    return r;
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
}
// Resume authenticator. The fast-reconnect token (clientSalt) travels in cleartext during the original
// handshake, so on its own it is a bearer credential: anyone who observed it could present it and burn the
// real client's one-shot resume. The MAC binds the request to the ECDH master (which never touches the
// wire): only a holder of the master can mint a valid resume. (It does NOT stop replay of a
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
    putU64(nonce, freshSalt);   // fresh per resume -> unique (key, nonce)
    std::uint8_t aad[16];
    putU64(aad,     token);
    putU64(aad + 8, freshSalt);
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
inline std::optional<std::pair<SequenceNum, ByteSpan>> decodeChannelSeq(ByteSpan b) {
    if (b.size() < 2) return std::nullopt;
    const SequenceNum chSeq{ getU16BE(b.data()) };
    return std::pair<SequenceNum, ByteSpan>{ chSeq, b.subspan(2) };
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
inline constexpr double migrationCooldownMs       = 5000.0;
inline constexpr double resumeGraceMs             = 30000.0;   // window a dropped session token can reconnect in

// A recently-dropped session kept briefly for a fast reconnect: when it dropped, plus the key it
// negotiated -- restored on reconnect so a resumed session stays encrypted, not downgraded to plaintext.
struct ResumableSession {
    MonoTime                 at{};
    std::optional<X25519Key> master;     // ECDH shared secret, to re-key a resumed session with a fresh salt
    std::uint64_t            playerId{}; // the connect-token identity the original handshake verified
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
inline bool isPostHandshake(PacketType t) noexcept { return t == PacketType::Payload || t == PacketType::PayloadBatch || t == PacketType::Keepalive || t == PacketType::Disconnect || t == PacketType::TimeSyncPing || t == PacketType::TimeSyncPong || t == PacketType::MtuProbe; }

inline Bytes frameCleartextDatagram(const PacketHeader& header, const Bytes& payload);

// Handshake and control packets are cleartext by definition (there is no session key yet).
inline void queueControlPacket(NetPeer& peer, PacketType ptype, const Bytes& payload, const PeerId& pid) {
    const PacketHeader header{ ptype, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    peer.sendQueue.push_back(RawPacket{ pid, frameCleartextDatagram(header, payload) });
}

// --- handshake handlers ---
inline std::vector<PeerEvent> handleNewConnectionRequest(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    // The per-source rate gate already ran in handleConnectionRequest (the sole caller); here the order
    // is token-validate -> half-open cap -> client cap -> X25519 keygen, cheapest security check first
    // so a flood without a valid token never reaches the keygen.
    std::uint64_t playerId = 0;
    if (peer.config.tokenKey) {   // auth on: a valid sealed token gates everything below (incl. keygen) -- the DoS shield
        const auto tr = validateConnectToken(*peer.config.tokenKey, peer.tokenValidator, pkt.payload, now);
        if (tr.error) { queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::InvalidToken), pid); return {}; }
        playerId = tr.playerId;
    }
    if (static_cast<int>(peer.pending.size()) >= peer.config.maxPending) { peer.rateLimitDrops += 1; return {}; }   // half-open cap (DoS shield), distinct from the established-connection cap below
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
    // One per-source rate gate covering every reflective reply below (the idempotent Accepted, the
    // resume Accepted, the challenge resend, and a fresh request via handleNewConnectionRequest, its
    // sole caller, which trusts this gate) -- so a spoofed source cannot bounce an amplified stream off
    // the server.
    if (!rateLimiterAllow(peer.rateLimiter, sockAddrToKey(pid.addr), now)) { peer.rateLimitDrops += 1; return {}; }
    if (peer.connections.count(pid)) { queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid); return {}; }
    // reconnect: a request carrying a recently-dropped session token re-establishes that session
    // fast, skipping the challenge -- the token (the original clientSalt) is the credential. The
    // token is a resumption ticket: it also restores the key the session negotiated, so a resume
    // stays encrypted and skips the key exchange too -- true QUIC-style 0-RTT resume.
    if (const auto resume = decodeResume(pkt.payload)) {
        const auto rit = peer.resumableTokens.find(resume->token);
        if (rit != peer.resumableTokens.end() && rit->second.master && elapsedMs(rit->second.at, now) < resumeGraceMs
            && detail::constTimeEq(resumeMac(*rit->second.master, resume->token, resume->freshSalt).data(), resume->mac.data(), 16)) {
            // A resume takes a client slot like any other connection, so it is subject to the same cap.
            // Denied WITHOUT burning the resumable, so the client can resume once a slot frees.
            if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
                queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::ServerFull), pid);
                return {};
            }
            const X25519Key     master   = *rit->second.master;
            // The resume MAC proves possession of the ECDH master, which only the peer that completed
            // the original (token-validated) handshake holds -- so the identity that handshake verified
            // carries over. Without this a resumed session came up anonymous on a token-gated server.
            const std::uint64_t playerId = rit->second.playerId;
            peer.resumableTokens.erase(rit);   // burn only on a MAC-authenticated resume (proof of master possession)
            peer.pending.erase(pid);
            Connection conn = newConnection(peer.config, resume->token, now);
            conn.playerId = playerId;
            applySessionKeys(conn, master, resume->freshSalt, /*isServer=*/true);   // re-key from the client's fresh salt
            touchRecvTime(conn, now);
            markConnected(conn, now);
            peer.connections[pid] = std::move(conn);
            queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid);
            return { evReconnected(pid, playerId) };
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
    queueControlPacket(peer, PacketType::ConnectionResponse,
                       encodeConnectionResponse(it->second.clientSalt, it->second.ephemeralPub, it->second.serverSalt), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionResponse(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Inbound) return {};
    const auto resp = decodeConnectionResponse(pkt.payload);
    if (!resp) return {};
    // Return-routability gate. A wrong echo is DROPPED silently -- no deny, and crucially the pending
    // survives: replying would make the server a reflector, and cancelling the pending would let
    // anyone who can guess an in-progress client's address abort its handshake. The real client's
    // request retry re-drives the same (retransmit-stable) challenge.
    if (resp->serverSaltEcho != it->second.serverSalt) return {};
    const std::uint64_t clientSalt = resp->clientSalt;
    if (clientSalt == 0 || clientSalt == it->second.serverSalt) {
        removePending(peer, pid);
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::InvalidChallenge), pid);
        return {};
    }
    // Re-check the client cap here, not only at the request: several handshakes admitted while there was
    // room can complete in the same tick, and inserting unconditionally would take the connection table
    // past maxClients. maxPending bounds how far it could overshoot, but "bounded overshoot" is still an
    // exceeded limit, so the last arrivals are denied ServerFull instead.
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        removePending(peer, pid);
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::ServerFull), pid);
        return {};
    }
    Connection conn = newConnection(peer.config, clientSalt, now);
    conn.playerId = it->second.playerId;   // the identity validated from the client's connect token (0 if auth off)
    const X25519Key shared = x25519Shared(it->second.ephemeralPriv, resp->pub);
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
// A keyed connection's Disconnect is authenticated + handled inline in handlePacket; by the time a
// Disconnect reaches the cold path the peer is only ever a pending/unknown one (an unauthenticated
// cleartext Disconnect cannot take a real connection down).
inline std::vector<PeerEvent> handleDisconnect(NetPeer& peer, const PeerId& pid) {
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
// Feed one fragment to the reassembler and, if it completed a message, route it. Returns whether the
// packet may be acked: a fragment that is merely still assembling is accepted (it is held in the
// assembler), while a completed message the channel refused is not.
inline bool handleFragment(NetPeer& peer, const PeerId& pid, ChannelId channel, ByteSpan fragData, MonoTime now) {
    FragmentAssembler& assembler =
        peer.fragmentAssemblers
            .try_emplace(pid, newFragmentAssembler(peer.config.fragmentTimeoutMs, peer.config.maxReassemblyBufferSize,
                                                   peer.config.maxFragments))
            .first->second;
    const auto complete = processFragment(assembler, fragData.data(), fragData.size(), now);
    if (!complete) return true;
    const auto cs = decodeChannelSeq(ByteSpan(complete->data(), complete->size()));
    if (!cs) return true;   // malformed inner wire: resending it would not fix it
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return true;
    return receiveIncomingPayload(it->second, channel, cs->first, Bytes(cs->second.begin(), cs->second.end()), now);
}
// Route one channel-wire ([channel/fragment byte][seq][data]) into the connection's channels. Takes a
// span into the decrypted scratch; the single owned copy is materialized here, where a message is handed
// off to persist in the channel buffer -- everything upstream of this point is alloc-free. Returns
// whether the wire was accepted, which decides whether the carrying packet may be acked.
inline bool receiveChannelWire(NetPeer& peer, const PeerId& pid, Connection& conn, ByteSpan wire, MonoTime now) {
    if (wire.empty()) return true;
    const auto [channel, isFragment] = decodePayloadHeader(wire[0]);
    const ByteSpan rest = wire.subspan(1);
    if (isFragment) return handleFragment(peer, pid, channel, rest, now);
    if (wire.size() < static_cast<std::size_t>(minPayloadSize)) return true;   // truncated wire, not a capacity problem
    if (const auto cs = decodeChannelSeq(rest))
        return receiveIncomingPayload(conn, channel, cs->first, Bytes(cs->second.begin(), cs->second.end()), now);
    return true;
}
// Route a decrypted payload (one wire, or a coalesced batch) and report whether ALL of it was accepted.
// A batch is all-or-nothing for acking purposes: if any message was refused the packet goes unacked, the
// sender retransmits every message it carried, and the ones that did land are recognized as duplicates.
inline bool routeDecryptedPayload(NetPeer& peer, const PeerId& pid, Connection& conn, PacketType ptype,
                                  ByteSpan payload, MonoTime now) {
    if (ptype != PacketType::PayloadBatch) return receiveChannelWire(peer, pid, conn, payload, now);
    bool accepted = true;
    forEachBatchWire(payload, [&](ByteSpan w) { accepted = receiveChannelWire(peer, pid, conn, w, now) && accepted; });
    return accepted;
}
inline std::vector<PeerEvent> handleMigration(NetPeer& peer, const PeerId& newPid, const Packet& pkt, MonoTime now) {
    if (!peer.config.enableConnectionMigration) return {};
    // Gate the candidate scan + trial-decrypt behind the per-source rate limiter: an off-path attacker
    // must not be able to force an O(connections) scan + an AEAD-open per spoofed payload, and the
    // maxTrackedSources cap bounds the total even under a spoofed-source flood. A real migrating client
    // needs exactly one accepted attempt (it is keyed by the new address the moment it migrates).
    if (!rateLimiterAllow(peer.rateLimiter, sockAddrToKey(newPid.addr), now)) { peer.rateLimitDrops += 1; return {}; }
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
    // Route the now-decrypted payload on the migrated connection -- same span path as the keyed receive.
    Connection& mconn = peer.connections[newPid];
    processIncomingAcks(mconn, pkt.header, now);
    touchRecvTime(mconn, now);
    const ByteSpan mpayload(dec->plaintext.data(), dec->plaintext.size());
    if (routeDecryptedPayload(peer, newPid, mconn, pkt.header.type, mpayload, now))
        recordReceivedPacket(mconn, pkt.header);   // ack only what the channels took
    return { evMigrated(cand->oldPeer, newPid) };
}

// Cold-path dispatch: control/handshake packets (cleartext) plus post-handshake packets from a peer we
// have no keyed connection for. A keyed connection's post-handshake traffic is decrypted and routed in
// handlePacket and never reaches here -- so Payload/PayloadBatch here is always a migration probe (path-
// validated by decryption inside handleMigration), and TimeSync/Keepalive without a connection are noise.
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
        case PacketType::Disconnect:    return handleDisconnect(peer, pid);
        case PacketType::Payload:
        case PacketType::PayloadBatch:  return handleMigration(peer, pid, pkt, now);
        case PacketType::TimeSyncPing:
        case PacketType::TimeSyncPong:
        case PacketType::Keepalive:
        case PacketType::MtuProbe:      return {};   // only meaningful on a keyed connection -> handled in handlePacket
    }
    return {};
}

// --- incoming packet handling: decrypt + anti-replay + route ---
// The keyed post-handshake path copies nothing: it reads the header in place, decrypts the ciphertext
// into a reused thread-local scratch, and routes the plaintext by span -- the single owned copy is
// materialized only where a message must outlive the packet (the channel buffer). Control/handshake
// packets and migration probes take the owned cold path below.
inline std::vector<PeerEvent> handlePacket(NetPeer& peer, const PeerId& pid, const Bytes& dat, MonoTime now) {
    Reader     r{ dat.data(), dat.size(), 0 };
    const auto header = readHeader(r);   // header only -- no payload copy
    if (!header) return {};
    const PacketType ptype = header->type;
    const int        bytes = static_cast<int>(dat.size());

    const auto connIt = peer.connections.find(pid);
    const bool keyed  = connIt != peer.connections.end() && connIt->second.recvKey.has_value();

    if (isPostHandshake(ptype) && keyed) {
        Connection&         conn   = connIt->second;
        const std::uint8_t* enc    = dat.data() + packetHeaderBytes;   // [counter:8][ciphertext][tag:16]
        const std::size_t   encLen = dat.size() - packetHeaderBytes;   // dat.size() >= packetHeaderBytes (readHeader checked)
        recordBytesReceived(conn, bytes, now);

        static thread_local Bytes scratch;                             // reused -> no per-packet plaintext alloc
        if (scratch.size() < encLen) scratch.resize(encLen);           // grows once; the span below is valid only for this packet
        const auto info = decryptInto(*conn.recvKey, peer.config.protocolId,
                                      dat.data(), packetHeaderBytes,   // the cleartext header, authenticated as AAD
                                      enc, encLen, scratch.data());
        if (!info) { conn.stats.decryptionFailures += 1; return {}; }
        if (!replayAccept(conn.recvReplay, info->counter.value)) return {};   // replayed or outside the window
        const ByteSpan payload(scratch.data(), info->length);

        if (ptype == PacketType::Disconnect) {   // erases conn -- read the reason, then stop touching it
            const DisconnectReason reason = info->length == 0 ? DisconnectReason::Requested : parseDisconnectReason(scratch[0]);
            peer.connections.erase(pid);
            cleanupPeer(peer, pid);
            return { evDisconnected(pid, reason) };
        }
        processIncomingAcks(conn, *header, now);   // the peer's acks always land, whatever we do with the payload
        touchRecvTime(conn, now);
        switch (ptype) {
            case PacketType::Payload:
            case PacketType::PayloadBatch:
                // Ack this packet only if every message it carried was accepted. A refused message stays
                // unacknowledged, so the sender retransmits it instead of believing it was delivered.
                if (!routeDecryptedPayload(peer, pid, conn, ptype, payload, now)) return {};
                break;
            case PacketType::TimeSyncPing:
                if (payload.size() >= 8) sendTimeSyncPong(conn, getU64(payload.data()), now);   // echo our reply stamped with our clock
                break;
            case PacketType::TimeSyncPong:
                if (payload.size() >= 16)                                                       // fold the round-trip into the offset estimate
                    clockSyncObserve(conn.clockSync, static_cast<double>(getU64(payload.data())) / nsPerMs,
                                     static_cast<double>(getU64(payload.data() + 8)) / nsPerMs, static_cast<double>(now.ns) / nsPerMs);
                break;
            default: break;   // Keepalive / MtuProbe: the header processing above is all they need
                              // (a probe's padding means nothing; ACKING it below is the discovery signal)
        }
        recordReceivedPacket(conn, *header);   // fully consumed -> our next header acks it
        return {};
    }

    // cold path: control/handshake (cleartext) + a payload from an unknown source (a migration probe)
    Packet pkt{ *header, Bytes(dat.begin() + static_cast<std::ptrdiff_t>(packetHeaderBytes), dat.end()) };
    if (connIt != peer.connections.end()) recordBytesReceived(connIt->second, bytes, now);
    return handlePacketByType(peer, pid, pkt, now, ptype);
}

// --- outgoing: build the datagram in its final layout, in one allocation ---
// A datagram is [header:9][payload][crc:4] in the clear, or [header:9][counter:8][ciphertext][tag:16][crc:4]
// once keyed. Both are assembled directly into one exactly-sized buffer: the size is known before any
// bytes are written, so the ciphertext is encrypted straight into place and the CRC is computed over the
// finished bytes. (Serializing, slicing off the header, encrypting into a second buffer, appending it, then
// copying the whole thing again to add a CRC cost five allocations and four copies of the payload per
// packet -- on the hot path, for every datagram, while the receive path next door copies nothing.)
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

// The keyed form. The cleartext header is authenticated as AAD (so tampering with it fails the tag), and
// the nonce counter travels in the clear ahead of the ciphertext, exactly as the receive path expects.
inline Bytes sealDatagram(const EncryptionKey& key, NonceCounter counter, std::uint32_t protocolId,
                          const PacketHeader& header, const Bytes& payload) {
    const std::size_t ctOffset = packetHeaderBytes + static_cast<std::size_t>(nonceSize);
    Bytes out(ctOffset + payload.size() + static_cast<std::size_t>(authTagSize) + static_cast<std::size_t>(crc32Size));
    Writer w{ out.data(), packetHeaderBytes, 0, true };
    writeHeader(w, header);

    std::uint8_t nonce[12];
    buildNonce(counter.value, protocolId, nonce);
    std::memcpy(out.data() + packetHeaderBytes, nonce, static_cast<std::size_t>(nonceSize));   // counter, 8 bytes BE
    aeadSeal(key.data(), nonce, out.data(), packetHeaderBytes,                                 // AAD: the header just written
             payload.data(), payload.size(),
             out.data() + ctOffset,                                                            // ciphertext, in place
             out.data() + ctOffset + payload.size());                                          // tag, straight after it
    writeCrc32Trailer(out);
    return out;
}

// --- outgoing: encrypt post-handshake payloads, append CRC ---
inline std::vector<RawPacket> encryptOutgoing(NetPeer& peer, const PeerId& pid, Connection& conn, const std::vector<OutgoingPacket>& packets) {
    std::vector<RawPacket> out;
    out.reserve(packets.size());
    for (const OutgoingPacket& op : packets) {
        PacketHeader header = op.header;
        header.type = op.type;
        if (conn.sendKey && isPostHandshake(op.type)) {
            // Fail closed: never wrap the send counter -- reusing a (key,nonce) pair would be
            // catastrophic for ChaCha20-Poly1305. 2^64 packets on one un-rekeyed session is unreachable
            // (~585,000 years at 1M pkt/s); a session that somehow reached it stops sending and times
            // out rather than reuse a nonce.
            if (conn.sendNonce.value == UINT64_MAX) continue;
            const NonceCounter nonce = conn.sendNonce;
            out.push_back(RawPacket{ pid, sealDatagram(*conn.sendKey, nonce, peer.config.protocolId, header, op.payload) });
            conn.sendNonce = NonceCounter{ nonce.value + 1 };
        } else {
            out.push_back(RawPacket{ pid, frameCleartextDatagram(header, op.payload) });
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
            peer.resumableTokens[conn.clientSalt] = { now, conn.resumeMaster, conn.playerId };   // token + shared secret + identity, to restore on reconnect
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
// Expire half-open handshakes. Only an OUTBOUND pending reports a timeout: we asked to connect and the
// attempt failed, which the caller is waiting to hear about. An inbound pending that never completed is
// a peer that walked away (or never existed -- a spoofed request); surfacing Disconnected for it would
// report a disconnect for a peer that was never connected, once per abandoned handshake.
inline std::vector<PeerEvent> cleanupPending(NetPeer& peer, MonoTime now) {
    const double           timeout = peer.config.connectionRequestTimeoutMs;
    std::vector<PeerEvent> events;
    for (auto it = peer.pending.begin(); it != peer.pending.end();) {
        if (elapsedMs(it->second.createdAt, now) > timeout) {
            if (it->second.direction == ConnectionDirection::Outbound)
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
// Disconnect a peer, telling it why. The reason travels on the wire and arrives as the remote's
// Disconnected event, so a server can distinguish a kick from an ordinary close (default Requested).
inline void peerDisconnect(NetPeer& peer, const PeerId& pid, MonoTime now,
                           DisconnectReason reason = DisconnectReason::Requested) {
    if (const auto it = peer.connections.find(pid); it != peer.connections.end()) disconnect(it->second, reason, now);
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
// Queue a message to every connected peer (except `except`). Like sendMessage this enqueues into each
// peer's channels; the next peerProcess coalesces + encrypts + sends. Best-effort: per-peer failures ignored.
inline void peerBroadcast(NetPeer& peer, ChannelId channel, const Bytes& dat, const std::optional<PeerId>& except, MonoTime now) {
    for (auto& [pid, conn] : peer.connections) {
        if (except && *except == pid) continue;
        sendMessage(conn, channel, dat, now);
    }
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
// The connect-token identity this connection authenticated (0 when auth is off). Survives a fast
// reconnect, so a server can attribute a resumed session without having cached the Connected event.
inline std::optional<std::uint64_t> peerPlayerId(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.connections.find(pid);
    return it == peer.connections.end() ? std::nullopt : std::optional<std::uint64_t>(it->second.playerId);
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
