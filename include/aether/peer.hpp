// aether - the unified peer API. A NetPeer can accept and initiate connections (server, client, or
// P2P). The core is pure: peerProcess(now, incoming) advances every connection, runs the
// handshake, encrypts/decrypts, reassembles fragments, handles migration, and returns events
// plus packets to send. The socket IO loop that feeds it lives in net.hpp. Data-first.
#pragma once

#include "aether/connection.hpp"
#include "aether/fragment.hpp"
#include "aether/security.hpp"
#include "aether/socket.hpp"
#include "aether/util.hpp"

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
    enum Kind { Connected, Disconnected, Message, Migrated };
    Kind                kind      = Connected;
    PeerId              peer{};
    ConnectionDirection direction = ConnectionDirection::Inbound;   // Connected
    DisconnectReason    reason    = DisconnectReason::Requested;     // Disconnected
    ChannelId           channel   = ChannelId{};                     // Message
    Bytes               data;                                        // Message
    PeerId              other{};                                     // Migrated: new id (peer = old)
};
inline PeerEvent evConnected(const PeerId& p, ConnectionDirection d) { PeerEvent e; e.kind = PeerEvent::Connected; e.peer = p; e.direction = d; return e; }
inline PeerEvent evDisconnected(const PeerId& p, DisconnectReason r) { PeerEvent e; e.kind = PeerEvent::Disconnected; e.peer = p; e.reason = r; return e; }
inline PeerEvent evMessage(const PeerId& p, ChannelId ch, Bytes d)   { PeerEvent e; e.kind = PeerEvent::Message; e.peer = p; e.channel = ch; e.data = std::move(d); return e; }
inline PeerEvent evMigrated(const PeerId& oldP, const PeerId& newP)  { PeerEvent e; e.kind = PeerEvent::Migrated; e.peer = oldP; e.other = newP; return e; }

struct IncomingPacket { PeerId from; Bytes data; };
struct RawPacket      { PeerId to;   Bytes data; };

struct PendingConnection {
    ConnectionDirection direction = ConnectionDirection::Inbound;
    std::uint64_t       serverSalt = 0;
    std::uint64_t       clientSalt = 0;
    MonoTime            createdAt{};
    int                 retryCount = 0;
    MonoTime            lastRetry{};
};

// --- pure protocol helpers (salts, deny reasons, payload header, FNV hash) ---
inline Bytes encodeSalt(std::uint64_t salt) {
    Bytes b(8);
    for (int i = 0; i < 8; ++i) b[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(salt >> (8 * i));   // little-endian
    return b;
}
inline std::optional<std::uint64_t> decodeSalt(const Bytes& b) {
    if (b.size() < 8) return std::nullopt;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(b[static_cast<std::size_t>(i)]) << (8 * i);
    return v;
}

enum class DenyReason : std::uint8_t { ServerFull = 1, InvalidChallenge = 2 };
inline Bytes encodeDenyReason(DenyReason r) { return Bytes{ static_cast<std::uint8_t>(r) }; }
inline DenyReason decodeDenyReason(const Bytes& d) { return static_cast<DenyReason>(d.empty() ? 0 : d[0]); }
inline DisconnectReason denyToDisconnectReason(DenyReason r) {
    switch (r) {
        case DenyReason::ServerFull:       return DisconnectReason::ServerFull;
        case DenyReason::InvalidChallenge: return DisconnectReason::ProtocolMismatch;
        default:                           return static_cast<DisconnectReason>(static_cast<std::uint8_t>(r));
    }
}

inline constexpr std::uint8_t payloadFragmentFlag = 0x80;
inline constexpr std::uint8_t payloadChannelMask  = 0x07;
inline constexpr int          minPayloadSize      = 3;

inline std::pair<ChannelId, bool> decodePayloadHeader(std::uint8_t b) {
    return { static_cast<ChannelId>(b & payloadChannelMask), (b & payloadFragmentFlag) != 0 };
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
inline constexpr int    cookieSecretSize          = 32;
inline constexpr double peerFragmentTimeoutMs     = 5000.0;
inline constexpr int    peerFragmentMaxBufferSize = 1024 * 1024;
inline constexpr double migrationCooldownMs       = 5000.0;

struct NetPeer {
    Address                              localAddr{};
    std::map<PeerId, Connection>         connections;
    std::map<PeerId, PendingConnection>  pending;
    NetworkConfig                        config;
    RateLimiter                          rateLimiter{};
    Bytes                                cookieSecret;
    std::uint64_t                        rngState = 0;
    std::map<PeerId, FragmentAssembler>  fragmentAssemblers;
    std::map<std::uint64_t, MonoTime>    migrationCooldowns;
    std::vector<RawPacket>               sendQueue;
    std::uint64_t                        rateLimitDrops = 0;
};

inline std::pair<Bytes, std::uint64_t> generateCookieSecret(std::uint64_t seed) {
    Bytes secret;
    secret.reserve(cookieSecretSize);
    std::uint64_t s = seed;
    for (int i = 0; i < cookieSecretSize; ++i) { const auto r = nextRandom(s); secret.push_back(static_cast<std::uint8_t>(r.output)); s = r.state; }
    return { secret, s };
}
inline NetPeer newPeerState(const Address& localAddr, const NetworkConfig& config, MonoTime now) {
    NetPeer peer;
    peer.localAddr   = localAddr;
    peer.config      = config;
    peer.rateLimiter = newRateLimiter(config.rateLimitPerSecond, now);
    const auto [secret, rng1] = generateCookieSecret(now.ns);
    peer.cookieSecret = secret;
    peer.rngState     = rng1;
    return peer;
}

// --- internal helpers ---
inline void cleanupPeer(NetPeer& peer, const PeerId& pid)   { peer.fragmentAssemblers.erase(pid); }
inline void removePending(NetPeer& peer, const PeerId& pid) { peer.pending.erase(pid); }
inline bool isPostHandshake(PacketType t) noexcept { return t == PacketType::Payload || t == PacketType::Keepalive || t == PacketType::Disconnect; }

inline void queueControlPacket(NetPeer& peer, PacketType ptype, const Bytes& payload, const PeerId& pid) {
    const PacketHeader header{ ptype, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    peer.sendQueue.push_back(RawPacket{ pid, appendCrc32(serializePacket(Packet{ header, payload })) });
}

// --- handshake handlers ---
inline std::vector<PeerEvent> handleNewConnectionRequest(NetPeer& peer, const PeerId& pid, MonoTime now) {
    const bool allowed = rateLimiterAllow(peer.rateLimiter, sockAddrToKey(pid.addr), now);
    if (!allowed)                                                       { peer.rateLimitDrops += 1; return {}; }
    if (static_cast<int>(peer.pending.size()) >= peer.config.maxClients) { peer.rateLimitDrops += 1; return {}; }
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::ServerFull), pid);
        return {};
    }
    const auto rng = nextRandom(peer.rngState);
    PendingConnection pend;
    pend.direction = ConnectionDirection::Inbound;
    pend.serverSalt = rng.output;
    pend.createdAt = now;
    pend.lastRetry = now;
    peer.pending[pid] = pend;
    peer.rngState     = rng.state;
    queueControlPacket(peer, PacketType::ConnectionChallenge, encodeSalt(rng.output), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionRequest(NetPeer& peer, const PeerId& pid, MonoTime now) {
    if (peer.connections.count(pid)) { queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid); return {}; }
    if (const auto it = peer.pending.find(pid); it != peer.pending.end()) {
        queueControlPacket(peer, PacketType::ConnectionChallenge, encodeSalt(it->second.serverSalt), pid);
        return {};
    }
    return handleNewConnectionRequest(peer, pid, now);
}
inline std::vector<PeerEvent> handleConnectionChallenge(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    const auto serverSalt = decodeSalt(pkt.payload);
    if (!serverSalt) return {};
    it->second.serverSalt = *serverSalt;
    queueControlPacket(peer, PacketType::ConnectionResponse, encodeSalt(it->second.clientSalt), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionResponse(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Inbound) return {};
    const auto clientSalt = decodeSalt(pkt.payload);
    if (!clientSalt) return {};
    if (*clientSalt == 0 || *clientSalt == it->second.serverSalt) {
        removePending(peer, pid);
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::InvalidChallenge), pid);
        return {};
    }
    Connection conn = newConnection(peer.config, *clientSalt, now);
    touchRecvTime(conn, now);
    markConnected(conn, now);
    peer.connections[pid] = std::move(conn);
    peer.pending.erase(pid);
    queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid);
    return { evConnected(pid, ConnectionDirection::Inbound) };
}
inline std::vector<PeerEvent> handleConnectionAccepted(NetPeer& peer, const PeerId& pid, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    Connection conn = newConnection(peer.config, it->second.clientSalt, now);
    touchRecvTime(conn, now);
    markConnected(conn, now);
    peer.connections[pid] = std::move(conn);
    peer.pending.erase(pid);
    return { evConnected(pid, ConnectionDirection::Outbound) };
}
inline std::vector<PeerEvent> handleDisconnect(NetPeer& peer, const PeerId& pid) {
    if (peer.connections.count(pid)) {
        peer.connections.erase(pid);
        cleanupPeer(peer, pid);
        return { evDisconnected(pid, DisconnectReason::Requested) };
    }
    removePending(peer, pid);
    return {};
}

// --- migration ---
inline std::uint64_t migrationTokenFor(const Connection& conn) noexcept { return conn.clientSalt; }
struct MigrationCandidate { PeerId oldPeer; std::uint64_t token = 0; };
inline std::optional<MigrationCandidate> findMigrationCandidate(const NetPeer& peer, const Packet& pkt, MonoTime) {
    const int incomingSeq = pkt.header.sequence.value;
    const int maxDistance = peer.config.maxSequenceDistance;
    for (const auto& [pid, conn] : peer.connections)
        if (std::abs(incomingSeq - static_cast<int>(connRemoteSeq(conn).value)) <= maxDistance)
            return MigrationCandidate{ pid, migrationTokenFor(conn) };
    return std::nullopt;
}

// --- payload / fragment / migration dispatch ---
inline std::vector<PeerEvent> handleFragment(NetPeer& peer, const PeerId& pid, ChannelId channel, const Bytes& fragData, MonoTime now) {
    FragmentAssembler& assembler =
        peer.fragmentAssemblers.try_emplace(pid, newFragmentAssembler(peerFragmentTimeoutMs, peerFragmentMaxBufferSize)).first->second;
    const auto complete = processFragment(assembler, fragData.data(), fragData.size(), now);
    if (!complete) return {};
    const auto cs = decodeChannelSeq(*complete);
    if (!cs) return {};
    if (const auto it = peer.connections.find(pid); it != peer.connections.end())
        receiveIncomingPayload(it->second, channel, cs->first, cs->second, now);
    return {};
}
inline std::vector<PeerEvent> handlePayload(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return {};
    processIncomingHeader(it->second, pkt.header, now);
    touchRecvTime(it->second, now);
    const Bytes& payload = pkt.payload;
    if (payload.empty()) return {};
    const auto [channel, isFragment] = decodePayloadHeader(payload[0]);
    const Bytes rest(payload.begin() + 1, payload.end());
    if (isFragment) return handleFragment(peer, pid, channel, rest, now);
    if (static_cast<int>(payload.size()) < minPayloadSize) return {};
    if (const auto cs = decodeChannelSeq(rest))
        receiveIncomingPayload(it->second, channel, cs->first, cs->second, now);
    return {};
}
inline std::vector<PeerEvent> handleMigration(NetPeer& peer, const PeerId& newPid, const Packet& pkt, MonoTime now) {
    if (!peer.config.enableConnectionMigration) return {};
    const auto cand = findMigrationCandidate(peer, pkt, now);
    if (!cand) return {};
    if (const auto it = peer.migrationCooldowns.find(cand->token);
        it != peer.migrationCooldowns.end() && elapsedMs(it->second, now) < migrationCooldownMs) return {};
    const auto connIt = peer.connections.find(cand->oldPeer);
    if (connIt == peer.connections.end()) return {};

    Connection migrated = std::move(connIt->second);
    peer.connections.erase(connIt);
    resetTransportMetrics(migrated, now);
    peer.connections[newPid] = std::move(migrated);
    peer.migrationCooldowns[cand->token] = now;
    if (const auto fa = peer.fragmentAssemblers.find(cand->oldPeer); fa != peer.fragmentAssemblers.end()) {
        peer.fragmentAssemblers[newPid] = std::move(fa->second);
        peer.fragmentAssemblers.erase(fa);
    }
    std::vector<PeerEvent> events{ evMigrated(cand->oldPeer, newPid) };
    for (auto& e : handlePayload(peer, newPid, pkt, now)) events.push_back(std::move(e));
    return events;
}

inline std::vector<PeerEvent> handlePacketByType(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now, PacketType ptype) {
    switch (ptype) {
        case PacketType::ConnectionRequest:   return handleConnectionRequest(peer, pid, now);
        case PacketType::ConnectionChallenge: return handleConnectionChallenge(peer, pid, pkt, now);
        case PacketType::ConnectionResponse:  return handleConnectionResponse(peer, pid, pkt, now);
        case PacketType::ConnectionAccepted:  return handleConnectionAccepted(peer, pid, now);
        case PacketType::ConnectionDenied:
            removePending(peer, pid);
            return { evDisconnected(pid, denyToDisconnectReason(decodeDenyReason(pkt.payload))) };
        case PacketType::Disconnect:          return handleDisconnect(peer, pid);
        case PacketType::Payload:
            return peer.connections.count(pid) ? handlePayload(peer, pid, pkt, now) : handleMigration(peer, pid, pkt, now);
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
    const bool keyed  = connIt != peer.connections.end() && connIt->second.encryptionKey.has_value();

    if (isPostHandshake(ptype) && keyed) {
        Connection& conn = connIt->second;
        recordBytesReceived(conn, bytes, now);
        const auto dec = decrypt(*conn.encryptionKey, peer.config.protocolId, pkt.payload.data(), pkt.payload.size());
        if (!dec) { conn.stats.decryptionFailures += 1; return {}; }
        if (conn.recvNonceMax && dec->counter.value <= *conn.recvNonceMax) return {};   // replay
        conn.recvNonceMax = dec->counter.value;
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
        if (conn.encryptionKey && isPostHandshake(op.type)) {
            const NonceCounter nonce = conn.sendNonce;
            Bytes combined(serialized.begin(), serialized.begin() + static_cast<std::ptrdiff_t>(packetHeaderBytes));
            const Bytes enc = encrypt(*conn.encryptionKey, nonce, peer.config.protocolId,
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
            queueControlPacket(peer, PacketType::ConnectionRequest, {}, pid);
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
    const auto rng = nextRandom(peer.rngState);
    PendingConnection pend;
    pend.direction  = ConnectionDirection::Outbound;
    pend.clientSalt = rng.output;
    pend.createdAt  = now;
    pend.lastRetry  = now;
    peer.pending[pid] = pend;
    peer.rngState     = rng.state;
    queueControlPacket(peer, PacketType::ConnectionRequest, {}, pid);
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
