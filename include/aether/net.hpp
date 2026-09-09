// aether - real UDP IO loop. A Host owns a socket and a NetPeer; hostTick receives a bounded
// non-blocking batch, validates+strips CRC, runs peerProcess, and sends replies on the caller's
// thread. Packet and byte budgets ensure intake returns even when the socket stays readable.
// Data-first: a plain Host struct + free functions.
#pragma once

#include "aether/config.hpp"
#include "aether/connection.hpp"
#include "aether/peer.hpp"
#include "aether/rendezvous.hpp"
#include "aether/security.hpp"
#include "aether/socket.hpp"
#include "aether/types.hpp"

#include <cstdint>
#include <chrono>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace aether {

inline constexpr std::size_t maxHostDiagnostics = 32;
enum class HostIoOperation { Send, Receive };
struct HostIoError { HostIoOperation operation = HostIoOperation::Send; Address address; SocketError error; };
// Bounded records accumulate until taken, including API calls made between ticks.
// Socket counters remain cumulative even when this diagnostic buffer fills.
struct HostDiagnostics {
    std::vector<HostIoError> ioErrors;
    std::vector<BroadcastFailure> queueErrors;
    std::uint64_t omittedIoErrors = 0;
    std::uint64_t omittedQueueErrors = 0;
    std::optional<ConnectError> rendezvousConnectError;
};

struct Host {
    HostDiagnostics diagnostics;
    Socket                       socket{};
    NetPeer                      peer;
    std::optional<Address>       rendezvousAddr;   // set by hostJoinRoom; replies from here are Paired messages
    std::optional<Address>       punchTarget;      // an Accept peer hole-punches this address until connected
    std::optional<Address>       partnerAddr;      // the partner's direct address: the connection key + punch target
    std::optional<std::uint64_t> pendingRoom;      // room awaiting pairing -- Register is re-sent until paired
    std::uint64_t                roomId = 0;        // the paired room, used to wrap packets when relaying
    MonoTime                     lastRegister{};
    MonoTime                     punchStart{};      // when pairing happened -- the punch deadline runs from here
    double                       punchTimeoutMs = defaultPunchTimeoutMs;   // try the punch this long, then relay
    bool                         relaying = false;  // routing through the rendezvous because the punch did not connect
};

inline HostDiagnostics hostTakeDiagnostics(Host& host) {
    auto diagnostics = std::move(host.diagnostics);
    host.diagnostics = {};
    return diagnostics;
}
inline void hostRecordIoError(Host& host, HostIoOperation operation, const Address& address, SocketError error) {
    if (host.diagnostics.ioErrors.size() < maxHostDiagnostics)
        host.diagnostics.ioErrors.push_back({operation, address, error});
    else ++host.diagnostics.omittedIoErrors;
}
inline bool hostSendDatagram(Host& host, ByteSpan data, const Address& to) {
    if (sendTo(host.socket, data, to) >= 0) return true;
    hostRecordIoError(host, HostIoOperation::Send, to, host.socket.lastSendError);
    return false;
}
inline void hostFlush(Host& host, const std::vector<RawPacket>& outgoing) {
    for (const auto& packet : outgoing) {
        if (host.relaying && host.partnerAddr && host.rendezvousAddr && addrEqual(packet.to.addr, *host.partnerAddr)) {
            const auto wrapped = encodeRelay(host.roomId, packet.data.data(), packet.data.size());
            hostSendDatagram(host, wrapped, *host.rendezvousAddr);
        } else hostSendDatagram(host, packet.data, packet.to.addr);
    }
}

// Open a host bound to bindAddr (use addrAny(port) for a server, addrLocalhost(0) for ephemeral).
inline std::optional<Host> openHost(const Address& bindAddr, const NetworkConfig& config, MonoTime now) {
    if (validateConfig(config)) return std::nullopt;   // reject an invalid config rather than run with it
    auto sock = openUdp(bindAddr);
    if (!sock) return std::nullopt;
    Host h;
    h.socket = *sock;
    h.peer   = newPeerState(localAddr(*sock), config, now);
    return h;
}

// One game-loop step: receive a bounded batch, queue outgoing messages to all peers, process,
// then send. Returns the events that occurred this tick.
inline std::vector<PeerEvent> hostTick(Host& h, const std::vector<std::pair<ChannelId, Bytes>>& messages, MonoTime now) {
    static thread_local std::vector<std::uint8_t> scratch(maxUdpPacketSize);

    std::vector<IncomingPacket> incoming;
    const auto& budget = h.peer.config.receiveBudget;
    std::size_t receivedBytes = 0;
    for (std::size_t packets = 0; packets < budget.maxDatagrams && receivedBytes < budget.maxBytes; ++packets) {
        Address   from{};
        const int n = recvFrom(h.socket, std::span<std::uint8_t>(scratch.data(), scratch.size()), from);
        if (n < 0) {
            if (h.socket.lastReceiveError.code != SocketErrorCode::WouldBlock)
                hostRecordIoError(h, HostIoOperation::Receive, {}, h.socket.lastReceiveError);
            break;
        }
        const std::size_t len = static_cast<std::size_t>(n);
        // A boundary datagram that does not fit is discarded before CRC/copying. It is UDP loss,
        // recoverable by reliable channels; the rest remains queued for a future tick.
        if (len > budget.maxBytes - receivedBytes) break;
        receivedBytes += len;
        if (h.rendezvousAddr && addrEqual(from, *h.rendezvousAddr)) {
            const Bytes raw(scratch.begin(), scratch.begin() + n);   // rendezvous frames are rare (pairing + relay), so the owned copy costs nothing here
            if (const auto paired = decodePaired(raw)) {   // a pairing reply from the rendezvous
                if (!h.pendingRoom) continue; // A duplicated/stale reply must not restart an established session.
                if (h.pendingRoom) h.roomId = *h.pendingRoom;   // the room we joined -- used to wrap relayed packets
                h.pendingRoom = std::nullopt;                   // paired -- stop re-registering
                h.partnerAddr = paired->second;
                h.punchStart  = now;
                h.relaying    = (h.punchTimeoutMs <= 0.0);      // <= 0 means skip the punch and relay immediately
                if (paired->first == PunchRole::Connect) h.diagnostics.rendezvousConnectError = peerConnect(h.peer, PeerId{ paired->second }, now);
                else if (!h.relaying)                    h.punchTarget = paired->second;   // Accept: hole-punch direct
                continue;
            }
            // not a pairing reply -- a peer packet the rendezvous relayed to us; attribute it to the partner.
            if (h.relaying && h.partnerAddr) {
                if (const auto payloadLen = crc32StrippedLen(raw.data(), raw.size()))
                    incoming.push_back(IncomingPacket{ PeerId{ *h.partnerAddr },
                                                       Bytes(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(*payloadLen)) });
            }
            continue;
        }
        // Ordinary peer traffic, the hot path: check the CRC in place on the scratch and materialize
        // the payload exactly once. Copying the datagram and then copying it again to strip the four
        // trailing CRC bytes would cost two allocations per datagram, which is what crc32StrippedLen
        // exists to avoid.
        if (const auto payloadLen = crc32StrippedLen(scratch.data(), len))
            incoming.push_back(IncomingPacket{ PeerId{ from },
                                               Bytes(scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(*payloadLen)) });
    }

    for (const auto& [ch, msg] : messages) {
        for (auto& failure : peerBroadcast(h.peer, ch, msg, std::nullopt, now)) {
            if (h.diagnostics.queueErrors.size() < maxHostDiagnostics) h.diagnostics.queueErrors.push_back(std::move(failure));
            else ++h.diagnostics.omittedQueueErrors;
        }
    }

    const auto epochNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const UnixTime tokenTime{epochNs > 0 ? static_cast<std::uint64_t>(epochNs) : 0};
    auto result = peerProcess(h.peer, now, incoming, tokenTime);
    hostFlush(h, result.outgoing);

    // hole-punch: while an Accept peer waits to be reached, keep an outbound flowing to the peer's
    // address so its NAT mapping stays open; the inbound handshake lands once both sides have punched.
    if (h.punchTarget) {
        if (peerIsConnected(h.peer, PeerId{ *h.punchTarget })) {
            h.punchTarget = std::nullopt;
        } else {
            const std::uint8_t punch = 0;
            hostSendDatagram(h, std::span<const std::uint8_t>(&punch, 1), *h.punchTarget);
        }
    }

    // fallback: if the direct punch has not connected within the deadline, relay through the rendezvous.
    if (h.partnerAddr && !h.relaying && h.punchTimeoutMs > 0.0
        && elapsedMs(h.punchStart, now) >= h.punchTimeoutMs && !peerIsConnected(h.peer, PeerId{ *h.partnerAddr })) {
        h.relaying    = true;
        h.punchTarget = std::nullopt;   // stop the direct openers; everything goes through the relay now
    }

    // re-send Register until the rendezvous pairs us -- UDP, so the first one can be lost.
    if (h.pendingRoom && h.rendezvousAddr && elapsedMs(h.lastRegister, now) >= registerRetryMs) {
        const Bytes reg = encodeRegister(*h.pendingRoom);
        hostSendDatagram(h, std::span<const std::uint8_t>(reg.data(), reg.size()), *h.rendezvousAddr);
        h.lastRegister = now;
    }
    return std::move(result.events);
}

inline std::optional<ConnectError> hostConnect(Host& h, const Address& addr, MonoTime now) { return peerConnect(h.peer, PeerId{ addr }, now); }
// Connect presenting a sealed connect token (minted by your auth backend); the server must be opened
// with the matching config.tokenKey. The verified playerId arrives on the Connected event.
inline std::optional<ConnectError> hostConnectWithToken(Host& h, const Address& addr, const ConnectCredential& token, MonoTime now) {
    return peerConnectWithToken(h.peer, PeerId{ addr }, token, now);
}
// Join a room on the rendezvous server; once paired, hostTick auto-connects (or hole-punches) to the
// peer. Register is re-sent each tick until paired, so a lost first datagram does not strand the join.
inline std::optional<ConnectError> hostJoinRoom(Host& h, const Address& rendezvous, std::uint64_t roomId, MonoTime now) {
    if (!addressValid(rendezvous)) return ConnectError::InvalidAddress;
    if (!h.peer.config.allowUnauthenticated || h.peer.config.tokenKey) return ConnectError::AuthenticationRequired;
    h.rendezvousAddr = rendezvous;
    h.pendingRoom    = roomId;
    h.lastRegister   = now;
    const Bytes reg = encodeRegister(roomId);
    hostSendDatagram(h, std::span<const std::uint8_t>(reg.data(), reg.size()), rendezvous);
    return std::nullopt;
}
inline std::optional<ConnectError> hostReconnect(Host& h, const Address& addr, std::uint64_t token, MonoTime now,
                                                std::optional<ConnectCredential> fallback = std::nullopt) {
    return peerReconnect(h.peer, PeerId{addr}, token, now, std::move(fallback));
}
inline void hostDisconnect(Host& h, const Address& addr, MonoTime now, DisconnectReason reason = DisconnectReason::Requested) {
    peerDisconnect(h.peer, PeerId{addr}, now, reason);
}
// Flush initial disconnects using normal direct/relay routing. Keep ticking for retry/timeout
// processing if desired, then closeHost releases the socket and all remaining session state.
inline void hostShutdown(Host& h, MonoTime now) {
    h.pendingRoom.reset();
    h.punchTarget.reset();
    hostFlush(h, peerShutdown(h.peer, now));
}
inline std::optional<ConnectionError> hostSend(Host& h, const Address& addr, ChannelId ch, const Bytes& data, MonoTime now) {
    return peerSend(h.peer, PeerId{ addr }, ch, data, now);
}
inline void closeHost(Host& h) {
    closeSocket(h.socket);
    h.peer.pending.clear();
    h.peer.connections.clear();
    h.peer.resumableTokens.clear();
    h.peer.sendQueue.clear();
    h.peer.fragmentAssemblers.clear();
    h.peer.pathValidations.clear();
    h.pendingRoom.reset();
    h.punchTarget.reset();
}

} // namespace aether
