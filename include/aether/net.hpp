// aether - real UDP IO loop. A Host owns a socket and a NetPeer; hostTick drains all pending
// datagrams (non-blocking), validates+strips their CRC, runs the pure peerProcess, and sends the
// replies. A non-blocking drain per tick keeps it simple; a dedicated receive thread can be layered
// on later. Data-first: a plain Host struct + free functions.
#pragma once

#include "aether/peer.hpp"
#include "aether/rendezvous.hpp"
#include "aether/security.hpp"
#include "aether/socket.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace aether {

struct Host {
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

// Open a host bound to bindAddr (use addrAny(port) for a server, addrLocalhost(0) for ephemeral).
inline std::optional<Host> openHost(const Address& bindAddr, const NetworkConfig& config, MonoTime now) {
    auto sock = openUdp(bindAddr);
    if (!sock) return std::nullopt;
    Host h;
    h.socket = *sock;
    h.peer   = newPeerState(localAddr(*sock), config, now);
    return h;
}

// One game-loop step: receive everything pending, queue outgoing messages to all peers, process,
// then send. Returns the events that occurred this tick.
inline std::vector<PeerEvent> hostTick(Host& h, const std::vector<std::pair<ChannelId, Bytes>>& messages, MonoTime now) {
    static thread_local std::vector<std::uint8_t> scratch(maxUdpPacketSize);

    std::vector<IncomingPacket> incoming;
    for (;;) {
        Address   from{};
        const int n = recvFrom(h.socket, std::span<std::uint8_t>(scratch.data(), scratch.size()), from);
        if (n <= 0) break;
        Bytes raw(scratch.begin(), scratch.begin() + n);
        if (h.rendezvousAddr && addrEqual(from, *h.rendezvousAddr)) {
            if (const auto paired = decodePaired(raw)) {   // a pairing reply from the rendezvous
                if (h.pendingRoom) h.roomId = *h.pendingRoom;   // the room we joined -- used to wrap relayed packets
                h.pendingRoom = std::nullopt;                   // paired -- stop re-registering
                h.partnerAddr = paired->second;
                h.punchStart  = now;
                h.relaying    = (h.punchTimeoutMs <= 0.0);      // <= 0 means skip the punch and relay immediately
                if (paired->first == PunchRole::Connect) peerConnect(h.peer, PeerId{ paired->second }, now);
                else if (!h.relaying)                    h.punchTarget = paired->second;   // Accept: hole-punch direct
                continue;
            }
            // not a pairing reply -- a peer packet the rendezvous relayed to us; attribute it to the partner.
            if (h.relaying && h.partnerAddr) {
                if (auto v = validateAndStripCrc32(raw)) incoming.push_back(IncomingPacket{ PeerId{ *h.partnerAddr }, std::move(*v) });
            }
            continue;
        }
        if (auto v = validateAndStripCrc32(raw)) incoming.push_back(IncomingPacket{ PeerId{ from }, std::move(*v) });
    }

    for (const auto& [ch, msg] : messages) peerBroadcast(h.peer, ch, msg, std::nullopt, now);

    auto result = peerProcess(h.peer, now, incoming);
    for (const RawPacket& rp : result.outgoing) {
        if (h.relaying && h.partnerAddr && h.rendezvousAddr && addrEqual(rp.to.addr, *h.partnerAddr)) {
            const Bytes wrapped = encodeRelay(h.roomId, rp.data.data(), rp.data.size());   // forward via the rendezvous
            sendTo(h.socket, std::span<const std::uint8_t>(wrapped.data(), wrapped.size()), *h.rendezvousAddr);
        } else {
            sendTo(h.socket, std::span<const std::uint8_t>(rp.data.data(), rp.data.size()), rp.to.addr);
        }
    }

    // hole-punch: while an Accept peer waits to be reached, keep an outbound flowing to the peer's
    // address so its NAT mapping stays open; the inbound handshake lands once both sides have punched.
    if (h.punchTarget) {
        if (peerIsConnected(h.peer, PeerId{ *h.punchTarget })) {
            h.punchTarget = std::nullopt;
        } else {
            const std::uint8_t punch = 0;
            sendTo(h.socket, std::span<const std::uint8_t>(&punch, 1), *h.punchTarget);
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
        sendTo(h.socket, std::span<const std::uint8_t>(reg.data(), reg.size()), *h.rendezvousAddr);
        h.lastRegister = now;
    }
    return std::move(result.events);
}

inline void hostConnect(Host& h, const Address& addr, MonoTime now) { peerConnect(h.peer, PeerId{ addr }, now); }
// Join a room on the rendezvous server; once paired, hostTick auto-connects (or hole-punches) to the
// peer. Register is re-sent each tick until paired, so a lost first datagram does not strand the join.
inline void hostJoinRoom(Host& h, const Address& rendezvous, std::uint64_t roomId, MonoTime now) {
    h.rendezvousAddr = rendezvous;
    h.pendingRoom    = roomId;
    h.lastRegister   = now;
    const Bytes reg = encodeRegister(roomId);
    sendTo(h.socket, std::span<const std::uint8_t>(reg.data(), reg.size()), rendezvous);
}
inline void hostDisconnect(Host& h, const Address& addr, MonoTime now) { peerDisconnect(h.peer, PeerId{ addr }, now); }
inline std::optional<ConnectionError> hostSend(Host& h, const Address& addr, ChannelId ch, const Bytes& data, MonoTime now) {
    return peerSend(h.peer, PeerId{ addr }, ch, data, now);
}
inline void closeHost(Host& h) { closeSocket(h.socket); }

} // namespace aether
