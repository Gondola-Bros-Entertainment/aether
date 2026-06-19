// aether - real UDP IO loop. A Host owns a socket and a NetPeer; hostTick drains all pending
// datagrams (non-blocking), validates+strips their CRC, runs the pure peerProcess, and sends the
// replies. A non-blocking drain per tick keeps it simple; a dedicated receive thread can be layered
// on later. Data-first: a plain Host struct + free functions.
#pragma once

#include "aether/peer.hpp"
#include "aether/security.hpp"
#include "aether/socket.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace aether {

struct Host {
    Socket  socket{};
    NetPeer peer;
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
        if (auto v = validateAndStripCrc32(raw)) incoming.push_back(IncomingPacket{ PeerId{ from }, std::move(*v) });
    }

    for (const auto& [ch, msg] : messages) peerBroadcast(h.peer, ch, msg, std::nullopt, now);

    auto result = peerProcess(h.peer, now, incoming);
    for (const RawPacket& rp : result.outgoing)
        sendTo(h.socket, std::span<const std::uint8_t>(rp.data.data(), rp.data.size()), rp.to.addr);
    return std::move(result.events);
}

inline void hostConnect(Host& h, const Address& addr, MonoTime now) { peerConnect(h.peer, PeerId{ addr }, now); }
inline void hostDisconnect(Host& h, const Address& addr, MonoTime now) { peerDisconnect(h.peer, PeerId{ addr }, now); }
inline std::optional<ConnectionError> hostSend(Host& h, const Address& addr, ChannelId ch, const Bytes& data, MonoTime now) {
    return peerSend(h.peer, PeerId{ addr }, ch, data, now);
}
inline void closeHost(Host& h) { closeSocket(h.socket); }

} // namespace aether
