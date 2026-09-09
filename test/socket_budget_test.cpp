#include "check.hpp"
// A perpetually readable fake socket must not starve connection timers or exceed intake bounds.
#define recvFrom budgetTestRecvFrom
#include "aether/net.hpp"
#undef recvFrom
#include <cassert>
#include <cstring>
#include <cstdio>

namespace aether {
static Bytes queuedDatagram;
static std::size_t reads = 0;
int budgetTestRecvFrom(Socket&, std::span<std::uint8_t> buffer, Address& from) {
    from = addrLocalhost(19001);
    aether::test::require(queuedDatagram.size() <= buffer.size());
    if (!queuedDatagram.empty()) std::memcpy(buffer.data(), queuedDatagram.data(), queuedDatagram.size());
    ++reads;
    return static_cast<int>(queuedDatagram.size());
}
}

int main() {
    using namespace aether;
    NetworkConfig cfg;
    aether::test::require(!validateConfig(cfg));
    cfg.receiveBudget.maxDatagrams = 0;
    aether::test::require(validateConfig(cfg) == ConfigError::InvalidReceiveBudget);
    cfg.receiveBudget.maxDatagrams = 3;
    cfg.receiveBudget.maxBytes = maxUdpPacketSize - 1;
    aether::test::require(validateConfig(cfg) == ConfigError::InvalidReceiveBudget);
    cfg.receiveBudget.maxBytes = maxUdpPacketSize;
    aether::test::require(!validateConfig(cfg));
    Host host;
    host.peer = newPeerState(addrLocalhost(0), cfg, MonoTime{1});
    const PeerId remote{addrLocalhost(19002)};
    auto connection = newConnection(cfg, 1, MonoTime{1});
    connection.state = ConnectionState::Connected;
    host.peer.connections.emplace(remote, std::move(connection));
    queuedDatagram.clear(); reads = 0;
    const auto events = hostTick(host, {}, MonoTime{60000000000ull});
    aether::test::require(reads == 3); // Zero-length packets still consume the packet budget.
    aether::test::require(events.size() == 1 && events[0].kind == PeerEvent::Disconnected);
    aether::test::require(host.peer.connections.empty()); // A perpetually readable socket did not starve the timer.

    host.peer.config.receiveBudget.maxDatagrams = 100;
    queuedDatagram = frameCleartextDatagram(PacketHeader{PacketType::Keepalive, {}, {}, 0}, Bytes(32768 - packetHeaderBytes - crc32Size));
    aether::test::require(queuedDatagram.size() == 32768);
    reads = 0;
    hostTick(host, {}, MonoTime{60000000001ull});
    aether::test::require(reads == 2); // Byte budget stops before CRC-valid packets can grow an unbounded vector.

    RendezvousServer rv;
    rv.receiveBudget = {3, maxUdpPacketSize};
    Socket socket;
    queuedDatagram.clear(); reads = 0;
    rendezvousTick(rv, socket, MonoTime{1});
    aether::test::require(reads == 3);
    rv.receiveBudget.maxDatagrams = 100;
    queuedDatagram.assign(32768, 0); reads = 0;
    rendezvousTick(rv, socket, MonoTime{2});
    aether::test::require(reads == 2); // Unrecognized rendezvous frames still consume bytes before allocation.
    std::puts("socket intake budgets and timer progress OK");
}
