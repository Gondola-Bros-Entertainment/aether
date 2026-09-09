#include "check.hpp"
#include <aether/net.hpp>
#include <thread>

using namespace aether;
using aether::test::require;

int main() try {
    MonoTime now{1};
    NetworkConfig cfg;
    EncryptionKey key{};
    secureRandomBytes(key.data(), key.size());
    cfg.tokenKey = key;
    cfg.tokenAudience = 4200;
    const auto epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const UnixTime expires{static_cast<std::uint64_t>(epoch) + 3600ull * 1000000000};
    const auto one = issueConnectCredential(key, ConnectToken{101, expires, {1}, {cfg.protocolId, cfg.tokenAudience}});
    const auto two = issueConnectCredential(key, ConnectToken{102, expires, {2}, {cfg.protocolId, cfg.tokenAudience}});
    auto server = openHost(addrLocalhost(0), cfg, now);
    cfg.tokenKey.reset();
    auto first = openHost(addrLocalhost(0), cfg, now);
    auto second = openHost(addrLocalhost(0), cfg, now);
    require(server && first && second);
    const auto serverAddr = peerLocalAddr(server->peer);
    const auto firstAddr = peerLocalAddr(first->peer);
    const auto secondAddr = peerLocalAddr(second->peer);
    require(!hostConnectWithToken(*first, serverAddr, one, now));
    require(!hostConnectWithToken(*second, serverAddr, two, now));
    auto tick = [&] {
        now.ns += 1000000;
        hostTick(*first, {}, now);
        hostTick(*second, {}, now);
        const auto events = hostTick(*server, {}, now);
        for (const auto& event : events) if (event.kind == PeerEvent::Connected || event.kind == PeerEvent::Reconnected) {
            require(event.playerId == 101 || event.playerId == 102);
            require(event.userData == Bytes{static_cast<std::uint8_t>(event.playerId - 100)});
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    };
    for (int i = 0; i < 2000 && (peerCount(first->peer) != 1 || peerCount(second->peer) != 1); ++i) tick();
    require(peerCount(server->peer) == 2 && peerCount(first->peer) == 1 && peerCount(second->peer) == 1);
    require(hostTakeDiagnostics(*server).ioErrors.empty());
    require(hostTakeDiagnostics(*first).ioErrors.empty() && hostTakeDiagnostics(*second).ioErrors.empty());
    // A broadcast rejection names the individual peers. Diagnostic memory stays bounded.
    hostTick(*server, std::vector<std::pair<ChannelId, Bytes>>(40, {ChannelId{99}, Bytes{1}}), now);
    auto diagnostics = hostTakeDiagnostics(*server);
    require(diagnostics.queueErrors.size() == maxHostDiagnostics && diagnostics.omittedQueueErrors == 80 - maxHostDiagnostics);
    for (const auto& failure : diagnostics.queueErrors) {
        require(failure.error.kind == ConnectionError::InvalidChannel);
        require(addrEqual(failure.peer.addr, firstAddr) || addrEqual(failure.peer.addr, secondAddr));
    }
    require(hostTakeDiagnostics(*server).queueErrors.empty());
    const Bytes message{9,8,7};
    require(!hostSend(*first, serverAddr, ChannelId{0}, message, now));
    bool delivered = false;
    for (int i = 0; i < 1000 && !delivered; ++i) {
        now.ns += 1000000;
        hostTick(*first, {}, now);
        for (const auto& event : hostTick(*server, {}, now))
            if (event.kind == PeerEvent::Message) { require(event.data == message); delivered = true; }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    require(delivered);
    // Simulate inactivity using the pure monotonic clock while keeping real socket IO.
    const auto token = *peerSessionToken(first->peer, PeerId{serverAddr});
    now.ns += 11000ull * 1000000;
    peerProcess(first->peer, now, {});
    peerProcess(second->peer, now, {});
    peerProcess(server->peer, now, {});
    require(peerCount(first->peer) == 0 && peerCount(server->peer) == 0);
    require(!hostReconnect(*first, serverAddr, token, now));
    for (int i = 0; i < 2000 && peerCount(first->peer) == 0; ++i) tick();
    require(peerCount(first->peer) == 1 && peerCount(server->peer) == 1);
    require(peerPlayerId(server->peer, PeerId{firstAddr}) == 101);
    hostShutdown(*server, now);
    require(peerConnectedIds(server->peer).empty() && !peerIsConnected(server->peer, PeerId{firstAddr}));
    bool disconnected = false;
    for (int i = 0; i < 100 && !disconnected; ++i) {
        now.ns += 1000000;
        for (const auto& event : hostTick(*first, {}, now))
            if (event.kind == PeerEvent::Disconnected) disconnected = true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    require(disconnected);
    closeHost(*first); closeHost(*second); closeHost(*server);
    // A closed socket is an observable receive/send failure, not an empty queue or a successful send.
    hostTick(*server, {}, now);
    require(!hostSendDatagram(*server, message, firstAddr));
    diagnostics = hostTakeDiagnostics(*server);
    require(diagnostics.ioErrors.size() == 2);
    require(diagnostics.ioErrors[0].operation == HostIoOperation::Receive);
    require(diagnostics.ioErrors[1].operation == HostIoOperation::Send);
    require(diagnostics.ioErrors[0].error.code == SocketErrorCode::Closed);
    require(server->socket.receiveErrors > 0 && server->socket.sendErrors > 0);
    std::puts("host_lifecycle_test: two authenticated UDP clients, message, bounded diagnostics, resume and shutdown passed");
}
 catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
