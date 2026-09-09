#include "check.hpp"
#include "aether/peer.hpp"
#include <cassert>
#include <cstdio>
#include <climits>
int main() {
    using namespace aether;
    // Valid extreme receive capacity must not overflow credit hysteresis arithmetic.
    {
        NetworkConfig config;
        config.defaultChannelConfig.maxReceiveBufferSize = INT_MAX;
        aether::test::require(!validateConfig(config));
        auto connection = newConnection(config, 1, MonoTime{1});
        maybeAdvertiseWindow(connection, MonoTime{2});
        maybeAdvertiseWindow(connection, MonoTime{3});
    }
    // Statistics count datagrams within a flush, including every coalesced/control wire.
    {
        auto statsPeer = newPeerState(addrLocalhost(5000), NetworkConfig{}, MonoTime{1});
        auto connection = newConnection(NetworkConfig{}, 1, MonoTime{1});
        markConnected(connection, MonoTime{1});
        connection.sendKey = EncryptionKey{};
        for (int n = 0; n < 5; ++n) enqueueEmptyPacket(connection);
        statsPeer.connections.emplace(PeerId{addrLocalhost(5001)}, std::move(connection));
        drainAllConnectionQueues(statsPeer, MonoTime{2});
        aether::test::require(statsPeer.sendQueue.size() == 5);
        aether::test::require(statsPeer.connections.begin()->second.stats.packetsSent == 5);
    }
    // Default strict ordering retains a gap and later delivers everything in order, even after 5s.
    auto ch = newChannel(ChannelId{0}, reliableOrderedChannel());
    onMessageReceived(ch, SequenceNum{2}, {'C'}, MonoTime{1});
    onMessageReceived(ch, SequenceNum{1}, {'B'}, MonoTime{2});
    channelUpdate(ch, MonoTime{6000000000});
    aether::test::require(!ch.failure && channelReceive(ch).empty());
    onMessageReceived(ch, SequenceNum{0}, {'A'}, MonoTime{6000000001});
    const auto got = channelReceive(ch);
    aether::test::require((got == std::vector<Bytes>{{'A'}, {'B'}, {'C'}}));

    NetworkConfig cfg; cfg.maxChannels = 1; cfg.defaultChannelConfig.maxReliableRetries = 0;
    const PeerId remote{addrLocalhost(2000)};
    auto peer = newPeerState(addrLocalhost(1000), cfg, MonoTime{1});
    auto conn = newConnection(cfg, 1, MonoTime{1});
    markConnected(conn, MonoTime{1});
    const auto sent = channelSend(conn.channels[0], {42}, MonoTime{1});
    commitOutgoingMessage(conn.channels[0], sent.seq, MonoTime{1});
    peer.connections.emplace(remote, std::move(conn));
    aether::test::require(updateConnections(peer, MonoTime{1000000000}).empty());
    auto& closing = peer.connections.at(remote);
    aether::test::require(closing.state == ConnectionState::Disconnecting);
    aether::test::require(closing.disconnectReason == DisconnectReason::DeliveryFailed);
    auto initial = drainSendQueue(closing);
    aether::test::require(initial.size() == 1 && initial[0].type == PacketType::Disconnect);
    aether::test::require(initial[0].payload == Bytes{disconnectReasonCode(DisconnectReason::DeliveryFailed)});
    for (std::uint64_t second = 2; second <= 4; ++second) {
        aether::test::require(updateConnections(peer, MonoTime{second * 1000000000}).empty());
        auto retry = drainSendQueue(peer.connections.at(remote));
        aether::test::require(retry.size() == 1 && retry[0].payload == initial[0].payload);
    }
    const auto ended = updateConnections(peer, MonoTime{5000000000});
    aether::test::require(ended.size() == 1 && ended[0].kind == PeerEvent::Disconnected);
    aether::test::require(ended[0].reason == DisconnectReason::DeliveryFailed);
    aether::test::require(peer.connections.empty());
    std::puts("strict delivery and explicit terminal reason OK");
}
