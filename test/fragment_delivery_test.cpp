#include "check.hpp"
#include "aether/testnet.hpp"
#include <cassert>
#include <cstdio>
using namespace aether;
int main() {
    NetworkConfig cfg;
    cfg.maxChannels = 1;
    cfg.enableMtuDiscovery = false;
    cfg.defaultChannelConfig.maxMessageSize = 4096;
    cfg.defaultChannelConfig.maxReceiveBufferSize = 1;
    cfg.maxReassemblyBufferSize = 2500;
    aether::test::require(validateConfig(cfg) == ConfigError::InvalidReassemblyBufferSize);
    cfg.maxReassemblyBufferSize = 5000;
    aether::test::require(!validateConfig(cfg));
    const PeerId remote{addrLocalhost(23001)};
    auto peer = newPeerState(addrLocalhost(23000), cfg, MonoTime{1});
    auto conn = newConnection(cfg, 1, MonoTime{1});
    markConnected(conn, MonoTime{1});
    peer.connections.emplace(remote, std::move(conn));
    auto& receiver = peer.connections.at(remote);
    auto& channel = receiver.channels[0];
    aether::test::require(onMessageReceived(channel, SequenceNum{0}, {1}, MonoTime{1}));
    auto tx = newChannel(ChannelId{0}, cfg.defaultChannelConfig);
    tx.localSeq = SequenceNum{1};
    const auto sent = channelSend(tx, Bytes(3000, 42), MonoTime{2});
    auto& message = tx.sendBuffer.at(sent.seq);
    const auto wires = buildMessageWires(cfg, ChannelId{0}, message);
    message.fragmentCount = wires.fragmentCount;
    aether::test::require(wires.wires.size() == 3);
    for (std::size_t i = 0; i < wires.wires.size(); ++i) {
        const auto& wire = wires.wires[i];
        const bool accepted = receiveChannelWire(peer, remote, receiver, wire.data, MonoTime{3});
        aether::test::require(accepted == (i < 2));
        if (accepted) acknowledgeMessage(tx, sent.seq, wire.fragIndex);
    }
    auto& assembler = peer.fragmentAssemblers.at(remote);
    const auto charge = assembler.currentSize;
    aether::test::require(charge > 3000 && charge <= 5000 && assembler.buffers.size() == 1);
    aether::test::require(!message.acked);
    auto competing = message;
    competing.sequence = SequenceNum{2};
    competing.fragAckBits = {};
    const auto otherWires = buildMessageWires(cfg, ChannelId{0}, competing);
    aether::test::require(!receiveChannelWire(peer, remote, receiver, otherWires.wires[0].data, MonoTime{4}));
    aether::test::require(assembler.currentSize == charge && assembler.buffers.size() == 1);
    aether::test::require(channelReceive(channel) == std::vector<Bytes>{{1}});
    const auto retry = buildMessageWires(cfg, ChannelId{0}, message);
    aether::test::require(retry.wires.size() == 1);
    const auto& final = retry.wires[0];
    aether::test::require(receiveChannelWire(peer, remote, receiver, final.data, MonoTime{5}));
    aether::test::require(assembler.buffers.empty() && assembler.currentSize == 0);
    aether::test::require(channelReceive(channel) == std::vector<Bytes>{Bytes(3000, 42)});
    // Lose the final ACK: retransmitting that fragment must ACK without allocating/re-delivering.
    aether::test::require(receiveChannelWire(peer, remote, receiver, final.data, MonoTime{6}));
    acknowledgeMessage(tx, sent.seq, final.fragIndex);
    aether::test::require(message.acked && channelReceive(channel).empty());
    aether::test::require(assembler.buffers.empty());

    // An ACKed partial assembly is never silently evicted by its idle deadline.
    aether::test::require(receiveChannelWire(peer, remote, receiver, otherWires.wires[0].data, MonoTime{7}));
    const auto retained = assembler.currentSize;
    cleanupFragments(assembler, MonoTime{6000000000});
    aether::test::require(assembler.currentSize == retained);
    updateConnections(peer, MonoTime{6000000000});
    aether::test::require(receiver.state == ConnectionState::Disconnecting);
    aether::test::require(receiver.disconnectReason == DisconnectReason::DeliveryFailed);

    // Duplicates at the raw byte cap do not evict useful unacknowledged reassembly either.
    auto raw = newFragmentAssembler(5000, 243, 8);
    Bytes piece(7, 1);
    writeFragmentHeader(piece.data(), {MessageId{1}, 0, 3});
    processFragment(raw, piece.data(), piece.size(), MonoTime{1});
    piece[4] = 1;
    processFragment(raw, piece.data(), piece.size(), MonoTime{2});
    writeFragmentHeader(piece.data(), {MessageId{2}, 0, 3});
    processFragment(raw, piece.data(), piece.size(), MonoTime{3});
    writeFragmentHeader(piece.data(), {MessageId{1}, 0, 3});
    processFragment(raw, piece.data(), piece.size(), MonoTime{4});
    aether::test::require(raw.buffers.at(MessageId{1}).fragments.size() == 2 && raw.currentSize == 243);

    // Real peers: capacity for one assembly, a one-message receive queue, loss and ACK loss.
    for (std::uint64_t seed = 1; seed <= 4; ++seed) {
        auto config = cfg;
        config.fragmentTimeoutMs = 30000;
        const PeerId a{addrLocalhost(23002)}, b{addrLocalhost(23003)};
        auto server = newPeerState(a.addr, config, MonoTime{1});
        auto client = newPeerState(b.addr, config, MonoTime{1});
        auto link = newTestLink(server, a, client, b);
        peerConnect(client, a, MonoTime{1});
        auto now = testLinkConnect(link, MonoTime{1}, 16000000, 400);
        aether::test::require(peerIsConnected(server, b) && peerIsConnected(client, a));
        link.rng = seed;
        testLinkImpair(link, {.lossRate=.2, .latencyNs=10000000, .jitterNs=20000000,
                             .duplicateChance=.2, .outOfOrderChance=.2});
        for (int i = 0; i < 8; ++i) aether::test::require(!peerSend(client, a, ChannelId{0}, Bytes(3000, static_cast<std::uint8_t>(i)), now));
        int delivered = 0;
        for (int tick = 0; tick < 4000; ++tick) {
            now.ns += 16000000;
            auto step = testLinkStep(link, now);
            aether::test::require(!testHasEvent(step.aEvents, PeerEvent::Disconnected));
            aether::test::require(!testHasEvent(step.bEvents, PeerEvent::Disconnected));
            for (const auto& event : step.aEvents) if (event.kind == PeerEvent::Message) {
                aether::test::require(event.data == Bytes(3000, static_cast<std::uint8_t>(delivered)));
                ++delivered;
                aether::test::require(delivered <= 8);
            }
            if (delivered == 8 && client.connections.at(a).channels[0].sendBuffer.empty()) break;
        }
        aether::test::require(delivered == 8 && client.connections.at(a).channels[0].sendBuffer.empty());
        aether::test::require(client.connections.at(a).stats.reliableDropped == 0);
    }
    std::puts("fragment retention, backpressure, ACK loss and bounded recovery OK");
}
