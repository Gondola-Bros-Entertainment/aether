#include "check.hpp"
#include "aether/peer.hpp"

#include <cassert>

int main() {
    using namespace aether;
    const NetworkConfig config;
    const PeerId other{addrV4(0x0A000001, 1000)}, original{addrV4(0x0A000002, 2000)};
    const PeerId rebound{addrV4(0x0A000003, 3000)};
    auto peer = newPeerState(addrLocalhost(4000), config, MonoTime{1});
    X25519Key master{}, otherMaster{};
    master.fill(42); otherMaster.fill(93);
    auto wrong = newConnection(config, 1, MonoTime{1});
    applySessionKeys(wrong, otherMaster, 1, true);
    markConnected(wrong, MonoTime{1});
    wrong.reliability.remoteSeq = SequenceNum{101};
    auto right = newConnection(config, 2, MonoTime{1});
    applySessionKeys(right, master, 2, true);
    markConnected(right, MonoTime{1});
    right.reliability.remoteSeq = SequenceNum{100};
    auto sender = newConnection(config, 2, MonoTime{1});
    applySessionKeys(sender, master, 2, false);
    aether::test::require(sender.connectionId == right.connectionId && right.connectionId != wrong.connectionId);
    const auto id = right.connectionId;
    peer.connections.emplace(other, std::move(wrong));
    peer.connections.emplace(original, std::move(right));
    PacketHeader header{PacketType::Payload, SequenceNum{101}, SequenceNum{0}, 0, id};
    auto frame = sealDatagram(*sender.sendKey, NonceCounter{1}, config.protocolId, header, Bytes{0, 0, 0, 42});
    auto packet = *validateAndStripCrc32(frame);
    const auto parsed = deserializePacket(packet);
    aether::test::require(parsed && parsed->header.connectionId == id);
    const auto candidate = findMigrationCandidate(peer, *parsed, MonoTime{2});
    aether::test::require(candidate && candidate->oldPeer == original);
    // The unrelated peer has an EXACT sequence match: it must not intercept the real migration.
    handlePacket(peer, rebound, packet, MonoTime{2});
    aether::test::require(peer.pathValidations.size() == 1 && peer.pathValidations.begin()->second.current == original);
    aether::test::require(peer.connections.count(original) == 1 && peer.connections.count(rebound) == 0); // still require path proof
    // The public ID cannot authorize traffic: changing it breaks the authenticated header.
    peer.pathValidations.clear();
    packet[9] ^= 1;
    handlePacket(peer, rebound, packet, MonoTime{3});
    aether::test::require(peer.pathValidations.empty());
    // Unsupported versions and truncated headers are rejected before dispatch.
    packet[8] &= 0xF0;
    aether::test::require(!deserializePacket(packet));
    aether::test::require(!deserializePacket(Bytes(16)));
    // A re-keyed resume changes the public identity as well as the traffic keys.
    applySessionKeys(sender, ratchetResumeMaster(master, 123), 123, false);
    aether::test::require(sender.connectionId != id);
}
