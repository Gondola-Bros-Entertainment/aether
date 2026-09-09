#include "check.hpp"
// Count key-generation work at the random-source boundary; invalid keys must spend the quota.
#define secureRandomBytes handshakeTestRandomBytes
#include "aether/peer.hpp"
#undef secureRandomBytes
#include <cassert>
#include <cstdio>
namespace aether {
void secureRandomBytes(std::uint8_t*, std::size_t);
static int randomCalls = 0;
void handshakeTestRandomBytes(std::uint8_t* out, std::size_t count) {
    ++randomCalls;
    secureRandomBytes(out, count);
}
}
int main() {
    using namespace aether;
    const PeerId remote{addrLocalhost(18001)};
    auto peer = newPeerState(addrLocalhost(18000), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{1});
    peerConnect(peer, remote, MonoTime{1});
    Packet invalid{PacketHeader{PacketType::ConnectionChallenge, {}, {}, 0}, encodeSaltAndKey(42, X25519Key{})};
    const int before = randomCalls;
    for (int n = 0; n < 100; ++n) handleConnectionChallenge(peer, remote, invalid, MonoTime{2});
    aether::test::require(randomCalls - before == maxChallengeKeyAttempts);
    aether::test::require(peer.pending.at(remote).challengeKeyAttempts == maxChallengeKeyAttempts);
    aether::test::require(!peer.pending.at(remote).ephemeralReady);
    // Retrying an already accepted challenge still works after the remaining work budget is spent.
    peer = newPeerState(addrLocalhost(18000), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{1});
    peerConnect(peer, remote, MonoTime{1});
    X25519Key priv{}, pub{};
    genEphemeralKeypair(priv, pub);
    Packet valid{PacketHeader{PacketType::ConnectionChallenge, {}, {}, 0}, encodeSaltAndKey(43, pub)};
    handleConnectionChallenge(peer, remote, valid, MonoTime{2});
    for (int n = 0; n < 100; ++n) handleConnectionChallenge(peer, remote, invalid, MonoTime{3});
    const auto queued = peer.sendQueue.size();
    const auto calls = randomCalls;
    handleConnectionChallenge(peer, remote, valid, MonoTime{4});
    aether::test::require(peer.sendQueue.size() == queued + 1 && randomCalls == calls);
    std::puts("handshake work bounded across invalid keys and valid retransmission OK");
}
