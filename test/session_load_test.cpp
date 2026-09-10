#include "check.hpp"
#include <aether/aether.hpp>
#include <chrono>

using namespace aether;
using aether::test::require;

int main() try {
    const auto started = std::chrono::steady_clock::now();
    constexpr std::size_t count = 64;
    const PeerId serverId{addrLocalhost(18999)};
    EncryptionKey issuer{};
    secureRandomBytes(issuer.data(), issuer.size());
    NetworkConfig config;
    config.tokenKey = issuer;
    config.tokenAudience = 1;
    config.rateLimitPerSecond = 1024; // explicit same-host burst profile
    auto server = newPeerState(serverId.addr, config, MonoTime{1});
    config.tokenKey.reset();
    std::vector<NetPeer> clients;
    clients.reserve(count);
    std::array<std::vector<IncomingPacket>, count> inboxes;
    std::array<bool, count> sent{}, received{};
    std::size_t requests = 0, replies = 0;
    for (std::size_t i = 0; i < count; ++i) {
        const auto credential = issueConnectCredential(issuer, {i + 1, UnixTime{100000000000ull}, {}, {config.protocolId, 1}});
        clients.push_back(newPeerState(addrLocalhost(static_cast<std::uint16_t>(19000 + i)), config, MonoTime{1}));
        require(!peerConnectWithToken(clients.back(), serverId, credential, MonoTime{1}));
    }
    for (std::uint64_t tick = 1; tick <= 2000 && replies < count; ++tick) {
        const MonoTime now{tick * 1000000};
        std::vector<IncomingPacket> incoming;
        for (std::size_t i = 0; i < count; ++i) {
            auto& client = clients[i];
            const auto result = peerProcess(client, now, inboxes[i], UnixTime{now.ns});
            inboxes[i].clear();
            for (const auto& event : result.events) {
                if (event.kind == PeerEvent::Connected && !sent[i]) {
                    require(!peerSend(client, serverId, ChannelId{0}, Bytes(32, static_cast<std::uint8_t>(i + 1)), now));
                    sent[i] = true;
                } else if (event.kind == PeerEvent::Message) {
                    require(!received[i] && event.data == Bytes(32, static_cast<std::uint8_t>(i + 1)));
                    received[i] = true;
                    ++replies;
                }
            }
            for (const auto& packet : result.outgoing) {
                const auto stripped = validateAndStripCrc32(packet.data); require(stripped);
                incoming.push_back({PeerId{client.localAddr}, *stripped});
            }
        }
        const auto result = peerProcess(server, now, incoming, UnixTime{now.ns});
        for (const auto& event : result.events) if (event.kind == PeerEvent::Message) {
            const auto identity = peerPlayerId(server, event.peer); require(identity);
            require(event.data == Bytes(32, static_cast<std::uint8_t>(*identity)));
            require(!peerSend(server, event.peer, event.channel, event.data, now));
            ++requests;
        }
        for (const auto& packet : result.outgoing) {
            const auto index = static_cast<std::size_t>(addrPort(packet.to.addr) - 19000);
            require(index < count);
            const auto stripped = validateAndStripCrc32(packet.data); require(stripped);
            inboxes[index].push_back({serverId, *stripped});
        }
        require(server.pending.size() <= static_cast<std::size_t>(server.config.maxPending));
        require(server.connections.size() <= count);
    }
    require(requests == count && replies == count && peerCount(server) == static_cast<int>(count));
    require(server.tokenValidator.usedNonces.size() == count);
    // Cached generations are bounded, and disabled caching retains no timeout secrets.
    server.config.maxResumableSessions = 8;
    peerProcess(server, MonoTime{20000000000ull}, {});
    require(server.resumableTokens.size() == 8);
    const auto elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    std::printf("session_load_test: 64 authenticated peers, 128 reliable 32-byte messages, %.1f ms wall time\n", elapsed);
} catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what()); return 1;
}
