#include "check.hpp"
#include <aether/aether.hpp>

using namespace aether;
using aether::test::require;

namespace {
constexpr std::uint64_t ms = 1000000;
const PeerId server{addrLocalhost(18001)}, client{addrLocalhost(18002)}, attacker{addrLocalhost(18003)};

Packet control(PacketType type, Bytes payload = {}) { return {PacketHeader{type}, std::move(payload)}; }
Packet take(const PeerProcessResult& result, PacketType type) {
    for (const auto& raw : result.outgoing) {
        const auto data = validateAndStripCrc32(raw.data);
        require(data);
        const auto packet = deserializePacket(*data);
        if (packet && packet->header.type == type) return *packet;
    }
    require(false);
    return {};
}

struct Fixture {
    EncryptionKey key{};
    NetworkConfig cfg;
    ConnectCredential credential;
    NetPeer s, c;
    MonoTime now{ms};
    UnixTime wall{ms};
    Fixture() {
        secureRandomBytes(key.data(), key.size());
        cfg.tokenKey = key;
        cfg.tokenAudience = 42;
        cfg.connectionRequestTimeoutMs = 1500;
        cfg.connectionRequestMaxRetries = 12;
        cfg.rateLimitPerSecond = 10000;
        credential = issueConnectCredential(key, ConnectToken{77, UnixTime{3600ull * 1000 * ms}, {1, 2, 3}, {cfg.protocolId, cfg.tokenAudience}});
        s = newPeerState(server.addr, cfg, now);
        auto clientCfg = cfg;
        clientCfg.tokenKey.reset();
        c = newPeerState(client.addr, clientCfg, now);
    }
    PeerProcessResult deliver(NetPeer& peer, const PeerId& from, const Packet& packet) {
        now.ns += ms;
        return peerProcess(peer, now, {{from, serializePacket(packet)}}, wall);
    }
    Packet start() {
        require(!peerConnectWithToken(c, server, credential, now));
        return take(peerProcess(c, now, {}, wall), PacketType::ConnectionRequest);
    }
    Packet challenge(const Packet& first, const PeerId& from = client) {
        auto retry = take(deliver(s, from, first), PacketType::ConnectionRetry);
        const auto request = decodeConnectionRequest(first.payload);
        require(request);
        return take(deliver(s, from, control(PacketType::ConnectionRequest,
                    encodeConnectionRequest(retry.payload, request->body))), PacketType::ConnectionChallenge);
    }
    Packet response(const Packet& challengePacket) {
        return take(deliver(c, server, challengePacket), PacketType::ConnectionResponse);
    }
    void finish(const Packet& responsePacket, bool resume = false) {
        const auto result = deliver(s, client, responsePacket);
        require(testHasEvent(result.events, resume ? PeerEvent::Reconnected : PeerEvent::Connected));
        require(result.events.front().playerId == 77 && result.events.front().userData == Bytes({1, 2, 3}));
        const auto acceptance = take(result, PacketType::ConnectionAccepted);
        require(testHasEvent(deliver(c, server, acceptance).events, resume ? PeerEvent::Reconnected : PeerEvent::Connected));
        require(c.connections.at(server).authenticated && s.connections.at(client).authenticated);
        require(c.connections.at(server).sendKey == s.connections.at(client).recvKey);
        require(c.connections.at(server).recvKey == s.connections.at(client).sendKey);
        require(c.connections.at(server).sendKey != c.connections.at(server).recvKey);
        require(c.connections.at(server).resumeMaster == s.connections.at(client).resumeMaster);
    }
    void connect() { const auto first = start(); finish(response(challenge(first))); }
    std::uint64_t drop() {
        const auto token = *peerSessionToken(c, server);
        now.ns += 11000 * ms;
        peerProcess(c, now, {}, wall);
        peerProcess(s, now, {}, wall);
        require(c.connections.empty() && s.connections.empty());
        require(c.resumableTokens.count(token) && s.resumableTokens.count(token));
        return token;
    }
};
}

int main() try {
    // Secure defaults, strict credential shapes and scope are visible API errors.
    {
        Fixture f;
        require(peerConnect(f.c, server, f.now) == ConnectError::AuthenticationRequired);
        require(f.c.pending.empty() && f.c.sendQueue.empty());
        auto invalid = f.credential;
        invalid.scope.protocolId ^= 1;
        require(peerConnectWithToken(f.c, server, invalid, f.now) == ConnectError::InvalidCredential);
        invalid = f.credential; invalid.proofKey.fill(0);
        require(peerConnectWithToken(f.c, server, invalid, f.now) == ConnectError::InvalidCredential);
        require(peerConnectWithToken(f.c, PeerId{}, f.credential, f.now) == ConnectError::InvalidAddress);
        const auto other = issueConnectCredential(f.key, ConnectToken{77, f.credential.expiresAt, {}, f.credential.scope});
        require(other.proofKey != f.credential.proofKey);
    }
    // Observing a token is not enough: changing any byte of its bound request fails before allocation.
    {
        Fixture f;
        const auto first = f.start();
        for (std::size_t i = 1; i < first.payload.size(); ++i) {
            auto bad = first; bad.payload[i] ^= 0x80;
            const auto result = f.deliver(f.s, attacker, bad);
            require(result.events.empty() && result.outgoing.empty());
            require(f.s.pending.empty() && f.s.tokenValidator.usedNonces.empty());
        }
        f.s.config.tokenAudience++;
        require(f.deliver(f.s, client, first).outgoing.empty());
        f.s.config.tokenAudience--;
        require(f.deliver(f.s, attacker, control(PacketType::ConnectionRequest,
                encodeConnectionRequest({}, f.credential.token))).outgoing.empty()); // legacy bearer token
    }
    // Plaintext Accepted/Denied, a forged challenge and an incorrect confirmation never abort or connect.
    {
        Fixture f;
        const auto first = f.start();
        require(f.deliver(f.c, server, control(PacketType::ConnectionDenied, {3})).events.empty());
        require(f.deliver(f.c, server, control(PacketType::ConnectionAccepted)).events.empty());
        require(f.c.pending.count(server) == 1);
        const auto challenge = f.challenge(first);
        require(f.s.tokenValidator.usedNonces.empty());
        auto fake = challenge; fake.payload.back() ^= 1;
        require(f.deliver(f.c, server, fake).outgoing.empty());
        const auto response = f.response(challenge);
        require(f.deliver(f.c, server, control(PacketType::ConnectionAccepted)).events.empty());
        auto wrongProof = response; wrongProof.payload.back() ^= 1;
        require(f.deliver(f.s, client, wrongProof).events.empty());
        require(f.s.connections.empty() && f.s.tokenValidator.usedNonces.empty());
        f.finish(response);
        require(f.s.tokenValidator.usedNonces.size() == 1);
        // Lost acceptance: repeated requests/responses recover without a second event or token spend.
        const auto repeat = f.deliver(f.s, client, response);
        require(repeat.events.empty());
        require(take(repeat, PacketType::ConnectionAccepted).payload.size() == authReplyPrefixBytes + 32);
        require(f.deliver(f.s, client, first).events.empty());
    }
    // A short forged Retry/challenge burst cannot permanently spend the real client's
    // work budget. It recovers after the bounded work interval without a new attempt.
    {
        Fixture f;
        const auto first = f.start();
        for (std::uint8_t i = 1; i <= 3; ++i)
            f.deliver(f.c, server, control(PacketType::ConnectionRetry, Bytes(retryCookieSize, i)));
        const auto retry = take(f.deliver(f.s, client, first), PacketType::ConnectionRetry);
        require(f.deliver(f.c, server, retry).outgoing.empty());
        f.now.ns += 150 * ms;
        const auto request = take(f.deliver(f.c, server, retry), PacketType::ConnectionRequest);
        const auto challenge = take(f.deliver(f.s, client, request), PacketType::ConnectionChallenge);
        for (int i = 0; i < 3; ++i) {
            auto bad = challenge; bad.payload.back() ^= 1;
            require(f.deliver(f.c, server, bad).outgoing.empty());
        }
        f.now.ns += 150 * ms;
        f.finish(f.response(challenge));
    }
    // A copied valid request sent from another address cannot spend the credential with a copied response.
    {
        Fixture f;
        const auto first = f.start();
        const auto attackerChallenge = f.challenge(first, attacker);
        const auto honestChallenge = f.challenge(first);
        require(attackerChallenge.payload != honestChallenge.payload);
        const auto response = f.response(honestChallenge);
        require(f.deliver(f.s, attacker, response).events.empty());
        require(f.s.tokenValidator.usedNonces.empty());
        f.finish(response);
        require(!peerIsConnected(f.s, attacker));
    }
    // Expiry is checked at completion, even if the wall clock later moves backwards.
    {
        Fixture f;
        const auto first = f.start();
        const auto response = f.response(f.challenge(first));
        f.wall = f.credential.expiresAt;
        const auto rejected = f.deliver(f.s, client, response);
        require(f.s.connections.empty() && f.s.tokenValidator.usedNonces.empty());
        const auto denial = take(rejected, PacketType::ConnectionDenied);
        require(testHasEvent(f.deliver(f.c, server, denial).events, PeerEvent::Disconnected));
        f.wall.ns = 1;
        require(take(f.deliver(f.s, client, first), PacketType::ConnectionDenied).payload.size() == authReplyPrefixBytes + 33);
    }
    // A slot lost while proof was in flight leaves the credential usable when capacity returns.
    {
        Fixture f;
        const auto first = f.start();
        const auto response = f.response(f.challenge(first));
        f.s.config.maxClients = 1;
        f.s.connections.emplace(attacker, newConnection(f.cfg, 99, f.now));
        take(f.deliver(f.s, client, response), PacketType::ConnectionDenied);
        require(f.s.tokenValidator.usedNonces.empty());
        f.s.connections.clear();
        f.c.pending.clear();
        const auto again = f.start();
        f.finish(f.response(f.challenge(again)));
    }
    // Fresh reconnect proofs bind both ephemeral keys. Captured attempts cannot win a race,
    // consume the cached secret, or reproduce the next generation's traffic keys.
    {
        Fixture f; f.connect();
        const auto oldKey = f.c.connections.at(server).sendKey;
        const auto token = f.drop();
        const auto oldMaster = f.s.resumableTokens.at(token).master;
        require(!peerReconnect(f.c, server, token, f.now));
        const auto first = take(peerProcess(f.c, f.now, {}, f.wall), PacketType::ConnectionRequest);
        const auto attackerChallenge = f.challenge(first, attacker);
        const auto honestChallenge = f.challenge(first);
        require(attackerChallenge.payload != honestChallenge.payload);
        const auto response = f.response(honestChallenge);
        require(f.deliver(f.s, attacker, response).events.empty());
        require(f.s.resumableTokens.at(token).master == oldMaster);
        f.finish(response, true);
        require(f.s.connections.at(client).pathValidated);
        require(f.c.connections.at(server).sendKey != oldKey);
        require(f.c.connections.at(server).resumeMaster != oldMaster);
        f.s.pending.erase(attacker);
        f.drop();
        require(f.deliver(f.s, attacker, first).outgoing.empty());
        require(f.s.pending.empty() && f.s.resumableTokens.count(token));
    }
    // Authenticated handshake plus reliable gameplay messages under loss, latency and duplicates.
    for (std::uint64_t seed = 1; seed <= 8; ++seed) {
        Fixture f;
        f.c.config.connectionRequestTimeoutMs = f.s.config.connectionRequestTimeoutMs = 10000;
        f.c.config.connectionRequestMaxRetries = 40;
        require(!peerConnectWithToken(f.c, server, f.credential, f.now));
        auto link = newTestLink(f.c, client, f.s, server);
        link.rng = seed;
        testLinkImpair(link, {.lossRate=.15, .latencyNs=35*ms, .jitterNs=15*ms,
                             .duplicateChance=.2, .outOfOrderChance=.2, .maxDatagramBytes=576});
        auto t = testLinkConnect(link, f.now, 10*ms, 1000);
        require(peerIsConnected(f.c, server) && peerIsConnected(f.s, client));
        const Bytes message{7, 8, 9};
        require(!peerSend(f.c, server, ChannelId{0}, message, t));
        bool received = false;
        testLinkRun(link, t, 10*ms, 500, [&](const TestLinkStep& step) {
            for (const auto& event : step.bEvents) if (event.kind == PeerEvent::Message) {
                require(event.data == message); received = true;
            }
            return received;
        });
        require(received);
    }
    // Server restart: a fresh credential is used only after our local resume deadline.
    {
        Fixture f; f.connect();
        const auto token = f.drop();
        f.s.resumableTokens.clear();
        auto replacement = issueConnectCredential(f.key, ConnectToken{77, f.credential.expiresAt, {1,2,3}, f.credential.scope});
        require(!peerReconnect(f.c, server, token, f.now, replacement));
        require(f.deliver(f.c, server, control(PacketType::ConnectionDenied, {3})).events.empty());
        require(f.c.pending.at(server).isReconnect);
        auto link = newTestLink(f.c, client, f.s, server);
        testLinkConnect(link, f.now, 10*ms, 1000);
        require(peerIsConnected(f.c, server) && peerIsConnected(f.s, client));
        require(peerPlayerId(f.s, client) == 77);
    }
    std::puts("session_auth_test: scoped admission, proof, expiry, replay races, fresh resume, loss and fallback passed");
}
 catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
