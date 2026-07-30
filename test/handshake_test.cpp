// aether - handshake security properties, pinned after an audit found both of them broken.
//
//  1. The connection challenge is a RETURN-ROUTABILITY proof. The server's challenge salt was sent
//     and stored but never echoed or verified, so a peer that never received the challenge still
//     completed the handshake -- a source-spoofing flood could fill every client slot with
//     connections to addresses that do not exist. The echo closes that, and a WRONG echo must be
//     dropped silently: replying would make the server a reflector, and cancelling the pending would
//     let anyone who can guess an in-flight client's address abort its handshake.
//
//  2. The connect-token identity survives a fast reconnect. The resume path rebuilt the connection
//     without it, so a resumed session came up anonymous on a token-gated server with no way to
//     recover who the player was.
#include <aether/aether.hpp>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

using namespace aether;

namespace {

// One cleartext control packet from `from`, as peerProcess consumes it (CRC already stripped).
IncomingPacket control(const PeerId& from, PacketType type, const Bytes& payload) {
    const PacketHeader header{ type, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    return IncomingPacket{ from, serializePacket(Packet{ header, payload }) };
}

// The serverSalt the server put in the challenge it queued for `pid`.
std::uint64_t challengeSaltFor(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.pending.find(pid);
    assert(it != peer.pending.end());
    return it->second.serverSalt;
}

constexpr std::uint64_t tickNs = 1000000;   // 1ms

} // namespace

int main() {
    // --- 1a. a response that never saw the challenge is rejected, and does NOT burn the pending ---
    {
        const Address addrS = addrLocalhost(9401), addrA = addrLocalhost(9402);
        const PeerId  idA{ addrA };
        NetPeer S = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });

        std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, {}) };
        const auto challenge = peerProcess(S, MonoTime{ 1000000 }, in);
        assert(challenge.outgoing.size() == 1);          // the server answered with a challenge
        assert(S.pending.count(idA) == 1);               // ...and opened a pending for it

        // Respond blind: a well-formed response carrying a serverSalt echo we could not have known.
        X25519Key priv{}, pub{};
        genEphemeralKeypair(priv, pub);
        const std::uint64_t realSalt  = challengeSaltFor(S, idA);
        const std::uint64_t wrongSalt = realSalt ^ 1ull;   // off by one bit: still a pure guess
        std::vector<IncomingPacket> blind{
            control(idA, PacketType::ConnectionResponse, encodeConnectionResponse(0xDEADBEEFCAFEull, pub, wrongSalt)) };
        const auto after = peerProcess(S, MonoTime{ 2000000 }, blind);

        assert(!peerIsConnected(S, idA));                // no connection slot committed
        for (const auto& e : after.events) assert(e.kind != PeerEvent::Connected);
        assert(after.outgoing.empty());                  // silent drop -- not a reflector
        assert(S.pending.count(idA) == 1);               // the real client's handshake is untouched
        std::printf("handshake_test: blind response rejected, no reply, pending survives\n");

        // The SAME peer, now echoing correctly, completes -- proving the gate is the echo and not
        // some unrelated rejection.
        std::vector<IncomingPacket> good{
            control(idA, PacketType::ConnectionResponse, encodeConnectionResponse(0xDEADBEEFCAFEull, pub, realSalt)) };
        const auto ok = peerProcess(S, MonoTime{ 3000000 }, good);
        bool connected = false;
        for (const auto& e : ok.events) if (e.kind == PeerEvent::Connected) connected = true;
        assert(connected && peerIsConnected(S, idA));
        std::printf("handshake_test: correct echo completes the handshake\n");
    }

    // --- 1b. a real client/server pair still handshakes end to end over the new response wire ---
    {
        const Address addrS = addrLocalhost(9411), addrC = addrLocalhost(9412);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, NetworkConfig{}, MonoTime{ 0 });
        peerConnect(C, idS, MonoTime{ 0 });

        TestLink link = newTestLink(C, idC, S, idS);
        testLinkConnect(link, MonoTime{ 0 }, tickNs, 24);
        assert(peerIsConnected(S, idC) && peerIsConnected(C, idS));
        std::printf("handshake_test: full challenge/response handshake still completes both ways\n");
    }

    // --- 1c. ...and it completes over a link that loses, delays, duplicates and reorders ---
    // The handshake is four cleartext round-trips with its own retry timer; impairing every one of them
    // at once is the case a clean-loopback test never reaches.
    {
        const Address addrS = addrLocalhost(9431), addrC = addrLocalhost(9432);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, NetworkConfig{}, MonoTime{ 0 });
        peerConnect(C, idS, MonoTime{ 0 });

        TestLink link = newTestLink(C, idC, S, idS);
        testLinkImpair(link, TestLinkConfig{ .lossRate = 0.3, .latencyNs = 20 * tickNs, .jitterNs = 5 * tickNs,
                                             .duplicateChance = 0.1, .outOfOrderChance = 0.1 });
        testLinkConnect(link, MonoTime{ 0 }, tickNs, 4000);
        assert(peerIsConnected(S, idC) && peerIsConnected(C, idS));
        std::printf("handshake_test: handshake completes through 30%% loss + 20ms latency + jitter + dups + reorder\n");
    }

    // --- 1d. an abandoned INBOUND handshake expires quietly ---
    // A half-open handshake that never completes is a peer that walked away (or a spoofed source that was
    // never there). Reporting Disconnected for it told the server a peer it never had a connection with
    // had disconnected -- one bogus event per abandoned handshake, and a spoof flood is all of them.
    {
        const Address addrS = addrLocalhost(9441);
        NetPeer S = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
        const PeerId ghost{ addrLocalhost(9442) };

        std::vector<IncomingPacket> in{ control(ghost, PacketType::ConnectionRequest, {}) };
        peerProcess(S, MonoTime{ tickNs }, in);
        assert(S.pending.count(ghost) == 1);

        const std::uint64_t past = static_cast<std::uint64_t>(S.config.connectionRequestTimeoutMs) * tickNs * 2;
        const auto expired = peerProcess(S, MonoTime{ past }, {});
        assert(S.pending.empty());                              // swept
        for (const auto& e : expired.events) assert(e.kind != PeerEvent::Disconnected);

        // A client's OWN failed connect still reports the timeout -- that one the caller is waiting for.
        NetPeer C = newPeerState(addrLocalhost(9443), NetworkConfig{}, MonoTime{ 0 });
        const PeerId dead{ addrLocalhost(9444) };               // nothing is listening
        peerConnect(C, dead, MonoTime{ 0 });
        bool timedOut = false;
        const auto attempt = peerProcess(C, MonoTime{ past }, {});   // named: a range-for over a temporary's
        for (const auto& e : attempt.events)                         // member does not extend its lifetime
            if (e.kind == PeerEvent::Disconnected && e.reason == DisconnectReason::Timeout) timedOut = true;
        assert(timedOut);
        std::printf("handshake_test: abandoned inbound handshake expires silently, outbound reports its timeout\n");
    }

    // --- 1e. maxClients holds at the moment connections are ADMITTED, not just when requested ---
    // The cap was checked at the request and then the response inserted unconditionally, so every
    // handshake already in flight when the last slot filled still became a connection.
    {
        NetworkConfig cfg;
        cfg.maxClients = 2;
        const Address addrS = addrLocalhost(9451);
        NetPeer S = newPeerState(addrS, cfg, MonoTime{ 0 });

        constexpr int clients = 6;
        std::vector<PeerId>    ids;         ids.reserve(clients);
        std::vector<X25519Key> pubs;        pubs.reserve(clients);
        std::vector<IncomingPacket> requests; requests.reserve(clients);
        for (int i = 0; i < clients; ++i) {
            ids.push_back(PeerId{ addrLocalhost(static_cast<std::uint16_t>(9460 + i)) });
            X25519Key priv{}, pub{};
            genEphemeralKeypair(priv, pub);
            pubs.push_back(pub);
            requests.push_back(control(ids.back(), PacketType::ConnectionRequest, {}));
        }
        peerProcess(S, MonoTime{ tickNs }, requests);            // all challenged in one tick: 6 pendings, 0 connections
        assert(S.pending.size() == clients);

        std::vector<IncomingPacket> responses;                  // ...then every one of them responds at once
        responses.reserve(clients);
        for (int i = 0; i < clients; ++i)
            responses.push_back(control(ids[static_cast<std::size_t>(i)], PacketType::ConnectionResponse,
                                        encodeConnectionResponse(0x1000ull + static_cast<std::uint64_t>(i),
                                                                 pubs[static_cast<std::size_t>(i)],
                                                                 challengeSaltFor(S, ids[static_cast<std::size_t>(i)]))));
        peerProcess(S, MonoTime{ 2 * tickNs }, responses);
        assert(peerCount(S) == cfg.maxClients);                 // held at 2, not 6
        std::printf("handshake_test: maxClients holds at admission (%d of %d responses accepted)\n",
                    peerCount(S), clients);
    }

    // --- 2. the verified connect-token identity survives a fast reconnect ---
    {
        EncryptionKey K{};
        secureRandomBytes(K.data(), K.size());
        NetworkConfig serverCfg;  serverCfg.tokenKey = K;

        const Address addrS = addrLocalhost(9421), addrC = addrLocalhost(9422);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, serverCfg, MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, NetworkConfig{}, MonoTime{ 0 });

        constexpr std::uint64_t player = 424242;
        const Bytes token = sealConnectToken(K, ConnectToken{ player, MonoTime{ 3600ull * 1000000000ull }, {} });
        peerConnectWithToken(C, idS, token, MonoTime{ 0 });

        TestLink      link        = newTestLink(C, idC, S, idS);
        std::uint64_t connectedAs = 0;
        MonoTime      t = testLinkRun(link, MonoTime{ 0 }, tickNs, 24, [&](const TestLinkStep& s) {
            for (const PeerEvent& e : s.bEvents) if (e.kind == PeerEvent::Connected) connectedAs = e.playerId;
            return connectedAs != 0 && peerIsConnected(C, idS);   // the client is keyed one tick after the server
        });
        assert(connectedAs == player);
        assert(peerPlayerId(S, idC) == player);
        const auto sessionToken = peerSessionToken(C, idS);
        assert(sessionToken.has_value());

        // Blackhole the link so both ends time out and stash a resumable session.
        for (int k = 0; k < 30; ++k) {
            t = MonoTime{ t.ns + 1000000000ull };   // 1s per step, past the 10s connection timeout
            peerProcess(C, t, {});
            peerProcess(S, t, {});
        }
        assert(peerCount(S) == 0 && peerCount(C) == 0);

        peerReconnect(C, idS, *sessionToken, t);
        std::uint64_t reconnectedAs = 0;
        bool          resumed       = false;
        testLinkRun(link, t, tickNs, 24, [&](const TestLinkStep& s) {
            for (const PeerEvent& e : s.bEvents)
                if (e.kind == PeerEvent::Reconnected) { resumed = true; reconnectedAs = e.playerId; }
            return resumed;
        });
        assert(resumed);                                  // it took the 0-RTT resume path, not a full handshake
        assert(reconnectedAs == player);                  // ...and the event carries the identity
        assert(peerPlayerId(S, idC) == player);           // ...as does the connection itself
        std::printf("handshake_test: connect-token identity %llu survives the fast reconnect\n",
                    static_cast<unsigned long long>(player));
    }

    std::printf("handshake_test: return-routability, impaired-link handshake, quiet pending expiry, "
                "admission cap, reconnect identity OK\n");
    return 0;
}
