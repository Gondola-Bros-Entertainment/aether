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

// The stateless retry cookie the server mints for `from`. A raw-protocol test has to walk the same
// exchange a real client does: an uncookied request buys nothing but a cookie, and the server
// allocates no pending and no keypair until that cookie comes back.
Bytes retryCookieFor(NetPeer& S, const PeerId& from, MonoTime now) {
    std::vector<IncomingPacket> in{ control(from, PacketType::ConnectionRequest, encodeConnectionRequest({}, {})) };
    const auto r = peerProcess(S, now, in);
    assert(r.outgoing.size() == 1);
    assert(S.pending.count(from) == 0);   // nothing committed for an unproven address
    const auto stripped = validateAndStripCrc32(r.outgoing[0].data);
    assert(stripped);
    const auto pkt = deserializePacket(*stripped);
    assert(pkt && pkt->header.type == PacketType::ConnectionRetry);
    return pkt->payload;
}
// A ConnectionRequest carrying a freshly-earned cookie: the packet that actually reaches the keygen.
IncomingPacket cookiedRequest(NetPeer& S, const PeerId& from, const Bytes& body, MonoTime now) {
    const Bytes cookie = retryCookieFor(S, from, now);
    return control(from, PacketType::ConnectionRequest, encodeConnectionRequest(cookie, body));
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
    // --- 0. the stateless retry cookie: nothing is allocated for an unproven address ---
    //
    // A ConnectionRequest used to buy a half-open slot and an X25519 keypair from an address that had
    // proven nothing. The cookie moves both behind a round trip the server keeps no state for: it is
    // an AEAD tag over (source address, time epoch) under a per-peer secret, so it is unforgeable,
    // useless from any other address, and expires on its own.
    {
        const Address addrS = addrLocalhost(9301);
        NetPeer S = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
        const PeerId idA{ addrLocalhost(9302) }, idB{ addrLocalhost(9303) };

        // an uncookied request allocates nothing and yields only a cookie (asserted inside the helper)
        const Bytes cookie = retryCookieFor(S, idA, MonoTime{ 1000000 });
        assert(cookie.size() == retryCookieSize);
        assert(S.pending.empty());

        // the SAME cookie presented from a different source address is worthless: it is bound to the
        // address it was minted for, which is the whole point of proving routability
        {
            NetPeer S2 = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
            const Bytes forA = retryCookieFor(S2, idA, MonoTime{ 1000000 });
            std::vector<IncomingPacket> in{ control(idB, PacketType::ConnectionRequest, encodeConnectionRequest(forA, {})) };
            peerProcess(S2, MonoTime{ 2000000 }, in);
            assert(S2.pending.count(idB) == 0);   // no pending, no keygen: it just earned idB its own cookie
        }

        // a garbage cookie of the right length is rejected too (it is a MAC, not a length check)
        {
            NetPeer S3 = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
            const Bytes junk(retryCookieSize, 0xAB);
            std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, encodeConnectionRequest(junk, {})) };
            peerProcess(S3, MonoTime{ 2000000 }, in);
            assert(S3.pending.count(idA) == 0);
        }

        // the real cookie, from the address it was minted for, is what opens the pending
        {
            std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, encodeConnectionRequest(cookie, {})) };
            const auto r = peerProcess(S, MonoTime{ 2000000 }, in);
            assert(S.pending.count(idA) == 1);
            assert(r.outgoing.size() == 1);   // ...and now the challenge goes out
        }

        // and it expires: past two epochs the same cookie no longer validates
        {
            NetPeer S4 = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
            const Bytes old = retryCookieFor(S4, idA, MonoTime{ 1000000 });
            const MonoTime later{ 1000000 + cookieEpochNs * 3 };
            assert(!retryCookieValid(S4.cookieSecret, idA.addr, old, later));
            assert(retryCookieValid(S4.cookieSecret, idA.addr, old, MonoTime{ 1000000 }));       // still good in its own epoch
            assert(retryCookieValid(S4.cookieSecret, idA.addr, old, MonoTime{ 1000000 + cookieEpochNs }));   // and the next one
        }

        // a malformed request framing earns nothing at all -- not even a cookie to reflect
        {
            NetPeer S5 = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });
            std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, Bytes{}) };
            const auto r = peerProcess(S5, MonoTime{ 1000000 }, in);
            assert(r.outgoing.empty());
            assert(S5.pending.empty());
        }
        std::printf("aether retry-cookie OK: no pending or keygen until a valid, address-bound cookie comes back\n");
    }

    // --- 1a. a response that never saw the challenge is rejected, and does NOT burn the pending ---
    {
        const Address addrS = addrLocalhost(9401), addrA = addrLocalhost(9402);
        const PeerId  idA{ addrA };
        NetPeer S = newPeerState(addrS, NetworkConfig{}, MonoTime{ 0 });

        std::vector<IncomingPacket> in{ cookiedRequest(S, idA, {}, MonoTime{ 500000 }) };
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

        std::vector<IncomingPacket> in{ cookiedRequest(S, ghost, {}, MonoTime{ tickNs / 2 }) };
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
            // Distinct HOSTS, not distinct ports on one host: the per-source rate limit keys on the
            // address alone, so six ports off 127.0.0.1 would share a single bucket and the later ones
            // would be shed before they ever reached the admission cap this case is about.
            ids.push_back(PeerId{ addrV4(0x0A000001u + static_cast<std::uint32_t>(i), 9460) });
            X25519Key priv{}, pub{};
            genEphemeralKeypair(priv, pub);
            pubs.push_back(pub);
            requests.push_back(cookiedRequest(S, ids.back(), {}, MonoTime{ tickNs / 2 }));
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
        const X25519Key masterBefore = *S.connections.at(idC).resumeMaster;

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

        // The resumed session must NOT key from the master the previous one used. Every timeout re-arms
        // the resumable with whatever the connection holds, so leaving it unchanged made a captured
        // resume request valid again on the next generation -- and re-keying from it reproduced the
        // earlier session's keystream exactly, since a resumed connection restarts its nonce at 0.
        const X25519Key masterAfter = *S.connections.at(idC).resumeMaster;
        assert(masterAfter != masterBefore);              // the chain advanced, end to end

        // A resume authenticates the SENDER, never the address it claims to be at. So the resumed
        // connection comes up anti-amplification capped: a resume replayed with a victim's source
        // address must not buy the attacker seconds of our outbound aimed at that victim.
        assert(!S.connections.at(idC).pathValidated);
        assert(S.connections.at(idC).unvalidatedRecvBytes > 0);
        // The real client is genuinely there, so its first encrypted packet lifts the cap and 0-RTT is
        // unaffected -- it never waits for a round trip it would have had to pay for otherwise.
        testLinkRun(link, t, tickNs, 12, [&](const TestLinkStep&) {
            return S.connections.count(idC) && S.connections.at(idC).pathValidated;
        });
        assert(S.connections.at(idC).pathValidated);
        std::printf("handshake_test: connect-token identity %llu survives the fast reconnect\n",
                    static_cast<unsigned long long>(player));
    }

    // --- 2b. the anti-amplification cap itself ---
    {
        NetworkConfig cfg;
        Connection    c = newConnection(cfg, 7, MonoTime{ 0 });

        // A normally-handshaked connection is validated already: the cookie and the challenge echo both
        // proved routability before it existed, so the cap must never throttle it.
        assert(c.pathValidated);
        assert(amplificationAllowsSend(c, 1 << 20));

        // Unvalidated, the budget is a small multiple of what actually arrived -- and zero received
        // means zero sent, which is the spoofed-victim case.
        c.pathValidated        = false;
        c.unvalidatedRecvBytes = 0;
        c.unvalidatedSentBytes = 0;
        assert(!amplificationAllowsSend(c, 1));

        c.unvalidatedRecvBytes = 100;
        assert(amplificationAllowsSend(c, 300));          // exactly 3x is allowed
        assert(!amplificationAllowsSend(c, 301));         // past it is not
        c.unvalidatedSentBytes = 300;
        assert(!amplificationAllowsSend(c, 1));           // budget spent

        markPathValidated(c);                             // proof arrived -> uncapped again
        assert(c.pathValidated);
        assert(amplificationAllowsSend(c, 1 << 20));
        std::printf("handshake_test: unvalidated paths are amplification-capped\n");
    }

    // --- 3. a spent resume cannot be replayed into a second session ---
    {
        X25519Key master{};
        secureRandomBytes(master.data(), master.size());
        constexpr std::uint64_t token = 0xA1B2C3D4E5F60718ull;
        constexpr std::uint64_t salt  = 0x0011223344556677ull;

        const auto captured = resumeMac(master, token, salt);   // what an observer records off the wire
        assert(detail::constTimeEq(resumeMac(master, token, salt).data(), captured.data(), 16));

        // Accepting the resume advances the master, and the advanced value is what a later timeout
        // re-arms the resumable with.
        const X25519Key next = ratchetResumeMaster(master, salt);
        assert(next != master);

        // So presenting the captured bytes a second time no longer authenticates.
        assert(!detail::constTimeEq(resumeMac(next, token, salt).data(), captured.data(), 16));

        // And even if it somehow did, it could not reproduce the keystream: the session keys derive
        // from the advanced secret, so no two sessions share a (key, nonce) pair. That reuse is what
        // turned a replay into a two-time pad -- XOR of the two ciphertexts recovered the plaintext.
        const DirectionalKeys k1 = deriveDirectionalKeys(master, salt);
        const DirectionalKeys k2 = deriveDirectionalKeys(next, salt);
        assert(k1.serverToClient != k2.serverToClient);
        assert(k1.clientToServer != k2.clientToServer);

        // The ratchet is deterministic and salt-bound: both peers must land on the same value from the
        // same salt, or the resumed session would fail to decrypt.
        assert(ratchetResumeMaster(master, salt) == next);
        assert(ratchetResumeMaster(master, salt + 1) != next);
        std::printf("handshake_test: a spent resume cannot be replayed; the master ratchets\n");
    }

    // --- 4. the per-source rate limit keys on the HOST, not the (host, port) pair ---
    {
        NetPeer P = newPeerState(addrLocalhost(9500), NetworkConfig{}, MonoTime{ 0 });

        // One host, many source ports, one bucket. Hashing the port too minted a fresh budget for every
        // port an ordinary host bound: ~1200x its cap from 5000 ports, which also filled the tracked-
        // source table so that every NEW address was shed -- a single machine could stop anyone else
        // from connecting without spoofing anything.
        const std::uint64_t k1 = sockAddrToKey(addrV4(0x0A000001u, 1000), P.addrHashSeed);
        for (std::uint16_t port = 1001; port < 1064; ++port)
            assert(sockAddrToKey(addrV4(0x0A000001u, port), P.addrHashSeed) == k1);

        // Distinct hosts still get distinct buckets, or the limit would be global.
        assert(sockAddrToKey(addrV4(0x0A000002u, 1000), P.addrHashSeed) != k1);
        assert(sockAddrToKey(addrV4(0x0B000001u, 1000), P.addrHashSeed) != k1);

        // The seed is per-peer and drawn from the CSPRNG, so an attacker cannot compute an address
        // that lands in a victim's bucket and starve it -- FNV-1a alone is trivially invertible.
        NetPeer Q = newPeerState(addrLocalhost(9501), NetworkConfig{}, MonoTime{ 0 });
        assert(Q.addrHashSeed != P.addrHashSeed);
        assert(sockAddrToKey(addrV4(0x0A000001u, 1000), Q.addrHashSeed) != k1);
        std::printf("handshake_test: rate-limit key is per-host and seeded\n");
    }

    std::printf("handshake_test: return-routability, impaired-link handshake, quiet pending expiry, "
                "admission cap, reconnect identity OK\n");
    return 0;
}
