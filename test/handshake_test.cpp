#include "check.hpp"
// aether - handshake security properties, each pinned by the case that would otherwise break it.
//
//  1. The connection challenge is a RETURN-ROUTABILITY proof. The server's challenge salt was sent
//     and stored but never echoed or verified, so a peer that never received the challenge still
//     completed the handshake -- a source-spoofing flood could fill every client slot with
//     connections to addresses that do not exist. The echo closes that, and a WRONG echo must be
//     dropped silently: replying would make the server a reflector, and cancelling the pending would
//     let anyone who can guess an in-flight client's address abort its handshake.
//
// Authenticated credential, expiry, capacity and resumption regressions are in session_auth_test.cpp.
#include <aether/aether.hpp>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <vector>

using namespace aether;

namespace {

PeerProcessResult processAt(NetPeer& peer, MonoTime now, const std::vector<IncomingPacket>& packets) {
    return peerProcess(peer, now, packets, UnixTime{now.ns});
}

// One cleartext control packet from `from`, as peerProcess consumes it (CRC already stripped).
IncomingPacket control(const PeerId& from, PacketType type, const Bytes& payload) {
    const PacketHeader header{ type, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    return IncomingPacket{ from, serializePacket(Packet{ header, payload }) };
}

// The packet inside an outgoing datagram, as the IO layer would hand it over (CRC validated + stripped).
std::optional<Packet> replyPacket(const RawPacket& raw) {
    const auto stripped = validateAndStripCrc32(raw.data);
    if (!stripped) return std::nullopt;
    return deserializePacket(*stripped);
}

// The stateless retry cookie the server mints for `from`. A raw-protocol test has to walk the same
// exchange a real client does: an uncookied request buys nothing but a cookie, and the server
// allocates no pending and no keypair until that cookie comes back. The body rides along from the
// first request, because a token-gated server rejects one that carries no token before it mints
// anything -- which is also exactly what a real client sends.
Bytes retryCookieFor(NetPeer& S, const PeerId& from, const Bytes& body, MonoTime now) {
    std::vector<IncomingPacket> in{ control(from, PacketType::ConnectionRequest, encodeConnectionRequest({}, body)) };
    const auto r = processAt(S, now, in);
    assert(S.pending.count(from) == 0);   // nothing committed for an unproven address
    Bytes cookie;
    int   replies = 0;                    // ...and one cookie is the whole of what this address earns
    for (const RawPacket& p : r.outgoing) {
        if (p.to != from) continue;       // other live connections keep sending; only this peer's reply matters
        replies += 1;
        const auto pkt = replyPacket(p);
        assert(pkt && pkt->header.type == PacketType::ConnectionRetry);
        cookie = pkt->payload;
    }
    assert(replies == 1);
    return cookie;
}
// A ConnectionRequest carrying a freshly-earned cookie: the packet that actually reaches the keygen.
IncomingPacket cookiedRequest(NetPeer& S, const PeerId& from, const Bytes& body, MonoTime now) {
    const Bytes cookie = retryCookieFor(S, from, body, now);
    return control(from, PacketType::ConnectionRequest, encodeConnectionRequest(cookie, body));
}

// The serverSalt the server put in the challenge it queued for `pid`.
std::uint64_t challengeSaltFor(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.pending.find(pid);
    assert(it != peer.pending.end());
    return it->second.serverSalt;
}

// Walk one raw client all the way through the server-side exchange (cookie, challenge, response), so a
// test can stand up a connection carrying the clientSalt it chooses.
void handshakeRaw(NetPeer& S, const PeerId& from, std::uint64_t clientSalt, const Bytes& body, MonoTime now) {
    std::vector<IncomingPacket> req{ cookiedRequest(S, from, body, now) };
    processAt(S, now, req);
    X25519Key priv{}, pub{};
    genEphemeralKeypair(priv, pub);
    const std::uint64_t salt = challengeSaltFor(S, from);
    std::vector<IncomingPacket> resp{ control(from, PacketType::ConnectionResponse,
                                              encodeConnectionResponse(clientSalt, pub, salt)) };
    processAt(S, now, resp);
}

// A cleartext datagram dropped straight into the link, addressed to `to` -- what an off-path attacker
// spoofing the other end's address puts on the wire. The link CRC-validates on arrival, so it carries one.
TestDatagram spoofed(const PeerId& to, PacketType type, const Bytes& payload, MonoTime deliverAt) {
    const PacketHeader header{ type, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    return TestDatagram{ to, appendCrc32(serializePacket(Packet{ header, payload })), deliverAt };
}

constexpr std::uint64_t tickNs = 1000000;   // 1ms

} // namespace

int main() {
    // A legacy anonymous salt can begin with the authenticated envelope marker.
    // Established handshake state, not a random payload byte, selects the decoder.
    {
        auto peer = newPeerState(addrLocalhost(9600), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{0});
        const PeerId remote{addrLocalhost(9601)};
        handshakeRaw(peer, remote, 0x01020304050607a2ull, {}, MonoTime{tickNs});
        aether::test::require(peerIsConnected(peer, remote));
    }

    // --- 0. the stateless retry cookie: nothing is allocated for an unproven address ---
    //
    // A ConnectionRequest used to buy a half-open slot and an X25519 keypair from an address that had
    // proven nothing. The cookie moves both behind a round trip the server keeps no state for: it is
    // an AEAD tag over (source address, time epoch) under a per-peer secret, so it is unforgeable,
    // useless from any other address, and expires on its own.
    {
        const Address addrS = addrLocalhost(9301);
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId idA{ addrLocalhost(9302) }, idB{ addrLocalhost(9303) };

        // an uncookied request allocates nothing and yields only a cookie (asserted inside the helper)
        const Bytes cookie = retryCookieFor(S, idA, {}, MonoTime{ 1000000 });
        assert(cookie.size() == retryCookieSize);
        assert(S.pending.empty());

        // the SAME cookie presented from a different source address is worthless: it is bound to the
        // address it was minted for, which is the whole point of proving routability
        {
            NetPeer S2 = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
            const Bytes forA = retryCookieFor(S2, idA, {}, MonoTime{ 1000000 });
            std::vector<IncomingPacket> in{ control(idB, PacketType::ConnectionRequest, encodeConnectionRequest(forA, {})) };
            processAt(S2, MonoTime{ 2000000 }, in);
            assert(S2.pending.count(idB) == 0);   // no pending, no keygen: it just earned idB its own cookie
        }

        // a garbage cookie of the right length is rejected too (it is a MAC, not a length check)
        {
            NetPeer S3 = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
            const Bytes junk(retryCookieSize, 0xAB);
            std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, encodeConnectionRequest(junk, {})) };
            processAt(S3, MonoTime{ 2000000 }, in);
            assert(S3.pending.count(idA) == 0);
        }

        // the real cookie, from the address it was minted for, is what opens the pending
        {
            std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, encodeConnectionRequest(cookie, {})) };
            const auto r = processAt(S, MonoTime{ 2000000 }, in);
            assert(S.pending.count(idA) == 1);
            assert(r.outgoing.size() == 1);   // ...and now the challenge goes out
        }

        // and it expires: past two epochs the same cookie no longer validates
        {
            NetPeer S4 = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
            const Bytes old = retryCookieFor(S4, idA, {}, MonoTime{ 1000000 });
            const MonoTime later{ 1000000 + cookieEpochNs * 3 };
            assert(!retryCookieValid(S4.cookieSecret, idA.addr, old, later));
            assert(retryCookieValid(S4.cookieSecret, idA.addr, old, MonoTime{ 1000000 }));       // still good in its own epoch
            assert(retryCookieValid(S4.cookieSecret, idA.addr, old, MonoTime{ 1000000 + cookieEpochNs }));   // and the next one
        }

        // a malformed request framing earns nothing at all -- not even a cookie to reflect
        {
            NetPeer S5 = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
            std::vector<IncomingPacket> in{ control(idA, PacketType::ConnectionRequest, Bytes{}) };
            const auto r = processAt(S5, MonoTime{ 1000000 }, in);
            assert(r.outgoing.empty());
            assert(S5.pending.empty());
        }
        std::printf("aether retry-cookie OK: no pending or keygen until a valid, address-bound cookie comes back\n");
    }

    // --- 1a. a response that never saw the challenge is rejected, and does NOT burn the pending ---
    {
        const Address addrS = addrLocalhost(9401), addrA = addrLocalhost(9402);
        const PeerId  idA{ addrA };
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });

        std::vector<IncomingPacket> in{ cookiedRequest(S, idA, {}, MonoTime{ 500000 }) };
        const auto challenge = processAt(S, MonoTime{ 1000000 }, in);
        assert(challenge.outgoing.size() == 1);          // the server answered with a challenge
        assert(S.pending.count(idA) == 1);               // ...and opened a pending for it

        // Respond blind: a well-formed response carrying a serverSalt echo we could not have known.
        X25519Key priv{}, pub{};
        genEphemeralKeypair(priv, pub);
        const std::uint64_t realSalt  = challengeSaltFor(S, idA);
        const std::uint64_t wrongSalt = realSalt ^ 1ull;   // off by one bit: still a pure guess
        std::vector<IncomingPacket> blind{
            control(idA, PacketType::ConnectionResponse, encodeConnectionResponse(0xDEADBEEFCAFEull, pub, wrongSalt)) };
        const auto after = processAt(S, MonoTime{ 2000000 }, blind);

        assert(!peerIsConnected(S, idA));                // no connection slot committed
        for (const auto& e : after.events) assert(e.kind != PeerEvent::Connected);
        assert(after.outgoing.empty());                  // silent drop -- not a reflector
        assert(S.pending.count(idA) == 1);               // the real client's handshake is untouched
        std::printf("handshake_test: blind response rejected, no reply, pending survives\n");

        // The SAME peer, now echoing correctly, completes -- proving the gate is the echo and not
        // some unrelated rejection.
        std::vector<IncomingPacket> good{
            control(idA, PacketType::ConnectionResponse, encodeConnectionResponse(0xDEADBEEFCAFEull, pub, realSalt)) };
        const auto ok = processAt(S, MonoTime{ 3000000 }, good);
        bool connected = false;
        for (const auto& e : ok.events) if (e.kind == PeerEvent::Connected) connected = true;
        assert(connected && peerIsConnected(S, idA));
        std::printf("handshake_test: correct echo completes the handshake\n");
    }

    // --- 1b. a real client/server pair still handshakes end to end over the new response wire ---
    {
        const Address addrS = addrLocalhost(9411), addrC = addrLocalhost(9412);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
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
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
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
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId ghost{ addrLocalhost(9442) };

        std::vector<IncomingPacket> in{ cookiedRequest(S, ghost, {}, MonoTime{ tickNs / 2 }) };
        processAt(S, MonoTime{ tickNs }, in);
        assert(S.pending.count(ghost) == 1);

        const std::uint64_t past = static_cast<std::uint64_t>(S.config.connectionRequestTimeoutMs) * tickNs * 2;
        const auto expired = processAt(S, MonoTime{ past }, {});
        assert(S.pending.empty());                              // swept
        for (const auto& e : expired.events) assert(e.kind != PeerEvent::Disconnected);

        // A client's OWN failed connect still reports the timeout -- that one the caller is waiting for.
        NetPeer C = newPeerState(addrLocalhost(9443), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId dead{ addrLocalhost(9444) };               // nothing is listening
        peerConnect(C, dead, MonoTime{ 0 });
        bool timedOut = false;
        const auto attempt = processAt(C, MonoTime{ past }, {});   // named: a range-for over a temporary's
        for (const auto& e : attempt.events)                         // member does not extend its lifetime
            if (e.kind == PeerEvent::Disconnected && e.reason == DisconnectReason::Timeout) timedOut = true;
        assert(timedOut);
        std::printf("handshake_test: abandoned inbound handshake expires silently, outbound reports its timeout\n");
    }

    // --- 1e. maxClients holds at the moment connections are ADMITTED, not just when requested ---
    // The cap was checked at the request and then the response inserted unconditionally, so every
    // handshake already in flight when the last slot filled still became a connection.
    {
        NetworkConfig cfg = aether::test::anonymousConfig<NetworkConfig>();
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
        processAt(S, MonoTime{ tickNs }, requests);            // all challenged in one tick: 6 pendings, 0 connections
        assert(S.pending.size() == clients);

        std::vector<IncomingPacket> responses;                  // ...then every one of them responds at once
        responses.reserve(clients);
        for (int i = 0; i < clients; ++i)
            responses.push_back(control(ids[static_cast<std::size_t>(i)], PacketType::ConnectionResponse,
                                        encodeConnectionResponse(0x1000ull + static_cast<std::uint64_t>(i),
                                                                 pubs[static_cast<std::size_t>(i)],
                                                                 challengeSaltFor(S, ids[static_cast<std::size_t>(i)]))));
        processAt(S, MonoTime{ 2 * tickNs }, responses);
        assert(peerCount(S) == cfg.maxClients);                 // held at 2, not 6
        std::printf("handshake_test: maxClients holds at admission (%d of %d responses accepted)\n",
                    peerCount(S), clients);
    }

    // --- 2b. the anti-amplification cap itself ---
    {
        NetworkConfig cfg = aether::test::anonymousConfig<NetworkConfig>();
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

    // --- 4. the per-source rate limit keys on the HOST, not the (host, port) pair ---
    {
        NetPeer P = newPeerState(addrLocalhost(9500), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });

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
        NetPeer Q = newPeerState(addrLocalhost(9501), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        assert(Q.addrHashSeed != P.addrHashSeed);
        assert(sockAddrToKey(addrV4(0x0A000001u, 1000), Q.addrHashSeed) != k1);
        std::printf("handshake_test: rate-limit key is per-host and seeded\n");
    }

    // --- 5. the echoed salt and the session key must come from the SAME challenge ---
    // A challenge is cleartext, so anyone can inject one from the server's address. Taking the salt
    // from the newest challenge while keeping a key derived from an older one leaves both ends
    // reporting Connected with keys that cannot decrypt each other, and the connection dies at the
    // timeout with nothing having ever been delivered.
    {
        const Address addrS = addrLocalhost(9461), addrC = addrLocalhost(9462);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        peerConnect(C, idS, MonoTime{ 0 });

        TestLink  link = newTestLink(C, idC, S, idS);
        X25519Key evilPriv{}, evilPub{};
        genEphemeralKeypair(evilPriv, evilPub);
        link.inFlight.push_back(spoofed(idC, PacketType::ConnectionChallenge,
                                        encodeSaltAndKey(0xF00DF00DF00DF00Dull, evilPub), MonoTime{ 0 }));

        MonoTime t = testLinkConnect(link, MonoTime{ 0 }, tickNs, 64);
        assert(peerIsConnected(S, idC) && peerIsConnected(C, idS));
        const Connection& cc = C.connections.at(idS);
        const Connection& sc = S.connections.at(idC);
        assert(cc.sendKey && cc.recvKey && sc.sendKey && sc.recvKey);
        assert(*cc.sendKey == *sc.recvKey && *cc.recvKey == *sc.sendKey);   // keys that can actually decrypt

        peerSend(C, idS, ChannelId{ 0 }, Bytes{ 7, 7, 7 }, t);   // ...and prove it end to end
        bool delivered = false;
        testLinkRun(link, t, tickNs, 32, [&](const TestLinkStep& s) {
            for (const PeerEvent& e : s.bEvents) if (e.kind == PeerEvent::Message) delivered = true;
            return delivered;
        });
        assert(delivered);
        std::printf("handshake_test: an injected challenge cannot split the echoed salt from the session key\n");
    }

    // --- 5b. a challenge whose shared secret is degenerate keys nothing, and latches nothing ---
    // An all-zero public key is a low-order point: x25519Shared refuses it. Treating that failure as
    // "keypair done" would leave the pending permanently unkeyable, so the genuine challenge behind it
    // could never rescue the handshake.
    {
        const Address addrS = addrLocalhost(9463), addrC = addrLocalhost(9464);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        peerConnect(C, idS, MonoTime{ 0 });

        TestLink        link = newTestLink(C, idC, S, idS);
        const X25519Key degenerate{};   // all zeroes -> an all-zero shared secret anyone could compute
        link.inFlight.push_back(spoofed(idC, PacketType::ConnectionChallenge, encodeSaltAndKey(7, degenerate), MonoTime{ 0 }));

        testLinkStep(link, MonoTime{ tickNs });
        assert(C.pending.count(idS) == 1);
        assert(!C.pending.at(idS).sessionShared);      // nothing committed
        assert(!C.pending.at(idS).ephemeralReady);     // ...and nothing latched
        for (const TestDatagram& d : link.inFlight) {
            const auto stripped = validateAndStripCrc32(d.data);
            const auto pk       = stripped ? deserializePacket(*stripped) : std::nullopt;
            assert(!pk || pk->header.type != PacketType::ConnectionResponse);   // no response to a challenge we refused
        }

        testLinkConnect(link, MonoTime{ tickNs }, tickNs, 64);
        assert(peerIsConnected(S, idC) && peerIsConnected(C, idS));   // the real handshake still completes
        std::printf("handshake_test: a degenerate challenge keys nothing and blocks nothing\n");
    }

    // --- 8. an unauthenticated cleartext Disconnect cannot erase a handshake ---
    // Erasing a pending here aborts a connect attempt with one spoofed packet, and silently: the entry
    // is gone, so cleanupPending has nothing left to report the timeout for and the caller waits forever.
    {
        NetPeer      C = newPeerState(addrLocalhost(9491), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId dead{ addrLocalhost(9492) };
        peerConnect(C, dead, MonoTime{ 0 });

        std::vector<IncomingPacket> kill{ control(dead, PacketType::Disconnect, {}) };
        const auto killed = processAt(C, MonoTime{ tickNs }, kill);
        assert(C.pending.count(dead) == 1);   // the handshake is untouched
        assert(killed.events.empty());

        const std::uint64_t past = static_cast<std::uint64_t>(C.config.connectionRequestTimeoutMs) * tickNs * 2;
        const auto expired = processAt(C, MonoTime{ past }, {});
        bool timedOut = false;
        for (const auto& e : expired.events)
            if (e.kind == PeerEvent::Disconnected && e.reason == DisconnectReason::Timeout) timedOut = true;
        assert(timedOut);                     // ...and the caller still hears the outcome

        NetPeer      S = newPeerState(addrLocalhost(9493), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId idA{ addrV4(0x0A000013u, 9494) };
        std::vector<IncomingPacket> req{ cookiedRequest(S, idA, {}, MonoTime{ tickNs / 2 }) };
        processAt(S, MonoTime{ tickNs }, req);
        assert(S.pending.count(idA) == 1);
        std::vector<IncomingPacket> spoof{ control(idA, PacketType::Disconnect, {}) };
        processAt(S, MonoTime{ 2 * tickNs }, spoof);
        assert(S.pending.count(idA) == 1);    // the server's half-open handshake survives it too
        std::printf("handshake_test: a cleartext Disconnect leaves half-open handshakes alone\n");
    }

    // --- 9. an early ConnectionAccepted must not abort the handshake ---
    // Refusing to key an unkeyed connection is right (a plaintext zombie is worse), but tearing the
    // pending down with it hands one injected cleartext packet the power to kill any connect attempt.
    {
        const Address addrS = addrLocalhost(9495), addrC = addrLocalhost(9496);
        const PeerId  idS{ addrS }, idC{ addrC };
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        peerConnect(C, idS, MonoTime{ 0 });

        TestLink link = newTestLink(C, idC, S, idS);
        link.inFlight.push_back(spoofed(idC, PacketType::ConnectionAccepted, {}, MonoTime{ 0 }));
        testLinkConnect(link, MonoTime{ 0 }, tickNs, 64);
        assert(peerIsConnected(S, idC) && peerIsConnected(C, idS));
        assert(C.connections.at(idS).sendKey);   // and it came up keyed, never as a plaintext zombie
        std::printf("handshake_test: an injected Accepted keys nothing and cancels nothing\n");
    }

    // --- 10. simultaneous connect resolves a role instead of sending zeros ---
    // Both ends calling peerConnect leaves each holding an outbound pending, which carries no challenge
    // material at all. Answering the peer's request out of one sends a zero salt and an all-zero public
    // key -- a challenge that can never key anything.
    {
        const Address addrA = addrLocalhost(9501), addrB = addrLocalhost(9502);
        const PeerId  idA{ addrA }, idB{ addrB };
        NetPeer A = newPeerState(addrA, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer B = newPeerState(addrB, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        peerConnect(A, idB, MonoTime{ 0 });
        peerConnect(B, idA, MonoTime{ 0 });

        TestLink link = newTestLink(A, idA, B, idB);
        bool     aUp = false, bUp = false;
        MonoTime t = testLinkRun(link, MonoTime{ 0 }, tickNs, 64, [&](const TestLinkStep& s) {
            for (const PeerEvent& e : s.aEvents) if (e.kind == PeerEvent::Connected) aUp = true;
            for (const PeerEvent& e : s.bEvents) if (e.kind == PeerEvent::Connected) bUp = true;
            return aUp && bUp;
        });
        assert(aUp && bUp);                                  // both callers heard about the connection they asked for
        assert(peerIsConnected(A, idB) && peerIsConnected(B, idA));
        const Connection& ca = A.connections.at(idB);
        const Connection& cb = B.connections.at(idA);
        assert(*ca.sendKey == *cb.recvKey && *ca.recvKey == *cb.sendKey);

        peerSend(A, idB, ChannelId{ 0 }, Bytes{ 4, 2 }, t);
        bool delivered = false;
        testLinkRun(link, t, tickNs, 32, [&](const TestLinkStep& s) {
            for (const PeerEvent& e : s.bEvents) if (e.kind == PeerEvent::Message) delivered = true;
            return delivered;
        });
        assert(delivered);
        std::printf("handshake_test: a simultaneous connect resolves roles and completes\n");
    }

    // --- 11. one session's resumable cannot be overwritten by another claiming the same token ---
    // clientSalt arrives on the wire, so two live sessions can carry the same one. Keying the resumable
    // table by it alone lets whichever drops last replace the other's master, and the peer that really
    // holds that master then has its correctly-MAC'd resume rejected.
    {
        NetPeer      S = newPeerState(addrLocalhost(9511), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId idA{ addrV4(0x0A000014u, 9512) }, idB{ addrV4(0x0A000015u, 9513) };
        constexpr std::uint64_t shared = 0x5151515151515151ull;

        handshakeRaw(S, idA, shared, {}, MonoTime{ tickNs });                     // both claim the same token
        handshakeRaw(S, idB, shared, {}, MonoTime{ 8000ull * tickNs });           // ...8s apart, so they expire apart
        assert(peerCount(S) == 2);
        const X25519Key masterA = *S.connections.at(idA).resumeMaster;
        const X25519Key masterB = *S.connections.at(idB).resumeMaster;
        assert(masterA != masterB);

        processAt(S, MonoTime{ 12000ull * tickNs }, {});   // A idles out; B is still live
        assert(peerCount(S) == 1 && S.connections.count(idB) == 1);
        assert(S.resumableTokens.count(shared) == 1);
        assert(*S.resumableTokens.at(shared).master == masterA);

        processAt(S, MonoTime{ 20000ull * tickNs }, {});   // now B idles out too
        assert(peerCount(S) == 0);
        assert(*S.resumableTokens.at(shared).master == masterA);   // A's entry survives, still A's master
        assert(S.resumableTokens.at(shared).owner == idA);
        std::printf("handshake_test: a colliding session token cannot clobber the live resumable\n");
    }

    // --- 13. a Retry is never larger than the request that drew it ---
    // The cookie is minted for an address that has proven nothing, so a request smaller than its own
    // reply would make the server a reflector for whatever address the datagram claimed.
    {
        NetPeer      S = newPeerState(addrLocalhost(9531), aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        const PeerId idA{ addrV4(0x0A000016u, 9532) };

        const Bytes tiny{ 0 };   // framing-valid: no cookie, no body -- and far below the minimum
        std::vector<IncomingPacket> small{ control(idA, PacketType::ConnectionRequest, tiny) };
        const auto shed = processAt(S, MonoTime{ tickNs }, small);
        assert(shed.outgoing.empty());
        assert(S.pending.empty());

        const Bytes padded = encodeConnectionRequest({}, {});   // what a real client sends
        assert(requestDatagramBytes(padded) >= minConnectionRequestBytes);
        std::vector<IncomingPacket> ok{ control(idA, PacketType::ConnectionRequest, padded) };
        const auto answered = processAt(S, MonoTime{ 2 * tickNs }, ok);
        assert(answered.outgoing.size() == 1);
        const auto retry = replyPacket(answered.outgoing[0]);
        assert(retry && retry->header.type == PacketType::ConnectionRetry);
        assert(answered.outgoing[0].data.size() <= requestDatagramBytes(padded));   // no amplification, at all
        std::printf("handshake_test: an undersized request draws no cookie; a padded one is answered 1:1\n");
    }

    // --- 14. the AEAD authenticates the header as it ARRIVED, on every path ---
    // The migration and path-validation paths rebuilt their AAD from the parsed header. writeHeader
    // normalizes the low nibble of byte 8 and readHeader discards it, so those four bits sat outside
    // the tag on exactly those paths while every other path authenticated the wire bytes.
    {
        const Address addrS = addrLocalhost(9541), addrC = addrLocalhost(9542);
        const PeerId  idS{ addrS }, idC{ addrC }, idMoved{ addrV4(0x0A000017u, 9543) };
        NetPeer S = newPeerState(addrS, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        NetPeer C = newPeerState(addrC, aether::test::anonymousConfig<NetworkConfig>(), MonoTime{ 0 });
        peerConnect(C, idS, MonoTime{ 0 });
        TestLink link = newTestLink(C, idC, S, idS);
        MonoTime t    = testLinkConnect(link, MonoTime{ 0 }, tickNs, 24);
        assert(peerIsConnected(S, idC) && peerIsConnected(C, idS));

        peerSend(C, idS, ChannelId{ 0 }, Bytes{ 1, 2, 3, 4 }, t);
        Bytes datagram;   // captured before the link carries it, so the server has never seen it
        for (int k = 0; k < 32 && datagram.empty(); ++k) {
            t = MonoTime{ t.ns + tickNs };
            const auto sent = processAt(C, t, {});
            for (const RawPacket& p : sent.outgoing) {
                const auto pk = replyPacket(p);
                if (!pk || (pk->header.type != PacketType::Payload && pk->header.type != PacketType::PayloadBatch)) continue;
                const auto stripped = validateAndStripCrc32(p.data);
                if (stripped) datagram = *stripped;
            }
        }
        assert(!datagram.empty());

        Bytes tampered = datagram;
        tampered[8] = static_cast<std::uint8_t>(tampered[8] ^ 0x0F);   // the four bits readHeader throws away
        t = MonoTime{ t.ns + tickNs };
        const auto rejected = processAt(S, t, { IncomingPacket{ idMoved, tampered } });
        for (const RawPacket& p : rejected.outgoing) assert(p.to != idMoved);
        assert(S.pathValidations.empty());   // it never authenticated, so no path challenge went out

        t = MonoTime{ t.ns + tickNs };
        const auto probed = processAt(S, t, { IncomingPacket{ idMoved, datagram } });
        bool challenged = false;
        for (const RawPacket& p : probed.outgoing) if (p.to == idMoved) challenged = true;
        assert(challenged && S.pathValidations.count(idMoved) == 1);   // the untouched copy does
        std::printf("handshake_test: flipping the discarded header bits breaks the tag on the migration path\n");
    }

    std::printf("handshake_test: return-routability, impaired-link handshake, quiet pending expiry, "
                "admission cap, reconnect identity OK\n");
    return 0;
}
