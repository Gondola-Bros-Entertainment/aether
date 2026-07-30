// Path-MTU discovery. Unit-tests the pure search (binary, optimistic-first, retry/timeout, re-probe,
// black-hole collapse), then runs it END TO END: two real peers over a link that silently eats
// datagrams above 1300 bytes -- exactly what a real path does -- must converge on 1300 exactly, and
// an unrestricted link must confirm the full ceiling. Fragmentation stays chunked at the floor by
// design (see mtu.hpp), so discovery must never change what a fragmented message looks like.
#include <aether/aether.hpp>

#include <cassert>
#include <cstdint>
#include <cstdio>

using namespace aether;

namespace {

MonoTime atMs(std::uint64_t ms) { return MonoTime{ ms * 1000000ull }; }

// Drive a search to completion against a simulated path that carries `pathMtu`: probes at or under
// it are acked, larger ones time out. Returns the number of probe datagrams "sent".
int runSearch(MtuDiscovery& m, int pathMtu) {
    std::uint64_t ms     = 0;
    int           probes = 0;
    std::uint16_t seq    = 0;
    for (int guard = 0; guard < 200 && (m.searching || m.probeSeq); ++guard) {
        ms += 600;   // past the probe timeout at the default 100ms rto (max(2*rto, 500) = 500)
        if (const int size = mtuTick(m, atMs(ms), 100.0)) {
            ++probes;
            mtuOnProbeSent(m, SequenceNum{ seq++ }, size, atMs(ms));
            if (size <= pathMtu) mtuOnProbeAcked(m, atMs(ms));   // fits: the peer acks it
        }
    }
    return probes;
}

} // namespace

int main() {
    // Disabled or ceiling == floor: no search, no probes, plpmtu stays the floor.
    {
        MtuDiscovery off = newMtuDiscovery(1200, 1500, /*enabled=*/false);
        assert(!off.searching && mtuTick(off, atMs(1), 100.0) == 0 && off.plpmtu == 1200);
        MtuDiscovery flat = newMtuDiscovery(1200, 1200, /*enabled=*/true);
        assert(!flat.searching && mtuTick(flat, atMs(1), 100.0) == 0 && flat.plpmtu == 1200);
    }

    // The common case is one probe: the path carries the ceiling, the first (optimistic) probe is
    // the ceiling itself, and its ack finishes the search.
    {
        MtuDiscovery m = newMtuDiscovery(1200, 1500, true);
        assert(runSearch(m, 1500) == 1);
        assert(!m.searching && m.plpmtu == 1500 && m.searchDoneAt.has_value());
        assert(mtuTick(m, atMs(10000), 100.0) == 0);   // done: quiet until the re-probe timer
    }

    // A constrained path: the search converges on the EXACT largest size the path carries, each
    // unfit size costing mtuProbeRetries timeouts and each fit size one ack.
    {
        MtuDiscovery m = newMtuDiscovery(1200, 1500, true);
        const int probes = runSearch(m, 1300);
        assert(!m.searching && m.plpmtu == 1300);
        assert(probes <= 9 * mtuProbeRetries);   // <= ceil(log2(300)) + 1 sizes, 3 tries each, worst case

        // ...and a lone probe answered late (after its timeout wrote it off) changes nothing.
        mtuOnProbeAcked(m, atMs(999999));
        assert(m.plpmtu == 1300);
    }

    // A path below everything but the floor: every probe fails, the search concludes AT the floor.
    {
        MtuDiscovery m = newMtuDiscovery(1200, 1500, true);
        runSearch(m, 1200);
        assert(!m.searching && m.plpmtu == 1200);
    }

    // Retries: a size is written off only after mtuProbeRetries unanswered probes, and the retry
    // re-probes the SAME size (the size is a pure function of the bounds).
    {
        MtuDiscovery m = newMtuDiscovery(1200, 1500, true);
        std::uint64_t ms = 0;
        for (int k = 0; k < mtuProbeRetries; ++k) {
            ms += 600;
            const int size = mtuTick(m, atMs(ms), 100.0);
            assert(size == 1500);   // same size every retry
            mtuOnProbeSent(m, SequenceNum{ static_cast<std::uint16_t>(k) }, size, atMs(ms));
        }
        ms += 600;
        const int next = mtuTick(m, atMs(ms), 100.0);   // third timeout: 1500 written off, bisect
        assert(m.hi == 1499 && next == (1200 + 1499 + 1) / 2);
    }

    // The re-probe timer restarts the search from scratch, and a search that then converges LOWER
    // lowers plpmtu (paths change in both directions).
    {
        MtuDiscovery m = newMtuDiscovery(1200, 1500, true);
        runSearch(m, 1500);
        assert(m.plpmtu == 1500);
        std::uint64_t ms = static_cast<std::uint64_t>(mtuReprobeIntervalMs) + 1000;
        assert(mtuTick(m, atMs(ms), 100.0) == 1500 && m.searching);   // timer fired: probing again
        mtuOnProbeSent(m, SequenceNum{ 9 }, 1500, atMs(ms));
        // the path shrank to 1250: drive the re-search to its new conclusion
        std::uint16_t seq = 10;
        for (int guard = 0; guard < 200 && (m.searching || m.probeSeq); ++guard) {
            ms += 600;
            if (const int size = mtuTick(m, atMs(ms), 100.0)) {
                mtuOnProbeSent(m, SequenceNum{ seq++ }, size, atMs(ms));
                if (size <= 1250) mtuOnProbeAcked(m, atMs(ms));
            }
        }
        assert(!m.searching && m.plpmtu == 1250);
    }

    // Black-hole collapse: back to the floor NOW, searching again.
    {
        MtuDiscovery m = newMtuDiscovery(1200, 1500, true);
        runSearch(m, 1500);
        assert(m.plpmtu == 1500);
        mtuCollapse(m);
        assert(m.plpmtu == 1200 && m.searching);
    }

    std::printf("mtu_test: search unit OK -- 1-probe happy path, exact convergence, retries, reprobe, collapse\n");

    // END TO END: a real peer pair over a link that eats datagrams above 1300 bytes. Discovery must
    // converge on exactly 1300, message traffic must keep flowing throughout (probe losses are not
    // data losses), and a fragmented message must still chunk at the FLOOR.
    {
        NetworkConfig cfg;   // mtu 1200, ceiling 1500, discovery on -- the defaults
        cfg.defaultChannelConfig.maxMessageSize = 8192;   // room for the fragmented probe-payload below
        assert(!validateConfig(cfg));

        const Address addrA = addrLocalhost(9601), addrB = addrLocalhost(9602);
        const PeerId  idA{ addrA }, idB{ addrB };
        NetPeer A = newPeerState(addrA, cfg, MonoTime{ 0 });
        NetPeer B = newPeerState(addrB, cfg, MonoTime{ 0 });
        peerConnect(A, idB, MonoTime{ 0 });

        TestLink link = newTestLink(A, idA, B, idB);
        testLinkImpair(link, TestLinkConfig{ .maxDatagramBytes = 1300 });
        MonoTime t = testLinkConnect(link, MonoTime{ 0 }, 1000000, 40);
        assert(peerIsConnected(A, idB) && peerIsConnected(B, idA));

        // Tick at 10ms for up to 40s of sim time; converged when both directions report 1300.
        int delivered = 0;
        t = testLinkRun(link, t, 10000000, 4000, [&](const TestLinkStep& step) {
            for (const PeerEvent& e : step.bEvents) if (e.kind == PeerEvent::Message) ++delivered;
            const auto sa = peerStats(A, idB);
            const auto sb = peerStats(B, idA);
            return sa && sb && sa->pathMtu == 1300 && sb->pathMtu == 1300;
        });
        const auto statsA = peerStats(A, idB);
        assert(statsA && statsA->pathMtu == 1300);   // the exact path MTU, not a bracket
        const auto statsB = peerStats(B, idA);
        assert(statsB && statsB->pathMtu == 1300);

        // The discovered headroom must not change fragmentation: a 5000-byte message still chunks
        // at the floor (5 fragments at a 1200 MTU), every datagram fits the path, and it arrives.
        const auto err = peerSend(A, idB, ChannelId{ 0 }, Bytes(5000, 0x3C), t);
        assert(!err);
        Bytes got;
        testLinkRun(link, t, 10000000, 800, [&](TestLinkStep step) {
            for (PeerEvent& e : step.bEvents) if (e.kind == PeerEvent::Message) got = std::move(e.data);
            return !got.empty();
        });
        assert(got == Bytes(5000, 0x3C));
        std::printf("mtu_test: e2e OK -- both directions converged on 1300 exactly, fragmented traffic unaffected\n");
    }

    // An unrestricted link confirms the full ceiling with the optimistic first probe.
    {
        NetworkConfig cfg;
        const Address addrA = addrLocalhost(9611), addrB = addrLocalhost(9612);
        const PeerId  idA{ addrA }, idB{ addrB };
        NetPeer A = newPeerState(addrA, cfg, MonoTime{ 0 });
        NetPeer B = newPeerState(addrB, cfg, MonoTime{ 0 });
        peerConnect(A, idB, MonoTime{ 0 });
        TestLink link = newTestLink(A, idA, B, idB);
        MonoTime t = testLinkConnect(link, MonoTime{ 0 }, 1000000, 40);
        testLinkRun(link, t, 10000000, 400, [&](const TestLinkStep&) {
            const auto s = peerStats(A, idB);
            return s && s->pathMtu == 1500;
        });
        const auto s = peerStats(A, idB);
        assert(s && s->pathMtu == 1500);
        std::printf("mtu_test: clean path confirms the ceiling (1500) with the optimistic first probe\n");
    }

    return 0;
}
