// aether - deterministic in-memory network. Runs real NetPeers against each other with no sockets:
// packets are carried by value, so loss, latency, jitter, duplication and reordering are exact and
// reproducible from a seed. This is what the library's own tests drive, and the same thing an app can
// use to test its netcode in CI without binding a port.
//
// The unit is a LINK between two peers. testLinkStep advances both a tick, moves each side's outgoing
// datagrams through the impairment model (CRC-validated on arrival, exactly like the socket layer), and
// hands back the events both sides raised. Data-first: plain structs + free functions.
#pragma once

#include "aether/peer.hpp"
#include "aether/security.hpp"
#include "aether/util.hpp"

#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

namespace aether {

// Impairments applied per direction. All-zero (the default) is a perfect link.
struct TestLinkConfig {
    double        lossRate         = 0.0;   // fraction of datagrams dropped, [0,1]
    std::uint64_t latencyNs        = 0;     // constant one-way delay
    std::uint64_t jitterNs         = 0;     // uniform extra delay in [0, jitterNs]
    double        duplicateChance  = 0.0;   // fraction of datagrams delivered twice
    double        outOfOrderChance = 0.0;   // fraction given a large extra delay, so they land late
    int           maxDatagramBytes = 0;     // path MTU: datagrams larger than this vanish, exactly like a real black hole (0 = unlimited)
};

inline constexpr std::uint64_t testOutOfOrderDelayNs  = 50000000;   // 50ms: enough to land behind later packets
inline constexpr std::uint64_t testDuplicateJitterNs  = 10000000;   // 10ms spread between a packet and its duplicate

// One datagram in flight, addressed by the peer it is going TO.
struct TestDatagram { PeerId to; Bytes data; MonoTime deliverAt{}; };

// A bidirectional link between exactly two peers. `a` and `b` are borrowed, not owned -- the caller
// keeps the NetPeers (and their configs, which the link never inspects).
struct TestLink {
    NetPeer*                 a = nullptr;
    NetPeer*                 b = nullptr;
    PeerId                   ida{};
    PeerId                   idb{};
    TestLinkConfig           aToB{};
    TestLinkConfig           bToA{};
    std::deque<TestDatagram> inFlight;
    std::uint64_t            rng = 0x9E3779B97F4A7C15ull;   // fixed seed -> the same run every time
};

inline TestLink newTestLink(NetPeer& a, const PeerId& ida, NetPeer& b, const PeerId& idb) {
    TestLink link;
    link.a   = &a;
    link.b   = &b;
    link.ida = ida;
    link.idb = idb;
    return link;
}
// Apply the same impairments in both directions.
inline void testLinkImpair(TestLink& link, const TestLinkConfig& both) { link.aToB = both; link.bToA = both; }

inline std::uint64_t testLinkNext(TestLink& link) {
    const auto r = nextRandom(link.rng);
    link.rng = r.state;
    return r.output;
}

// Queue one datagram, applying the direction's impairments. Dropped packets simply never queue.
inline void testLinkEmit(TestLink& link, const TestLinkConfig& cfg, const PeerId& to, Bytes data, MonoTime now) {
    if (cfg.maxDatagramBytes > 0 && static_cast<int>(data.size()) > cfg.maxDatagramBytes) return;   // oversized: silently eaten, no ICMP
    if (cfg.lossRate > 0.0 && randomDouble(testLinkNext(link)) < cfg.lossRate) return;

    std::uint64_t delay = cfg.latencyNs;
    if (cfg.jitterNs > 0) delay += testLinkNext(link) % (cfg.jitterNs + 1);
    if (cfg.outOfOrderChance > 0.0 && randomDouble(testLinkNext(link)) < cfg.outOfOrderChance)
        delay += testLinkNext(link) % (testOutOfOrderDelayNs + 1);

    const MonoTime deliverAt{ now.ns + delay };
    const bool     duplicate = cfg.duplicateChance > 0.0 && randomDouble(testLinkNext(link)) < cfg.duplicateChance;
    if (duplicate) {
        const MonoTime dupAt{ deliverAt.ns + testLinkNext(link) % (testDuplicateJitterNs + 1) };
        link.inFlight.push_back(TestDatagram{ to, data, dupAt });   // copy: the original is moved below
    }
    link.inFlight.push_back(TestDatagram{ to, std::move(data), deliverAt });
}

// Everything due at or before `now`, in delivery order; the rest stays in flight. Two packets due in
// the same tick keep their queue order, so reordering comes only from the delay model.
inline std::vector<TestDatagram> testLinkDue(TestLink& link, MonoTime now) {
    std::vector<TestDatagram> due;
    std::deque<TestDatagram>  still;
    for (TestDatagram& d : link.inFlight) {
        if (d.deliverAt.ns <= now.ns) due.push_back(std::move(d));
        else                          still.push_back(std::move(d));
    }
    link.inFlight = std::move(still);
    return due;
}

// The events each side raised this tick. Kept separate because "which peer saw this" is exactly what a
// test asserts on (a server's Connected is not a client's).
struct TestLinkStep { std::vector<PeerEvent> aEvents; std::vector<PeerEvent> bEvents; };

// Advance the link one tick: deliver what is due, process both peers, and queue what they sent. A
// datagram whose CRC does not validate is dropped here, as the real IO layer would.
inline TestLinkStep testLinkStep(TestLink& link, MonoTime now) {
    std::vector<IncomingPacket> toA, toB;
    for (TestDatagram& d : testLinkDue(link, now)) {
        auto stripped = validateAndStripCrc32(d.data);
        if (!stripped) continue;
        if (d.to == link.ida) toA.push_back(IncomingPacket{ link.idb, std::move(*stripped) });
        else                  toB.push_back(IncomingPacket{ link.ida, std::move(*stripped) });
    }

    PeerProcessResult ra = peerProcess(*link.a, now, toA);
    PeerProcessResult rb = peerProcess(*link.b, now, toB);
    for (RawPacket& p : ra.outgoing) testLinkEmit(link, link.aToB, link.idb, std::move(p.data), now);
    for (RawPacket& p : rb.outgoing) testLinkEmit(link, link.bToA, link.ida, std::move(p.data), now);
    return { std::move(ra.events), std::move(rb.events) };
}

// Step the link until `stop(step)` returns true, or maxTicks have passed; returns the time reached.
// The tick period is the caller's, so a test can run at whatever rate it wants to model.
template <class Stop>
inline MonoTime testLinkRun(TestLink& link, MonoTime from, std::uint64_t tickNs, int maxTicks, Stop&& stop) {
    MonoTime now = from;
    for (int k = 0; k < maxTicks; ++k) {
        now = MonoTime{ now.ns + tickNs };
        if (stop(testLinkStep(link, now))) break;
    }
    return now;
}

// Did either side raise this kind of event this tick?
inline bool testHasEvent(const std::vector<PeerEvent>& events, PeerEvent::Kind kind) {
    for (const PeerEvent& e : events)
        if (e.kind == kind) return true;
    return false;
}

// Run a link until both peers report Connected (the handshake), or the tick budget runs out. Returns
// the time reached; check peerIsConnected on both sides to confirm.
inline MonoTime testLinkConnect(TestLink& link, MonoTime from, std::uint64_t tickNs, int maxTicks) {
    bool aUp = false, bUp = false;
    return testLinkRun(link, from, tickNs, maxTicks, [&](const TestLinkStep& s) {
        aUp = aUp || testHasEvent(s.aEvents, PeerEvent::Connected);
        bUp = bUp || testHasEvent(s.bEvents, PeerEvent::Connected);
        return aUp && bUp;
    });
}

} // namespace aether
