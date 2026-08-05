// Cross-layer transport tests: the RTT/loss signal must not depend on a connection carrying
// RELIABLE traffic, and the congestion window must bound what a single tick emits.
// assert() is the check, so build WITHOUT NDEBUG.
#include "aether/connection.hpp"
#include "aether/peer.hpp"
#include "aether/testnet.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>

using namespace aether;

namespace {

constexpr std::uint64_t tickNs = 16000000;   // ~60Hz

struct Pair {
    NetPeer  server;
    NetPeer  client;
    PeerId   sp;
    PeerId   cp;
    TestLink link;
};

// Bring up a connected pair over the deterministic in-memory network.
MonoTime connectPair(Pair& p, const NetworkConfig& cfg, MonoTime now) {
    const Address sa = addrV4(0x0A000001, 1000), ca = addrV4(0x0A000002, 2000);
    p.sp     = PeerId{ sa };
    p.cp     = PeerId{ ca };
    p.server = newPeerState(sa, cfg, now);
    p.client = newPeerState(ca, cfg, now);
    p.link   = newTestLink(p.server, p.sp, p.client, p.cp);
    peerConnect(p.client, p.sp, now);
    now = testLinkConnect(p.link, now, tickNs, 400);
    assert(peerIsConnected(p.client, p.sp));
    return now;
}

} // namespace

int main() {
    // ---- an UNRELIABLE-only connection still measures RTT and loss ----
    //
    // recordLossSample/updateRtt are only reachable from processAcks, which walks the sent ring.
    // While flushPendingWires registered a packet there only when it carried a reliable message, a
    // connection streaming unreliable snapshots -- the ordinary shape for replicated state -- fed the
    // loss window nothing. It reported zero loss and zero RTT on a badly degraded path, graded itself
    // Excellent, and its AIMD controller additively increased INTO the congestion because it never saw
    // a bad sample. Every payload packet is registered now, with size 0 when it carries no reliable
    // bytes so window accounting is untouched.
    {
        NetworkConfig cfg;
        cfg.channelConfigs = { unreliableChannel() };
        cfg.maxChannels    = 1;

        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });

        TestLinkConfig bad;
        bad.lossRate  = 0.40;
        bad.latencyNs = 30000000;   // 60ms round trip
        testLinkImpair(p.link, bad);

        const Bytes payload(200, 0xAB);
        for (int t = 0; t < 300; ++t) {
            now = MonoTime{ now.ns + tickNs };
            peerSend(p.client, p.sp, ChannelId{ 0 }, payload, now);
            testLinkStep(p.link, now);
        }

        const Connection& c = p.client.connections.at(p.sp);
        assert(c.reliability.lossWindowCount > 0);          // the loss window is actually fed
        assert(packetLossFraction(c.reliability) > 0.1);    // and reports real loss, not a flat 0
        assert(c.reliability.hasRttSample);                 // RTT is sampled off the same acks
        assert(c.reliability.srtt > 0.0);
        assert(c.stats.rtt > 0.0);                          // ...and reaches the app-facing stats
        assert(c.stats.packetLoss > 0.1);
        assert(c.stats.connectionQuality != ConnectionQuality::Excellent);   // no longer graded perfect
        // the rate controller now reacts instead of ramping up into the loss
        assert(c.congestion.currentSendRate <= c.congestion.baseSendRate);

        // the unreliable traffic must NOT have been charged to the congestion window (size 0),
        // otherwise nothing would ever ack those bytes back out and the window would wedge shut
        assert(c.reliability.bytesAcked == 0);
    }

    // A clean link must still read as clean: the widened signal reports real conditions, it does
    // not manufacture loss.
    {
        NetworkConfig cfg;
        cfg.channelConfigs = { unreliableChannel() };
        cfg.maxChannels    = 1;

        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });
        TestLinkConfig clean;
        clean.latencyNs = 10000000;   // 20ms round trip, no loss
        testLinkImpair(p.link, clean);

        const Bytes payload(200, 0xCD);
        for (int t = 0; t < 200; ++t) {
            now = MonoTime{ now.ns + tickNs };
            peerSend(p.client, p.sp, ChannelId{ 0 }, payload, now);
            testLinkStep(p.link, now);
        }
        const Connection& c = p.client.connections.at(p.sp);
        assert(c.reliability.lossWindowCount > 0);
        assert(packetLossFraction(c.reliability) == 0.0);   // a clean link reads clean
        assert(c.stats.rtt > 0.0);
        assert(c.congestion.mode == CongestionMode::Good);
    }

    // ---- the congestion window bounds a single tick ----
    //
    // cwCanSend reads bytesInFlight, which only moved when the tick's wires were flushed -- after
    // every channel had already been drained. So each message in a tick tested the same pre-tick
    // figure and one tick could admit many times cwnd (13.4x with a one-MTU window). Reserving the
    // bytes at admission is what makes the check bind.
    {
        NetworkConfig cfg;
        cfg.useCwndCongestion = true;
        cfg.channelConfigs    = { reliableOrderedChannel() };
        cfg.maxChannels       = 1;
        cfg.sendRate          = 1000.0;   // token bucket wide open: only the WINDOW is under test
        cfg.maxPacketRate     = 2000.0;

        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });
        Connection& c = p.client.connections.at(p.sp);

        c.cwnd->cwnd                = 1200.0;   // one MTU
        c.cwnd->phase               = CongestionPhase::Avoidance;
        c.cwnd->bytesInFlight       = 0;
        c.cwnd->pendingBytes        = 0;
        c.cwnd->minInterPacketDelay = 0.0;
        c.reliability.rto           = 10000.0;   // hold off the idle slow-start restart and the retransmit clock

        const Bytes payload(400, 0x5A);   // each wire is well past smallReliableThreshold, so the window gates it
        constexpr std::uint64_t wireBytes = 403;   // [channel byte][seq:2][payload]
        for (int i = 0; i < 40; ++i) peerSend(p.client, p.sp, ChannelId{ 0 }, payload, now);

        now = MonoTime{ now.ns + tickNs };
        updateConnectedPure(c, now);

        assert(c.cwnd->bytesInFlight <= static_cast<std::uint64_t>(c.cwnd->cwnd));   // the window HOLDS
        assert(c.cwnd->bytesInFlight > 0);                                           // ...without stalling the sender
        assert(c.cwnd->pendingBytes == 0);   // every reservation was realized at flush; none leaked

        // Pacing spreads a window over an RTT, so filling one can take more than a single tick. What
        // must hold on EVERY tick is that nothing is admitted past the window.
        for (int t = 0; t < 4 && c.cwnd->bytesInFlight + wireBytes <= static_cast<std::uint64_t>(c.cwnd->cwnd); ++t) {
            now = MonoTime{ now.ns + tickNs };
            updateConnectedPure(c, now);
            assert(c.cwnd->bytesInFlight <= static_cast<std::uint64_t>(c.cwnd->cwnd));
            assert(c.cwnd->pendingBytes == 0);
        }

        // and a full window blocks the next tick rather than admitting more
        const std::uint64_t inFlight = c.cwnd->bytesInFlight;
        assert(inFlight + wireBytes > static_cast<std::uint64_t>(c.cwnd->cwnd));   // it really is full
        now = MonoTime{ now.ns + tickNs };
        updateConnectedPure(c, now);
        assert(c.cwnd->bytesInFlight == inFlight);
        assert(c.cwnd->pendingBytes == 0);
    }

    // ---- the congestion WINDOW must react to loss of unreliable-only packets ----
    //
    // processIncomingAcks gated cwOnLoss on res.fastRetransmit being non-empty. An unreliable-only
    // packet is registered in the sent ring with msgCount 0 and size 0, so a triple-NACK on one
    // produced a loss SAMPLE (the AIMD arm reacted) but no fastRetransmit entries and no lostBytes:
    // the window never shrank. On the traffic shape games actually send -- a stream of unreliable
    // snapshots -- New Reno sat at its initial size through 40% loss. The signal is the lost-packet
    // COUNT, because congestion is a property of the path, not of a delivery mode.
    {
        NetworkConfig cfg;
        cfg.useCwndCongestion = true;
        cfg.channelConfigs    = { unreliableChannel() };
        cfg.maxChannels       = 1;

        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });

        const double cwnd0 = p.client.connections.at(p.sp).cwnd->cwnd;
        assert(cwnd0 > 0.0);

        TestLinkConfig bad;
        bad.lossRate  = 0.40;
        bad.latencyNs = 30000000;
        testLinkImpair(p.link, bad);

        const Bytes payload(200, 0xAB);
        for (int t = 0; t < 400; ++t) {
            now = MonoTime{ now.ns + tickNs };
            peerSend(p.client, p.sp, ChannelId{ 0 }, payload, now);
            testLinkStep(p.link, now);
        }

        const Connection& c = p.client.connections.at(p.sp);
        assert(c.reliability.totalLost > 0);                 // packets really were declared lost
        assert(c.cwnd->cwnd < cwnd0);                        // ...and the WINDOW responded to them
        assert(c.cwnd->phase != CongestionPhase::SlowStart);  // it left slow start on the loss episode
        // window accounting is still untouched by unreliable traffic: nothing acks it, so charging
        // it would leak the window shut.
        assert(c.cwnd->bytesInFlight == 0);
        assert(c.cwnd->pendingBytes == 0);
    }

    // ---- ONE window reduction per loss episode, through the real header path ----
    //
    // Two packets of one flight cross their triple-NACK threshold in different headers, and a header
    // that acks with no loss lands between them. That one ends fast recovery, so the second drop is
    // judged with the phase already back in avoidance and a phase-based guard halves the window a
    // second time for a single congestion signal (four spread drops reach the cwnd floor).
    {
        NetworkConfig cfg;
        cfg.useCwndCongestion = true;
        cfg.channelConfigs    = { unreliableChannel() };
        cfg.maxChannels       = 1;

        const MonoTime now{ 0 };
        Connection c = newConnection(cfg, 7, now);
        markConnected(c, now);
        c.cwnd->phase = CongestionPhase::Avoidance;
        c.cwnd->cwnd  = 48000.0;

        for (std::uint16_t s = 1; s <= 10; ++s)   // ten in flight; the peer never receives 2 or 6
            onPacketSent(c.reliability, SequenceNum{ s }, now, ChannelId{ 0 }, SequenceNum{ s }, 1200);

        ReliableEndpoint peer{};
        const auto deliver = [&](std::uint16_t arrived) {   // one arrival -> the header the peer would send
            const SequenceNum sn{ arrived };
            onPacketsReceived(peer, &sn, 1);
            const auto [ackSeq, bits] = getAckInfo(peer);
            PacketHeader h{};
            h.type    = PacketType::Keepalive;
            h.ack     = ackSeq;
            h.ackBits = static_cast<std::uint32_t>(bits);
            processIncomingAcks(c, h, now);
        };

        deliver(1);
        deliver(3);
        deliver(4);
        const double cwndAtLoss = c.cwnd->cwnd;
        deliver(5);                                          // seq 2 crosses the threshold: ONE reduction
        assert(c.cwnd->phase == CongestionPhase::Recovery);
        const double afterFirst = c.cwnd->ssthresh;
        assert(afterFirst == cwndAtLoss / 2.0);

        deliver(7);                                          // acks with no loss: fast recovery ends here
        assert(c.cwnd->phase == CongestionPhase::Avoidance);
        deliver(8);
        deliver(9);                                          // seq 6, same flight -> no second reduction
        assert(c.reliability.totalLost == 2);
        assert(c.cwnd->ssthresh == afterFirst);
    }

    // ---- a path that goes totally DARK must degrade the signal, not freeze it ----
    //
    // Every loss signal is ack-driven, so a total outage produces none at all: the loss window keeps
    // reporting its last healthy value, the rate controller reads good conditions and additively
    // increases INTO the dead path, quality still grades Excellent, and the MTU black-hole rule -- which
    // needs a near-total loss fraction -- can never fire. Unresolved packets are written off by timeout.
    {
        NetworkConfig cfg;
        cfg.channelConfigs = { unreliableChannel() };
        cfg.maxChannels    = 1;

        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });

        const Bytes payload(200, 0xAB);
        for (int t = 0; t < 120; ++t) {   // a clean stretch first, so there is a healthy reading to freeze
            now = MonoTime{ now.ns + tickNs };
            peerSend(p.client, p.sp, ChannelId{ 0 }, payload, now);
            testLinkStep(p.link, now);
        }
        const Connection& c = p.client.connections.at(p.sp);
        assert(c.stats.connectionQuality == ConnectionQuality::Excellent);
        assert(c.stats.packetLoss == 0.0);
        const double rateBefore = c.congestion.currentSendRate;
        assert(rateBefore > minSendRate);

        TestLinkConfig dark;
        dark.lossRate = 1.0;   // nothing gets through, in either direction
        testLinkImpair(p.link, dark);

        for (int t = 0; t < 240; ++t) {   // ~4s: well inside the 10s connection timeout
            now = MonoTime{ now.ns + tickNs };
            peerSend(p.client, p.sp, ChannelId{ 0 }, payload, now);
            testLinkStep(p.link, now);
        }
        assert(peerIsConnected(p.client, p.sp));                          // still Connected, as before...
        assert(c.stats.packetLoss > 0.9);                                 // ...but the loss signal MOVED
        assert(c.stats.connectionQuality == ConnectionQuality::Bad);      // ...and so did the grade
        assert(c.congestion.mode == CongestionMode::Bad);
        assert(c.congestion.currentSendRate < rateBefore);                // the controller backed OFF
        assert(c.reliability.totalLost > 0);
    }

    // ---- a fragmented retransmit is priced PER FRAGMENT, exactly as its first send is ----
    //
    // A fragmented message is several datagrams and its total can exceed the whole token bucket.
    // Summing every unacked fragment and testing the total against a bucket sized in single datagrams
    // admits it NEVER: it does not retransmit, does not advance its retry count, and so never reaches
    // the retry-limit disposal either -- and breaking out of the pass froze everything queued behind it.
    {
        NetworkConfig cfg;
        cfg.sendRate       = 2.0;    // bucket capacity == 2 * mtu == 2400 bytes, well under the message below
        cfg.maxPacketRate  = 8.0;
        cfg.channelConfigs = { reliableOrderedChannel() };
        cfg.channelConfigs[0].maxMessageSize     = 16384;
        cfg.channelConfigs[0].maxReliableRetries = 3;   // a short budget, so disposal is reachable in sim time
        cfg.maxChannels    = 1;
        assert(!validateConfig(cfg));

        MonoTime   now{ 0 };
        Connection c = newConnection(cfg, 1, now);
        markConnected(c, now);
        c.peerCredit[0] = 64;   // the receiver is not the constraint under test here

        assert(!sendMessage(c, ChannelId{ 0 }, Bytes(4000, 0x7E), now));   // ~4 fragments: over one bucket
        assert(!sendMessage(c, ChannelId{ 0 }, Bytes(40, 0x11), now));     // a small one queued BEHIND it

        // Nothing is ever acked, so both keep qualifying for retransmit until their budgets run out.
        const std::uint64_t tick = 16000000;
        int ticks = 0;
        for (; ticks < 12000 && !c.channels[0].sendBuffer.empty(); ++ticks) {
            now = MonoTime{ now.ns + tick };
            updateConnectedPure(c, now);
            drainSendQueue(c);   // the wire goes nowhere: only the send-side accounting is under test
        }
        const Channel& ch = c.channels[0];
        assert(ticks < 12000);                    // it terminated rather than spinning forever
        assert(ch.totalRetransmits > 0);          // the over-budget message DOES retransmit...
        assert(ch.sendBuffer.empty());            // ...and the retry limit finally disposes of both
        assert(ch.totalReliableDropped == 2);     // including the small one, which was never frozen behind it
        assert(c.stats.reliableDropped == 2);     // ...and the application can SEE the broken guarantee
    }

    // ---- an idle connection must not trade an ack-only every tick ----
    //
    // recordReceivedPacket set pendingAck for ANY packet, and a bare ack-only goes out as a
    // Keepalive -- so each side's ack was itself treated as needing an ack and the two ping-ponged
    // at tick rate forever. On an idle link with zero application traffic that measured ~0.91
    // packets per tick per side, about 28x the keepalive cadence. Only a packet carrying something
    // the sender waits on (channel data, or an MTU probe whose ack is the discovery signal) earns a
    // prompt ack now; the sequence is still recorded either way, so the ack bitfield stays exact.
    {
        NetworkConfig cfg;   // defaults: 1000ms keepalive, 1000ms time-sync, 10000ms timeout
        Pair     p;
        MonoTime now = connectPair(p, cfg, MonoTime{ 0 });

        const std::uint64_t sent0 = peerStats(p.client, p.sp)->packetsSent;
        const int           ticks = 300;   // 5 seconds at ~60Hz, nothing sent by the application
        for (int t = 0; t < ticks; ++t) {
            now = MonoTime{ now.ns + tickNs };
            testLinkStep(p.link, now);
        }
        const std::uint64_t sent = peerStats(p.client, p.sp)->packetsSent - sent0;

        // 5s of keepalives + time-sync pings + their pongs is ~15 packets, plus a short MTU search.
        // The bound that matters is that this is a function of the CADENCES, not of the tick rate.
        assert(sent > 0);                                    // the link stays alive
        assert(sent < static_cast<std::uint64_t>(ticks) / 4);   // and nowhere near one per tick
        assert(peerIsConnected(p.client, p.sp));             // no timeout from the quieter link
        assert(peerIsConnected(p.server, p.cp));

        // a reliable message must still be acked PROMPTLY, not held until the next keepalive
        const Bytes msg(64, 0x11);
        now = MonoTime{ now.ns + tickNs };
        peerSend(p.client, p.sp, ChannelId{ 0 }, msg, now);
        for (int t = 0; t < 8; ++t) { now = MonoTime{ now.ns + tickNs }; testLinkStep(p.link, now); }
        const Connection& c = p.client.connections.at(p.sp);
        assert(c.reliability.totalAcked > 0);                // the ack came back inside a few ticks
        assert(c.channels[0].sendBuffer.empty());            // ...and retired the message
    }

    // A reservation must never wrap the counter, and must survive a connection reset.
    {
        CongestionWindow cw = newCongestionWindow(1200);
        cwOnAdmit(cw, 500);
        assert(cw.pendingBytes == 500);
        cwOnSend(cw, 500, MonoTime{ 1 });
        assert(cw.pendingBytes == 0 && cw.bytesInFlight == 500);
        cwOnSend(cw, 900, MonoTime{ 2 });            // flushed more than was reserved
        assert(cw.pendingBytes == 0);                // saturates at 0 rather than wrapping
        assert(cw.bytesInFlight == 1400);
    }

    // ---- a peer that has received nothing must not acknowledge anything ----
    //
    // getAckInfo cannot express "nothing received yet": before its first receive it reports the default
    // remoteSeq 0 with an empty bitfield, which on the wire is a genuine ack of packet 0. So a peer that
    // had heard nothing acked our packet 0 -- and if that packet carried a reliable message that was
    // lost, the sender marked it delivered and never sent it again. Reserving sequence 0 (firstSequence)
    // is what makes the two cases distinguishable: no record ever exists at the sequence such a header
    // names.
    {
        NetworkConfig cfg;
        const MonoTime now{ 0 };

        Connection c = newConnection(cfg, 1234, now);
        markConnected(c, now);
        assert(c.localSeq != SequenceNum{ 0 });   // ...both on a fresh connection and on connect
        resetConnection(c);
        assert(c.localSeq != SequenceNum{ 0 });   // ...and on a recycled one

        // Register a reliable packet at the first sequence we would actually send.
        markConnected(c, now);
        const SequenceNum first = c.localSeq;
        assert(first == firstSequence);
        onPacketSent(c.reliability, first, now, ChannelId{ 0 }, SequenceNum{ 0 }, 200);
        assert(isInFlight(c.reliability, first));

        // Now the peer's very first header, sent before it had received anything: ack = 0, bits = 0.
        PacketHeader virgin{};
        virgin.type    = PacketType::Keepalive;
        virgin.ack     = SequenceNum{ 0 };
        virgin.ackBits = 0;
        processIncomingAcks(c, virgin, now);
        assert(isInFlight(c.reliability, first));   // still in flight: nothing was falsely confirmed
    }

    std::printf("transport_stats_test: all assertions passed\n");
    return 0;
}
