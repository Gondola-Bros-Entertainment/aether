#include "check.hpp"
// Congestion control: pins the Good/Bad AIMD rate controller (ccUpdate), RFC 2861 idle slow-start
// restart, window pacing gates, and the sliding-window bandwidth tracker. Data-first: structs driven
// by free functions.
// New Reno cwOnAck/cwOnLoss are covered elsewhere and not re-pinned here.
#include "aether/congestion.hpp"

#include <cstdio>

using namespace aether;
using aether::test::require;

// MonoTime is nanoseconds; build one from milliseconds for readable timelines.
static constexpr MonoTime atMs(double ms) { return MonoTime{ static_cast<std::uint64_t>(ms * 1.0e6) }; }

int main() {
    // A fractional packet rate must eventually admit a full datagram without refilling faster
    // than requested. Bucket capacity and refill rate are different quantities.
    {
        auto cc = aether::newCongestionController(.5, .5, .1, 250, 10000);
        aether::ccRefillBudget(cc, 1200, aether::MonoTime{1});
        require(cc.budgetBytes == 1200);
        aether::ccDeductBudget(cc, 1200);
        aether::ccRefillBudget(cc, 1200, aether::MonoTime{1000000001});
        require(cc.budgetBytes == 600);
        aether::ccRefillBudget(cc, 1200, aether::MonoTime{2000000001});
        require(cc.budgetBytes == 1200);
        aether::ccUpdate(cc, 1, 1000, aether::MonoTime{2000000002});
        require(cc.currentSendRate <= .5);
    }
    // --- ccUpdate: Good -> Bad multiplicative decrease ---
    // base=100 pkts/s, loss thresh 0.1, rtt thresh 100ms, recovery 2000ms (adaptive=2.0s).
    {
        CongestionController cc = newCongestionController(100.0, 400.0, 0.1, 100.0, 2000.0);
        require(cc.currentSendRate == 100.0);
        require(cc.mode == CongestionMode::Good);

        // First bad entry: no prior good entry, so recoveryMult=1.0 (no quick-drop yet).
        ccUpdate(cc, 0.5 /*loss > 0.1*/, 10.0, atMs(0.0));
        require(cc.mode == CongestionMode::Bad);
        require(cc.currentSendRate == 50.0);           // 100 * 0.5 multiplicative decrease
        require(cc.adaptiveRecoverySecs == 2.0);       // unchanged: mult was 1.0
    }

    // --- ccUpdate: RTT-spike alone (not loss) also drives Bad, and the rate floor holds ---
    {
        CongestionController cc = newCongestionController(2.0, 8.0, 0.1, 100.0, 1000.0);
        cc.currentSendRate = 1.5;
        ccUpdate(cc, 0.0 /*no loss*/, 250.0 /*rtt > 100*/, atMs(0.0));
        require(cc.mode == CongestionMode::Bad);
        require(cc.currentSendRate == minSendRate);     // max(1.0, 1.5*0.5=0.75) clamps to floor
    }

    // --- ccUpdate: quick-drop doubles recovery; adaptive-recovery halving shrinks it back ---
    {
        CongestionController cc = newCongestionController(100.0, 400.0, 0.1, 100.0, 2000.0);

        // Drive Bad then recover to Good so lastGoodEntry gets set (the quick-drop precondition).
        ccUpdate(cc, 0.5, 10.0, atMs(0.0));             // -> Bad, adaptive stays 2.0
        require(cc.mode == CongestionMode::Bad);
        ccUpdate(cc, 0.0, 10.0, atMs(100.0));           // good conditions begin
        ccUpdate(cc, 0.0, 10.0, atMs(2200.0));          // dwell (>=2000ms) elapsed -> Good
        require(cc.mode == CongestionMode::Good);
        require(cc.currentSendRate == 100.0);           // reset to base on Good entry
        require(cc.lastGoodEntry.has_value());

        // Quick-drop: go Bad again within 10s of the good entry -> recoveryMult=2.0 doubles adaptive.
        ccUpdate(cc, 0.5, 10.0, atMs(2300.0));          // 100ms since good entry < 10s
        require(cc.mode == CongestionMode::Bad);
        require(cc.adaptiveRecoverySecs == 4.0);        // 2.0 * 2.0 quick-drop multiplier

        // Adaptive-recovery halving: recover to Good, then stay good past a 10s halve interval.
        ccUpdate(cc, 0.0, 10.0, atMs(2400.0));          // good conditions begin (Bad)
        ccUpdate(cc, 0.0, 10.0, atMs(7000.0));          // dwell (>=4000ms) elapsed -> Good
        require(cc.mode == CongestionMode::Good);
        const double adaptiveAtGood = cc.adaptiveRecoverySecs;   // still 4.0
        require(adaptiveAtGood == 4.0);
        ccUpdate(cc, 0.0, 10.0, atMs(18000.0));         // ~11s good (>=10s interval) -> halve once
        require(cc.adaptiveRecoverySecs == 2.0);        // max(1.0, 4.0 / 2^1)
    }

    // --- ccUpdate: Bad -> Good only after the dwell time elapses ---
    {
        CongestionController cc = newCongestionController(100.0, 400.0, 0.1, 100.0, 2000.0);
        ccUpdate(cc, 0.5, 10.0, atMs(0.0));             // -> Bad, currentSendRate=50, adaptive=2.0s
        require(cc.mode == CongestionMode::Bad);
        require(cc.currentSendRate == 50.0);

        ccUpdate(cc, 0.0, 10.0, atMs(500.0));           // good conditions start at 500ms
        require(cc.mode == CongestionMode::Bad);        // dwell not elapsed -> still Bad
        require(cc.currentSendRate == 50.0);

        ccUpdate(cc, 0.0, 10.0, atMs(1000.0));          // only 500ms < 2000ms dwell -> still Bad
        require(cc.mode == CongestionMode::Bad);

        ccUpdate(cc, 0.0, 10.0, atMs(2600.0));          // 2100ms >= 2000ms dwell -> Good, rate=base
        require(cc.mode == CongestionMode::Good);
        require(cc.currentSendRate == 100.0);
    }

    // --- cwSlowStartRestart: idle gap > 2*RTO resets cwnd, ssthresh = previous cwnd ---
    {
        CongestionWindow cw = newCongestionWindow(1200);
        const double initialCwnd = static_cast<double>(initialCwndPackets * 1200);
        require(cw.cwnd == initialCwnd);

        // Grow the window past initial so the restart is observable, then send to stamp lastSendTime.
        cw.phase = CongestionPhase::Avoidance;
        cw.cwnd  = 50000.0;
        cwOnSend(cw, 1200, atMs(0.0));
        require(cw.lastSendTime.has_value());

        const double rtoMs = 200.0;
        // Within 2*RTO: no restart.
        cwSlowStartRestart(cw, rtoMs, atMs(300.0));     // 300ms < 400ms -> unchanged
        require(cw.cwnd == 50000.0);
        require(cw.phase == CongestionPhase::Avoidance);

        // Past 2*RTO: restart -- cwnd back to initial, ssthresh = the cwnd we had.
        cwSlowStartRestart(cw, rtoMs, atMs(500.0));     // 500ms > 400ms -> restart
        require(cw.phase == CongestionPhase::SlowStart);
        require(cw.cwnd == initialCwnd);
        require(cw.ssthresh == 50000.0);                // previous cwnd

        // ...and the restart clears bytesInFlight: after 2 RTOs of silence nothing is still in the
        // network. The 1200 charged above was never resolved (a packet lost right before the idle,
        // with no later traffic to NACK it) -- ghost bytes that would otherwise occupy the fresh
        // window until that ring slot was reused.
        require(cw.bytesInFlight == 0);
        require(cwCanSend(cw, 1200));
    }

    // --- cwUpdatePacing / cwCanSendPaced: the gate binds WITHIN a tick ---
    // A timestamp compare against the last flush answers identically for every packet in a tick, so
    // the tick passes all of its traffic or none of it. Tokens are spent one per admitted packet, so
    // the second packet of a tick sees a different answer from the first.
    {
        CongestionWindow cw = newCongestionWindow(1200);
        // cwnd = 12000 bytes = 10 packets; rtt 100ms -> 100/10 = 10ms min inter-packet delay.
        cwUpdatePacing(cw, 100.0, atMs(0.0));
        require(cw.minInterPacketDelay == 10.0);

        int burst = 0;                                   // the seeded bucket: one window's worth, then dry
        while (cwCanSendPaced(cw)) { cwOnPacedSend(cw); ++burst; }
        require(burst == 10);
        require(!cwCanSendPaced(cw));                    // ...and no more at the same instant

        cwUpdatePacing(cw, 100.0, atMs(16.0));           // one 60Hz tick earns 1.6 intervals
        int second = 0;
        while (cwCanSendPaced(cw)) { cwOnPacedSend(cw); ++second; }
        require(second == 1);                            // one whole packet; the 0.6 carries forward
    }

    // --- ...and pacing is not a function of the caller's TICK RATE ---
    // The same second of wall clock must release the same number of packets whether the application
    // ticks at 20Hz or 144Hz. Comparing `now` against a per-flush timestamp would make the answer
    // swing between "everything" and "nothing" purely on where the tick boundary falls.
    {
        const auto releasedInOneSecond = [](double hz) {
            CongestionWindow cw = newCongestionWindow(1200);
            cw.cwnd = 120.0 * 1200.0;                    // 120-packet window: 100ms rtt -> 0.833ms apart
            int sent = 0;
            for (int i = 0; i <= static_cast<int>(hz); ++i) {
                cwUpdatePacing(cw, 100.0, atMs(i * (1000.0 / hz)));
                while (cwCanSendPaced(cw)) { cwOnPacedSend(cw); ++sent; }
            }
            return sent;
        };
        const int fast = releasedInOneSecond(144.0);
        const int slow = releasedInOneSecond(20.0);
        require(fast > 1200 && slow > 1200);             // ~1200 paced + the seeded window
        require(fast - slow <= 2 && slow - fast <= 2);   // identical bar the rounding of the tick grid
    }

    // --- BandwidthTracker: a bucketed sliding window whose rate decays on its own ---
    // Reading it takes the time, so bytes leave the window as it slides -- an idle connection reports 0
    // rather than its last burst, with no sweep to remember and no per-packet allocation to make.
    {
        const double windowMs = 1000.0;
        BandwidthTracker bt = newBandwidthTracker(windowMs);
        require(btBytesPerSecond(bt, atMs(0.0)) == 0.0);       // nothing recorded

        btRecord(bt, 500, atMs(0.0));
        btRecord(bt, 500, atMs(100.0));
        require(btBytesPerSecond(bt, atMs(100.0)) == 1000.0);   // 1000 bytes in the last second

        // Slide the window past the first two records: only the third is still inside it.
        btRecord(bt, 200, atMs(1100.0));
        require(btBytesPerSecond(bt, atMs(1100.0)) == 200.0);

        // Read with no fresh record at all, a full window later -> everything has aged out.
        require(btBytesPerSecond(bt, atMs(2200.0)) == 0.0);

        // Sub-bucket writes accumulate rather than replacing each other (both land in bucket 0).
        BandwidthTracker fine = newBandwidthTracker(windowMs);
        btRecord(fine, 10, atMs(0.0));
        btRecord(fine, 10, atMs(1.0));
        require(btBytesPerSecond(fine, atMs(1.0)) == 20.0);

        // The ring cycles: a record one full window later reuses slot 0, and the stale bytes it held are
        // discarded instead of being counted twice.
        btRecord(fine, 30, atMs(windowMs));
        require(btBytesPerSecond(fine, atMs(windowMs)) == 30.0);
    }

    // --- the AIMD ramp is held under the configured packet-rate cap, not just 4x base ---
    // A validated maxPacketRate must also bind the ramp, which would otherwise run to 4*sendRate.
    {
        CongestionController cc = newCongestionController(60.0, 120.0, 0.1, 100.0, 2000.0);
        require(ccMaxSendRate(cc) == 120.0);            // min(4*60, 120), not 240
        for (int i = 0; i < 200; ++i) ccUpdate(cc, 0.0, 10.0, atMs(i * 100.0));
        require(cc.currentSendRate == 120.0);           // pinned at the cap, not ramping past it
    }

    // --- the byte budget is a TOKEN BUCKET earned from elapsed time, not a per-tick grant ---
    // A full second's worth per call would let a 60Hz loop send 60x the configured rate, and the rate
    // arm of the controller would never bind.
    {
        constexpr int mtu = 1200;
        CongestionController cc = newCongestionController(60.0, 120.0, 0.1, 100.0, 2000.0);

        ccRefillBudget(cc, mtu, atMs(0.0));             // first call has no elapsed time: seed full
        require(cc.burstBytes == 60.0 * mtu);           // capacity == one second at the current rate
        require(cc.budgetBytes == cc.burstBytes);

        ccDeductBudget(cc, 60 * mtu);
        require(cc.budgetBytes == 0.0);
        require(!ccCanSend(cc, 1));

        ccRefillBudget(cc, mtu, atMs(0.0));             // no time passed -> nothing earned
        require(cc.budgetBytes == 0.0);

        ccRefillBudget(cc, mtu, atMs(1000.0 / 60.0));   // one 60Hz tick earns one packet, not a second
        require(cc.budgetBytes > 1150.0 && cc.budgetBytes < 1250.0);

        ccRefillBudget(cc, mtu, atMs(60000.0));         // a long idle gap banks at most the capacity
        require(cc.budgetBytes == cc.burstBytes);
    }

    // --- the window returns every byte it charges: acked, declared lost, or evicted ---
    {
        CongestionWindow cw = newCongestionWindow(1200);
        cwOnSend(cw, 1200, atMs(0.0));
        cwOnSend(cw, 1200, atMs(1.0));
        require(cw.bytesInFlight == 2400);

        cwReleaseInFlight(cw, 1200);                    // one declared lost -> leaves flight, no growth
        require(cw.bytesInFlight == 1200);
        cwOnAck(cw, 1200);                              // one acked -> leaves flight and grows
        require(cw.bytesInFlight == 0);

        cwReleaseInFlight(cw, 5000);                    // saturates at zero, never wraps
        require(cw.bytesInFlight == 0);
    }

    // --- a run where every packet is lost must not leak the window shut ---
    // A lost packet's bytes must leave bytesInFlight; otherwise it only grows until it reaches cwnd
    // and the window admits nothing but sub-64-byte reliable messages.
    {
        CongestionWindow cw = newCongestionWindow(1200);
        for (int i = 0; i < 500; ++i) {
            cwOnSend(cw, 1200, atMs(i * 16.0));
            cwReleaseInFlight(cw, 1200);                // what processIncomingAcks does with lostBytes
            cwOnLoss(cw);
        }
        require(cw.bytesInFlight == 0);
        require(cwCanSend(cw, 1200));                   // still open for business
    }

    // --- the additive increase is per SECOND, so the ramp does not depend on the caller's tick rate ---
    // A per-call increment would make the send rate a function of frame rate: a 144Hz loop would ramp
    // more than 7x faster than a 20Hz one from identical network conditions.
    {
        CongestionController fast = newCongestionController(60.0, 1000.0, 0.1, 100.0, 2000.0);
        CongestionController slow = newCongestionController(60.0, 1000.0, 0.1, 100.0, 2000.0);
        for (int i = 0; i <= 144; ++i) ccUpdate(fast, 0.0, 10.0, atMs(i * (1000.0 / 144.0)));   // 1s at 144Hz
        for (int i = 0; i <= 20;  ++i) ccUpdate(slow, 0.0, 10.0, atMs(i * (1000.0 / 20.0)));    // 1s at 20Hz
        const double ramped = sendRateIncreasePerSec;                    // one second of good conditions
        require(fast.currentSendRate > 60.0 + ramped - 0.5 && fast.currentSendRate < 60.0 + ramped + 0.5);
        require(slow.currentSendRate > 60.0 + ramped - 0.5 && slow.currentSendRate < 60.0 + ramped + 0.5);
    }

    // --- one window reduction per loss EPISODE, with an ACK INTERLEAVED between the two drops ---
    //
    // Two packets of ONE flight reach their triple-NACK threshold in different headers, and between
    // them a header arrives that acks with no loss. That header ends fast recovery, so the second drop
    // is judged with the phase already back in avoidance: a phase-based guard lets it halve again, and
    // one congestion signal takes two full reductions (four spread drops reach the cwnd floor). The
    // episode is a fact about SEQUENCE space, so processAcks is what decides it.
    {
        ReliableEndpoint tx{}, rx{};
        const ChannelId  ch{ 0 };
        for (std::uint16_t s = 1; s <= 10; ++s)
            onPacketSent(tx, SequenceNum{ s }, atMs(0.0), ch, SequenceNum{ s }, 1200);

        CongestionWindow cw = newCongestionWindow(1200);
        cw.phase = CongestionPhase::Avoidance;
        cw.cwnd  = 48000.0;

        // One arriving packet -> the header the receiver would send -> exactly what processIncomingAcks
        // does with it. Hoisted into a lambda because every step of the timeline mutates both endpoints.
        const auto deliver = [&](std::uint16_t arrived) {
            const SequenceNum sn{ arrived };
            onPacketsReceived(rx, &sn, 1);
            const auto [ackSeq, bits] = getAckInfo(rx);
            const AckResult r = processAcks(tx, ackSeq, bits, atMs(60.0));
            if (r.lostPackets > 0) { if (r.newLossEpisode) cwOnLoss(cw); }
            else if (r.ackedPackets > 0) cwOnAck(cw, r.ackedBytes);
            return r;
        };

        deliver(1);                                       // seq 2 and seq 6 are the drops
        deliver(3);
        deliver(4);
        const double cwndAtLoss = cw.cwnd;                // the acks above grew it a little
        const AckResult declaredFirst = deliver(5);       // seq 2 crosses the threshold here
        require(declaredFirst.lostPackets == 1 && declaredFirst.newLossEpisode);
        require(cw.phase == CongestionPhase::Recovery);
        const double afterFirst = cw.ssthresh;
        require(afterFirst == cwndAtLoss / 2.0);          // ONE reduction so far

        const AckResult clean = deliver(7);               // acks, no new loss -> fast recovery ends here
        require(clean.lostPackets == 0);
        require(cw.phase == CongestionPhase::Avoidance);   // the phase can no longer identify the episode

        deliver(8);
        const AckResult declaredSecond = deliver(9);      // seq 6 crosses the threshold: SAME flight
        require(declaredSecond.lostPackets == 1);
        require(!declaredSecond.newLossEpisode);          // already responded to; not a fresh signal
        require(cw.ssthresh == afterFirst);               // still one reduction, not halved a second time

        // A drop from a LATER flight is a genuinely new episode and does reduce again.
        for (std::uint16_t s = 11; s <= 20; ++s)
            onPacketSent(tx, SequenceNum{ s }, atMs(100.0), ch, SequenceNum{ s }, 1200);
        const double beforeNewEpisode = cw.ssthresh;
        deliver(11);                                      // seq 12 is the drop
        deliver(13);
        deliver(14);
        const AckResult declaredThird = deliver(15);
        require(declaredThird.newLossEpisode);
        require(cw.phase == CongestionPhase::Recovery);
        require(cw.ssthresh < beforeNewEpisode);
    }

    // --- cwOnLoss itself is the reduction, applied once per episode by its caller ---
    {
        CongestionWindow cw = newCongestionWindow(1200);
        cw.phase = CongestionPhase::Avoidance;
        cw.cwnd  = 48000.0;
        cwOnLoss(cw);
        require(cw.phase == CongestionPhase::Recovery);
        require(cw.ssthresh == 24000.0);
        require(cw.cwnd == 24000.0 + 3.0 * 1200.0);       // fast recovery inflates by the 3 segments that left
        cwOnAck(cw, 1200);                                // first ack of new data deflates back
        require(cw.phase == CongestionPhase::Avoidance && cw.cwnd == cw.ssthresh);
    }

    // --- an idle slow-start restart must leave the sent ring and the window consistent ---
    // The restart zeroes bytesInFlight because nothing of ours can still be in the network. Records left
    // behind in the sent ring would each report their size ONE MORE TIME -- on a late ack, a loss
    // declaration or an eviction -- and every one of those subtractions comes off a counter that no
    // longer holds those bytes, so the window under-counts and over-admits by up to a full ring.
    {
        ReliableEndpoint ep{};
        const ChannelId  ch{ 0 };
        CongestionWindow cw = newCongestionWindow(1200);
        for (std::uint16_t s = 1; s <= 20; ++s) {
            onPacketSent(ep, SequenceNum{ s }, atMs(0.0), ch, SequenceNum{ s }, 1000);
            cwOnSend(cw, 1000, atMs(0.0));
        }
        require(cw.bytesInFlight == 20000 && packetsInFlight(ep) == 20);

        const bool restarted = cwSlowStartRestart(cw, 100.0, atMs(1000.0));   // 1s idle > 2 * 100ms RTO
        require(restarted);
        require(cw.bytesInFlight == 0);
        abandonSentPackets(ep);                          // what updateConnectedPure does on a restart
        require(packetsInFlight(ep) == 0);

        // A late ack for an abandoned record resolves to nothing, so it cannot subtract bytes the
        // window no longer holds.
        const AckResult late = processAcks(ep, SequenceNum{ 20 }, 0xFFFFFFFFull, atMs(1100.0));
        require(late.ackedBytes == 0 && late.lostBytes == 0 && late.acked.empty());
        cwReleaseInFlight(cw, late.ackedBytes + late.lostBytes);
        require(cw.bytesInFlight == 0);

        // ...and the fresh window admits exactly its own size, not more.
        require(cwCanSend(cw, static_cast<int>(cw.cwnd)));
        require(!cwCanSend(cw, static_cast<int>(cw.cwnd) + 1));
    }

    // --- processAcks reports a declared loss's bytes exactly once, and a late ack does not re-credit ---
    {
        ReliableEndpoint ep{};
        const ChannelId  ch{ 0 };
        for (std::uint16_t s = 0; s < 6; ++s)
            onPacketSent(ep, SequenceNum{ s }, atMs(0.0), ch, SequenceNum{ s }, 100);

        ReliableEndpoint peer{};   // everything but seq 0 arrives, so seq 0 is NACKed by the bitfield
        const SequenceNum got[] = { SequenceNum{ 1 }, SequenceNum{ 2 }, SequenceNum{ 3 },
                                    SequenceNum{ 4 }, SequenceNum{ 5 } };
        onPacketsReceived(peer, got, 5);
        const auto [ackSeq, ackBits] = getAckInfo(peer);

        int declaredLost = 0;
        for (int i = 0; i < fastRetransmitThreshold; ++i)
            declaredLost += processAcks(ep, ackSeq, ackBits, atMs(60.0)).lostBytes;
        require(declaredLost == 100);                   // seq 0's bytes, reported once across the passes

        const AckResult late = processAcks(ep, SequenceNum{ 0 }, 0, atMs(70.0));
        require(!late.acked.empty());                   // seq 0 was delivered after all...
        require(late.ackedBytes == 0);                  // ...but its bytes already left flight when declared
    }

    // --- onPacketSent reports the bytes of a packet evicted to make room ---
    // An evicted packet is never resolved by an ack, so its bytes would stay in flight forever.
    {
        ReliableEndpoint ep{};
        ep.maxInFlight = 2;
        const ChannelId ch{ 0 };
        require(onPacketSent(ep, SequenceNum{ 0 }, atMs(0.0), ch, SequenceNum{ 0 }, 111) == 0);
        require(onPacketSent(ep, SequenceNum{ 1 }, atMs(1.0), ch, SequenceNum{ 1 }, 222) == 0);
        require(onPacketSent(ep, SequenceNum{ 2 }, atMs(2.0), ch, SequenceNum{ 2 }, 333) == 111);   // oldest goes
    }

    std::printf("congestion_test: AIMD + rate cap + tick-rate-independent ramp, token bucket, "
                "one reduction per loss episode, window byte conservation, slow-start-restart, pacing, "
                "bandwidth-tracker OK\n");
    return 0;
}
