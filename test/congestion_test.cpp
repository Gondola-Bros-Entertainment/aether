// Congestion control: pins the parts an audit found untested -- the Good/Bad AIMD rate
// controller (ccUpdate), RFC 2861 idle slow-start restart, window pacing gates, and the
// sliding-window bandwidth tracker. Data-first: structs driven by free functions, assert checks.
// New Reno cwOnAck/cwOnLoss are covered elsewhere and not re-pinned here.
#include "aether/congestion.hpp"

#include <cassert>
#include <cstdio>

using namespace aether;

// MonoTime is nanoseconds; build one from milliseconds for readable timelines.
static constexpr MonoTime atMs(double ms) { return MonoTime{ static_cast<std::uint64_t>(ms * 1.0e6) }; }

int main() {
    // --- ccUpdate: Good -> Bad multiplicative decrease ---
    // base=100 pkts/s, loss thresh 0.1, rtt thresh 100ms, recovery 2000ms (adaptive=2.0s).
    {
        CongestionController cc = newCongestionController(100.0, 400.0, 0.1, 100.0, 2000.0);
        assert(cc.currentSendRate == 100.0);
        assert(cc.mode == CongestionMode::Good);

        // First bad entry: no prior good entry, so recoveryMult=1.0 (no quick-drop yet).
        ccUpdate(cc, 0.5 /*loss > 0.1*/, 10.0, atMs(0.0));
        assert(cc.mode == CongestionMode::Bad);
        assert(cc.currentSendRate == 50.0);            // 100 * 0.5 multiplicative decrease
        assert(cc.adaptiveRecoverySecs == 2.0);        // unchanged: mult was 1.0
    }

    // --- ccUpdate: RTT-spike alone (not loss) also drives Bad, and the rate floor holds ---
    {
        CongestionController cc = newCongestionController(2.0, 8.0, 0.1, 100.0, 1000.0);
        cc.currentSendRate = 1.5;
        ccUpdate(cc, 0.0 /*no loss*/, 250.0 /*rtt > 100*/, atMs(0.0));
        assert(cc.mode == CongestionMode::Bad);
        assert(cc.currentSendRate == minSendRate);      // max(1.0, 1.5*0.5=0.75) clamps to floor
    }

    // --- ccUpdate: quick-drop doubles recovery; adaptive-recovery halving shrinks it back ---
    {
        CongestionController cc = newCongestionController(100.0, 400.0, 0.1, 100.0, 2000.0);

        // Drive Bad then recover to Good so lastGoodEntry gets set (the quick-drop precondition).
        ccUpdate(cc, 0.5, 10.0, atMs(0.0));             // -> Bad, adaptive stays 2.0
        assert(cc.mode == CongestionMode::Bad);
        ccUpdate(cc, 0.0, 10.0, atMs(100.0));           // good conditions begin
        ccUpdate(cc, 0.0, 10.0, atMs(2200.0));          // dwell (>=2000ms) elapsed -> Good
        assert(cc.mode == CongestionMode::Good);
        assert(cc.currentSendRate == 100.0);            // reset to base on Good entry
        assert(cc.lastGoodEntry.has_value());

        // Quick-drop: go Bad again within 10s of the good entry -> recoveryMult=2.0 doubles adaptive.
        ccUpdate(cc, 0.5, 10.0, atMs(2300.0));          // 100ms since good entry < 10s
        assert(cc.mode == CongestionMode::Bad);
        assert(cc.adaptiveRecoverySecs == 4.0);         // 2.0 * 2.0 quick-drop multiplier

        // Adaptive-recovery halving: recover to Good, then stay good past a 10s halve interval.
        ccUpdate(cc, 0.0, 10.0, atMs(2400.0));          // good conditions begin (Bad)
        ccUpdate(cc, 0.0, 10.0, atMs(7000.0));          // dwell (>=4000ms) elapsed -> Good
        assert(cc.mode == CongestionMode::Good);
        const double adaptiveAtGood = cc.adaptiveRecoverySecs;   // still 4.0
        assert(adaptiveAtGood == 4.0);
        ccUpdate(cc, 0.0, 10.0, atMs(18000.0));         // ~11s good (>=10s interval) -> halve once
        assert(cc.adaptiveRecoverySecs == 2.0);         // max(1.0, 4.0 / 2^1)
    }

    // --- ccUpdate: Bad -> Good only after the dwell time elapses ---
    {
        CongestionController cc = newCongestionController(100.0, 400.0, 0.1, 100.0, 2000.0);
        ccUpdate(cc, 0.5, 10.0, atMs(0.0));             // -> Bad, currentSendRate=50, adaptive=2.0s
        assert(cc.mode == CongestionMode::Bad);
        assert(cc.currentSendRate == 50.0);

        ccUpdate(cc, 0.0, 10.0, atMs(500.0));           // good conditions start at 500ms
        assert(cc.mode == CongestionMode::Bad);         // dwell not elapsed -> still Bad
        assert(cc.currentSendRate == 50.0);

        ccUpdate(cc, 0.0, 10.0, atMs(1000.0));          // only 500ms < 2000ms dwell -> still Bad
        assert(cc.mode == CongestionMode::Bad);

        ccUpdate(cc, 0.0, 10.0, atMs(2600.0));          // 2100ms >= 2000ms dwell -> Good, rate=base
        assert(cc.mode == CongestionMode::Good);
        assert(cc.currentSendRate == 100.0);
    }

    // --- cwSlowStartRestart: idle gap > 2*RTO resets cwnd, ssthresh = previous cwnd ---
    {
        CongestionWindow cw = newCongestionWindow(1200);
        const double initialCwnd = static_cast<double>(initialCwndPackets * 1200);
        assert(cw.cwnd == initialCwnd);

        // Grow the window past initial so the restart is observable, then send to stamp lastSendTime.
        cw.phase = CongestionPhase::Avoidance;
        cw.cwnd  = 50000.0;
        cwOnSend(cw, 1200, atMs(0.0));
        assert(cw.lastSendTime.has_value());

        const double rtoMs = 200.0;
        // Within 2*RTO: no restart.
        cwSlowStartRestart(cw, rtoMs, atMs(300.0));     // 300ms < 400ms -> unchanged
        assert(cw.cwnd == 50000.0);
        assert(cw.phase == CongestionPhase::Avoidance);

        // Past 2*RTO: restart -- cwnd back to initial, ssthresh = the cwnd we had.
        cwSlowStartRestart(cw, rtoMs, atMs(500.0));     // 500ms > 400ms -> restart
        assert(cw.phase == CongestionPhase::SlowStart);
        assert(cw.cwnd == initialCwnd);
        assert(cw.ssthresh == 50000.0);                 // previous cwnd

        // ...and the restart clears bytesInFlight: after 2 RTOs of silence nothing is still in the
        // network. The 1200 charged above was never resolved (a packet lost right before the idle,
        // with no later traffic to NACK it) -- ghost bytes that would otherwise occupy the fresh
        // window until that ring slot was reused.
        assert(cw.bytesInFlight == 0);
        assert(cwCanSend(cw, 1200));
    }

    // --- cwUpdatePacing / cwCanSendPaced: the inter-packet delay actually gates a send ---
    {
        CongestionWindow cw = newCongestionWindow(1200);
        // cwnd = 12000 bytes = 10 packets; rtt 100ms -> 100/10 = 10ms min inter-packet delay.
        cwUpdatePacing(cw, 100.0);
        assert(cw.minInterPacketDelay == 10.0);

        // No send yet -> always allowed.
        const bool firstAllowed = cwCanSendPaced(cw, atMs(0.0));
        assert(firstAllowed);

        cwOnSend(cw, 1200, atMs(0.0));                  // stamp the send time
        const bool tooSoon = cwCanSendPaced(cw, atMs(5.0));   // 5ms < 10ms -> gated
        assert(!tooSoon);
        const bool afterInterval = cwCanSendPaced(cw, atMs(10.0)); // 10ms >= 10ms -> allowed
        assert(afterInterval);
    }

    // --- BandwidthTracker: a bucketed sliding window whose rate decays on its own ---
    // Reading it takes the time, so bytes leave the window as it slides -- an idle connection reports 0
    // rather than its last burst, with no sweep to remember and no per-packet allocation to make.
    {
        const double windowMs = 1000.0;
        BandwidthTracker bt = newBandwidthTracker(windowMs);
        assert(btBytesPerSecond(bt, atMs(0.0)) == 0.0);        // nothing recorded

        btRecord(bt, 500, atMs(0.0));
        btRecord(bt, 500, atMs(100.0));
        assert(btBytesPerSecond(bt, atMs(100.0)) == 1000.0);   // 1000 bytes in the last second

        // Slide the window past the first two records: only the third is still inside it.
        btRecord(bt, 200, atMs(1100.0));
        assert(btBytesPerSecond(bt, atMs(1100.0)) == 200.0);

        // Read with no fresh record at all, a full window later -> everything has aged out.
        assert(btBytesPerSecond(bt, atMs(2200.0)) == 0.0);

        // Sub-bucket writes accumulate rather than replacing each other (both land in bucket 0).
        BandwidthTracker fine = newBandwidthTracker(windowMs);
        btRecord(fine, 10, atMs(0.0));
        btRecord(fine, 10, atMs(1.0));
        assert(btBytesPerSecond(fine, atMs(1.0)) == 20.0);

        // The ring cycles: a record one full window later reuses slot 0, and the stale bytes it held are
        // discarded instead of being counted twice.
        btRecord(fine, 30, atMs(windowMs));
        assert(btBytesPerSecond(fine, atMs(windowMs)) == 30.0);
    }

    // --- the AIMD ramp is held under the configured packet-rate cap, not just 4x base ---
    // maxPacketRate was validated at setup and then never enforced, so the ramp ran to 4*sendRate
    // regardless of it.
    {
        CongestionController cc = newCongestionController(60.0, 120.0, 0.1, 100.0, 2000.0);
        assert(ccMaxSendRate(cc) == 120.0);             // min(4*60, 120), not 240
        for (int i = 0; i < 200; ++i) ccUpdate(cc, 0.0, 10.0, atMs(i * 100.0));
        assert(cc.currentSendRate == 120.0);            // pinned at the cap, not ramping past it
    }

    // --- the byte budget is a TOKEN BUCKET earned from elapsed time, not a per-tick grant ---
    // It used to hand out a full second's worth on every call, so a 60Hz loop was allowed 60x the
    // configured send rate and the rate arm of the controller never actually bound.
    {
        constexpr int mtu = 1200;
        CongestionController cc = newCongestionController(60.0, 120.0, 0.1, 100.0, 2000.0);

        ccRefillBudget(cc, mtu, atMs(0.0));             // first call has no elapsed time: seed full
        assert(cc.burstBytes == 60.0 * mtu);            // capacity == one second at the current rate
        assert(cc.budgetBytes == cc.burstBytes);

        ccDeductBudget(cc, 60 * mtu);
        assert(cc.budgetBytes == 0.0);
        assert(!ccCanSend(cc, 1));

        ccRefillBudget(cc, mtu, atMs(0.0));             // no time passed -> nothing earned
        assert(cc.budgetBytes == 0.0);

        ccRefillBudget(cc, mtu, atMs(1000.0 / 60.0));   // one 60Hz tick earns one packet, not a second
        assert(cc.budgetBytes > 1150.0 && cc.budgetBytes < 1250.0);

        ccRefillBudget(cc, mtu, atMs(60000.0));         // a long idle gap banks at most the capacity
        assert(cc.budgetBytes == cc.burstBytes);
    }

    // --- the window returns every byte it charges: acked, declared lost, or evicted ---
    {
        CongestionWindow cw = newCongestionWindow(1200);
        cwOnSend(cw, 1200, atMs(0.0));
        cwOnSend(cw, 1200, atMs(1.0));
        assert(cw.bytesInFlight == 2400);

        cwReleaseInFlight(cw, 1200);                    // one declared lost -> leaves flight, no growth
        assert(cw.bytesInFlight == 1200);
        cwOnAck(cw, 1200);                              // one acked -> leaves flight and grows
        assert(cw.bytesInFlight == 0);

        cwReleaseInFlight(cw, 5000);                    // saturates at zero, never wraps
        assert(cw.bytesInFlight == 0);
    }

    // --- a run where every packet is lost must not leak the window shut ---
    // Nothing returned a lost packet's bytes, so bytesInFlight only ever grew until it reached cwnd
    // and the window stopped admitting anything but sub-64-byte reliable messages.
    {
        CongestionWindow cw = newCongestionWindow(1200);
        for (int i = 0; i < 500; ++i) {
            cwOnSend(cw, 1200, atMs(i * 16.0));
            cwReleaseInFlight(cw, 1200);                // what processIncomingHeader does with lostBytes
            cwOnLoss(cw);
        }
        assert(cw.bytesInFlight == 0);
        assert(cwCanSend(cw, 1200));                    // still open for business
    }

    // --- the additive increase is per SECOND, so the ramp does not depend on the caller's tick rate ---
    // A per-call increment made the send rate a function of frame rate: a 144Hz loop ramped more than
    // 7x faster than a 20Hz one from identical network conditions.
    {
        CongestionController fast = newCongestionController(60.0, 1000.0, 0.1, 100.0, 2000.0);
        CongestionController slow = newCongestionController(60.0, 1000.0, 0.1, 100.0, 2000.0);
        for (int i = 0; i <= 144; ++i) ccUpdate(fast, 0.0, 10.0, atMs(i * (1000.0 / 144.0)));   // 1s at 144Hz
        for (int i = 0; i <= 20;  ++i) ccUpdate(slow, 0.0, 10.0, atMs(i * (1000.0 / 20.0)));    // 1s at 20Hz
        const double ramped = sendRateIncreasePerSec;                    // one second of good conditions
        assert(fast.currentSendRate > 60.0 + ramped - 0.5 && fast.currentSendRate < 60.0 + ramped + 0.5);
        assert(slow.currentSendRate > 60.0 + ramped - 0.5 && slow.currentSendRate < 60.0 + ramped + 0.5);
    }

    // --- one window reduction per loss episode ---
    // A burst drop trips several packets' triple-NACK thresholds inside the same window. Halving on each
    // took the window to a fraction of the single reduction congestion actually called for; the second
    // and later losses of an episode we are already recovering from must not cut it again (NewReno).
    {
        CongestionWindow cw = newCongestionWindow(1200);
        cw.phase = CongestionPhase::Avoidance;
        cw.cwnd  = 48000.0;

        cwOnLoss(cw);                                    // the episode: ssthresh 24000, cwnd inflated by 3 MSS
        assert(cw.phase == CongestionPhase::Recovery);
        assert(cw.ssthresh == 24000.0);
        const double afterFirst = cw.cwnd;
        assert(afterFirst == 24000.0 + 3.0 * 1200.0);

        cwOnLoss(cw);                                    // more of the same burst
        cwOnLoss(cw);
        assert(cw.ssthresh == 24000.0);                  // still one reduction, not 24000 -> 12000 -> 6000
        assert(cw.cwnd == afterFirst);

        cwOnAck(cw, 1200);                               // first ack of new data ends the episode...
        assert(cw.phase == CongestionPhase::Avoidance && cw.cwnd == cw.ssthresh);
        cwOnLoss(cw);                                    // ...so a NEW episode reduces again
        assert(cw.ssthresh == 12000.0);
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
        assert(declaredLost == 100);                    // seq 0's bytes, reported once across the passes

        const AckResult late = processAcks(ep, SequenceNum{ 0 }, 0, atMs(70.0));
        assert(!late.acked.empty());                    // seq 0 was delivered after all...
        assert(late.ackedBytes == 0);                   // ...but its bytes already left flight when declared
    }

    // --- onPacketSent reports the bytes of a packet evicted to make room ---
    // An evicted packet is never resolved by an ack, so its bytes would stay in flight forever.
    {
        ReliableEndpoint ep{};
        ep.maxInFlight = 2;
        const ChannelId ch{ 0 };
        assert(onPacketSent(ep, SequenceNum{ 0 }, atMs(0.0), ch, SequenceNum{ 0 }, 111) == 0);
        assert(onPacketSent(ep, SequenceNum{ 1 }, atMs(1.0), ch, SequenceNum{ 1 }, 222) == 0);
        assert(onPacketSent(ep, SequenceNum{ 2 }, atMs(2.0), ch, SequenceNum{ 2 }, 333) == 111);   // oldest goes
    }

    std::printf("congestion_test: AIMD + rate cap + tick-rate-independent ramp, token bucket, "
                "one reduction per loss episode, window byte conservation, slow-start-restart, pacing, "
                "bandwidth-tracker OK\n");
    return 0;
}
