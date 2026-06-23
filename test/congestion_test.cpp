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
        CongestionController cc = newCongestionController(100.0, 0.1, 100.0, 2000.0);
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
        CongestionController cc = newCongestionController(2.0, 0.1, 100.0, 1000.0);
        cc.currentSendRate = 1.5;
        ccUpdate(cc, 0.0 /*no loss*/, 250.0 /*rtt > 100*/, atMs(0.0));
        assert(cc.mode == CongestionMode::Bad);
        assert(cc.currentSendRate == minSendRate);      // max(1.0, 1.5*0.5=0.75) clamps to floor
    }

    // --- ccUpdate: quick-drop doubles recovery; adaptive-recovery halving shrinks it back ---
    {
        CongestionController cc = newCongestionController(100.0, 0.1, 100.0, 2000.0);

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
        CongestionController cc = newCongestionController(100.0, 0.1, 100.0, 2000.0);
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

    // --- BandwidthTracker: old bytes evict past the window; rate reflects only the live window ---
    {
        const double windowMs = 1000.0;
        BandwidthTracker bt = newBandwidthTracker(windowMs);
        assert(btBytesPerSecond(bt) == 0.0);            // empty

        btRecord(bt, 500, atMs(0.0));
        btRecord(bt, 500, atMs(100.0));
        assert(bt.totalBytes == 1000);                  // both inside the window
        // rate = totalBytes / (windowMs/1000) = 1000 / 1.0s
        assert(btBytesPerSecond(bt) == 1000.0);

        // Record past the window: the two old (>=1000ms) entries evict, only the new one remains.
        btRecord(bt, 200, atMs(1100.0));                // cleanup runs: 0ms and 100ms entries drop
        assert(bt.window.size() == 1);
        assert(bt.totalBytes == 200);                   // only the current-window bytes
        assert(btBytesPerSecond(bt) == 200.0);          // 200 / 1.0s

        // Explicit btCleanup with no fresh record also evicts the lone stale entry.
        btCleanup(bt, atMs(2200.0));                    // 1100ms entry is now 1100ms old (>=1000)
        assert(bt.window.empty());
        assert(bt.totalBytes == 0);
        assert(btBytesPerSecond(bt) == 0.0);
    }

    std::printf("congestion_test: ccUpdate AIMD, slow-start-restart, pacing, bandwidth-tracker OK\n");
    return 0;
}
