// aether - clocksync edge behavior. Pins three things an audit found untested: bestRttMs decays
// UPWARD (a fluke-low best is forgotten, not pinned forever), a negative RTT sample is rejected,
// and the offset EMA smooths toward the observed offset. assert() IS the check -> no NDEBUG.
#include <aether/clocksync.hpp>

#include <cassert>
#include <cstdio>

int main() {
    constexpr double eps = 1e-6;

    // bestRttMs upward decay: one fluke-low RTT sets the best, then many higher RTTs relax it UP.
    {
        aether::ClockSync cs;
        // t0=0, t2=10 -> rtt 10 (the one-off low). remote chosen so offset is irrelevant here.
        aether::clockSyncObserve(cs, 0.0, 5.0, 10.0);
        assert(cs.hasSample);
        const double low = cs.bestRttMs;
        assert(low > 10.0 - eps && low < 10.0 + eps);   // best pinned at the fluke low

        // Now feed a long run of rtt=100 samples; the best must climb toward 100, never above it,
        // and never below where it started -- a decaying recent best, not a lifetime minimum.
        double prev = low;
        for (int i = 0; i < 200; ++i) {
            aether::clockSyncObserve(cs, 0.0, 50.0, 100.0);   // rtt = 100, not a new best
            assert(cs.bestRttMs >= prev - eps);               // monotonically non-decreasing (upward)
            assert(cs.bestRttMs < 100.0 + eps);               // never overshoots the feed
            prev = cs.bestRttMs;
        }
        assert(cs.bestRttMs > low + eps);   // it moved UP off the fluke low (not pinned forever)
        assert(cs.bestRttMs > 99.0);        // and converged toward the sustained 100ms rtt
    }

    // A negative RTT sample is rejected: localRecv < localSend (out-of-order/bogus) must not touch
    // the estimate. Establish a known state, fire a bad sample, assert nothing changed.
    {
        aether::ClockSync cs;
        aether::clockSyncObserve(cs, 0.0, 25.0, 40.0);   // rtt 40, valid -> sets best + offset
        const double keepOffset = cs.offsetMs;
        const double keepBest   = cs.bestRttMs;
        aether::clockSyncObserve(cs, 100.0, 9999.0, 50.0);   // rtt = -50 -> rejected
        assert(cs.offsetMs > keepOffset - eps && cs.offsetMs < keepOffset + eps);
        assert(cs.bestRttMs > keepBest - eps && cs.bestRttMs < keepBest + eps);
    }

    // Offset EMA smooths toward the observed offset across non-best samples. First sample sets a
    // baseline offset; later same-rtt samples (not a new best) drag the estimate toward the new
    // offset by alpha each step, monotonically, without overshooting it.
    {
        aether::ClockSync cs;
        constexpr double rtt = 60.0;   // fixed rtt -> first sample is best, rest are EMA samples

        // Baseline: offset = remote - (t0+t2)/2 = 100 - 30 = 70.
        aether::clockSyncObserve(cs, 0.0, 100.0, rtt);
        assert(cs.offsetMs > 70.0 - eps && cs.offsetMs < 70.0 + eps);
        const double base = cs.offsetMs;

        // Target offset 200: with t0=0,t2=60 the midpoint is 30, so remote = 230 gives offset 200.
        constexpr double target = 200.0;
        const double remote = target + rtt / 2.0;   // = 230
        double prev = base;
        for (int i = 0; i < 100; ++i) {
            aether::clockSyncObserve(cs, 0.0, remote, rtt);     // same rtt -> EMA, not a new best
            assert(cs.offsetMs > prev - eps);                   // moving up toward target
            assert(cs.offsetMs < target + eps);                 // never overshoots
            prev = cs.offsetMs;
        }
        assert(cs.offsetMs > base + eps);   // it actually moved off the baseline
        assert(cs.offsetMs > target - 1.0); // and converged onto the observed offset

        // One step matches the EMA formula exactly: started at base, one sample -> blend.
        aether::ClockSync cs2;
        aether::clockSyncObserve(cs2, 0.0, 100.0, rtt);   // best, offset = 70
        aether::clockSyncObserve(cs2, 0.0, remote, rtt);  // EMA step toward 200
        const double expect = (1.0 - aether::clockSyncEmaAlpha) * 70.0 + aether::clockSyncEmaAlpha * 200.0;
        assert(cs2.offsetMs > expect - eps && cs2.offsetMs < expect + eps);
    }

    std::printf("aether clocksync edge OK: best rtt decays upward off a fluke low, negative rtt rejected, offset EMA converges\n");
    return 0;
}
