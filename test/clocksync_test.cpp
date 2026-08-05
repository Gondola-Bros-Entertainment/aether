// aether - clocksync edge behavior. Pins the sample filter (a negative RTT and any non-finite input
// are rejected, not absorbed), that bestRttMs decays UPWARD (a fluke-low best is forgotten, not
// pinned forever), and that the offset EMA smooths toward the observed offset. assert() IS the
// check -> no NDEBUG.
#include <aether/clocksync.hpp>

#include <cassert>
#include <cmath>
#include <cstdio>
#include <limits>

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

    // A non-finite sample is rejected on every input, not absorbed. remoteMs comes off the wire, and
    // one NaN would otherwise reach the EMA, which has no way back: every later estimate blends with
    // a NaN and stays one, while clockOffsetErrorBoundMs reads bestRttMs and keeps reporting a small
    // healthy bound over an offset that is not a number -- fail-open on the guard callers check
    // before lag compensation. Downstream, an interpolation sample at a NaN time returns nothing at
    // all, forever.
    {
        const double nan = std::numeric_limits<double>::quiet_NaN();
        const double inf = std::numeric_limits<double>::infinity();

        aether::ClockSync cs;
        aether::clockSyncObserve(cs, 0.0, 25.0, 40.0);   // one healthy sample -> known state
        const double keepOffset = cs.offsetMs;
        const double keepBest   = cs.bestRttMs;

        aether::clockSyncObserve(cs, 0.0, nan, 40.0);    // non-finite remote clock (peer-supplied)
        aether::clockSyncObserve(cs, 0.0, inf, 40.0);
        aether::clockSyncObserve(cs, 0.0, -inf, 40.0);
        aether::clockSyncObserve(cs, nan, 25.0, 40.0);   // and non-finite local stamps
        aether::clockSyncObserve(cs, 0.0, 25.0, nan);
        aether::clockSyncObserve(cs, inf, 25.0, inf);
        assert(!std::isnan(cs.offsetMs) && !std::isnan(cs.bestRttMs));
        assert(cs.offsetMs > keepOffset - eps && cs.offsetMs < keepOffset + eps);   // untouched
        assert(cs.bestRttMs > keepBest - eps && cs.bestRttMs < keepBest + eps);

        // The estimate still tracks: 500 healthy samples after the bad ones converge normally, and
        // the reported bound stays finite and consistent with the offset it describes.
        const double remote = 200.0 + 40.0 / 2.0;   // t0=0, t2=40 -> midpoint 20 -> offset 200
        for (int i = 0; i < 500; ++i) aether::clockSyncObserve(cs, 0.0, remote, 40.0);
        const double bound = aether::clockOffsetErrorBoundMs(cs);
        assert(std::isfinite(cs.offsetMs) && cs.offsetMs > 199.0 && cs.offsetMs < 201.0);
        assert(std::isfinite(bound) && bound > 0.0);
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

    // ---- the offset error bound actually bounds the error ----
    //
    // Cristian's algorithm assumes the two one-way delays match; when they do not, the estimate is
    // off by exactly (forward - reverse)/2, which is at most rtt/2. Half the tightest round-trip is
    // therefore a true bound, and the API has to expose it: an asymmetric path biases the offset
    // silently, and an app doing lag compensation cannot tell a shared timeline from a guess.
    {
        aether::ClockSync fresh;
        // No sample yet: infinite, so a caller comparing against a threshold fails closed rather
        // than reading "0ms of error" off an estimate that does not exist.
        assert(!fresh.hasSample);
        assert(aether::clockOffsetErrorBoundMs(fresh) == std::numeric_limits<double>::infinity());

        // Simulate a path with one-way delays f and r, true clock offset 0. The pong observes
        // t0 = 0, remote = f (the reply is stamped on arrival at the peer), t2 = f + r.
        const auto check = [](double f, double r) {
            aether::ClockSync cs;
            for (int i = 0; i < 50; ++i) aether::clockSyncObserve(cs, 0.0, f, f + r);
            const double bound = aether::clockOffsetErrorBoundMs(cs);
            const double error = cs.offsetMs;            // true offset is 0, so the estimate IS the error
            assert(cs.hasSample);
            assert(bound > 0.0);
            assert(std::fabs(error) <= bound + 1e-9);    // the bound holds
            return error;
        };

        assert(std::fabs(check(25.0, 25.0)) < 1e-9);     // symmetric: no error at all
        // asymmetric: the error is real, tracks (f - r)/2, and stays inside rtt/2
        const double e1 = check(10.0, 90.0);
        assert(e1 < -1.0 && std::fabs(e1 - (10.0 - 90.0) / 2.0) < 1e-6);
        const double e2 = check(145.0, 5.0);
        assert(e2 > 1.0 && std::fabs(e2 - (145.0 - 5.0) / 2.0) < 1e-6);
    }

    std::printf("aether clocksync edge OK: best rtt decays upward off a fluke low, negative rtt rejected, offset EMA converges, asymmetric-path error stays inside the reported bound\n");
    return 0;
}
