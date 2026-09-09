// aether - clock offset estimation. Recovers the offset between the local clock and a remote
// peer's clock from timestamped round-trips (Cristian's algorithm), giving the app a shared
// timeline for snapshot interpolation and prediction. Times are plain milliseconds (the same unit
// interpolation already uses); the app converts its MonoTime once at the edge. Data-first: a plain
// struct mutated by free functions.
#pragma once

#include <cmath>
#include <limits>

namespace aether {

inline constexpr double clockSyncEmaAlpha = 0.1;   // weight for samples that are not a new best

struct ClockSync {
    double offsetMs  = 0.0;     // estimate of (remoteClock - localClock), milliseconds
    double bestRttMs = 0.0;     // smallest round-trip seen -> its offset sample is the most trusted
    bool   hasSample = false;
    double latestOffsetMs = 0.0;
    double latestRttMs = 0.0;
    double lastSampleTimeMs = 0.0; // local receive timestamp; caller can assess sample age
};

// Fold in one round-trip: localSendMs (t0, our clock when we asked), remoteMs (t1, their clock when
// they replied), localRecvMs (t2, our clock when the reply landed). Under a symmetric path the
// reply's remote time lines up with our midpoint (t0+t2)/2, so offset = t1 - (t0+t2)/2. A tighter
// round-trip is a better sample, so a new best RTT is taken directly; otherwise the estimate is
// EMA-smoothed to ride out jitter.
inline void clockSyncObserve(ClockSync& cs, double localSendMs, double remoteMs, double localRecvMs) {
    // remoteMs is a peer-supplied number and the local stamps come from the app, so no input is
    // trusted to be finite. Reject invalid samples before they contaminate the smoothed offset
    // and all later estimates.
    if (!std::isfinite(localSendMs) || !std::isfinite(remoteMs) || !std::isfinite(localRecvMs)) return;
    const double rtt = localRecvMs - localSendMs;
    if (rtt < 0.0) return;                                       // out-of-order / bogus sample
    const double offset = remoteMs - (localSendMs + localRecvMs) / 2.0;
    // Finite inputs at the extremes can still overflow the subtraction, so check the results too.
    if (!std::isfinite(rtt) || !std::isfinite(offset)) return;
    cs.latestOffsetMs = offset;
    cs.latestRttMs = rtt;
    cs.lastSampleTimeMs = localRecvMs;
    if (!cs.hasSample || rtt < cs.bestRttMs) {
        cs.offsetMs  = offset;
        cs.bestRttMs = rtt;
        cs.hasSample = true;
    } else {
        cs.offsetMs = (1.0 - clockSyncEmaAlpha) * cs.offsetMs + clockSyncEmaAlpha * offset;
        // A new low is taken directly (above); otherwise relax the best UP toward the current RTT, so a
        // stale or fluke-low best is forgotten over time -- a decaying recent best, not a lifetime
        // minimum, so the offset keeps tracking real clock drift instead of anchoring to one old sample.
        cs.bestRttMs += clockSyncEmaAlpha * (rtt - cs.bestRttMs);
    }
}

// Error bound at the latest measurement, assuming the clock offset is constant during that
// round trip and network delays are nonnegative. The true offset lies within latestOffset +/-
// latestRtt/2. Include the distance from our smoothed estimate to that interval's centre: RTT/2
// alone would under-report error while the EMA catches up after an offset change.
// This cannot bound later unobserved clock drift or steps. lastSampleTimeMs exposes sample age;
// the caller decides when to request a fresh measurement. Infinity until a sample exists.
inline double clockOffsetErrorBoundMs(const ClockSync& cs) noexcept {
    return cs.hasSample ? std::abs(cs.offsetMs - cs.latestOffsetMs) + cs.latestRttMs / 2.0
                        : std::numeric_limits<double>::infinity();
}

// Convert between the two timelines once an offset is known.
inline double localToRemoteMs(const ClockSync& cs, double localMs)  { return localMs + cs.offsetMs; }
inline double remoteToLocalMs(const ClockSync& cs, double remoteMs) { return remoteMs - cs.offsetMs; }

} // namespace aether
