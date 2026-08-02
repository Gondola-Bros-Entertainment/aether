// aether - clock offset estimation. Recovers the offset between the local clock and a remote
// peer's clock from timestamped round-trips (Cristian's algorithm), giving the app a shared
// timeline for snapshot interpolation and prediction. Times are plain milliseconds (the same unit
// interpolation already uses); the app converts its MonoTime once at the edge. Data-first: a plain
// struct mutated by free functions.
#pragma once

#include <limits>

namespace aether {

inline constexpr double clockSyncEmaAlpha = 0.1;   // weight for samples that are not a new best

struct ClockSync {
    double offsetMs  = 0.0;     // estimate of (remoteClock - localClock), milliseconds
    double bestRttMs = 0.0;     // smallest round-trip seen -> its offset sample is the most trusted
    bool   hasSample = false;
};

// Fold in one round-trip: localSendMs (t0, our clock when we asked), remoteMs (t1, their clock when
// they replied), localRecvMs (t2, our clock when the reply landed). Under a symmetric path the
// reply's remote time lines up with our midpoint (t0+t2)/2, so offset = t1 - (t0+t2)/2. A tighter
// round-trip is a better sample, so a new best RTT is taken directly; otherwise the estimate is
// EMA-smoothed to ride out jitter.
inline void clockSyncObserve(ClockSync& cs, double localSendMs, double remoteMs, double localRecvMs) {
    const double rtt = localRecvMs - localSendMs;
    if (rtt < 0.0) return;                                       // out-of-order / bogus sample
    const double offset = remoteMs - (localSendMs + localRecvMs) / 2.0;
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

// How far the offset could be wrong, in milliseconds. Cristian's algorithm assumes the two one-way
// delays are equal; when they are not, the estimate is off by exactly (forward - reverse) / 2, and
// since forward + reverse is the round-trip, that error is at most rtt / 2 in magnitude. Half the
// round-trip is therefore a true bound rather than a heuristic: a 5ms-out / 145ms-back path reads
// exactly 70ms off, inside the 75ms its 150ms round-trip allows.
//
// The rtt used is bestRttMs, which is the DECAYING recent best (see clockSyncObserve), not a lifetime
// minimum. That keeps the bound honest as a path changes -- a fluke-low sample from minutes ago would
// otherwise report a tightness the current path no longer has -- at the cost of the bound widening
// toward the prevailing RTT once the low sample stops recurring.
//
// Asymmetric routing is ordinary on real paths, so check this before doing lag compensation against
// the offset: a large bound means the shared timeline is a guess. Infinity until a sample exists, so
// a caller comparing against a threshold fails closed.
inline double clockOffsetErrorBoundMs(const ClockSync& cs) noexcept {
    return cs.hasSample ? cs.bestRttMs / 2.0 : std::numeric_limits<double>::infinity();
}

// Convert between the two timelines once an offset is known.
inline double localToRemoteMs(const ClockSync& cs, double localMs)  { return localMs + cs.offsetMs; }
inline double remoteToLocalMs(const ClockSync& cs, double remoteMs) { return remoteMs - cs.offsetMs; }

} // namespace aether
