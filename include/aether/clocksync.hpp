// aether - clock offset estimation. Recovers the offset between the local clock and a remote
// peer's clock from timestamped round-trips (Cristian's algorithm), giving the app a shared
// timeline for snapshot interpolation and prediction. Times are plain milliseconds (the same unit
// interpolation already uses); the app converts its MonoTime once at the edge. Data-first: a plain
// struct mutated by free functions.
#pragma once

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
    }
}

// Convert between the two timelines once an offset is known.
inline double localToRemoteMs(const ClockSync& cs, double localMs)  { return localMs + cs.offsetMs; }
inline double remoteToLocalMs(const ClockSync& cs, double remoteMs) { return remoteMs - cs.offsetMs; }

} // namespace aether
