// aether - snapshot interpolation. Buffers timestamped snapshots and samples a smoothly
// interpolated state at a playback delay behind the latest, hiding network jitter. Interpolation
// is an overloaded lerp() free function: defaults for float/double here, user types provide their
// own (found by ADL).
#pragma once

#include <algorithm>
#include <cstddef>
#include <deque>
#include <optional>

namespace aether {

inline constexpr int    defaultBufferDepth     = 3;   // snapshots buffered before playback starts
inline constexpr double defaultPlaybackDelayMs = 100.0;
// Playback interpolates between a PAIR of snapshots, so two is the floor on readiness whatever
// bufferDepth is set to; the field is public data, and a depth of 0 or less would otherwise report an
// empty buffer ready to sample.
inline constexpr int    snapshotMinDepth = 2;
// History is retained as a multiple of the playback delay. Retaining exactly the delay is one entry
// short: the sample target sits playbackDelayMs behind the newest timestamp, and interpolating it
// needs a snapshot OLDER than the target to come from. The second delay's worth is that entry plus
// slack for jitter and for a renderTime trailing the newest snapshot.
inline constexpr double snapshotRetentionFactor = 2.0;
// Memory backstop. Retention is by time and the timestamps come off the wire, so a peer stamping
// snapshots microseconds apart would otherwise grow the buffer without limit. Only a send rate above
// snapshotMaxEntries per retention window (5kHz at the defaults) hits this instead of the time trim.
inline constexpr int    snapshotMaxEntries = 1024;

inline float  lerp(float a, float b, float t) noexcept  { return a + (b - a) * t; }
inline double lerp(double a, double b, float t) noexcept { return a + (b - a) * static_cast<double>(t); }

template <class T> struct TimestampedSnapshot { double timestamp = 0.0; T state{}; };

template <class T> struct SnapshotBuffer {
    std::deque<TimestampedSnapshot<T>> snapshots;
    int    bufferDepth     = defaultBufferDepth;
    double playbackDelayMs = defaultPlaybackDelayMs;
};

template <class T> SnapshotBuffer<T> newSnapshotBuffer() { return SnapshotBuffer<T>{}; }
template <class T> SnapshotBuffer<T> newSnapshotBufferWithConfig(int depth, double delay) {
    SnapshotBuffer<T> b;
    b.bufferDepth     = depth;
    b.playbackDelayMs = delay;
    return b;
}

// How far back pushSnapshot keeps history, in ms. Derived from the playback delay because the two
// have to be related: sampleSnapshot looks that far behind the newest timestamp, so history capped
// independently of it (by a snapshot COUNT, say) spans whatever the send rate happens to make it --
// too short at a high rate, and every sample clamps to the oldest entry and steps instead of
// interpolating, with nothing in the API saying so.
template <class T> double snapshotRetentionMs(const SnapshotBuffer<T>& buf) noexcept {
    return buf.playbackDelayMs > 0.0 ? buf.playbackDelayMs * snapshotRetentionFactor : 0.0;
}

// Push a snapshot with its server timestamp (ms). Out-of-order snapshots are dropped.
template <class T> void pushSnapshot(SnapshotBuffer<T>& buf, double timestamp, const T& state) {
    if (!buf.snapshots.empty() && timestamp <= buf.snapshots.back().timestamp) return;
    buf.snapshots.push_back(TimestampedSnapshot<T>{ timestamp, state });

    // Trim by time, oldest first, and only while the SECOND entry is still past the horizon: that
    // keeps exactly one snapshot older than the retained span, which is the one an interpolated
    // sample at the far end of the span reads from. Never trim below a pair -- sampleSnapshot needs
    // two -- so a delay of 0 leaves the two newest rather than emptying the buffer.
    const double horizon = buf.snapshots.back().timestamp - snapshotRetentionMs(buf);
    while (buf.snapshots.size() > 2 && buf.snapshots[1].timestamp <= horizon) buf.snapshots.pop_front();
    while (static_cast<int>(buf.snapshots.size()) > snapshotMaxEntries) buf.snapshots.pop_front();
}

// Sample an interpolated state at renderTime (ms); nullopt if fewer than two snapshots.
template <class T> std::optional<T> sampleSnapshot(const SnapshotBuffer<T>& buf, double renderTime) {
    if (buf.snapshots.size() < 2) return std::nullopt;
    const double targetTime = renderTime - buf.playbackDelayMs;
    const auto&  s          = buf.snapshots;
    for (std::size_t i = 0; i + 1 < s.size(); ++i) {
        const auto& a = s[i];
        const auto& b = s[i + 1];
        if (targetTime >= a.timestamp && targetTime <= b.timestamp) {
            const double duration = b.timestamp - a.timestamp;
            if (duration <= 0.0) return a.state;
            float t = static_cast<float>((targetTime - a.timestamp) / duration);
            t = std::clamp(t, 0.0f, 1.0f);
            return lerp(a.state, b.state, t);
        }
    }
    if (targetTime > s.back().timestamp)  return s.back().state;    // past the end
    if (targetTime < s.front().timestamp) return s.front().state;   // before the start
    return std::nullopt;
}

template <class T> void   snapshotReset(SnapshotBuffer<T>& buf) { buf.snapshots.clear(); }
template <class T> int    snapshotCount(const SnapshotBuffer<T>& buf) { return static_cast<int>(buf.snapshots.size()); }
template <class T> bool   snapshotIsEmpty(const SnapshotBuffer<T>& buf) { return buf.snapshots.empty(); }
template <class T> bool   snapshotReady(const SnapshotBuffer<T>& buf) {
    const int depth = buf.bufferDepth > snapshotMinDepth ? buf.bufferDepth : snapshotMinDepth;
    return static_cast<int>(buf.snapshots.size()) >= depth;
}

// Does the buffered history reach back past the sample target, i.e. will sampleSnapshot interpolate
// between a pair rather than clamp to the oldest entry? False is the degraded case and the reason
// this is exposed at all: clamping is stepping, it looks like ordinary playback, and it is otherwise
// indistinguishable from the healthy path from outside. Normal while the buffer fills; a delay that
// outruns the history if it persists.
template <class T> bool snapshotSpansDelay(const SnapshotBuffer<T>& buf) {
    if (buf.snapshots.size() < 2) return false;
    return buf.snapshots.back().timestamp - buf.snapshots.front().timestamp >= buf.playbackDelayMs;
}

} // namespace aether
