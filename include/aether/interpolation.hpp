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

inline constexpr int    defaultBufferDepth     = 3;
inline constexpr double defaultPlaybackDelayMs = 100.0;

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

// Push a snapshot with its server timestamp (ms). Out-of-order snapshots are dropped.
template <class T> void pushSnapshot(SnapshotBuffer<T>& buf, double timestamp, const T& state) {
    if (!buf.snapshots.empty() && timestamp <= buf.snapshots.back().timestamp) return;
    buf.snapshots.push_back(TimestampedSnapshot<T>{ timestamp, state });
    const int maxEntries = buf.bufferDepth * 2;
    while (static_cast<int>(buf.snapshots.size()) > maxEntries) buf.snapshots.pop_front();
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
            t = std::max(0.0f, std::min(1.0f, t));
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
template <class T> bool   snapshotReady(const SnapshotBuffer<T>& buf) { return static_cast<int>(buf.snapshots.size()) >= buf.bufferDepth; }
template <class T> double snapshotPlaybackDelayMs(const SnapshotBuffer<T>& buf) { return buf.playbackDelayMs; }
template <class T> void   setPlaybackDelayMs(SnapshotBuffer<T>& buf, double delay) { buf.playbackDelayMs = delay; }

} // namespace aether
