// aether - delta-compressed state replication. DeltaTracker (sender) encodes a snapshot as a
// delta against the last ack-confirmed baseline; BaselineManager (receiver) keeps a ring of
// confirmed snapshots to decode against. The diff/apply uses the automatic reflection delta from
// delta.hpp -- define a plain struct and replication just works.
#pragma once

#include "aether/delta.hpp"
#include "aether/serialize.hpp"
#include "aether/types.hpp"

#include <cstdint>
#include <deque>
#include <optional>
#include <tuple>
#include <utility>

namespace aether {

using BaselineSeq = std::uint16_t;
inline constexpr BaselineSeq noBaseline      = 0xFFFF;   // sentinel: no baseline, full state follows
inline constexpr int         maxSnapshotBytes = 65536;   // scratch buffer cap for one snapshot
// Bare-struct cap defaults, so a default-constructed DeltaTracker/BaselineManager is usable rather
// than silently one-deep (a cap of 0 keeps a single entry, so deltaOnAck for any but the most recent
// snapshot fails and the baseline never advances). The new* factories override these.
inline constexpr int         defaultReplicationCap = 64;

// Pack a full snapshot / a delta. A reused thread-local scratch (sized once per thread) avoids the
// per-call 64KB allocation; only the right-sized result is copied out.
template <class T> Bytes packFull(const T& v) {
    static thread_local Bytes scratch(maxSnapshotBytes);
    for (;;) {
        Writer w{ scratch.data(), scratch.size(), 0, true };
        pack(w, v);
        if (w.ok) return Bytes(scratch.data(), scratch.data() + w.pos);
        scratch.resize(scratch.size() * 2);   // snapshot outgrew the scratch -> grow + retry, never truncate
    }
}
template <class T> Bytes packDelta(const T& prev, const T& curr) {
    static thread_local Bytes scratch(maxSnapshotBytes);
    for (;;) {
        Writer w{ scratch.data(), scratch.size(), 0, true };
        deltaPack(w, prev, curr);
        if (w.ok) return Bytes(scratch.data(), scratch.data() + w.pos);
        scratch.resize(scratch.size() * 2);   // grow + retry rather than silently truncate the delta
    }
}

// --- sender side ---
template <class T> struct DeltaTracker {
    std::deque<std::pair<BaselineSeq, T>>    pending;
    std::optional<std::pair<BaselineSeq, T>> confirmed;
    int                                      maxPending = defaultReplicationCap;
};
template <class T> DeltaTracker<T> newDeltaTracker(int maxPending) {
    DeltaTracker<T> t;
    t.maxPending = maxPending;
    return t;
}

// Encode current state as [baselineSeq:u16 LE][delta or full payload]; stores it as pending.
template <class T> Bytes deltaEncode(DeltaTracker<T>& tracker, BaselineSeq seqNum, const T& current) {
    Bytes out(2);
    if (tracker.confirmed) {
        const BaselineSeq baseSeq = tracker.confirmed->first;
        out[0] = static_cast<std::uint8_t>(baseSeq);
        out[1] = static_cast<std::uint8_t>(baseSeq >> 8);
        const Bytes payload = packDelta(tracker.confirmed->second, current);
        out.insert(out.end(), payload.begin(), payload.end());
    } else {
        out[0] = static_cast<std::uint8_t>(noBaseline);
        out[1] = static_cast<std::uint8_t>(noBaseline >> 8);
        const Bytes payload = packFull(current);
        out.insert(out.end(), payload.begin(), payload.end());
    }
    if (static_cast<int>(tracker.pending.size()) >= tracker.maxPending && !tracker.pending.empty()) tracker.pending.pop_front();
    tracker.pending.push_back({ seqNum, current });
    return out;
}

// On ACK: promote the matching pending snapshot to the confirmed baseline, drop older ones.
template <class T> void deltaOnAck(DeltaTracker<T>& tracker, BaselineSeq seqNum) {
    int idx = -1;
    for (int i = 0; i < static_cast<int>(tracker.pending.size()); ++i)
        if (tracker.pending[static_cast<std::size_t>(i)].first == seqNum) { idx = i; break; }
    if (idx < 0) return;
    auto acked = tracker.pending[static_cast<std::size_t>(idx)];
    // Keep everything after the acked index (the original's wraparound filter was always-true).
    std::deque<std::pair<BaselineSeq, T>> remaining;
    for (int i = idx + 1; i < static_cast<int>(tracker.pending.size()); ++i)
        remaining.push_back(tracker.pending[static_cast<std::size_t>(i)]);
    tracker.pending   = std::move(remaining);
    tracker.confirmed = std::move(acked);
}
template <class T> void deltaReset(DeltaTracker<T>& tracker) {
    tracker.pending.clear();
    tracker.confirmed.reset();
}
template <class T> std::optional<BaselineSeq> deltaConfirmedSeq(const DeltaTracker<T>& tracker) {
    if (tracker.confirmed) return tracker.confirmed->first;
    return std::nullopt;
}

// --- receiver side ---
template <class T> struct BaselineManager {
    std::deque<std::tuple<BaselineSeq, T, MonoTime>> snapshots;
    int    maxSnapshots = defaultReplicationCap;
    double timeoutMs    = 0.0;
};
template <class T> BaselineManager<T> newBaselineManager(int maxSnapshots, double timeoutMs) {
    BaselineManager<T> m;
    m.maxSnapshots = maxSnapshots;
    m.timeoutMs    = timeoutMs;
    return m;
}
template <class T> void pushBaseline(BaselineManager<T>& m, BaselineSeq seqNum, const T& state, MonoTime now) {
    std::deque<std::tuple<BaselineSeq, T, MonoTime>> kept;
    for (auto& s : m.snapshots) if (elapsedMs(std::get<2>(s), now) < m.timeoutMs) kept.push_back(s);
    m.snapshots = std::move(kept);
    if (static_cast<int>(m.snapshots.size()) >= m.maxSnapshots && !m.snapshots.empty()) m.snapshots.pop_front();
    m.snapshots.push_back(std::make_tuple(seqNum, state, now));
}
template <class T> const T* getBaseline(const BaselineManager<T>& m, BaselineSeq seqNum) {
    for (auto it = m.snapshots.rbegin(); it != m.snapshots.rend(); ++it)   // most recent first
        if (std::get<0>(*it) == seqNum) return &std::get<1>(*it);
    return nullptr;
}
template <class T> void baselineReset(BaselineManager<T>& m) { m.snapshots.clear(); }
template <class T> int  baselineCount(const BaselineManager<T>& m) { return static_cast<int>(m.snapshots.size()); }
template <class T> bool baselineIsEmpty(const BaselineManager<T>& m) { return m.snapshots.empty(); }

// Decode a delta-encoded payload against the referenced baseline; nullopt if missing/short.
template <class T> std::optional<T> deltaDecode(const BaselineManager<T>& baselines, const Bytes& dat) {
    if (dat.size() < 2) return std::nullopt;
    const BaselineSeq baseSeq = static_cast<BaselineSeq>(static_cast<std::uint16_t>(dat[0]) | (static_cast<std::uint16_t>(dat[1]) << 8));
    Reader r{ dat.data() + 2, dat.size() - 2, 0 };
    if (baseSeq == noBaseline) return unpack<T>(r);
    const T* baseline = getBaseline(baselines, baseSeq);
    if (!baseline) return std::nullopt;
    return deltaUnpack<T>(r, *baseline);
}

} // namespace aether
