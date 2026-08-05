// aether - delta-compressed state replication. DeltaTracker (sender) encodes a snapshot as a
// delta against the last ack-confirmed baseline; BaselineManager (receiver) keeps a ring of
// confirmed snapshots to decode against. The diff/apply uses the automatic reflection delta from
// delta.hpp, so a plain aggregate needs no annotation to replicate.
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

// A snapshot id, not an int: a bare typedef lets a channel sequence be passed where a snapshot id
// belongs, and the two are never interchangeable.
enum class BaselineSeq : std::uint16_t {};
constexpr std::uint16_t baselineSeqBits(BaselineSeq s) noexcept { return static_cast<std::uint16_t>(s); }
// Sentinel in the 2-byte payload header: "no baseline, full state follows". 0xFFFF is therefore RESERVED
// by the wire format and can never identify a real snapshot -- a delta encoded against a baseline with
// that id would be read by the receiver as a full snapshot and decode to garbage. Every entry point below
// declines it, so a caller that numbers its snapshots straight through the wrap loses nothing but the
// ability to use that one id as a baseline (the snapshot itself still sends, as a delta or in full).
inline constexpr BaselineSeq noBaseline      = BaselineSeq{ 0xFFFF };
inline constexpr int         maxSnapshotBytes = 65536;   // scratch buffer cap for one snapshot
// Bare-struct defaults, so a default-constructed DeltaTracker/BaselineManager holds a real ring: 64
// snapshots, each kept a second. A cap of 0 keeps a single entry, and an ack for anything but the
// newest snapshot then finds nothing to confirm; a timeout of 0 means "no time-based expiry" rather
// than "expire everything" -- see pushBaseline. The new* factories override both.
inline constexpr int         defaultReplicationCap    = 64;
inline constexpr double      defaultBaselineTimeoutMs = 1000.0;
// A 16-bit seq repeats every 65536 snapshots, so pending must hold strictly fewer than that: past
// the limit one seq identifies two entries and an ack cannot say which.
inline constexpr int         maxPendingLimit = 65535;
// Snapshots deltaEncode will send against an unacked baseline before falling back to full state.
// Under defaultReplicationCap, so against a default receiver the fallback fires before that
// receiver's ring can evict the baseline -- the stall is avoided rather than recovered from.
inline constexpr int         defaultMaxBaselineAge = 32;

// Pack a full snapshot / a delta. A reused thread-local scratch (sized once per thread) avoids the
// per-call 64KB allocation; only the right-sized result is copied out.
// `prefix` reserves that many leading bytes for the caller to fill (e.g. deltaEncode's baseline-seq
// header), so the payload is copied out of the scratch exactly once -- no separate header buffer + copy.
template <class T> Bytes packFull(const T& v, std::size_t prefix = 0) {
    static thread_local Bytes scratch(maxSnapshotBytes);
    for (;;) {
        Writer w{ scratch.data(), scratch.size(), 0, true };
        pack(w, v);
        if (w.ok) {
            Bytes out;
            out.reserve(prefix + w.pos);
            out.resize(prefix);                                          // leading bytes, for the caller
            out.insert(out.end(), scratch.data(), scratch.data() + w.pos);
            return out;
        }
        scratch.resize(scratch.size() * 2);   // snapshot outgrew the scratch -> grow + retry, never truncate
    }
}
template <class T> Bytes packDelta(const T& prev, const T& curr, std::size_t prefix = 0) {
    static thread_local Bytes scratch(maxSnapshotBytes);
    for (;;) {
        Writer w{ scratch.data(), scratch.size(), 0, true };
        deltaPack(w, prev, curr);
        if (w.ok) {
            Bytes out;
            out.reserve(prefix + w.pos);
            out.resize(prefix);
            out.insert(out.end(), scratch.data(), scratch.data() + w.pos);
            return out;
        }
        scratch.resize(scratch.size() * 2);   // grow + retry rather than silently truncate the delta
    }
}

// --- sender side ---
template <class T> struct DeltaTracker {
    std::deque<std::pair<BaselineSeq, T>>    pending;
    std::optional<std::pair<BaselineSeq, T>> confirmed;
    int                                      maxPending = defaultReplicationCap;
    // Snapshots encoded since the last ack, and the point at which deltaEncode stops trusting the
    // confirmed baseline (see its recovery rule). sinceAck saturates at maxBaselineAge, so a
    // connection that never acks cannot overflow it.
    int                                      sinceAck       = 0;
    int                                      maxBaselineAge = defaultMaxBaselineAge;
};
template <class T> DeltaTracker<T> newDeltaTracker(int maxPending) {
    DeltaTracker<T> t;
    t.maxPending = maxPending;
    return t;
}

// Encode current state as [baselineSeq:u16 LE][delta or full payload]; stores it as pending.
//
// Recovery rule: the sender cannot see the receiver's ring, so it bounds how stale its own baseline
// may get. Once maxBaselineAge snapshots have gone out with no ack, the baseline is treated as
// evicted and full state is sent instead -- a full snapshot decodes against nothing, so the receiver
// can store and ack it and confirmed advances again. Without that bound one evicted baseline stalls
// replication for good: every later delta references a baseline the receiver no longer has, so it
// decodes nothing, so it acks nothing, so confirmed never moves off the evicted snapshot.
// maxBaselineAge <= 0 turns the fallback off.
template <class T> Bytes deltaEncode(DeltaTracker<T>& tracker, BaselineSeq seqNum, const T& current) {
    Bytes      out;
    const bool baselineTooOld = tracker.maxBaselineAge > 0 && tracker.sinceAck >= tracker.maxBaselineAge;
    if (tracker.confirmed && !baselineTooOld) {
        const BaselineSeq baseSeq = tracker.confirmed->first;
        out = packDelta(tracker.confirmed->second, current, 2);   // 2 leading header bytes, payload copied once
        out[0] = static_cast<std::uint8_t>(baselineSeqBits(baseSeq));
        out[1] = static_cast<std::uint8_t>(baselineSeqBits(baseSeq) >> 8);
    } else {
        out = packFull(current, 2);
        out[0] = static_cast<std::uint8_t>(baselineSeqBits(noBaseline));
        out[1] = static_cast<std::uint8_t>(baselineSeqBits(noBaseline) >> 8);
    }
    if (tracker.sinceAck < tracker.maxBaselineAge) ++tracker.sinceAck;   // saturates: only the threshold matters
    if (seqNum == noBaseline) return out;   // reserved id: the snapshot is sent, but never becomes a baseline
    // maxPending is public data, so the 16-bit-seq limit is enforced here rather than trusted at
    // construction: a larger cap would let one seq value sit in pending twice.
    const int cap = tracker.maxPending < maxPendingLimit ? tracker.maxPending : maxPendingLimit;
    if (static_cast<int>(tracker.pending.size()) >= cap && !tracker.pending.empty()) tracker.pending.pop_front();
    tracker.pending.push_back({ seqNum, current });
    return out;
}

// On ACK: promote the matching pending snapshot to the confirmed baseline, drop older ones.
template <class T> void deltaOnAck(DeltaTracker<T>& tracker, BaselineSeq seqNum) {
    // Newest match wins, as on the receiver's getBaseline. A seq is only unique within one 65536
    // wrap, so the two sides must resolve a repeat the same way; confirming an older duplicate would
    // encode deltas against a snapshot a full wrap stale, and those still DECODE -- into wrong state.
    int idx = -1;
    for (int i = static_cast<int>(tracker.pending.size()) - 1; i >= 0; --i)
        if (tracker.pending[static_cast<std::size_t>(i)].first == seqNum) { idx = i; break; }
    if (idx < 0) return;
    auto acked = tracker.pending[static_cast<std::size_t>(idx)];
    // Keep only what is newer than the acked index: confirmed moves forward only, so nothing at or
    // before it can be a baseline again.
    std::deque<std::pair<BaselineSeq, T>> remaining;
    for (int i = idx + 1; i < static_cast<int>(tracker.pending.size()); ++i)
        remaining.push_back(tracker.pending[static_cast<std::size_t>(i)]);
    tracker.pending   = std::move(remaining);
    tracker.confirmed = std::move(acked);
    tracker.sinceAck  = 0;   // the baseline is fresh again -> full-state fallback backs off
}
template <class T> void deltaReset(DeltaTracker<T>& tracker) {
    tracker.pending.clear();
    tracker.confirmed.reset();
    tracker.sinceAck = 0;
}
template <class T> std::optional<BaselineSeq> deltaConfirmedSeq(const DeltaTracker<T>& tracker) {
    if (tracker.confirmed) return tracker.confirmed->first;
    return std::nullopt;
}

// --- receiver side ---
template <class T> struct BaselineManager {
    std::deque<std::tuple<BaselineSeq, T, MonoTime>> snapshots;
    int    maxSnapshots = defaultReplicationCap;
    double timeoutMs    = defaultBaselineTimeoutMs;   // <= 0 disables time-based expiry
};
template <class T> BaselineManager<T> newBaselineManager(int maxSnapshots, double timeoutMs) {
    BaselineManager<T> m;
    m.maxSnapshots = maxSnapshots;
    m.timeoutMs    = timeoutMs;
    return m;
}
template <class T> void pushBaseline(BaselineManager<T>& m, BaselineSeq seqNum, const T& state, MonoTime now) {
    if (seqNum == noBaseline) return;   // reserved id (see noBaseline): storing it would never be looked up

    // timeoutMs <= 0 means no time-based expiry, so the count cap alone bounds the ring. It cannot
    // mean "expire immediately": elapsedMs saturates at 0 and is never negative, so a 0 threshold is
    // met by every entry including the one just pushed, leaving the ring permanently one deep.
    // now is monotonic across pushes, so expired snapshots are always a front prefix -- pop them in
    // place rather than rebuilding (and copying every surviving T into) a fresh deque each push.
    if (m.timeoutMs > 0.0)
        while (!m.snapshots.empty() && elapsedMs(std::get<2>(m.snapshots.front()), now) >= m.timeoutMs) m.snapshots.pop_front();
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

// Why a decode failed. The two cases need different reactions, so they cannot share one nullopt:
// Malformed is a short or non-canonical payload and the packet is simply dropped, while
// BaselineMissing means the referenced snapshot has left this ring and NOTHING the sender encodes
// against it will ever decode -- only full state recovers (see deltaEncode's recovery rule).
enum class DeltaDecodeError : std::uint8_t { Malformed, BaselineMissing };

// Decode a delta-encoded payload against the referenced baseline; nullopt if missing/short, with the
// reason written through err when it is non-null.
template <class T>
std::optional<T> deltaDecode(const BaselineManager<T>& baselines, const Bytes& dat, DeltaDecodeError* err = nullptr) {
    const auto fail = [&](DeltaDecodeError e) { if (err) *err = e; return std::optional<T>{}; };
    if (dat.size() < 2) return fail(DeltaDecodeError::Malformed);
    const BaselineSeq baseSeq = static_cast<BaselineSeq>(static_cast<std::uint16_t>(dat[0]) | (static_cast<std::uint16_t>(dat[1]) << 8));
    Reader r{ dat.data() + 2, dat.size() - 2, 0 };
    if (baseSeq == noBaseline) {
        auto full = unpack<T>(r);
        if (!full) return fail(DeltaDecodeError::Malformed);
        return full;
    }
    const T* baseline = getBaseline(baselines, baseSeq);
    if (!baseline) return fail(DeltaDecodeError::BaselineMissing);
    auto out = deltaUnpack<T>(r, *baseline);
    if (!out) return fail(DeltaDecodeError::Malformed);
    return out;
}

} // namespace aether
