// aether - congestion control and bandwidth tracking. Two controllers: a binary Good/Bad AIMD
// rate limiter and a TCP New-Reno style window, plus a sliding-window bandwidth tracker and
// message batching. Data-first: structs mutated by free functions in place.
#pragma once

#include "aether/reliability.hpp"
#include "aether/serialize.hpp"
#include "aether/stats.hpp"
#include "aether/types.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace aether {

// --- constants ---
inline constexpr double        congestionRateReduction   = 0.5;   // multiplicative decrease
inline constexpr double        minSendRate               = 1.0;   // packets/sec floor
inline constexpr int           batchHeaderSize           = 1;     // u8 message count
inline constexpr int           batchLengthSize           = 2;     // u16 length prefix
inline constexpr int           initialCwndPackets        = 10;
inline constexpr int           minCwndBytes              = 1200;
inline constexpr double        minRecoverySecs           = 1.0;
inline constexpr double        maxRecoverySecs           = 60.0;
inline constexpr double        recoveryHalveIntervalSecs = 10.0;
inline constexpr double        quickDropThresholdSecs    = 10.0;
inline constexpr double        sendRateIncreasePerSec    = 10.0;  // additive increase, packets/sec per second of good conditions
inline constexpr double        maxSendRateMultiplier     = 4.0;
inline constexpr double        initialSsthresh           = std::numeric_limits<double>::infinity();

enum class CongestionMode  { Good, Bad };
enum class CongestionPhase { SlowStart, Avoidance, Recovery };

// --- binary congestion controller (Good/Bad mode with AIMD) ---
// The byte allowance is a TOKEN BUCKET earned from elapsed time, not a per-tick grant: sendRate is
// packets per SECOND, so handing out a full second's worth every tick would let a 60Hz loop send 60x
// the configured rate (and leave the rate arm of the controller effectively inert). Capacity is one
// second's worth, so an idle gap banks at most a one-second burst instead of unlimited credit.
struct CongestionController {
    CongestionMode          mode                 = CongestionMode::Good;
    std::optional<MonoTime> goodConditionsStart;
    double                  lossThreshold        = 0.0;
    double                  rttThresholdMs       = 0.0;
    double                  baseSendRate         = 0.0;
    double                  maxSendRate          = 0.0;   // hard packets/sec ceiling (config maxPacketRate)
    double                  currentSendRate      = 0.0;
    double                  budgetBytes          = 0.0;   // tokens available, bytes
    double                  burstBytes           = 0.0;   // bucket capacity == one second at the current rate
    std::optional<MonoTime> lastRefill;
    std::optional<MonoTime> lastUpdate;          // drives the additive increase off elapsed time, not tick count
    double                  adaptiveRecoverySecs = 0.0;
    std::optional<MonoTime> lastGoodEntry;
    std::optional<MonoTime> lastBadEntry;
};

// The ceiling the additive increase may ramp to: maxSendRateMultiplier above base, held under the
// configured packet-rate cap (validateConfig already requires maxPacketRate >= sendRate). Taking the
// min in both directions means a nonsensical cap can only ever slow the sender down, never speed it up.
inline double ccMaxSendRate(const CongestionController& cc) noexcept {
    return std::min(cc.baseSendRate * maxSendRateMultiplier, cc.maxSendRate);
}

inline CongestionController newCongestionController(double baseSendRate, double maxSendRate, double lossThreshold,
                                                   double rttThresholdMs, double recoveryTimeMs) {
    CongestionController cc;
    cc.lossThreshold        = lossThreshold;
    cc.rttThresholdMs       = rttThresholdMs;
    cc.baseSendRate         = baseSendRate;
    cc.maxSendRate          = maxSendRate;
    cc.currentSendRate      = baseSendRate;
    cc.adaptiveRecoverySecs = recoveryTimeMs / 1000.0;
    return cc;
}

// Earn tokens for the time since the last refill at currentSendRate packets/sec of mtu bytes each.
// The first call has no elapsed time to earn against, so it seeds a full bucket and starts the clock.
inline void ccRefillBudget(CongestionController& cc, int mtu, MonoTime now) {
    cc.burstBytes = cc.currentSendRate * static_cast<double>(mtu);
    if (!cc.lastRefill) { cc.budgetBytes = cc.burstBytes; cc.lastRefill = now; return; }
    const double earned = elapsedMs(*cc.lastRefill, now) / 1000.0 * cc.burstBytes;
    cc.budgetBytes = std::min(cc.budgetBytes + earned, cc.burstBytes);
    cc.lastRefill  = now;
}
inline void ccDeductBudget(CongestionController& cc, int bytes) { cc.budgetBytes -= static_cast<double>(bytes); }

// Update Good/Bad state from current loss and RTT. Call it once per tick; the additive increase is
// per SECOND of good conditions, so the ramp is identical at 20Hz and 144Hz (a per-call increment
// would make the send rate a function of the caller's frame rate).
inline void ccUpdate(CongestionController& cc, double packetLoss, double rttMs, MonoTime now) {
    const bool   isBad      = packetLoss > cc.lossThreshold || rttMs > cc.rttThresholdMs;
    const double elapsedSec = cc.lastUpdate ? elapsedMs(*cc.lastUpdate, now) / 1000.0 : 0.0;
    cc.lastUpdate = now;
    if (cc.mode == CongestionMode::Good) {
        if (isBad) {
            const double recoveryMult = (cc.lastGoodEntry && elapsedMs(*cc.lastGoodEntry, now) < quickDropThresholdSecs * 1000.0) ? 2.0 : 1.0;
            cc.mode                 = CongestionMode::Bad;
            cc.lastBadEntry         = now;
            cc.currentSendRate      = std::max(minSendRate, cc.currentSendRate * congestionRateReduction);
            cc.goodConditionsStart  = std::nullopt;
            cc.adaptiveRecoverySecs = std::min(maxRecoverySecs, cc.adaptiveRecoverySecs * recoveryMult);
        } else {
            cc.currentSendRate = std::min(ccMaxSendRate(cc), cc.currentSendRate + sendRateIncreasePerSec * elapsedSec);
            if (cc.lastGoodEntry) {
                const double elapsed   = elapsedMs(*cc.lastGoodEntry, now) / 1000.0;
                const int    intervals = static_cast<int>(elapsed / recoveryHalveIntervalSecs);
                if (intervals > 0) {
                    cc.adaptiveRecoverySecs = std::max(minRecoverySecs, cc.adaptiveRecoverySecs / std::pow(2.0, intervals));
                    cc.lastGoodEntry        = now;
                }
            }
        }
    } else {                                    // Bad
        if (!isBad) {
            if (!cc.goodConditionsStart) {
                cc.goodConditionsStart = now;
            } else if (elapsedMs(*cc.goodConditionsStart, now) >= cc.adaptiveRecoverySecs * 1000.0) {
                cc.mode                = CongestionMode::Good;
                cc.lastGoodEntry       = now;
                cc.currentSendRate     = cc.baseSendRate;
                cc.goodConditionsStart = std::nullopt;
            }
        } else {
            cc.goodConditionsStart = std::nullopt;
        }
    }
}

inline bool ccCanSend(const CongestionController& cc, int packetBytes) {
    return cc.budgetBytes >= static_cast<double>(packetBytes);
}

inline CongestionLevel ccCongestionLevel(const CongestionController& cc) {
    if (cc.mode == CongestionMode::Bad) return CongestionLevel::Critical;
    const double budgetRatio = cc.burstBytes <= 0.0 ? 1.0 : cc.budgetBytes / cc.burstBytes;
    return budgetRatio < 0.25 ? CongestionLevel::Elevated : CongestionLevel::None;
}

// --- window-based congestion controller (TCP New Reno style) ---
struct CongestionWindow {
    CongestionPhase         phase               = CongestionPhase::SlowStart;
    double                  cwnd                = 0.0;
    double                  ssthresh            = initialSsthresh;
    std::uint64_t           bytesInFlight       = 0;
    // Reliable bytes ADMITTED this tick but not yet coalesced into a datagram. bytesInFlight only
    // moves when the tick's wires are flushed, so without this every message in a tick tests the same
    // pre-tick figure and the window bounds nothing: one tick could admit many times cwnd. Counting
    // admitted-but-unflushed bytes is what makes the window bind within a tick. It returns to 0 every
    // flush, since every admitted wire is flushed.
    std::uint64_t           pendingBytes        = 0;
    int                     mtu                 = 0;
    std::optional<MonoTime> lastSendTime;
    double                  minInterPacketDelay = 0.0;   // milliseconds
};

inline CongestionWindow newCongestionWindow(int mtu) {
    CongestionWindow cw;
    cw.cwnd = static_cast<double>(initialCwndPackets * mtu);
    cw.mtu  = mtu;
    return cw;
}

// Return bytes to the window. Split out from cwOnAck because bytes leave flight for three distinct
// reasons -- acked, DECLARED LOST, or evicted from the sent ring unresolved -- but only an ack may
// grow the window. Without this the loss and eviction paths never gave their bytes back and the
// window filled permanently. Saturates at 0, so a double release can never wrap it.
inline void cwReleaseInFlight(CongestionWindow& cw, int bytes) noexcept {
    cw.bytesInFlight -= std::min<std::uint64_t>(static_cast<std::uint64_t>(bytes), cw.bytesInFlight);
}

inline void cwOnAck(CongestionWindow& cw, int bytes) {
    cwReleaseInFlight(cw, bytes);
    switch (cw.phase) {
        case CongestionPhase::SlowStart:
            cw.cwnd += static_cast<double>(bytes);
            if (cw.cwnd >= cw.ssthresh) cw.phase = CongestionPhase::Avoidance;
            break;
        case CongestionPhase::Avoidance:
            if (cw.cwnd > 0.0) cw.cwnd += static_cast<double>(cw.mtu) * static_cast<double>(bytes) / cw.cwnd;
            break;
        case CongestionPhase::Recovery:
            // RFC 5681: the first ack of new data ends fast recovery -- deflate the inflated window
            // back to ssthresh and resume congestion avoidance. Without an exit, a single loss would
            // freeze the window until an idle slow-start restart.
            cw.cwnd  = cw.ssthresh;
            cw.phase = CongestionPhase::Avoidance;
            break;
    }
}

inline void cwOnLoss(CongestionWindow& cw) {
    // RFC 5681 fast recovery: halve ssthresh, then inflate the window by the 3 segments the
    // duplicate acks proved had left the network, so the sender keeps emitting during recovery
    // (cwOnAck deflates back to ssthresh on the first ack of new data).
    //
    // ONE reduction per loss episode. A burst drop trips several packets' triple-NACK thresholds within
    // the same window, and halving on each would cut the window to a fraction of the single reduction
    // congestion actually calls for. Further losses while already recovering are part of the episode we
    // have already responded to (NewReno); the exit is cwOnAck's first ack of new data.
    if (cw.phase == CongestionPhase::Recovery) return;
    cw.ssthresh = std::max(static_cast<double>(minCwndBytes), cw.cwnd / 2.0);
    cw.cwnd     = cw.ssthresh + 3.0 * static_cast<double>(cw.mtu);
    cw.phase    = CongestionPhase::Recovery;
}

// Reserve window space for a wire the moment it is admitted, before it has been coalesced into a
// datagram. Paired with cwOnSend, which converts the reservation into real in-flight bytes at flush.
inline void cwOnAdmit(CongestionWindow& cw, int bytes) noexcept {
    cw.pendingBytes += static_cast<std::uint64_t>(bytes);
}

inline void cwOnSend(CongestionWindow& cw, int bytes, MonoTime now) {
    cw.bytesInFlight += static_cast<std::uint64_t>(bytes);
    cw.pendingBytes  -= std::min<std::uint64_t>(static_cast<std::uint64_t>(bytes), cw.pendingBytes);   // reservation realized; saturates so it can never wrap
    cw.lastSendTime   = now;
}

inline bool cwCanSend(const CongestionWindow& cw, int packetBytes) {
    return cw.bytesInFlight + cw.pendingBytes + static_cast<std::uint64_t>(packetBytes) <= static_cast<std::uint64_t>(cw.cwnd);
}

inline void cwUpdatePacing(CongestionWindow& cw, double rttMs) {
    if (cw.cwnd > 0.0 && rttMs > 0.0) {
        const double packetsInWindow = cw.cwnd / static_cast<double>(cw.mtu);
        cw.minInterPacketDelay = packetsInWindow > 0.0 ? rttMs / packetsInWindow : 0.0;
    }
}

inline bool cwCanSendPaced(const CongestionWindow& cw, MonoTime now) {
    if (!cw.lastSendTime) return true;
    return elapsedMs(*cw.lastSendTime, now) >= cw.minInterPacketDelay;
}

// Reset to slow start after a long idle (RFC 2861): more than 2 RTOs without sending.
inline void cwSlowStartRestart(CongestionWindow& cw, double rtoMs, MonoTime now) {
    if (!cw.lastSendTime) return;
    constexpr double ssrIdleThreshold = 2.0;
    if (elapsedMs(*cw.lastSendTime, now) > ssrIdleThreshold * rtoMs) {
        const double prevCwnd = cw.cwnd;
        cw.phase    = CongestionPhase::SlowStart;
        cw.cwnd     = static_cast<double>(initialCwndPackets * cw.mtu);
        cw.ssthresh = prevCwnd;
        // Nothing sent for 2 RTOs means nothing of ours is still in the network: every outstanding
        // packet was delivered or dropped long ago. Ghost bytes -- a packet lost right before the idle,
        // never NACKed because no later traffic arrived to reveal it -- would otherwise wedge the fresh
        // window shut until that packet's ring slot happens to be reused.
        cw.bytesInFlight = 0;
    }
}

inline CongestionLevel cwCongestionLevel(const CongestionWindow& cw) {
    const double utilization = cw.cwnd <= 0.0 ? 1.0 : static_cast<double>(cw.bytesInFlight) / cw.cwnd;
    if (utilization > 0.95) return CongestionLevel::Critical;
    if (utilization > 0.85) return CongestionLevel::High;
    if (utilization > 0.70) return CongestionLevel::Elevated;
    return CongestionLevel::None;
}

// --- bandwidth tracker (fixed sliding window of time buckets) ---
// Throughput over the last windowDurationMs. The window is a RING OF TIME BUCKETS, not a list of
// per-packet samples: recording is O(1) with zero heap traffic (a per-packet container node would be an
// allocation on every datagram, on the hot path), and the footprint per connection is a fixed 1KB
// regardless of packet rate. Resolution is windowDurationMs / bandwidthBucketCount -- about 16ms at the
// default 1s window, finer than a frame at 60Hz.
//
// A bucket slot holds the absolute bucket number it was written for, so a slot the ring has cycled past
// is recognized as stale rather than counted. That is what makes the rate DECAY on its own: the reader
// only sums buckets inside the window ending at `now`, so a connection that stops sending reports its
// throughput falling to zero without anything having to sweep it. (The previous design pruned on record,
// which meant an idle connection reported its last burst forever, since nothing was being recorded.)
inline constexpr int bandwidthBucketCount = 64;

struct BandwidthTracker {
    std::array<std::uint64_t, bandwidthBucketCount> bucketId{};      // absolute bucket number in each slot
    std::array<std::uint64_t, bandwidthBucketCount> bucketBytes{};   // bytes recorded into that bucket
    double windowDurationMs = 0.0;
    double bucketMs         = 0.0;
};

inline BandwidthTracker newBandwidthTracker(double windowDurationMs) {
    BandwidthTracker bt;
    bt.windowDurationMs = windowDurationMs;
    bt.bucketMs         = windowDurationMs / static_cast<double>(bandwidthBucketCount);
    return bt;
}

// The absolute bucket a timestamp falls in. Monotonic in `now`, and exact well past any realistic
// uptime (a double holds every integer to 2^53, which at a 16ms bucket is ~4 million years).
inline std::uint64_t btBucketOf(const BandwidthTracker& bt, MonoTime now) noexcept {
    if (bt.bucketMs <= 0.0) return 0;
    return static_cast<std::uint64_t>(static_cast<double>(now.ns) / 1.0e6 / bt.bucketMs);
}

inline void btRecord(BandwidthTracker& bt, int bytes, MonoTime now) noexcept {
    const std::uint64_t id   = btBucketOf(bt, now);
    const std::size_t   slot = static_cast<std::size_t>(id % bandwidthBucketCount);
    if (bt.bucketId[slot] != id) { bt.bucketId[slot] = id; bt.bucketBytes[slot] = 0; }   // ring cycled: reuse the slot
    bt.bucketBytes[slot] += static_cast<std::uint64_t>(bytes);
}

// Bytes per second over the window ending at `now`. Takes the time because the answer depends on it:
// the same buckets mean a different rate a second later, and a tracker cannot be read honestly without
// knowing when "now" is.
inline double btBytesPerSecond(const BandwidthTracker& bt, MonoTime now) noexcept {
    if (bt.windowDurationMs <= 0.0) return 0.0;
    const std::uint64_t newest = btBucketOf(bt, now);
    const std::uint64_t span   = static_cast<std::uint64_t>(bandwidthBucketCount) - 1;
    const std::uint64_t oldest = newest > span ? newest - span : 0;
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < static_cast<std::size_t>(bandwidthBucketCount); ++i)
        if (bt.bucketId[i] >= oldest && bt.bucketId[i] <= newest) total += bt.bucketBytes[i];
    return static_cast<double>(total) / (bt.windowDurationMs / 1000.0);
}

// --- message unbatching. Decode a coalesced [u8 count][u16 len BE][data]... batch. The encoder is
//     inlined in connection.hpp's flushPendingWires, which interleaves per-message reliability
//     tracking with the framing, so it owns the encode side. ---
// Walk a coalesced batch, invoking f(wireSpan) for each message wire with no copy. Returns false on a
// malformed batch (f may already have run for earlier wires). The single framing parser, shared by the
// zero-copy receive path (span) and unbatchMessages (which materializes owned Bytes).
template <class F>
inline bool forEachBatchWire(ByteSpan data, F&& f) {
    if (data.empty()) return false;
    const int msgCount = data[0];
    if (msgCount > maxMsgsPerPacket) return false;   // the encoder never coalesces more than this; reject a malformed/oversized batch
    std::size_t offset = 1;
    for (int n = 0; n < msgCount; ++n) {             // validate the whole framing first -- all-or-nothing: a malformed batch dispatches nothing
        if (data.size() - offset < 2) return false;   // offset <= size() (loop invariant) -> subtraction form, not the additive shape the standard forbids
        const std::size_t len = getU16BE(data.data() + offset);
        offset += 2 + len;
        if (offset > data.size()) return false;
    }
    offset = 1;
    for (int n = 0; n < msgCount; ++n) {             // framing valid -> dispatch each wire span
        const std::size_t len = getU16BE(data.data() + offset);
        f(data.subspan(offset + 2, len));
        offset += 2 + len;
    }
    return true;
}

// Owning form: materialize each wire as a Bytes; nullopt on a malformed batch.
inline std::optional<std::vector<Bytes>> unbatchMessages(const Bytes& data) {
    std::vector<Bytes> out;
    if (!forEachBatchWire(ByteSpan(data.data(), data.size()),
                          [&](ByteSpan w) { out.emplace_back(w.begin(), w.end()); }))
        return std::nullopt;
    return out;
}

} // namespace aether
