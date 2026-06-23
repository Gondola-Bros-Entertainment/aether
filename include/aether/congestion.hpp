// aether - congestion control and bandwidth tracking. Two controllers: a binary Good/Bad AIMD
// rate limiter and a TCP New-Reno style window, plus a sliding-window bandwidth tracker and
// message batching. Data-first: structs mutated by free functions in place.
#pragma once

#include "aether/reliability.hpp"
#include "aether/serialize.hpp"
#include "aether/stats.hpp"
#include "aether/types.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <deque>
#include <limits>
#include <optional>
#include <span>
#include <utility>
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
inline constexpr double        sendRateIncrease          = 1.0;   // additive increase, packets/sec
inline constexpr double        maxSendRateMultiplier     = 4.0;
inline constexpr double        initialSsthresh           = std::numeric_limits<double>::infinity();

enum class CongestionMode  { Good, Bad };
enum class CongestionPhase { SlowStart, Avoidance, Recovery };

// --- binary congestion controller (Good/Bad mode with AIMD) ---
struct CongestionController {
    CongestionMode          mode                 = CongestionMode::Good;
    std::optional<MonoTime> goodConditionsStart;
    double                  lossThreshold        = 0.0;
    double                  rttThresholdMs       = 0.0;
    double                  baseSendRate         = 0.0;
    double                  currentSendRate      = 0.0;
    int                     budgetBytesRemaining = 0;
    int                     bytesPerTick         = 0;
    double                  adaptiveRecoverySecs = 0.0;
    std::optional<MonoTime> lastGoodEntry;
    std::optional<MonoTime> lastBadEntry;
};

inline CongestionController newCongestionController(double baseSendRate, double lossThreshold,
                                                   double rttThresholdMs, double recoveryTimeMs) {
    CongestionController cc;
    cc.lossThreshold        = lossThreshold;
    cc.rttThresholdMs       = rttThresholdMs;
    cc.baseSendRate         = baseSendRate;
    cc.currentSendRate      = baseSendRate;
    cc.adaptiveRecoverySecs = recoveryTimeMs / 1000.0;
    return cc;
}

// Refill the per-tick byte budget = floor(rate * mtu).
inline void ccRefillBudget(CongestionController& cc, int mtu) {
    cc.bytesPerTick         = static_cast<int>(cc.currentSendRate * static_cast<double>(mtu));
    cc.budgetBytesRemaining = cc.bytesPerTick;
}
inline void ccDeductBudget(CongestionController& cc, int bytes) { cc.budgetBytesRemaining -= bytes; }

// Update Good/Bad state from current loss and RTT.
inline void ccUpdate(CongestionController& cc, double packetLoss, double rttMs, MonoTime now) {
    const bool isBad = packetLoss > cc.lossThreshold || rttMs > cc.rttThresholdMs;
    if (cc.mode == CongestionMode::Good) {
        if (isBad) {
            const double recoveryMult = (cc.lastGoodEntry && elapsedMs(*cc.lastGoodEntry, now) < quickDropThresholdSecs * 1000.0) ? 2.0 : 1.0;
            cc.mode                 = CongestionMode::Bad;
            cc.lastBadEntry         = now;
            cc.currentSendRate      = std::max(minSendRate, cc.currentSendRate * congestionRateReduction);
            cc.goodConditionsStart  = std::nullopt;
            cc.adaptiveRecoverySecs = std::min(maxRecoverySecs, cc.adaptiveRecoverySecs * recoveryMult);
        } else {
            const double maxRate = cc.baseSendRate * maxSendRateMultiplier;
            cc.currentSendRate   = std::min(maxRate, cc.currentSendRate + sendRateIncrease);
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

inline bool ccCanSend(const CongestionController& cc, int packetsSentThisCycle, int packetBytes) {
    return static_cast<double>(packetsSentThisCycle) < cc.currentSendRate && cc.budgetBytesRemaining >= packetBytes;
}

inline CongestionLevel ccCongestionLevel(const CongestionController& cc) {
    if (cc.mode == CongestionMode::Bad) return CongestionLevel::Critical;
    const double budgetRatio = cc.bytesPerTick <= 0 ? 1.0 : static_cast<double>(cc.budgetBytesRemaining) / static_cast<double>(cc.bytesPerTick);
    return budgetRatio < 0.25 ? CongestionLevel::Elevated : CongestionLevel::None;
}

// --- window-based congestion controller (TCP New Reno style) ---
struct CongestionWindow {
    CongestionPhase         phase               = CongestionPhase::SlowStart;
    double                  cwnd                = 0.0;
    double                  ssthresh            = initialSsthresh;
    std::uint64_t           bytesInFlight       = 0;
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

inline void cwOnAck(CongestionWindow& cw, int bytes) {
    cw.bytesInFlight -= std::min<std::uint64_t>(static_cast<std::uint64_t>(bytes), cw.bytesInFlight);
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
    cw.ssthresh = std::max(static_cast<double>(minCwndBytes), cw.cwnd / 2.0);
    cw.cwnd     = cw.ssthresh + 3.0 * static_cast<double>(cw.mtu);
    cw.phase    = CongestionPhase::Recovery;
}

inline void cwOnSend(CongestionWindow& cw, int bytes, MonoTime now) {
    cw.bytesInFlight += static_cast<std::uint64_t>(bytes);
    cw.lastSendTime   = now;
}

inline bool cwCanSend(const CongestionWindow& cw, int packetBytes) {
    return cw.bytesInFlight + static_cast<std::uint64_t>(packetBytes) <= static_cast<std::uint64_t>(cw.cwnd);
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
    }
}

inline CongestionLevel cwCongestionLevel(const CongestionWindow& cw) {
    const double utilization = cw.cwnd <= 0.0 ? 1.0 : static_cast<double>(cw.bytesInFlight) / cw.cwnd;
    if (utilization > 0.95) return CongestionLevel::Critical;
    if (utilization > 0.85) return CongestionLevel::High;
    if (utilization > 0.70) return CongestionLevel::Elevated;
    return CongestionLevel::None;
}

// --- bandwidth tracker (sliding window with cached byte total) ---
struct BandwidthTracker {
    std::deque<std::pair<MonoTime, int>> window;
    double                               windowDurationMs = 0.0;
    int                                  totalBytes       = 0;
};

inline BandwidthTracker newBandwidthTracker(double windowDurationMs) {
    BandwidthTracker bt;
    bt.windowDurationMs = windowDurationMs;
    return bt;
}

inline void btCleanup(BandwidthTracker& bt, MonoTime now) {
    while (!bt.window.empty() && elapsedMs(bt.window.front().first, now) >= bt.windowDurationMs) {
        bt.totalBytes -= bt.window.front().second;
        bt.window.pop_front();
    }
}
inline void btRecord(BandwidthTracker& bt, int bytes, MonoTime now) {
    bt.window.emplace_back(now, bytes);
    bt.totalBytes += bytes;
    btCleanup(bt, now);
}
inline double btBytesPerSecond(const BandwidthTracker& bt) {
    if (bt.window.empty()) return 0.0;
    const double elapsedSecs = bt.windowDurationMs / 1000.0;
    return elapsedSecs > 0.0 ? static_cast<double>(bt.totalBytes) / elapsedSecs : 0.0;
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
