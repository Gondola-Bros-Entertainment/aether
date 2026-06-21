// aether - reliable delivery: sequence/ack tracking, Jacobson/Karels RTT + RTO,
// fast retransmit, in-flight tracking, and a rolling loss window. Ring buffers
// are plain arrays mutated in place.
#pragma once

#include "aether/types.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <utility>
#include <vector>

namespace aether {

inline constexpr double        initialRtoMs               = 100.0;
inline constexpr int           ackBitsWindow              = 32;   // matches the 32-bit ackBits wire field
inline constexpr double        rttAlpha                   = 0.125;   // Jacobson/Karels SRTT
inline constexpr double        rttBeta                    = 0.25;    // ...RTTVAR
inline constexpr double        minRtoMs                   = 50.0;
inline constexpr double        maxRtoMs                   = 2000.0;
inline constexpr int           lossWindowSize             = 256;
inline constexpr std::uint8_t  fastRetransmitThreshold    = 3;
inline constexpr std::uint16_t defaultMaxSequenceDistance = 32768;
inline constexpr int           defaultMaxInFlight         = 256;
inline constexpr int           sentBufferSize             = 256;     // ring; power of 2
inline constexpr int           recvBufferSize             = 256;
inline constexpr std::uint8_t  maxMsgsPerPacket           = 16;      // cap on coalesced messages per sent packet

// --- 256-bit rolling loss window (1 = lost) ---
struct LossWindow { std::uint64_t bits[4]{}; };

inline void lossSet(LossWindow& w, int idx, bool lost) noexcept {
    const std::uint64_t bit = std::uint64_t(1) << (idx & 63);
    if (lost) w.bits[idx >> 6] |= bit;
    else      w.bits[idx >> 6] &= ~bit;
}
inline int lossCount(const LossWindow& w, int n) noexcept {
    if (n <= 0) return 0;
    if (n > lossWindowSize) n = lossWindowSize;
    int total = 0;
    for (int i = 0; i < 4 && n > 0; ++i) {
        const int           take = n < 64 ? n : 64;
        const std::uint64_t mask = (take == 64) ? ~std::uint64_t(0) : ((std::uint64_t(1) << take) - 1);
        total += std::popcount(w.bits[i] & mask);
        n -= take;
    }
    return total;
}

// --- generic sequence buffer: a ring indexed by sequence & (size-1) ---
inline int nextPow2(int n) noexcept { int p = 1; while (p < n) p <<= 1; return p; }

template <class T>
struct SequenceBuffer {
    struct Entry { SequenceNum seq{}; T value{}; bool occupied{}; };
    std::vector<Entry> entries;
    int                mask{};
    explicit SequenceBuffer(int size = 256)
        : entries(static_cast<std::size_t>(nextPow2(size))), mask(nextPow2(size) - 1) {}
};
template <class T> int  sbIndex(const SequenceBuffer<T>& b, SequenceNum s) noexcept { return s.value & b.mask; }
template <class T> void sbInsert(SequenceBuffer<T>& b, SequenceNum s, const T& v) {
    auto& e = b.entries[static_cast<std::size_t>(sbIndex(b, s))];
    e.seq = s; e.value = v; e.occupied = true;
}
template <class T> bool sbExists(const SequenceBuffer<T>& b, SequenceNum s) {
    const auto& e = b.entries[static_cast<std::size_t>(sbIndex(b, s))];
    return e.occupied && e.seq == s;
}
template <class T> const T* sbGet(const SequenceBuffer<T>& b, SequenceNum s) {
    const auto& e = b.entries[static_cast<std::size_t>(sbIndex(b, s))];
    return (e.occupied && e.seq == s) ? &e.value : nullptr;
}

// --- received-packet dedup buffer (per-slot occupied flag, so seq 65535 is a real value and
//     not a sentinel -- fixes the old 0xFFFF collision that dropped seq 65535 once per wrap) ---
struct ReceivedSlot { std::uint16_t seq{}; bool occupied{}; };
struct ReceivedBuffer {
    std::array<ReceivedSlot, recvBufferSize> slots{};
};
inline bool rbExists(const ReceivedBuffer& b, SequenceNum s) noexcept {
    const ReceivedSlot& slot = b.slots[s.value & (recvBufferSize - 1)];
    return slot.occupied && slot.seq == s.value;
}
inline void rbInsert(ReceivedBuffer& b, SequenceNum s) noexcept {
    ReceivedSlot& slot = b.slots[s.value & (recvBufferSize - 1)];
    slot.seq      = s.value;
    slot.occupied = true;
}

// --- sent-packet ring buffer (ack processing + RTT) ---
// A reliable channel message (channel + its per-channel sequence). Defined here because the sent
// record stores a list of them: one packet can carry several once coalesced.
// A reliable channel message reference. fragIndex is 0 for an unfragmented message; for a fragmented
// one it is which fragment this packet carried, so the channel acks each fragment independently.
struct ChannelMsg { ChannelId channel{}; SequenceNum seq{}; std::uint8_t fragIndex{}; };
struct SentPacketRecord {
    std::array<ChannelMsg, maxMsgsPerPacket> msgs{};
    std::uint8_t msgCount{};
    MonoTime     sendTime{};
    int          size{};
    std::uint8_t nackCount{};
    bool         countedLost{};   // already recorded a loss sample (fast-retransmit); don't double-count if it later arrives
};
struct SentRing { SequenceNum seq{}; SentPacketRecord rec{}; bool occupied{}; };
struct SentPacketBuffer {
    std::array<SentRing, sentBufferSize> ring{};
    int count{};
};
inline int spbIndex(SequenceNum s) noexcept { return s.value & (sentBufferSize - 1); }
inline SentPacketRecord* spbLookup(SentPacketBuffer& b, SequenceNum s) noexcept {
    auto& e = b.ring[static_cast<std::size_t>(spbIndex(s))];
    return (e.occupied && e.seq == s) ? &e.rec : nullptr;
}
inline bool spbMember(const SentPacketBuffer& b, SequenceNum s) noexcept {
    const auto& e = b.ring[static_cast<std::size_t>(spbIndex(s))];
    return e.occupied && e.seq == s;
}
inline void spbInsert(SentPacketBuffer& b, SequenceNum s, const SentPacketRecord& r) noexcept {
    auto& e = b.ring[static_cast<std::size_t>(spbIndex(s))];
    if (!e.occupied) ++b.count;
    e.seq = s; e.rec = r; e.occupied = true;
}
inline void spbDelete(SentPacketBuffer& b, SequenceNum s) noexcept {
    auto& e = b.ring[static_cast<std::size_t>(spbIndex(s))];
    if (e.occupied && e.seq == s) { e.occupied = false; --b.count; }
}
inline bool spbFindOldest(const SentPacketBuffer& b, SequenceNum& outSeq) noexcept {
    bool found = false; MonoTime best{};
    for (const auto& e : b.ring)
        if (e.occupied && (!found || e.rec.sendTime.ns < best.ns)) { best = e.rec.sendTime; outSeq = e.seq; found = true; }
    return found;
}

// --- the reliable endpoint ---
struct AckResult {
    std::vector<ChannelMsg> acked;
    std::vector<ChannelMsg> fastRetransmit;
    int                     ackedBytes = 0;   // actual bytes acked this call (drives the congestion window)
};

struct ReliableEndpoint {
    SequenceNum      localSeq{};
    SequenceNum      remoteSeq{};
    std::uint64_t    ackBits{};
    SentPacketBuffer sent{};
    ReceivedBuffer   received{};
    std::uint16_t    maxSeqDistance = defaultMaxSequenceDistance;
    int              maxInFlight    = defaultMaxInFlight;
    double           srtt   = 0.0;
    double           rttvar = 0.0;
    double           rto    = initialRtoMs;
    bool             hasRttSample = false;
    LossWindow       lossWindow{};
    int              lossWindowIndex = 0;
    int              lossWindowCount = 0;
    std::uint64_t    totalSent = 0, totalAcked = 0, totalLost = 0, packetsEvicted = 0;
    std::uint64_t    bytesSent = 0, bytesAcked = 0;
};

inline SequenceNum nextSequence(ReliableEndpoint& ep) {
    const SequenceNum s = ep.localSeq;
    ep.localSeq = next(ep.localSeq);
    return s;
}

inline void updateRtt(ReliableEndpoint& ep, double sampleMs) {
    if (!ep.hasRttSample) {
        ep.srtt = sampleMs;
        ep.rttvar = sampleMs / 2.0;
        ep.hasRttSample = true;
    } else {
        ep.rttvar = (1.0 - rttBeta) * ep.rttvar + rttBeta * std::abs(sampleMs - ep.srtt);
        ep.srtt   = (1.0 - rttAlpha) * ep.srtt + rttAlpha * sampleMs;
    }
    ep.rto = std::clamp(ep.srtt + 4.0 * ep.rttvar, minRtoMs, maxRtoMs);
}

inline void recordLossSample(ReliableEndpoint& ep, bool lost) {
    lossSet(ep.lossWindow, ep.lossWindowIndex % lossWindowSize, lost);
    ep.lossWindowIndex += 1;
    ep.lossWindowCount = std::min(lossWindowSize, ep.lossWindowCount + 1);
}

inline void onPacketSent(ReliableEndpoint& ep, SequenceNum seq, MonoTime sendTime,
                         std::span<const ChannelMsg> msgs, int size) {
    if (ep.sent.count >= ep.maxInFlight) {
        SequenceNum worst{};
        if (spbFindOldest(ep.sent, worst)) { spbDelete(ep.sent, worst); ep.packetsEvicted += 1; }
    }
    SentPacketRecord rec{};
    rec.msgCount = static_cast<std::uint8_t>(std::min<std::size_t>(msgs.size(), maxMsgsPerPacket));
    for (std::uint8_t i = 0; i < rec.msgCount; ++i) rec.msgs[i] = msgs[i];
    rec.sendTime = sendTime;
    rec.size     = size;
    spbInsert(ep.sent, seq, rec);
    ep.totalSent += 1;
    ep.bytesSent += static_cast<std::uint64_t>(size);
}
// convenience: a single (channel, seq) message -- the non-coalesced path.
inline void onPacketSent(ReliableEndpoint& ep, SequenceNum seq, MonoTime sendTime,
                         ChannelId ch, SequenceNum chSeq, int size) {
    const ChannelMsg m{ ch, chSeq };
    onPacketSent(ep, seq, sendTime, std::span<const ChannelMsg>(&m, 1), size);
}

inline void onPacketsReceived(ReliableEndpoint& ep, const SequenceNum* seqs, std::size_t n) {
    for (std::size_t k = 0; k < n; ++k) {
        const SequenceNum sn = seqs[k];
        if (static_cast<std::uint32_t>(std::abs(sequenceDiff(sn, ep.remoteSeq))) > ep.maxSeqDistance) continue;
        if (rbExists(ep.received, sn)) continue;
        rbInsert(ep.received, sn);
        if (newer(sn, ep.remoteSeq)) {
            const int d = sequenceDiff(sn, ep.remoteSeq);
            ep.ackBits = (d <= ackBitsWindow) ? ((ep.ackBits << d) | (std::uint64_t(1) << (d - 1))) : 0;
            ep.remoteSeq = sn;
        } else {
            const int d = sequenceDiff(ep.remoteSeq, sn);
            if (d > 0 && d <= ackBitsWindow) ep.ackBits |= (std::uint64_t(1) << (d - 1));
        }
    }
}

inline AckResult processAcks(ReliableEndpoint& ep, SequenceNum ackSeq, std::uint64_t ackBitsVal, MonoTime now) {
    AckResult result;
    std::uint64_t bAcked = 0;
    for (int i = 0; i <= ackBitsWindow; ++i) {
        const SequenceNum seq    = (i == 0) ? ackSeq : SequenceNum{ static_cast<std::uint16_t>(ackSeq.value - i) };
        const bool        bitSet = (i == 0) ? true : ((ackBitsVal & (std::uint64_t(1) << (i - 1))) != 0);
        SentPacketRecord* rec = spbLookup(ep.sent, seq);
        if (!rec) continue;
        if (bitSet) {
            for (std::uint8_t k = 0; k < rec->msgCount; ++k) result.acked.push_back(rec->msgs[k]);
            updateRtt(ep, elapsedMs(rec->sendTime, now));         // one RTT sample per acked packet (Jacobson/Karels)
            bAcked += static_cast<std::uint64_t>(rec->size);
            if (!rec->countedLost) recordLossSample(ep, false);   // don't double-count a packet already counted lost
            spbDelete(ep.sent, seq);
        } else {
            rec->nackCount = static_cast<std::uint8_t>(std::min(255, rec->nackCount + 1));
            if (rec->nackCount == fastRetransmitThreshold) {   // crosses the loss threshold exactly once
                recordLossSample(ep, true);                    // ...so packetLossPercent actually moves off zero
                rec->countedLost = true;
                ep.totalLost += 1;
                for (std::uint8_t k = 0; k < rec->msgCount; ++k) result.fastRetransmit.push_back(rec->msgs[k]);
            }
        }
    }
    ep.totalAcked   += result.acked.size();
    ep.bytesAcked   += bAcked;
    result.ackedBytes = static_cast<int>(bAcked);
    return result;
}

inline std::pair<SequenceNum, std::uint64_t> getAckInfo(const ReliableEndpoint& ep) {
    return { ep.remoteSeq, ep.ackBits };
}
inline double packetLossPercent(const ReliableEndpoint& ep) {
    return ep.lossWindowCount == 0 ? 0.0
        : static_cast<double>(lossCount(ep.lossWindow, ep.lossWindowCount)) / ep.lossWindowCount;
}
inline bool isInFlight(const ReliableEndpoint& ep, SequenceNum s) { return spbMember(ep.sent, s); }
inline int  packetsInFlight(const ReliableEndpoint& ep) { return ep.sent.count; }

// Reset transport metrics (in-flight, RTT, loss) for a new network path, e.g. connection
// migration. Sequence state (local/remote/ackBits/received dedup) is preserved on purpose.
inline void resetReliabilityMetrics(ReliableEndpoint& ep) {
    ep.sent            = SentPacketBuffer{};
    ep.srtt            = 0.0;
    ep.rttvar          = 0.0;
    ep.rto             = initialRtoMs;
    ep.hasRttSample    = false;
    ep.lossWindow      = LossWindow{};
    ep.lossWindowIndex = 0;
    ep.lossWindowCount = 0;
    ep.totalSent = ep.totalAcked = ep.totalLost = ep.packetsEvicted = 0;
    ep.bytesSent = ep.bytesAcked = 0;
}

} // namespace aether
