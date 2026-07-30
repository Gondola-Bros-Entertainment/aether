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

// --- sequence dedup ring: "have I already seen this 16-bit sequence?" ---
// A per-slot occupied flag, so sequence 65535 is a real value and not a sentinel. Slot = seq & 255,
// holding the full sequence, so a sequence more than recvBufferSize behind the newest simply falls out
// of the ring (it is re-accepted rather than falsely rejected -- the safe direction for both users).
// Used by the packet layer (duplicate datagrams) and by ReliableUnordered channels (duplicate messages).
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
    // RELIABLE wire bytes this packet carries -- not the whole datagram. This is the unit the
    // congestion window is charged on send and credited on ack/loss, so charge and release match
    // exactly; batch framing and any unreliable wires riding along are deliberately excluded
    // (nothing ever acks them, so counting them would leak the window shut).
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
// The record that inserting `s` would silently overwrite: an unresolved packet from a full ring cycle
// ago (s - 256) still occupying s's slot. nullptr when the slot is free or already holds s.
inline const SentPacketRecord* spbDisplaced(const SentPacketBuffer& b, SequenceNum s) noexcept {
    const auto& e = b.ring[static_cast<std::size_t>(spbIndex(s))];
    return (e.occupied && e.seq != s) ? &e.rec : nullptr;
}

// --- the reliable endpoint ---
struct AckResult {
    std::vector<ChannelMsg> acked;
    std::vector<ChannelMsg> fastRetransmit;
    // Bytes acked this call, EXCLUDING packets already declared lost (those released their bytes
    // when they were declared, so crediting them again would double-release). Drives window growth.
    int                     ackedBytes = 0;
    // Bytes of packets newly DECLARED lost this call. They leave flight but must not grow the window.
    int                     lostBytes  = 0;
};

// Outgoing sequence numbers are owned by the Connection (conn.localSeq), which stamps the header and
// passes the sequence in to onPacketSent -- the endpoint only ever tracks what it has RECEIVED.
struct ReliableEndpoint {
    SequenceNum      remoteSeq{};
    // False until the first packet arrives: a default remoteSeq of 0 is NOT a sequence we have seen,
    // and treating it as one falsely acknowledges sequence 0 (see onPacketsReceived).
    bool             hasRemoteSeq = false;
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

// Record a sent packet. Returns the bytes of any packet REMOVED UNRESOLVED to make room -- evicted
// over maxInFlight, or displaced from its ring slot by a sequence one full cycle later -- because an
// ack can never resolve it now: the caller must release those bytes from the congestion window or
// they stay in flight forever. A victim already declared lost contributes 0: it released its bytes
// when it was declared (AckResult.lostBytes), and releasing again would double-count.
inline int onPacketSent(ReliableEndpoint& ep, SequenceNum seq, MonoTime sendTime,
                        std::span<const ChannelMsg> msgs, int size) {
    int evictedBytes = 0;
    if (ep.sent.count >= ep.maxInFlight) {
        SequenceNum worst{};
        if (spbFindOldest(ep.sent, worst)) {
            if (const SentPacketRecord* victim = spbLookup(ep.sent, worst))
                if (!victim->countedLost) evictedBytes += victim->size;
            spbDelete(ep.sent, worst);
            ep.packetsEvicted += 1;
        }
    }
    if (const SentPacketRecord* stale = spbDisplaced(ep.sent, seq)) {   // spbInsert below overwrites it
        if (!stale->countedLost) evictedBytes += stale->size;
        ep.packetsEvicted += 1;
    }
    SentPacketRecord rec{};
    rec.msgCount = static_cast<std::uint8_t>(std::min<std::size_t>(msgs.size(), maxMsgsPerPacket));
    for (std::uint8_t i = 0; i < rec.msgCount; ++i) rec.msgs[i] = msgs[i];
    rec.sendTime = sendTime;
    rec.size     = size;
    spbInsert(ep.sent, seq, rec);
    ep.totalSent += 1;
    ep.bytesSent += static_cast<std::uint64_t>(size);
    return evictedBytes;
}
// convenience: a single (channel, seq) message -- the non-coalesced path.
inline int onPacketSent(ReliableEndpoint& ep, SequenceNum seq, MonoTime sendTime,
                        ChannelId ch, SequenceNum chSeq, int size) {
    const ChannelMsg m{ ch, chSeq };
    return onPacketSent(ep, seq, sendTime, std::span<const ChannelMsg>(&m, 1), size);
}

inline void onPacketsReceived(ReliableEndpoint& ep, const SequenceNum* seqs, std::size_t n) {
    for (std::size_t k = 0; k < n; ++k) {
        const SequenceNum sn = seqs[k];
        if (ep.hasRemoteSeq && static_cast<std::uint32_t>(std::abs(sequenceDiff(sn, ep.remoteSeq))) > ep.maxSeqDistance) continue;
        if (rbExists(ep.received, sn)) continue;
        rbInsert(ep.received, sn);
        if (!ep.hasRemoteSeq) {
            // The first packet we have ever seen: nothing precedes it, so the bitfield stays empty.
            // Advancing from the default remoteSeq 0 instead would shift in a set bit meaning
            // "sequence 0 received" -- so if packet 0 were the one that got lost, the sender would
            // see it acknowledged, mark its reliable messages delivered, and never retransmit them.
            ep.hasRemoteSeq = true;
            ep.remoteSeq    = sn;
            ep.ackBits      = 0;
            continue;
        }
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
    std::uint64_t bAcked = 0, bLost = 0;
    for (int i = 0; i <= ackBitsWindow; ++i) {
        const SequenceNum seq    = (i == 0) ? ackSeq : SequenceNum{ static_cast<std::uint16_t>(ackSeq.value - i) };
        const bool        bitSet = (i == 0) ? true : ((ackBitsVal & (std::uint64_t(1) << (i - 1))) != 0);
        SentPacketRecord* rec = spbLookup(ep.sent, seq);
        if (!rec) continue;
        if (bitSet) {
            for (std::uint8_t k = 0; k < rec->msgCount; ++k) result.acked.push_back(rec->msgs[k]);
            updateRtt(ep, elapsedMs(rec->sendTime, now));         // one RTT sample per acked packet (Jacobson/Karels)
            if (!rec->countedLost) {          // a packet already declared lost released its bytes and took its
                bAcked += static_cast<std::uint64_t>(rec->size);   // loss sample back then; a late ack must not
                recordLossSample(ep, false);                       // release or sample it a second time
            }
            spbDelete(ep.sent, seq);
        } else {
            rec->nackCount = static_cast<std::uint8_t>(std::min(255, rec->nackCount + 1));
            if (rec->nackCount == fastRetransmitThreshold) {   // crosses the loss threshold exactly once
                recordLossSample(ep, true);                    // ...so packetLossFraction actually moves off zero
                rec->countedLost = true;
                ep.totalLost += 1;
                bLost += static_cast<std::uint64_t>(rec->size);
                for (std::uint8_t k = 0; k < rec->msgCount; ++k) result.fastRetransmit.push_back(rec->msgs[k]);
            }
        }
    }
    ep.totalAcked   += result.acked.size();
    ep.bytesAcked   += bAcked;
    result.ackedBytes = static_cast<int>(bAcked);
    result.lostBytes  = static_cast<int>(bLost);
    return result;
}

inline std::pair<SequenceNum, std::uint64_t> getAckInfo(const ReliableEndpoint& ep) {
    return { ep.remoteSeq, ep.ackBits };
}
// Does an incoming header's (ack, ackBits) pair acknowledge `seq`? Bit i-1 of ackBits is ack - i,
// the same layout processAcks walks. For callers tracking a packet OUTSIDE the sent ring (an MTU
// probe carries no reliable messages, so it is never registered there).
inline bool ackCovers(SequenceNum ackSeq, std::uint64_t ackBits, SequenceNum seq) noexcept {
    if (seq == ackSeq) return true;
    const int d = sequenceDiff(ackSeq, seq);
    return d > 0 && d <= ackBitsWindow && (ackBits & (std::uint64_t(1) << (d - 1))) != 0;
}
// Loss over the rolling window as a FRACTION in [0,1] -- not a percent. (It was named
// packetLossPercent while returning a fraction; every caller already treated it as a fraction and
// scaled by 100 where a percent was wanted, so the name was the only thing wrong.)
inline double packetLossFraction(const ReliableEndpoint& ep) {
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
