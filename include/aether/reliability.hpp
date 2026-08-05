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
// How far BEHIND the newest sequence we have received a packet may still be and be processed. Past
// this it is an ancient duplicate: outside the 32-bit ack bitfield and outside the recvBufferSize-slot
// dedup ring, so it can neither be acked usefully nor recognized as a repeat. Far-FUTURE sequences are
// deliberately NOT bounded by it -- see onPacketsReceived.
inline constexpr std::uint16_t defaultMaxSequenceDistance = 1024;
inline constexpr int           defaultMaxInFlight         = 256;
inline constexpr int           sentBufferSize             = 256;     // ring; power of 2
inline constexpr int           recvBufferSize             = 256;
inline constexpr std::uint8_t  maxMsgsPerPacket           = 16;      // cap on coalesced messages per sent packet
// A sent packet unresolved this many RTOs is declared lost by TIMEOUT. The triple-NACK path needs
// acks to fire, so on a path that has gone silent it never runs at all.
inline constexpr double        rtoLossMultiplier          = 2.0;
// Retransmit backoff: attempt N waits 2^(N-1) RTOs, so a retry budget covers an outage instead of a
// fraction of a second. Beyond this the shift stops (maxRtoMs caps the wait long before it anyway).
inline constexpr int           maxBackoffExponent         = 6;

// --- 256-bit rolling loss window (1 = lost) ---
static_assert(lossWindowSize > 0 && (lossWindowSize & (lossWindowSize - 1)) == 0,
              "the window index is masked, so the size must be a power of two");
struct LossWindow { std::array<std::uint64_t, 4> bits{}; };

inline void lossSet(LossWindow& w, int idx, bool lost) noexcept {
    const std::uint64_t bit = std::uint64_t(1) << (idx & 63);
    if (lost) w.bits[static_cast<std::size_t>(idx >> 6)] |= bit;
    else      w.bits[static_cast<std::size_t>(idx >> 6)] &= ~bit;
}
inline int lossCount(const LossWindow& w, int n) noexcept {
    if (n <= 0) return 0;
    if (n > lossWindowSize) n = lossWindowSize;
    int total = 0;
    for (std::size_t i = 0; i < w.bits.size() && n > 0; ++i) {
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
    // COUNT of packets newly acknowledged, whatever they carried. The mirror of lostPackets, and for
    // the same reason: an unreliable-only packet is recorded with size 0, so ackedBytes stays 0 when one
    // is confirmed. Growth is byte-driven and correctly ignores it, but ENTERING cwOnAck at all is what
    // ends fast recovery -- gating that on bytes left a mostly-unreliable stream stuck in Recovery from
    // its first loss until whenever the next reliable ack happened to arrive.
    int                     ackedPackets = 0;
    // COUNT of packets newly declared lost, whatever they carried. This is the congestion signal;
    // the two fields above are byte accounting and neither can stand in for it. A packet carrying
    // only unreliable wires is a real drop on the path, but its `size` is 0 (see SentPacketRecord)
    // and it contributes no fastRetransmit entries, so both would read as "nothing was lost" for
    // the exact traffic shape -- a stream of unreliable snapshots -- that games send most of.
    int                     lostPackets = 0;
    // True when a loss here opened a NEW congestion EPISODE (see noteLossEpisode). The window must
    // reduce once per episode, and the phase alone cannot say which: any header that acks with no
    // loss ends recovery, so the second and third drops of one flight arrive with the phase already
    // back in avoidance and each would take a full halving.
    bool                    newLossEpisode = false;
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
    // Free-running write cursor, masked into the window on every use. Unsigned so the wrap at 2^32 is
    // defined and (because lossWindowSize divides 2^32) seamless -- a signed counter is UB there, and
    // the negative value it becomes indexes the window out of bounds.
    std::uint32_t    lossWindowIndex = 0;
    int              lossWindowCount = 0;
    // NewReno loss episodes. newestSentSeq is the flight boundary: when an episode opens it is copied
    // into lossRecoverSeq, and any later loss not newer than that was already in flight then, so it is
    // more of the same drop rather than a fresh congestion signal.
    SequenceNum      newestSentSeq{};
    SequenceNum      lossRecoverSeq{};
    bool             lossEpisodeOpen = false;
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

// How long to wait before retransmit attempt `retryCount` (1 == the first send). Exponential backoff,
// held under maxRtoMs: without it every attempt waits the same base RTO, so a retry budget of ten
// spans about half a second at the 50ms floor -- the message is written off while the connection
// itself is still minutes from timing out, and a path that blinks for a second loses everything in
// flight. The cap is what keeps a backed-off retransmit responsive when the path returns.
inline double retransmitTimeoutMs(double baseRtoMs, int retryCount) noexcept {
    const int shift = std::min(retryCount > 1 ? retryCount - 1 : 0, maxBackoffExponent);
    return std::min(baseRtoMs * static_cast<double>(std::uint32_t{ 1 } << shift), maxRtoMs);
}

inline void recordLossSample(ReliableEndpoint& ep, bool lost) {
    lossSet(ep.lossWindow, static_cast<int>(ep.lossWindowIndex & (lossWindowSize - 1)), lost);
    ep.lossWindowIndex += 1;
    ep.lossWindowCount = std::min(lossWindowSize, ep.lossWindowCount + 1);
}

// Place a declared loss in a congestion EPISODE, and return whether it opened a new one. An episode
// covers everything that was already in flight when it opened, so the second and third packets of one
// dropped flight fold into the first packet's episode however far apart their NACK thresholds trip.
inline bool noteLossEpisode(ReliableEndpoint& ep, SequenceNum lostSeq) noexcept {
    if (ep.lossEpisodeOpen && !newer(lostSeq, ep.lossRecoverSeq)) return false;
    ep.lossEpisodeOpen = true;
    ep.lossRecoverSeq  = ep.newestSentSeq;
    return true;
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
    if (ep.totalSent == 0 || newer(seq, ep.newestSentSeq)) ep.newestSentSeq = seq;   // the flight boundary a loss episode is measured against
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
        // The distance guard bounds the PAST only. A sequence far in the future means we fell behind
        // -- a long silence while the peer kept sending -- and refusing it is self-sealing: remoteSeq
        // can never advance, every later packet is equally out of range, and no ack is ever sent again
        // while the connection stays alive on received-time alone. The newer() branch below
        // resynchronizes to it with an empty bitfield, which is exactly right: nothing before it is
        // known to have arrived. A sequence far in the PAST is an ancient duplicate, outside both the
        // ack bitfield and the dedup ring, and must not rewind anything.
        if (ep.hasRemoteSeq && sequenceDiff(sn, ep.remoteSeq) < -static_cast<int>(ep.maxSeqDistance)) continue;
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
            if (!rec->countedLost) {          // a packet already declared lost released its bytes and took its
                // Karn: a packet that was written off contributes no RTT sample. The elapsed time to a
                // late ack of one measures the retransmit timeline, not the path, and feeding it in
                // moves srtt and rttvar by whole multiples in a single sample.
                updateRtt(ep, elapsedMs(rec->sendTime, now));       // one RTT sample per acked packet (Jacobson/Karels)
                bAcked += static_cast<std::uint64_t>(rec->size);   // loss sample back then; a late ack must not
                recordLossSample(ep, false);                       // release or sample it a second time
                result.ackedPackets += 1;
            }
            spbDelete(ep.sent, seq);
        } else {
            rec->nackCount = static_cast<std::uint8_t>(std::min(255, rec->nackCount + 1));
            // countedLost is checked as well as the threshold: a timeout may already have written this
            // packet off (see declareTimedOutPackets), and declaring it twice double-counts the loss
            // and releases its bytes from the window a second time.
            if (!rec->countedLost && rec->nackCount == fastRetransmitThreshold) {   // crosses the loss threshold exactly once
                recordLossSample(ep, true);                    // ...so packetLossFraction actually moves off zero
                rec->countedLost = true;
                ep.totalLost += 1;
                result.lostPackets += 1;
                bLost += static_cast<std::uint64_t>(rec->size);
                if (noteLossEpisode(ep, seq)) result.newLossEpisode = true;
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

// Packets written off by TIMEOUT rather than by a triple-NACK.
struct TimeoutResult {
    int  lostBytes    = 0;   // bytes leaving flight; the caller releases them from the congestion window
    int  lostPackets  = 0;
    bool newLossEpisode = false;
};

// Declare every unresolved sent packet older than timeoutMs lost. The NACK path needs ACKS to fire, so
// on a path that has gone silent it never runs: no loss sample is ever recorded, packetLossFraction
// keeps returning its pre-outage value, and a rate controller reading that sees good conditions and
// additively increases into a dead path while the health signal still reports the best grade there is.
// A packet unresolved for several RTOs is lost whether or not a later ack ever revealed it.
//
// The record STAYS in the ring, marked countedLost: a late ack must still resolve the channel messages
// it carried (it just contributes no bytes, no RTT sample and no second loss -- see processAcks).
inline TimeoutResult declareTimedOutPackets(ReliableEndpoint& ep, MonoTime now, double timeoutMs) {
    TimeoutResult out;
    for (auto& e : ep.sent.ring) {
        if (!e.occupied || e.rec.countedLost) continue;
        if (elapsedMs(e.rec.sendTime, now) < timeoutMs) continue;
        e.rec.countedLost = true;
        recordLossSample(ep, true);
        ep.totalLost      += 1;
        out.lostBytes     += e.rec.size;
        out.lostPackets   += 1;
        if (noteLossEpisode(ep, e.seq)) out.newLossEpisode = true;
    }
    return out;
}

// Drop every sent record, resolved or not. For an idle so long that nothing of ours can still be in
// the network (see cwSlowStartRestart): the window is emptied at the same moment, and a ring still
// holding those records would report each one's size a second time on its next late ack, loss
// declaration or eviction -- each subtraction taken from a counter that no longer contains the bytes.
// Their channel messages are not lost: they are unacked, so the channel's own RTO resends them.
inline void abandonSentPackets(ReliableEndpoint& ep) noexcept { ep.sent = SentPacketBuffer{}; }

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
// Loss over the rolling window as a FRACTION in [0,1] -- not a percent. Scale by 100 to display one.
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
    ep.newestSentSeq   = SequenceNum{};   // a new path starts a new flight, so no episode carries over
    ep.lossRecoverSeq  = SequenceNum{};
    ep.lossEpisodeOpen = false;
    ep.totalSent = ep.totalAcked = ep.totalLost = ep.packetsEvicted = 0;
    ep.bytesSent = ep.bytesAcked = 0;
}

} // namespace aether
