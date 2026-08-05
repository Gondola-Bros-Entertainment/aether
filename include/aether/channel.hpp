// aether - channel-based delivery with five reliability modes. Each channel owns its sequence
// numbers, its send/receive buffering, and (for ordered mode) a reorder buffer. Data-first: a
// plain Channel struct + free functions.
#pragma once

#include "aether/reliability.hpp"   // ReceivedBuffer: the sequence-dedup ring, shared with the packet layer
#include "aether/types.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace aether {

enum class DeliveryMode {
    Unreliable,           // fire and forget
    UnreliableSequenced,  // unreliable, drops out-of-order
    ReliableUnordered,    // guaranteed, any order
    ReliableOrdered,      // guaranteed, strict order
    ReliableSequenced,    // guaranteed, drops out-of-order
};
constexpr bool isReliable(DeliveryMode m) noexcept  { return m != DeliveryMode::Unreliable && m != DeliveryMode::UnreliableSequenced; }
constexpr bool isSequenced(DeliveryMode m) noexcept { return m == DeliveryMode::UnreliableSequenced || m == DeliveryMode::ReliableSequenced; }
constexpr bool isOrdered(DeliveryMode m) noexcept   { return m == DeliveryMode::ReliableOrdered; }

// Ceiling on messageBufferSize (channelConfigValid enforces it). Two things depend on the send buffer
// staying well inside half the 16-bit sequence space: it is walked in WRAP-AWARE order (see
// sendBufferOldest), which is only defined while the buffered sequences span less than 0x8000; and
// peerCreditUnknown (connection.hpp) has to stay above any reachable unacked count, which this bounds.
inline constexpr int maxMessageBufferSize = 16384;

struct ChannelConfig {
    DeliveryMode deliveryMode         = DeliveryMode::ReliableOrdered;
    int          maxMessageSize       = 1024;   // a message over the MTU is fragmented; ceiling ~maxFragmentCount*chunk (~295KB at a 1200 MTU)
    int          messageBufferSize    = 256;
    bool         blockOnFull          = false;
    double       orderedBufferTimeout = 5000.0;
    int          maxOrderedBufferSize = 64;
    int          maxReliableRetries   = 10;
    int          maxReceiveBufferSize = 8192;   // cap on undrained delivered messages: a memory shield against an app that stops draining
    std::uint8_t priority             = 0;
};
inline ChannelConfig unreliableChannel()        { return { .deliveryMode = DeliveryMode::Unreliable        }; }
inline ChannelConfig reliableOrderedChannel()   { return { .deliveryMode = DeliveryMode::ReliableOrdered   }; }
inline ChannelConfig reliableSequencedChannel() { return { .deliveryMode = DeliveryMode::ReliableSequenced }; }

struct ChannelMessage {
    SequenceNum sequence{};
    Bytes       data;
    MonoTime    sendTime{};
    bool        acked           = false;
    int         retryCount      = 0;
    bool        reliable        = false;
    bool        forceRetransmit = false;   // set by a triple-NACK: resend on the next pass, ignoring the RTO
    std::uint8_t                 fragmentCount = 0;   // 0/1 == sent in one packet; >1 == split into this many fragments
    std::uint8_t                 sentFragments = 0;   // first-send progress: fragments [0, sentFragments) have gone out (paced across ticks by the send budget)
    // Retransmit progress within ONE attempt: the fragment index the next pass resumes from. A
    // fragmented message can need more wire bytes than the whole token bucket holds, so a pass that
    // runs out of budget stops here and continues next tick; the retry count advances only once every
    // missing fragment has gone out, which is what makes one retry one complete attempt.
    std::uint8_t                 retxFragment  = 0;
    std::array<std::uint64_t, 4> fragAckBits{};       // which fragments are acked (256-bit, matches maxFragmentCount 255); message acked when all set
};

enum class ChannelError { None, BufferFull, MessageTooLarge };

struct Channel {
    ChannelConfig config{};
    ChannelId     channelId{};
    SequenceNum   localSeq{};
    SequenceNum   remoteSeq{};
    std::map<SequenceNum, ChannelMessage>             sendBuffer;
    std::vector<Bytes>                                receiveBuffer;
    std::map<SequenceNum, std::pair<Bytes, MonoTime>> orderedBuffer;
    SequenceNum   orderedExpected{};
    // ReliableUnordered has no ordering state to infer duplicates from, so it dedups explicitly: a
    // retransmit whose ack was lost carries a message we may already have delivered, and delivering it
    // twice would make a "reliable" channel at-least-once. The other modes need no window (ordered
    // compares against orderedExpected, sequenced against remoteSeq, unreliable is fire-and-forget).
    ReceivedBuffer recvDedup{};
    std::uint64_t totalSent = 0, totalReceived = 0, totalRetransmits = 0;
    // Intake accounting, kept as three distinct facts because they mean opposite things to an app: DROPPED
    // is data that is gone (an unreliable message with no room, one over the size cap, one superseded on a
    // sequenced channel), DUPLICATE is a retransmit of something already delivered (expected on a lossy
    // link, harmless), and REFUSED is backpressure -- a reliable message a full buffer turned away, left
    // unacked so the sender brings it back. Folding refusals into "dropped" would report healthy
    // backpressure as data loss on a channel that in fact lost nothing.
    std::uint64_t totalDropped = 0, totalDuplicate = 0, totalRefused = 0;
    // The subset of totalDropped that is a BROKEN PROMISE: a reliable message the transport gave up on
    // (retry budget spent, or too large to fragment). Kept apart from totalDropped because everything
    // else in that counter is a drop the channel's contract allows; this one is the contract failing,
    // and an application that cares about the guarantee needs to be able to see it (NetworkStats).
    std::uint64_t totalReliableDropped = 0;
};

inline Channel newChannel(ChannelId id, const ChannelConfig& cfg) {
    Channel c;
    c.config = cfg;
    c.channelId = id;
    return c;
}
// noexcept but not constexpr: Channel holds std::map, so no Channel can exist in a constant
// expression and a constexpr here could never be evaluated as one.
inline bool channelIsReliable(const Channel& ch) noexcept { return isReliable(ch.config.deliveryMode); }

// --- sending ---
struct SendResult { ChannelError error = ChannelError::None; SequenceNum seq{}; };

inline void cleanupAcked(Channel& ch);

// The OLDEST message in the send buffer, in wraparound order.
//
// sendBuffer is a std::map keyed on the raw 16-bit sequence, because SequenceNum::operator< is a
// numeric compare "for ordered containers only" -- so at the wrap the map's own order is not send
// order: with 65533,65534,65535,0,1,2 queued it walks 0,1,2,65533,65534,65535 and begin() is the
// NEWEST message. Every buffered sequence was issued before localSeq, so the true oldest is the first
// key at or after localSeq, and the rest of send order continues from the map's start once the top is
// exhausted -- a rotation of the key order, found in one lower_bound rather than a scan.
inline std::map<SequenceNum, ChannelMessage>::iterator sendBufferOldest(Channel& ch) {
    const auto it = ch.sendBuffer.lower_bound(ch.localSeq);
    return it == ch.sendBuffer.end() ? ch.sendBuffer.begin() : it;
}
// Step to the next message in send order, wrapping back to the map's first key at the top.
inline void sendBufferAdvance(Channel& ch, std::map<SequenceNum, ChannelMessage>::iterator& it) {
    if (++it == ch.sendBuffer.end()) it = ch.sendBuffer.begin();
}

inline SendResult channelSend(Channel& ch, const Bytes& payload, MonoTime now) {
    if (static_cast<int>(payload.size()) > ch.config.maxMessageSize) return { ChannelError::MessageTooLarge, {} };
    if (static_cast<int>(ch.sendBuffer.size()) >= ch.config.messageBufferSize) {
        // A reliable channel must never silently drop a buffered message -- it would break the
        // delivery guarantee and stall the receiver's ordering -- so it backpressures instead.
        if (ch.config.blockOnFull || isReliable(ch.config.deliveryMode)) return { ChannelError::BufferFull, {} };
        ch.sendBuffer.erase(sendBufferOldest(ch));   // unreliable: drop oldest to make room (wrap-aware, not begin())
    }
    const SequenceNum seq = ch.localSeq;
    ch.sendBuffer[seq] = ChannelMessage{ seq, payload, now, false, 0, isReliable(ch.config.deliveryMode) };
    ch.localSeq = next(ch.localSeq);
    ch.totalSent += 1;
    return { ChannelError::None, seq };
}

// Peek the next UNSENT message (OLDEST first, in wraparound order -- see sendBufferOldest), looking
// PAST in-flight ones so several messages can be in flight at once -- a sliding window, not
// stop-and-wait (one per RTT). Cleans acked entries out. Returns a pointer INTO the send buffer (no
// payload copy); it is valid only until the buffer is next mutated, so read it before
// commitOutgoingMessage, which consumes it.
inline const ChannelMessage* peekOutgoingMessage(Channel& ch) {
    cleanupAcked(ch);   // done first, so the ordered walk below cannot erase under its own iterator
    if (ch.sendBuffer.empty()) return nullptr;
    auto it = sendBufferOldest(ch);
    for (std::size_t n = ch.sendBuffer.size(); n > 0; --n) {
        if (it->second.retryCount == 0) return &it->second;   // oldest not-yet-sent message
        sendBufferAdvance(ch, it);                            // in flight, awaiting ack -> look past it
    }
    return nullptr;
}
// Consume the message peekOutgoingMessage returned (by sequence): reliable -> mark sent (retry 1,
// kept for retransmit), unreliable -> remove (fire and forget). `now` restarts the RTO clock: the
// message may have waited queued behind others (or spread its fragments over several ticks) since
// channelSend stamped it, and an RTO measured from creation would fire the moment a delayed send
// finally completed.
inline void commitOutgoingMessage(Channel& ch, SequenceNum seq, MonoTime now) {
    auto it = ch.sendBuffer.find(seq);
    if (it == ch.sendBuffer.end() || it->second.acked || it->second.retryCount != 0) return;
    if (it->second.reliable) { it->second.retryCount = 1; it->second.sendTime = now; }
    else                     ch.sendBuffer.erase(it);
}

// Reliable messages whose RTO has elapsed (or that were flagged for fast-retransmit), OLDEST first in
// wraparound order -- the caller spends a bounded receiver credit on them, so the order has to be real
// send order and not the map's raw key order (see sendBufferOldest). Returns CANDIDATES only -- send
// state advances in commitRetransmit, called once a candidate is actually admitted past the congestion
// budget, so a budget-blocked retransmit does not burn a retry or reset its RTO. Messages past the
// retry limit are dropped here (that is not budget-gated).
//
// The wait grows with the attempt (retransmitTimeoutMs): a fixed RTO spends ten retries inside a
// second, which writes reliable messages off while the connection is still nowhere near its timeout.
//
// The candidates are POINTERS into the send buffer, not copies -- a retransmit pass runs every tick on
// a lossy link, and copying each candidate's payload just to decide whether the budget admits it is a
// per-tick heap copy of data already in hand. They stay valid while the caller walks them (the only
// mutation in that loop is commitRetransmit, which edits a message in place); they are invalidated by
// anything that erases from the send buffer, so do not hold them across a channelSend or channelUpdate.
inline std::vector<const ChannelMessage*> getRetransmitMessages(Channel& ch, MonoTime now, double rtoMs) {
    std::vector<const ChannelMessage*> out;
    if (!isReliable(ch.config.deliveryMode) || ch.sendBuffer.empty()) return out;
    auto it = sendBufferOldest(ch);
    for (std::size_t n = ch.sendBuffer.size(); n > 0; --n) {
        const auto cur = it;
        sendBufferAdvance(ch, it);   // stepped before any erase below, which invalidates only `cur`
        ChannelMessage& msg = cur->second;
        if (msg.acked || msg.retryCount == 0) continue;
        if (msg.retryCount > ch.config.maxReliableRetries) {
            ch.sendBuffer.erase(cur);
            ch.totalDropped          += 1;
            ch.totalReliableDropped  += 1;   // the delivery guarantee just failed; the app must be able to see it
            if (ch.sendBuffer.empty()) break;
            continue;
        }
        if (msg.forceRetransmit || elapsedMs(msg.sendTime, now) >= retransmitTimeoutMs(rtoMs, msg.retryCount))
            out.push_back(&msg);
    }
    return out;
}
// Commit a retransmit that was actually admitted (enqueued past the budget): advance its send time
// and retry count, clear the fast-retransmit flag, and rewind the fragment cursor for the next
// attempt. Mirrors the peek/commit split for fresh sends.
inline void commitRetransmit(Channel& ch, SequenceNum seq, MonoTime now) {
    auto it = ch.sendBuffer.find(seq);
    if (it == ch.sendBuffer.end() || it->second.acked || it->second.retryCount == 0) return;
    it->second.forceRetransmit = false;
    it->second.sendTime        = now;
    it->second.retryCount     += 1;
    it->second.retxFragment    = 0;
    ch.totalRetransmits        += 1;
}

// Mark a specific in-flight message for immediate retransmit (fast-retransmit on a triple-NACK): the
// next getRetransmitMessages resends it without waiting out the RTO. Routed through the normal
// retransmit pass so the congestion budget and retry limit still apply.
inline void markForRetransmit(Channel& ch, SequenceNum seq) noexcept {
    auto it = ch.sendBuffer.find(seq);
    if (it != ch.sendBuffer.end() && !it->second.acked && it->second.retryCount > 0)
        it->second.forceRetransmit = true;
}

// --- receiving ---
//
// Acknowledgement is entirely PACKET level: the packet header's ack + ack bitfield resolve the
// (channel, seq, fragment) triples the sent-packet ring recorded, and processAcks feeds those to
// acknowledgeMessage. A channel therefore keeps no ack list of its own.
//
// Which is why every intake function below reports whether it ACCEPTED the message. A receiver must not
// acknowledge data it did not take: if a full buffer discards a message the packet carrying it has
// already been acked, the sender marks it delivered and never sends it again -- silent loss on a channel
// whose entire promise is that it does not lose things. Returning false leaves the packet unacknowledged,
// so the sender retransmits, and the caps become end-to-end BACKPRESSURE instead of a data leak. (This
// only works because duplicates are recognized: the retransmit of a message that did land arrives again
// and must be acked, not delivered twice -- see the dedup in onMessageReceived.)
//
// "Accepted" means "no retransmit would help": delivered, or permanently unacceptable (a duplicate, or a
// payload over the channel's declared size cap -- resending those changes nothing). It is false only for
// a TRANSIENT refusal, which clears as the app drains or the ordering gap fills.
inline bool deliverOrdered(Channel& ch, Bytes&& payload);
inline bool bufferOrdered(Channel& ch, SequenceNum seq, Bytes&& payload, MonoTime now);
inline void flushOrderedBuffer(Channel& ch);

// Buffer a delivered message, capped at maxReceiveBufferSize so an app that stops draining cannot grow
// the receive buffer without bound. At the cap it returns false and the payload is left untouched (it is
// only moved from on success), so a reliable caller can leave it for the sender to retransmit. The caller
// does the accounting, because only it knows whether a refusal here is recoverable.
inline bool pushReceived(Channel& ch, Bytes&& payload) {
    if (static_cast<int>(ch.receiveBuffer.size()) >= ch.config.maxReceiveBufferSize) return false;
    ch.receiveBuffer.push_back(std::move(payload));
    ch.totalReceived += 1;
    return true;
}

inline bool onMessageReceived(Channel& ch, SequenceNum seq, Bytes payload, MonoTime now) {
    // Enforce the channel's size contract on RECEIVE too, not just send: a peer (or a reassembled
    // fragment stream) can present a payload far larger than maxMessageSize, and buffering it would
    // bypass the cap the channel declared. A legitimately-sent message is always within the bound.
    if (static_cast<int>(payload.size()) > ch.config.maxMessageSize) { ch.totalDropped += 1; return true; }   // never acceptable
    switch (ch.config.deliveryMode) {
        case DeliveryMode::Unreliable:
            // Nothing retransmits an unreliable message, so a refusal here is a real drop, not backpressure.
            if (!pushReceived(ch, std::move(payload))) { ch.totalDropped += 1; }
            return true;
        case DeliveryMode::UnreliableSequenced:
            if (!newer(seq, ch.remoteSeq)) { ch.totalDropped += 1; return true; }   // superseded by a newer one
            if (!pushReceived(ch, std::move(payload))) { ch.totalDropped += 1; return true; }
            ch.remoteSeq = seq;
            return true;
        case DeliveryMode::ReliableUnordered:
            if (rbExists(ch.recvDedup, seq)) { ch.totalDuplicate += 1; return true; }   // already delivered
            if (!pushReceived(ch, std::move(payload))) { ch.totalRefused += 1; return false; }
            rbInsert(ch.recvDedup, seq);   // recorded only once it is genuinely delivered
            return true;
        case DeliveryMode::ReliableOrdered:
            // Three cases, and the third is the one that matters: a sequence OLDER than the one we are
            // waiting for has already been delivered (or flushed past), so it is a duplicate. Buffering
            // it instead would redeliver it on the next timeout flush AND drag orderedExpected backward.
            if      (seq == ch.orderedExpected)      return deliverOrdered(ch, std::move(payload));
            else if (newer(seq, ch.orderedExpected)) return bufferOrdered(ch, seq, std::move(payload), now);
            ch.totalDuplicate += 1;
            return true;
        case DeliveryMode::ReliableSequenced:
            if (!newer(seq, ch.remoteSeq)) { ch.totalDuplicate += 1; return true; }   // superseded or a repeat
            if (!pushReceived(ch, std::move(payload))) { ch.totalRefused += 1; return false; }
            ch.remoteSeq = seq;
            return true;
    }
    return true;
}

// Deliver the message the ordering window is waiting for, then drain whatever it unblocks. The window
// advances only once the message is actually in the receive buffer -- advancing past a refused message
// would lose it and desync every sequence after it.
inline bool deliverOrdered(Channel& ch, Bytes&& payload) {
    if (!pushReceived(ch, std::move(payload))) { ch.totalRefused += 1; return false; }
    ch.orderedExpected = next(ch.orderedExpected);
    flushOrderedBuffer(ch);
    return true;
}
inline bool bufferOrdered(Channel& ch, SequenceNum seq, Bytes&& payload, MonoTime now) {
    // A sequence already waiting in the buffer is a duplicate (a network dup, or a batch retransmit
    // re-carrying a message that did land): ack it and keep the original entry. Re-inserting would
    // reset its flush-timeout clock, and at the cap it would refuse -- and block the ack of -- a
    // message the channel already holds.
    if (ch.orderedBuffer.find(seq) != ch.orderedBuffer.end()) { ch.totalDuplicate += 1; return true; }
    if (static_cast<int>(ch.orderedBuffer.size()) >= ch.config.maxOrderedBufferSize) { ch.totalRefused += 1; return false; }
    ch.orderedBuffer[seq] = { std::move(payload), now };
    return true;
}
inline void flushOrderedBuffer(Channel& ch) {
    for (;;) {
        auto it = ch.orderedBuffer.find(ch.orderedExpected);
        if (it == ch.orderedBuffer.end()) break;
        if (!pushReceived(ch, std::move(it->second.first))) break;   // receive buffer full: leave it buffered, retry next drain
        ch.orderedBuffer.erase(it);
        ch.orderedExpected = next(ch.orderedExpected);
    }
}

// --- flow control ---
// Free slots: the credit this channel advertises to its sender. Counted in MESSAGES, because that is
// the unit the buffer caps are in.
//
// An ordered channel has a SECOND buffer and it has to be part of the answer. While a gap is open,
// everything arriving behind it goes to the reorder buffer, bufferOrdered refuses at
// maxOrderedBufferSize, and the refused packets go unacked -- so a credit counting only the receive
// buffer advertises room the receiver does not have. The sender then retransmits into a buffer that
// stays full until orderedBufferTimeout, which outlasts a retry budget, and the messages behind the
// gap are destroyed instead of delayed.
//
// The OCCUPANCY is what counts, not the cap: with the reorder buffer empty every arrival is delivered
// straight through and the receive buffer is the only limit. The floor of one slot is what keeps a
// full reorder buffer backpressure rather than deadlock -- the message that FILLS the gap is delivered
// straight through and never touches the reorder buffer, so the window must never close on the one
// message that would drain it, and the sender retransmits oldest-first, which is exactly that message.
inline int channelFreeReceiveSlots(const Channel& ch) noexcept {
    const int used = static_cast<int>(ch.receiveBuffer.size());
    const int free = used >= ch.config.maxReceiveBufferSize ? 0 : ch.config.maxReceiveBufferSize - used;
    if (free == 0 || !isOrdered(ch.config.deliveryMode)) return free;
    const int buffered = static_cast<int>(ch.orderedBuffer.size());
    if (buffered == 0) return free;
    const int reordFree = buffered >= ch.config.maxOrderedBufferSize ? 0 : ch.config.maxOrderedBufferSize - buffered;
    return std::max(1, std::min(free, reordFree));
}
// Reliable messages sent and not yet acked. Each one may still need a slot at the receiver, so this
// is what the peer's advertised credit is spent against. Unsent messages (retryCount 0) are still
// queued locally and have cost the receiver nothing yet.
inline int channelUnackedCount(const Channel& ch) noexcept {
    int n = 0;
    for (const auto& kv : ch.sendBuffer)
        if (!kv.second.acked && kv.second.retryCount > 0) ++n;
    return n;
}

// Has this fragment been acked? Only meaningful for a message the sender recorded as fragmented; the
// send path reads it to retransmit just the fragments still missing.
inline bool fragmentAcked(const ChannelMessage& msg, std::uint8_t fragIndex) noexcept {
    return (msg.fragAckBits[fragIndex >> 6] & (std::uint64_t{ 1 } << (fragIndex & 63))) != 0;
}

// Ack one fragment of a message (fragIndex 0 for an unfragmented message). A fragmented message is
// only fully acked -- and so stops retransmitting -- once every fragment has been acked.
inline void acknowledgeMessage(Channel& ch, SequenceNum seq, std::uint8_t fragIndex = 0) {
    auto it = ch.sendBuffer.find(seq);
    if (it == ch.sendBuffer.end()) return;
    ChannelMessage& m = it->second;
    if (m.fragmentCount <= 1) { m.acked = true; return; }
    m.fragAckBits[fragIndex >> 6] |= (std::uint64_t{ 1 } << (fragIndex & 63));   // dedups a retransmitted fragment's repeat ack
    int seen = 0;
    for (const std::uint64_t w : m.fragAckBits) seen += std::popcount(w);
    if (seen >= m.fragmentCount) m.acked = true;
}
inline std::vector<Bytes> channelReceive(Channel& ch) {
    std::vector<Bytes> out = std::move(ch.receiveBuffer);
    ch.receiveBuffer.clear();
    return out;
}

// --- maintenance ---
inline void cleanupAcked(Channel& ch) {
    for (auto it = ch.sendBuffer.begin(); it != ch.sendBuffer.end(); )
        if (it->second.acked) it = ch.sendBuffer.erase(it);
        else                  ++it;
}
// Give up on a gap that never filled: deliver what has been waiting past the timeout and resume
// ordering after it. The window only ever moves FORWARD -- a flush must never rewind orderedExpected,
// or every already-delivered sequence in between becomes deliverable a second time and the messages
// after it stall until they time out too. Whatever the flush skipped past is a permanent gap.
inline void flushTimedOutOrdered(Channel& ch, MonoTime now) {
    if (!isOrdered(ch.config.deliveryMode) || ch.orderedBuffer.empty()) return;
    const double timeout = ch.config.orderedBufferTimeout;
    SequenceNum maxFlushed{};
    bool        anyFlushed = false;
    for (auto it = ch.orderedBuffer.begin(); it != ch.orderedBuffer.end(); ) {
        if (elapsedMs(it->second.second, now) >= timeout) {
            if (!pushReceived(ch, std::move(it->second.first))) { ++it; continue; }   // no room: keep it buffered for the next pass
            if (!anyFlushed || newer(it->first, maxFlushed)) { maxFlushed = it->first; anyFlushed = true; }   // wrap-aware max, not raw <
            it = ch.orderedBuffer.erase(it);
        } else {
            ++it;
        }
    }
    if (!anyFlushed) return;
    const SequenceNum resumeAt = next(maxFlushed);
    if (newer(resumeAt, ch.orderedExpected)) ch.orderedExpected = resumeAt;   // forward only, wrap-aware
    flushOrderedBuffer(ch);   // the flush may have exposed a buffered successor -- deliver it now, not next tick
}
inline void channelUpdate(Channel& ch, MonoTime now) { cleanupAcked(ch); flushTimedOutOrdered(ch, now); }

inline void resetChannel(Channel& ch) {
    ch.localSeq = {};
    ch.remoteSeq = {};
    ch.sendBuffer.clear();
    ch.receiveBuffer.clear();
    ch.orderedBuffer.clear();
    ch.orderedExpected = {};
    ch.recvDedup       = ReceivedBuffer{};
    ch.totalSent = ch.totalReceived = ch.totalRetransmits = 0;
    ch.totalDropped = ch.totalDuplicate = ch.totalRefused = ch.totalReliableDropped = 0;
}

} // namespace aether
