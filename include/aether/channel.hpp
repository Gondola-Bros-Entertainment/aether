// aether - channel-based delivery with five reliability modes. Each channel owns its sequence
// numbers, its send/receive buffering, and (for ordered mode) a reorder buffer. Data-first: a
// plain Channel struct + free functions.
#pragma once

#include "aether/types.hpp"

#include <map>
#include <optional>
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
inline bool isReliable(DeliveryMode m)  { return m != DeliveryMode::Unreliable && m != DeliveryMode::UnreliableSequenced; }
inline bool isSequenced(DeliveryMode m) { return m == DeliveryMode::UnreliableSequenced || m == DeliveryMode::ReliableSequenced; }
inline bool isOrdered(DeliveryMode m)   { return m == DeliveryMode::ReliableOrdered; }

struct ChannelConfig {
    DeliveryMode deliveryMode         = DeliveryMode::ReliableOrdered;
    int          maxMessageSize       = 1024;
    int          messageBufferSize    = 256;
    bool         blockOnFull          = false;
    double       orderedBufferTimeout = 5000.0;
    int          maxOrderedBufferSize = 64;
    int          maxReliableRetries   = 10;
    std::uint8_t priority             = 0;
};
inline ChannelConfig unreliableChannel()        { return { .deliveryMode = DeliveryMode::Unreliable        }; }
inline ChannelConfig reliableOrderedChannel()   { return { .deliveryMode = DeliveryMode::ReliableOrdered   }; }
inline ChannelConfig reliableSequencedChannel() { return { .deliveryMode = DeliveryMode::ReliableSequenced }; }

struct ChannelMessage {
    SequenceNum sequence{};
    Bytes       data;
    MonoTime    sendTime{};
    bool        acked      = false;
    int         retryCount = 0;
    bool        reliable   = false;
};

enum class ChannelError { None, BufferFull, MessageTooLarge };

struct Channel {
    ChannelConfig config{};
    ChannelId     channelId{};
    SequenceNum   localSeq{};
    SequenceNum   remoteSeq{};
    std::map<SequenceNum, ChannelMessage>             sendBuffer;
    std::vector<Bytes>                                receiveBuffer;
    std::vector<SequenceNum>                          pendingAck;
    std::map<SequenceNum, std::pair<Bytes, MonoTime>> orderedBuffer;
    SequenceNum   orderedExpected{};
    std::uint64_t totalSent = 0, totalReceived = 0, totalDropped = 0, totalRetransmits = 0;
};

inline Channel newChannel(ChannelId id, const ChannelConfig& cfg) {
    Channel c;
    c.config = cfg;
    c.channelId = id;
    return c;
}
inline bool channelIsReliable(const Channel& ch) { return isReliable(ch.config.deliveryMode); }

// --- sending ---
struct SendResult { ChannelError error = ChannelError::None; SequenceNum seq{}; };

inline SendResult channelSend(Channel& ch, const Bytes& payload, MonoTime now) {
    if (static_cast<int>(payload.size()) > ch.config.maxMessageSize) return { ChannelError::MessageTooLarge, {} };
    const bool full = static_cast<int>(ch.sendBuffer.size()) >= ch.config.messageBufferSize;
    if (full && ch.config.blockOnFull) return { ChannelError::BufferFull, {} };
    if (full) ch.sendBuffer.erase(ch.sendBuffer.begin());   // drop oldest to make room
    const SequenceNum seq = ch.localSeq;
    ch.sendBuffer[seq] = ChannelMessage{ seq, payload, now, false, 0, isReliable(ch.config.deliveryMode) };
    ch.localSeq = next(ch.localSeq);
    ch.totalSent += 1;
    return { ChannelError::None, seq };
}

// Next message to put on the wire, in sequence order. Reliable msgs stay buffered for
// retransmit; unreliable are removed (fire and forget). nullopt = nothing new to send.
inline std::optional<ChannelMessage> getOutgoingMessage(Channel& ch) {
    while (!ch.sendBuffer.empty()) {
        auto it = ch.sendBuffer.begin();
        ChannelMessage& msg = it->second;
        if (msg.acked) { ch.sendBuffer.erase(it); continue; }
        if (msg.retryCount == 0) {
            const ChannelMessage out = msg;
            if (msg.reliable) msg.retryCount = 1;
            else              ch.sendBuffer.erase(it);
            return out;
        }
        return std::nullopt;   // head already sent, awaiting ack
    }
    return std::nullopt;
}

// Peek the next message to send WITHOUT committing (cleans acked entries off the front).
// Lets the caller check congestion/cwnd before consuming it via commitOutgoingMessage.
inline std::optional<ChannelMessage> peekOutgoingMessage(Channel& ch) {
    while (!ch.sendBuffer.empty()) {
        auto it = ch.sendBuffer.begin();
        if (it->second.acked) { ch.sendBuffer.erase(it); continue; }
        if (it->second.retryCount == 0) return it->second;
        return std::nullopt;   // head already sent, awaiting ack
    }
    return std::nullopt;
}
// Commit the head message returned by peekOutgoingMessage: reliable -> mark sent (retry 1),
// unreliable -> remove (fire and forget). Call only right after a successful peek.
inline void commitOutgoingMessage(Channel& ch) {
    if (ch.sendBuffer.empty()) return;
    auto it = ch.sendBuffer.begin();
    if (it->second.acked || it->second.retryCount != 0) return;
    if (it->second.reliable) it->second.retryCount = 1;
    else                     ch.sendBuffer.erase(it);
}

// Reliable messages whose RTO has elapsed; drops ones past the retry limit.
inline std::vector<ChannelMessage> getRetransmitMessages(Channel& ch, MonoTime now, double rtoMs) {
    std::vector<ChannelMessage> out;
    if (!isReliable(ch.config.deliveryMode)) return out;
    for (auto it = ch.sendBuffer.begin(); it != ch.sendBuffer.end(); ) {
        ChannelMessage& msg = it->second;
        if (msg.acked || msg.retryCount == 0) { ++it; continue; }
        if (msg.retryCount > ch.config.maxReliableRetries) { it = ch.sendBuffer.erase(it); ch.totalDropped += 1; continue; }
        if (elapsedMs(msg.sendTime, now) >= rtoMs) {
            const ChannelMessage resend = msg;
            msg.sendTime = now;
            msg.retryCount += 1;
            ch.totalRetransmits += 1;
            out.push_back(resend);
        }
        ++it;
    }
    return out;
}

// --- receiving ---
inline void deliverOrdered(Channel& ch, const Bytes& payload);
inline void bufferOrdered(Channel& ch, SequenceNum seq, const Bytes& payload, MonoTime now);
inline void flushOrderedBuffer(Channel& ch);

inline void onMessageReceived(Channel& ch, SequenceNum seq, const Bytes& payload, MonoTime now) {
    switch (ch.config.deliveryMode) {
        case DeliveryMode::Unreliable:
            ch.receiveBuffer.push_back(payload);
            ch.totalReceived += 1;
            break;
        case DeliveryMode::UnreliableSequenced:
            if (newer(seq, ch.remoteSeq)) { ch.receiveBuffer.push_back(payload); ch.remoteSeq = seq; ch.totalReceived += 1; }
            else                          { ch.totalDropped += 1; }
            break;
        case DeliveryMode::ReliableUnordered:
            ch.receiveBuffer.push_back(payload);
            ch.pendingAck.push_back(seq);
            ch.totalReceived += 1;
            break;
        case DeliveryMode::ReliableOrdered:
            ch.pendingAck.push_back(seq);
            if (seq == ch.orderedExpected) deliverOrdered(ch, payload);
            else                           bufferOrdered(ch, seq, payload, now);
            break;
        case DeliveryMode::ReliableSequenced:
            ch.pendingAck.push_back(seq);
            if (newer(seq, ch.remoteSeq)) { ch.receiveBuffer.push_back(payload); ch.remoteSeq = seq; ch.totalReceived += 1; }
            else                          { ch.totalDropped += 1; }
            break;
    }
}

inline void deliverOrdered(Channel& ch, const Bytes& payload) {
    ch.receiveBuffer.push_back(payload);
    ch.orderedExpected = next(ch.orderedExpected);
    ch.totalReceived += 1;
    flushOrderedBuffer(ch);
}
inline void bufferOrdered(Channel& ch, SequenceNum seq, const Bytes& payload, MonoTime now) {
    if (static_cast<int>(ch.orderedBuffer.size()) >= ch.config.maxOrderedBufferSize) { ch.totalDropped += 1; return; }
    ch.orderedBuffer[seq] = { payload, now };
}
inline void flushOrderedBuffer(Channel& ch) {
    for (;;) {
        auto it = ch.orderedBuffer.find(ch.orderedExpected);
        if (it == ch.orderedBuffer.end()) break;
        ch.receiveBuffer.push_back(it->second.first);
        ch.orderedBuffer.erase(it);
        ch.orderedExpected = next(ch.orderedExpected);
        ch.totalReceived += 1;
    }
}

inline void acknowledgeMessage(Channel& ch, SequenceNum seq) {
    auto it = ch.sendBuffer.find(seq);
    if (it != ch.sendBuffer.end()) it->second.acked = true;
}

inline std::vector<Bytes> channelReceive(Channel& ch) {
    std::vector<Bytes> out = std::move(ch.receiveBuffer);
    ch.receiveBuffer.clear();
    return out;
}
inline std::vector<SequenceNum> takePendingAcks(Channel& ch) {
    std::vector<SequenceNum> out = std::move(ch.pendingAck);
    ch.pendingAck.clear();
    return out;
}

// --- maintenance ---
inline void cleanupAcked(Channel& ch) {
    for (auto it = ch.sendBuffer.begin(); it != ch.sendBuffer.end(); )
        if (it->second.acked) it = ch.sendBuffer.erase(it);
        else                  ++it;
}
inline void flushTimedOutOrdered(Channel& ch, MonoTime now) {
    if (!isOrdered(ch.config.deliveryMode) || ch.orderedBuffer.empty()) return;
    const double timeout = ch.config.orderedBufferTimeout;
    SequenceNum maxFlushed{};
    bool        anyFlushed = false;
    for (auto it = ch.orderedBuffer.begin(); it != ch.orderedBuffer.end(); ) {
        if (elapsedMs(it->second.second, now) >= timeout) {
            ch.receiveBuffer.push_back(it->second.first);
            ch.totalReceived += 1;
            if (!anyFlushed || maxFlushed < it->first) { maxFlushed = it->first; anyFlushed = true; }
            it = ch.orderedBuffer.erase(it);
        } else {
            ++it;
        }
    }
    if (anyFlushed) ch.orderedExpected = next(maxFlushed);
}
inline void channelUpdate(Channel& ch, MonoTime now) { cleanupAcked(ch); flushTimedOutOrdered(ch, now); }

inline void resetChannel(Channel& ch) {
    ch.localSeq = {};
    ch.remoteSeq = {};
    ch.sendBuffer.clear();
    ch.receiveBuffer.clear();
    ch.pendingAck.clear();
    ch.orderedBuffer.clear();
    ch.orderedExpected = {};
    ch.totalSent = ch.totalReceived = ch.totalDropped = ch.totalRetransmits = 0;
}

} // namespace aether
