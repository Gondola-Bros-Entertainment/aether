#include "check.hpp"
// Channel reliability. Pins the per-message fragment-ack mask, and the DUPLICATE handling on receive --
// a retransmit carries a message the peer may already have delivered (its ack was lost), and every
// reliable mode has to recognize that. Data-first: plain Channel struct + free functions.
#include "aether/channel.hpp"

#include <cstdio>

using aether::test::require;

int main() {
    // Sequence zero is a real first message; reset restores the no-message-received state.
    for (auto mode : {aether::DeliveryMode::UnreliableSequenced, aether::DeliveryMode::ReliableSequenced}) {
        aether::ChannelConfig cfg; cfg.deliveryMode = mode;
        auto ch = aether::newChannel(aether::ChannelId{0}, cfg);
        for (int reset = 0; reset < 2; ++reset) {
            require(aether::onMessageReceived(ch, aether::SequenceNum{0}, aether::Bytes{42}, {}));
            require(aether::channelReceive(ch) == std::vector<aether::Bytes>{{42}});
            aether::onMessageReceived(ch, aether::SequenceNum{0}, aether::Bytes{42}, {});
            require(aether::channelReceive(ch).empty());
            aether::resetChannel(ch);
        }
    }
    // Duplicates remain duplicates beyond the packet ring and across message sequence wrap.
    {
        aether::ChannelConfig cfg; cfg.deliveryMode = aether::DeliveryMode::ReliableUnordered;
        auto ch = aether::newChannel(aether::ChannelId{0}, cfg);
        for (unsigned i = 0; i < 66000; ++i) {
            const aether::SequenceNum seq{static_cast<std::uint16_t>(i)};
            require(aether::onMessageReceived(ch, seq, aether::Bytes{42}, {}));
            require(aether::channelReceive(ch).size() == 1);
            if (i >= 256) {
                const aether::SequenceNum old{static_cast<std::uint16_t>(i - 256)};
                require(aether::onMessageReceived(ch, old, aether::Bytes{42}, {}));
                require(aether::channelReceive(ch).empty());
            }
        }
    }
    // A long-lived missing ACK prevents sequence reuse even if newer entries are promptly retired.
    for (std::uint16_t start : {std::uint16_t{0}, std::uint16_t{65000}}) {
        auto cfg = aether::reliableOrderedChannel();
        auto tx = aether::newChannel(aether::ChannelId{0}, cfg);
        tx.localSeq = aether::SequenceNum{start};
        auto first = aether::channelSend(tx, {42}, {});
        require(first.error == aether::ChannelError::None);
        for (int i = 1; i < aether::maxMessageBufferSize; ++i) {
            const auto sent = aether::channelSend(tx, {42}, {});
            require(sent.error == aether::ChannelError::None);
            aether::acknowledgeMessage(tx, sent.seq);
        }
        require(aether::channelSend(tx, {42}, {}).error == aether::ChannelError::BufferFull);
        aether::acknowledgeMessage(tx, first.seq);
        require(aether::channelSend(tx, {42}, {}).error == aether::ChannelError::None);
    }
    // Out-of-order evidence never evicts a hole: refuse the next window, then advance when zero arrives.
    {
        aether::ChannelConfig cfg; cfg.deliveryMode = aether::DeliveryMode::ReliableUnordered;
        auto ch = aether::newChannel(aether::ChannelId{0}, cfg);
        for (unsigned i = 1; i < aether::maxMessageBufferSize; ++i) {
            require(aether::onMessageReceived(ch, aether::SequenceNum{static_cast<std::uint16_t>(i)}, {42}, {}));
            aether::channelReceive(ch);
        }
        require(!aether::onMessageReceived(ch, aether::SequenceNum{aether::maxMessageBufferSize}, {42}, {}));
        require(aether::onMessageReceived(ch, aether::SequenceNum{1}, {42}, {}));
        require(aether::channelReceive(ch).empty());
        require(aether::onMessageReceived(ch, aether::SequenceNum{0}, {42}, {}));
        require(ch.unorderedExpected.value == aether::maxMessageBufferSize);
        require(aether::channelReceive(ch).size() == 1);
        require(aether::onMessageReceived(ch, aether::SequenceNum{aether::maxMessageBufferSize}, {42}, {}));
        require(aether::channelReceive(ch).size() == 1);
    }

    // A duplicate of an already-DELIVERED sequence on an ordered channel must be dropped, not buffered.
    // Buffering it would let the ordered-buffer timeout redeliver it AND drag orderedExpected backward
    // past every sequence already delivered, so the messages after it would stall behind a rewound
    // window -- one lost ack could wedge a channel for as long as traffic kept flowing.
    {
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        for (std::uint16_t s = 0; s < 3; ++s)
            aether::onMessageReceived(ch, aether::SequenceNum{ s }, aether::Bytes{ static_cast<std::uint8_t>(s) }, aether::MonoTime{ 0 });
        require(aether::channelReceive(ch).size() == 3);
        require(ch.orderedExpected == aether::SequenceNum{ 3 });

        const bool acked = aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, aether::Bytes{ 0 }, aether::MonoTime{ 1000000 });
        require(ch.orderedBuffer.empty());                    // recognized as a duplicate, never buffered
        require(ch.totalDuplicate == 1 && ch.totalDropped == 0 && ch.totalRefused == 0);
        require(acked);   // and it must still be ACKED: the peer resent it precisely because it saw no ack

        aether::channelUpdate(ch, aether::MonoTime{ 6000000000ull });   // 6s: past the 5s ordered timeout
        require(aether::channelReceive(ch).empty());          // nothing to redeliver
        require(ch.orderedExpected == aether::SequenceNum{ 3 });        // window did NOT rewind

        // ...so the next real messages still deliver immediately.
        aether::onMessageReceived(ch, aether::SequenceNum{ 3 }, aether::Bytes{ 3 }, aether::MonoTime{ 6100000000ull });
        aether::onMessageReceived(ch, aether::SequenceNum{ 4 }, aether::Bytes{ 4 }, aether::MonoTime{ 6100000000ull });
        require(aether::channelReceive(ch).size() == 2);
    }

    // An explicit gap deadline terminates strict ordering; it must never publish later commands.
    {
        aether::ChannelConfig cfg;
        cfg.deliveryMode         = aether::DeliveryMode::ReliableOrdered;
        cfg.orderedBufferTimeout = 100.0;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);

        aether::onMessageReceived(ch, aether::SequenceNum{ 2 }, aether::Bytes{ 2 }, aether::MonoTime{ 0 });              // waits on the 0,1 gap
        aether::onMessageReceived(ch, aether::SequenceNum{ 3 }, aether::Bytes{ 3 }, aether::MonoTime{ 190000000ull });   // arrives later, still fresh
        aether::channelUpdate(ch, aether::MonoTime{ 200000000ull });   // 200ms: seq 2 timed out, seq 3 has not

        const auto got = aether::channelReceive(ch);
        require(got.empty());
        require(ch.failure == aether::ChannelFailure::OrderedGapTimeout);
        require(ch.orderedExpected == aether::SequenceNum{ 0 });
        require(ch.orderedBuffer.size() == 2); // Retained until explicit connection termination/reset.
        require(!aether::onMessageReceived(ch, aether::SequenceNum{0}, {0}, {}));
        require(aether::channelSend(ch, {0}, {}).error == aether::ChannelError::DeliveryFailed);
    }

    // ReliableUnordered has no ordering state to infer duplicates from, so it dedups explicitly: a
    // retransmitted message must be delivered exactly once, not once per copy that arrives.
    {
        aether::ChannelConfig cfg;
        cfg.deliveryMode = aether::DeliveryMode::ReliableUnordered;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);

        aether::onMessageReceived(ch, aether::SequenceNum{ 7 }, aether::Bytes{ 0xAA }, aether::MonoTime{ 0 });
        aether::onMessageReceived(ch, aether::SequenceNum{ 7 }, aether::Bytes{ 0xAA }, aether::MonoTime{ 1000000 });   // retransmit
        require(aether::channelReceive(ch).size() == 1);
        require(ch.totalDuplicate == 1 && ch.totalReceived == 1 && ch.totalDropped == 0);

        // Out-of-order first arrivals are still both delivered -- this mode promises delivery, not order.
        aether::onMessageReceived(ch, aether::SequenceNum{ 9 }, aether::Bytes{ 0x09 }, aether::MonoTime{ 2000000 });
        aether::onMessageReceived(ch, aether::SequenceNum{ 8 }, aether::Bytes{ 0x08 }, aether::MonoTime{ 3000000 });
        require(aether::channelReceive(ch).size() == 2);
        aether::onMessageReceived(ch, aether::SequenceNum{ 8 }, aether::Bytes{ 0x08 }, aether::MonoTime{ 4000000 });   // dup of the late one
        require(aether::channelReceive(ch).empty());
    }

    // A reliable message split into N>1 fragments acks only when the LAST fragment lands. Acking a
    // strict subset (and any order) leaves it un-acked; the remaining fragments flip it exactly on
    // the last one.
    {
        constexpr std::uint8_t N = 5;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 1, 2, 3 }, aether::MonoTime{ 0 });
        require(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });   // in flight (reliable, retryCount 1)
        ch.sendBuffer.at(sr.seq).fragmentCount = N;                          // recorded as 5 fragments

        // strict subset, out of order: 4 of 5 acked -> still not acked
        aether::acknowledgeMessage(ch, sr.seq, 3);
        aether::acknowledgeMessage(ch, sr.seq, 0);
        aether::acknowledgeMessage(ch, sr.seq, 4);
        aether::acknowledgeMessage(ch, sr.seq, 1);
        require(!ch.sendBuffer.at(sr.seq).acked);             // 4/5 -> incomplete

        aether::acknowledgeMessage(ch, sr.seq, 2);            // the 5th and last fragment
        require(ch.sendBuffer.at(sr.seq).acked);             // all fragments in -> acked
    }

    // A duplicate fragment ack (same index twice) is idempotent: it does not double-count, so it
    // cannot flip the message acked before the genuinely-last fragment arrives.
    {
        constexpr std::uint8_t N = 5;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 7 }, aether::MonoTime{ 0 });
        require(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });
        ch.sendBuffer.at(sr.seq).fragmentCount = N;

        aether::acknowledgeMessage(ch, sr.seq, 0);
        aether::acknowledgeMessage(ch, sr.seq, 0);            // repeat
        aether::acknowledgeMessage(ch, sr.seq, 0);            // repeat again
        aether::acknowledgeMessage(ch, sr.seq, 1);
        aether::acknowledgeMessage(ch, sr.seq, 2);
        aether::acknowledgeMessage(ch, sr.seq, 3);
        require(!ch.sendBuffer.at(sr.seq).acked);             // 4 distinct (0..3), dups didn't count -> not acked
        aether::acknowledgeMessage(ch, sr.seq, 4);            // the actual last distinct fragment
        require(ch.sendBuffer.at(sr.seq).acked);
    }

    // fragmentCount <= 1 (an unfragmented message) acks immediately on the first acknowledge.
    {
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 9 }, aether::MonoTime{ 0 });
        require(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });   // fragmentCount stays 0 (sent in one packet)
        require(!ch.sendBuffer.at(sr.seq).acked);
        aether::acknowledgeMessage(ch, sr.seq);              // single ack flips it
        require(ch.sendBuffer.at(sr.seq).acked);
    }

    // A duplicate of a sequence already WAITING in the reorder buffer is acked, not re-buffered or
    // refused. Refusing it at the cap would block the ack of a message the channel already holds, so
    // the sender would keep resending into a permanent refusal; re-inserting it below the cap would
    // reset the entry's flush-timeout clock.
    {
        aether::ChannelConfig cfg = aether::reliableOrderedChannel();
        cfg.maxOrderedBufferSize  = 2;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);

        aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, aether::Bytes{ 1 }, aether::MonoTime{ 0 });   // waits on 0
        aether::onMessageReceived(ch, aether::SequenceNum{ 2 }, aether::Bytes{ 2 }, aether::MonoTime{ 0 });   // buffer now full
        require(ch.orderedBuffer.size() == 2);

        const bool acked = aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, aether::Bytes{ 1 }, aether::MonoTime{ 500000000ull });
        require(acked);                                           // already held -> ack it, retransmit helps nothing
        require(ch.totalDuplicate == 1 && ch.totalRefused == 0);
        require(ch.orderedBuffer.size() == 2);
        require(ch.orderedBuffer.at(aether::SequenceNum{ 1 }).second.ns == 0);   // original clock kept

        aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, aether::Bytes{ 0 }, aether::MonoTime{ 1000000 });   // gap fills
        require(aether::channelReceive(ch).size() == 3);          // 0,1,2 delivered; the dup delivered once
    }

    // A reliable message whose retry budget runs out is DROPPED, and every attempt has to wait out its
    // own backoff first. With a flat RTO the whole budget is spent inside a fraction of a second, so a
    // link that blinks erases the message while the connection is still nowhere near its own timeout --
    // and the drop is recorded as a BROKEN GUARANTEE, not as generic "dropped data", because that is
    // the only thing that distinguishes it from an unreliable drop the contract allows.
    {
        aether::ChannelConfig cfg = aether::reliableOrderedChannel();
        cfg.maxReliableRetries    = 3;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);
        const auto sr = aether::channelSend(ch, aether::Bytes{ 1 }, aether::MonoTime{ 0 });
        require(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });   // in flight, retryCount 1

        // Nothing ever acks it. Poll every 10ms; each attempt has to wait out ITS backoff (50, 100, 200).
        std::uint64_t nowMs = 0;
        int           attempts = 0;
        for (int pass = 0; pass < 200 && !ch.failure; ++pass) {
            const auto cands = aether::getRetransmitMessages(ch, aether::MonoTime{ nowMs * 1000000 }, 50.0);
            if (cands.empty()) { nowMs += 10; continue; }
            ++attempts;
            aether::commitRetransmit(ch, sr.seq, aether::MonoTime{ nowMs * 1000000 });   // hoisted: it mutates send state
        }
        require(ch.failure == aether::ChannelFailure::RetryLimitExceeded);
        require(ch.sendBuffer.size() == 1); // Failed state retains the message until reset.
        require(attempts == cfg.maxReliableRetries);          // ...after exactly that many attempts
        require(nowMs >= 50 + 100 + 200 + 400); // Includes the final transmission's ACK deadline.
        require(ch.totalDropped == 1);
        require(ch.totalReliableDropped == 1);                // the guarantee failed, and it is visible
    }

    // The advertised credit has to reflect the REORDER buffer's occupancy. While a gap is open every
    // later message queues there, bufferOrdered refuses at maxOrderedBufferSize, and a refused packet is
    // left unacked -- so a credit counting only the receive buffer tells the sender to keep pushing into
    // a buffer that stays full for orderedBufferTimeout, far longer than any retry budget lasts.
    {
        aether::ChannelConfig cfg = aether::reliableOrderedChannel();
        cfg.maxOrderedBufferSize  = 4;
        cfg.maxReceiveBufferSize  = 8192;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);
        require(aether::channelFreeReceiveSlots(ch) == 8192);   // no gap: the receive buffer is the only limit

        for (std::uint16_t s = 1; s <= 4; ++s)                 // seq 0 never arrives; 1..4 pile up behind it
            aether::onMessageReceived(ch, aether::SequenceNum{ s }, aether::Bytes{ static_cast<std::uint8_t>(s) },
                                      aether::MonoTime{ 0 });
        require(ch.orderedBuffer.size() == 4);
        require(aether::channelFreeReceiveSlots(ch) == 1);     // the credit SEES the reorder buffer now

        const bool accepted = aether::onMessageReceived(ch, aether::SequenceNum{ 5 }, aether::Bytes{ 5 }, aether::MonoTime{ 0 });
        require(!accepted && ch.totalRefused == 1);            // ...and the refusal it was predicting happens

        // The one-slot floor is what makes this backpressure and not deadlock: the message that FILLS
        // the gap is delivered straight through, so the window must never close on it.
        const bool filled = aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, aether::Bytes{ 0 }, aether::MonoTime{ 0 });
        require(filled);
        require(ch.orderedBuffer.empty());                     // 0 unblocked 1..4
        require(aether::channelReceive(ch).size() == 5);
        require(aether::channelFreeReceiveSlots(ch) == 8192);
    }

    // The send buffer is a std::map keyed on the RAW 16-bit sequence, so at the wrap its own order is
    // not send order: with 65533..65535,0..2 queued it walks 0,1,2,65533,65534,65535 and begin() is the
    // NEWEST message. Three operations mean "oldest" and all three read that order.
    {
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        ch.localSeq = aether::SequenceNum{ 65533 };
        for (int i = 0; i < 6; ++i) {
            const auto r = aether::channelSend(ch, aether::Bytes{ static_cast<std::uint8_t>(i) }, aether::MonoTime{ 0 });
            require(r.error == aether::ChannelError::None);
        }
        require(ch.sendBuffer.begin()->first == aether::SequenceNum{ 0 });   // the map's first key is the NEWEST run

        const std::uint16_t order[] = { 65533, 65534, 65535, 0, 1, 2 };
        for (const std::uint16_t want : order) {
            const aether::ChannelMessage* m = aether::peekOutgoingMessage(ch);
            require(m && m->sequence == aether::SequenceNum{ want });       // oldest first, across the wrap
            aether::commitOutgoingMessage(ch, m->sequence, aether::MonoTime{ 0 });
        }
        require(!aether::peekOutgoingMessage(ch));

        // ...and the retransmit candidates come back in that same order, which is what the receiver's
        // credit budget in processRetransmissions spends its slots on.
        const auto cands = aether::getRetransmitMessages(ch, aether::MonoTime{ 200ull * 1000000 }, 100.0);
        require(cands.size() == 6);
        for (std::size_t i = 0; i < cands.size(); ++i)
            require(cands[i]->sequence == aether::SequenceNum{ order[i] });
    }

    // ...and an unreliable overflow evicts the OLDEST message, which at the wrap is not begin().
    {
        aether::ChannelConfig cfg = aether::unreliableChannel();
        cfg.messageBufferSize     = 4;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);
        ch.localSeq = aether::SequenceNum{ 65534 };
        for (int i = 0; i < 4; ++i)                                          // holds 65534, 65535, 0, 1
            aether::channelSend(ch, aether::Bytes{ static_cast<std::uint8_t>(i) }, aether::MonoTime{ 0 });
        require(ch.sendBuffer.size() == 4);

        aether::channelSend(ch, aether::Bytes{ 4 }, aether::MonoTime{ 0 });   // full: one has to go
        require(ch.sendBuffer.size() == 4);
        require(ch.sendBuffer.find(aether::SequenceNum{ 65534 }) == ch.sendBuffer.end());   // the oldest went...
        require(ch.sendBuffer.find(aether::SequenceNum{ 0 }) != ch.sendBuffer.end());       // ...not the newest
        require(ch.sendBuffer.find(aether::SequenceNum{ 2 }) != ch.sendBuffer.end());
    }

    std::printf("aether channel OK: duplicate receives dropped (ordered window never rewinds, unordered dedups); "
                "fragment-ack N>1 acks only on the last fragment, dup acks idempotent; retry budget backs off "
                "and its drop is observable; reorder occupancy closes the window; send order is wrap-aware\n");
    return 0;
}
