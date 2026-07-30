// Channel reliability. Pins the per-message fragment-ack mask, and the DUPLICATE handling on receive --
// a retransmit carries a message the peer may already have delivered (its ack was lost), and every
// reliable mode has to recognize that. Data-first: plain Channel struct + free functions.
#include "aether/channel.hpp"

#include <cassert>
#include <cstdio>

int main() {
    // A duplicate of an already-DELIVERED sequence on an ordered channel must be dropped, not buffered.
    // Buffering it meant the ordered-buffer timeout later redelivered it AND dragged orderedExpected
    // backward past every sequence already delivered, so the messages after it stalled behind a window
    // that had rewound -- one lost ack could wedge a channel for as long as traffic kept flowing.
    {
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        for (std::uint16_t s = 0; s < 3; ++s)
            aether::onMessageReceived(ch, aether::SequenceNum{ s }, aether::Bytes{ static_cast<std::uint8_t>(s) }, aether::MonoTime{ 0 });
        assert(aether::channelReceive(ch).size() == 3);
        assert(ch.orderedExpected == aether::SequenceNum{ 3 });

        const bool acked = aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, aether::Bytes{ 0 }, aether::MonoTime{ 1000000 });
        assert(ch.orderedBuffer.empty());                     // recognized as a duplicate, never buffered
        assert(ch.totalDuplicate == 1 && ch.totalDropped == 0 && ch.totalRefused == 0);
        assert(acked);   // and it must still be ACKED: the peer resent it precisely because it saw no ack

        aether::channelUpdate(ch, aether::MonoTime{ 6000000000ull });   // 6s: past the 5s ordered timeout
        assert(aether::channelReceive(ch).empty());           // nothing to redeliver
        assert(ch.orderedExpected == aether::SequenceNum{ 3 });         // window did NOT rewind

        // ...so the next real messages still deliver immediately.
        aether::onMessageReceived(ch, aether::SequenceNum{ 3 }, aether::Bytes{ 3 }, aether::MonoTime{ 6100000000ull });
        aether::onMessageReceived(ch, aether::SequenceNum{ 4 }, aether::Bytes{ 4 }, aether::MonoTime{ 6100000000ull });
        assert(aether::channelReceive(ch).size() == 2);
    }

    // A timeout flush gives up on a gap, so it must only ever move the window FORWARD, and must deliver
    // any buffered successor it just exposed rather than leaving it for the next tick.
    {
        aether::ChannelConfig cfg;
        cfg.deliveryMode         = aether::DeliveryMode::ReliableOrdered;
        cfg.orderedBufferTimeout = 100.0;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);

        aether::onMessageReceived(ch, aether::SequenceNum{ 2 }, aether::Bytes{ 2 }, aether::MonoTime{ 0 });              // waits on the 0,1 gap
        aether::onMessageReceived(ch, aether::SequenceNum{ 3 }, aether::Bytes{ 3 }, aether::MonoTime{ 190000000ull });   // arrives later, still fresh
        aether::channelUpdate(ch, aether::MonoTime{ 200000000ull });   // 200ms: seq 2 timed out, seq 3 has not

        const auto got = aether::channelReceive(ch);
        assert(got.size() == 2 && got[0] == aether::Bytes{ 2 } && got[1] == aether::Bytes{ 3 });   // 3 followed 2 out immediately
        assert(ch.orderedExpected == aether::SequenceNum{ 4 });
        assert(ch.orderedBuffer.empty());
    }

    // ReliableUnordered has no ordering state to infer duplicates from, so it dedups explicitly: a
    // retransmitted message must be delivered exactly once, not once per copy that arrives.
    {
        aether::ChannelConfig cfg;
        cfg.deliveryMode = aether::DeliveryMode::ReliableUnordered;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);

        aether::onMessageReceived(ch, aether::SequenceNum{ 7 }, aether::Bytes{ 0xAA }, aether::MonoTime{ 0 });
        aether::onMessageReceived(ch, aether::SequenceNum{ 7 }, aether::Bytes{ 0xAA }, aether::MonoTime{ 1000000 });   // retransmit
        assert(aether::channelReceive(ch).size() == 1);
        assert(ch.totalDuplicate == 1 && ch.totalReceived == 1 && ch.totalDropped == 0);

        // Out-of-order first arrivals are still both delivered -- this mode promises delivery, not order.
        aether::onMessageReceived(ch, aether::SequenceNum{ 9 }, aether::Bytes{ 0x09 }, aether::MonoTime{ 2000000 });
        aether::onMessageReceived(ch, aether::SequenceNum{ 8 }, aether::Bytes{ 0x08 }, aether::MonoTime{ 3000000 });
        assert(aether::channelReceive(ch).size() == 2);
        aether::onMessageReceived(ch, aether::SequenceNum{ 8 }, aether::Bytes{ 0x08 }, aether::MonoTime{ 4000000 });   // dup of the late one
        assert(aether::channelReceive(ch).empty());
    }

    // A reliable message split into N>1 fragments acks only when the LAST fragment lands. Acking a
    // strict subset (and any order) leaves it un-acked; the remaining fragments flip it exactly on
    // the last one.
    {
        constexpr std::uint8_t N = 5;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 1, 2, 3 }, aether::MonoTime{ 0 });
        assert(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });   // in flight (reliable, retryCount 1)
        ch.sendBuffer.at(sr.seq).fragmentCount = N;                          // recorded as 5 fragments

        // strict subset, out of order: 4 of 5 acked -> still not acked
        aether::acknowledgeMessage(ch, sr.seq, 3);
        aether::acknowledgeMessage(ch, sr.seq, 0);
        aether::acknowledgeMessage(ch, sr.seq, 4);
        aether::acknowledgeMessage(ch, sr.seq, 1);
        assert(!ch.sendBuffer.at(sr.seq).acked);              // 4/5 -> incomplete

        aether::acknowledgeMessage(ch, sr.seq, 2);            // the 5th and last fragment
        assert(ch.sendBuffer.at(sr.seq).acked);              // all fragments in -> acked
    }

    // A duplicate fragment ack (same index twice) is idempotent: it does not double-count, so it
    // cannot flip the message acked before the genuinely-last fragment arrives.
    {
        constexpr std::uint8_t N = 5;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 7 }, aether::MonoTime{ 0 });
        assert(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });
        ch.sendBuffer.at(sr.seq).fragmentCount = N;

        aether::acknowledgeMessage(ch, sr.seq, 0);
        aether::acknowledgeMessage(ch, sr.seq, 0);            // repeat
        aether::acknowledgeMessage(ch, sr.seq, 0);            // repeat again
        aether::acknowledgeMessage(ch, sr.seq, 1);
        aether::acknowledgeMessage(ch, sr.seq, 2);
        aether::acknowledgeMessage(ch, sr.seq, 3);
        assert(!ch.sendBuffer.at(sr.seq).acked);              // 4 distinct (0..3), dups didn't count -> not acked
        aether::acknowledgeMessage(ch, sr.seq, 4);            // the actual last distinct fragment
        assert(ch.sendBuffer.at(sr.seq).acked);
    }

    // fragmentCount <= 1 (an unfragmented message) acks immediately on the first acknowledge.
    {
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 9 }, aether::MonoTime{ 0 });
        assert(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq, aether::MonoTime{ 0 });   // fragmentCount stays 0 (sent in one packet)
        assert(!ch.sendBuffer.at(sr.seq).acked);
        aether::acknowledgeMessage(ch, sr.seq);              // single ack flips it
        assert(ch.sendBuffer.at(sr.seq).acked);
    }

    // A duplicate of a sequence already WAITING in the reorder buffer is acked, not re-buffered or
    // refused. At the cap the old behavior refused it -- blocking the ack of a message the channel
    // already held, so the sender kept resending into a permanent refusal -- and below the cap it
    // re-inserted, resetting the entry's flush-timeout clock.
    {
        aether::ChannelConfig cfg = aether::reliableOrderedChannel();
        cfg.maxOrderedBufferSize  = 2;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, cfg);

        aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, aether::Bytes{ 1 }, aether::MonoTime{ 0 });   // waits on 0
        aether::onMessageReceived(ch, aether::SequenceNum{ 2 }, aether::Bytes{ 2 }, aether::MonoTime{ 0 });   // buffer now full
        assert(ch.orderedBuffer.size() == 2);

        const bool acked = aether::onMessageReceived(ch, aether::SequenceNum{ 1 }, aether::Bytes{ 1 }, aether::MonoTime{ 500000000ull });
        assert(acked);                                            // already held -> ack it, retransmit helps nothing
        assert(ch.totalDuplicate == 1 && ch.totalRefused == 0);
        assert(ch.orderedBuffer.size() == 2);
        assert(ch.orderedBuffer.at(aether::SequenceNum{ 1 }).second.ns == 0);   // original clock kept

        aether::onMessageReceived(ch, aether::SequenceNum{ 0 }, aether::Bytes{ 0 }, aether::MonoTime{ 1000000 });   // gap fills
        assert(aether::channelReceive(ch).size() == 3);           // 0,1,2 delivered; the dup delivered once
    }

    std::printf("aether channel OK: duplicate receives dropped (ordered window never rewinds, unordered dedups); "
                "fragment-ack N>1 acks only on the last fragment, dup acks idempotent\n");
    return 0;
}
