// Channel reliability: pin the per-message fragment-ack mask. A fragmented reliable message must
// stay un-acked until EVERY fragment is acked, dedup a repeated fragment ack, and an unfragmented
// message must ack on the first acknowledge. Covered only indirectly by the e2e loss test; this
// pins it deterministically. Data-first: plain Channel struct + free functions.
#include "aether/channel.hpp"

#include <cassert>
#include <cstdio>

int main() {
    // A reliable message split into N>1 fragments acks only when the LAST fragment lands. Acking a
    // strict subset (and any order) leaves it un-acked; the remaining fragments flip it exactly on
    // the last one.
    {
        constexpr std::uint8_t N = 5;
        aether::Channel ch = aether::newChannel(aether::ChannelId{ 0 }, aether::reliableOrderedChannel());
        const auto sr = aether::channelSend(ch, aether::Bytes{ 1, 2, 3 }, aether::MonoTime{ 0 });
        assert(sr.error == aether::ChannelError::None);
        aether::commitOutgoingMessage(ch, sr.seq);            // in flight (reliable, retryCount 1)
        aether::setMessageFragmentCount(ch, sr.seq, N);       // recorded as 5 fragments

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
        aether::commitOutgoingMessage(ch, sr.seq);
        aether::setMessageFragmentCount(ch, sr.seq, N);

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
        aether::commitOutgoingMessage(ch, sr.seq);            // fragmentCount stays 0 (sent in one packet)
        assert(!ch.sendBuffer.at(sr.seq).acked);
        aether::acknowledgeMessage(ch, sr.seq);              // single ack flips it
        assert(ch.sendBuffer.at(sr.seq).acked);
    }

    std::printf("aether channel fragment-ack OK: N>1 acks only on the last fragment, dup acks idempotent, unfragmented acks on first\n");
    return 0;
}
