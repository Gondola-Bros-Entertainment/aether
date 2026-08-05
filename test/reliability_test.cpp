// Loss-window unit test: pins lossCount() + the sliding 256-bit LossWindow
// (recordLossSample / packetLossFraction). assert() is the check, so build WITHOUT
// NDEBUG. Data-first: plain structs + free functions, no framework.
#include "aether/reliability.hpp"

#include <cassert>
#include <cstdio>

int main() {
    using namespace aether;

    // lossCount over a hand-set window. Exercises every branch of the per-word loop,
    // especially take==64 (the boundary the code special-cases to dodge 1<<64 UB).
    {
        LossWindow w{};

        // empty window: nothing lost regardless of how many positions we count
        assert(lossCount(w, 0)   == 0);
        assert(lossCount(w, 1)   == 0);
        assert(lossCount(w, 256) == 0);

        // n clamps to [0, 256]; negative/zero -> 0, oversized -> 256 positions
        assert(lossCount(w, -5)   == 0);
        assert(lossCount(w, 9999) == 0);

        // mark every bit lost across all four 64-bit words
        for (int i = 0; i < lossWindowSize; ++i) lossSet(w, i, true);
        // n < 64 (the take=n, mask=(1<<n)-1 branch): only the low n bits of word 0
        assert(lossCount(w, 1)  == 1);
        assert(lossCount(w, 13) == 13);
        assert(lossCount(w, 63) == 63);
        // n == 64 exactly: take==64 special-case mask (~0), whole first word, no 1<<64
        assert(lossCount(w, 64) == 64);
        // spilling into the second word: 64 (take==64) + remainder (n<64) branch
        assert(lossCount(w, 65)  == 65);
        assert(lossCount(w, 128) == 128);   // two full words, both via take==64
        assert(lossCount(w, 200) == 200);   // three full words + 8 remainder
        assert(lossCount(w, 256) == 256);   // all four words via take==64

        // a known partial pattern: clear the even indices, every odd index stays lost
        for (int i = 0; i < lossWindowSize; i += 2) lossSet(w, i, false);
        assert(lossCount(w, 256) == 128);   // half of 256 lost
        assert(lossCount(w, 64)  == 32);    // half of the take==64 word lost
        assert(lossCount(w, 10)  == 5);     // 1,3,5,7,9 lost in [0,10)
    }

    // The FIRST packet an endpoint ever sees acknowledges nothing behind it. A default remoteSeq of 0
    // is not a sequence we received, so seeding the ack bitfield from it shifted in a set bit meaning
    // "sequence 0 received" -- if packet 0 was the one lost, the sender saw it acked, marked its
    // reliable messages delivered and never retransmitted them. Silent data loss on the first packet.
    {
        ReliableEndpoint rx{};
        const SequenceNum arrived[] = { SequenceNum{ 1 }, SequenceNum{ 2 } };   // packet 0 was lost
        onPacketsReceived(rx, arrived, 2);
        const auto [ackSeq, ackBits] = getAckInfo(rx);
        assert(ackSeq == SequenceNum{ 2 });
        assert((ackBits & 0x1u) != 0);      // bit 0 == seq 1: genuinely received
        assert((ackBits & 0x2u) == 0);      // bit 1 == seq 0: never received, must NOT be acked

        // ...and the sender agrees: seq 0 stays in flight and is retransmittable.
        ReliableEndpoint tx{};
        const ChannelId ch{ 0 };
        for (std::uint16_t s = 0; s < 3; ++s)
            onPacketSent(tx, SequenceNum{ s }, MonoTime{ 0 }, ch, SequenceNum{ s }, 100);
        const AckResult res = processAcks(tx, ackSeq, ackBits, MonoTime{ 10ull * 1000000 });
        assert(res.acked.size() == 2);                       // seqs 1 and 2 only
        assert(isInFlight(tx, SequenceNum{ 0 }));            // seq 0 is still owed
    }

    // A first packet that IS seq 0 still acks correctly (the common case: markConnected zeroes localSeq).
    {
        ReliableEndpoint rx{};
        const SequenceNum arrived[] = { SequenceNum{ 0 }, SequenceNum{ 1 } };
        onPacketsReceived(rx, arrived, 2);
        const auto [ackSeq, ackBits] = getAckInfo(rx);
        assert(ackSeq == SequenceNum{ 1 } && (ackBits & 0x1u) != 0);   // bit 0 == seq 0, received
    }

    // sliding window via recordLossSample: count caps at the window size, index wraps
    // modulo it, and packetLossFraction = lostInWindow / countInWindow.

    // all-received -> 0% loss
    {
        ReliableEndpoint ep{};
        for (int i = 0; i < 100; ++i) recordLossSample(ep, false);
        assert(ep.lossWindowCount == 100 && ep.lossWindowIndex == 100);
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == 0);
        assert(packetLossFraction(ep) == 0.0);
    }

    // a known partial-loss ratio: every 4th packet lost over a sub-full window -> 25%
    {
        ReliableEndpoint ep{};
        const int n = 200;
        int expectLost = 0;
        for (int i = 0; i < n; ++i) {
            const bool lost = (i % 4 == 0);
            if (lost) ++expectLost;
            recordLossSample(ep, lost);
        }
        assert(ep.lossWindowCount == n);   // still under the 256 cap, no aging yet
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == expectLost);
        assert(expectLost == 50);
        const double pct = packetLossFraction(ep);
        assert(pct > 0.249 && pct < 0.251);   // 50/200 == 0.25
    }

    // overflowing window: feed > 256 samples so the oldest age out (index wraps mod 256).
    // First fill 256 as all-lost, then push 256 all-received: every original lost sample
    // is overwritten, so the window reads 0% even though half of all samples were lost.
    {
        ReliableEndpoint ep{};
        for (int i = 0; i < lossWindowSize; ++i) recordLossSample(ep, true);    // window full, all lost
        assert(ep.lossWindowCount == lossWindowSize);
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == lossWindowSize); // 256 lost
        assert(packetLossFraction(ep) == 1.0);                                   // 100%

        for (int i = 0; i < lossWindowSize; ++i) recordLossSample(ep, false);   // overwrite all 256 slots
        assert(ep.lossWindowCount == lossWindowSize);                           // count stays capped at 256
        assert(ep.lossWindowIndex == 2 * lossWindowSize);                       // index keeps climbing
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == 0);              // old losses aged out
        assert(packetLossFraction(ep) == 0.0);

        // one more wrapped write lands at slot (512 % 256 == 0): mark it lost -> exactly 1 in 256
        recordLossSample(ep, true);
        assert(ep.lossWindowCount == lossWindowSize);
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == 1);
        const double pct = packetLossFraction(ep);
        assert(pct > 0.0039 && pct < 0.0040);   // 1/256 ~= 0.00390625
    }

    // The sent ring returns every unresolved packet's bytes EXACTLY ONCE. Two paths remove a record
    // without an ack, and each had a byte-accounting bug the e2e soak was too small to reach:
    //
    //  - EVICTION of a packet already declared lost double-released: the declare (lostBytes) and the
    //    eviction both reported its size, deflating bytesInFlight below truth.
    //  - DISPLACEMENT leaked: a live record whose slot is reused a full ring cycle later (count still
    //    under maxInFlight, so the eviction path never ran) was overwritten reporting nothing, so its
    //    charged bytes stayed "in flight" forever.
    {
        // Declare seq 0 lost via triple-NACK, then evict it: the eviction must report 0 bytes.
        ReliableEndpoint ep{};
        ep.maxInFlight = 4;
        const ChannelId ch{ 0 };
        for (std::uint16_t s = 0; s < 4; ++s)
            onPacketSent(ep, SequenceNum{ s }, MonoTime{ s }, ch, SequenceNum{ s }, 100);
        const AckResult nack1 = processAcks(ep, SequenceNum{ 1 }, 0b0,  MonoTime{ 10 });
        const AckResult nack2 = processAcks(ep, SequenceNum{ 2 }, 0b1,  MonoTime{ 11 });
        const AckResult nack3 = processAcks(ep, SequenceNum{ 3 }, 0b11, MonoTime{ 12 });
        assert(nack1.lostBytes == 0 && nack2.lostBytes == 0);
        assert(nack3.lostBytes == 100);   // the third NACK declares it: released HERE, exactly once
        for (std::uint16_t s = 4; s < 7; ++s)
            onPacketSent(ep, SequenceNum{ s }, MonoTime{ 100u + s }, ch, SequenceNum{ s }, 100);
        assert(onPacketSent(ep, SequenceNum{ 7 }, MonoTime{ 200 }, ch, SequenceNum{ 7 }, 100) == 0);   // not again
        assert(ep.packetsEvicted == 1);

        // ...but evicting a LIVE (never-declared) victim does report its bytes.
        ReliableEndpoint ep2{};
        ep2.maxInFlight = 2;
        onPacketSent(ep2, SequenceNum{ 0 }, MonoTime{ 0 }, ch, SequenceNum{ 0 }, 300);
        onPacketSent(ep2, SequenceNum{ 1 }, MonoTime{ 1 }, ch, SequenceNum{ 1 }, 100);
        assert(onPacketSent(ep2, SequenceNum{ 2 }, MonoTime{ 2 }, ch, SequenceNum{ 2 }, 100) == 300);
    }
    {
        // Displacement: seq 0 stays live and unresolved while 1..255 are sent and acked (in windows
        // that never cover seq 0), so the ring is nearly empty when seq 256 lands on slot 0.
        ReliableEndpoint ep{};   // default maxInFlight 256 == ring size: count never forces an eviction
        const ChannelId ch{ 0 };
        onPacketSent(ep, SequenceNum{ 0 }, MonoTime{ 0 }, ch, SequenceNum{ 0 }, 777);
        for (std::uint16_t s = 1; s <= 255; ++s)
            onPacketSent(ep, SequenceNum{ s }, MonoTime{ s }, ch, SequenceNum{ s }, 100);
        const std::uint16_t ackPoints[] = { 33, 65, 97, 129, 161, 193, 225, 255 };
        for (const std::uint16_t a : ackPoints)
            processAcks(ep, SequenceNum{ a }, 0xFFFFFFFFull, MonoTime{ 500 });
        assert(packetsInFlight(ep) == 1);   // only seq 0 left, live

        assert(onPacketSent(ep, SequenceNum{ 256 }, MonoTime{ 1000 }, ch, SequenceNum{ 256 }, 100) == 777);
        assert(ep.packetsEvicted == 1);     // the displacement is an eviction and is counted as one
        assert(packetsInFlight(ep) == 1);   // the overwrite swapped records; the count did not drift
        assert(!isInFlight(ep, SequenceNum{ 0 }) && isInFlight(ep, SequenceNum{ 256 }));
    }

    // The window index is a free-running cursor MASKED into the window, so its wrap costs nothing. A
    // signed counter is UB at 2^31 and the negative value it becomes indexes LossWindow::bits out of
    // bounds -- about 200 days on one connection at 120 packets a second.
    {
        ReliableEndpoint ep{};
        ep.lossWindowIndex = 0xFFFFFFFFu;    // one short of the wrap; 0xFFFFFFFF & 255 == slot 255
        ep.lossWindowCount = lossWindowSize;
        recordLossSample(ep, true);
        assert(ep.lossWindowIndex == 0u);                              // wrapped, defined, back to slot 0
        assert(lossCount(ep.lossWindow, lossWindowSize) == 1);
        recordLossSample(ep, true);                                    // slot 0: a seamless continuation
        assert(ep.lossWindowIndex == 1u);
        assert(lossCount(ep.lossWindow, lossWindowSize) == 2);
    }

    // A sequence far in the FUTURE resynchronizes the endpoint; it must never deafen it. Skipping the
    // remoteSeq update along with the insert is self-sealing: once the remote falls out of range every
    // later packet is equally far out, so remoteSeq freezes and no ack is ever sent again -- while
    // received-time keeps the connection alive on top of a channel that can no longer confirm anything.
    {
        ReliableEndpoint ep{};
        ep.maxSeqDistance = 1024;
        const SequenceNum first{ 1 };
        onPacketsReceived(ep, &first, 1);
        assert(ep.remoteSeq == SequenceNum{ 1 });

        const SequenceNum farAhead{ 5000 };   // the peer kept sending through a long silence
        onPacketsReceived(ep, &farAhead, 1);
        assert(ep.remoteSeq == SequenceNum{ 5000 });     // resynchronized...
        assert(getAckInfo(ep).second == 0);              // ...with an empty bitfield: nothing before it is known

        const SequenceNum resumed[] = { SequenceNum{ 5001 }, SequenceNum{ 5002 } };
        onPacketsReceived(ep, resumed, 2);
        const auto [ackSeq, ackBits] = getAckInfo(ep);
        assert(ackSeq == SequenceNum{ 5002 });           // ...and it keeps acking from there
        assert((ackBits & 0x1u) != 0);

        const SequenceNum ancient{ 100 };                // far in the PAST: a duplicate, not an advance
        onPacketsReceived(ep, &ancient, 1);
        assert(ep.remoteSeq == SequenceNum{ 5002 });
        assert(!rbExists(ep.received, ancient));
    }

    // ...and the DEFAULT distance is a real bound. abs(sequenceDiff) tops out at 32768, so a guard
    // testing "> 32768" rejects nothing at any of the 65536 offsets.
    {
        ReliableEndpoint ep{};
        assert(ep.maxSeqDistance == defaultMaxSequenceDistance);
        assert(defaultMaxSequenceDistance < 32768);
        const SequenceNum here{ 1000 };
        onPacketsReceived(ep, &here, 1);
        const SequenceNum tooOld{ static_cast<std::uint16_t>(1000 - defaultMaxSequenceDistance - 1) };
        onPacketsReceived(ep, &tooOld, 1);
        assert(!rbExists(ep.received, tooOld));          // out of range -> not even recorded
        const SequenceNum justInRange{ static_cast<std::uint16_t>(1000 - defaultMaxSequenceDistance) };
        onPacketsReceived(ep, &justInRange, 1);
        assert(rbExists(ep.received, justInRange));      // ...and the edge itself still is
    }

    // Karn's algorithm: a packet already DECLARED LOST contributes no RTT sample. The elapsed time to
    // its late ack measures the retransmit timeline, not the path, and one such sample drags the whole
    // estimator with it (srtt 20 -> 130, rto from the 50ms floor to over a second).
    {
        ReliableEndpoint ep{};
        const ChannelId  ch{ 0 };
        for (std::uint16_t s = 0; s < 6; ++s)
            onPacketSent(ep, SequenceNum{ s }, MonoTime{ 0 }, ch, SequenceNum{ s }, 100);

        ReliableEndpoint peer{};   // everything but seq 0 arrives, so seq 0 is NACKed by the bitfield
        const SequenceNum got[] = { SequenceNum{ 1 }, SequenceNum{ 2 }, SequenceNum{ 3 },
                                    SequenceNum{ 4 }, SequenceNum{ 5 } };
        onPacketsReceived(peer, got, 5);
        const auto [ackSeq, ackBits] = getAckInfo(peer);

        const MonoTime at20{ 20ull * 1000000 };
        for (int i = 0; i < fastRetransmitThreshold; ++i) processAcks(ep, ackSeq, ackBits, at20);
        assert(ep.hasRttSample && ep.totalLost == 1);          // honest 20ms samples, and seq 0 written off
        const double srttBefore = ep.srtt, rtoBefore = ep.rto;
        assert(srttBefore > 19.9 && srttBefore < 20.1);
        assert(rtoBefore == minRtoMs);

        const AckResult late = processAcks(ep, SequenceNum{ 0 }, 0, MonoTime{ 500ull * 1000000 });
        assert(!late.acked.empty());        // it WAS delivered, so the channel message is resolved...
        assert(late.ackedBytes == 0);       // ...but its bytes already left flight when it was declared
        assert(ep.srtt == srttBefore);      // ...and the estimator does not take its timing
        assert(ep.rto  == rtoBefore);
    }

    // The retransmit wait backs off per ATTEMPT, held at maxRtoMs. A flat RTO spends a ten-retry budget
    // inside about half a second at the 50ms floor, so a path that blinks erases every reliable message
    // in flight while the connection itself is nowhere near its own timeout.
    {
        assert(retransmitTimeoutMs(50.0, 1) == 50.0);      // the first retransmit waits one plain RTO
        assert(retransmitTimeoutMs(50.0, 2) == 100.0);
        assert(retransmitTimeoutMs(50.0, 3) == 200.0);
        assert(retransmitTimeoutMs(50.0, 6) == 1600.0);
        assert(retransmitTimeoutMs(50.0, 7) == maxRtoMs);   // held at the cap from here on
        assert(retransmitTimeoutMs(50.0, 99) == maxRtoMs);
        assert(retransmitTimeoutMs(500.0, 4) == maxRtoMs);  // the cap binds before the shift does

        double budget = 0.0;                                // what a default retry budget actually spans
        for (int retry = 1; retry <= 10; ++retry) budget += retransmitTimeoutMs(minRtoMs, retry);
        assert(budget > 10000.0);                           // longer than the default connection timeout
    }

    // Packets no ack ever resolved are written off by TIMEOUT. Every other loss signal is ack-driven,
    // so a path that has gone silent produces none at all and the loss figure freezes at its last
    // healthy value -- which is what a rate controller and the quality grade both read.
    {
        ReliableEndpoint ep{};
        const ChannelId  ch{ 0 };
        for (std::uint16_t s = 1; s <= 8; ++s)
            onPacketSent(ep, SequenceNum{ s }, MonoTime{ 0 }, ch, SequenceNum{ s }, 300);
        assert(packetLossFraction(ep) == 0.0);   // no acks have arrived: nothing sampled either way

        const TimeoutResult early = declareTimedOutPackets(ep, MonoTime{ 50ull * 1000000 }, 200.0);
        assert(early.lostPackets == 0);          // 50ms: inside the grace, nothing written off yet

        const TimeoutResult swept = declareTimedOutPackets(ep, MonoTime{ 500ull * 1000000 }, 200.0);
        assert(swept.lostPackets == 8);
        assert(swept.lostBytes == 8 * 300);
        assert(swept.newLossEpisode);            // ...and it counts as ONE congestion episode, not eight
        assert(packetLossFraction(ep) == 1.0);   // the signal finally moved

        const TimeoutResult again = declareTimedOutPackets(ep, MonoTime{ 900ull * 1000000 }, 200.0);
        assert(again.lostPackets == 0);          // already declared: never counted twice

        // A late ack still resolves the channel message, and still releases nothing twice.
        const AckResult late = processAcks(ep, SequenceNum{ 8 }, 0, MonoTime{ 900ull * 1000000 });
        assert(!late.acked.empty() && late.ackedBytes == 0);
    }

    std::printf("aether loss-window OK: lossCount take==64 mask, overflow aging, 0%%/25%%/100%% ratios exact; "
                "ring returns unresolved bytes exactly once (lost-then-evicted 0, displaced live counted); "
                "index wrap masked, far-future resync, Karn, backoff, timeout-declared loss\n");
    return 0;
}
