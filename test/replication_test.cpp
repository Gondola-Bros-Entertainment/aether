// aether - delta replication ack-handling test. Pins deltaOnAck under lost / out-of-order / stale
// acks: the in-order path is covered in roundtrip.cpp; this nails the cases where an ack is the
// newest (not the oldest pending), arrives stale for an already-dropped seq, or never arrives at all.
// Standalone: assert() is the check, so build WITHOUT NDEBUG (no -O2 -DNDEBUG).
#include "aether/replication.hpp"

#include <cassert>
#include <cstdio>

namespace {

// Plain replicated struct: a couple of fields so a delta is strictly smaller than a full snapshot.
struct Ent { int hp; int x; };

} // namespace

int main() {
    using namespace aether;

    // --- out-of-order ack: ack the NEWEST pending seq, not the oldest ---
    // Encode several snapshots with no acks so pending grows, then ack the most recent. The confirmed
    // baseline must jump straight to it and pending must keep ONLY entries newer than the acked seq.
    {
        DeltaTracker<Ent> tr = newDeltaTracker<Ent>(8);
        const Ent s0{ 100, 0 };
        const Ent s1{ 100, 1 };
        const Ent s2{ 100, 2 };
        (void)deltaEncode(tr, 0, s0);
        (void)deltaEncode(tr, 1, s1);
        (void)deltaEncode(tr, 2, s2);
        assert(tr.pending.size() == 3 && !tr.confirmed);   // nothing acked yet

        deltaOnAck(tr, 2);   // ack the newest, skipping 0 and 1
        const auto conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == 2);                         // baseline jumped to the newest acked seq
        assert(tr.pending.empty());                         // 0 and 1 dropped; nothing is newer than 2
        assert(tr.confirmed->second.x == 2);               // confirmed holds the acked snapshot
    }

    // --- out-of-order then NEW encode uses the right baseline + a stale ack is a no-op ---
    // After acking a middle seq, only newer entries survive in pending. A later snapshot deltas against
    // the confirmed baseline; a stale ack for an already-dropped older seq must not regress confirmed,
    // and the receiver still decodes the new delta against the surviving baseline.
    {
        DeltaTracker<Ent>    tr = newDeltaTracker<Ent>(8);
        BaselineManager<Ent> bm = newBaselineManager<Ent>(8, 60000.0);
        const Ent s0{ 100, 0 };
        const Ent s1{ 100, 1 };
        const Ent s2{ 100, 2 };

        // seq 0: full snapshot. Receiver decodes + stores it as a baseline.
        const auto enc0 = deltaEncode(tr, 0, s0);
        const auto dec0 = deltaDecode(bm, enc0);
        assert(dec0 && dec0->x == 0);
        pushBaseline(bm, 0, *dec0, MonoTime{ 0 });

        // seqs 1 and 2 encoded before any further ack -> pending = {0,1,2}.
        (void)deltaEncode(tr, 1, s1);
        (void)deltaEncode(tr, 2, s2);

        // Ack the MIDDLE seq 1: confirmed -> 1, pending keeps only {2}.
        deltaOnAck(tr, 1);
        auto conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == 1 && tr.pending.size() == 1 && tr.pending.front().first == 2);

        // Receiver must have seq 1 as a baseline for the next delta to resolve against it.
        const Ent s1recv{ 100, 1 };
        pushBaseline(bm, 1, s1recv, MonoTime{ 1 });

        // STALE ack for seq 0 -- already dropped from pending -> a no-op, confirmed must NOT regress.
        deltaOnAck(tr, 0);
        conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == 1);                         // still 1, not regressed to 0
        assert(tr.pending.size() == 1 && tr.pending.front().first == 2);   // pending untouched

        // A new snapshot now deltas against baseline seq 1 and still round-trips on the receiver.
        const Ent s3{ 100, 3 };
        const auto enc3 = deltaEncode(tr, 3, s3);
        const auto dec3 = deltaDecode(bm, enc3);
        assert(dec3 && dec3->hp == 100 && dec3->x == 3);
        assert(enc3.size() < enc0.size());                 // delta beats the full snapshot
    }

    // --- lost ack: the ack for a snapshot never arrives ---
    // The baseline must simply stay put (receiver keeps the older baseline), and the very next snapshot
    // still round-trips because it deltas against that same un-advanced baseline.
    {
        DeltaTracker<Ent>    tr = newDeltaTracker<Ent>(8);
        BaselineManager<Ent> bm = newBaselineManager<Ent>(8, 60000.0);
        const Ent s0{ 100, 0 };

        const auto enc0 = deltaEncode(tr, 0, s0);
        const auto dec0 = deltaDecode(bm, enc0);
        assert(dec0 && dec0->x == 0);
        pushBaseline(bm, 0, *dec0, MonoTime{ 0 });
        deltaOnAck(tr, 0);
        assert(deltaConfirmedSeq(tr) && *deltaConfirmedSeq(tr) == 0);   // baseline at seq 0

        // seq 1 sent but its ack is LOST: we never call deltaOnAck(tr, 1).
        const Ent s1{ 100, 1 };
        const auto enc1 = deltaEncode(tr, 1, s1);
        const auto dec1 = deltaDecode(bm, enc1);
        assert(dec1 && dec1->x == 1);
        const auto confAfterLoss = deltaConfirmedSeq(tr);
        assert(confAfterLoss && *confAfterLoss == 0);      // baseline did NOT advance to 1

        // seq 2: because seq 1's ack was lost, this still deltas against baseline seq 0 -- and decodes,
        // since the receiver still holds seq 0. (No need for the lost seq-1 baseline.)
        const Ent s2{ 100, 2 };
        const auto enc2 = deltaEncode(tr, 2, s2);
        assert(enc2[0] == 0 && enc2[1] == 0);              // header references baseline seq 0
        const auto dec2 = deltaDecode(bm, enc2);
        assert(dec2 && dec2->hp == 100 && dec2->x == 2);   // next delta still round-trips
    }

    std::printf("aether replication-ack OK: out-of-order ack advances + prunes pending; stale ack is a no-op (no regress); lost ack leaves baseline put and the next delta still round-trips\n");
    return 0;
}
