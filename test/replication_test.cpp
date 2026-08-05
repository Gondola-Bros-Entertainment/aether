// aether - snapshot replication test. Pins deltaOnAck under lost / out-of-order / stale / repeated
// acks (the in-order path is covered in roundtrip.cpp), the ring and staleness bounds that keep the
// two sides able to recover from an evicted baseline, what fieldEqual counts as a change inside a
// container, and the client-side snapshot buffer that the same snapshots feed.
// Standalone: assert() is the check, so build WITHOUT NDEBUG (no -O2 -DNDEBUG).
#include "aether/interpolation.hpp"
#include "aether/replication.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <vector>

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
        (void)deltaEncode(tr, BaselineSeq{ 0 }, s0);
        (void)deltaEncode(tr, BaselineSeq{ 1 }, s1);
        (void)deltaEncode(tr, BaselineSeq{ 2 }, s2);
        assert(tr.pending.size() == 3 && !tr.confirmed);   // nothing acked yet

        deltaOnAck(tr, BaselineSeq{ 2 });   // ack the newest, skipping 0 and 1
        const auto conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == BaselineSeq{ 2 });                         // baseline jumped to the newest acked seq
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
        const auto enc0 = deltaEncode(tr, BaselineSeq{ 0 }, s0);
        const auto dec0 = deltaDecode(bm, enc0);
        assert(dec0 && dec0->x == 0);
        pushBaseline(bm, BaselineSeq{ 0 }, *dec0, MonoTime{ 0 });

        // seqs 1 and 2 encoded before any further ack -> pending = {0,1,2}.
        (void)deltaEncode(tr, BaselineSeq{ 1 }, s1);
        (void)deltaEncode(tr, BaselineSeq{ 2 }, s2);

        // Ack the MIDDLE seq 1: confirmed -> 1, pending keeps only {2}.
        deltaOnAck(tr, BaselineSeq{ 1 });
        auto conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == BaselineSeq{ 1 } && tr.pending.size() == 1 && tr.pending.front().first == BaselineSeq{ 2 });

        // Receiver must have seq 1 as a baseline for the next delta to resolve against it.
        const Ent s1recv{ 100, 1 };
        pushBaseline(bm, BaselineSeq{ 1 }, s1recv, MonoTime{ 1 });

        // STALE ack for seq 0 -- already dropped from pending -> a no-op, confirmed must NOT regress.
        deltaOnAck(tr, BaselineSeq{ 0 });
        conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == BaselineSeq{ 1 });                         // still 1, not regressed to 0
        assert(tr.pending.size() == 1 && tr.pending.front().first == BaselineSeq{ 2 });   // pending untouched

        // A new snapshot now deltas against baseline seq 1 and still round-trips on the receiver.
        const Ent s3{ 100, 3 };
        const auto enc3 = deltaEncode(tr, BaselineSeq{ 3 }, s3);
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

        const auto enc0 = deltaEncode(tr, BaselineSeq{ 0 }, s0);
        const auto dec0 = deltaDecode(bm, enc0);
        assert(dec0 && dec0->x == 0);
        pushBaseline(bm, BaselineSeq{ 0 }, *dec0, MonoTime{ 0 });
        deltaOnAck(tr, BaselineSeq{ 0 });
        assert(deltaConfirmedSeq(tr) && *deltaConfirmedSeq(tr) == BaselineSeq{ 0 });   // baseline at seq 0

        // seq 1 sent but its ack is LOST: we never call deltaOnAck(tr, BaselineSeq{ 1 }).
        const Ent s1{ 100, 1 };
        const auto enc1 = deltaEncode(tr, BaselineSeq{ 1 }, s1);
        const auto dec1 = deltaDecode(bm, enc1);
        assert(dec1 && dec1->x == 1);
        const auto confAfterLoss = deltaConfirmedSeq(tr);
        assert(confAfterLoss && *confAfterLoss == BaselineSeq{ 0 });      // baseline did NOT advance to 1

        // seq 2: because seq 1's ack was lost, this still deltas against baseline seq 0 -- and decodes,
        // since the receiver still holds seq 0. (No need for the lost seq-1 baseline.)
        const Ent s2{ 100, 2 };
        const auto enc2 = deltaEncode(tr, BaselineSeq{ 2 }, s2);
        assert(enc2[0] == 0 && enc2[1] == 0);              // header references baseline seq 0
        const auto dec2 = deltaDecode(bm, enc2);
        assert(dec2 && dec2->hp == 100 && dec2->x == 2);   // next delta still round-trips
    }

    std::printf("aether replication-ack OK: out-of-order ack advances + prunes pending; stale ack is a no-op (no regress); lost ack leaves baseline put and the next delta still round-trips\n");

    // --- a bare BaselineManager holds a real ring, not one snapshot ---
    // These defaults are what a caller gets who never reaches for the new* factories. A 0 timeout
    // read as a live threshold expires EVERY entry on every push -- elapsedMs saturates at 0 and is
    // never negative, so the predicate holds even for the snapshot just stored -- leaving a one-deep
    // ring in which maxSnapshots never applies and any baseline but the newest is already gone.
    {
        BaselineManager<Ent> bare;   // bare struct: no factory, no configuration
        pushBaseline(bare, BaselineSeq{ 0 }, Ent{ 100, 0 }, MonoTime{ 0 });
        pushBaseline(bare, BaselineSeq{ 1 }, Ent{ 100, 1 }, MonoTime{ 16000000ull });   // +16ms
        pushBaseline(bare, BaselineSeq{ 2 }, Ent{ 100, 2 }, MonoTime{ 32000000ull });
        const int  bareCount = baselineCount(bare);
        const Ent* bare0     = getBaseline(bare, BaselineSeq{ 0 });
        const Ent* bare1     = getBaseline(bare, BaselineSeq{ 1 });
        const Ent* bare2     = getBaseline(bare, BaselineSeq{ 2 });
        assert(bareCount == 3);
        assert(bare0 && bare0->x == 0);    // the earlier seqs are still resolvable
        assert(bare1 && bare1->x == 1);
        assert(bare2 && bare2->x == 2);

        // maxSnapshots is what bounds the ring, so pushing past it drops the OLDEST, one at a time.
        BaselineManager<Ent> capped = newBaselineManager<Ent>(4, 0.0);   // 0 -> no time-based expiry
        for (int i = 0; i < 10; ++i)
            pushBaseline(capped, static_cast<BaselineSeq>(i), Ent{ 100, i }, MonoTime{ static_cast<std::uint64_t>(i) * 1000000ull });
        const int  cappedCount = baselineCount(capped);
        const Ent* evicted     = getBaseline(capped, BaselineSeq{ 5 });
        const Ent* newest      = getBaseline(capped, BaselineSeq{ 9 });
        assert(cappedCount == 4);
        assert(!evicted);
        assert(newest && newest->x == 9);

        // A positive timeout still expires: 200ms of gap past a 100ms timeout drops the older entry.
        BaselineManager<Ent> timed = newBaselineManager<Ent>(8, 100.0);
        pushBaseline(timed, BaselineSeq{ 0 }, Ent{ 100, 0 }, MonoTime{ 0 });
        pushBaseline(timed, BaselineSeq{ 1 }, Ent{ 100, 1 }, MonoTime{ 200000000ull });   // +200ms
        const int  timedCount = baselineCount(timed);
        const Ent* expiredOne = getBaseline(timed, BaselineSeq{ 0 });
        assert(timedCount == 1 && !expiredOne);
    }
    std::printf("aether replication-ring OK: default BaselineManager keeps every pushed snapshot, count cap evicts oldest-first, positive timeout still expires\n");

    // --- an ack resolves a repeated seq the way the receiver does: newest first ---
    // A BaselineSeq is 16 bits, so it repeats every 65536 snapshots and pending can hold one value
    // twice. getBaseline scans newest-first; an ack scanning oldest-first confirms the snapshot from
    // the PREVIOUS wrap, and deltas against that decode cleanly into wrong state -- silent
    // divergence, not a dropped packet. pending is plain data, so build the duplicate directly.
    {
        DeltaTracker<Ent> tr;
        tr.pending.push_back({ BaselineSeq{ 0 }, Ent{ 100, 0 } });   // seq 0, a full wrap ago
        tr.pending.push_back({ BaselineSeq{ 1 }, Ent{ 100, 1 } });
        tr.pending.push_back({ BaselineSeq{ 0 }, Ent{ 100, 2 } });   // seq 0 again: what an ack for 0 can only mean
        deltaOnAck(tr, BaselineSeq{ 0 });
        const auto conf = deltaConfirmedSeq(tr);
        assert(conf && *conf == BaselineSeq{ 0 });
        assert(tr.confirmed->second.x == 2);   // the newest match, not the stale duplicate
        assert(tr.pending.empty());            // nothing was newer than it

        // And deltaEncode cannot build that duplicate itself: pending is capped below the wrap
        // whatever maxPending is set to, so a seq is unique within it.
        DeltaTracker<Ent> big = newDeltaTracker<Ent>(1000000);
        for (int i = 0; i < maxPendingLimit; ++i)
            big.pending.push_back({ static_cast<BaselineSeq>(i), Ent{ 100, i } });
        (void)deltaEncode(big, BaselineSeq{ 4242 }, Ent{ 100, 7 });
        assert(static_cast<int>(big.pending.size()) <= maxPendingLimit);
    }
    std::printf("aether replication-ack OK: a repeated seq confirms the newest pending match, pending capped below the 16-bit wrap\n");

    // --- an evicted baseline does not stall replication for good ---
    // Acks stop arriving, the receiver's ring rolls past the confirmed baseline, and every delta
    // after that references a snapshot the receiver no longer holds. With no bound on how stale the
    // sender's baseline may get that is terminal: no decode -> no ack -> confirmed never advances ->
    // no decode. So the receiver has to say WHICH failure it hit, and the sender has to fall back to
    // full state on its own -- full state decodes against nothing, which is the way back in.
    {
        DeltaTracker<Ent> tr = newDeltaTracker<Ent>(64);
        tr.maxBaselineAge = 20;   // deliberately looser than the receiver's ring, so the stall happens
        BaselineManager<Ent> bm = newBaselineManager<Ent>(8, 60000.0);   // 8-deep receiver ring

        const auto       enc0 = deltaEncode(tr, BaselineSeq{ 0 }, Ent{ 100, 0 });
        DeltaDecodeError err0 = DeltaDecodeError::BaselineMissing;
        const auto       dec0 = deltaDecode(bm, enc0, &err0);
        assert(dec0 && dec0->x == 0);
        pushBaseline(bm, BaselineSeq{ 0 }, *dec0, MonoTime{ 0 });
        deltaOnAck(tr, BaselineSeq{ 0 });   // the last ack that ever arrives

        int  firstMissing = -1, firstRecovered = -1, failedAfterRecovery = 0;
        bool recoveredWithFullState = false;
        for (int i = 1; i <= 200; ++i) {
            const auto       enc = deltaEncode(tr, static_cast<BaselineSeq>(i), Ent{ 100, i });
            DeltaDecodeError err = DeltaDecodeError::Malformed;
            const auto       dec = deltaDecode(bm, enc, &err);
            if (!dec) {
                assert(err == DeltaDecodeError::BaselineMissing);   // told apart from a short packet
                if (firstMissing < 0) firstMissing = i;
                if (firstRecovered >= 0) ++failedAfterRecovery;
                continue;
            }
            assert(dec->x == i);
            pushBaseline(bm, static_cast<BaselineSeq>(i), *dec, MonoTime{ static_cast<std::uint64_t>(i) * 1000000ull });
            if (firstMissing >= 0 && firstRecovered < 0) {
                firstRecovered         = i;
                recoveredWithFullState = (enc[0] == 0xFF && enc[1] == 0xFF);   // noBaseline header
            }
        }
        assert(firstMissing == 9);          // the 8-deep ring evicts baseline 0 on the 8th push
        assert(firstRecovered > 0);         // and the sender gets itself out, with no ack to help
        assert(recoveredWithFullState);     // by sending full state, not another undecodable delta
        assert(failedAfterRecovery == 0);   // and stays out
        assert(firstRecovered - firstMissing <= tr.maxBaselineAge + 1);

        // One ack getting through puts it back on deltas against the fresh baseline.
        deltaOnAck(tr, BaselineSeq{ 200 });
        const auto       encBack = deltaEncode(tr, BaselineSeq{ 201 }, Ent{ 100, 201 });
        DeltaDecodeError errBack = DeltaDecodeError::Malformed;
        const auto       decBack = deltaDecode(bm, encBack, &errBack);
        assert(encBack[0] == 200 && encBack[1] == 0);   // header names baseline seq 200, not noBaseline
        assert(decBack && decBack->x == 201);
    }
    std::printf("aether replication-recovery OK: an evicted baseline reports BaselineMissing, the sender falls back to full state and replication resumes\n");

    // --- fieldEqual looks inside containers, element by element ---
    // The changemask decides what the receiver applies, so "unchanged" has to mean what the full
    // path would encode, at every depth. operator== on a container compares elements by VALUE: it
    // calls +0.0 and -0.0 equal, so a sign flip inside a vector<float> ships a mask saying nothing
    // changed while the two sides hold different bits; it calls NaN unequal to itself, so a field
    // that never changed is re-sent every tick; and it does not exist at all for a plain aggregate.
    {
        struct Vf { std::vector<float> v; int tag; };

        const Vf   plusZero{ { 0.0f }, 1 };
        const Vf   minusZero{ { -0.0f }, 1 };
        const bool zerosEqual = fieldEqual(plusZero, minusZero);
        assert(!zerosEqual);   // a sign flip inside the vector is a change

        const Bytes signDelta = packDelta(plusZero, minusZero);
        Reader      signReader{ signDelta.data(), signDelta.size(), 0 };
        const auto  signApplied = deltaUnpack<Vf>(signReader, plusZero);
        assert(signApplied && signApplied->v.size() == 1);
        assert(std::signbit(signApplied->v[0]));   // the receiver ends up on the sender's bits

        // The mirror case: NaN is unequal to itself by value, so an untouched field would re-send.
        const Vf    nanState{ { std::numeric_limits<float>::quiet_NaN() }, 1 };
        const Bytes nanDelta = packDelta(nanState, nanState);
        assert(nanDelta.size() == 1);   // changemask only, no field payload

        // optional<T> is the same comparison one level down.
        struct Of { std::optional<float> o; int tag; };
        const bool optZerosEqual = fieldEqual(Of{ 0.0f, 1 }, Of{ -0.0f, 1 });
        const bool optNoneEqual  = fieldEqual(Of{ 0.0f, 1 }, Of{ std::nullopt, 1 });
        const bool optSameEqual  = fieldEqual(Of{ std::nullopt, 1 }, Of{ std::nullopt, 1 });
        assert(!optZerosEqual && !optNoneEqual && optSameEqual);

        // A vector of plain aggregates has no operator== to fall through to at all: the comparison
        // has to recurse into the element's fields, and the delta has to round-trip what it finds.
        struct Item { int id; float w; };
        struct Bag { std::vector<Item> items; int tag; };
        const Bag  before{ { Item{ 1, 2.0f }, Item{ 2, 3.0f } }, 7 };
        const Bag  after{ { Item{ 1, 2.0f }, Item{ 2, 4.0f } }, 7 };
        const bool bagSame    = fieldEqual(before, before);
        const bool bagChanged = fieldEqual(before, after);
        assert(bagSame && !bagChanged);
        const Bytes bagDelta = packDelta(before, after);
        Reader      bagReader{ bagDelta.data(), bagDelta.size(), 0 };
        const auto  bagApplied = deltaUnpack<Bag>(bagReader, before);
        assert(bagApplied && bagApplied->items.size() == 2 && bagApplied->items[1].id == 2);
        assert(bagApplied->items[1].w > 3.9f && bagApplied->items[1].w < 4.1f);
        const Bytes bagUnchanged = packDelta(before, before);
        assert(bagUnchanged.size() == 1);   // changemask only

        // A string field is bytes, with no element to recurse into.
        struct Sf { std::string s; int tag; };
        const bool strSame    = fieldEqual(Sf{ "abc", 1 }, Sf{ "abc", 1 });
        const bool strChanged = fieldEqual(Sf{ "abc", 1 }, Sf{ "abd", 1 });
        assert(strSame && !strChanged);
    }
    std::printf("aether delta OK: fieldEqual recurses through vector/optional (sign flip is a change, NaN is not, aggregate elements compile and round-trip)\n");

    // --- the flag bytes decode canonically: 0 or 1, and nothing else ---
    // varint.hpp rejects an overlong integer and the changemask rejects a set padding bit for the
    // reason these bytes must be checked too: a byte meaning "true" in 255 ways is 255 packets that
    // decode to the same state, so peers can disagree about whether they saw the same packet and any
    // duplicate check or signature over the bytes stops describing the values. Hand-build the
    // payloads -- the encoder cannot produce the non-canonical form, which is the whole point.
    {
        // Layout for a 2-field struct: [changemask 0x01 = field 0 changed][field 0 payload].
        struct Bf { bool flag; int tag; };
        const Bf    prevB{ false, 7 };
        const Bytes boolTrue{ 0x01, 0x01 };
        const Bytes boolFalse{ 0x01, 0x00 };
        const Bytes boolNonCanonical{ 0x01, 0x02 };
        Reader      rBoolTrue{ boolTrue.data(), boolTrue.size(), 0 };
        Reader      rBoolFalse{ boolFalse.data(), boolFalse.size(), 0 };
        Reader      rBoolBad{ boolNonCanonical.data(), boolNonCanonical.size(), 0 };
        const auto  decBoolTrue  = deltaUnpack<Bf>(rBoolTrue, prevB);
        const auto  decBoolFalse = deltaUnpack<Bf>(rBoolFalse, prevB);
        const auto  decBoolBad   = deltaUnpack<Bf>(rBoolBad, prevB);
        assert(decBoolTrue && decBoolTrue->flag && decBoolTrue->tag == 7);
        assert(decBoolFalse && !decBoolFalse->flag);
        assert(!decBoolBad);   // 0x02 is not a bool

        // The optional's present flag is the same byte with the same rule.
        struct Op { std::optional<int> o; int tag; };
        const Op    prevO{ std::nullopt, 7 };
        const Bytes optPresent{ 0x01, 0x01, 0x2A };   // flag 1, then zigzag(21)
        const Bytes optAbsent{ 0x01, 0x00 };
        const Bytes optNonCanonical{ 0x01, 0x02, 0x2A };
        Reader      rOptPresent{ optPresent.data(), optPresent.size(), 0 };
        Reader      rOptAbsent{ optAbsent.data(), optAbsent.size(), 0 };
        Reader      rOptBad{ optNonCanonical.data(), optNonCanonical.size(), 0 };
        const auto  decOptPresent = deltaUnpack<Op>(rOptPresent, prevO);
        const auto  decOptAbsent  = deltaUnpack<Op>(rOptAbsent, prevO);
        const auto  decOptBad     = deltaUnpack<Op>(rOptBad, prevO);
        assert(decOptPresent && decOptPresent->o && *decOptPresent->o == 21);
        assert(decOptAbsent && !decOptAbsent->o);
        assert(!decOptBad);   // 0x02 is not a present flag

        // What the encoder produces still round-trips, at both flag values.
        const Bf   flagOn{ true, 7 };
        const Bytes boolRoundTrip = packDelta(prevB, flagOn);
        Reader      rBoolRound{ boolRoundTrip.data(), boolRoundTrip.size(), 0 };
        const auto  decBoolRound = deltaUnpack<Bf>(rBoolRound, prevB);
        assert(decBoolRound && decBoolRound->flag);
        const Op    optOn{ 21, 7 };
        const Bytes optRoundTrip = packDelta(prevO, optOn);
        Reader      rOptRound{ optRoundTrip.data(), optRoundTrip.size(), 0 };
        const auto  decOptRound = deltaUnpack<Op>(rOptRound, prevO);
        assert(decOptRound && decOptRound->o && *decOptRound->o == 21);
    }
    std::printf("aether delta OK: bool and optional-present bytes accept only 0/1, non-canonical forms rejected, encoder output still round-trips\n");

    // --- the snapshot buffer spans the delay it is sampled at ---
    // sampleSnapshot looks playbackDelayMs behind the newest timestamp. History capped by a COUNT
    // spans however long the send rate makes those entries last, which is unrelated to the delay: at
    // the shipped defaults it covered 83ms at 60Hz against a 100ms delay, so every sample fell off
    // the front and returned the oldest state -- stepping, not interpolating, while snapshotReady()
    // still said ready. Retention is derived from the delay, so the span holds at any rate.
    {
        const auto playAt = [](double hz) {
            SnapshotBuffer<float> sb = newSnapshotBuffer<float>();
            const double          dt = 1000.0 / hz;
            int                   sampled = 0;
            for (int i = 0; i < static_cast<int>(hz) * 2; ++i) {   // two seconds of snapshots
                const double t = static_cast<double>(i) * dt;
                pushSnapshot(sb, t, static_cast<float>(i));
                if (t < sb.playbackDelayMs + dt) continue;   // still filling the delay
                const bool spans = snapshotSpansDelay(sb);
                const auto s     = sampleSnapshot(sb, t);
                assert(spans);   // history reaches back past the sample target
                assert(s);
                // The state IS the frame index, so an interpolated sample reads the target in frames.
                const double expect = (t - sb.playbackDelayMs) / dt;
                assert(*s > expect - 0.01 && *s < expect + 0.01);
                ++sampled;
            }
            return sampled;
        };
        const int at60  = playAt(60.0);
        const int at120 = playAt(120.0);
        assert(at60 > 0 && at120 > 0);

        // bufferDepth <= 0 must not report an empty buffer ready to sample, and must not empty the
        // buffer either: playback needs a PAIR whatever the configured depth says.
        SnapshotBuffer<float> zeroDepth = newSnapshotBufferWithConfig<float>(0, 100.0);
        const bool            readyEmpty = snapshotReady(zeroDepth);
        assert(!readyEmpty);
        pushSnapshot(zeroDepth, 0.0, 0.0f);
        const bool readyOne = snapshotReady(zeroDepth);
        assert(!readyOne);   // one snapshot has nothing to interpolate against
        pushSnapshot(zeroDepth, 16.0, 1.0f);
        const bool readyTwo = snapshotReady(zeroDepth);
        const int  keptTwo  = snapshotCount(zeroDepth);
        assert(readyTwo && keptTwo == 2);   // and a depth of 0 no longer discards every push

        // Where the delay genuinely outruns the history, the degraded case is reportable rather
        // than a clamped sample that looks exactly like ordinary playback.
        SnapshotBuffer<float> slow = newSnapshotBufferWithConfig<float>(3, 5000.0);
        pushSnapshot(slow, 0.0, 0.0f);
        pushSnapshot(slow, 100.0, 1.0f);
        const bool slowSpans  = snapshotSpansDelay(slow);
        const auto slowSample = sampleSnapshot(slow, 100.0);
        assert(!slowSpans);                          // 100ms of history under a 5s delay
        assert(slowSample && *slowSample == 0.0f);   // clamped to the oldest -- and it says so
    }
    std::printf("aether interpolation OK: history spans the playback delay at 60Hz and 120Hz (samples interpolate, not clamp), depth 0 is not ready and does not empty the buffer\n");
    return 0;
}
