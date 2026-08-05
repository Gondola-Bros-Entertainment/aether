// aether - pins the serializer and reassembly behaviors an audit flagged:
//   1. nested-dynamic round-trip (the bounded-amplification path): vector<string> /
//      vector<vector<uint8_t>> with empty inner elements pack+unpack exactly.
//   2. non-canonical delta changemask rejection: a high padding bit set beyond the
//      field count in the mask byte makes deltaUnpack return nullopt.
//   3. the memcpy fast path admits only fields whose wire bytes ARE their memory bytes.
//   4. a zero-field reflection is believable only for an empty struct.
//   5. an enum decodes over the whole range its fixed underlying type can hold.
//   6. the optional flag and bool accept 0 and 1 and nothing else.
//   7. an out-of-range fragment index buffers nothing and evicts nothing.
//   8. a container length is written through its 4-byte prefix exactly.
// Standalone, no framework: assert() is the check (so build WITHOUT -DNDEBUG).
#include "aether/bitserialize.hpp"
#include "aether/delta.hpp"
#include "aether/fragment.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

int main() {
    // ---- 1. nested-dynamic round-trip ----
    // vector<string> with several EMPTY strings: each empty element is ~1 wire byte but a real
    // std::string object on decode -- the bounded ~24x amplification path. Must reconstruct exactly.
    {
        struct WithStrs { std::vector<std::string> items; };
        WithStrs orig;
        orig.items = { "", "", "hello", "", "world", "" };   // mix of empty + non-empty

        std::uint8_t buf[128];
        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::pack(w, orig);
        assert(w.ok);

        aether::Reader r{ buf, w.pos, 0 };
        const auto back = aether::unpack<WithStrs>(r);
        assert(back && back->items.size() == orig.items.size());
        for (std::size_t k = 0; k < orig.items.size(); ++k) assert(back->items[k] == orig.items[k]);
    }

    // vector<vector<uint8_t>> with several EMPTY inner vectors: same nested-dynamic shape one level
    // deeper. Empty inner vectors must round-trip as empty, not dropped or merged.
    {
        struct WithVecs { std::vector<std::vector<std::uint8_t>> items; };
        WithVecs orig;
        orig.items = { {}, {}, { 1, 2, 3 }, {}, { 9 }, {} };

        std::uint8_t buf[128];
        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::pack(w, orig);
        assert(w.ok);

        aether::Reader r{ buf, w.pos, 0 };
        const auto back = aether::unpack<WithVecs>(r);
        assert(back && back->items.size() == orig.items.size());
        for (std::size_t k = 0; k < orig.items.size(); ++k) assert(back->items[k] == orig.items[k]);
    }

    // ---- 2. non-canonical delta changemask rejection ----
    // 2-field struct -> n=2, maskBytes=1, the mask byte is at wire offset 0. Our encoder only ever
    // sets the low 2 bits; deltaUnpack must reject any high padding bit (here 0x80).
    {
        struct Pair { int a; int b; };
        const Pair prev{ 1, 2 };
        Pair curr = prev;
        curr.a = 7;                                   // one field changes -> mask = 0b01

        std::uint8_t buf[32];
        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::deltaPack(w, prev, curr);
        assert(w.ok && w.pos >= 1);

        // canonical (uncorrupted) delta still round-trips.
        aether::Reader r{ buf, w.pos, 0 };
        const auto ok = aether::deltaUnpack(r, prev);
        assert(ok && ok->a == 7 && ok->b == 2);

        // corrupt the first (only) mask byte: set a high bit beyond the 2-field count.
        buf[0] |= 0x80;
        aether::Reader rbad{ buf, w.pos, 0 };
        const auto bad = aether::deltaUnpack(rbad, prev);
        assert(!bad);                                 // non-canonical mask -> rejected
    }

    // ---- 3. the memcpy fast path admits only byte-identical fields ----
    // std::optional<int> is trivially copyable and its 8 bytes of memory happen to match what a
    // naive size walk calls its wire size -- but its wire form is a 1-byte flag plus the value only
    // when engaged. A memcpy of it ships the object's spare bytes (whatever was on the stack) and,
    // on decode, drops an arbitrary byte onto the engaged flag, so reading the optional reads a bool
    // holding something other than 0 or 1. Trivially-copyable is not the question the gate asks.
    {
        struct WithOpt  { std::optional<int> o; };
        struct Inner    { std::optional<int> o; };
        struct Nested   { Inner inner; std::uint32_t tail; };
        struct Pod      { std::uint32_t a; std::uint16_t b; std::uint8_t c, d; float e; };
        struct WithEnum { aether::ChannelId ch; std::uint8_t x, y, z; };
        static_assert(!aether::canMemcpySerialize<WithOpt>(), "an optional field must take the portable path");
        static_assert(!aether::canMemcpySerialize<Nested>(),  "an optional nested one level down must too");
        static_assert(aether::canMemcpySerialize<Pod>(),      "a plain POD keeps the memcpy fast path");
        static_assert(aether::canMemcpySerialize<WithEnum>(), "an enum with a fixed underlying type keeps it");

        // serialize() and writeAny() must agree byte for byte: the memcpy path is a substitute for
        // the per-field writes, not a second wire format.
        const WithOpt none{};
        const WithOpt some{ 0x1234 };
        std::uint8_t fast[16], slow[16];
        aether::Writer wf{ fast, sizeof fast, 0, true };
        aether::Writer ws{ slow, sizeof slow, 0, true };
        aether::serialize(wf, none);
        aether::writeAny(ws, none);
        assert(wf.ok && ws.ok);
        assert(wf.pos == 1 && ws.pos == 1);                       // one flag byte, not sizeof(optional<int>)
        assert(std::memcmp(fast, slow, wf.pos) == 0);

        aether::Writer wsome{ fast, sizeof fast, 0, true };
        aether::serialize(wsome, some);
        assert(wsome.ok && wsome.pos == 5);                       // flag + 4-byte value
        aether::Reader rsome{ fast, wsome.pos, 0 };
        const auto backSome = aether::deserialize<WithOpt>(rsome);
        assert(backSome && backSome->o && *backSome->o == 0x1234);

        // the raw memory image of a disengaged optional is not a valid encoding of anything
        const std::uint8_t residue[] = { 0xAA, 0xBB, 0xCC, 0xDD, 0x02, 0x00, 0x00, 0x00 };
        aether::Reader rres{ residue, sizeof residue, 0 };
        const auto fromResidue = aether::deserialize<WithOpt>(rres);
        assert(!fromResidue);
    }

    // ---- 4. a zero-field reflection is believable only for an empty struct ----
    // Every other field count is cross-checked by its structured binding, which fails to compile if
    // the arity is wrong. The n==0 branch has no binding, so a shape whose first probe fails (a
    // reference member, a private member, a base class, a user-declared constructor) counts 0 and
    // would serialize as zero bytes with nothing anywhere to catch it. tieFields static_asserts on
    // exactly that, and a static_assert cannot be instantiated from a test that still compiles; what
    // is pinned here is the positive side -- a plain aggregate counts and writes every field, and an
    // empty struct still reflects as 0.
    {
        struct Plain { int hp; int x; int y; };
        struct Empty {};
        static_assert(aether::fieldCount<Plain>() == 3, "a plain 3-field aggregate reflects 3 fields");
        static_assert(aether::fieldCount<Empty>() == 0, "an empty struct reflects 0 fields");

        std::uint8_t buf[32];
        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::serialize(w, Plain{ 7, 8, 9 });
        assert(w.ok && w.pos == 12);                              // 3 * 4 bytes, not 0
        aether::Writer we{ buf, sizeof buf, 0, true };
        aether::serialize(we, Empty{});
        assert(we.ok && we.pos == 0);
    }

    // ---- 5. an enum decodes over the whole range its underlying type can hold ----
    // ChannelId is `enum class ChannelId : std::uint8_t {}`: a fixed underlying type makes it total
    // over that type, so all 256 byte values are valid and none may be rejected. An enum with NO
    // fixed underlying type stops at its largest enumerator and casting past it is undefined -- both
    // decoders now refuse that shape at compile time, so it cannot appear in this suite.
    {
        struct Msg { aether::ChannelId ch; bool flag; };           // bool keeps it off the memcpy path
        for (int raw = 0; raw < 256; ++raw) {
            const std::uint8_t bytes[2] = { static_cast<std::uint8_t>(raw), 1 };
            aether::Reader r{ bytes, sizeof bytes, 0 };
            const auto got = aether::deserialize<Msg>(r);
            assert(got && aether::toInt(got->ch) == raw && got->flag);
        }
        // the bit path packs the enum at its underlying width and must accept the same full range
        for (const int raw : { 0, 1, 200, 255 }) {
            const Msg in{ static_cast<aether::ChannelId>(raw), false };
            std::uint8_t bits[4];
            aether::BitWriter bw{ bits, sizeof bits };
            const std::size_t n = aether::packBits(bw, in);
            assert(bw.ok);
            aether::BitReader br{ bits, n };
            const auto got = aether::unpackBits<Msg>(br);
            assert(got && aether::toInt(got->ch) == raw && !got->flag);
        }
    }

    // ---- 6. the optional flag and bool accept 0 and 1, nothing else ----
    // The encoder writes 0 or 1, so any other byte is a second spelling of a value this library
    // would never produce -- 255 wire forms for one bool. varint.hpp and delta.hpp already reject
    // their non-canonical forms; these two are the same rule.
    {
        struct S { std::optional<std::uint16_t> o; bool b; };
        const std::uint8_t engaged[]    = { 0x01, 0x34, 0x12, 0x01 };
        const std::uint8_t disengaged[] = { 0x00, 0x00 };
        const std::uint8_t badFlag[]    = { 0x02, 0x34, 0x12, 0x01 };
        const std::uint8_t badBool[]    = { 0x00, 0x02 };

        aether::Reader r1{ engaged, sizeof engaged, 0 };
        const auto v1 = aether::deserialize<S>(r1);
        assert(v1 && v1->o && *v1->o == 0x1234 && v1->b);
        aether::Reader r2{ disengaged, sizeof disengaged, 0 };
        const auto v2 = aether::deserialize<S>(r2);
        assert(v2 && !v2->o && !v2->b);
        aether::Reader r3{ badFlag, sizeof badFlag, 0 };
        const auto v3 = aether::deserialize<S>(r3);
        assert(!v3);                                              // flag byte 2 is not a canonical "engaged"
        aether::Reader r4{ badBool, sizeof badBool, 0 };
        const auto v4 = aether::deserialize<S>(r4);
        assert(!v4);                                              // nor is bool byte 2 a canonical "true"
    }

    // ---- 7. an out-of-range fragment index buffers nothing and evicts nothing ----
    // index >= count belongs to no message: it can never be stored, so an entry made for it holds no
    // data, charges 0 against the byte cap, and is invisible to it -- while still taking one of the
    // maxBuffers slots. maxBuffers is 1 here, so if the bogus fragment reached the buffer-creation
    // step at all it would evict the live assembly and that assembly could never complete.
    {
        auto a = aether::newFragmentAssembler(5000.0, 4096, 1);
        std::uint8_t first[7];
        aether::writeFragmentHeader(first, aether::FragmentHeader{ aether::MessageId{ 7 }, 0, 2 });
        first[6] = 0xAA;
        const auto partial = aether::processFragment(a, first, sizeof first, aether::MonoTime{ 0 });
        assert(!partial && a.buffers.size() == 1);
        const std::size_t chargedAfterFirst = a.currentSize;

        std::uint8_t bogus[7];
        aether::writeFragmentHeader(bogus, aether::FragmentHeader{ aether::MessageId{ 9 }, 5, 2 });   // index 5 of 2
        bogus[6] = 0xBB;
        const auto rejected = aether::processFragment(a, bogus, sizeof bogus, aether::MonoTime{ 0 });
        assert(!rejected);
        assert(a.buffers.size() == 1);                            // no entry created for message 9
        assert(a.buffers.count(aether::MessageId{ 9 }) == 0);
        assert(a.currentSize == chargedAfterFirst);               // nothing charged, nothing evicted

        std::uint8_t second[7];
        aether::writeFragmentHeader(second, aether::FragmentHeader{ aether::MessageId{ 7 }, 1, 2 });
        second[6] = 0xCC;
        const auto done = aether::processFragment(a, second, sizeof second, aether::MonoTime{ 0 });
        assert(done && done->size() == 2 && (*done)[0] == 0xAA && (*done)[1] == 0xCC);
        assert(a.buffers.empty() && a.currentSize == 0);
    }

    // ---- 8. a container length is written through its 4-byte prefix exactly ----
    // A size past 2^32-1 does not fit the prefix, and truncating it would ship a count that
    // disagrees with the bytes that follow; the write fails (w.ok goes false) instead. Building a
    // >4GiB container is not something a test can do, so what is pinned here is the prefix itself:
    // ordinary lengths are written whole and little-endian, and round-trip.
    {
        struct S { std::string s; std::vector<std::uint16_t> v; };
        const S in{ "abc", { 1, 2 } };
        std::uint8_t buf[32];
        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::serialize(w, in);
        assert(w.ok && w.pos == 4 + 3 + 4 + 4);                   // len + "abc" + len + 2 * uint16
        assert(buf[0] == 3 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0);
        assert(buf[7] == 2 && buf[8] == 0 && buf[9] == 0 && buf[10] == 0);
        aether::Reader r{ buf, w.pos, 0 };
        const auto back = aether::deserialize<S>(r);
        assert(back && back->s == "abc" && back->v.size() == 2 && back->v[0] == 1 && back->v[1] == 2);
    }

    std::printf("aether serialize-dyn OK: nested-dynamic (empty string/vector) round-trips; non-canonical delta "
                "changemask, optional flag and bool rejected; memcpy gate excludes optional fields; enum decode "
                "total over its underlying type; out-of-range fragment index buffers nothing\n");
    return 0;
}
