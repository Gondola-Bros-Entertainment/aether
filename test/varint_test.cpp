// varint: pin LEB128 canonical/overlong rejection, full u64 range, and zigzag round-trips.
// readVarU parses untrusted bytes, so the hostile-encoding cases are built explicitly and fed
// through a Reader. Data-first: plain cursors + free functions, assert() is the check.
#include "aether/varint.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>

int main() {
    // overlong: 10 continuation bytes never terminate within the u64 budget -> rejected.
    {
        const std::uint8_t bytes[10] = { 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80 };
        aether::Reader r{ bytes, sizeof bytes, 0 };
        const auto v = aether::readVarU(r);
        assert(!v);   // overlong, no terminator -> nullopt
    }

    // non-canonical: 9 continuation bytes then a 10th carrying bits past bit 63 -> rejected,
    // never silently truncated.
    {
        const std::uint8_t bytes[10] = { 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x7F };
        aether::Reader r{ bytes, sizeof bytes, 0 };
        const auto v = aether::readVarU(r);
        assert(!v);   // 10th byte sets bits 1..6 (would overflow u64) -> nullopt
    }

    // canonical edge: 9 continuation bytes then a 10th = just bit 63 -> accepted.
    {
        const std::uint8_t bytes[10] = { 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x01 };
        aether::Reader r{ bytes, sizeof bytes, 0 };
        const auto v = aether::readVarU(r);
        assert(v && *v == (std::uint64_t{ 1 } << 63));   // only bit 63 set
    }

    // round-trip the boundary values bit-exact through Writer -> Reader.
    {
        const std::uint64_t cases[] = { 0, 1, 0x7F, 0x80, UINT64_MAX };
        for (const std::uint64_t want : cases) {
            std::uint8_t buf[10];
            aether::Writer w{ buf, sizeof buf, 0, true };
            aether::writeVarU(w, want);
            assert(w.ok);
            aether::Reader r{ buf, w.pos, 0 };
            const auto got = aether::readVarU(r);
            assert(got && *got == want && r.pos == w.pos);   // exact value, all bytes consumed
        }
    }

    // zigzag/unzigzag round-trips across the signed range, including the asymmetric extremes.
    {
        const std::int64_t cases[] = { INT64_MIN, INT32_MIN, -1, 0, 1, INT64_MAX };
        for (const std::int64_t want : cases) {
            const std::int64_t got = aether::unzigzag(aether::zigzag(want));
            assert(got == want);
        }
    }

    // Overlong encodings are rejected, not just overflowing ones. `80 ... 00` decodes to 0 in ten
    // bytes, so without this one value has many valid wire forms -- which matters the moment an encoded
    // form is ever hashed, compared, or length-budgeted. The encoder never emits these, and a decoder of
    // untrusted bytes should not accept what it would never produce.
    {
        const std::uint8_t overlong0[] = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
        aether::Reader r0{ overlong0, sizeof overlong0, 0 };
        assert(!aether::readVarU(r0));

        const std::uint8_t overlong1[] = { 0x81, 0x00 };   // 1, written in two bytes instead of one
        aether::Reader r1{ overlong1, sizeof overlong1, 0 };
        assert(!aether::readVarU(r1));

        // The canonical forms of the same values still decode.
        const std::uint8_t zero[] = { 0x00 };
        aether::Reader rz{ zero, sizeof zero, 0 };
        const auto vz = aether::readVarU(rz);
        assert(vz && *vz == 0);

        const std::uint8_t one[] = { 0x01 };
        aether::Reader ro{ one, sizeof one, 0 };
        const auto vo = aether::readVarU(ro);
        assert(vo && *vo == 1);

        // A multi-byte value whose final byte is legitimately non-zero is unaffected.
        const std::uint8_t big[] = { 0x80, 0x01 };   // 128
        aether::Reader rb{ big, sizeof big, 0 };
        const auto vb = aether::readVarU(rb);
        assert(vb && *vb == 128);
    }

    // The decode allocation budget bounds MEMORY, which a wire-length check cannot: one wire byte can
    // materialize an arbitrarily large element, so element count says nothing about resident size.
    {
        aether::Reader r{ nullptr, 0, 0 };
        const std::size_t budget = r.allocBudget;
        assert(budget > 0);
        assert(aether::chargeAlloc(r, 10, 8));                  // ordinary charge
        assert(r.allocBudget == budget - 80);
        assert(!aether::chargeAlloc(r, budget, 1024));          // would exceed -> refused
        assert(r.allocBudget == budget - 80);                   // ...and refusing costs nothing
        assert(!aether::chargeAlloc(r, ~std::uint64_t{ 0 }, 4096));   // the division form cannot overflow
        assert(!aether::chargeAlloc(r, 1, 0));                  // a zero element size is nonsense, not free
    }

    std::printf("aether varint OK: overlong + non-canonical rejected, bit-63 edge + u64 range round-trip, zigzag exact\n");
    return 0;
}
