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

    std::printf("aether varint OK: overlong + non-canonical rejected, bit-63 edge + u64 range round-trip, zigzag exact\n");
    return 0;
}
