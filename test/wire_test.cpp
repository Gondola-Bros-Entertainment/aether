// wire-contract arithmetic edges: the non-obvious Ranged/Quantized boundary cases the
// roundtrip smoke test does not cover -- negative Lo, the full int32 span (sign-extension
// cancellation), a zero-bit range (Lo == Hi), and Quantized at the 2^32 endpoint (the
// double math that dodges the uint32 UB). Each value round-trips BitWriter -> BitReader.
// Standalone: assert() is the check, one success line, no framework. Data-first.
#include "aether/bitpack.hpp"
#include "aether/wire.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdio>

// Round-trip a single wire-contract field through the bit cursors and hand back the value.
template <class Field>
static Field roundtrip(const Field& in) {
    std::uint8_t buf[16];
    aether::BitWriter w{ buf, sizeof buf };
    aether::writeWire(w, in);
    const std::size_t n = aether::flushBits(w);
    assert(w.ok);

    aether::BitReader r{ buf, n };
    Field out{};
    aether::readWire(r, out);
    assert(r.ok);
    return out;
}

int main() {
    // Ranged with a negative Lo: the offset is (uint64)v - (uint64)Lo, so a negative low end
    // must still round-trip the endpoints and an interior value exactly.
    {
        using R = aether::Ranged<int, -100, 100>;   // span 200 -> 8 bits
        const int lo  = roundtrip(R{ -100 });
        const int mid = roundtrip(R{ -7 });
        const int hi  = roundtrip(R{ 100 });
        assert(lo == -100 && mid == -7 && hi == 100);
    }

    // Ranged spanning the full int32 range: span = (uint64)INT32_MAX - (uint64)INT32_MIN is
    // exactly 2^32-1 (the two sign-extensions cancel), so this costs exactly 32 bits and the
    // extreme values plus 0 and -1 survive the offset round-trip.
    {
        using R = aether::Ranged<std::int32_t, INT32_MIN, INT32_MAX>;
        // pin the bit cost: a full-int32 field is exactly 32 bits on the wire
        static_assert(aether::bitsForMax(static_cast<std::uint64_t>(INT32_MAX)
                                         - static_cast<std::uint64_t>(INT32_MIN)) == 32,
                      "full int32 Ranged must be 32 bits");
        const std::int32_t lo   = roundtrip(R{ INT32_MIN });
        const std::int32_t hi   = roundtrip(R{ INT32_MAX });
        const std::int32_t zero = roundtrip(R{ 0 });
        const std::int32_t neg1 = roundtrip(R{ -1 });
        assert(lo == INT32_MIN && hi == INT32_MAX && zero == 0 && neg1 == -1);
    }

    // Zero-bit Ranged (Lo == Hi): the value is a constant, costs 0 bits, and decodes back to Lo.
    {
        using R = aether::Ranged<int, 42, 42>;   // span 0 -> 0 bits
        static_assert(aether::bitsForMax(0) == 0, "Lo == Hi must be 0 bits");
        std::uint8_t buf[4];
        aether::BitWriter w{ buf, sizeof buf };
        aether::writeWire(w, R{ 42 });
        const std::size_t n = aether::flushBits(w);
        assert(w.ok && n == 0);   // nothing written for a 0-bit field

        aether::BitReader r{ buf, n };
        R out{ 0 };
        aether::readWire(r, out);
        assert(r.ok && static_cast<int>(out) == 42);   // reconstructed from Lo, no bits read
    }

    // Quantized with Bits == 32: maxv = 2^32-1 done in double (a float cast would round up to
    // 2^32 and make the Hi endpoint an out-of-range uint32 cast -- UB). The endpoints must
    // decode within one quantization step.
    {
        using Q = aether::Quantized<-1.0f, 1.0f, 32>;
        const float step = 2.0f / 4294967295.0f;   // (Hi-Lo)/(2^32-1): the quantization step
        const float eps  = step * 4.0f;            // a few steps; float storage adds ~1e-7 abs here
        const float lo = roundtrip(Q{ -1.0f });
        const float hi = roundtrip(Q{ 1.0f });
        assert(std::fabs(lo - (-1.0f)) < eps);
        assert(std::fabs(hi - 1.0f) < eps);
    }

    std::printf("aether wire-edges OK: negative-Lo, full-int32 (32 bits), zero-bit Ranged, "
                "Quantized<32> endpoints all round-trip\n");
    return 0;
}
