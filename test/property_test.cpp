// aether - property tests: the reflective serializer must roundtrip arbitrary values, not just the
// one happy-path struct. Random structs through serialize/deserialize (floats compared bit-exactly,
// so NaN / inf / denormals all count) and through deltaPack/deltaUnpack. Deterministic (seeded PRNG).
#include <aether/aether.hpp>

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

struct Probe    { std::int32_t a; float b; std::uint64_t c; bool d; std::int16_t e; std::uint8_t f; };
struct IntProbe { std::int32_t a; std::uint64_t b; std::int16_t c; std::uint8_t d; bool e; };

bool floatBitsEqual(float x, float y) {
    std::uint32_t bx = 0, by = 0;
    std::memcpy(&bx, &x, 4);
    std::memcpy(&by, &y, 4);
    return bx == by;
}
bool probeEqual(const Probe& x, const Probe& y) {
    return x.a == y.a && floatBitsEqual(x.b, y.b) && x.c == y.c && x.d == y.d && x.e == y.e && x.f == y.f;
}
bool intProbeEqual(const IntProbe& x, const IntProbe& y) {
    return x.a == y.a && x.b == y.b && x.c == y.c && x.d == y.d && x.e == y.e;
}
std::uint64_t nextU64(std::uint64_t& s) { const auto r = aether::nextRandom(s); s = r.state; return r.output; }

} // namespace

int main() {
    std::uint64_t s = 0xC0FFEE1234ull;
    std::uint8_t buf[256];

    // serialize -> deserialize, arbitrary float bits (NaN / inf / denormal included), compared
    // bit-exactly: serialization must preserve the value exactly.
    for (int i = 0; i < 100000; ++i) {
        Probe a;
        a.a = static_cast<std::int32_t>(nextU64(s));
        const std::uint32_t fb = static_cast<std::uint32_t>(nextU64(s));
        std::memcpy(&a.b, &fb, 4);
        a.c = nextU64(s);
        a.d = (nextU64(s) & 1) != 0;
        a.e = static_cast<std::int16_t>(nextU64(s));
        a.f = static_cast<std::uint8_t>(nextU64(s));

        aether::Writer w{ buf, sizeof buf, 0, true };
        aether::serialize(w, a);
        aether::Reader r{ buf, w.pos, 0 };
        const auto back = aether::deserialize<Probe>(r);
        assert(back && probeEqual(*back, a));
    }

    // delta: deltaPack(prev, cur) then deltaUnpack(prev) reconstructs cur, for arbitrary prev/cur
    // (integer fields, so equality is unambiguous).
    for (int i = 0; i < 100000; ++i) {
        IntProbe p{ static_cast<std::int32_t>(nextU64(s)), nextU64(s), static_cast<std::int16_t>(nextU64(s)), static_cast<std::uint8_t>(nextU64(s)), (nextU64(s) & 1) != 0 };
        IntProbe q{ static_cast<std::int32_t>(nextU64(s)), nextU64(s), static_cast<std::int16_t>(nextU64(s)), static_cast<std::uint8_t>(nextU64(s)), (nextU64(s) & 1) != 0 };

        aether::Writer dw{ buf, sizeof buf, 0, true };
        aether::deltaPack(dw, p, q);
        aether::Reader dr{ buf, dw.pos, 0 };
        const auto back = aether::deltaUnpack(dr, p);
        assert(back && intProbeEqual(*back, q));
    }

    std::printf("aether property OK: 100k serialize roundtrips (floats bit-exact) + 100k delta roundtrips\n");
    return 0;
}
