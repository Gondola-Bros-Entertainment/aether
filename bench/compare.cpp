// Comparison benchmark (opt-in: -DAETHER_BENCH_COMPARE=ON). aether vs zpp::bits vs bitsery on the
// same plain struct. aether and zpp::bits are zero-annotation, reflective, C++20; bitsery wants a
// hand-written per-field serialize function in exchange for explicit widths. The headline
// difference is aether's automatic delta -- only the changed fields hit the wire -- which neither
// of the others has an analog for.
//
// Measured as a full roundtrip (encode + decode) with the input varied every iteration, so the
// optimizer cannot constant-fold the work away (a constant input makes zpp's trivial-copy memcpy
// vanish into ~0ns, which is not a real number). A float field is the one varied each tick, so
// every format's wire size stays stable.
#include "aether/aether.hpp"

#include <bitsery/adapter/buffer.h>
#include <bitsery/bitsery.h>
#include <bitsery/traits/array.h>
#include <zpp_bits.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>

namespace {

struct Entity {
    float         px{}, py{}, pz{};
    float         vx{}, vy{}, vz{};
    int           health{};
    int           mana{};
    std::uint32_t flags{};
    std::uint16_t typeId{};
    std::uint8_t  team{};
    bool          alive{};
};

// The per-field annotation bitsery requires (and the reflective libraries do not): every member
// listed by hand, with its wire width. Constrained to archives that have bitsery's value4b
// interface, because zpp::bits probes the SAME free-function name as its own customization point --
// unconstrained, this would hijack zpp's reflective path and feed its archive to bitsery calls.
template <typename S> requires requires(S& s, float f) { s.value4b(f); }
void serialize(S& s, Entity& e) {
    s.value4b(e.px); s.value4b(e.py); s.value4b(e.pz);
    s.value4b(e.vx); s.value4b(e.vy); s.value4b(e.vz);
    s.value4b(e.health);
    s.value4b(e.mana);
    s.value4b(e.flags);
    s.value2b(e.typeId);
    s.value1b(e.team);
    s.value1b(e.alive);
}
using BitseryBuffer = std::array<std::uint8_t, 256>;

template <class T> inline void sink(const T& v) {
#if defined(_MSC_VER)
    volatile char observed = *reinterpret_cast<const volatile char*>(&v);
    (void)observed;
#else
    asm volatile("" : : "m"(v) : "memory");
#endif
}

constexpr int kWarmup = 100000;
constexpr int kIters  = 3000000;

template <class F> double nsPer(F&& body) {
    for (int i = 0; i < kWarmup; ++i) body(i);
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i) body(i);
    const auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::nano>(t1 - t0).count() / static_cast<double>(kIters);
}

} // namespace

int main() {
    Entity e{ 1.5f, 2.5f, 3.5f, 0.1f, -0.2f, 0.3f, 850, 120, 0x7u, 42, 1, true };
    Entity prev  = e;
    Entity moved = e;
    moved.px     = 1.6f;   // two of twelve fields differ this tick (px, health)
    moved.health = 845;

    std::uint8_t buf[256];

    // wire sizes (measured once; varying a float field below keeps them stable)
    aether::Writer wr{ buf, sizeof buf, 0, true }; aether::serialize(wr, e);          const auto rawN   = wr.pos;
    aether::Writer wv{ buf, sizeof buf, 0, true }; aether::pack(wv, e);               const auto varN   = wv.pos;
    aether::Writer wd{ buf, sizeof buf, 0, true }; aether::deltaPack(wd, prev, moved); const auto deltaN = wd.pos;
    std::array<std::byte, 256> zb{};
    std::size_t zN = 0;
    { zpp::bits::out out{ zb }; out(e).or_throw(); zN = out.position(); }
    BitseryBuffer bb{};
    const std::size_t bN = bitsery::quickSerialization(bitsery::OutputBufferAdapter<BitseryBuffer>{ bb }, e);

    std::printf("entity: %zu fields, sizeof=%zu, %d roundtrips\n\n",
                aether::fieldCount<Entity>(), sizeof(Entity), kIters);
    std::printf("%-20s %14s %8s\n", "lib / mode", "roundtrip ns", "bytes");
    std::printf("%-20s %14s %8s\n", "----------", "------------", "-----");

    // aether: full fixed-width little-endian (zero annotation)
    {
        const double t = nsPer([&](int i) {
            e.px = static_cast<float>(i);
            aether::Writer w{ buf, sizeof buf, 0, true }; aether::serialize(w, e);
            aether::Reader r{ buf, w.pos, 0 }; auto o = aether::deserialize<Entity>(r); sink(o);
        });
        std::printf("%-20s %14.2f %8zu\n", "aether raw-LE", t, rawN);
    }
    // aether: full varint (zero annotation)
    {
        const double t = nsPer([&](int i) {
            e.px = static_cast<float>(i);
            aether::Writer w{ buf, sizeof buf, 0, true }; aether::pack(w, e);
            aether::Reader r{ buf, w.pos, 0 }; auto o = aether::unpack<Entity>(r); sink(o);
        });
        std::printf("%-20s %14.2f %8zu\n", "aether varint", t, varN);
    }
    // aether: automatic delta vs the last snapshot (the differentiator -- 2/12 fields changed)
    {
        const double t = nsPer([&](int i) {
            moved.px = static_cast<float>(i);
            aether::Writer w{ buf, sizeof buf, 0, true }; aether::deltaPack(w, prev, moved);
            aether::Reader r{ buf, w.pos, 0 }; auto o = aether::deltaUnpack(r, prev); sink(o);
        });
        std::printf("%-20s %14.2f %8zu\n", "aether delta 2/12", t, deltaN);
    }
    // zpp::bits: full fixed-width (zero annotation) -- no delta analog
    {
        const double t = nsPer([&](int i) {
            e.px = static_cast<float>(i);
            zpp::bits::out out{ zb }; out(e).or_throw();
            zpp::bits::in in{ zb }; Entity o; in(o).or_throw(); sink(o);
        });
        std::printf("%-20s %14.2f %8zu\n", "zpp::bits", t, zN);
    }
    // bitsery: full fixed-width (hand-annotated serialize) -- no delta analog
    {
        const double t = nsPer([&](int i) {
            e.px = static_cast<float>(i);
            const std::size_t n = bitsery::quickSerialization(bitsery::OutputBufferAdapter<BitseryBuffer>{ bb }, e);
            Entity o{};
            const auto st = bitsery::quickDeserialization(bitsery::InputBufferAdapter<BitseryBuffer>{ bb.begin(), n }, o);
            sink(st); sink(o);
        });
        std::printf("%-20s %14.2f %8zu\n", "bitsery", t, bN);
    }

    return 0;
}
