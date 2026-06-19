// Comparison benchmark (opt-in: -DAETHER_BENCH_COMPARE=ON). aether vs zpp::bits on the same plain
// struct. Both are zero-annotation, reflective, C++20. The headline difference is aether's
// automatic delta -- only the changed fields hit the wire -- which zpp::bits has no analog for.
//
// Measured as a full roundtrip (encode + decode) with the input varied every iteration, so the
// optimizer cannot constant-fold the work away (a constant input makes zpp's trivial-copy memcpy
// vanish into ~0ns, which is not a real number). A float field is the one varied each tick, so
// every format's wire size stays stable.
#include "aether/aether.hpp"

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

template <class T> inline void sink(const T& v) { asm volatile("" : : "m"(v) : "memory"); }

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

    return 0;
}
