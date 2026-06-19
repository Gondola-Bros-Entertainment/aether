// aether - serialization benchmark. Races the encode/decode paths on a realistic game
// entity: memcpy (the speed ceiling -- full size, not endian-portable, no validation),
// raw little-endian per field (portable, branchless), varint (smaller ints), and delta vs
// the last snapshot (smallest, and skips the fields that did not change).
//
// Build with -O3. The numbers are nanoseconds per op on THIS machine and cache state --
// read them RELATIVE to each other, not as absolutes. Compiler barrier (asm) is clang/gcc.
#include "aether/delta.hpp"      // pack/unpack (varint), deltaPack/deltaUnpack
#include "aether/reflect.hpp"    // serialize/deserialize (raw little-endian), fieldCount
#include "aether/serialize.hpp"  // Writer/Reader

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

// A realistic replicated entity: position + velocity + a few stats. Trivially copyable, so
// the memcpy path is legal. 12 fields -- a fair real-world size (the cap is 32).
struct Entity {
    float         px, py, pz;
    float         vx, vy, vz;
    int           health;
    int           mana;
    std::uint32_t flags;
    std::uint16_t typeId;
    std::uint8_t  team;
    bool          alive;
};

// Keep the optimizer from deleting work whose result is never observed. The "memory"
// clobber is the real barrier; "m"(v) just names something to anchor it to.
template <class T> inline void sink(const T& v) { asm volatile("" : : "m"(v) : "memory"); }

constexpr int kWarmup = 100000;
constexpr int kIters  = 3000000;

template <class F> double nsPer(F&& body) {
    for (int i = 0; i < kWarmup; ++i) body();
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < kIters; ++i) body();
    const auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::nano>(t1 - t0).count() / static_cast<double>(kIters);
}

} // namespace

int main() {
    Entity e{ 1.5f, 2.5f, 3.5f, 0.1f, -0.2f, 0.3f, 850, 120, 0x00000007u, 42, 1, true };
    Entity prev  = e;
    Entity moved = e;
    moved.px     = 1.6f;          // two of twelve fields move this tick -- a realistic rate
    moved.health = 845;

    std::uint8_t buf[256];

    // measure each format's size once
    aether::Writer ws{ buf, sizeof buf, 0, true }; aether::serialize(ws, e);
    const std::size_t rawBytes = ws.pos;
    aether::Writer wv{ buf, sizeof buf, 0, true }; aether::pack(wv, e);
    const std::size_t varBytes = wv.pos;
    aether::Writer wd{ buf, sizeof buf, 0, true }; aether::deltaPack(wd, prev, moved);
    const std::size_t deltaBytes = wd.pos;

    std::printf("entity: %zu fields, sizeof=%zu bytes, %d iters\n\n",
                aether::fieldCount<Entity>(), sizeof(Entity), kIters);
    std::printf("%-12s %12s %12s %8s\n", "mode", "encode ns", "decode ns", "bytes");
    std::printf("%-12s %12s %12s %8s\n", "----", "---------", "---------", "-----");

    // memcpy: the floor. One wide copy, no per-field work, no validation.
    {
        std::uint8_t b[sizeof(Entity)];
        const double enc = nsPer([&] { std::memcpy(b, &e, sizeof e); sink(b); });
        std::memcpy(b, &e, sizeof e);
        Entity out;
        const double dec = nsPer([&] { std::memcpy(&out, b, sizeof out); sink(out); });
        std::printf("%-12s %12.2f %12.2f %8zu\n", "memcpy", enc, dec, sizeof(Entity));
    }
    // raw little-endian per field: portable, branchless, the compiler merges adjacent stores.
    {
        const double enc = nsPer([&] { aether::Writer w{ buf, sizeof buf, 0, true }; aether::serialize(w, e); sink(buf); });
        aether::Writer w{ buf, sizeof buf, 0, true }; aether::serialize(w, e);
        const double dec = nsPer([&] { aether::Reader r{ buf, rawBytes, 0 }; auto o = aether::deserialize<Entity>(r); sink(o); });
        std::printf("%-12s %12.2f %12.2f %8zu\n", "raw-LE", enc, dec, rawBytes);
    }
    // varint full snapshot: ints shrink, but a data-dependent branch per value.
    {
        const double enc = nsPer([&] { aether::Writer w{ buf, sizeof buf, 0, true }; aether::pack(w, e); sink(buf); });
        aether::Writer w{ buf, sizeof buf, 0, true }; aether::pack(w, e);
        const double dec = nsPer([&] { aether::Reader r{ buf, varBytes, 0 }; auto o = aether::unpack<Entity>(r); sink(o); });
        std::printf("%-12s %12.2f %12.2f %8zu\n", "varint", enc, dec, varBytes);
    }
    // delta vs last snapshot: only the changed fields hit the wire (smallest + least work).
    {
        const double enc = nsPer([&] { aether::Writer w{ buf, sizeof buf, 0, true }; aether::deltaPack(w, prev, moved); sink(buf); });
        aether::Writer w{ buf, sizeof buf, 0, true }; aether::deltaPack(w, prev, moved);
        const double dec = nsPer([&] { aether::Reader r{ buf, deltaBytes, 0 }; auto o = aether::deltaUnpack(r, prev); sink(o); });
        std::printf("%-12s %12.2f %12.2f %8zu\n", "delta 2/12", enc, dec, deltaBytes);
    }

    return 0;
}
