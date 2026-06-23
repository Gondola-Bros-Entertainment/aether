// aether - pins two serializer behaviors an audit flagged:
//   1. nested-dynamic round-trip (the bounded-amplification path): vector<string> /
//      vector<vector<uint8_t>> with empty inner elements pack+unpack exactly.
//   2. non-canonical delta changemask rejection: a high padding bit set beyond the
//      field count in the mask byte makes deltaUnpack return nullopt.
// Standalone, no framework: assert() is the check (so build WITHOUT -DNDEBUG).
#include "aether/delta.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>
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

    std::printf("aether serialize-dyn OK: nested-dynamic (empty string/vector) round-trips; non-canonical delta changemask rejected\n");
    return 0;
}
