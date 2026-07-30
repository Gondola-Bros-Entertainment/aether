// aether - fuzz the decoders. Every byte-parsing path is network-facing, so it must survive
// arbitrary and truncated input without crashing -- graceful rejection only, never an out-of-bounds
// read. Deterministic (seeded PRNG) so any failure reproduces. Run under ASan/UBSan it proves there
// is no OOB read on hostile input; the run completing IS the test.
#include <aether/aether.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

namespace {

struct Probe { std::int32_t a; float b; std::uint64_t c; bool d; std::int16_t e; std::uint8_t f; };

// Dynamic-length fields (string / vector / optional + nested vector<string>) -- the reflective decoder
// paths the fixed-width Probe never reaches. These are exactly where the prior has()-overflow CRITICAL
// hid (an unfuzzed string length), so the hostile-byte sweep must cover them.
struct Dyn { std::string s; std::vector<std::uint32_t> v; std::optional<std::int64_t> o; std::vector<std::string> vs; };

// Wide enough (20 fields) for the ADAPTIVE changemask, so the sparse-index decoder -- mode byte,
// index list, canonical-form rejection -- takes the same hostile-bytes beating as everything else.
struct WideProbe {
    std::uint8_t f00, f01, f02, f03, f04, f05, f06, f07, f08, f09;
    std::uint8_t f10, f11, f12, f13, f14, f15, f16, f17, f18, f19;
};

// The BIT-level path, which the byte-oriented probes above never touch. Every field here has a wire
// contract, so arbitrary bytes must decode to values inside it -- the ranges are deliberately not
// powers of two, so the wire has bit patterns above Hi that a decoder could otherwise let through.
struct BitProbe {
    aether::Ranged<std::uint8_t, 0, 5>    small;    // 3 bits, raw 6 and 7 are out of contract
    aether::Ranged<int, -100, 100>        signed_;  // 8 bits, raw 201..255 out of contract
    aether::Quantized<-1.0f, 1.0f, 12>    q;
    bool                                  flag{};
};

aether::Bytes randomBytes(std::uint64_t& s, std::size_t n) {
    aether::Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) {
        const auto r = aether::nextRandom(s);
        s = r.state;
        b[i] = static_cast<std::uint8_t>(r.output);
    }
    return b;
}

} // namespace

int main() {
    std::uint64_t s = 0xA5A51234DEADull;
    const Probe prev{ 1, 2.0f, 3, true, 4, 5 };
    const Dyn       dynPrev{ "hello", { 1, 2, 3 }, std::int64_t{ -7 }, { "a", "b" } };
    const WideProbe widePrev{};

    for (int i = 0; i < 100000; ++i) {
        const auto lenR = aether::nextRandom(s);
        s = lenR.state;
        const aether::Bytes data = randomBytes(s, static_cast<std::size_t>(lenR.output % 540));   // spans the < and > MTU edges

        // packet-level decoders -- every incoming datagram hits these first
        (void) aether::validateAndStripCrc32(data);
        (void) aether::deserializePacket(data);
        (void) aether::unbatchMessages(data);

        // handshake + rendezvous decoders
        (void) aether::decodeSalt(data);
        (void) aether::decodeSaltAndKey(data);
        (void) aether::decodeDenyReason(data);
        (void) aether::decodeRegister(data);
        (void) aether::decodePaired(data);
        (void) aether::decodeRelay(data);
        (void) aether::deserializeAddr(data.data(), data.size());

        // fragment header parse + reassembly (fresh assembler per input -- this checks per-call safety)
        (void) aether::readFragmentHeader(data.data(), data.size());
        auto frag = aether::newFragmentAssembler(5000.0, 65536, 256);
        (void) aether::processFragment(frag, data.data(), data.size(), aether::MonoTime{ 0 });

        // the reflective serializer, fed raw bytes through a Reader -- fixed-width fields...
        aether::Reader r1{ data.data(), data.size(), 0 };
        (void) aether::deserialize<Probe>(r1);
        aether::Reader r2{ data.data(), data.size(), 0 };
        (void) aether::deltaUnpack(r2, prev);

        // ...and the dynamic-length decoders (string / vector / optional + nested)
        aether::Reader r3{ data.data(), data.size(), 0 };
        (void) aether::deserialize<Dyn>(r3);
        aether::Reader r4{ data.data(), data.size(), 0 };
        (void) aether::deltaUnpack(r4, dynPrev);
        aether::Reader r5{ data.data(), data.size(), 0 };
        (void) aether::deltaUnpack(r5, widePrev);   // the adaptive (sparse-index) mask decoder

        // the bit-packed path: arbitrary bytes must never yield a wire-contract value outside its range.
        // This is an assertion, not just a no-crash sweep -- an out-of-range Ranged is a value the app
        // will index or switch on, so the range is a promise the decoder has to keep on hostile input.
        aether::BitReader br{ data.data(), data.size() };
        if (const auto bits = aether::unpackBits<BitProbe>(br)) {
            assert(bits->small.value <= 5);
            assert(bits->signed_.value >= -100 && bits->signed_.value <= 100);
            assert(bits->q.value >= -1.0f && bits->q.value <= 1.0f);
        }
    }
    std::printf("aether fuzz OK: 100k iterations of random/truncated bytes (fixed + dynamic + bit-packed "
                "decoders), no crash and every wire contract held\n");
    return 0;
}
