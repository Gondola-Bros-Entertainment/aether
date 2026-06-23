// aether - fuzz the decoders. Every byte-parsing path is network-facing, so it must survive
// arbitrary and truncated input without crashing -- graceful rejection only, never an out-of-bounds
// read. Deterministic (seeded PRNG) so any failure reproduces. Run under ASan/UBSan it proves there
// is no OOB read on hostile input; the run completing IS the test.
#include <aether/aether.hpp>

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
    const Dyn   dynPrev{ "hello", { 1, 2, 3 }, std::int64_t{ -7 }, { "a", "b" } };

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
    }
    std::printf("aether fuzz OK: 100k iterations of random/truncated bytes (fixed + dynamic decoders), no crash\n");
    return 0;
}
