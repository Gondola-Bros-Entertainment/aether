#include "check.hpp"
#include "aether/delta.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <vector>

using namespace aether;

struct Empty {};
struct NestedEmpty { Empty a; Empty b; };
enum class SmallEnum : std::uint8_t { Zero };

template<class T> void zeroByteRoundTrip() {
    const std::vector<T> original(5);
    std::uint8_t bytes[32]{};
    for (bool compact : { false, true }) {
        Writer w{bytes, sizeof bytes};
        if (compact) pack(w, original); else serialize(w, original);
        aether::test::require(w.ok && w.pos == (compact ? 1 : 4));
        Reader r{bytes, w.pos};
        const auto result = compact ? unpack<std::vector<T>>(r) : deserialize<std::vector<T>>(r);
        aether::test::require(result && result->size() == original.size() && r.pos == w.pos);
        Reader tooLittleWork{bytes, w.pos};
        tooLittleWork.workBudget = 5; // vector itself plus five elements requires at least six visits
        aether::test::require(!(compact ? unpack<std::vector<T>>(tooLittleWork) : deserialize<std::vector<T>>(tooLittleWork)));
        Reader tooLittleMemory{bytes, w.pos};
        tooLittleMemory.allocBudget = 4 * sizeof(T);
        aether::test::require(!(compact ? unpack<std::vector<T>>(tooLittleMemory) : deserialize<std::vector<T>>(tooLittleMemory)));
    }
}

template<class T> void integerBounds() {
    std::uint8_t bytes[16]{};
    for (const T value : { std::numeric_limits<T>::min(), std::numeric_limits<T>::max() }) {
        Writer w{bytes, sizeof bytes};
        pack(w, value);
        Reader r{bytes, w.pos};
        aether::test::require(unpack<T>(r) == value);
    }
    if constexpr (sizeof(T) < 8) {
        Writer w{bytes, sizeof bytes};
        if constexpr (std::is_signed_v<T>) writeVarU(w, zigzag(std::int64_t{std::numeric_limits<T>::max()} + 1));
        else writeVarU(w, std::uint64_t{std::numeric_limits<T>::max()} + 1);
        Reader r{bytes, w.pos};
        aether::test::require(!unpack<T>(r));
        if constexpr (std::is_signed_v<T>) {
            w.pos = 0;
            writeVarU(w, zigzag(std::int64_t{std::numeric_limits<T>::min()} - 1));
            Reader below{bytes, w.pos};
            aether::test::require(!unpack<T>(below));
        }
    }
}

int main() {
    zeroByteRoundTrip<Empty>();
    zeroByteRoundTrip<NestedEmpty>();
    zeroByteRoundTrip<std::array<Empty, 3>>();
    integerBounds<std::int8_t>(); integerBounds<std::uint8_t>();
    integerBounds<std::int16_t>(); integerBounds<std::uint16_t>();
    integerBounds<std::int32_t>(); integerBounds<std::uint32_t>();
    integerBounds<std::int64_t>(); integerBounds<std::uint64_t>();
    std::uint8_t bytes[16]{};
    Writer w{bytes, sizeof bytes};
    writeVarU(w, 257);
    Reader integer{bytes, w.pos};
    Reader enumeration{bytes, w.pos};
    aether::test::require(!unpack<std::uint8_t>(integer));
    aether::test::require(!unpack<SmallEnum>(enumeration));
    // Tiny wire input must not request unbounded zero-byte decode work or allocations.
    for (bool compact : { false, true }) {
        w.pos = 0;
        if (compact) writeVarU(w, std::uint64_t{1} << 32); else write(w, std::uint32_t{1} << 30);
        Reader hostile{bytes, w.pos};
        aether::test::require(!(compact ? unpack<std::vector<Empty>>(hostile) : deserialize<std::vector<Empty>>(hostile)));
        aether::test::require(hostile.allocBudget == defaultDecodeAllocBudget);
    }
    // The delta path uses the same narrowing checks, and does not mutate its baseline on failure.
    struct Tiny { std::uint8_t value; };
    w.pos = 0; write(w, std::uint8_t{1}); writeVarU(w, 257);
    Reader delta{bytes, w.pos};
    const Tiny baseline{7};
    aether::test::require(!deltaUnpack(delta, baseline) && baseline.value == 7);
}
