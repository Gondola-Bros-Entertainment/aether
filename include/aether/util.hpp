// aether - small shared utilities. A deterministic SplitMix-style PRNG for the network simulator
// and tests ONLY (jitter / loss / reorder / dup) -- NEVER for security material: every key, salt,
// token, and nonce comes from the OS CSPRNG in random.hpp. (Sequence comparison lives in types.hpp
// as newer()/sequenceDiff().) Pure, no IO: nextRandom returns the output and the next state.
#pragma once

#include <cstdint>

namespace aether {

inline constexpr std::uint64_t lcgMultiplier = 6364136223846793005ull;
inline constexpr std::uint64_t lcgIncrement  = 1442695040888963407ull;

struct RandomResult { std::uint64_t output{}; std::uint64_t state{}; };

inline RandomResult nextRandom(std::uint64_t s) noexcept {
    const std::uint64_t next = lcgMultiplier * s + lcgIncrement;
    std::uint64_t z = next ^ (next >> 30);
    z *= 0xBF58476D1CE4E5B9ull;
    z ^= z >> 27;
    z *= 0x94D049BB133111EBull;
    z ^= z >> 31;
    return { z, next };
}

inline double randomDouble(std::uint64_t w) noexcept {
    return static_cast<double>(w & 0xFFFFFFFFull) / 4294967296.0;
}

} // namespace aether
