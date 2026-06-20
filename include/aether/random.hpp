// aether - cryptographically secure randomness from the OS CSPRNG. Key and nonce material must NOT
// come from the game PRNG (util.hpp), which is fast and deterministic but predictable; this is the
// source for X25519 ephemeral keys and any other secret. Like the socket layer, the declaration is
// here and the definition is in the platform .cpp (getentropy / BCryptGenRandom).
#pragma once

#include <cstddef>
#include <cstdint>

namespace aether {

// Fill out[0..len) with cryptographically secure random bytes.
void secureRandomBytes(std::uint8_t* out, std::size_t len);

// A cryptographically secure 64-bit value (little-endian over 8 CSPRNG bytes), for salts and tokens.
inline std::uint64_t secureRandom64() {
    std::uint8_t b[8];
    secureRandomBytes(b, sizeof b);
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(b[i]) << (8 * i);
    return v;
}

} // namespace aether
