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

} // namespace aether
