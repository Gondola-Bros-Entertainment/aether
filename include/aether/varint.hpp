// aether - LEB128 variable-length integers. Small values cost one byte and grow only as
// needed: automatic integer compression with zero annotation. Signed values use zig-zag so
// small magnitudes stay small either way. Byte-oriented, layered on the Writer/Reader.
#pragma once

#include "aether/serialize.hpp"

#include <cstdint>
#include <optional>

namespace aether {

inline void writeVarU(Writer& w, std::uint64_t v) noexcept {
    while (v >= 0x80) {
        write(w, static_cast<std::uint8_t>((v & 0x7Fu) | 0x80u));
        v >>= 7;
    }
    write(w, static_cast<std::uint8_t>(v));
}

inline std::optional<std::uint64_t> readVarU(Reader& r) noexcept {
    std::uint64_t v = 0;
    int shift = 0;
    for (int i = 0; i < 10; ++i) {                 // 10 * 7 = 70 bits covers a full u64
        const auto b = read<std::uint8_t>(r);
        if (!b) return std::nullopt;
        v |= static_cast<std::uint64_t>(*b & 0x7Fu) << shift;
        if ((*b & 0x80u) == 0) return v;
        shift += 7;
    }
    return std::nullopt;                            // overlong encoding
}

// Zig-zag maps signed to unsigned so that small |v| (positive or negative) encode small.
inline std::uint64_t zigzag(std::int64_t v) noexcept {
    const std::uint64_t signMask = v < 0 ? ~std::uint64_t{ 0 } : 0;   // ~0 = all bits set; canonical zigzag does this via (v >> 63)
    return (static_cast<std::uint64_t>(v) << 1) ^ signMask;
}
inline std::int64_t unzigzag(std::uint64_t v) noexcept {
    return static_cast<std::int64_t>(v >> 1) ^ -static_cast<std::int64_t>(v & 1);
}

} // namespace aether
