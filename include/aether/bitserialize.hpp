// aether - reflective bit-packed serialization. The fusion: aggregate reflection (define a
// plain struct, no codegen) + bit-packing (wire-contract types cost only the bits
// they need) + a unified field walk. A struct of Ranged/Quantized fields packs into a
// fraction of its byte-aligned size, with zero boilerplate.
#pragma once

#include "aether/bitpack.hpp"
#include "aether/reflect.hpp"
#include "aether/wire.hpp"

#include <bit>
#include <cstdint>
#include <optional>
#include <type_traits>

namespace aether {

// A primitive with no wire contract: full-width bits. bool is 1 bit (lossless and free),
// floats go through their IEEE bit pattern, integers as their natural width.
template <class T> void packPrimitive(BitWriter& w, const T& v) noexcept {
    if constexpr (std::is_same_v<T, bool>) {
        writeBits(w, v ? 1u : 0u, 1);
    } else if constexpr (std::is_floating_point_v<T>) {
        if constexpr (sizeof(T) == 4) {
            writeBits(w, std::bit_cast<std::uint32_t>(v), 32);
        } else {
            const auto u = std::bit_cast<std::uint64_t>(static_cast<double>(v));
            writeBits(w, static_cast<std::uint32_t>(u >> 32), 32);
            writeBits(w, static_cast<std::uint32_t>(u), 32);
        }
    } else {
        static_assert(std::is_integral_v<T>, "packPrimitive: unsupported type");
        const auto u = static_cast<std::make_unsigned_t<T>>(v);
        if constexpr (sizeof(T) <= 4) {
            writeBits(w, static_cast<std::uint32_t>(u), static_cast<int>(sizeof(T)) * 8);
        } else {
            writeBits(w, static_cast<std::uint32_t>(static_cast<std::uint64_t>(u) >> 32), 32);
            writeBits(w, static_cast<std::uint32_t>(u), 32);
        }
    }
}
template <class T> void unpackPrimitive(BitReader& r, T& v) noexcept {
    if constexpr (std::is_same_v<T, bool>) {
        v = readBits(r, 1) != 0;
    } else if constexpr (std::is_floating_point_v<T>) {
        if constexpr (sizeof(T) == 4) {
            v = std::bit_cast<float>(readBits(r, 32));
        } else {
            const std::uint64_t hi = readBits(r, 32), lo = readBits(r, 32);
            v = static_cast<T>(std::bit_cast<double>((hi << 32) | lo));
        }
    } else {
        static_assert(std::is_integral_v<T>, "unpackPrimitive: unsupported type");
        using U = std::make_unsigned_t<T>;
        if constexpr (sizeof(T) <= 4) {
            v = static_cast<T>(static_cast<U>(readBits(r, static_cast<int>(sizeof(T)) * 8)));
        } else {
            const std::uint64_t hi = readBits(r, 32), lo = readBits(r, 32);
            v = static_cast<T>(static_cast<U>((hi << 32) | lo));
        }
    }
}

// One field -> bits. Wire-contract type uses its budget; enum -> underlying width;
// nested aggregate -> recurse; plain primitive -> full width.
template <class T> void packField(BitWriter& w, const T& v) noexcept {
    if      constexpr (isWireType<T>)          writeWire(w, v);
    else if constexpr (std::is_enum_v<T>)      packPrimitive(w, static_cast<std::underlying_type_t<T>>(v));
    else if constexpr (std::is_aggregate_v<T>) forEachField(v, [&](const auto& f) { packField(w, f); });
    else                                       packPrimitive(w, v);
}
template <class T> void unpackField(BitReader& r, T& v) noexcept {
    if constexpr (isWireType<T>) {
        readWire(r, v);
    } else if constexpr (std::is_enum_v<T>) {
        std::underlying_type_t<T> u{};
        unpackPrimitive(r, u);
        v = static_cast<T>(u);
    } else if constexpr (std::is_aggregate_v<T>) {
        forEachField(v, [&](auto& f) { unpackField(r, f); });
    } else {
        unpackPrimitive(r, v);
    }
}

// The framework API. Pack any plain struct into the fewest bits its types allow; returns
// the byte count after flushing the final partial byte. unpackBits is the exact inverse.
template <class T> std::size_t packBits(BitWriter& w, const T& v) noexcept {
    packField(w, v);
    return flushBits(w);
}
template <class T> std::optional<T> unpackBits(BitReader& r) noexcept {
    T v{};
    unpackField(r, v);
    if (!r.ok) return std::nullopt;
    return v;
}

} // namespace aether
