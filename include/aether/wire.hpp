// aether - wire-contract types. The bit budget for a field lives in its TYPE, so the
// reflective serializer derives the exact wire size with zero annotations. Ranged<T,Lo,Hi>
// sends an integer in just the bits its range needs; Quantized<Lo,Hi,Bits> sends a float
// as fixed point in `Bits` bits. Plain data: a value member, free functions pack it.
#pragma once

#include "aether/bitpack.hpp"

#include <cstdint>
#include <type_traits>

namespace aether {

// An integer constrained to [Lo, Hi]. On the wire it costs exactly bitsForMax(Hi-Lo) bits.
// Implicitly converts to/from T, so it reads like a plain field at the call site.
template <class T, T Lo, T Hi>
struct Ranged {
    static_assert(std::is_integral_v<T>, "Ranged<T>: T must be integral");
    static_assert(Lo <= Hi, "Ranged<Lo,Hi>: Lo must be <= Hi");
    static_assert(bitsForMax(static_cast<std::uint64_t>(Hi) - static_cast<std::uint64_t>(Lo)) <= 32,
                  "Ranged: range too wide (> 32 bits); split the field");

    T value{ Lo };

    constexpr Ranged() = default;
    constexpr Ranged(T v) noexcept : value(v) {}
    constexpr operator T() const noexcept { return value; }
};

// A float in [Lo, Hi] sent as `Bits` of fixed-point precision (a compressed float).
template <float Lo, float Hi, int Bits>
struct Quantized {
    static_assert(Bits > 0 && Bits <= 32, "Quantized<Bits>: 1..32");
    static_assert(Lo < Hi, "Quantized<Lo,Hi>: Lo must be < Hi");

    float value{ Lo };

    constexpr Quantized() = default;
    constexpr Quantized(float v) noexcept : value(v) {}
    constexpr operator float() const noexcept { return value; }
};

// ---- type traits: is this a wire-contract type? ----
template <class>            inline constexpr bool isRangedV    = false;
template <class T, T L, T H> inline constexpr bool isRangedV<Ranged<T, L, H>> = true;
template <class>            inline constexpr bool isQuantizedV = false;
template <float L, float H, int B> inline constexpr bool isQuantizedV<Quantized<L, H, B>> = true;
template <class T> inline constexpr bool isWireType =
    isRangedV<std::remove_cvref_t<T>> || isQuantizedV<std::remove_cvref_t<T>>;

// ---- pack / unpack one wire-contract field ----
template <class T, T Lo, T Hi>
inline void writeWire(BitWriter& w, const Ranged<T, Lo, Hi>& r) noexcept {
    const T v = r.value < Lo ? Lo : (r.value > Hi ? Hi : r.value);   // clamp, never overflow the budget
    const std::uint64_t off = static_cast<std::uint64_t>(v) - static_cast<std::uint64_t>(Lo);
    writeBits(w, static_cast<std::uint32_t>(off),
              bitsForMax(static_cast<std::uint64_t>(Hi) - static_cast<std::uint64_t>(Lo)));
}
template <class T, T Lo, T Hi>
inline void readWire(BitReader& rd, Ranged<T, Lo, Hi>& r) noexcept {
    const std::uint32_t off = readBits(rd, bitsForMax(static_cast<std::uint64_t>(Hi) - static_cast<std::uint64_t>(Lo)));
    r.value = static_cast<T>(static_cast<std::uint64_t>(Lo) + off);
}

template <float Lo, float Hi, int Bits>
inline void writeWire(BitWriter& w, const Quantized<Lo, Hi, Bits>& q) noexcept {
    const float c = q.value < Lo ? Lo : (q.value > Hi ? Hi : q.value);
    const std::uint32_t maxv = Bits >= 32 ? 0xFFFFFFFFu : ((std::uint32_t{1} << Bits) - 1);
    // math in double: static_cast<float>(maxv) rounds 2^32-1 up to 2^32, so at Bits==32 a
    // value of Hi would cast an out-of-range float to uint32 (UB). double holds maxv exactly.
    const double norm = (static_cast<double>(c) - Lo) / (static_cast<double>(Hi) - Lo);
    const std::uint32_t qv = static_cast<std::uint32_t>(norm * maxv + 0.5);
    writeBits(w, qv, Bits);
}
template <float Lo, float Hi, int Bits>
inline void readWire(BitReader& r, Quantized<Lo, Hi, Bits>& q) noexcept {
    const std::uint32_t maxv = Bits >= 32 ? 0xFFFFFFFFu : ((std::uint32_t{1} << Bits) - 1);
    const std::uint32_t qv = readBits(r, Bits);
    q.value = static_cast<float>(static_cast<double>(Lo) + static_cast<double>(qv) / maxv * (static_cast<double>(Hi) - Lo));
}

} // namespace aether
