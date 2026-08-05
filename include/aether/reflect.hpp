// aether - the reflection base layer. Aggregate reflection over structured bindings: no macros,
// no codegen. Provides fieldCount, the isStd* traits, tieFields, forEachField, and the byte-exact
// writeAny/readAny that the rest of the serializer builds on. Works for any aggregate of
// primitives, enums, std::array, and nested aggregates (plus string/vector/optional fields).
#pragma once

#include "aether/serialize.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace aether {
namespace detail {

// Convertible to anything; used only in unevaluated context to probe field count. The body is
// never evaluated (the probe lives in requires-expressions), but it must be DEFINED, not just
// declared: probing a struct with optional/vector fields instantiates this operator during
// overload resolution, and a declared-only inline would trip -Wundefined-inline.
struct Any {
    template <class T> constexpr operator T() const noexcept { return T{}; }
};

// Cap probing one past the supported field max: a struct that brace-inits beyond this -- a genuine
// >32-field aggregate, or a raw C-array member that the probe mis-counts element-by-element -- stops
// here instead of recursing toward constexpr-stack exhaustion. tieFields then static_asserts with a
// clear message. Must match the AETHER_BIND ladder max in tieFields.
inline constexpr std::size_t maxReflectFields = 32;
template <class T, class... Probes>
constexpr std::size_t countFields() noexcept {
    if      constexpr (sizeof...(Probes) > maxReflectFields)      return sizeof...(Probes);
    else if constexpr (requires { T{ Probes{}..., Any{} }; })     return countFields<T, Probes..., Any>();
    else                                                          return sizeof...(Probes);
}

// True for an enum with a fixed underlying type: every `enum class`, and `enum E : U`. Such an enum
// is total over that type -- every bit pattern the underlying type can hold is a value of the enum
// -- so a decoded integer needs no range check. An enum WITHOUT one holds only the values its
// enumerators span (bounded by the bit width of the largest, not by the underlying type), a range
// reflection cannot see, and casting anything outside it is undefined behaviour. The probe is
// direct-list-initialization from the underlying type, well-formed only for the fixed form.
template <class E, bool = std::is_enum_v<E>>
inline constexpr bool enumHasFixedUnderlying = false;
template <class E>
inline constexpr bool enumHasFixedUnderlying<E, true> = requires { E{ std::underlying_type_t<E>{} }; };

// dynamic-field detection (length-prefixed on the wire): string, vector, optional.
template <class T>           inline constexpr bool isStdString   = std::is_same_v<std::remove_cvref_t<T>, std::string>;
template <class>             inline constexpr bool isStdVector   = false;
template <class U, class A>  inline constexpr bool isStdVector<std::vector<U, A>> = true;
template <class>             inline constexpr bool isStdOptional = false;
template <class U>           inline constexpr bool isStdOptional<std::optional<U>> = true;

// Cap the up-front reserve when decoding a length-prefixed vector from untrusted bytes, so a hostile
// element COUNT cannot inflate the allocation: reserve at most ~64KB worth of elements (one minimum),
// then grow as elements actually decode. The caller bounds the count to the remaining byte budget, so
// element count is bounded by input size. This caps only the RESERVE; total decoded object memory is
// bounded separately by the Reader's allocBudget (serialize.hpp), because element count says nothing
// about resident size once an element can cost more memory than it costs wire.
inline constexpr std::size_t decodeReserveByteBudget = std::size_t{ 64 } * 1024;
template <class E> constexpr std::size_t decodeReserveCount(std::uint64_t n) noexcept {
    constexpr std::size_t cap = sizeof(E) >= decodeReserveByteBudget ? 1 : decodeReserveByteBudget / sizeof(E);
    return n < cap ? static_cast<std::size_t>(n) : cap;
}

// A string/vector goes on the wire as a 4-byte length followed by its elements. A size past
// 2^32-1 does not fit that prefix, and a truncated prefix would disagree with the bytes that
// follow -- a length no decoder could reconcile -- so fail the write instead. No datagram can
// carry such a container, but serialize() is a public entry point and takes whatever it is given.
inline bool writeLengthPrefix(Writer& w, std::size_t n) noexcept {
    if (static_cast<std::uint64_t>(n) > 0xFFFFFFFFull) { w.ok = false; return false; }
    write(w, static_cast<std::uint32_t>(n));
    return w.ok;
}

} // namespace detail

// Number of fields in an aggregate.
template <class T>
constexpr std::size_t fieldCount() noexcept {
    return detail::countFields<std::remove_cvref_t<T>>();
}

// Bind an aggregate's fields as a tuple of references -- the SINGLE source of the fixed-arity
// decomposition that everything field-wise builds on (forEachField, forEachFieldPair,
// fieldEqual, the delta walk). C++20 has no variadic structured binding (binding packs are
// C++26, P1061), so each field count needs its own case -- exactly what boost.pfr generates.
// The local AETHER_BIND macro keeps each case to one line; the cap is just the last line, so
// raising it is adding lines. With C++26 static reflection this whole body becomes one loop and
// not a single caller changes.
#define AETHER_BIND(N, ...) else if constexpr (n == N) { auto&& [__VA_ARGS__] = t; return std::tie(__VA_ARGS__); }
template <class T>
constexpr auto tieFields(T&& t) {
    constexpr std::size_t n = fieldCount<T>();
    // 0 is believable only for an empty struct. Every other count is cross-checked by its
    // structured binding, which fails to compile if the arity is wrong -- this branch has no
    // binding, so a miscount here would pass silently and the type would serialize as nothing.
    // The count is 0 whenever the very first probe (T{Any{}}) does not compile: a reference
    // member, a private or protected member, a base class, or a user-declared constructor.
    if constexpr (n == 0) {
        static_assert(std::is_empty_v<std::remove_cvref_t<T>>,
                      "aether::tieFields: this type reflects as 0 fields but is not empty, so the field-count "
                      "probe cannot brace-initialize it -- it would serialize as zero bytes. A reference member, "
                      "a private/protected member, a base class, or a user-declared constructor each do this. "
                      "Make it a plain aggregate of values.");
        (void)t; return std::tuple<>{};
    }
    AETHER_BIND(1,  m0)
    AETHER_BIND(2,  m0,m1)
    AETHER_BIND(3,  m0,m1,m2)
    AETHER_BIND(4,  m0,m1,m2,m3)
    AETHER_BIND(5,  m0,m1,m2,m3,m4)
    AETHER_BIND(6,  m0,m1,m2,m3,m4,m5)
    AETHER_BIND(7,  m0,m1,m2,m3,m4,m5,m6)
    AETHER_BIND(8,  m0,m1,m2,m3,m4,m5,m6,m7)
    AETHER_BIND(9,  m0,m1,m2,m3,m4,m5,m6,m7,m8)
    AETHER_BIND(10, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9)
    AETHER_BIND(11, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10)
    AETHER_BIND(12, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11)
    AETHER_BIND(13, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12)
    AETHER_BIND(14, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13)
    AETHER_BIND(15, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14)
    AETHER_BIND(16, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15)
    AETHER_BIND(17, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16)
    AETHER_BIND(18, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17)
    AETHER_BIND(19, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18)
    AETHER_BIND(20, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19)
    AETHER_BIND(21, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20)
    AETHER_BIND(22, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21)
    AETHER_BIND(23, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22)
    AETHER_BIND(24, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23)
    AETHER_BIND(25, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24)
    AETHER_BIND(26, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25)
    AETHER_BIND(27, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25,m26)
    AETHER_BIND(28, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25,m26,m27)
    AETHER_BIND(29, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25,m26,m27,m28)
    AETHER_BIND(30, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25,m26,m27,m28,m29)
    AETHER_BIND(31, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25,m26,m27,m28,m29,m30)
    AETHER_BIND(32, m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,m16,m17,m18,m19,m20,m21,m22,m23,m24,m25,m26,m27,m28,m29,m30,m31)
    else { static_assert(n <= 32, "aether::tieFields: this aggregate exposes more than 32 fields to reflection. Either it genuinely has >32 members (add AETHER_BIND lines to raise the cap), or it contains a raw C-array member, which the field-count probe mis-counts element-by-element -- use std::array<T,N> instead (the idiomatic fixed array; it reflects as a single field)."); return std::tuple<>{}; }
}
#undef AETHER_BIND

// Apply f to each field, in declaration order (f gets references).
template <class T, class F>
constexpr void forEachField(T&& t, F&& f) {
    std::apply([&](auto&... fields) { (f(fields), ...); }, tieFields(static_cast<T&&>(t)));
}

// One value at fixed width: enum -> underlying; aggregate -> recurse; bool -> one byte;
// any integral (signed or unsigned, 1/2/4/8 bytes) -> its little-endian bit pattern;
// float/double -> raw. Sign is carried by the bit pattern, so it round-trips exactly.
template <class T> void writeAny(Writer& w, const T& v) {
    if      constexpr (std::is_enum_v<T>)       writeAny(w, static_cast<std::underlying_type_t<T>>(v));
    else if constexpr (detail::isStdString<T>)  { if (detail::writeLengthPrefix(w, v.size())) writeBytes(w, reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }
    else if constexpr (detail::isStdVector<T>)  { if (detail::writeLengthPrefix(w, v.size())) { for (const auto& e : v) writeAny(w, e); } }
    else if constexpr (detail::isStdOptional<T>) { write(w, static_cast<std::uint8_t>(v ? 1 : 0)); if (v) writeAny(w, *v); }
    else if constexpr (std::is_aggregate_v<T>)  forEachField(v, [&](const auto& field) { writeAny(w, field); });
    else if constexpr (std::is_same_v<T, bool>) write(w, static_cast<std::uint8_t>(v ? 1 : 0));
    else if constexpr (std::is_integral_v<T>) {
        using U = std::make_unsigned_t<T>;
        if      constexpr (sizeof(T) == 1) write(w, static_cast<std::uint8_t >(static_cast<U>(v)));
        else if constexpr (sizeof(T) == 2) write(w, static_cast<std::uint16_t>(static_cast<U>(v)));
        else if constexpr (sizeof(T) == 4) write(w, static_cast<std::uint32_t>(static_cast<U>(v)));
        else                               write(w, static_cast<std::uint64_t>(static_cast<U>(v)));
    } else {
        static_assert(std::is_floating_point_v<T> && (sizeof(T) == 4 || sizeof(T) == 8),
                      "aether: this type has no byte-wise wire form. The byte path covers integrals, 32/64-bit "
                      "floats, bool, enums with a fixed underlying type, std::array, nested aggregates, and "
                      "string/vector/optional. A field with a wire contract (Ranged, Quantized) is bit-packed "
                      "instead: pack it with packBits/unpackBits (bitserialize.hpp).");
        write(w, v);   // float, double
    }
}
template <class T> bool readAny(Reader& r, T& v) {
    if constexpr (std::is_enum_v<T>) {
        // A fixed underlying type is what makes the cast below total: the enum can hold every bit
        // pattern of that type, so no wire value is out of range. Reject the other form at compile
        // time rather than cast an untrusted integer into an enum that cannot represent it (UB).
        static_assert(detail::enumHasFixedUnderlying<T>,
                      "aether: a serializable enum needs a fixed underlying type (enum class E, or enum E : "
                      "std::uint8_t). Without one its valid values are bounded by its enumerators, which "
                      "reflection cannot see, so an out-of-range wire value would be undefined behaviour "
                      "instead of a rejected packet.");
        std::underlying_type_t<T> u{};
        if (!readAny(r, u)) return false;
        v = static_cast<T>(u);
        return true;
    } else if constexpr (detail::isStdString<T>) {
        const auto n = read<std::uint32_t>(r);
        if (!n || !has(r, *n)) return false;
        if (!chargeAlloc(r, *n, 1)) return false;
        v.assign(reinterpret_cast<const char*>(r.buf + r.pos), *n);
        r.pos += *n;
        return true;
    } else if constexpr (detail::isStdVector<T>) {
        const auto n = read<std::uint32_t>(r);
        // Count <= remaining bytes bounds the LOOP; charging sizeof(element) bounds the MEMORY, which
        // the byte count alone does not once one wire byte can materialize an arbitrarily large element.
        if (!n || *n > r.len - r.pos) return false;
        if (!chargeAlloc(r, *n, sizeof(typename T::value_type))) return false;
        v.clear();
        v.reserve(detail::decodeReserveCount<typename T::value_type>(*n));   // bounded up-front alloc; grow as elements parse
        for (std::uint32_t k = 0; k < *n; ++k) { typename T::value_type e{}; if (!readAny(r, e)) return false; v.push_back(std::move(e)); }
        return true;
    } else if constexpr (detail::isStdOptional<T>) {
        const auto f = read<std::uint8_t>(r);
        // Canonical forms only: the encoder writes 0 or 1, so every other byte is a second spelling
        // of "engaged" that this library would never produce -- rejected, like varint.hpp rejects an
        // overlong integer and delta.hpp a padded changemask.
        if (!f || *f > 1) return false;
        if (*f) { typename T::value_type tmp{}; if (!readAny(r, tmp)) return false; v = std::move(tmp); }
        else v.reset();
        return true;
    } else if constexpr (std::is_aggregate_v<T>) {
        bool ok = true;
        forEachField(v, [&](auto& field) { if (ok) ok = readAny(r, field); });
        return ok;
    } else if constexpr (std::is_same_v<T, bool>) {
        const auto b = read<std::uint8_t>(r);
        if (!b || *b > 1) return false;   // canonical: one wire form per value, as above
        v = (*b == 1);
        return true;
    } else if constexpr (std::is_integral_v<T>) {
        using U = std::make_unsigned_t<T>;
        std::optional<U> x;
        if      constexpr (sizeof(T) == 1) x = read<std::uint8_t >(r);
        else if constexpr (sizeof(T) == 2) x = read<std::uint16_t>(r);
        else if constexpr (sizeof(T) == 4) x = read<std::uint32_t>(r);
        else                               x = read<std::uint64_t>(r);
        if (!x) return false;
        v = static_cast<T>(*x);
        return true;
    } else {
        static_assert(std::is_floating_point_v<T> && (sizeof(T) == 4 || sizeof(T) == 8),
                      "aether: this type has no byte-wise wire form. The byte path covers integrals, 32/64-bit "
                      "floats, bool, enums with a fixed underlying type, std::array, nested aggregates, and "
                      "string/vector/optional. A field with a wire contract (Ranged, Quantized) is bit-packed "
                      "instead: unpack it with packBits/unpackBits (bitserialize.hpp).");
        const auto x = read<T>(r);   // float, double
        if (!x) return false;
        v = *x;
        return true;
    }
}

// Byte-wise wire size of an aggregate with no dynamic fields (no padding counted) -- used to gate
// the memcpy fast path below.
template <class T> constexpr std::size_t serializedSize() noexcept;
namespace detail {
template <class F> constexpr std::size_t fieldWireSize() noexcept {
    using U = std::remove_cvref_t<F>;
    if      constexpr (std::is_enum_v<U>)       return sizeof(std::underlying_type_t<U>);
    else if constexpr (std::is_same_v<U, bool>) return 1;
    else if constexpr (std::is_aggregate_v<U>)  return aether::serializedSize<U>();
    else                                        return sizeof(U);   // integral / floating-point
}
} // namespace detail
template <class T> constexpr std::size_t serializedSize() noexcept {
    using Tup = decltype(tieFields(std::declval<std::remove_cvref_t<T>&>()));
    return []<std::size_t... I>(std::index_sequence<I...>) constexpr noexcept {
        return (detail::fieldWireSize<std::tuple_element_t<I, Tup>>() + ... + std::size_t{ 0 });
    }(std::make_index_sequence<std::tuple_size_v<Tup>>{});
}

// True if T (recursively) has a field whose byte-wise wire form can differ from its raw memory
// bytes, which forces the whole type onto the portable per-field path. The test is a whitelist,
// because trivially-copyable is NOT the same question: std::optional<int> is trivially copyable,
// occupies 8 bytes of memory, and is 1 or 5 length-prefixed bytes on the wire, so a memcpy of it
// would ship padding and the engaged flag's spare bits and then rebuild the flag from whatever
// arrives (a bool holding 2 is UB the moment it is read). Only these are byte-identical:
//   - an integral or floating-point type at a width writeAny ships whole (bool excluded: it is
//     0/1 on the wire but any nonzero byte in memory)
//   - an enum with a fixed underlying type over such an integral -- with no fixed type, the enum
//     has fewer valid values than its object representation, so a memcpy'd byte pattern could be
//     a value it cannot hold
//   - a nested aggregate whose fields all pass the same test
template <class T> constexpr bool hasNonMemcpyField() noexcept;
namespace detail {
template <class F> constexpr bool fieldBlocksMemcpy() noexcept {
    using U = std::remove_cvref_t<F>;
    if      constexpr (std::is_same_v<U, bool>)     return true;
    else if constexpr (std::is_enum_v<U>)           return !enumHasFixedUnderlying<U> || fieldBlocksMemcpy<std::underlying_type_t<U>>();
    else if constexpr (std::is_integral_v<U>)       return !(sizeof(U) == 1 || sizeof(U) == 2 || sizeof(U) == 4 || sizeof(U) == 8);
    else if constexpr (std::is_floating_point_v<U>) return !(sizeof(U) == 4 || sizeof(U) == 8);
    else if constexpr (std::is_aggregate_v<U> && std::is_trivially_copyable_v<U>) return aether::hasNonMemcpyField<U>();
    else                                            return true;   // optional/string/vector, and any other class type
}
} // namespace detail
template <class T> constexpr bool hasNonMemcpyField() noexcept {
    using Tup = decltype(tieFields(std::declval<std::remove_cvref_t<T>&>()));
    return []<std::size_t... I>(std::index_sequence<I...>) constexpr noexcept {
        return (detail::fieldBlocksMemcpy<std::tuple_element_t<I, Tup>>() || ... || false);
    }(std::make_index_sequence<std::tuple_size_v<Tup>>{});
}

// True when T's byte-wise wire form is bit-identical to its memory image: a trivially copyable
// aggregate whose fields are every one of them byte-identical (see hasNonMemcpyField), with no
// padding, on a little-endian target. Only then is one memcpy a valid (and much faster)
// substitute for the per-field writes -- and the wire stays identical, so a big-endian peer on the
// portable path still interoperates. sizeof == serializedSize is the no-padding test: padding only
// ever adds to sizeof, so the two are equal exactly when nothing anywhere in T is padded.
template <class T> constexpr bool canMemcpySerialize() noexcept {
    using U = std::remove_cvref_t<T>;
    if constexpr (std::is_trivially_copyable_v<U> && std::is_aggregate_v<U>
                  && std::endian::native == std::endian::little && !hasNonMemcpyField<U>())
        return sizeof(U) == serializedSize<U>();
    else
        return false;
}

// The framework API. Any plain struct, in or out, no boilerplate.
template <class T> void serialize(Writer& w, const T& v) {
    if constexpr (canMemcpySerialize<T>()) {
        if (fits(w, sizeof(T))) { std::memcpy(w.buf + w.pos, &v, sizeof(T)); w.pos += sizeof(T); }
    } else {
        writeAny(w, v);
    }
}

template <class T> std::optional<T> deserialize(Reader& r) {
    if constexpr (canMemcpySerialize<T>()) {
        if (!has(r, sizeof(T))) return std::nullopt;
        T v{};
        std::memcpy(&v, r.buf + r.pos, sizeof(T));
        r.pos += sizeof(T);
        return v;
    } else {
        T v{};
        if (readAny(r, v)) return v;
        return std::nullopt;
    }
}

} // namespace aether
