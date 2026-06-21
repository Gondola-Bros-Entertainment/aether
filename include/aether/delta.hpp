// aether - the magic path. Define a plain struct; aether reflects it, varint-packs the
// primitives, and (the part nobody ships standalone) computes a delta against the previous
// snapshot so only the fields that CHANGED go on the wire. Zero annotations, zero codegen,
// the developer never thinks about bits or deltas. Data-first: free functions over plain T.
#pragma once

#include "aether/reflect.hpp"
#include "aether/varint.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace aether {

// Apply f(aField, bField) to corresponding fields of two same-typed aggregates -- built on
// tieFields, so it shares the single arity source (no duplicated decomposition).
template <class T, class F>
constexpr void forEachFieldPair(const T& a, const T& b, F&& f) {
    auto ta = tieFields(a);
    auto tb = tieFields(b);
    [&]<std::size_t... I>(std::index_sequence<I...>) {
        (f(std::get<I>(ta), std::get<I>(tb)), ...);
    }(std::make_index_sequence<std::tuple_size_v<decltype(ta)>>{});
}

// Deep field equality: primitives compare directly, nested aggregates recurse.
template <class T> bool fieldEqual(const T& a, const T& b) {
    if constexpr (std::is_enum_v<T>) {
        return a == b;
    } else if constexpr (std::is_aggregate_v<T>) {
        bool eq = true;
        forEachFieldPair(a, b, [&](const auto& x, const auto& y) { if (eq) eq = fieldEqual(x, y); });
        return eq;
    } else if constexpr (std::is_floating_point_v<T>) {
        // Compare floats by bit pattern so the changemask is bit-exact with the full path: value
        // equality would call +0.0 and -0.0 equal (silently dropping a sign flip the receiver
        // cannot reconstruct) and NaN never-equal (re-sending it every tick).
        if      constexpr (sizeof(T) == 4) return std::bit_cast<std::uint32_t>(a) == std::bit_cast<std::uint32_t>(b);
        else if constexpr (sizeof(T) == 8) return std::bit_cast<std::uint64_t>(a) == std::bit_cast<std::uint64_t>(b);
        else                               return a == b;
    } else {
        return a == b;
    }
}

// --- full snapshot: varint-packed, zero annotation ---
template <class T> void packValue(Writer& w, const T& v) {
    if      constexpr (std::is_enum_v<T>)           packValue(w, static_cast<std::underlying_type_t<T>>(v));
    else if constexpr (detail::isStdString<T>)      { writeVarU(w, v.size()); writeBytes(w, reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }
    else if constexpr (detail::isStdVector<T>)      { writeVarU(w, v.size()); for (const auto& f : v) packValue(w, f); }
    else if constexpr (detail::isStdOptional<T>)    { write(w, static_cast<std::uint8_t>(v ? 1 : 0)); if (v) packValue(w, *v); }
    else if constexpr (std::is_aggregate_v<T>)      forEachField(v, [&](const auto& f) { packValue(w, f); });
    else if constexpr (std::is_same_v<T, bool>)     write(w, static_cast<std::uint8_t>(v ? 1 : 0));
    else if constexpr (std::is_floating_point_v<T>) { static_assert(sizeof(T) == 4 || sizeof(T) == 8, "aether: only 32/64-bit floats are serializable"); write(w, v); }   // varint can't help a float
    else {
        static_assert(std::is_integral_v<T>, "packValue: unsupported type");
        if constexpr (std::is_signed_v<T>) writeVarU(w, zigzag(static_cast<std::int64_t>(v)));
        else                               writeVarU(w, static_cast<std::uint64_t>(v));
    }
}
template <class T> bool unpackValue(Reader& r, T& v) {
    if constexpr (std::is_enum_v<T>) {
        std::underlying_type_t<T> u{};
        if (!unpackValue(r, u)) return false;
        v = static_cast<T>(u);
        return true;
    } else if constexpr (detail::isStdString<T>) {
        const auto n = readVarU(r);
        if (!n || !has(r, static_cast<std::size_t>(*n))) return false;
        v.assign(reinterpret_cast<const char*>(r.buf + r.pos), static_cast<std::size_t>(*n));
        r.pos += static_cast<std::size_t>(*n);
        return true;
    } else if constexpr (detail::isStdVector<T>) {
        const auto n = readVarU(r);
        if (!n || *n > r.len - r.pos) return false;   // each element is >= 1 byte, so count <= remaining bytes
        v.clear();
        v.reserve(detail::decodeReserveCount<typename T::value_type>(*n));   // bounded up-front alloc; grow as elements parse
        for (std::uint64_t k = 0; k < *n; ++k) { typename T::value_type e{}; if (!unpackValue(r, e)) return false; v.push_back(std::move(e)); }
        return true;
    } else if constexpr (detail::isStdOptional<T>) {
        const auto f = read<std::uint8_t>(r);
        if (!f) return false;
        if (*f) { typename T::value_type tmp{}; if (!unpackValue(r, tmp)) return false; v = std::move(tmp); }
        else v.reset();
        return true;
    } else if constexpr (std::is_aggregate_v<T>) {
        bool ok = true;
        forEachField(v, [&](auto& f) { if (ok) ok = unpackValue(r, f); });
        return ok;
    } else if constexpr (std::is_same_v<T, bool>) {
        const auto b = read<std::uint8_t>(r);
        if (!b) return false;
        v = (*b != 0);
        return true;
    } else if constexpr (std::is_floating_point_v<T>) {
        static_assert(sizeof(T) == 4 || sizeof(T) == 8, "aether: only 32/64-bit floats are serializable");
        const auto x = read<T>(r);
        if (!x) return false;
        v = *x;
        return true;
    } else {
        static_assert(std::is_integral_v<T>, "unpackValue: unsupported type");
        const auto u = readVarU(r);
        if (!u) return false;
        if constexpr (std::is_signed_v<T>) v = static_cast<T>(unzigzag(*u));
        else                               v = static_cast<T>(*u);
        return true;
    }
}

template <class T> void pack(Writer& w, const T& v) { packValue(w, v); }
template <class T> std::optional<T> unpack(Reader& r) {
    T v{};
    if (unpackValue(r, v)) return v;
    return std::nullopt;
}

// --- delta snapshot: changemask (one bit per top-level field) + only changed fields ---
template <class T> void deltaPack(Writer& w, const T& prev, const T& curr) {
    constexpr std::size_t n         = fieldCount<T>();
    constexpr std::size_t maskBytes = (n + 7) / 8;
    std::uint8_t mask[maskBytes ? maskBytes : 1] = {};

    std::size_t i = 0;
    forEachFieldPair(prev, curr, [&](const auto& p, const auto& c) {
        if (!fieldEqual(p, c)) mask[i >> 3] |= static_cast<std::uint8_t>(1u << (i & 7));
        ++i;
    });
    writeBytes(w, mask, maskBytes);

    i = 0;
    forEachFieldPair(prev, curr, [&](const auto& p, const auto& c) {
        (void)p;
        if (mask[i >> 3] & (1u << (i & 7))) packValue(w, c);
        ++i;
    });
}
template <class T> std::optional<T> deltaUnpack(Reader& r, const T& prev) {
    constexpr std::size_t n         = fieldCount<T>();
    constexpr std::size_t maskBytes = (n + 7) / 8;
    std::uint8_t mask[maskBytes ? maskBytes : 1] = {};
    if (!readBytes(r, mask, maskBytes)) return std::nullopt;

    T curr = prev;                                  // unchanged fields inherit the baseline
    bool ok = true;
    std::size_t i = 0;
    forEachField(curr, [&](auto& c) {
        if (ok && (mask[i >> 3] & (1u << (i & 7)))) ok = unpackValue(r, c);
        ++i;
    });
    if (!ok) return std::nullopt;
    return curr;
}

} // namespace aether
