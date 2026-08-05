// aether - serialization and delta compression over plain structs. reflect.hpp decomposes an
// aggregate into its fields; packValue varint-packs each one; deltaPack writes a changemask plus
// only the fields that differ from a previous snapshot. No annotations, no codegen, no per-type
// registration. Data-first: free functions over plain T.
#pragma once

#include "aether/reflect.hpp"
#include "aether/varint.hpp"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
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

// Deep field equality: primitives compare directly, nested aggregates and containers recurse.
// This decides what goes on the wire, so it has to agree with packValue at EVERY depth. Containers
// therefore recurse per element instead of calling operator==, which would compare their elements by
// value: inside a vector or an optional that makes +0.0 and -0.0 equal (a sign flip the receiver
// never hears about) and NaN never-equal (an unchanged field re-sent every tick), and it does not
// compile at all for a container of plain aggregates, which have no operator==.
template <class T> bool fieldEqual(const T& a, const T& b) {
    if constexpr (std::is_enum_v<T>) {
        return a == b;
    } else if constexpr (detail::isStdString<T>) {
        return a == b;                                     // bytes: no float or aggregate element to recurse into
    } else if constexpr (detail::isStdVector<T>) {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (!fieldEqual(a[i], b[i])) return false;
        return true;
    } else if constexpr (detail::isStdOptional<T>) {
        if (a.has_value() != b.has_value()) return false;
        return !a.has_value() || fieldEqual(*a, *b);
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
        // A fixed underlying type is what makes the cast below total: the enum can hold every bit
        // pattern of that type, so no wire value is out of range. Reject the other form at compile
        // time rather than cast an untrusted integer into an enum that cannot represent it (UB).
        static_assert(detail::enumHasFixedUnderlying<T>,
                      "aether: a serializable enum needs a fixed underlying type (enum class E, or enum E : "
                      "std::uint8_t). Without one its valid values are bounded by its enumerators, which "
                      "reflection cannot see, so an out-of-range wire value would be undefined behaviour "
                      "instead of a rejected packet.");
        std::underlying_type_t<T> u{};
        if (!unpackValue(r, u)) return false;
        v = static_cast<T>(u);
        return true;
    } else if constexpr (detail::isStdString<T>) {
        const auto n = readVarU(r);
        // A varint length can exceed SIZE_MAX on a 32-bit target; truncating it would silently decode a
        // DIFFERENT string than the 64-bit peer encoded, so reject rather than narrow.
        if (!n || *n > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) return false;
        if (!has(r, static_cast<std::size_t>(*n))) return false;
        if (!chargeAlloc(r, *n, 1)) return false;
        v.assign(reinterpret_cast<const char*>(r.buf + r.pos), static_cast<std::size_t>(*n));
        r.pos += static_cast<std::size_t>(*n);
        return true;
    } else if constexpr (detail::isStdVector<T>) {
        const auto n = readVarU(r);
        // Count <= remaining bytes bounds the LOOP; charging sizeof(element) bounds the MEMORY, which
        // the byte count alone does not once one wire byte can materialize an arbitrarily large element.
        if (!n || *n > r.len - r.pos) return false;
        if (!chargeAlloc(r, *n, sizeof(typename T::value_type))) return false;
        v.clear();
        v.reserve(detail::decodeReserveCount<typename T::value_type>(*n));   // bounded up-front alloc; grow as elements parse
        for (std::uint64_t k = 0; k < *n; ++k) { typename T::value_type e{}; if (!unpackValue(r, e)) return false; v.push_back(std::move(e)); }
        return true;
    } else if constexpr (detail::isStdOptional<T>) {
        // One wire form per value: the encoder writes 0 or 1, so every other byte is rejected rather
        // than folded into "present". Treating any nonzero as present would give 255 encodings of one
        // optional, and a change-set has exactly one encoding here -- the same rule varint.hpp
        // enforces against an overlong integer and the changemask against a set padding bit.
        const auto f = read<std::uint8_t>(r);
        if (!f || *f > 1) return false;
        if (*f) { typename T::value_type tmp{}; if (!unpackValue(r, tmp)) return false; v = std::move(tmp); }
        else v.reset();
        return true;
    } else if constexpr (std::is_aggregate_v<T>) {
        bool ok = true;
        forEachField(v, [&](auto& f) { if (ok) ok = unpackValue(r, f); });
        return ok;
    } else if constexpr (std::is_same_v<T, bool>) {
        const auto b = read<std::uint8_t>(r);
        if (!b || *b > 1) return false;   // canonical: 0 or 1, as packValue writes (see the optional flag)
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

// --- delta snapshot: a changemask, then only the changed fields ---
//
// The mask adapts to the struct's width at compile time and to the change count at run time:
//   fieldCount <= 16: the plain bitmap, (n+7)/8 bytes, no discriminator. A mode byte would cost as
//     much as it could ever save at this width.
//   fieldCount  > 16: one mode byte. A value < maskBytes is a count of 1-byte field indices that
//     follow (strictly ascending); 0xFF means a full bitmap follows. Sparse is chosen exactly when
//     it is strictly smaller, so a wide struct with few changed fields -- the replication steady
//     state -- pays per change, not per field. (A 32-field struct sends one changed field under a
//     2-byte mask -- mode byte plus index -- instead of 5, the mode byte plus a 4-byte bitmap.)
// Both sides derive the layout from fieldCount<T>() alone, so encode and decode cannot disagree.
// The decoder rejects every encoding the encoder would not produce (non-canonical): sparse where a
// bitmap was due (and vice versa), unordered or out-of-range indices, padding bits -- one change-set,
// one wire form, exactly as the bitmap path has always enforced with its padding-bit check.
inline constexpr std::size_t  deltaSparseFieldMin = 17;    // adaptive from here up (reflection caps at 32)
inline constexpr std::uint8_t deltaMaskBitmap     = 0xFF;  // mode byte: a full bitmap follows

template <class T> void deltaPack(Writer& w, const T& prev, const T& curr) {
    constexpr std::size_t n         = fieldCount<T>();
    constexpr std::size_t maskBytes = (n + 7) / 8;
    std::uint8_t mask[maskBytes ? maskBytes : 1] = {};
    std::uint8_t changed[n ? n : 1];
    std::size_t  changedCount = 0;

    std::size_t i = 0;
    forEachFieldPair(prev, curr, [&](const auto& p, const auto& c) {
        if (!fieldEqual(p, c)) {
            mask[i >> 3] |= static_cast<std::uint8_t>(1u << (i & 7));
            changed[changedCount++] = static_cast<std::uint8_t>(i);   // ascending by construction
        }
        ++i;
    });
    if constexpr (n >= deltaSparseFieldMin) {
        if (changedCount < maskBytes) {   // 1 + count vs 1 + maskBytes: sparse strictly smaller
            write(w, static_cast<std::uint8_t>(changedCount));
            writeBytes(w, changed, changedCount);
        } else {
            write(w, deltaMaskBitmap);
            writeBytes(w, mask, maskBytes);
        }
    } else {
        writeBytes(w, mask, maskBytes);
    }

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

    // Canonical bitmap: only the low n bits may be set -- the encoder never sets a padding bit.
    const auto bitmapCanonical = [&]() {
        if constexpr (n % 8 != 0) {
            constexpr auto validLow = static_cast<std::uint8_t>((1u << (n % 8)) - 1);
            return (mask[maskBytes - 1] & static_cast<std::uint8_t>(~validLow)) == 0;
        } else {
            return true;
        }
    };
    if constexpr (n >= deltaSparseFieldMin) {
        const auto mode = read<std::uint8_t>(r);
        if (!mode) return std::nullopt;
        if (*mode == deltaMaskBitmap) {
            if (!readBytes(r, mask, maskBytes)) return std::nullopt;
            if (!bitmapCanonical()) return std::nullopt;
            int setBits = 0;
            for (std::size_t b = 0; b < maskBytes; ++b) setBits += std::popcount(mask[b]);
            if (static_cast<std::size_t>(setBits) < maskBytes) return std::nullopt;   // this few changes is always sent sparse
        } else {
            if (*mode >= maskBytes) return std::nullopt;   // this many changes is always sent as a bitmap
            int last = -1;
            for (std::uint8_t k = 0; k < *mode; ++k) {
                const auto idx = read<std::uint8_t>(r);
                if (!idx || *idx >= n || static_cast<int>(*idx) <= last) return std::nullopt;   // in range, strictly ascending
                last = *idx;
                mask[*idx >> 3] |= static_cast<std::uint8_t>(1u << (*idx & 7));
            }
        }
    } else {
        if (!readBytes(r, mask, maskBytes)) return std::nullopt;
        if (!bitmapCanonical()) return std::nullopt;
    }

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
