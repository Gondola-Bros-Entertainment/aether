// aether - zero-copy little-endian serialization. Data-first: Writer/Reader are plain cursors;
// free functions move them. The wire format is always little-endian, and the put/get are byte-wise
// -- endian-agnostic by construction; no targetByteOrder branch or runtime byteswap needed.
#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>

namespace aether {

// ---- little-endian primitives on raw bytes (byte-wise => portable) ----
inline void putU8 (std::uint8_t* p, std::uint8_t  v) noexcept { p[0] = v; }
inline void putU16(std::uint8_t* p, std::uint16_t v) noexcept { p[0] = std::uint8_t(v); p[1] = std::uint8_t(v >> 8); }
inline void putU32(std::uint8_t* p, std::uint32_t v) noexcept { for (int i = 0; i < 4; ++i) p[i] = std::uint8_t(v >> (8 * i)); }
inline void putU64(std::uint8_t* p, std::uint64_t v) noexcept { for (int i = 0; i < 8; ++i) p[i] = std::uint8_t(v >> (8 * i)); }

inline std::uint8_t  getU8 (const std::uint8_t* p) noexcept { return p[0]; }
inline std::uint16_t getU16(const std::uint8_t* p) noexcept { return std::uint16_t(p[0]) | std::uint16_t(p[1] << 8); }
inline std::uint16_t getU16BE(const std::uint8_t* p) noexcept { return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]); }   // big-endian: the hand-packed wire fields (channel seq, batch length)
inline std::uint32_t getU32(const std::uint8_t* p) noexcept { std::uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= std::uint32_t(p[i]) << (8 * i); return v; }
inline std::uint64_t getU64(const std::uint8_t* p) noexcept { std::uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= std::uint64_t(p[i]) << (8 * i); return v; }

inline void putF32(std::uint8_t* p, float  f) noexcept { putU32(p, std::bit_cast<std::uint32_t>(f)); }
inline void putF64(std::uint8_t* p, double d) noexcept { putU64(p, std::bit_cast<std::uint64_t>(d)); }
inline float  getF32(const std::uint8_t* p) noexcept { return std::bit_cast<float >(getU32(p)); }
inline double getF64(const std::uint8_t* p) noexcept { return std::bit_cast<double>(getU64(p)); }

// ---- write cursor: plain data, `ok` goes false on the first overflow ----
struct Writer {
    std::uint8_t* buf{};
    std::size_t   cap{};
    std::size_t   pos{};
    bool          ok{true};
};

inline bool fits(Writer& w, std::size_t n) noexcept {
    if (w.pos + n > w.cap) w.ok = false;
    return w.ok;
}

inline void write(Writer& w, std::uint8_t  v) noexcept { if (fits(w, 1)) { putU8 (w.buf + w.pos, v); w.pos += 1; } }
inline void write(Writer& w, std::uint16_t v) noexcept { if (fits(w, 2)) { putU16(w.buf + w.pos, v); w.pos += 2; } }
inline void write(Writer& w, std::uint32_t v) noexcept { if (fits(w, 4)) { putU32(w.buf + w.pos, v); w.pos += 4; } }
inline void write(Writer& w, std::uint64_t v) noexcept { if (fits(w, 8)) { putU64(w.buf + w.pos, v); w.pos += 8; } }
inline void write(Writer& w, float  v) noexcept { if (fits(w, 4)) { putF32(w.buf + w.pos, v); w.pos += 4; } }
inline void write(Writer& w, double v) noexcept { if (fits(w, 8)) { putF64(w.buf + w.pos, v); w.pos += 8; } }
inline void writeBytes(Writer& w, const std::uint8_t* p, std::size_t n) noexcept {
    if (fits(w, n)) { std::memcpy(w.buf + w.pos, p, n); w.pos += n; }
}

// ---- read cursor: plain data; read<T> consumes it, nullopt past the end ----
struct Reader {
    const std::uint8_t* buf{};
    std::size_t         len{};
    std::size_t         pos{};
};

// Overflow-proof: r.pos <= r.len is an invariant (every advance is bounds-checked first), so the
// subtraction never underflows -- and `n <= remaining` cannot wrap the way `r.pos + n <= r.len`
// would for an attacker-supplied n near SIZE_MAX (which would falsely pass, then over-read).
inline bool has(const Reader& r, std::size_t n) noexcept { return n <= r.len - r.pos; }

template <class T>
std::optional<T> read(Reader& r) noexcept {
    if (!has(r, sizeof(T))) return std::nullopt;
    T v{};
    if      constexpr (std::is_same_v<T, std::uint8_t>)  v = getU8 (r.buf + r.pos);
    else if constexpr (std::is_same_v<T, std::uint16_t>) v = getU16(r.buf + r.pos);
    else if constexpr (std::is_same_v<T, std::uint32_t>) v = getU32(r.buf + r.pos);
    else if constexpr (std::is_same_v<T, std::uint64_t>) v = getU64(r.buf + r.pos);
    else if constexpr (std::is_same_v<T, float>)         v = getF32(r.buf + r.pos);
    else if constexpr (std::is_same_v<T, double>)        v = getF64(r.buf + r.pos);
    else static_assert(sizeof(T) == 0, "aether::read: unsupported type");
    r.pos += sizeof(T);
    return v;
}

inline bool readBytes(Reader& r, std::uint8_t* out, std::size_t n) noexcept {
    if (!has(r, n)) return false;
    std::memcpy(out, r.buf + r.pos, n);
    r.pos += n;
    return true;
}

} // namespace aether
