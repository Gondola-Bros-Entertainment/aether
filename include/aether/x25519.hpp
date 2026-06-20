// aether - X25519 (Curve25519 ECDH, RFC 7748) from scratch, no dependencies. The field is
// GF(2^255-19) in radix 2^16: sixteen int64 limbs, so every limb product stays well inside 64 bits
// -- no 128-bit integers, MSVC-portable (the same constraint that shapes the poly1305 here). The
// scalar multiply is the Montgomery ladder with a constant-time conditional swap. Verified against
// the RFC 7748 section 5.2 test vector. Data-first: a field element is a plain array; free functions
// transform it.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace aether {

inline constexpr int x25519KeySize = 32;
using X25519Key = std::array<std::uint8_t, x25519KeySize>;

namespace detail {

using Gf = std::array<std::int64_t, 16>;   // a field element, radix 2^16

inline void gfAdd(Gf& o, const Gf& a, const Gf& b) noexcept { for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i]; }
inline void gfSub(Gf& o, const Gf& a, const Gf& b) noexcept { for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i]; }

// Propagate carries and fold 2^256 == 38 (mod 2^255-19) back into limb 0.
inline void gfCarry(Gf& o) noexcept {
    for (std::size_t i = 0; i < 16; ++i) {
        o[i] += std::int64_t{ 1 } << 16;
        const std::int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

inline void gfMul(Gf& o, const Gf& a, const Gf& b) noexcept {
    std::int64_t t[31] = {};
    for (int i = 0; i < 16; ++i)
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];   // reduce the high half (2^256 == 38)
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    gfCarry(o);
    gfCarry(o);
}

inline void gfSquare(Gf& o, const Gf& a) noexcept { gfMul(o, a, a); }

// Constant-time conditional swap of a and b when bit == 1.
inline void gfCswap(Gf& a, Gf& b, std::int64_t bit) noexcept {
    const std::int64_t mask = ~(bit - 1);
    for (int i = 0; i < 16; ++i) {
        const std::int64_t t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

inline void gfUnpack(Gf& o, const std::uint8_t* n) noexcept {
    for (std::size_t i = 0; i < 16; ++i)
        o[i] = static_cast<std::int64_t>(n[2 * i]) + (static_cast<std::int64_t>(n[2 * i + 1]) << 8);
    o[15] &= 0x7fff;   // a u-coordinate is 255 bits
}

// Reduce fully mod 2^255-19 and serialize to 32 little-endian bytes.
inline void gfPack(std::uint8_t* o, const Gf& n) noexcept {
    Gf t = n;
    gfCarry(t); gfCarry(t); gfCarry(t);
    for (int pass = 0; pass < 2; ++pass) {
        Gf m{};
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i]     = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const std::int64_t carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        gfCswap(t, m, 1 - carry);
    }
    for (std::size_t i = 0; i < 16; ++i) {
        o[2 * i]     = static_cast<std::uint8_t>(t[i] & 0xff);
        o[2 * i + 1] = static_cast<std::uint8_t>(t[i] >> 8);
    }
}

// Modular inverse via Fermat: o = i^(2^255-21) (mod 2^255-19).
inline void gfInvert(Gf& o, const Gf& i) noexcept {
    Gf c = i;
    for (int a = 253; a >= 0; --a) {
        gfSquare(c, c);
        if (a != 2 && a != 4) gfMul(c, c, i);
    }
    o = c;
}

inline constexpr Gf gf121665 = { 0xDB41, 1 };   // (a-2)/4 for the ladder = 121665

} // namespace detail

// X25519 scalar multiply: out = scalar * point, both 32-byte little-endian (RFC 7748).
inline void x25519(X25519Key& out, const X25519Key& scalar, const X25519Key& point) noexcept {
    using namespace detail;
    std::uint8_t e[32];
    for (int i = 0; i < 32; ++i) e[i] = scalar[i];
    e[0]  &= 248;   // clamp the scalar
    e[31] &= 127;
    e[31] |= 64;

    Gf x;
    gfUnpack(x, point.data());
    Gf a{}, b{}, c{}, d{}, f{}, g{};
    a[0] = d[0] = 1;
    for (int i = 0; i < 16; ++i) b[i] = x[i];

    for (int i = 254; i >= 0; --i) {
        const std::int64_t bit = (e[i >> 3] >> (i & 7)) & 1;
        gfCswap(a, b, bit);
        gfCswap(c, d, bit);
        gfAdd(f, a, c);
        gfSub(a, a, c);
        gfAdd(c, b, d);
        gfSub(b, b, d);
        gfSquare(d, f);
        gfSquare(g, a);
        gfMul(a, c, a);
        gfMul(c, b, f);
        gfAdd(f, a, c);
        gfSub(a, a, c);
        gfSquare(b, a);
        gfSub(c, d, g);
        gfMul(a, c, gf121665);
        gfAdd(a, a, d);
        gfMul(c, c, a);
        gfMul(a, d, g);
        gfMul(d, b, x);
        gfSquare(b, f);
        gfCswap(a, b, bit);
        gfCswap(c, d, bit);
    }
    gfInvert(c, c);
    gfMul(a, a, c);
    gfPack(out.data(), a);
}

// Public key from a secret key: out = secret * basepoint (u = 9).
inline void x25519Base(X25519Key& out, const X25519Key& secret) noexcept {
    X25519Key base{};
    base[0] = 9;
    x25519(out, secret, base);
}

} // namespace aether
