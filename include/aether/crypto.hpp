// aether - ChaCha20-Poly1305 AEAD for packet payloads (RFC 8439). Implemented from scratch, no
// crypto dependency, and verified against the RFC 8439 section 2.8.2 test vector in the test
// suite. Data-first: plain key bytes, free functions.
//
// Wire format of an encrypted payload: [counter:8 BE][ciphertext:N][auth tag:16].
// The 12-byte ChaCha nonce is [counter:8 BE][protocolId:4 BE].
#pragma once

#include "aether/types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace aether {

// 32-byte symmetric key for ChaCha20-Poly1305.
using EncryptionKey = std::array<std::uint8_t, 32>;

// Monotonically increasing nonce counter (one per connection direction).
struct NonceCounter { std::uint64_t value{}; };

inline constexpr int nonceSize          = 8;   // counter bytes on the wire
inline constexpr int authTagSize        = 16;
inline constexpr int encryptionOverhead = nonceSize + authTagSize;   // 24

namespace detail {

inline std::uint32_t cryptoLe32(const std::uint8_t* p) noexcept {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
inline std::uint32_t rotl32(std::uint32_t x, int n) noexcept { return (x << n) | (x >> (32 - n)); }

inline void quarterRound(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) noexcept {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// One 64-byte ChaCha20 keystream block (RFC 8439 section 2.3).
inline void chacha20Block(const std::uint8_t key[32], std::uint32_t counter,
                          const std::uint8_t nonce[12], std::uint8_t out[64]) noexcept {
    const std::uint32_t state[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        cryptoLe32(key + 0),  cryptoLe32(key + 4),  cryptoLe32(key + 8),  cryptoLe32(key + 12),
        cryptoLe32(key + 16), cryptoLe32(key + 20), cryptoLe32(key + 24), cryptoLe32(key + 28),
        counter, cryptoLe32(nonce + 0), cryptoLe32(nonce + 4), cryptoLe32(nonce + 8),
    };
    std::uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = state[i];
    for (int i = 0; i < 10; ++i) {
        quarterRound(x[0], x[4], x[8],  x[12]);
        quarterRound(x[1], x[5], x[9],  x[13]);
        quarterRound(x[2], x[6], x[10], x[14]);
        quarterRound(x[3], x[7], x[11], x[15]);
        quarterRound(x[0], x[5], x[10], x[15]);
        quarterRound(x[1], x[6], x[11], x[12]);
        quarterRound(x[2], x[7], x[8],  x[13]);
        quarterRound(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; ++i) {
        const std::uint32_t v = x[i] + state[i];
        out[i * 4 + 0] = std::uint8_t(v);
        out[i * 4 + 1] = std::uint8_t(v >> 8);
        out[i * 4 + 2] = std::uint8_t(v >> 16);
        out[i * 4 + 3] = std::uint8_t(v >> 24);
    }
}

// XOR a ChaCha20 keystream (starting at the given block counter) over in -> out.
inline void chacha20Xor(const std::uint8_t key[32], std::uint32_t counter, const std::uint8_t nonce[12],
                        const std::uint8_t* in, std::uint8_t* out, std::size_t len) noexcept {
    std::uint8_t block[64];
    std::size_t off = 0;
    while (off < len) {
        chacha20Block(key, counter, nonce, block);
        const std::size_t n = (len - off < 64) ? (len - off) : 64;
        for (std::size_t i = 0; i < n; ++i) out[off + i] = std::uint8_t(in[off + i] ^ block[i]);
        off += n;
        ++counter;
    }
}

// Poly1305 one-time MAC (RFC 8439 section 2.5), radix 2^26 over five limbs.
inline void poly1305(const std::uint8_t key[32], const std::uint8_t* msg, std::size_t len, std::uint8_t tag[16]) noexcept {
    std::uint32_t t0 = cryptoLe32(key + 0) & 0x0fffffffu;
    std::uint32_t t1 = cryptoLe32(key + 4) & 0x0ffffffcu;
    std::uint32_t t2 = cryptoLe32(key + 8) & 0x0ffffffcu;
    std::uint32_t t3 = cryptoLe32(key + 12) & 0x0ffffffcu;
    const std::uint64_t r[5] = {
        std::uint64_t(t0) & 0x3ffffff,
        (std::uint64_t(t0) >> 26 | std::uint64_t(t1) << 6) & 0x3ffffff,
        (std::uint64_t(t1) >> 20 | std::uint64_t(t2) << 12) & 0x3ffffff,
        (std::uint64_t(t2) >> 14 | std::uint64_t(t3) << 18) & 0x3ffffff,
        (std::uint64_t(t3) >> 8) & 0x3ffffff,
    };
    std::uint64_t h[5] = { 0, 0, 0, 0, 0 };

    std::size_t off = 0;
    while (off < len) {
        const std::size_t blk = (len - off < 16) ? (len - off) : 16;
        std::uint8_t buf[17] = { 0 };
        for (std::size_t i = 0; i < blk; ++i) buf[i] = msg[off + i];
        buf[blk] = 1;
        auto ext26 = [&](int bitlo) -> std::uint64_t {
            std::uint64_t v = 0;
            for (int b = 0; b < 26; ++b) { const int bit = bitlo + b; if (buf[bit >> 3] & (1u << (bit & 7))) v |= (std::uint64_t(1) << b); }
            return v;
        };
        h[0] += ext26(0); h[1] += ext26(26); h[2] += ext26(52); h[3] += ext26(78); h[4] += ext26(104);

        // 26-bit limbs keep every product under 2^58, so the multiply-reduce fits in uint64 --
        // no 128-bit type needed (the poly1305-donna 32-bit approach; portable to MSVC).
        std::uint64_t d[5];
        for (int m = 0; m < 5; ++m) {
            std::uint64_t acc = 0;
            for (int i = 0; i < 5; ++i) {
                const int j = m - i;
                if (j >= 0 && j < 5) acc += h[i] * r[j];
                const int j2 = m + 5 - i;
                if (j2 >= 0 && j2 < 5) acc += (5 * h[i]) * r[j2];
            }
            d[m] = acc;
        }
        std::uint64_t c = 0;
        for (int m = 0; m < 5; ++m) { const std::uint64_t v = d[m] + c; h[m] = v & 0x3ffffff; c = v >> 26; }
        h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
        off += blk;
    }

    // full carry, then a conditional subtract of p = 2^130 - 5
    std::uint64_t c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

    const bool ge = h[4] == 0x3ffffff && h[3] == 0x3ffffff && h[2] == 0x3ffffff && h[1] == 0x3ffffff && h[0] >= 0x3fffffb;
    if (ge) { std::uint64_t cc = 5; for (int m = 0; m < 5; ++m) { h[m] += cc; cc = h[m] >> 26; h[m] &= 0x3ffffff; } }

    // Reassemble the five 26-bit limbs into the low 128 bits as two uint64 halves, add the
    // 128-bit s key with a manual carry, then serialize little-endian. Portable, no __int128.
    const std::uint64_t lo  = h[0] | (h[1] << 26) | (h[2] << 52);
    const std::uint64_t hi  = (h[2] >> 12) | (h[3] << 14) | (h[4] << 40);
    const std::uint64_t sLo = std::uint64_t(cryptoLe32(key + 16)) | (std::uint64_t(cryptoLe32(key + 20)) << 32);
    const std::uint64_t sHi = std::uint64_t(cryptoLe32(key + 24)) | (std::uint64_t(cryptoLe32(key + 28)) << 32);
    const std::uint64_t rLo = lo + sLo;
    const std::uint64_t rHi = hi + sHi + (rLo < lo ? 1 : 0);   // carry out of the low half
    for (int i = 0; i < 8; ++i) tag[i]     = std::uint8_t(rLo >> (8 * i));
    for (int i = 0; i < 8; ++i) tag[8 + i] = std::uint8_t(rHi >> (8 * i));
}

inline bool constTimeEq(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) noexcept {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < n; ++i) diff = std::uint8_t(diff | (a[i] ^ b[i]));
    return diff == 0;
}

// Build the Poly1305 MAC input: aad || pad16 || ct || pad16 || le64(aadLen) || le64(ctLen).
inline void poly1305Tag(const std::uint8_t polyKey[32], const std::uint8_t* aad, std::size_t aadLen,
                        const std::uint8_t* ct, std::size_t ctLen, std::uint8_t tag[16]) {
    Bytes mac;
    mac.insert(mac.end(), aad, aad + aadLen);  while (mac.size() % 16) mac.push_back(0);
    mac.insert(mac.end(), ct, ct + ctLen);     while (mac.size() % 16) mac.push_back(0);
    for (int i = 0; i < 8; ++i) mac.push_back(std::uint8_t(aadLen >> (8 * i)));
    for (int i = 0; i < 8; ++i) mac.push_back(std::uint8_t(ctLen  >> (8 * i)));
    poly1305(polyKey, mac.data(), mac.size(), tag);
}

} // namespace detail

// AEAD seal (RFC 8439 section 2.8): encrypt pt into ct (caller-sized to ptLen) and write the tag.
inline void aeadSeal(const std::uint8_t key[32], const std::uint8_t nonce[12],
                     const std::uint8_t* aad, std::size_t aadLen,
                     const std::uint8_t* pt, std::size_t ptLen, std::uint8_t* ct, std::uint8_t tag[16]) {
    std::uint8_t polyKey[64];
    detail::chacha20Block(key, 0, nonce, polyKey);
    detail::chacha20Xor(key, 1, nonce, pt, ct, ptLen);
    detail::poly1305Tag(polyKey, aad, aadLen, ct, ptLen, tag);
}

// AEAD open: verify the tag and decrypt; nullopt on authentication failure.
inline std::optional<Bytes> aeadOpen(const std::uint8_t key[32], const std::uint8_t nonce[12],
                                     const std::uint8_t* aad, std::size_t aadLen,
                                     const std::uint8_t* ct, std::size_t ctLen, const std::uint8_t tag[16]) {
    std::uint8_t polyKey[64];
    detail::chacha20Block(key, 0, nonce, polyKey);
    std::uint8_t computed[16];
    detail::poly1305Tag(polyKey, aad, aadLen, ct, ctLen, computed);
    if (!detail::constTimeEq(computed, tag, 16)) return std::nullopt;
    Bytes pt(ctLen);
    detail::chacha20Xor(key, 1, nonce, ct, pt.data(), ctLen);
    return pt;
}

inline void buildNonce(std::uint64_t counter, std::uint32_t protocolId, std::uint8_t nonce[12]) noexcept {
    for (int i = 0; i < 8; ++i) nonce[i]     = std::uint8_t(counter    >> (56 - 8 * i));   // counter, 8 BE
    for (int i = 0; i < 4; ++i) nonce[8 + i] = std::uint8_t(protocolId >> (24 - 8 * i));   // protocol, 4 BE
}

// Encrypt a payload: returns [counter:8 BE][ciphertext][tag:16]. Caller bumps the counter.
inline Bytes encrypt(const EncryptionKey& key, NonceCounter counter, std::uint32_t protocolId,
                     const std::uint8_t* pt, std::size_t ptLen) {
    std::uint8_t nonce[12];
    buildNonce(counter.value, protocolId, nonce);
    Bytes out(static_cast<std::size_t>(nonceSize) + ptLen + authTagSize);
    for (int i = 0; i < nonceSize; ++i) out[i] = nonce[i];
    std::uint8_t tag[16];
    aeadSeal(key.data(), nonce, nullptr, 0, pt, ptLen, out.data() + nonceSize, tag);
    for (int i = 0; i < authTagSize; ++i) out[nonceSize + ptLen + i] = tag[i];
    return out;
}

struct DecryptResult { Bytes plaintext; NonceCounter counter; };

// Decrypt a payload of the form [counter:8 BE][ciphertext][tag:16]; nullopt on failure.
// The caller enforces anti-replay by checking the returned counter against the last seen.
inline std::optional<DecryptResult> decrypt(const EncryptionKey& key, std::uint32_t protocolId,
                                            const std::uint8_t* data, std::size_t len) {
    if (len < static_cast<std::size_t>(nonceSize) + authTagSize) return std::nullopt;
    std::uint64_t counter = 0;
    for (int i = 0; i < nonceSize; ++i) counter = (counter << 8) | data[i];
    const std::size_t    ctLen = len - nonceSize - authTagSize;
    const std::uint8_t*  ct    = data + nonceSize;
    const std::uint8_t*  tag   = data + nonceSize + ctLen;
    std::uint8_t nonce[12];
    buildNonce(counter, protocolId, nonce);
    auto pt = aeadOpen(key.data(), nonce, nullptr, 0, ct, ctLen, tag);
    if (!pt) return std::nullopt;
    return DecryptResult{ std::move(*pt), NonceCounter{ counter } };
}

} // namespace aether
