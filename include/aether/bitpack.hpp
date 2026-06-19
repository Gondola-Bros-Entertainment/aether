// aether - bit-level cursor for tight wire packing.
// Write a value in exactly the bits its range needs, not a whole byte. MSB-first, so the
// layout matches the packet header's bit packing. Data-first: plain cursors, free funcs.
#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>

namespace aether {

// Bits needed to represent an unsigned value in [0, maxValue] inclusive.
// 0 -> 0 bits (a constant), 1 -> 1 bit, 255 -> 8 bits, 1023 -> 10 bits.
constexpr int bitsForMax(std::uint64_t maxValue) noexcept {
    return maxValue == 0 ? 0 : static_cast<int>(std::bit_width(maxValue));
}

// ---- write cursor: accumulates bits MSB-first, flushes whole bytes as they fill ----
struct BitWriter {
    std::uint8_t* buf{};
    std::size_t   cap{};
    std::size_t   bytePos{};       // bytes committed to buf
    std::uint64_t scratch{};       // pending bits, held at the low end
    int           scratchBits{};   // count of pending bits (0..7 between calls)
    bool          ok{true};
};

// Append the low `bits` (0..32) of `value`. 0 bits is a no-op.
inline void writeBits(BitWriter& w, std::uint32_t value, int bits) noexcept {
    if (bits <= 0) return;
    const std::uint64_t masked = bits >= 32 ? value : (value & ((std::uint32_t{1} << bits) - 1));
    w.scratch = (w.scratch << bits) | masked;
    w.scratchBits += bits;
    while (w.scratchBits >= 8) {
        if (w.bytePos >= w.cap) { w.ok = false; w.scratchBits = 0; w.scratch = 0; return; }
        w.scratchBits -= 8;
        w.buf[w.bytePos++] = static_cast<std::uint8_t>((w.scratch >> w.scratchBits) & 0xFF);
    }
    w.scratch &= w.scratchBits == 0 ? 0ull : ((1ull << w.scratchBits) - 1);   // keep only live bits
}

// Pad the final partial byte with zeros and return total bytes written.
inline std::size_t flushBits(BitWriter& w) noexcept {
    if (w.scratchBits > 0) {
        if (w.bytePos >= w.cap) { w.ok = false; return w.bytePos; }
        w.buf[w.bytePos++] = static_cast<std::uint8_t>((w.scratch << (8 - w.scratchBits)) & 0xFF);
        w.scratchBits = 0;
        w.scratch = 0;
    }
    return w.bytePos;
}

// ---- read cursor: pulls bytes as needed, hands back MSB-first bit fields ----
struct BitReader {
    const std::uint8_t* buf{};
    std::size_t         len{};       // bytes available
    std::size_t         bytePos{};
    std::uint64_t       scratch{};
    int                 scratchBits{};
    bool                ok{true};
};

// Pull the next `bits` (0..32). Sets ok=false and returns 0 if the buffer runs out.
inline std::uint32_t readBits(BitReader& r, int bits) noexcept {
    if (bits <= 0) return 0;
    while (r.scratchBits < bits) {
        if (r.bytePos >= r.len) { r.ok = false; return 0; }
        r.scratch = (r.scratch << 8) | r.buf[r.bytePos++];
        r.scratchBits += 8;
    }
    r.scratchBits -= bits;
    const std::uint64_t out = r.scratch >> r.scratchBits;
    r.scratch &= r.scratchBits == 0 ? 0ull : ((1ull << r.scratchBits) - 1);   // keep only live bits
    return bits >= 32 ? static_cast<std::uint32_t>(out)
                      : static_cast<std::uint32_t>(out & ((std::uint32_t{1} << bits) - 1));
}

} // namespace aether
