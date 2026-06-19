// aether - domain newtypes for type safety.
// Plain data; free functions operate on it. Strong types so the compiler catches
// id mix-ups; zero runtime cost.
#pragma once

#include <cstdint>
#include <vector>

namespace aether {

// A byte buffer (payloads, packets, fragments).
using Bytes = std::vector<std::uint8_t>;

// A channel identifier - one logical stream of messages. Not a quantity.
enum class ChannelId : std::uint8_t {};
constexpr int toInt(ChannelId c) noexcept { return static_cast<int>(c); }

// A fragment / message identifier.
enum class MessageId : std::uint32_t {};

// A 16-bit sequence number with wraparound arithmetic. Just data -- construct with
// SequenceNum{n}; free functions below do the work.
struct SequenceNum {
    std::uint16_t value{};
};

constexpr bool operator==(SequenceNum a, SequenceNum b) noexcept { return a.value == b.value; }
constexpr bool operator!=(SequenceNum a, SequenceNum b) noexcept { return a.value != b.value; }
// Raw numeric order, for ordered containers only. Use newer() for wraparound logic.
constexpr bool operator<(SequenceNum a, SequenceNum b) noexcept { return a.value < b.value; }

constexpr SequenceNum next(SequenceNum s) noexcept {
    return { static_cast<std::uint16_t>(s.value + 1) };
}

// Is `a` strictly newer than `b`, accounting for 16-bit wrap (RFC 1982 serial
// arithmetic) so old packets sort before new across the 0xFFFF -> 0x0000 boundary?
constexpr bool newer(SequenceNum a, SequenceNum b) noexcept {
    const std::uint16_t d = static_cast<std::uint16_t>(a.value - b.value);
    return d != 0 && d < 0x8000;
}

// Signed distance a - b, accounting for 16-bit wrap (positive if a is ahead of b).
constexpr int sequenceDiff(SequenceNum a, SequenceNum b) noexcept {
    return static_cast<std::int16_t>(static_cast<std::uint16_t>(a.value - b.value));
}

// Monotonic time, nanoseconds.
struct MonoTime { std::uint64_t ns{}; };
constexpr double elapsedMs(MonoTime start, MonoTime now) noexcept {
    return static_cast<double>(now.ns - start.ns) / 1.0e6;
}

} // namespace aether
