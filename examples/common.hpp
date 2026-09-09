#pragma once

#include <aether/types.hpp>

#include <charconv>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

namespace aether_example {

inline aether::MonoTime monoNow() {
    return aether::MonoTime{static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count())};
}

inline std::optional<std::uint16_t> parsePort(std::string_view text) {
    if (text.empty()) return std::nullopt;
    unsigned value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0 || value > 65535)
        return std::nullopt;
    return static_cast<std::uint16_t>(value);
}

inline constexpr auto tickInterval = std::chrono::milliseconds(16);

} // namespace aether_example
