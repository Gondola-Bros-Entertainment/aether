#include <aether/aether.hpp>

#include <array>
#include <cstdint>

int main() {
    // Force the installed library's platform object and native dependencies to link.
    std::array<std::uint8_t, 32> random{};
    aether::secureRandomBytes(random.data(), random.size());
    const auto address = aether::addrLocalhost(7777);
    const auto encoded = aether::serializeAddr(address);
    const auto decoded = aether::deserializeAddr(encoded.data(), encoded.size());
    return decoded && aether::addrEqual(address, *decoded) && aether::addrPort(*decoded) == 7777 ? 0 : 1;
}
