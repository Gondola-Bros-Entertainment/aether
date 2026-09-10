#include <aether/aether.hpp>

#include <array>
#include <cstdint>

int main() try {
    // Force the installed library's platform object and native dependencies to link.
    std::array<std::uint8_t, 32> random{};
    aether::secureRandomBytes(random.data(), random.size());
    const auto address = aether::addrLocalhost(7777);
    const auto encoded = aether::serializeAddr(address);
    const auto decoded = aether::deserializeAddr(encoded.data(), encoded.size());
    if (!decoded || !aether::addrEqual(address, *decoded) || aether::addrPort(*decoded) != 7777) return 1;
    const auto resolved = aether::resolveAddresses("127.0.0.1", 7777, aether::AddressFamily::IPv4);
    if (resolved.error || aether::addressToString(resolved.addresses.front()) != "127.0.0.1:7777") return 2;
    const aether::TokenScope scope{17, 42};
    const auto credential = aether::issueConnectCredential(random, {7, {1000}, {1,2}, scope});
    const auto token = aether::openConnectToken(random, credential.token, {1});
    if (!token || token->token.scope != scope || token->token.proofKey != credential.proofKey) return 3;
    auto peer = aether::newPeerState(aether::addrLocalhost(0), {}, {1});
    if (aether::peerConnect(peer, aether::PeerId{address}, {1}) != aether::ConnectError::AuthenticationRequired) return 4;
    return 0;
}
 catch (...) { return 5; }
