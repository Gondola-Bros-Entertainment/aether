#include "check.hpp"
#include <aether/socket.hpp>

using namespace aether;
using aether::test::require;

int main() {
    auto v4 = resolveAddresses("127.0.0.1", 7777, AddressFamily::IPv4);
    require(!v4.error && v4.addresses.size() == 1);
    require(addrEqual(v4.addresses.front(), addrLocalhost(7777)));
    require(addressToString(v4.addresses.front()) == "127.0.0.1:7777");
    auto v6 = resolveAddresses("::1", 7777, AddressFamily::IPv6);
    require(!v6.error && v6.addresses.size() == 1);
    require(addressToString(v6.addresses.front()) == "[::1]:7777");
    const auto local = resolveAddresses("localhost", 0);
    require(!local.error && !local.addresses.empty() && local.addresses.size() <= maxResolvedAddresses);
    for (const auto& address : local.addresses) require(addressValid(address) && addrPort(address) == 0);
    require(resolveAddresses("", 7777).error->code == ResolveErrorCode::InvalidInput);
    require(resolveAddresses(std::string(256, 'a'), 7777).error->code == ResolveErrorCode::InvalidInput);
    require(resolveAddresses(std::string_view("localhost\0evil", 14), 7777).error->code == ResolveErrorCode::InvalidInput);
    require(resolveAddresses("127.0.0.1", 7777, static_cast<AddressFamily>(999)).error->code == ResolveErrorCode::InvalidInput);
    require(resolveAddresses("::1", 7777, AddressFamily::IPv4).error);
    require(!addressToString(Address{}));
    std::puts("address_resolution_test: numeric v4/v6, localhost, formatting and validation passed");
}
