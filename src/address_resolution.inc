// Shared POSIX/Winsock getaddrinfo implementation, included by the selected socket
// backend after its OS headers and addressRuntimeError helper. Not a public header.
namespace aether {

ResolveResult resolveAddresses(std::string_view host, std::uint16_t port, AddressFamily family) {
    if (host.empty() || host.size() > 255 || host.find('\0') != std::string_view::npos
        || (family != AddressFamily::Any && family != AddressFamily::IPv4 && family != AddressFamily::IPv6))
        return {{}, ResolveError{ResolveErrorCode::InvalidInput}};
    if (const int error = addressRuntimeError()) return {{}, ResolveError{ResolveErrorCode::RuntimeUnavailable, error}};
    addrinfo hints{};
    hints.ai_family = family == AddressFamily::IPv4 ? AF_INET : family == AddressFamily::IPv6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;
    addrinfo* raw = nullptr;
    const std::string name(host), service = std::to_string(port);
    const int error = getaddrinfo(name.c_str(), service.c_str(), &hints, &raw);
    if (error != 0) return {{}, ResolveError{ResolveErrorCode::LookupFailed, error}};
    const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> results(raw, freeaddrinfo);
    ResolveResult result;
    for (auto* entry = results.get(); entry && result.addresses.size() < maxResolvedAddresses; entry = entry->ai_next) {
        Address address;
        if (entry->ai_family == AF_INET && entry->ai_addrlen == sizeof(sockaddr_in)) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(entry->ai_addr);
            address = addrV4(ntohl(in->sin_addr.s_addr), ntohs(in->sin_port));
        } else if (entry->ai_family == AF_INET6 && entry->ai_addrlen == sizeof(sockaddr_in6)) {
            const auto* in = reinterpret_cast<const sockaddr_in6*>(entry->ai_addr);
            address = addrAny6(ntohs(in->sin6_port));
            auto* out = reinterpret_cast<sockaddr_in6*>(address.storage.data());
            out->sin6_addr = in->sin6_addr;
            out->sin6_scope_id = in->sin6_scope_id;
        } else continue;
        if (std::none_of(result.addresses.begin(), result.addresses.end(), [&](const auto& other) { return addrEqual(address, other); }))
            result.addresses.push_back(address);
    }
    if (result.addresses.empty()) result.error = ResolveError{ResolveErrorCode::NoAddresses};
    return result;
}

std::optional<std::string> addressToString(const Address& address) {
    if (!addressValid(address) || addressRuntimeError() != 0) return std::nullopt;
    char host[NI_MAXHOST]{};
    const int error = getnameinfo(sa(address), static_cast<int>(address.len), host,
        static_cast<std::uint32_t>(sizeof host), nullptr, 0, NI_NUMERICHOST);
    if (error != 0) return std::nullopt;
    const auto port = std::to_string(addrPort(address));
    return sa(address)->sa_family == AF_INET6 ? "[" + std::string(host) + "]:" + port : std::string(host) + ":" + port;
}

} // namespace aether
