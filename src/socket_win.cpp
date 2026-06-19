// aether - UDP socket platform layer (Winsock; Windows).
#include "aether/socket.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>

#pragma comment(lib, "ws2_32.lib")   // also linked via CMake; harmless to repeat

namespace aether {

static_assert(sizeof(sockaddr_storage) <= addrStorageSize, "Address.storage too small");

namespace {
// Winsock needs one-time process init; a static guard does it before main and cleans up at exit.
// Platform glue lives only in this .cpp.
struct WinsockInit {
    WinsockInit() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WinsockInit() { WSACleanup(); }
};
const WinsockInit winsockInit{};

sockaddr*       sa(Address& a)       { return reinterpret_cast<sockaddr*>(a.storage); }
const sockaddr* sa(const Address& a) { return reinterpret_cast<const sockaddr*>(a.storage); }
} // namespace

Address addrV4(std::uint32_t ip, std::uint16_t port) {
    Address a{};
    auto* in            = reinterpret_cast<sockaddr_in*>(a.storage);
    in->sin_family      = AF_INET;
    in->sin_addr.s_addr = htonl(ip);
    in->sin_port        = htons(port);
    a.len               = sizeof(sockaddr_in);
    return a;
}
Address addrAny(std::uint16_t port)       { return addrV4(INADDR_ANY, port); }
Address addrLocalhost(std::uint16_t port) { return addrV4(INADDR_LOOPBACK, port); }

Address addrAny6(std::uint16_t port) {
    Address a{};
    auto* in        = reinterpret_cast<sockaddr_in6*>(a.storage);
    in->sin6_family = AF_INET6;
    in->sin6_addr   = in6addr_any;
    in->sin6_port   = htons(port);
    a.len           = sizeof(sockaddr_in6);
    return a;
}

std::uint16_t addrPort(const Address& a) {
    if (sa(a)->sa_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6*>(a.storage)->sin6_port);
    return ntohs(reinterpret_cast<const sockaddr_in*>(a.storage)->sin_port);
}

bool addrEqual(const Address& a, const Address& b) {
    return a.len == b.len && std::memcmp(a.storage, b.storage, a.len) == 0;
}

std::optional<Socket> openUdp(const Address& bindAddr) {
    const int          family = sa(bindAddr)->sa_family;
    const SocketHandle fd     = static_cast<SocketHandle>(::socket(family, SOCK_DGRAM, 0));
    if (fd == invalidSocket) return std::nullopt;
    const SOCKET h   = static_cast<SOCKET>(fd);
    const char   yes = 1;
    ::setsockopt(h, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (::bind(h, sa(bindAddr), static_cast<int>(bindAddr.len)) != 0) {
        ::closesocket(h);
        return std::nullopt;
    }
    u_long nonblocking = 1;
    ::ioctlsocket(h, FIONBIO, &nonblocking);
    Socket s{};
    s.fd = fd;
    return s;
}

void closeSocket(Socket& s) {
    if (s.fd != invalidSocket) { ::closesocket(static_cast<SOCKET>(s.fd)); s.fd = invalidSocket; }
}
bool isOpen(const Socket& s) { return s.fd != invalidSocket; }

Address localAddr(const Socket& s) {
    Address a{};
    int len = sizeof(a.storage);
    if (::getsockname(static_cast<SOCKET>(s.fd), sa(a), &len) == 0) a.len = static_cast<std::uint32_t>(len);
    return a;
}

int sendTo(Socket& s, std::span<const std::uint8_t> data, const Address& to) {
    const int n = ::sendto(static_cast<SOCKET>(s.fd), reinterpret_cast<const char*>(data.data()),
                           static_cast<int>(data.size()), 0, sa(to), static_cast<int>(to.len));
    if (n < 0) return -1;
    s.bytesSent   += static_cast<std::uint64_t>(n);
    s.packetsSent += 1;
    return n;
}

int recvFrom(Socket& s, std::span<std::uint8_t> buf, Address& from) {
    from = Address{};
    int       len = sizeof(from.storage);
    const int n   = ::recvfrom(static_cast<SOCKET>(s.fd), reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0, sa(from), &len);
    if (n < 0) return (WSAGetLastError() == WSAEWOULDBLOCK) ? 0 : -1;
    from.len      = static_cast<std::uint32_t>(len);
    s.bytesRecv   += static_cast<std::uint64_t>(n);
    s.packetsRecv += 1;
    return n;
}

} // namespace aether
