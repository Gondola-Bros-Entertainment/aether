// aether - UDP socket platform layer (POSIX/BSD sockets; macOS + Linux).
#include "aether/socket.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace aether {

static_assert(sizeof(sockaddr_storage) <= addrStorageSize, "Address.storage too small");

namespace {
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
    const SocketHandle fd     = ::socket(family, SOCK_DGRAM, 0);
    if (fd == invalidSocket) return std::nullopt;
    const int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (::bind(fd, sa(bindAddr), bindAddr.len) < 0) { ::close(fd); return std::nullopt; }
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    Socket s{};
    s.fd = fd;
    return s;
}

void closeSocket(Socket& s) { if (s.fd != invalidSocket) { ::close(s.fd); s.fd = invalidSocket; } }
bool isOpen(const Socket& s) { return s.fd != invalidSocket; }

Address localAddr(const Socket& s) {
    Address a{};
    socklen_t len = sizeof(a.storage);
    if (::getsockname(s.fd, sa(a), &len) == 0) a.len = len;
    return a;
}

int sendTo(Socket& s, std::span<const std::uint8_t> data, const Address& to) {
    const ssize_t n = ::sendto(s.fd, data.data(), data.size(), 0, sa(to), to.len);
    if (n < 0) return -1;
    s.bytesSent   += static_cast<std::uint64_t>(n);
    s.packetsSent += 1;
    return static_cast<int>(n);
}

int recvFrom(Socket& s, std::span<std::uint8_t> buf, Address& from) {
    from = Address{};
    socklen_t     len = sizeof(from.storage);
    const ssize_t n   = ::recvfrom(s.fd, buf.data(), buf.size(), 0, sa(from), &len);
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    from.len      = len;
    s.bytesRecv   += static_cast<std::uint64_t>(n);
    s.packetsRecv += 1;
    return static_cast<int>(n);
}

} // namespace aether
