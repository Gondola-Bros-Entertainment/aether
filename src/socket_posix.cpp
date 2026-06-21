// aether - UDP socket platform layer (POSIX/BSD sockets; macOS + Linux).
#include "aether/random.hpp"
#include "aether/socket.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#  define AETHER_HAS_SA_LEN 1   // BSD sockaddrs carry a leading length byte; set it so a built address
#endif                          // is byte-identical to a kernel-returned one (addrEqual / PeerId are memcmp)

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
#ifdef AETHER_HAS_SA_LEN
    in->sin_len         = sizeof(sockaddr_in);
#endif
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
#ifdef AETHER_HAS_SA_LEN
    in->sin6_len    = sizeof(sockaddr_in6);
#endif
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

Bytes serializeAddr(const Address& a) {
    Bytes b;
    if (sa(a)->sa_family == AF_INET6) {
        const auto* in   = reinterpret_cast<const sockaddr_in6*>(a.storage);
        const auto  port = ntohs(in->sin6_port);
        b.push_back(6);
        b.push_back(static_cast<std::uint8_t>(port >> 8));
        b.push_back(static_cast<std::uint8_t>(port & 0xFF));
        const auto* ip = reinterpret_cast<const std::uint8_t*>(&in->sin6_addr);
        b.insert(b.end(), ip, ip + 16);
    } else {
        const auto* in   = reinterpret_cast<const sockaddr_in*>(a.storage);
        const auto  port = ntohs(in->sin_port);
        const auto  ip   = ntohl(in->sin_addr.s_addr);
        b.push_back(4);
        b.push_back(static_cast<std::uint8_t>(port >> 8));
        b.push_back(static_cast<std::uint8_t>(port & 0xFF));
        b.push_back(static_cast<std::uint8_t>(ip >> 24));
        b.push_back(static_cast<std::uint8_t>(ip >> 16));
        b.push_back(static_cast<std::uint8_t>(ip >> 8));
        b.push_back(static_cast<std::uint8_t>(ip));
    }
    return b;
}

std::optional<Address> deserializeAddr(const std::uint8_t* p, std::size_t n) {
    if (n < 3) return std::nullopt;
    const std::uint16_t port = static_cast<std::uint16_t>((std::uint16_t(p[1]) << 8) | p[2]);
    if (p[0] == 4) {
        if (n != 7) return std::nullopt;   // exact length: the wire form is canonical, no trailing bytes accepted
        const std::uint32_t ip = (std::uint32_t(p[3]) << 24) | (std::uint32_t(p[4]) << 16) | (std::uint32_t(p[5]) << 8) | p[6];
        return addrV4(ip, port);
    }
    if (p[0] == 6) {
        if (n != 19) return std::nullopt;   // exact length, as above
        Address a{};
        auto* in        = reinterpret_cast<sockaddr_in6*>(a.storage);
        in->sin6_family = AF_INET6;
        in->sin6_port   = htons(port);
        std::memcpy(&in->sin6_addr, p + 3, 16);
#ifdef AETHER_HAS_SA_LEN
        in->sin6_len    = sizeof(sockaddr_in6);
#endif
        a.len           = sizeof(sockaddr_in6);
        return a;
    }
    return std::nullopt;
}

std::optional<Socket> openUdp(const Address& bindAddr) {
    const int          family = sa(bindAddr)->sa_family;
    const SocketHandle fd     = ::socket(family, SOCK_DGRAM, 0);
    if (fd == invalidSocket) return std::nullopt;
    const int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    if (::bind(fd, sa(bindAddr), bindAddr.len) < 0) { ::close(fd); return std::nullopt; }
    // The non-blocking mode is load-bearing -- the whole per-tick drain assumes recv never blocks.
    // If it cannot be set, fail closed rather than hand back a blocking socket that hangs the loop.
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { ::close(fd); return std::nullopt; }
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
    ssize_t n;
    do { n = ::sendto(s.fd, data.data(), data.size(), 0, sa(to), to.len); } while (n < 0 && errno == EINTR);
    if (n < 0) return -1;
    s.bytesSent   += static_cast<std::uint64_t>(n);
    s.packetsSent += 1;
    return static_cast<int>(n);
}

// Returns the datagram length (>= 0; a real 0-byte datagram returns 0), or -1 for "no more data"
// (EAGAIN/EWOULDBLOCK) or a hard error. The drain loops on n >= 0, so a 0-byte datagram no longer
// reads as "queue empty" and stalls the rest of the queue for the tick.
int recvFrom(Socket& s, std::span<std::uint8_t> buf, Address& from) {
    from = Address{};
    socklen_t len = sizeof(from.storage);
    ssize_t   n;
    do { len = sizeof(from.storage); n = ::recvfrom(s.fd, buf.data(), buf.size(), 0, sa(from), &len); }
    while (n < 0 && errno == EINTR);                          // a signal is not "no data" -- retry
    if (n < 0) return -1;
    from.len      = len;
    s.bytesRecv   += static_cast<std::uint64_t>(n);
    s.packetsRecv += 1;
    return static_cast<int>(n);
}

void secureRandomBytes(std::uint8_t* out, std::size_t len) {
    constexpr std::size_t getentropyMaxChunk = 256;   // getentropy(2) rejects larger requests
    std::size_t off = 0;
    while (off < len) {
        const std::size_t chunk = (len - off < getentropyMaxChunk) ? (len - off) : getentropyMaxChunk;
        if (::getentropy(out + off, chunk) != 0) {
            // The CSPRNG is the only source of key material; fail closed rather than hand back
            // un-random bytes that would become a predictable key.
            std::fprintf(stderr, "aether: getentropy failed (errno %d); aborting to avoid weak keys\n", errno);
            std::abort();
        }
        off += chunk;
    }
}

} // namespace aether
