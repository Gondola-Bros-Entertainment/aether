// aether - UDP socket platform layer (Winsock; Windows).
#include "aether/random.hpp"
#include "aether/socket.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")   // also linked via CMake; harmless to repeat
#pragma comment(lib, "bcrypt.lib")   // BCryptGenRandom

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
        a.len           = sizeof(sockaddr_in6);
        return a;
    }
    return std::nullopt;
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
    // Non-blocking is load-bearing for the per-tick drain; fail closed if it cannot be set rather
    // than return a blocking socket that hangs the loop.
    u_long nonblocking = 1;
    if (::ioctlsocket(h, FIONBIO, &nonblocking) != 0) { ::closesocket(h); return std::nullopt; }
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

// Returns the datagram length (>= 0; a real 0-byte datagram returns 0), or -1 for "no more data"
// (WSAEWOULDBLOCK) or a hard error. The drain loops on n >= 0, so a 0-byte datagram no longer reads
// as "queue empty" and stalls the rest of the queue for the tick.
int recvFrom(Socket& s, std::span<std::uint8_t> buf, Address& from) {
    from = Address{};
    int       len = sizeof(from.storage);
    const int n   = ::recvfrom(static_cast<SOCKET>(s.fd), reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0, sa(from), &len);
    if (n < 0) return -1;
    from.len      = static_cast<std::uint32_t>(len);
    s.bytesRecv   += static_cast<std::uint64_t>(n);
    s.packetsRecv += 1;
    return n;
}

void secureRandomBytes(std::uint8_t* out, std::size_t len) {
    const NTSTATUS st = BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {   // STATUS_SUCCESS == 0; fail closed rather than proceed with un-random key material
        std::fprintf(stderr, "aether: BCryptGenRandom failed (0x%lx); aborting to avoid weak keys\n",
                     static_cast<unsigned long>(st));
        std::abort();
    }
}

} // namespace aether
