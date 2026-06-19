// aether - non-blocking UDP socket and address.
// Data-first: plain Address / Socket structs, free functions. The header stays platform-free
// (bar one handle typedef); the OS calls live in socket_posix.cpp / socket_win.cpp.
#pragma once

#include <cstdint>
#include <optional>
#include <span>

namespace aether {

inline constexpr std::size_t maxUdpPacketSize = 65536;
inline constexpr std::size_t addrStorageSize  = 128;   // >= sizeof(sockaddr_storage)

// An IP endpoint (v4 or v6). Opaque bytes; build it with the helpers below.
struct Address {
    alignas(8) unsigned char storage[addrStorageSize]{};
    std::uint32_t            len{};
};

Address       addrAny(std::uint16_t port);         // 0.0.0.0:port
Address       addrAny6(std::uint16_t port);        // [::]:port
Address       addrLocalhost(std::uint16_t port);   // 127.0.0.1:port
Address       addrV4(std::uint32_t ip, std::uint16_t port);
std::uint16_t addrPort(const Address& a);
bool          addrEqual(const Address& a, const Address& b);

// A UDP socket handle: an int fd on POSIX, but a Windows SOCKET is an unsigned pointer-width value
// that does not fit in an int -- so the handle type is selected per platform. This typedef is the
// one place portability reaches past the platform .cpp.
#ifdef _WIN32
using SocketHandle = std::uintptr_t;
inline constexpr SocketHandle invalidSocket = ~static_cast<SocketHandle>(0);   // INVALID_SOCKET
#else
using SocketHandle = int;
inline constexpr SocketHandle invalidSocket = -1;
#endif

// A non-blocking UDP socket. fd == invalidSocket means invalid. Stats are plain counters.
struct Socket {
    SocketHandle  fd{ invalidSocket };
    std::uint64_t bytesSent{};
    std::uint64_t bytesRecv{};
    std::uint64_t packetsSent{};
    std::uint64_t packetsRecv{};
};

std::optional<Socket> openUdp(const Address& bindAddr);   // socket + reuseaddr + bind + non-blocking
void                  closeSocket(Socket& s);
bool                  isOpen(const Socket& s);
Address               localAddr(const Socket& s);         // getsockname

int sendTo(Socket& s, std::span<const std::uint8_t> data, const Address& to);   // bytes, or -1
int recvFrom(Socket& s, std::span<std::uint8_t> buf, Address& from);            // bytes (>0), 0 if none, -1 on error

} // namespace aether
