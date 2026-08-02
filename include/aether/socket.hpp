// aether - non-blocking UDP socket and address.
// Data-first: plain Address / Socket structs, free functions. The header stays platform-free
// (bar one handle typedef); the OS calls live in socket_posix.cpp / socket_win.cpp.
#pragma once

#include "aether/types.hpp"

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

// --- address hashing (rate-limit keys) ---
inline constexpr std::uint64_t fnvOffsetBasis = 14695981039346656037ull;
inline constexpr std::uint64_t fnvPrime       = 1099511628211ull;
inline std::uint64_t fnvMix(std::uint64_t h, std::uint64_t v) noexcept { return (h ^ v) * fnvPrime; }

// Hash a remote address to a rate-limit key: the HOST, deliberately NOT the (host, port) pair.
//
// Hashing the whole sockaddr included the source port, so one ordinary unspoofed host got a fresh
// budget for every port it bound: measured at ~1200x its cap from 5000 ports, which also filled the
// tracked-source table and made the limiter shed every NEW source -- so a single machine could lock
// legitimate clients out entirely. A port is not an identity; the host is what a per-source limit is
// meant to bound.
//
// The sockaddr layout is fixed where it matters: both sockaddr_in and sockaddr_in6 keep the port at
// bytes 2-3, with the address at 4..8 (v4) or 8..24 (v6). Reading those directly keeps this
// allocation-free, which serializeAddr's canonical form would not be on a per-packet path.
//
// `seed` is a per-server random value: FNV-1a is trivially invertible, so an unseeded key let an
// attacker with an address range compute one that collides with a victim's bucket and starve it.
inline std::uint64_t sockAddrToKey(const Address& addr, std::uint64_t seed) noexcept {
    const bool          v6  = addr.len > 16;   // sockaddr_in is 16 bytes, sockaddr_in6 is 28
    const std::uint32_t off = v6 ? 8u : 4u;
    const std::uint32_t n   = v6 ? 16u : 4u;
    std::uint64_t       h   = fnvMix(fnvMix(fnvOffsetBasis, seed), v6 ? 6u : 4u);   // family: v4 and v6 must not collide
    for (std::uint32_t i = 0; i < n && off + i < addr.len; ++i) h = fnvMix(h, addr.storage[off + i]);
    return h;
}

// Canonical, cross-platform address wire form: [family:1 (4|6)][port:2 BE][ip: 4 or 16 bytes]. Send
// an address between peers with this, NOT the raw sockaddr bytes -- sockaddr layout differs across
// platforms (e.g. macOS has a leading sin_len byte), so raw bytes mis-parse between a mac and a
// linux/windows peer.
Bytes                  serializeAddr(const Address& a);
std::optional<Address> deserializeAddr(const std::uint8_t* p, std::size_t n);

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
int recvFrom(Socket& s, std::span<std::uint8_t> buf, Address& from);            // datagram bytes (>=0; 0 is a real 0-byte datagram), -1 if no data (would-block) or error

} // namespace aether
