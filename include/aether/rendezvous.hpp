// aether - NAT punch-through. Two peers behind NATs cannot accept unsolicited inbound, so a public
// rendezvous server pairs them: each peer registers for a room, the server learns its public
// (NAT-mapped) address from the datagram source and hands each peer the other's address plus a role
// (one connects, one accepts). Both then send to that address, opening their NAT mappings, and the
// normal aether handshake completes over the direct path. Data-first: plain structs + free functions.
#pragma once

#include "aether/socket.hpp"
#include "aether/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

namespace aether {

// --- address serialization: the raw sockaddr bytes (family/port/ip line up across platforms) ---
inline Bytes encodeAddr(const Address& a) {
    Bytes b;
    b.reserve(static_cast<std::size_t>(1) + a.len);
    b.push_back(static_cast<std::uint8_t>(a.len));
    b.insert(b.end(), a.storage, a.storage + a.len);
    return b;
}
inline std::optional<Address> decodeAddr(const std::uint8_t* p, std::size_t n) {
    if (n == 0) return std::nullopt;
    const std::uint32_t len = p[0];
    if (len > addrStorageSize || n < static_cast<std::size_t>(1) + len) return std::nullopt;
    Address a{};
    a.len = len;
    for (std::uint32_t i = 0; i < len; ++i) a.storage[i] = p[1 + i];
    return a;
}

// --- rendezvous wire protocol ---
// Register: a peer joins a room. Paired: once two peers share a room, the server returns the other
// peer's public address + a role (one connects, the other accepts).
enum class RendezvousMsg : std::uint8_t { Register = 1, Paired = 2 };
enum class PunchRole     : std::uint8_t { Connect = 0, Accept = 1 };

inline Bytes encodeRegister(std::uint64_t roomId) {
    Bytes b;
    b.push_back(static_cast<std::uint8_t>(RendezvousMsg::Register));
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(roomId >> (8 * i)));
    return b;
}
inline std::optional<std::uint64_t> decodeRegister(const Bytes& b) {
    if (b.size() < 9 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Register)) return std::nullopt;
    std::uint64_t room = 0;
    for (int i = 0; i < 8; ++i) room |= static_cast<std::uint64_t>(b[static_cast<std::size_t>(1 + i)]) << (8 * i);
    return room;
}
inline Bytes encodePaired(PunchRole role, const Address& peerAddr) {
    Bytes b;
    b.push_back(static_cast<std::uint8_t>(RendezvousMsg::Paired));
    b.push_back(static_cast<std::uint8_t>(role));
    const Bytes addr = encodeAddr(peerAddr);
    b.insert(b.end(), addr.begin(), addr.end());
    return b;
}
inline std::optional<std::pair<PunchRole, Address>> decodePaired(const Bytes& b) {
    if (b.size() < 2 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Paired)) return std::nullopt;
    const auto role = static_cast<PunchRole>(b[1]);
    const auto addr = decodeAddr(b.data() + 2, b.size() - 2);
    if (!addr) return std::nullopt;
    return std::pair<PunchRole, Address>{ role, *addr };
}

} // namespace aether
