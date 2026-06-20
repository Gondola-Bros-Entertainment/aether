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
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

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
enum class RendezvousMsg : std::uint8_t { Register = 1, Paired = 2, Relay = 3 };
enum class PunchRole     : std::uint8_t { Connect = 0, Accept = 1 };

inline constexpr double registerRetryMs = 1000.0;   // re-send Register this often until the rendezvous pairs us

inline Bytes encodeRegister(std::uint64_t roomId) {
    Bytes b;
    b.push_back(static_cast<std::uint8_t>(RendezvousMsg::Register));
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(roomId >> (8 * i)));
    return b;
}
inline std::optional<std::uint64_t> decodeRegister(const Bytes& b) {
    if (b.size() < 9 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Register)) return std::nullopt;
    std::uint64_t room = 0;
    for (std::size_t i = 0; i < 8; ++i) room |= static_cast<std::uint64_t>(b[1 + i]) << (8 * i);
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

// Relay: a punch-failed peer wraps each packet for the rendezvous to forward to its session partner.
inline Bytes encodeRelay(std::uint64_t roomId, const std::uint8_t* inner, std::size_t n) {
    Bytes b;
    b.reserve(static_cast<std::size_t>(9) + n);
    b.push_back(static_cast<std::uint8_t>(RendezvousMsg::Relay));
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(roomId >> (8 * i)));
    b.insert(b.end(), inner, inner + n);
    return b;
}
inline std::optional<std::pair<std::uint64_t, Bytes>> decodeRelay(const Bytes& b) {
    if (b.size() < 9 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Relay)) return std::nullopt;
    std::uint64_t room = 0;
    for (std::size_t i = 0; i < 8; ++i) room |= static_cast<std::uint64_t>(b[1 + i]) << (8 * i);
    return std::pair<std::uint64_t, Bytes>{ room, Bytes(b.begin() + 9, b.end()) };
}

// --- rendezvous server: pairs two peers per room, and relays between them when the punch fails ---
struct RendezvousServer {
    std::map<std::uint64_t, Address>                     waiting;    // roomId -> first peer, awaiting its pair
    std::map<std::uint64_t, std::pair<Address, Address>> sessions;   // roomId -> the paired peers, for relaying
};

// Pure: a Register pairs with a waiting peer in the same room and returns the Paired replies to
// send -- the waiter accepts, the newcomer connects. Testable without a socket.
inline std::vector<std::pair<Address, Bytes>> rendezvousProcess(
        RendezvousServer& rv, const std::vector<std::pair<Address, Bytes>>& incoming) {
    std::vector<std::pair<Address, Bytes>> out;
    for (const auto& [src, data] : incoming) {
        if (const auto room = decodeRegister(data)) {
            const auto it = rv.waiting.find(*room);
            if (it == rv.waiting.end()) {
                rv.waiting[*room] = src;                                          // first peer waits
            } else {
                const Address first = it->second;
                rv.waiting.erase(it);
                rv.sessions[*room] = { first, src };                             // remember the pair for relay fallback
                out.emplace_back(first, encodePaired(PunchRole::Accept, src));    // the waiter accepts
                out.emplace_back(src,   encodePaired(PunchRole::Connect, first)); // the newcomer connects
            }
        } else if (const auto relay = decodeRelay(data)) {
            if (const auto sit = rv.sessions.find(relay->first); sit != rv.sessions.end()) {
                const Address& dst = addrEqual(src, sit->second.first) ? sit->second.second : sit->second.first;
                out.emplace_back(dst, relay->second);                            // forward the inner packet to the partner
            }
        }
    }
    return out;
}

// Drive the server over a real socket: drain Registers, send the Paired replies.
inline void rendezvousTick(RendezvousServer& rv, Socket& sock) {
    static thread_local std::vector<std::uint8_t> scratch(maxUdpPacketSize);
    std::vector<std::pair<Address, Bytes>> incoming;
    for (;;) {
        Address from{};
        const int n = recvFrom(sock, std::span<std::uint8_t>(scratch.data(), scratch.size()), from);
        if (n <= 0) break;
        incoming.emplace_back(from, Bytes(scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(n)));
    }
    for (const auto& [addr, data] : rendezvousProcess(rv, incoming))
        sendTo(sock, std::span<const std::uint8_t>(data.data(), data.size()), addr);
}

} // namespace aether
