// aether - NAT punch-through. Two peers behind NATs cannot accept unsolicited inbound, so a public
// rendezvous server pairs them: each peer registers for a room, the server learns its public
// (NAT-mapped) address from the datagram source and hands each peer the other's address plus a role
// (one connects, one accepts). Both then send to that address, opening their NAT mappings, and the
// normal aether handshake completes over the direct path. Data-first: plain structs + free functions.
#pragma once

#include "aether/serialize.hpp"
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

// Addresses go on the wire via the canonical {family, port, ip} form (socket.hpp's serializeAddr /
// deserializeAddr) so a mac peer and a linux/windows peer agree -- raw sockaddr bytes would not.

// --- rendezvous wire protocol ---
// Register: a peer joins a room. Paired: once two peers share a room, the server returns the other
// peer's public address + a role (one connects, the other accepts).
enum class RendezvousMsg : std::uint8_t { Register = 1, Paired = 2, Relay = 3 };
enum class PunchRole     : std::uint8_t { Connect = 0, Accept = 1 };

inline constexpr double registerRetryMs       = 1000.0;   // re-send Register this often until the rendezvous pairs us
inline constexpr double defaultPunchTimeoutMs = 5000.0;   // try the direct hole-punch this long, then fall back to relay

inline Bytes encodeRegister(std::uint64_t roomId) {
    Bytes b(9);
    b[0] = static_cast<std::uint8_t>(RendezvousMsg::Register);
    putU64(b.data() + 1, roomId);
    return b;
}
inline std::optional<std::uint64_t> decodeRegister(const Bytes& b) {
    if (b.size() < 9 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Register)) return std::nullopt;
    return getU64(b.data() + 1);
}
inline Bytes encodePaired(PunchRole role, const Address& peerAddr) {
    Bytes b;
    b.push_back(static_cast<std::uint8_t>(RendezvousMsg::Paired));
    b.push_back(static_cast<std::uint8_t>(role));
    const Bytes addr = serializeAddr(peerAddr);
    b.insert(b.end(), addr.begin(), addr.end());
    return b;
}
inline std::optional<std::pair<PunchRole, Address>> decodePaired(const Bytes& b) {
    if (b.size() < 2 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Paired)) return std::nullopt;
    if (b[1] > static_cast<std::uint8_t>(PunchRole::Accept)) return std::nullopt;   // reject an undefined role byte rather than treat it as Accept
    const auto role = static_cast<PunchRole>(b[1]);
    const auto addr = deserializeAddr(b.data() + 2, b.size() - 2);
    if (!addr) return std::nullopt;
    return std::pair<PunchRole, Address>{ role, *addr };
}

// Relay: a punch-failed peer wraps each packet for the rendezvous to forward to its session partner.
inline Bytes encodeRelay(std::uint64_t roomId, const std::uint8_t* inner, std::size_t n) {
    Bytes b(9);
    b.reserve(static_cast<std::size_t>(9) + n);
    b[0] = static_cast<std::uint8_t>(RendezvousMsg::Relay);
    putU64(b.data() + 1, roomId);
    b.insert(b.end(), inner, inner + n);
    return b;
}
inline std::optional<std::pair<std::uint64_t, Bytes>> decodeRelay(const Bytes& b) {
    if (b.size() < 9 || b[0] != static_cast<std::uint8_t>(RendezvousMsg::Relay)) return std::nullopt;
    return std::pair<std::uint64_t, Bytes>{ getU64(b.data() + 1), Bytes(b.begin() + 9, b.end()) };
}

// --- rendezvous server: pairs two peers per room, and relays between them when the punch fails ---
inline constexpr double rendezvousTtlMs    = 300000.0;   // drop a waiting peer / idle session after 5 min
inline constexpr int    rendezvousMaxRooms = 4096;       // hard cap on each room table (waiting + sessions): a Register-flood memory shield

struct RendezvousSession { Address a; Address b; MonoTime at; };   // the paired peers + last activity
struct RendezvousServer {
    std::map<std::uint64_t, std::pair<Address, MonoTime>> waiting;    // roomId -> (first peer, when it registered)
    std::map<std::uint64_t, RendezvousSession>            sessions;   // roomId -> the paired peers, for relaying
    int                                                   maxRooms = rendezvousMaxRooms;   // hard cap on each table (flood shield)
};

// Evict the stalest entry of a table at the room cap -- a count-based flood shield complementing the
// time-based TTL sweep, mirroring the bounded self-cleaning tables elsewhere (rate limiter, tokens).
inline void evictOldestWaiting(RendezvousServer& rv) {
    auto oldest = rv.waiting.end();
    for (auto it = rv.waiting.begin(); it != rv.waiting.end(); ++it)
        if (oldest == rv.waiting.end() || it->second.second.ns < oldest->second.second.ns) oldest = it;
    if (oldest != rv.waiting.end()) rv.waiting.erase(oldest);
}
inline void evictOldestSession(RendezvousServer& rv) {
    auto oldest = rv.sessions.end();
    for (auto it = rv.sessions.begin(); it != rv.sessions.end(); ++it)
        if (oldest == rv.sessions.end() || it->second.at.ns < oldest->second.at.ns) oldest = it;
    if (oldest != rv.sessions.end()) rv.sessions.erase(oldest);
}

// Pure: a Register pairs with a waiting peer in the same room and returns the Paired replies to send
// -- the waiter accepts, the newcomer connects. Stale waiters / idle sessions are swept by TTL each
// call so a long-running server does not leak. Testable without a socket.
inline std::vector<std::pair<Address, Bytes>> rendezvousProcess(
        RendezvousServer& rv, const std::vector<std::pair<Address, Bytes>>& incoming, MonoTime now) {
    for (auto it = rv.waiting.begin(); it != rv.waiting.end();)
        if (elapsedMs(it->second.second, now) >= rendezvousTtlMs) it = rv.waiting.erase(it); else ++it;
    for (auto it = rv.sessions.begin(); it != rv.sessions.end();)
        if (elapsedMs(it->second.at, now) >= rendezvousTtlMs) it = rv.sessions.erase(it); else ++it;

    std::vector<std::pair<Address, Bytes>> out;
    for (const auto& [src, data] : incoming) {
        if (const auto room = decodeRegister(data)) {
            const auto it = rv.waiting.find(*room);
            if (it == rv.waiting.end()) {
                if (static_cast<int>(rv.waiting.size()) >= rv.maxRooms) evictOldestWaiting(rv);   // at the cap: shed the stalest waiter
                rv.waiting[*room] = { src, now };                                 // first peer waits
            } else {
                const Address first = it->second.first;
                rv.waiting.erase(it);
                if (rv.sessions.find(*room) == rv.sessions.end() && static_cast<int>(rv.sessions.size()) >= rv.maxRooms) evictOldestSession(rv);
                rv.sessions[*room] = { first, src, now };                         // remember the pair for relay fallback
                out.emplace_back(first, encodePaired(PunchRole::Accept, src));     // the waiter accepts
                out.emplace_back(src,   encodePaired(PunchRole::Connect, first));  // the newcomer connects
            }
        } else if (const auto relay = decodeRelay(data)) {
            if (const auto sit = rv.sessions.find(relay->first); sit != rv.sessions.end()) {
                const bool isFirst  = addrEqual(src, sit->second.a);
                const bool isSecond = addrEqual(src, sit->second.b);
                if (isFirst || isSecond) {   // only a paired member may relay -- not an open reflector
                    sit->second.at = now;     // activity keeps the session alive
                    out.emplace_back(isFirst ? sit->second.b : sit->second.a, relay->second);
                }
            }
        }
    }
    return out;
}

// Drive the server over a real socket: drain Registers, send the Paired replies.
inline void rendezvousTick(RendezvousServer& rv, Socket& sock, MonoTime now) {
    static thread_local std::vector<std::uint8_t> scratch(maxUdpPacketSize);
    std::vector<std::pair<Address, Bytes>> incoming;
    for (;;) {
        Address from{};
        const int n = recvFrom(sock, std::span<std::uint8_t>(scratch.data(), scratch.size()), from);
        if (n < 0) break;   // -1 == no more data; a 0-byte datagram returns 0 and is drained so it cannot stall the queue
        incoming.emplace_back(from, Bytes(scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(n)));
    }
    for (const auto& [addr, data] : rendezvousProcess(rv, incoming, now))
        sendTo(sock, std::span<const std::uint8_t>(data.data(), data.size()), addr);
}

} // namespace aether
