// aether - pure deterministic network for testing. A fully in-memory link with configurable
// latency, loss, jitter, duplicates, and reordering, plus a multi-peer TestWorld. No real sockets,
// fully reproducible. Data-first: plain structs + free functions, state mutated in place.
#pragma once

#include "aether/peer.hpp"
#include "aether/security.hpp"
#include "aether/socket.hpp"
#include "aether/types.hpp"
#include "aether/util.hpp"

#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace aether {

inline constexpr std::uint64_t testNsPerMs                  = 1000000;
inline constexpr std::uint64_t testNetOutOfOrderMaxDelayNs  = 50000000;   // 50ms
inline constexpr std::uint64_t testNetDuplicateJitterNs     = 10000000;   // 10ms

struct TestNetConfig {
    std::uint64_t latencyNs        = 0;
    double        lossRate         = 0.0;
    std::uint64_t jitterNs         = 0;
    double        duplicateChance  = 0.0;
    double        outOfOrderChance = 0.0;
};

struct InFlightPacket { Address from{}; Address to{}; Bytes data; MonoTime deliverAt{}; };

struct TestNetState {
    MonoTime                              currentTime{};
    Address                               localAddr{};
    std::deque<InFlightPacket>            inFlight;
    std::deque<std::pair<Bytes, Address>> inbox;
    TestNetConfig                         config;
    std::uint64_t                         rng    = 42;   // deterministic seed
    bool                                  closed = false;
};

inline TestNetState initialTestNetState(const Address& localAddr) {
    TestNetState s;
    s.localAddr = localAddr;
    return s;
}

// Send: schedule the packet in flight, applying loss / latency / jitter / reorder / duplicate.
inline void testNetSend(TestNetState& st, const Address& to, const Bytes& bytes) {
    if (st.closed) return;
    const TestNetConfig& cfg = st.config;
    const auto r1 = nextRandom(st.rng); st.rng = r1.state;
    if (randomDouble(r1.output) < cfg.lossRate) return;                       // dropped
    const auto r2 = nextRandom(st.rng); st.rng = r2.state;
    const std::uint64_t jitter = cfg.jitterNs == 0 ? 0 : (r2.output % (cfg.jitterNs + 1));
    const auto r3 = nextRandom(st.rng); st.rng = r3.state;
    std::uint64_t oooDelay = 0;
    if (randomDouble(r3.output) < cfg.outOfOrderChance) {
        const auto r3b = nextRandom(st.rng); st.rng = r3b.state;   // independent draw for the delay magnitude
        oooDelay = r3b.output % (testNetOutOfOrderMaxDelayNs + 1);
    }
    const MonoTime deliverAt{ st.currentTime.ns + cfg.latencyNs + jitter + oooDelay };
    st.inFlight.push_back(InFlightPacket{ st.localAddr, to, bytes, deliverAt });
    const auto r4 = nextRandom(st.rng); st.rng = r4.state;
    if (randomDouble(r4.output) < cfg.duplicateChance) {
        const auto r5 = nextRandom(st.rng); st.rng = r5.state;
        const MonoTime dupAt{ deliverAt.ns + (r5.output % (testNetDuplicateJitterNs + 1)) };
        st.inFlight.push_back(InFlightPacket{ st.localAddr, to, bytes, dupAt });
    }
}

// Receive one delivered packet (CRC validated + stripped); nullopt if the inbox is empty.
inline std::optional<std::pair<Bytes, Address>> testNetRecv(TestNetState& st) {
    if (st.inbox.empty()) return std::nullopt;
    auto front = std::move(st.inbox.front());
    st.inbox.pop_front();
    auto v = validateAndStripCrc32(front.first);
    if (!v) return std::nullopt;                                              // drop corrupt
    return std::pair<Bytes, Address>{ std::move(*v), front.second };
}

// Advance time and move any in-flight packets addressed to us into the inbox.
inline void advanceTime(TestNetState& st, MonoTime newTime) {
    std::deque<InFlightPacket> still;
    for (auto& p : st.inFlight) {
        if (p.deliverAt.ns <= newTime.ns) {
            if (addrEqual(p.to, st.localAddr)) st.inbox.push_back({ p.data, p.from });
        } else {
            still.push_back(std::move(p));
        }
    }
    st.currentTime = newTime;
    st.inFlight    = std::move(still);
}

inline void simulateLatency(TestNetState& st, std::uint64_t ms) { st.config.latencyNs = ms * testNsPerMs; }
inline void simulateLoss(TestNetState& st, double rate) { st.config.lossRate = rate; }
inline int  testPendingCount(const TestNetState& st) { return static_cast<int>(st.inFlight.size()); }

// --- multi-peer world ---
struct TestWorld {
    std::map<PeerId, TestNetState> peers;
    MonoTime                       globalTime{};
};

inline TestWorld newTestWorld() { return TestWorld{}; }

// Get (creating if needed) the state for a peer at the given address.
inline TestNetState& worldPeer(TestWorld& w, const Address& addr) {
    const PeerId pid{ addr };
    auto it = w.peers.find(pid);
    if (it == w.peers.end()) {
        TestNetState s = initialTestNetState(addr);
        s.currentTime = w.globalTime;
        it = w.peers.emplace(pid, std::move(s)).first;
    }
    return it->second;
}

// Deliver every ready packet to its destination's inbox; keep the rest with their senders.
inline void deliverPackets(TestWorld& w) {
    std::vector<InFlightPacket> all;
    for (auto& [pid, ps] : w.peers) {
        (void)pid;
        for (auto& p : ps.inFlight) all.push_back(std::move(p));
        ps.inFlight.clear();
    }
    for (auto& p : all) {
        if (p.deliverAt.ns <= w.globalTime.ns) {
            if (const auto it = w.peers.find(PeerId{ p.to }); it != w.peers.end()) it->second.inbox.push_back({ p.data, p.from });
        } else {
            if (const auto it = w.peers.find(PeerId{ p.from }); it != w.peers.end()) it->second.inFlight.push_back(std::move(p));
        }
    }
}

inline void worldAdvanceTime(TestWorld& w, MonoTime newTime) {
    w.globalTime = newTime;
    for (auto& [pid, ps] : w.peers) { (void)pid; ps.currentTime = newTime; }
    deliverPackets(w);
}

} // namespace aether
