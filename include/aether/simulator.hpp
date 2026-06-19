// aether - network condition simulator. Models loss, latency, jitter, duplicates, reordering,
// and a token-bucket bandwidth cap for testing a real send path. Addresses are opaque u64 keys.
// Data-first: a plain struct mutated by free functions.
#pragma once

#include "aether/config.hpp"
#include "aether/types.hpp"
#include "aether/util.hpp"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <utility>
#include <vector>

namespace aether {

inline constexpr double outOfOrderMaxDelayMs         = 50.0;
inline constexpr double immediateDeliveryThresholdMs = 1.0;
inline constexpr double duplicateJitterMs            = 20.0;

struct DelayedPacket { Bytes data; std::uint64_t addr = 0; MonoTime deliverAt{}; };

struct NetworkSimulator {
    SimulationConfig         config;
    std::deque<DelayedPacket> delayedPackets;
    double                   tokenBucketTokens = 0.0;
    MonoTime                 lastTokenRefill{};
    std::uint64_t            rngState = 0;
};

inline NetworkSimulator newNetworkSimulator(const SimulationConfig& config, MonoTime now) {
    NetworkSimulator s;
    s.config         = config;
    s.lastTokenRefill = now;
    s.rngState       = now.ns;
    return s;
}

inline std::uint64_t simNextRandom(NetworkSimulator& s) { const auto r = nextRandom(s.rngState); s.rngState = r.state; return r.output; }

inline void refillTokens(NetworkSimulator& s, MonoTime now) {
    const double elapsedSecs = elapsedMs(s.lastTokenRefill, now) / 1000.0;
    const double refillRate  = static_cast<double>(s.config.bandwidthLimitBytesPerSec);
    s.tokenBucketTokens = std::min(s.tokenBucketTokens + elapsedSecs * refillRate, refillRate);   // cap at 1s worth
    s.lastTokenRefill   = now;
}

using SimPacket = std::pair<Bytes, std::uint64_t>;

// Push an outgoing packet through the simulator; returns any packets to deliver immediately.
inline std::vector<SimPacket> simulatorProcessSend(NetworkSimulator& s, const Bytes& data, std::uint64_t addr, MonoTime now) {
    const std::uint64_t   r1  = simNextRandom(s);
    const std::uint64_t   r2  = simNextRandom(s);
    const std::uint64_t   r3  = simNextRandom(s);
    const std::uint64_t   r4  = simNextRandom(s);
    const SimulationConfig& cfg = s.config;

    if (cfg.packetLoss > 0.0 && randomDouble(r1) < cfg.packetLoss) return {};
    if (cfg.bandwidthLimitBytesPerSec > 0) {
        refillTokens(s, now);
        const double needed = static_cast<double>(data.size());
        if (s.tokenBucketTokens < needed) return {};
        s.tokenBucketTokens -= needed;
    }

    const double baseLatency = static_cast<double>(cfg.latencyMs);
    const double jitter      = cfg.jitterMs > 0 ? randomDouble(r2) * static_cast<double>(cfg.jitterMs) : 0.0;
    const double extraDelay  = (cfg.outOfOrderChance > 0.0 && randomDouble(r3) < cfg.outOfOrderChance)
                                   ? randomDouble(r4) * outOfOrderMaxDelayMs : 0.0;
    const double   totalDelayMs = baseLatency + jitter + extraDelay;
    const MonoTime deliverAt{ now.ns + static_cast<std::uint64_t>(totalDelayMs * 1e6) };

    std::vector<SimPacket> immediate;
    if (totalDelayMs < immediateDeliveryThresholdMs) immediate.push_back({ data, addr });
    else                                             s.delayedPackets.push_back({ data, addr, deliverAt });

    const std::uint64_t rd = simNextRandom(s);
    if (cfg.duplicateChance > 0.0 && randomDouble(rd) < cfg.duplicateChance) {
        const std::uint64_t rdJitter = simNextRandom(s);   // independent draw for the dup jitter, not the gate value
        const MonoTime dupAt{ now.ns + static_cast<std::uint64_t>((totalDelayMs + randomDouble(rdJitter) * duplicateJitterMs) * 1e6) };
        s.delayedPackets.push_back({ data, addr, dupAt });
    }
    return immediate;
}

// Collect packets whose delivery time has passed.
inline std::vector<SimPacket> simulatorReceiveReady(NetworkSimulator& s, MonoTime now) {
    std::vector<SimPacket>    ready;
    std::deque<DelayedPacket> notReady;
    for (auto& p : s.delayedPackets) {
        if (p.deliverAt.ns <= now.ns) ready.push_back({ p.data, p.addr });
        else                          notReady.push_back(std::move(p));
    }
    s.delayedPackets = std::move(notReady);
    return ready;
}

inline int                     simulatorPendingCount(const NetworkSimulator& s) { return static_cast<int>(s.delayedPackets.size()); }
inline const SimulationConfig& simulatorConfig(const NetworkSimulator& s) { return s.config; }

} // namespace aether
