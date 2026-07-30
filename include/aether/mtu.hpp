// aether - path-MTU discovery (probe-based, RFC 8899 DPLPMTUD style). config.mtu is the FLOOR the
// whole transport is validated against; discovery only ever raises the usable size above it, by
// sending padded probe datagrams and watching whether they are acknowledged. Never ICMP: Too Big
// messages are filtered often enough that depending on them is how a connection stalls silently.
//
// What the discovered size changes is COALESCING only -- how many channel wires share one datagram.
// Fragmentation stays chunked at the floor on purpose: a fragmented message's chunk boundaries must
// hold for its whole lifetime (the peer's reassembler keys on the count, and selective retransmit
// keys on the indices), so chunking at a probed size would leave a reliable message unresendable if
// the path later shrank. Batches have no such pin -- they are re-formed from scratch at every flush,
// so a shrink self-heals on the next tick's coalescing.
//
// This is a pure state machine: the connection layer sends the probes, watches the acks, and calls
// in. Sizes below the floor are never probed; a path that cannot carry the floor is out of contract
// (the same assumption QUIC makes of 1200).
#pragma once

#include "aether/types.hpp"

#include <algorithm>
#include <optional>

namespace aether {

inline constexpr int    mtuProbeRetries        = 3;         // unanswered probes before a size is declared unfit
inline constexpr double mtuReprobeIntervalMs   = 600000.0;  // re-search cadence; paths change (RFC 8899 RAISE_TIMER)
inline constexpr double mtuProbeTimeoutFloorMs = 500.0;     // probes are cheap and not latency-critical: wait generously
// Black-hole fallback: near-total loss while coalescing above the floor reads as "the path shrank
// under us" -- collapse to the floor immediately rather than waiting out the re-probe timer. A real
// outage trips this too, harmlessly: the floor is equally dead until the path heals, and the next
// search restores the size.
inline constexpr double mtuBlackholeLossFraction = 0.9;
inline constexpr int    mtuBlackholeMinSamples   = 8;

struct MtuDiscovery {
    int  baseMtu = 0;   // the validated floor (config.mtu); never probed below
    int  ceiling = 0;   // the search's upper bound (config.mtuProbeCeiling)
    int  plpmtu  = 0;   // confirmed: a datagram this size has been proven to traverse the path
    bool enabled = false;
    // Binary-search bounds: every size <= lo is confirmed, every size > hi has failed.
    int  lo        = 0;
    int  hi        = 0;
    bool searching = false;
    std::optional<SequenceNum> probeSeq;      // packet sequence of the in-flight probe (none = no probe out)
    int                        probeSize  = 0;
    MonoTime                   probeSentAt{};
    int                        probeFails = 0;   // consecutive unanswered probes at probeSize
    std::optional<MonoTime>    searchDoneAt;     // set when a search concludes; drives the re-probe timer
};

inline MtuDiscovery newMtuDiscovery(int baseMtu, int ceiling, bool enabled) {
    MtuDiscovery m;
    m.baseMtu   = baseMtu;
    m.ceiling   = ceiling;
    m.plpmtu    = baseMtu;
    m.enabled   = enabled;
    m.lo        = baseMtu;
    m.hi        = ceiling;
    m.searching = enabled && ceiling > baseMtu;   // ceiling == floor: nothing to discover
    return m;
}

inline double mtuProbeTimeoutMs(double rtoMs) noexcept { return std::max(2.0 * rtoMs, mtuProbeTimeoutFloorMs); }

inline void mtuFinishSearch(MtuDiscovery& m, MonoTime now) {
    m.plpmtu       = m.lo;   // authoritative: a re-search that converged LOWER lowers it
    m.searching    = false;
    m.searchDoneAt = now;
    m.probeSeq     = std::nullopt;
    m.probeFails   = 0;
}

// Advance the search one tick. Returns the datagram size to probe now, or 0 when no probe should be
// sent (disabled, done, or one is still in flight). Handles the probe timeout (an unanswered probe
// counts against its size, three strikes and the size is unfit) and the periodic re-search.
inline int mtuTick(MtuDiscovery& m, MonoTime now, double rtoMs) {
    if (!m.enabled) return 0;
    if (!m.searching && m.searchDoneAt && elapsedMs(*m.searchDoneAt, now) >= mtuReprobeIntervalMs) {
        m.lo           = m.baseMtu;   // full re-search: a rerouted path can carry more OR less than before
        m.hi           = m.ceiling;
        m.searching    = m.lo < m.hi;
        m.searchDoneAt = std::nullopt;
    }
    if (!m.searching) return 0;
    if (m.probeSeq) {
        if (elapsedMs(m.probeSentAt, now) < mtuProbeTimeoutMs(rtoMs)) return 0;   // still waiting
        m.probeSeq = std::nullopt;
        if (++m.probeFails >= mtuProbeRetries) {
            m.hi         = m.probeSize - 1;   // this size does not fit the path
            m.probeFails = 0;
            if (m.lo >= m.hi) { mtuFinishSearch(m, now); return 0; }
        }
    }
    // Optimistic first: most paths carry the ceiling outright, so try it whole before bisecting.
    // The size is a pure function of (lo, hi, ceiling), so a retry naturally re-probes the same size.
    return m.hi == m.ceiling ? m.hi : (m.lo + m.hi + 1) / 2;
}

inline void mtuOnProbeSent(MtuDiscovery& m, SequenceNum seq, int size, MonoTime now) {
    m.probeSeq    = seq;
    m.probeSize   = size;
    m.probeSentAt = now;
}

// The in-flight probe was acknowledged: its size traverses the path, and is usable immediately.
inline void mtuOnProbeAcked(MtuDiscovery& m, MonoTime now) {
    if (!m.probeSeq) return;   // answered after the timeout already wrote it off: the retry will confirm
    m.lo         = m.probeSize;
    m.plpmtu     = std::max(m.plpmtu, m.lo);
    m.probeSeq   = std::nullopt;
    m.probeFails = 0;
    if (m.lo >= m.hi) mtuFinishSearch(m, now);
}

// Fall back to the floor NOW (see mtuBlackholeLossFraction) and search again from scratch. During an
// outage every probe fails too, so the search just re-concludes at the floor and the periodic
// re-probe restores the size once the path heals.
inline void mtuCollapse(MtuDiscovery& m) {
    m.plpmtu       = m.baseMtu;
    m.lo           = m.baseMtu;
    m.hi           = m.ceiling;
    m.searching    = m.enabled && m.lo < m.hi;
    m.probeSeq     = std::nullopt;
    m.probeFails   = 0;
    m.searchDoneAt = std::nullopt;
}

} // namespace aether
