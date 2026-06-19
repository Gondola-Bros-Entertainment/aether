// aether - message fragmentation, reassembly, and path-MTU discovery. Splits messages too big
// for the MTU into 6-byte-headered
// fragments, reassembles them, and probes the path MTU via binary search.
#pragma once

#include "aether/types.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <vector>

namespace aether {

inline constexpr int    fragmentHeaderSize      = 6;     // messageId(4) + index(1) + count(1)
inline constexpr int    maxFragmentCount        = 255;
inline constexpr int    fragMinMtu              = 576;
inline constexpr int    fragMaxMtu              = 1500;
inline constexpr int    mtuConvergenceThreshold = 1;
inline constexpr double defaultProbeTimeoutMs   = 500.0;
inline constexpr int    defaultMaxProbeAttempts = 10;

// --- fragment header (messageId is MSB-first) ---
struct FragmentHeader { MessageId messageId{}; std::uint8_t index{}; std::uint8_t count{}; };

inline void writeFragmentHeader(std::uint8_t* p, const FragmentHeader& h) noexcept {
    const std::uint32_t id = static_cast<std::uint32_t>(h.messageId);
    p[0] = std::uint8_t(id >> 24); p[1] = std::uint8_t(id >> 16);
    p[2] = std::uint8_t(id >> 8);  p[3] = std::uint8_t(id);
    p[4] = h.index; p[5] = h.count;
}
inline std::optional<FragmentHeader> readFragmentHeader(const std::uint8_t* p, std::size_t n) noexcept {
    if (n < static_cast<std::size_t>(fragmentHeaderSize)) return std::nullopt;
    const std::uint32_t id = (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
                             (std::uint32_t(p[2]) << 8)  |  std::uint32_t(p[3]);
    return FragmentHeader{ static_cast<MessageId>(id), p[4], p[5] };
}

// --- splitting ---
struct FragmentResult { std::vector<Bytes> fragments; bool tooMany{}; };

inline FragmentResult fragmentMessage(MessageId id, const std::uint8_t* data, std::size_t len, int maxPayload) {
    FragmentResult r;
    if (len == 0 || maxPayload <= 0) return r;
    const int count = static_cast<int>((len + static_cast<std::size_t>(maxPayload) - 1) / static_cast<std::size_t>(maxPayload));
    if (count > maxFragmentCount) { r.tooMany = true; return r; }
    for (int i = 0; i < count; ++i) {
        const std::size_t start = static_cast<std::size_t>(i) * static_cast<std::size_t>(maxPayload);
        const std::size_t end   = std::min(start + static_cast<std::size_t>(maxPayload), len);
        Bytes frag(static_cast<std::size_t>(fragmentHeaderSize) + (end - start));
        writeFragmentHeader(frag.data(), FragmentHeader{ id, static_cast<std::uint8_t>(i), static_cast<std::uint8_t>(count) });
        std::memcpy(frag.data() + fragmentHeaderSize, data + start, end - start);
        r.fragments.push_back(std::move(frag));
    }
    return r;
}

// --- reassembly ---
struct FragmentBuffer {
    std::map<std::uint8_t, Bytes> fragments;
    std::uint8_t count{};
    MonoTime     createdAt{};
    int          totalSize{};
};
struct FragmentAssembler {
    std::map<MessageId, FragmentBuffer> buffers;
    double timeoutMs{};
    int    maxBufferSize{};
    int    currentSize{};
};
inline FragmentAssembler newFragmentAssembler(double timeoutMs, int maxSize) { return { {}, timeoutMs, maxSize, 0 }; }

inline void cleanupFragments(FragmentAssembler& a, MonoTime now) {
    for (auto it = a.buffers.begin(); it != a.buffers.end(); ) {
        if (elapsedMs(it->second.createdAt, now) >= a.timeoutMs) {
            a.currentSize -= it->second.totalSize;
            it = a.buffers.erase(it);
        } else {
            ++it;
        }
    }
}
inline void expireOldestFragment(FragmentAssembler& a) {
    auto oldest = a.buffers.end();
    for (auto it = a.buffers.begin(); it != a.buffers.end(); ++it)
        if (oldest == a.buffers.end() || it->second.createdAt.ns < oldest->second.createdAt.ns) oldest = it;
    if (oldest != a.buffers.end()) { a.currentSize -= oldest->second.totalSize; a.buffers.erase(oldest); }
}

// Feed one fragment; returns the reassembled message if this fragment completed it.
inline std::optional<Bytes> processFragment(FragmentAssembler& a, const std::uint8_t* data, std::size_t len, MonoTime now) {
    cleanupFragments(a, now);
    const auto hdr = readFragmentHeader(data, len);
    if (!hdr) return std::nullopt;
    const std::uint8_t* fragData = data + fragmentHeaderSize;
    const int           fragSize = static_cast<int>(len - static_cast<std::size_t>(fragmentHeaderSize));
    const MessageId     msgId    = hdr->messageId;

    auto it = a.buffers.find(msgId);
    if (it != a.buffers.end() && it->second.count != hdr->count) return std::nullopt;   // count disagreement

    if (a.currentSize + fragSize > a.maxBufferSize) expireOldestFragment(a);

    it = a.buffers.find(msgId);
    if (it == a.buffers.end()) {
        FragmentBuffer nb;
        nb.count = hdr->count;
        nb.createdAt = now;
        it = a.buffers.emplace(msgId, std::move(nb)).first;
    }
    FragmentBuffer& buf = it->second;

    if (hdr->index < buf.count && buf.fragments.find(hdr->index) == buf.fragments.end()) {
        buf.fragments.emplace(hdr->index, Bytes(fragData, fragData + fragSize));
        buf.totalSize  += fragSize;
        a.currentSize  += fragSize;
    }

    if (buf.count > 0 && buf.fragments.size() == static_cast<std::size_t>(buf.count)) {
        Bytes out;
        out.reserve(static_cast<std::size_t>(buf.totalSize));
        for (const auto& kv : buf.fragments) out.insert(out.end(), kv.second.begin(), kv.second.end());
        a.currentSize -= buf.totalSize;
        a.buffers.erase(it);
        return out;
    }
    return std::nullopt;
}

// --- path-MTU discovery (binary search) ---
enum class MtuState { Probing, Complete };
struct MtuDiscovery {
    int      minMtu        = fragMinMtu;
    int      maxMtu        = fragMaxMtu;
    int      currentProbe  = (fragMinMtu + fragMaxMtu) / 2;
    int      discoveredMtu = fragMinMtu;
    MtuState state         = MtuState::Probing;
    double   probeTimeoutMs = defaultProbeTimeoutMs;
    bool     hasLastProbe  = false;
    MonoTime lastProbeTime{};
    int      attempts      = 0;
    int      maxAttempts   = defaultMaxProbeAttempts;
};
inline MtuDiscovery newMtuDiscovery(int lo, int hi) {
    MtuDiscovery m;
    m.minMtu = lo; m.maxMtu = hi; m.currentProbe = (lo + hi) / 2; m.discoveredMtu = lo;
    return m;
}
inline MtuDiscovery defaultMtuDiscovery() { return newMtuDiscovery(fragMinMtu, fragMaxMtu); }

inline std::optional<int> nextProbe(MtuDiscovery& m, MonoTime now) {
    if (m.state == MtuState::Complete || m.attempts >= m.maxAttempts) { m.state = MtuState::Complete; return std::nullopt; }
    if (m.maxMtu - m.minMtu <= mtuConvergenceThreshold)              { m.state = MtuState::Complete; return std::nullopt; }
    if (m.hasLastProbe && elapsedMs(m.lastProbeTime, now) < m.probeTimeoutMs) return std::nullopt;
    const int probe = (m.minMtu + m.maxMtu) / 2;
    m.currentProbe = probe; m.lastProbeTime = now; m.hasLastProbe = true; m.attempts += 1;
    return probe;
}
inline void onProbeSuccess(MtuDiscovery& m, int size) {
    if (size >= m.minMtu) { m.discoveredMtu = size; m.minMtu = size; }
}
inline void onProbeTimeout(MtuDiscovery& m) { m.maxMtu = m.currentProbe; }
inline void checkProbeTimeout(MtuDiscovery& m, MonoTime now) {
    if (m.state == MtuState::Complete) return;
    if (m.hasLastProbe && elapsedMs(m.lastProbeTime, now) >= m.probeTimeoutMs) onProbeTimeout(m);
}
inline int  discoveredMtu(const MtuDiscovery& m) { return m.discoveredMtu; }
inline bool mtuIsComplete(const MtuDiscovery& m) { return m.state == MtuState::Complete; }

} // namespace aether
