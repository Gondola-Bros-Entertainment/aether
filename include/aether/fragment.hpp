// aether - message fragmentation and reassembly. Splits messages too big for the MTU into
// 6-byte-headered fragments and reassembles them.
#pragma once

#include "aether/types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace aether {

inline constexpr int    fragmentHeaderSize      = 6;     // messageId(4) + index(1) + count(1)
inline constexpr int    maxFragmentCount        = 255;

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

// How many fragments a message of `len` bytes needs at `maxPayload` bytes each. 0 means it cannot be
// fragmented at all: either there is nothing to send, or it would need more than maxFragmentCount pieces
// (the fragment index is one byte by design). Computed and range-checked in size_t BEFORE any narrowing,
// because a >2GiB len would otherwise overflow an int cast, wrap past the guard, and silently drop the
// message. Exposed separately so a caller that wants only SOME fragments (a partial retransmit) can size
// the set without building every piece first.
inline std::size_t fragmentCountFor(std::size_t len, int maxPayload) noexcept {
    if (len == 0 || maxPayload <= 0) return 0;
    const std::size_t count = (len + static_cast<std::size_t>(maxPayload) - 1) / static_cast<std::size_t>(maxPayload);
    return count > static_cast<std::size_t>(maxFragmentCount) ? 0 : count;
}
// The byte range fragment `index` covers. Half-open [start, end); end is clamped, so the last fragment is
// short. The single source of the offset math, shared by whole-message and per-fragment builds.
inline std::pair<std::size_t, std::size_t> fragmentRange(std::size_t len, int maxPayload, std::size_t index) noexcept {
    const std::size_t start = index * static_cast<std::size_t>(maxPayload);
    return { start, std::min(start + static_cast<std::size_t>(maxPayload), len) };
}

inline FragmentResult fragmentMessage(MessageId id, const std::uint8_t* data, std::size_t len, int maxPayload) {
    FragmentResult r;
    const std::size_t count = fragmentCountFor(len, maxPayload);
    if (count == 0) {
        r.tooMany = len != 0 && maxPayload > 0;   // distinguish "too many to fragment" from "nothing to fragment"
        return r;
    }
    r.fragments.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {           // count <= 255 here, so the uint8_t index/count casts below are exact
        const auto [start, end] = fragmentRange(len, maxPayload, i);
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
    MonoTime     lastFragmentAt{};   // when the last NEW fragment landed -- expiry is idle-based (see cleanupFragments)
    std::size_t  totalSize{};   // size_t so the running total cannot overflow at a large cap
};
struct FragmentAssembler {
    std::map<MessageId, FragmentBuffer> buffers;
    double      timeoutMs{};
    int         maxBufferSize{};   // cap on total buffered fragment bytes
    int         maxBuffers{};      // cap on concurrent in-flight messages (distinct message ids)
    std::size_t currentSize{};
};
inline FragmentAssembler newFragmentAssembler(double timeoutMs, int maxSize, int maxBuffers) {
    return { {}, timeoutMs, maxSize, maxBuffers, 0 };
}

// Expire assemblies that have stopped making progress. IDLE-based (time since the last new fragment),
// not total-age: the sender paces a large message's fragments across ticks at its budget's rate, so a
// legitimate assembly can take longer than the timeout while still advancing, and a total-age expiry
// would drop it mid-assembly. One that has gone a full timeout with nothing new is abandoned (its
// sender gave up, died, or burned its retries) and is dropped. Memory stays bounded either way:
// maxBufferSize and maxBuffers cap it regardless of how slowly an assembly advances.
inline void cleanupFragments(FragmentAssembler& a, MonoTime now) {
    for (auto it = a.buffers.begin(); it != a.buffers.end(); ) {
        if (elapsedMs(it->second.lastFragmentAt, now) >= a.timeoutMs) {
            a.currentSize -= it->second.totalSize;
            it = a.buffers.erase(it);
        } else {
            ++it;
        }
    }
}
// Evict the least-recently-advancing assembly (the one most likely abandoned) to make room.
inline bool expireOldestFragment(FragmentAssembler& a) {
    auto oldest = a.buffers.end();
    for (auto it = a.buffers.begin(); it != a.buffers.end(); ++it)
        if (oldest == a.buffers.end() || it->second.lastFragmentAt.ns < oldest->second.lastFragmentAt.ns) oldest = it;
    if (oldest == a.buffers.end()) return false;
    a.currentSize -= oldest->second.totalSize;
    a.buffers.erase(oldest);
    return true;
}

// Feed one fragment; returns the reassembled message if this fragment completed it.
inline std::optional<Bytes> processFragment(FragmentAssembler& a, const std::uint8_t* data, std::size_t len, MonoTime now) {
    cleanupFragments(a, now);
    const auto hdr = readFragmentHeader(data, len);
    if (!hdr) return std::nullopt;
    if (hdr->count == 0) return std::nullopt;   // a 0-fragment message can never complete -- never buffer it
    const std::uint8_t* fragData = data + fragmentHeaderSize;
    const std::size_t   fragSize = len - static_cast<std::size_t>(fragmentHeaderSize);   // len >= fragmentHeaderSize (readFragmentHeader checked)
    // A fragment with no data is malformed: a real split always puts at least one byte in every piece. It
    // would otherwise occupy a slot and count toward completion, letting a peer assemble a message out of
    // nothing.
    if (fragSize == 0) return std::nullopt;
    const MessageId     msgId    = hdr->messageId;

    auto it = a.buffers.find(msgId);
    if (it != a.buffers.end() && it->second.count != hdr->count) return std::nullopt;   // count disagreement

    const std::size_t cap = static_cast<std::size_t>(a.maxBufferSize);                 // maxBufferSize > 0 (validateConfig)
    if (fragSize > cap) return std::nullopt;                                           // one fragment larger than the whole cap -> reject
    while (a.currentSize + fragSize > cap && expireOldestFragment(a)) {}               // evict oldest until it fits (the cap is enforced, not advisory)

    it = a.buffers.find(msgId);
    if (it == a.buffers.end()) {
        if (a.maxBuffers > 0 && static_cast<int>(a.buffers.size()) >= a.maxBuffers) expireOldestFragment(a);   // bound concurrent messages
        FragmentBuffer nb;
        nb.count = hdr->count;
        nb.lastFragmentAt = now;
        it = a.buffers.emplace(msgId, std::move(nb)).first;
    }
    FragmentBuffer& buf = it->second;

    if (hdr->index < buf.count && buf.fragments.find(hdr->index) == buf.fragments.end()) {
        buf.fragments.emplace(hdr->index, Bytes(fragData, fragData + fragSize));
        buf.totalSize      += fragSize;
        a.currentSize      += fragSize;
        buf.lastFragmentAt  = now;   // progress: the idle-expiry clock restarts
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

} // namespace aether
