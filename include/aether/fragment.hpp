// aether - message fragmentation and reassembly. Splits messages too big for the MTU into
// 6-byte-headered fragments and reassembles them.
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
    int    maxBufferSize{};   // cap on total buffered fragment bytes
    int    maxBuffers{};      // cap on concurrent in-flight messages (distinct message ids)
    int    currentSize{};
};
inline FragmentAssembler newFragmentAssembler(double timeoutMs, int maxSize, int maxBuffers) {
    return { {}, timeoutMs, maxSize, maxBuffers, 0 };
}

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
inline bool expireOldestFragment(FragmentAssembler& a) {
    auto oldest = a.buffers.end();
    for (auto it = a.buffers.begin(); it != a.buffers.end(); ++it)
        if (oldest == a.buffers.end() || it->second.createdAt.ns < oldest->second.createdAt.ns) oldest = it;
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
    const int           fragSize = static_cast<int>(len - static_cast<std::size_t>(fragmentHeaderSize));
    const MessageId     msgId    = hdr->messageId;

    auto it = a.buffers.find(msgId);
    if (it != a.buffers.end() && it->second.count != hdr->count) return std::nullopt;   // count disagreement

    if (fragSize > a.maxBufferSize) return std::nullopt;                               // one fragment larger than the whole cap -> reject
    while (a.currentSize + fragSize > a.maxBufferSize && expireOldestFragment(a)) {}   // evict oldest until it fits (the cap is enforced, not advisory)

    it = a.buffers.find(msgId);
    if (it == a.buffers.end()) {
        if (a.maxBuffers > 0 && static_cast<int>(a.buffers.size()) >= a.maxBuffers) expireOldestFragment(a);   // bound concurrent messages
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

} // namespace aether
