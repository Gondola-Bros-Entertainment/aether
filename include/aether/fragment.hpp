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
    std::size_t  reservedBytes{};   // nonzero: reliable assembly owns this capacity until delivery or disconnect
};
struct FragmentAssembler {
    std::map<MessageId, FragmentBuffer> buffers;
    double      timeoutMs{};
    int         maxBufferSize{};   // cap on total buffered fragment bytes (payload + per-fragment overhead)
    int         maxBuffers{};      // cap on concurrent in-flight messages (distinct message ids)
    std::size_t currentSize{};
};

// Bookkeeping charged for holding one fragment, on top of its payload: a map node, the Bytes header,
// and its own heap block. It has to be charged for maxReassemblyBufferSize to describe memory at all:
// a tiny fragment costs an order of magnitude more resident bytes than payload bytes, so a flood of
// them would blow far past a payload-only accounting and the real ceiling would be maxBuffers * 255 *
// this. Approximate by nature; the point is that it is not zero.
inline constexpr std::size_t fragmentOverheadBytes = 80;

// What a buffer costs against the cap. totalSize stays pure payload because the assembled message is
// sized from it; the overhead is derived from the fragment count so the two can never drift.
inline std::size_t fragmentBufferCharge(const FragmentBuffer& b) noexcept {
    return b.reservedBytes ? b.reservedBytes : b.totalSize + b.fragments.size() * fragmentOverheadBytes;
}
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
        if (!it->second.reservedBytes && elapsedMs(it->second.lastFragmentAt, now) >= a.timeoutMs) {
            a.currentSize -= fragmentBufferCharge(it->second);
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
        if (!it->second.reservedBytes
            && (oldest == a.buffers.end() || it->second.lastFragmentAt.ns < oldest->second.lastFragmentAt.ns)) oldest = it;
    if (oldest == a.buffers.end()) return false;
    a.currentSize -= fragmentBufferCharge(oldest->second);
    a.buffers.erase(oldest);
    return true;
}

// Removing a retained reliable assembly is legal only after channel acceptance or connection failure.
inline void releaseFragment(FragmentAssembler& a, MessageId id) {
    const auto it = a.buffers.find(id);
    if (it == a.buffers.end()) return;
    a.currentSize -= fragmentBufferCharge(it->second);
    a.buffers.erase(it);
}
struct FragmentReceipt {
    bool accepted = false;
    std::optional<Bytes> message;
};
inline std::optional<Bytes> assembledMessage(const FragmentBuffer& buffer) {
    if (buffer.fragments.size() != buffer.count) return std::nullopt;
    Bytes out;
    out.reserve(buffer.totalSize);
    for (const auto& [index, bytes] : buffer.fragments) {
        (void)index;
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

// A nonzero reservation pins all accepted pieces, including a complete message awaiting channel
// capacity. Ordinary partial reassembly can expire or be evicted; acknowledged reliable data cannot.
inline FragmentReceipt acceptFragment(FragmentAssembler& a, const std::uint8_t* data, std::size_t len,
                                      MonoTime now, std::size_t reservationBytes = 0) {
    const auto header = readFragmentHeader(data, len);
    if (!header || header->count == 0 || header->index >= header->count
        || len == fragmentHeaderSize || a.maxBufferSize <= 0 || a.maxBuffers <= 0) return {};
    cleanupFragments(a, now);
    const auto* payload = data + fragmentHeaderSize;
    const auto size = len - fragmentHeaderSize;
    const auto charge = size + fragmentOverheadBytes;
    const auto cap = static_cast<std::size_t>(a.maxBufferSize);
    if (charge > cap || reservationBytes > cap || (reservationBytes && charge > reservationBytes)) return {};
    auto it = a.buffers.find(header->messageId);
    if (it != a.buffers.end()) {
        auto& buffer = it->second;
        if (buffer.count != header->count || buffer.reservedBytes != reservationBytes) return {};
        if (const auto old = buffer.fragments.find(header->index); old != buffer.fragments.end()) {
            if (old->second.size() != size || !std::equal(old->second.begin(), old->second.end(), payload)) return {};
            return {true, assembledMessage(buffer)}; // Duplicates neither evict data nor extend idle expiry.
        }
        if (reservationBytes && buffer.totalSize + (buffer.fragments.size() + 1) * fragmentOverheadBytes + size > reservationBytes)
            return {};
    }
    const auto additional = reservationBytes ? (it == a.buffers.end() ? reservationBytes : 0) : charge;
    while (additional > cap - a.currentSize) {
        if (!expireOldestFragment(a)) return {}; // Backpressure; every remaining assembly is retained.
    }
    it = a.buffers.find(header->messageId);
    if (it == a.buffers.end()) {
        if (a.buffers.size() >= static_cast<std::size_t>(a.maxBuffers) && !expireOldestFragment(a)) return {};
        FragmentBuffer buffer;
        buffer.count = header->count;
        buffer.lastFragmentAt = now;
        buffer.reservedBytes = reservationBytes;
        it = a.buffers.emplace(header->messageId, std::move(buffer)).first;
        a.currentSize += reservationBytes;
    }
    auto& buffer = it->second;
    buffer.fragments.emplace(header->index, Bytes(payload, payload + size));
    buffer.totalSize += size;
    buffer.lastFragmentAt = now;
    if (!reservationBytes) a.currentSize += charge;
    auto message = assembledMessage(buffer);
    if (message && !reservationBytes) releaseFragment(a, header->messageId);
    return {true, std::move(message)};
}

// Standalone best-effort reassembly. Transports use acceptFragment's separate acceptance result.
inline std::optional<Bytes> processFragment(FragmentAssembler& a, const std::uint8_t* data, std::size_t len, MonoTime now) {
    return acceptFragment(a, data, len, now).message;
}

} // namespace aether
