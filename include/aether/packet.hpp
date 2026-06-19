// aether - wire packet header.
// The header is 68 bits packed MSB-first into 9 bytes: a 4-bit type, a 16-bit
// sequence, a 16-bit ack (most recent sequence received), and a 32-bit ack bitfield
// (the 32 preceding acks) -- the sequence + ack-bitfield reliable-UDP scheme. Plain data + free
// functions; the bit layout is a fixed, stable wire format.
#pragma once

#include "aether/serialize.hpp"
#include "aether/types.hpp"

#include <cstdint>
#include <optional>

namespace aether {

// Packet type tag (4 bits on the wire). Extra fields follow the header in the payload.
enum class PacketType : std::uint8_t {
    ConnectionRequest   = 0,   // client initiates a connection
    ConnectionAccepted  = 1,   // server accepts
    ConnectionDenied    = 2,   // server rejects (+ 8-bit reason)
    Payload             = 3,   // game data (+ 3-bit channel, 1-bit is_fragment)
    Disconnect          = 4,   // graceful disconnect (+ 8-bit reason)
    Keepalive           = 5,   // keep the connection alive
    ConnectionChallenge = 6,   // server challenge (+ 64-bit server salt)
    ConnectionResponse  = 7,   // client response (+ 64-bit client salt)
};
inline constexpr std::uint8_t packetTypeMax = 7;

// The header fields, unpacked. Just data.
struct PacketHeader {
    PacketType    type{};
    SequenceNum   sequence{};
    SequenceNum   ack{};       // most recent sequence received from the peer
    std::uint32_t ackBits{};   // the 32 acks preceding `ack`
};

inline constexpr std::size_t packetHeaderBytes = 9;   // (68 + 7) / 8

// Pack the header MSB-first into a fixed stable wire format:
//   b0 [type:4][seq>>12:4]   b1 [seq>>4]            b2 [seq&F<<4][ack>>12]
//   b3 [ack>>4]              b4 [ack&F<<4][abf>>28] b5 [abf>>20]
//   b6 [abf>>12]             b7 [abf>>4]            b8 [abf&F<<4]
inline void writeHeader(Writer& w, const PacketHeader& h) noexcept {
    const std::uint8_t  pt  = static_cast<std::uint8_t>(h.type);
    const std::uint16_t sn  = h.sequence.value;
    const std::uint16_t ak  = h.ack.value;
    const std::uint32_t abf = h.ackBits;
    write(w, static_cast<std::uint8_t>((pt << 4)          | (sn >> 12)));
    write(w, static_cast<std::uint8_t>( sn >> 4));
    write(w, static_cast<std::uint8_t>(((sn & 0x0F) << 4) | (ak >> 12)));
    write(w, static_cast<std::uint8_t>( ak >> 4));
    write(w, static_cast<std::uint8_t>(((ak & 0x0F) << 4) | (abf >> 28)));
    write(w, static_cast<std::uint8_t>( abf >> 20));
    write(w, static_cast<std::uint8_t>( abf >> 12));
    write(w, static_cast<std::uint8_t>( abf >> 4));
    write(w, static_cast<std::uint8_t>((abf & 0x0F) << 4));
}

// Read a header, or nullopt if too short / the type tag is out of range.
inline std::optional<PacketHeader> readHeader(Reader& r) noexcept {
    if (!has(r, packetHeaderBytes)) return std::nullopt;
    const std::uint8_t* b = r.buf + r.pos;
    const std::uint8_t pt = static_cast<std::uint8_t>(b[0] >> 4);
    if (pt > packetTypeMax) return std::nullopt;
    const std::uint16_t sn = static_cast<std::uint16_t>(
        (std::uint16_t(b[0] & 0x0F) << 12) | (std::uint16_t(b[1]) << 4) | (b[2] >> 4));
    const std::uint16_t ak = static_cast<std::uint16_t>(
        (std::uint16_t(b[2] & 0x0F) << 12) | (std::uint16_t(b[3]) << 4) | (b[4] >> 4));
    const std::uint32_t abf =
        (std::uint32_t(b[4] & 0x0F) << 28) | (std::uint32_t(b[5]) << 20) |
        (std::uint32_t(b[6]) << 12)        | (std::uint32_t(b[7]) << 4)  | (b[8] >> 4);
    r.pos += packetHeaderBytes;
    return PacketHeader{ static_cast<PacketType>(pt), SequenceNum{sn}, SequenceNum{ak}, abf };
}

// A complete packet: the 9-byte header followed by its payload bytes.
struct Packet {
    PacketHeader header{};
    Bytes        payload;
};

// Serialize header + payload into one buffer.
inline Bytes serializePacket(const Packet& pkt) {
    Bytes out(packetHeaderBytes);
    Writer w{ out.data(), out.size(), 0, true };
    writeHeader(w, pkt.header);
    out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());
    return out;
}

// Split a buffer into header + trailing payload; nullopt if too short / bad type tag.
inline std::optional<Packet> deserializePacket(const Bytes& data) {
    Reader r{ data.data(), data.size(), 0 };
    const auto h = readHeader(r);
    if (!h) return std::nullopt;
    return Packet{ *h, Bytes(data.begin() + static_cast<std::ptrdiff_t>(packetHeaderBytes), data.end()) };
}

} // namespace aether
