// aether - connection state machine for one peer: ties together the handshake state machine,
// channels, reliability tracking, and congestion control. Data-first: a plain Connection struct
// mutated by free functions; operations that can fail return std::optional<ConnectionError>
// (nullopt = success).
#pragma once

#include "aether/channel.hpp"
#include "aether/clocksync.hpp"
#include "aether/config.hpp"
#include "aether/congestion.hpp"
#include "aether/crypto.hpp"
#include "aether/fragment.hpp"
#include "aether/mtu.hpp"
#include "aether/packet.hpp"
#include "aether/reliability.hpp"
#include "aether/stats.hpp"
#include "aether/types.hpp"
#include "aether/x25519.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

namespace aether {

inline constexpr double bandwidthWindowMs  = 1000.0;
inline constexpr double timeSyncIntervalMs = 1000.0;   // cadence of TimeSyncPing while connected
inline constexpr int          timeSyncPingBytes       = 8;      // TimeSyncPing payload: [u64 sender ns]
inline constexpr int          timeSyncPongBytes       = 16;     // TimeSyncPong payload: [u64 echoed ns][u64 responder ns]
inline constexpr std::uint8_t channelWireFragmentFlag = 0x80;   // channel byte high bit: this wire is a fragment
inline constexpr std::uint8_t channelWireChannelMask  = 0x07;   // channel byte low 3 bits: channel id (<= 8 channels)
// --- receiver flow control ---
// Credit the peer has not advertised yet. A receiver that is keeping up never advertises at all, so
// this is the steady state on a healthy link and it must never throttle: 0xFFFF is far above any
// reachable unacked count (messageBufferSize caps that at a few hundred).
inline constexpr std::uint16_t peerCreditUnknown = 0xFFFF;
// At or below this many free slots a channel counts as restricted: the receiver starts advertising,
// and keeps the figure fresh, so the sender throttles before the buffer is flat out rather than
// slamming into a closed window.
inline constexpr int    windowLowCredit = 8;
// Re-advertise cadence WHILE restricted. UDP loses packets, and a lost "window reopened" update
// would otherwise wedge the sender permanently; this is the receiver-side persist timer.
inline constexpr double windowRefreshMs = 250.0;
static_assert(maxChannelCount <= channelWireChannelMask + 1, "channel id must fit the low bits of the channel wire byte");
// channelWireSeqBytes / packetWireOverhead / effectivePayloadBudget / maxFragmentChunk are single-sourced
// in config.hpp (MTU-derived sizing; validateConfig uses them to reject an unfragmentable maxMessageSize).

// The states a Connection can actually be in. A handshake in progress is NOT one of them: the peer
// layer holds half-open handshakes in its own pending table (peer.hpp PendingConnection) and only ever
// constructs a Connection once the handshake has completed, so there is no "connecting" Connection.
enum class ConnectionState { Disconnected, Connected, Disconnecting };

// Disconnect reason: the enum value IS the wire byte, so any code round-trips losslessly
// (codes 0..4 are named; others are valid but unnamed).
enum class DisconnectReason : std::uint8_t {
    Timeout = 0, Requested = 1, Kicked = 2, ServerFull = 3, ProtocolMismatch = 4,
};
inline std::uint8_t      disconnectReasonCode(DisconnectReason r) noexcept { return static_cast<std::uint8_t>(r); }
inline DisconnectReason  parseDisconnectReason(std::uint8_t code) noexcept { return static_cast<DisconnectReason>(code); }

// Errors from connection operations. A small tagged struct: the payload fields are only
// meaningful for the matching kind.
struct ConnectionError {
    enum Kind { NotConnected, Timeout, InvalidChannel, ChannelErr };
    Kind         kind         = NotConnected;
    ChannelId    channel      = ChannelId{};          // for InvalidChannel
    ChannelError channelError = ChannelError::None;   // for ChannelErr
};

// A packet waiting to be sent. header.type and type are kept in sync at enqueue.
struct OutgoingPacket {
    PacketHeader header{};
    PacketType   type{};
    Bytes        payload;
};

// A channel-message wire awaiting coalescing into a packet (accumulated per tick, flushed batched).
struct PendingWire {
    Bytes      wire;        // [channel/fragment byte][seq][data]
    bool       reliable{};
    ChannelMsg msg{};       // (channel, channelSeq) -- used for reliability when reliable
};

// One peer connection.
struct Connection {
    NetworkConfig                config;
    ConnectionState              state      = ConnectionState::Disconnected;
    std::uint64_t                clientSalt = 0;
    std::uint64_t                serverSalt = 0;
    std::uint64_t                playerId   = 0;   // verified connect-token identity (server side); 0 when auth is off
    MonoTime                     lastSendTime{};
    MonoTime                     lastRecvTime{};
    std::optional<MonoTime>      startTime;
    SequenceNum                  localSeq{};
    ReliableEndpoint             reliability{};
    std::vector<Channel>         channels;          // dense, indexed by channel id
    std::vector<int>             channelPriority;   // channel indices, highest priority first
    CongestionController         congestion{};
    std::optional<CongestionWindow> cwnd;
    BandwidthTracker             bandwidthUp{};
    BandwidthTracker             bandwidthDown{};
    std::vector<OutgoingPacket>  sendQueue;
    std::vector<PendingWire>     pendingWires;   // accumulated this tick, flushed (coalesced) at tick end
    NetworkStats                 stats{};
    std::optional<MonoTime>      disconnectTime;
    int                          disconnectRetries = 0;
    std::optional<EncryptionKey> sendKey;        // our send direction (c2s for the client, s2c for the server)
    std::optional<EncryptionKey> recvKey;        // the peer's send direction
    std::optional<X25519Key>     resumeMaster;   // ECDH shared secret, cached to re-key a fast reconnect
    NonceCounter                 sendNonce{};
    ReplayWindow                 recvReplay{};                // 64-bit sliding window (replayWindowBits, crypto.hpp)
    bool                         pendingAck        = false;
    ClockSync                    clockSync{};                 // estimated offset to the peer's clock
    MonoTime                     lastTimeSyncTime{};          // last TimeSyncPing send time
    MtuDiscovery                 mtuDiscovery{};              // path-MTU search; plpmtu feeds the coalescing budget
    // --- receiver flow control (see maybeAdvertiseWindow) ---
    std::array<std::uint16_t, maxChannelCount> peerCredit{};        // free receive slots the PEER last advertised
    std::array<std::uint16_t, maxChannelCount> advertisedCredit{};  // what WE last told the peer
    MonoTime                                   lastWindowAdvertise{};
    bool                                       windowAdvertised = false;   // false => advertisedCredit means nothing yet
    SequenceNum                                windowUpdateSeq{};          // sequence of the last WindowUpdate we sent
    bool                                       windowUpdateAcked = true;   // false while one is unconfirmed -> keep re-sending
    SequenceNum                                windowUpdateAppliedSeq{};   // sequence of the last one we APPLIED
    bool                                       windowUpdateApplied = false;
    // --- anti-amplification (see amplificationAllowsSend) ---
    bool          pathValidated        = true;   // false until this address proves it RECEIVES
    std::uint64_t unvalidatedRecvBytes = 0;      // bytes accepted from it while unvalidated
    std::uint64_t unvalidatedSentBytes = 0;      // bytes we have sent to it while unvalidated
};

// --- construction ---
// The reliability endpoint carries two configured caps: how many packets may be in flight before the
// oldest unresolved one is evicted, and how far an incoming sequence may jump before it is treated as
// noise rather than a legitimate reorder. Built here (not defaulted inside ReliableEndpoint) so a reset
// or a migration restores the configured values instead of silently reverting to the struct defaults.
inline ReliableEndpoint newReliableEndpoint(const NetworkConfig& config) {
    ReliableEndpoint ep;
    ep.maxInFlight    = config.maxInFlight;
    ep.maxSeqDistance = config.maxSequenceDistance;
    return ep;
}

// Outgoing sequences start at 1: 0 is reserved so that "I have received nothing yet" is unambiguous.
// getAckInfo has no way to say it -- before the first receive it reports the default remoteSeq 0 with
// an empty bitfield, which is byte-for-byte a genuine acknowledgement of packet 0. The receive side
// already guards this (onPacketsReceived refuses to advance from the default, and says why), but the
// SEND side still emitted it: a peer that had heard nothing acked our packet 0, and if that packet
// carried a reliable message that was lost, the sender marked it delivered and never retransmitted it
// -- silent loss on a channel whose contract is no loss. Never sending 0 means no sent-ring record
// exists for the sequence such a header names, so the false ack resolves to nothing. Wraparound
// reaches 0 legitimately ~65k packets later, by which point both sides have long since received.
inline constexpr SequenceNum firstSequence{ 1 };

inline Connection newConnection(const NetworkConfig& config, std::uint64_t clientSalt, MonoTime now) {
    Connection c;
    c.config       = config;
    c.clientSalt   = clientSalt;
    c.lastSendTime = now;
    c.lastRecvTime = now;
    c.reliability  = newReliableEndpoint(config);
    c.localSeq     = firstSequence;

    const int numChannels = std::min(config.maxChannels, maxChannelCount);   // the 3-bit channel wire field caps here
    c.channels.reserve(static_cast<std::size_t>(numChannels));
    for (int i = 0; i < numChannels; ++i) {
        const ChannelConfig cfg = (i < static_cast<int>(config.channelConfigs.size()))
                                      ? config.channelConfigs[static_cast<std::size_t>(i)]
                                      : config.defaultChannelConfig;
        c.channels.push_back(newChannel(static_cast<ChannelId>(i), cfg));
    }
    c.channelPriority.resize(static_cast<std::size_t>(numChannels));
    for (int i = 0; i < numChannels; ++i) c.channelPriority[static_cast<std::size_t>(i)] = i;
    std::stable_sort(c.channelPriority.begin(), c.channelPriority.end(),
                     [&](int a, int b) { return c.channels[static_cast<std::size_t>(a)].config.priority > c.channels[static_cast<std::size_t>(b)].config.priority; });

    c.congestion = newCongestionController(config.sendRate, config.maxPacketRate, config.congestionBadLossThreshold,
                                           config.congestionGoodRttThreshold, config.congestionRecoveryTimeMs);
    if (config.useCwndCongestion) c.cwnd = newCongestionWindow(config.mtu);
    c.bandwidthUp   = newBandwidthTracker(bandwidthWindowMs);
    c.bandwidthDown = newBandwidthTracker(bandwidthWindowMs);
    c.mtuDiscovery  = newMtuDiscovery(config.mtu, config.mtuProbeCeiling, config.enableMtuDiscovery);
    c.peerCredit.fill(peerCreditUnknown);   // until the peer says otherwise, assume it can keep up
    return c;
}

// --- queries ---
inline ConnectionState     connectionState(const Connection& c) noexcept { return c.state; }
inline bool                isConnected(const Connection& c) noexcept { return c.state == ConnectionState::Connected; }
inline const NetworkStats& connectionStats(const Connection& c) noexcept { return c.stats; }
inline SequenceNum         connRemoteSeq(const Connection& c) noexcept { return c.reliability.remoteSeq; }
inline std::uint8_t        channelCount(const Connection& c) noexcept { return static_cast<std::uint8_t>(c.channels.size()); }
inline bool                clockSynced(const Connection& c) noexcept { return c.clockSync.hasSample; }
inline double              clockOffsetMs(const Connection& c) noexcept { return c.clockSync.offsetMs; }
// Bound on how wrong clockOffsetMs can be (see clockOffsetErrorBoundMs): read it before trusting
// the offset, because an asymmetric path biases it silently.
inline double              clockOffsetErrorMs(const Connection& c) noexcept { return clockOffsetErrorBoundMs(c.clockSync); }

// --- anti-amplification ---
//
// A 0-RTT resume is authenticated by a MAC over the ECDH master, which proves the sender holds the
// master -- it does NOT prove the sender is at the source address, and that address is attacker
// chosen. So a replayed resume spoofed to a victim's address made the server open a full connection
// there and stream game traffic at it for the whole connection timeout: tens of bytes in, seconds of
// outbound at a target of the attacker's choosing. Requiring a challenge first would cost the round
// trip that 0-RTT resume exists to avoid, so instead the connection comes up UNVALIDATED and may only
// send a small multiple of what it has received, until a packet decrypts from that address -- which
// only a peer actually there can produce. The real client sends immediately, so it lifts the cap on
// its first packet and never notices; a spoofed victim sends nothing, so nothing is amplified at it.
inline constexpr int amplificationFactor = 3;   // the usual anti-amplification ratio (QUIC uses 3x)

inline bool amplificationAllowsSend(const Connection& c, int bytes) noexcept {
    if (c.pathValidated) return true;
    return c.unvalidatedSentBytes + static_cast<std::uint64_t>(bytes)
           <= c.unvalidatedRecvBytes * static_cast<std::uint64_t>(amplificationFactor);
}
// A packet that decrypted came from a peer holding the key AND arrived from this address, which is
// exactly the proof the cap was waiting for.
inline void markPathValidated(Connection& c) noexcept {
    c.pathValidated        = true;
    c.unvalidatedRecvBytes = 0;
    c.unvalidatedSentBytes = 0;
}

// --- header creation ---
// EVERY header carries our current ack state, so building one discharges whatever ack was pending --
// which is why pendingAck is cleared here rather than inferred at tick end from an empty send queue.
// The queue cannot answer the question: a time-sync pong is queued while the incoming batch is still
// being processed, so its header predates any packet that arrives later in that same batch. Testing
// "did we queue anything" then suppressed the ack for a payload the pong could not have carried, and
// the sender retransmitted it an RTO later. Clearing at the point the ack is actually snapshotted
// ties the decision to ordering instead.
inline PacketHeader createHeaderInternal(Connection& conn) {
    const auto [ackSeq, ackBits64] = getAckInfo(conn.reliability);
    conn.pendingAck = false;
    return PacketHeader{ PacketType::Payload, conn.localSeq, ackSeq, static_cast<std::uint32_t>(ackBits64) };
}
// --- send-queue helpers ---
inline void enqueueEmptyPacket(Connection& conn) {   // keepalive / ack-only share this wire form
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::Keepalive;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::Keepalive, Bytes{} });
    conn.localSeq = next(conn.localSeq);
}
inline void sendKeepalive(Connection& conn) { enqueueEmptyPacket(conn); }
inline void sendAckOnly(Connection& conn)   { enqueueEmptyPacket(conn); }

// Queue an MTU probe: zero padding sized so the SEALED datagram is exactly probeSize bytes on the
// wire. It rides the normal send path (sequence, encryption, CRC) so its ack is proof a real
// datagram of that size traversed the path; the padding itself means nothing and the receiver
// discards it. Not budget- or window-charged: a probe is rare (a handful per search, searches
// minutes apart) and carries no data to account for.
inline SequenceNum sendMtuProbe(Connection& conn, int probeSize) {
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::MtuProbe;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::MtuProbe,
                                             Bytes(static_cast<std::size_t>(probeSize - packetWireOverhead)) });
    const SequenceNum seq = conn.localSeq;
    conn.localSeq = next(conn.localSeq);
    return seq;
}

// clock sync: a TimeSyncPing carries our send time; the peer replies with a TimeSyncPong echoing
// it plus the peer's own time, which lets us estimate the clock offset (see clocksync.hpp).
inline void sendTimeSyncPing(Connection& conn, MonoTime now) {
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::TimeSyncPing;
    Bytes payload(timeSyncPingBytes);
    putU64(payload.data(), now.ns);
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::TimeSyncPing, std::move(payload) });
    conn.localSeq         = next(conn.localSeq);
    conn.lastTimeSyncTime = now;
}
inline void sendTimeSyncPong(Connection& conn, std::uint64_t echoNs, MonoTime now) {
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::TimeSyncPong;
    Bytes payload(timeSyncPongBytes);
    putU64(payload.data(),     echoNs);   // echo the originator's send time
    putU64(payload.data() + 8, now.ns);   // our timestamp
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::TimeSyncPong, std::move(payload) });
    conn.localSeq = next(conn.localSeq);
}

// --- receiver flow control: advertise, apply, gate ---
//
// Backpressure alone (withhold the ack, let the sender retransmit) never loses data silently, but the
// sender only discovers the receiver's limit by retransmitting into it, and a receiver that stops
// draining entirely burns the message's retry budget until it is dropped. An advertised credit lets
// the sender stop BEFORE that: it stays queued, channelSend reports BufferFull, and the application
// feels the backpressure instead of the wire eating a message.
//
// Credit is per CHANNEL (a stalled channel must not throttle the others), carried in its own packet
// (a header field would cost bytes on every datagram to report something that rarely changes), and is
// a limit INDEPENDENT of the congestion gates: those bound what the path can carry, this bounds what
// the receiver can hold. Only reliable channels are governed, because nothing retransmits an
// unreliable message and a refused one is a drop by contract, not backpressure.

// [count:1] then count x [channel:1][freeSlots:2 BE].
inline Bytes encodeWindowUpdate(const Connection& conn) {
    const std::uint8_t n = static_cast<std::uint8_t>(conn.channels.size());
    Bytes p;
    p.reserve(1 + static_cast<std::size_t>(n) * 3);
    p.push_back(n);
    for (std::uint8_t i = 0; i < n; ++i) {
        const int free = channelFreeReceiveSlots(conn.channels[i]);
        const std::uint16_t v = free > 0xFFFF ? 0xFFFF : static_cast<std::uint16_t>(free);
        p.push_back(i);
        p.push_back(static_cast<std::uint8_t>(v >> 8));
        p.push_back(static_cast<std::uint8_t>(v & 0xFF));
    }
    return p;
}
// Untrusted bytes: accept only exactly what the encoder emits, and never index a channel we do not
// have. Validated in full BEFORE anything is written, so a rejected update leaves credit exactly as
// it was -- half-applying one desyncs the channels it did reach against the ones it did not.
inline bool applyWindowUpdate(Connection& conn, const PacketHeader& header, ByteSpan p) {
    if (p.empty()) return false;
    const std::size_t n = p[0];
    if (n > maxChannelCount || p.size() != 1 + n * 3) return false;
    for (std::size_t k = 0; k < n; ++k)
        if (p[1 + k * 3] >= conn.channels.size()) return false;
    // Credit is an absolute figure, not a delta, so a REORDERED update must never land: UDP delivering
    // last tick's "0 free" after this tick's "16 free" would leave the sender believing the window is
    // shut, and the receiver -- already unrestricted and steady -- has nothing further to say. Applying
    // only strictly newer updates makes a late one a no-op instead of a stall.
    if (conn.windowUpdateApplied && !newer(header.sequence, conn.windowUpdateAppliedSeq)) return false;
    conn.windowUpdateApplied    = true;
    conn.windowUpdateAppliedSeq = header.sequence;
    for (std::size_t k = 0; k < n; ++k)
        conn.peerCredit[p[1 + k * 3]] = getU16BE(p.data() + 1 + k * 3 + 1);
    return true;
}
inline bool windowRestricted(const Channel& ch) noexcept {
    return channelFreeReceiveSlots(ch) <= windowLowCredit;
}
// Advertise the receiver's ABSORPTION CAPACITY, and call this AFTER the application has collected --
// both parts matter, and getting either wrong costs an order of magnitude.
//
// Measured before the collection, the credit is the buffer's instantaneous trough: a receiver that
// drains fully every tick reads as "0 free" the moment a tick's arrivals land, even though it is
// about to empty completely. The sender then stop-and-goes against a credit oscillating between 0
// and the cap. Measured after, the figure is what the receiver can actually absorb before the next
// collection, which is the number the sender needs.
//
// The first advertisement is unconditional, because capacity is not something the sender can guess:
// until it hears one it assumes no limit, and an unpaced sender overruns the buffer every tick and
// spends the difference on refusals and retransmits. On a full drain the figure never changes after
// that, so the steady state is exactly one packet per connection.
inline void maybeAdvertiseWindow(Connection& conn, MonoTime now) {
    bool restricted = false, changed = !conn.windowAdvertised;   // the sender must learn the capacity at least once
    for (std::size_t i = 0; i < conn.channels.size(); ++i) {
        if (!channelIsReliable(conn.channels[i])) continue;
        const Channel& ch  = conn.channels[i];
        const int      free = channelFreeReceiveSlots(ch);
        const bool     isR  = windowRestricted(ch);
        const bool     wasR = conn.windowAdvertised && conn.advertisedCredit[i] <= windowLowCredit;
        restricted = restricted || isR;
        // Re-advertise on a crossing of the restricted threshold, or a move big enough to matter.
        // A small wobble is not worth a packet.
        const int adv   = static_cast<int>(conn.advertisedCredit[i]);
        const int delta = free > adv ? free - adv : adv - free;
        // Ceiling form of (delta * 4 >= cap): the product overflows int for a cap above INT_MAX/4,
        // which validateConfig currently admits.
        changed = changed || (isR != wasR) || (delta >= (ch.config.maxReceiveBufferSize + 3) / 4);
    }
    // Re-send while UNCONFIRMED, not merely while restricted. A WindowUpdate is not registered in the
    // sent ring, so nothing retransmits it; the reopen that follows a drain is a single datagram, and
    // once it is sent the receiver is unrestricted with a steady free count -- nothing left to trigger
    // another. Losing that one datagram therefore left the sender at credit 0 with no way to ever hear
    // otherwise, wedging the channel on a healthy link. Keying the persist timer off the peer's
    // acknowledgement instead closes that: the reopen repeats every windowRefreshMs until a header
    // covers it, which is the same proof-of-delivery an MTU probe uses.
    const bool unconfirmed = !conn.windowUpdateAcked;
    if (!changed && !((restricted || unconfirmed) && elapsedMs(conn.lastWindowAdvertise, now) >= windowRefreshMs)) return;

    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::WindowUpdate;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::WindowUpdate, encodeWindowUpdate(conn) });
    conn.windowUpdateSeq   = conn.localSeq;   // confirmed by any header acking it (see processIncomingAcks)
    conn.windowUpdateAcked = false;
    conn.localSeq = next(conn.localSeq);
    for (std::size_t i = 0; i < conn.channels.size(); ++i) {
        const int free = channelFreeReceiveSlots(conn.channels[i]);
        conn.advertisedCredit[i] = free > 0xFFFF ? 0xFFFF : static_cast<std::uint16_t>(free);
    }
    conn.lastWindowAdvertise = now;
    conn.windowAdvertised    = true;
}

// The inner wire of a channel message: [seqHi][seqLo][payload] -- the exact bytes the receiver's
// reassembler rejoins before decoding the seq. It is never materialized as a buffer on the send
// side: an unfragmented message goes straight to its wire, and a fragment is rendered from the
// message directly (encodeFragmentWireAt), so this length is arithmetic.
inline std::size_t channelInnerSize(const ChannelMessage& msg) noexcept {
    return static_cast<std::size_t>(channelWireSeqBytes) + msg.data.size();
}
// Wire form of a whole (unfragmented) channel message: [channel:3 bits | reserved:5][seqHi][seqLo][payload].
// Built in one exactly-sized allocation -- this is the path every message that fits an MTU takes, on every
// send and every retransmit, so composing it from an inner buffer would copy each payload twice.
inline Bytes encodeChannelWire(int chIdx, const ChannelMessage& msg) {
    constexpr std::size_t dataOffset = 1 + static_cast<std::size_t>(channelWireSeqBytes);
    const std::uint16_t   seqRaw     = msg.sequence.value;
    Bytes wire(dataOffset + msg.data.size());
    wire[0] = static_cast<std::uint8_t>(chIdx & channelWireChannelMask);
    wire[1] = static_cast<std::uint8_t>(seqRaw >> 8);
    wire[2] = static_cast<std::uint8_t>(seqRaw & 0xFF);
    if (!msg.data.empty()) std::memcpy(wire.data() + dataOffset, msg.data.data(), msg.data.size());
    return wire;
}

// One fragment's wire -- [channel byte | fragment flag][fragment header][slice of the inner] -- rendered
// STRAIGHT from the message in a single exactly-sized allocation. The inner is [seqHi][seqLo][payload],
// so only inner offsets 0 and 1 are seq bytes and everything after maps to payload at (offset - 2).
// Rendering from the message matters because pacing revisits a partially-sent message every tick, and
// materializing a ~300KB inner buffer to slice one or two admitted fragments out of it would copy the
// whole message per tick.
inline Bytes encodeFragmentWireAt(int chIdx, MessageId id, const ChannelMessage& msg,
                                  int chunk, std::size_t index, std::size_t count) {
    const auto [start, end] = fragmentRange(channelInnerSize(msg), chunk, index);
    Bytes wire(1 + static_cast<std::size_t>(fragmentHeaderSize) + (end - start));
    wire[0] = static_cast<std::uint8_t>((chIdx & channelWireChannelMask) | channelWireFragmentFlag);
    writeFragmentHeader(wire.data() + 1, FragmentHeader{ id, static_cast<std::uint8_t>(index), static_cast<std::uint8_t>(count) });
    std::uint8_t*       dst    = wire.data() + 1 + fragmentHeaderSize;
    std::size_t         pos    = start;
    const std::uint16_t seqRaw = msg.sequence.value;
    if (pos == 0 && pos < end) { *dst++ = static_cast<std::uint8_t>(seqRaw >> 8);   ++pos; }
    if (pos == 1 && pos < end) { *dst++ = static_cast<std::uint8_t>(seqRaw & 0xFF); ++pos; }
    if (pos < end) std::memcpy(dst, msg.data.data() + (pos - static_cast<std::size_t>(channelWireSeqBytes)), end - pos);
    return wire;
}
// The (channel, seq)-unique id the peer's reassembler keys a fragmented message on.
inline MessageId fragmentMessageId(int chIdx, const ChannelMessage& msg) noexcept {
    return MessageId{ (static_cast<std::uint32_t>(chIdx) << 16) | msg.sequence.value };
}

// A message rendered for RETRANSMIT (first sends go through emitPacedFragments below): the single wire
// for an unfragmented message, else one wire per still-unacked fragment -- resending all of them would
// multiply the cost of a single lost chunk by the fragment count. Each wire is tagged with WHICH
// fragment it carries, because a subset's position in the list is not its index. fragmentCount is the
// message's TOTAL count (recorded on the message at first emission), not the number of wires here.
//
// ok is false only if the message is too large even to fragment (> maxFragmentCount chunks, ~295KB at
// a 1200 MTU). validateConfig rejects a maxMessageSize past maxFragmentableMessage, so for a validated
// config this is unreachable -- it stays a defensive backstop for a NetPeer built bypassing it.
struct MessageWire  { Bytes data; std::uint8_t fragIndex = 0; };
struct MessageWires { std::vector<MessageWire> wires; std::uint8_t fragmentCount = 0; bool ok = true; };
inline MessageWires buildMessageWires(const NetworkConfig& cfg, int chIdx, const ChannelMessage& msg) {
    MessageWires out;
    const std::size_t innerLen = channelInnerSize(msg);
    const int         chunk    = maxFragmentChunk(cfg);
    if (chunk <= 0 || innerLen <= static_cast<std::size_t>(chunk)) {   // fits one datagram -> one plain wire
        out.wires.push_back(MessageWire{ encodeChannelWire(chIdx, msg), 0 });
        return out;
    }
    const std::size_t count = fragmentCountFor(innerLen, chunk);
    if (count == 0) { out.ok = false; return out; }
    out.fragmentCount = static_cast<std::uint8_t>(count);
    out.wires.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint8_t index = static_cast<std::uint8_t>(i);
        if (fragmentAcked(msg, index)) continue;
        out.wires.push_back(MessageWire{ encodeFragmentWireAt(chIdx, fragmentMessageId(chIdx, msg), msg, chunk, i, count), index });
    }
    return out;
}

// Accumulate a channel-message wire for this tick; flushPendingWires coalesces them into packets.
// A reliable wire reserves its bytes in the congestion window HERE, at admission, because the window
// is only charged for real at flush -- and every message in the tick is admitted before that happens.
// Reserving at admission is what makes cwCanSend bind within a tick instead of testing a stale figure.
// The reservation is in the same unit flushPendingWires charges (the wire's own size), so the two
// cancel exactly and pendingBytes is back to 0 once the tick's wires are flushed.
inline void enqueuePayload(Connection& conn, bool trackReliable, int chIdx,
                           SequenceNum seq, std::uint8_t fragIndex, Bytes wireData) {
    if (trackReliable && conn.cwnd) cwOnAdmit(*conn.cwnd, static_cast<int>(wireData.size()));
    conn.pendingWires.push_back(
        PendingWire{ std::move(wireData), trackReliable, ChannelMsg{ static_cast<ChannelId>(chIdx), seq, fragIndex } });
}

// Coalesce this tick's accumulated wires into packets: a lone wire stays a plain Payload; several
// become one PayloadBatch ([u8 count][u16 len][wire]...). Each packet gets one sequence, and every
// reliable message it carries is registered under that sequence.
inline void flushPendingWires(Connection& conn, MonoTime now) {
    // Coalescing budget from the LIVE path MTU: discovery headroom above the config floor lets more
    // wires share a datagram. Safe to read fresh every flush -- batches are re-formed from scratch
    // here, so a plpmtu that shrank simply produces smaller batches from the next flush on.
    const int   budget = payloadBudgetAt(conn.mtuDiscovery.plpmtu);
    std::size_t i      = 0;
    while (i < conn.pendingWires.size()) {
        std::size_t n          = 0;
        int         groupBytes = batchHeaderSize;
        while (i + n < conn.pendingWires.size() && n < maxMsgsPerPacket) {
            const int add = batchLengthSize + static_cast<int>(conn.pendingWires[i + n].wire.size());
            if (n > 0 && groupBytes + add > budget) break;   // keep the datagram within the MTU (always take >= 1)
            groupBytes += add;
            ++n;
        }
        std::array<ChannelMsg, maxMsgsPerPacket> relMsgs{};
        std::uint8_t relCount = 0;
        int          relBytes = 0;   // reliable wire bytes only -- see SentPacketRecord::size
        Bytes        payload;
        PacketType   type;
        if (n == 1) {
            type = PacketType::Payload;
            if (conn.pendingWires[i].reliable) {
                relMsgs[relCount++] = conn.pendingWires[i].msg;
                relBytes += static_cast<int>(conn.pendingWires[i].wire.size());   // read the size before the move below
            }
            payload = std::move(conn.pendingWires[i].wire);   // pendingWires is cleared at the end; no copy needed
        } else {
            type = PacketType::PayloadBatch;
            payload.push_back(static_cast<std::uint8_t>(n));
            for (std::size_t k = 0; k < n; ++k) {
                const PendingWire& pw = conn.pendingWires[i + k];
                payload.push_back(static_cast<std::uint8_t>(pw.wire.size() >> 8));
                payload.push_back(static_cast<std::uint8_t>(pw.wire.size() & 0xFF));
                payload.insert(payload.end(), pw.wire.begin(), pw.wire.end());
                if (pw.reliable) { relMsgs[relCount++] = pw.msg; relBytes += static_cast<int>(pw.wire.size()); }
            }
        }
        PacketHeader header = createHeaderInternal(conn);
        header.type = type;
        conn.sendQueue.push_back(OutgoingPacket{ header, type, std::move(payload) });
        // Register EVERY payload packet, not only the ones carrying reliable messages. The sent ring is
        // what processAcks walks to produce RTT and loss samples, so registering only reliable packets
        // left a connection carrying purely unreliable traffic -- the shape of a state-snapshot stream,
        // which is the common case -- with no samples at all: it reported zero loss and zero RTT while
        // its rate controller additively increased into a lossy path.
        //
        // `size` stays the RELIABLE byte count (0 for an unreliable-only packet), because that is the
        // unit the congestion window is charged and credited on. So this widens the ack/RTT/loss
        // signal without touching window accounting by a byte.
        const int evicted = onPacketSent(conn.reliability, conn.localSeq, now,
                                         std::span<const ChannelMsg>(relMsgs.data(), relCount), relBytes);
        if (conn.cwnd) {
            if (relBytes > 0) cwOnSend(*conn.cwnd, relBytes, now);
            // An eviction discards a packet an ack can never resolve, so its bytes are returned
            // immediately -- and the victim may have carried reliable bytes even when this packet does not.
            cwReleaseInFlight(*conn.cwnd, evicted);
        }
        conn.localSeq = next(conn.localSeq);
        i += n;
    }
    conn.pendingWires.clear();
}

// --- operations ---
inline void disconnect(Connection& conn, DisconnectReason reason, MonoTime now) {
    if (conn.state == ConnectionState::Disconnected) return;
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::Disconnect;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::Disconnect, Bytes{ disconnectReasonCode(reason) } });
    conn.state             = ConnectionState::Disconnecting;
    conn.disconnectTime    = now;
    conn.disconnectRetries = 0;
    conn.localSeq          = next(conn.localSeq);
}

inline std::optional<ConnectionError> sendMessage(Connection& conn, ChannelId channelId, const Bytes& payload, MonoTime now) {
    if (conn.state != ConnectionState::Connected) return ConnectionError{ ConnectionError::NotConnected };
    const int idx = toInt(channelId);
    if (idx < 0 || idx >= static_cast<int>(conn.channels.size()))
        return ConnectionError{ ConnectionError::InvalidChannel, channelId };
    const SendResult res = channelSend(conn.channels[static_cast<std::size_t>(idx)], payload, now);
    if (res.error != ChannelError::None) {
        ConnectionError e{ ConnectionError::ChannelErr };
        e.channelError = res.error;
        return e;
    }
    return std::nullopt;
}

inline std::vector<Bytes> receiveMessage(Connection& conn, ChannelId channelId) {
    const int idx = toInt(channelId);
    if (idx < 0 || idx >= static_cast<int>(conn.channels.size())) return {};
    return channelReceive(conn.channels[static_cast<std::size_t>(idx)]);
}

// Route a message into its channel. Returns whether the channel ACCEPTED it: false is a transient
// refusal (a full buffer) that the sender should retransmit, so the caller must not ack that packet. An
// unknown channel id is accepted-and-discarded -- no retransmit would make that channel exist.
inline bool receiveIncomingPayload(Connection& conn, ChannelId channelId, SequenceNum chSeq, Bytes payload, MonoTime now) {
    const int idx = toInt(channelId);
    if (idx < 0 || idx >= static_cast<int>(conn.channels.size())) return true;
    return onMessageReceived(conn.channels[static_cast<std::size_t>(idx)], chSeq, std::move(payload), now);
}

// Does this packet type need an acknowledgement of its OWN, promptly? Only one carrying something
// the sender is waiting on: channel data (which may be reliable) and an MTU probe (whose ack IS the
// discovery signal). A bare Keepalive -- which is also the wire form of an ack-only -- carries
// nothing to confirm, and treating it as needing an ack is what made two idle peers trade one every
// tick forever: each side's ack was itself acked, ~28x the keepalive cadence, on a link with no
// application traffic at all. A time-sync ping is answered by a pong, whose header carries the ack.
inline constexpr bool needsPromptAck(PacketType t) noexcept {
    return t == PacketType::Payload || t == PacketType::PayloadBatch || t == PacketType::MtuProbe;
}

// Record that a packet arrived, so our next header acknowledges it. Called only once its payload has
// been accepted: acking a message a full buffer refused tells the sender it was delivered, and it is
// never sent again. Separate from processIncomingAcks for exactly that reason.
//
// The sequence is recorded for EVERY packet, so the ack bitfield stays exact whatever arrived; only
// whether to answer it this tick depends on the type.
inline void recordReceivedPacket(Connection& conn, const PacketHeader& header) {
    const SequenceNum sn = header.sequence;
    onPacketsReceived(conn.reliability, &sn, 1);
    if (needsPromptAck(header.type)) conn.pendingAck = true;
}

// Process the peer's acknowledgements from an incoming header: drive cwnd, sample RTT, resolve the
// channel messages it confirms, and flag triple-NACKed ones for fast retransmit. Runs whether or not we
// can accept this packet's own payload -- the peer's acks are facts about what IT received, and
// discarding them would stall our send window over a problem on our receive side.
inline void processIncomingAcks(Connection& conn, const PacketHeader& header, MonoTime now) {
    const std::uint64_t ackBits64 = header.ackBits;   // 32-bit wire field widened to 64
    const AckResult     res       = processAcks(conn.reliability, header.ack, ackBits64, now);

    // An MTU probe carries no reliable messages, so the sent ring never sees it -- its ack is read
    // straight off the header. (At very high send rates a probe's slot can slide out of the 33-seq
    // ack window before a header covering it arrives; the miss reads as a probe loss, which only
    // ever keeps the MTU smaller -- the safe direction.)
    if (conn.mtuDiscovery.probeSeq && ackCovers(header.ack, ackBits64, *conn.mtuDiscovery.probeSeq))
        mtuOnProbeAcked(conn.mtuDiscovery, now);

    // Same trick for the last WindowUpdate: it carries no reliable messages either, so the sent ring
    // never sees it and the header is the only proof it landed. Until one covers it, maybeAdvertiseWindow
    // keeps re-sending -- a missed ack costs a repeat, never a wedged channel.
    if (!conn.windowUpdateAcked && ackCovers(header.ack, ackBits64, conn.windowUpdateSeq))
        conn.windowUpdateAcked = true;

    if (conn.cwnd) {
        // One header can BOTH confirm packets and (via a triple-NACK) reveal losses. The byte
        // accounting must happen either way -- acked and newly-lost bytes have both left the
        // network -- but a header that signalled congestion must not also grow the window.
        //
        // The congestion test is the lost-packet COUNT, not the fastRetransmit list: congestion is a
        // property of the path, so any drop must shrink the window. Gating on fastRetransmit tied the
        // window to RELIABLE loss alone, and an unreliable-only packet yields no fastRetransmit
        // entries -- so on a stream of unreliable snapshots (what games mostly send) the window sat at
        // its initial size through 40% loss while the AIMD controller correctly halved its rate.
        //
        // The ack side is symmetric, and gated on the packet COUNT for the same reason: growth itself is
        // byte-driven (an unreliable packet's 0 bytes correctly grow nothing), but reaching cwOnAck is
        // what ENDS fast recovery. Testing ackedBytes meant an unreliable-only ack never reached it, so
        // one loss on a snapshot stream parked the window in Recovery until some reliable ack eventually
        // arrived -- shrinking on all traffic while recovering on almost none.
        cwReleaseInFlight(*conn.cwnd, res.lostBytes);
        if (res.lostPackets > 0) {
            cwReleaseInFlight(*conn.cwnd, res.ackedBytes);
            cwOnLoss(*conn.cwnd);
        } else if (res.ackedPackets > 0) {
            cwOnAck(*conn.cwnd, res.ackedBytes);
        }
    }
    for (const ChannelMsg& m : res.acked) {
        const int idx = toInt(m.channel);
        if (idx >= 0 && idx < static_cast<int>(conn.channels.size()))
            acknowledgeMessage(conn.channels[static_cast<std::size_t>(idx)], m.seq, m.fragIndex);
    }
    for (const ChannelMsg& m : res.fastRetransmit) {   // triple-NACKed -> resend without waiting out the RTO
        const int idx = toInt(m.channel);
        if (idx >= 0 && idx < static_cast<int>(conn.channels.size()))
            markForRetransmit(conn.channels[static_cast<std::size_t>(idx)], m.seq);
    }
}

// First-send emission for a FRAGMENTED message, paced by the congestion budget: as many fragments as
// the budget (and, for reliable traffic, the window) admit this tick, resuming next tick at
// msg.sentFragments. This is what lets maxMessageSize exceed one token bucket -- the message no longer
// has to be admitted whole. The split is a pure function of (innerLen, chunk), so indices and
// boundaries are identical across the ticks the message spans and across retransmits (selective
// retransmit depends on that). Returns false when the budget ran out mid-message: emission is in
// order, so the channel sends nothing past it this tick.
inline bool emitPacedFragments(Connection& conn, Channel& channel, int chIdx, SequenceNum seq,
                               std::size_t count, int chunk, MonoTime now) {
    const auto it = channel.sendBuffer.find(seq);
    if (it == channel.sendBuffer.end()) return true;   // erased mid-pacing (an unreliable overflow drop): nothing left to emit
    ChannelMessage& msg        = it->second;
    const bool      isReliable = channelIsReliable(channel);
    // Recorded BEFORE the first wire leaves, not at commit: an ack for an early fragment can arrive
    // while later ones are still unsent, and acknowledgeMessage must see the real count -- with it
    // still 0 the message would read as unfragmented and that first fragment ack would mark it fully
    // delivered.
    if (msg.sentFragments == 0) msg.fragmentCount = static_cast<std::uint8_t>(count);
    const MessageId msgId = fragmentMessageId(chIdx, msg);
    std::size_t i = msg.sentFragments;
    for (; i < count; ++i) {
        const auto [start, end] = fragmentRange(channelInnerSize(msg), chunk, i);
        const int  wireSize     = 1 + fragmentHeaderSize + static_cast<int>(end - start);
        if (!ccCanSend(conn.congestion, wireSize)) break;
        const bool windowGates = conn.cwnd && isReliable && wireSize > smallReliableThreshold;
        if (windowGates && !(cwCanSend(*conn.cwnd, wireSize) && cwCanSendPaced(*conn.cwnd, now))) break;
        ccDeductBudget(conn.congestion, wireSize);
        enqueuePayload(conn, isReliable, chIdx, seq, static_cast<std::uint8_t>(i),
                       encodeFragmentWireAt(chIdx, msgId, msg, chunk, i, count));
    }
    msg.sentFragments = static_cast<std::uint8_t>(i);
    if (i < count) return false;
    commitOutgoingMessage(channel, seq, now);   // fully emitted; the RTO clock starts now, not at channelSend
    return true;
}

// --- per-tick channel output ---
inline void processChannelMessages(Connection& conn, MonoTime now, int chIdx) {
    Channel& channel = conn.channels[static_cast<std::size_t>(chIdx)];
    // Receiver credit, counted once per tick and then tracked locally as messages are admitted:
    // recomputing the unacked count per message would make this loop quadratic in the send buffer.
    const bool creditGates = channelIsReliable(channel);
    const int  credit      = creditGates ? static_cast<int>(conn.peerCredit[static_cast<std::size_t>(chIdx)]) : 0;
    int        unacked     = creditGates ? channelUnackedCount(channel) : 0;
    for (;;) {
        // The receiver has no room for another message. Leave it queued: the send buffer fills and
        // channelSend reports BufferFull, so the application throttles instead of the sender burning
        // this message's retries against a buffer that cannot take it.
        if (creditGates && unacked >= credit) break;
        const ChannelMessage* peek = peekOutgoingMessage(channel);
        if (!peek) break;
        const SequenceNum seq        = peek->sequence;
        const bool        isReliable = channelIsReliable(channel);
        const std::size_t innerLen   = channelInnerSize(*peek);
        const int         chunk      = maxFragmentChunk(conn.config);

        if (chunk > 0 && innerLen > static_cast<std::size_t>(chunk)) {   // fragmented: paced, may span ticks
            const std::size_t count = fragmentCountFor(innerLen, chunk);
            // Beyond the fragmentable ceiling (see buildMessageWires): dispose + count, never stall.
            // Erased, not committed -- commit KEEPS a reliable message for retransmit, and one that can
            // never render would re-qualify as a retransmit candidate every tick forever.
            if (count == 0) { channel.sendBuffer.erase(seq); channel.totalDropped += 1; continue; }
            if (!emitPacedFragments(conn, channel, chIdx, seq, count, chunk, now)) break;   // budget spent mid-message
            if (creditGates) ++unacked;   // fully emitted, so committed: it now holds one receiver slot
            continue;
        }

        const int size = static_cast<int>(innerLen) + 1;    // [channel byte][seq:2][payload]: arithmetic, no render needed to price it
        if (!ccCanSend(conn.congestion, size)) break;       // rate gate
        // The window governs RELIABLE traffic only: nothing ever acks an unreliable message, so its
        // bytes could never be released and gating on them would wedge the window shut. Small
        // reliable messages skip the gate (latency) but are still charged at flush, so the
        // accounting stays exact. Unreliable traffic is bounded by the byte budget above.
        const bool windowGates = conn.cwnd && isReliable && size > smallReliableThreshold;
        if (windowGates && !(cwCanSend(*conn.cwnd, size) && cwCanSendPaced(*conn.cwnd, now))) break;

        Bytes wire = encodeChannelWire(chIdx, *peek);        // render before commit -- commit erases an unreliable *peek
        commitOutgoingMessage(channel, seq, now);
        ccDeductBudget(conn.congestion, size);
        enqueuePayload(conn, isReliable, chIdx, seq, 0, std::move(wire));
        if (creditGates) ++unacked;   // one more message the receiver must find room for
    }
}

inline void processChannelOutput(Connection& conn, MonoTime now) {
    for (const int chIdx : conn.channelPriority)
        if (chIdx >= 0 && chIdx < static_cast<int>(conn.channels.size()))
            processChannelMessages(conn, now, chIdx);
}

// Re-send reliable messages whose RTO has elapsed (congestion budget still applies).
inline void processRetransmissions(Connection& conn, MonoTime now, double rto) {
    for (int chIdx = 0; chIdx < static_cast<int>(conn.channels.size()); ++chIdx) {
        Channel& channel = conn.channels[static_cast<std::size_t>(chIdx)];
        // A receiver will refuse anything it has no room for, and every refused attempt spends a retry
        // the message only has so many of -- burning them against a shut window is exactly the drop the
        // advertised credit exists to prevent. Not sending keeps the retry count where it is
        // (commitRetransmit only runs on admission), so nothing is lost while it waits; the receiver's
        // re-advertise is what guarantees the reopen is heard.
        //
        // The bound is the credit itself, not merely "credit != 0". Gating only at zero meant a receiver
        // advertising 1 free slot still had EVERY expired message retransmitted at it each RTO: one was
        // accepted and the rest refused, each refusal burning a retry, so a receiver hovering at one or
        // two free slots for ~10 RTOs destroyed reliable messages anyway. Sending at most `credit` of
        // them -- getRetransmitMessages yields oldest-first, so these are the ones most worth the slot --
        // keeps the pressure exactly at what the receiver said it can take.
        const bool creditGates = channelIsReliable(channel);
        int        budget      = creditGates ? static_cast<int>(conn.peerCredit[static_cast<std::size_t>(chIdx)]) : 0;
        if (creditGates && budget == 0) continue;
        for (const ChannelMessage* msg : getRetransmitMessages(channel, now, rto)) {   // pointers into the send buffer, no payload copy
            if (creditGates && budget <= 0) break;   // the receiver's stated room is spent for this tick
            MessageWires mw = buildMessageWires(conn.config, chIdx, *msg);   // fragmented: only the pieces still unacked
            if (!mw.ok || mw.wires.empty()) continue;   // nothing missing left to resend
            int totalSize = 0;
            for (const MessageWire& w : mw.wires) totalSize += static_cast<int>(w.data.size());
            // Retransmits are budget-gated but never congestion-WINDOW-gated: they carry data the peer
            // is already missing, so blocking them behind a full window is exactly how a stalled
            // connection stays stalled. They are still charged at flush, so the window sees them.
            if (!ccCanSend(conn.congestion, totalSize)) break;   // budget gone -> leave the rest for next tick, state intact
            ccDeductBudget(conn.congestion, totalSize);
            const SequenceNum seq = msg->sequence;
            commitRetransmit(channel, seq, now);                 // advance send state only now that it is admitted
            if (creditGates) --budget;                           // this one is claiming a receiver slot
            for (MessageWire& w : mw.wires)
                enqueuePayload(conn, true, chIdx, seq, w.fragIndex, std::move(w.data));
        }
    }
}

// --- full reset (disconnect -> recycle) ---
inline void resetConnection(Connection& conn) {
    const NetworkConfig& config = conn.config;
    conn.startTime        = std::nullopt;
    conn.localSeq         = firstSequence;   // 0 stays reserved on a recycled connection too
    conn.sendQueue.clear();
    conn.pendingWires.clear();
    conn.clockSync        = ClockSync{};
    conn.lastTimeSyncTime = MonoTime{};
    conn.disconnectTime   = std::nullopt;
    conn.disconnectRetries = 0;
    conn.pendingAck       = false;
    conn.peerCredit.fill(peerCreditUnknown);   // a recycled connection must not inherit the old peer's credit
    conn.advertisedCredit.fill(0);
    conn.lastWindowAdvertise = MonoTime{};
    conn.windowAdvertised    = false;
    conn.windowUpdateSeq     = SequenceNum{};
    conn.windowUpdateAcked   = true;    // nothing outstanding on a fresh connection
    conn.windowUpdateAppliedSeq = SequenceNum{};
    conn.windowUpdateApplied    = false;
    for (Channel& ch : conn.channels) resetChannel(ch);
    conn.reliability  = newReliableEndpoint(config);
    // The window is transport state like everything else here: a recycled connection that kept the old
    // one would start life with a stale bytesInFlight (and phase) from the session that just ended,
    // and nothing would ever ack those bytes back out. resetTransportMetrics already did this.
    conn.cwnd         = config.useCwndCongestion ? std::optional<CongestionWindow>(newCongestionWindow(config.mtu)) : std::nullopt;
    conn.congestion   = newCongestionController(config.sendRate, config.maxPacketRate, config.congestionBadLossThreshold,
                                                config.congestionGoodRttThreshold, config.congestionRecoveryTimeMs);
    conn.bandwidthUp   = newBandwidthTracker(bandwidthWindowMs);
    conn.bandwidthDown = newBandwidthTracker(bandwidthWindowMs);
    conn.mtuDiscovery  = newMtuDiscovery(config.mtu, config.mtuProbeCeiling, config.enableMtuDiscovery);
}

// --- tick update ---
inline void updateConnectedPure(Connection& conn, MonoTime now) {
    const NetworkConfig& cfg = conn.config;

    ccUpdate(conn.congestion, conn.stats.packetLoss, conn.stats.rtt, now);
    ccRefillBudget(conn.congestion, cfg.mtu, now);

    if (conn.cwnd) {
        cwSlowStartRestart(*conn.cwnd, conn.reliability.rto, now);   // idle detection is in RTO units (RFC 2861)
        cwUpdatePacing(*conn.cwnd, conn.reliability.srtt);           // pacing spreads a window over one RTT, not one RTO
    }

    if (elapsedMs(conn.lastSendTime, now) > cfg.keepaliveIntervalMs) sendKeepalive(conn);
    if (elapsedMs(conn.lastTimeSyncTime, now) > timeSyncIntervalMs)  sendTimeSyncPing(conn, now);

    // Path-MTU discovery. Near-total loss while coalescing above the floor reads as a path that
    // shrank under us (a black hole): collapse to the floor now rather than waiting out a re-probe.
    if (conn.mtuDiscovery.plpmtu > conn.mtuDiscovery.baseMtu
        && conn.reliability.lossWindowCount >= mtuBlackholeMinSamples
        && packetLossFraction(conn.reliability) >= mtuBlackholeLossFraction)
        mtuCollapse(conn.mtuDiscovery);
    if (const int probeSize = mtuTick(conn.mtuDiscovery, now, conn.reliability.rto))
        mtuOnProbeSent(conn.mtuDiscovery, sendMtuProbe(conn, probeSize), probeSize, now);

    processChannelOutput(conn, now);
    processRetransmissions(conn, now, conn.reliability.rto);
    flushPendingWires(conn, now);
    for (Channel& ch : conn.channels) channelUpdate(ch, now);

    // An ack rides in the header of EVERY packet, and createHeaderInternal clears pendingAck as it
    // snapshots one -- so anything still pending here is an ack no packet built this tick could have
    // carried, and it needs a wire of its own.
    if (conn.pendingAck) sendAckOnly(conn);

    const CongestionLevel binaryLevel = ccCongestionLevel(conn.congestion);
    const CongestionLevel windowLevel = conn.cwnd ? cwCongestionLevel(*conn.cwnd) : CongestionLevel::None;
    const CongestionLevel congLevel   = static_cast<int>(binaryLevel) >= static_cast<int>(windowLevel) ? binaryLevel : windowLevel;

    conn.stats.rtt               = conn.reliability.srtt;
    conn.stats.packetLoss        = packetLossFraction(conn.reliability);
    conn.stats.bandwidthUp       = btBytesPerSecond(conn.bandwidthUp, now);     // window ends at now, so an
    conn.stats.bandwidthDown     = btBytesPerSecond(conn.bandwidthDown, now);   // idle link decays to 0
    conn.stats.connectionQuality = assessConnectionQuality(conn.reliability.srtt, conn.stats.packetLoss * 100.0);
    conn.stats.congestionLevel   = congLevel;
    conn.stats.pathMtu           = conn.mtuDiscovery.plpmtu;
    conn.pendingAck              = false;
}

inline std::optional<ConnectionError> updateConnected(Connection& conn, MonoTime now) {
    if (elapsedMs(conn.lastRecvTime, now) > conn.config.connectionTimeoutMs) return ConnectionError{ ConnectionError::Timeout };
    updateConnectedPure(conn, now);
    return std::nullopt;
}

inline std::optional<ConnectionError> updateDisconnecting(Connection& conn, MonoTime now) {
    if (!conn.disconnectTime) return std::nullopt;
    if (elapsedMs(*conn.disconnectTime, now) <= conn.config.disconnectRetryTimeoutMs) return std::nullopt;
    if (conn.disconnectRetries >= conn.config.disconnectRetries) {
        conn.state = ConnectionState::Disconnected;
        resetConnection(conn);
        return std::nullopt;
    }
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::Disconnect;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::Disconnect, Bytes{ disconnectReasonCode(DisconnectReason::Requested) } });
    conn.disconnectRetries += 1;
    conn.disconnectTime     = now;
    conn.localSeq           = next(conn.localSeq);
    return std::nullopt;
}

inline std::optional<ConnectionError> updateTick(Connection& conn, MonoTime now) {
    switch (conn.state) {
        case ConnectionState::Disconnected:  return std::nullopt;
        case ConnectionState::Connected:     return updateConnected(conn, now);
        case ConnectionState::Disconnecting: return updateDisconnecting(conn, now);
    }
    return std::nullopt;
}

// --- misc ---
inline std::vector<OutgoingPacket> drainSendQueue(Connection& conn) {
    std::vector<OutgoingPacket> out = std::move(conn.sendQueue);
    conn.sendQueue.clear();
    return out;
}
inline void touchRecvTime(Connection& conn, MonoTime now) { conn.lastRecvTime = now; }
inline void touchSendTime(Connection& conn, MonoTime now) { conn.lastSendTime = now; }

inline void markConnected(Connection& conn, MonoTime now) {
    conn.state     = ConnectionState::Connected;
    conn.startTime = now;
    conn.localSeq  = firstSequence;   // the first keyed packet must not be sequence 0 (see firstSequence)
}

inline void recordBytesSent(Connection& conn, int bytes, MonoTime now) {
    btRecord(conn.bandwidthUp, bytes, now);
    conn.stats.packetsSent += 1;
    conn.stats.bytesSent   += static_cast<std::uint64_t>(bytes);
    conn.lastSendTime       = now;
}
inline void recordBytesReceived(Connection& conn, int bytes, MonoTime now) {
    btRecord(conn.bandwidthDown, bytes, now);
    conn.stats.packetsReceived += 1;
    conn.stats.bytesReceived   += static_cast<std::uint64_t>(bytes);
}

// Reset transport metrics for a new network path (connection migration): clears RTT,
// congestion, bandwidth, and stats while preserving channels, salts, nonces, state, seqs.
inline void resetTransportMetrics(Connection& conn, MonoTime now) {
    const NetworkConfig& config = conn.config;
    resetReliabilityMetrics(conn.reliability);
    conn.congestion = newCongestionController(config.sendRate, config.maxPacketRate, config.congestionBadLossThreshold,
                                              config.congestionGoodRttThreshold, config.congestionRecoveryTimeMs);
    conn.cwnd          = config.useCwndCongestion ? std::optional<CongestionWindow>(newCongestionWindow(config.mtu)) : std::nullopt;
    conn.bandwidthUp   = newBandwidthTracker(bandwidthWindowMs);
    conn.bandwidthDown = newBandwidthTracker(bandwidthWindowMs);
    conn.mtuDiscovery  = newMtuDiscovery(config.mtu, config.mtuProbeCeiling, config.enableMtuDiscovery);   // a new path invalidates the old one's MTU
    conn.stats         = NetworkStats{};
    conn.lastSendTime  = now;
    conn.lastRecvTime  = now;
}

} // namespace aether
