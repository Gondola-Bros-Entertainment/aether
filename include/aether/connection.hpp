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
    bool                         dataSentThisTick  = false;
    ClockSync                    clockSync{};                 // estimated offset to the peer's clock
    MonoTime                     lastTimeSyncTime{};          // last TimeSyncPing send time
    MtuDiscovery                 mtuDiscovery{};              // path-MTU search; plpmtu feeds the coalescing budget
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

inline Connection newConnection(const NetworkConfig& config, std::uint64_t clientSalt, MonoTime now) {
    Connection c;
    c.config       = config;
    c.clientSalt   = clientSalt;
    c.lastSendTime = now;
    c.lastRecvTime = now;
    c.reliability  = newReliableEndpoint(config);

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

// --- header creation ---
inline PacketHeader createHeaderInternal(const Connection& conn) {
    const auto [ackSeq, ackBits64] = getAckInfo(conn.reliability);
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
inline void enqueuePayload(Connection& conn, bool trackReliable, int chIdx,
                           SequenceNum seq, std::uint8_t fragIndex, Bytes wireData) {
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
        if (relCount > 0) {
            // Charge the window here, in the same unit processAcks credits back (relBytes), so charge
            // and release match exactly regardless of how the wires coalesced. An eviction discards a
            // packet an ack can never resolve, so its bytes are returned immediately.
            const int evicted = onPacketSent(conn.reliability, conn.localSeq, now,
                                             std::span<const ChannelMsg>(relMsgs.data(), relCount), relBytes);
            if (conn.cwnd) {
                cwOnSend(*conn.cwnd, relBytes, now);
                cwReleaseInFlight(*conn.cwnd, evicted);
            }
        }
        conn.localSeq         = next(conn.localSeq);
        conn.dataSentThisTick = true;
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

// Record that a packet arrived, so our next header acknowledges it. Called only once its payload has
// been accepted: acking a message a full buffer refused tells the sender it was delivered, and it is
// never sent again. Separate from processIncomingAcks for exactly that reason.
inline void recordReceivedPacket(Connection& conn, const PacketHeader& header) {
    const SequenceNum sn = header.sequence;
    onPacketsReceived(conn.reliability, &sn, 1);
    conn.pendingAck = true;
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

    if (conn.cwnd) {
        // One header can BOTH confirm packets and (via a triple-NACK) reveal losses. The byte
        // accounting must happen either way -- acked and newly-lost bytes have both left the
        // network -- but a header that signalled congestion must not also grow the window.
        cwReleaseInFlight(*conn.cwnd, res.lostBytes);
        if (!res.fastRetransmit.empty()) {
            cwReleaseInFlight(*conn.cwnd, res.ackedBytes);
            cwOnLoss(*conn.cwnd);
        } else if (res.ackedBytes > 0) {
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
    for (;;) {
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
    }
}

inline void processChannelOutput(Connection& conn, MonoTime now) {
    conn.dataSentThisTick = false;
    for (const int chIdx : conn.channelPriority)
        if (chIdx >= 0 && chIdx < static_cast<int>(conn.channels.size()))
            processChannelMessages(conn, now, chIdx);
}

// Re-send reliable messages whose RTO has elapsed (congestion budget still applies).
inline void processRetransmissions(Connection& conn, MonoTime now, double rto) {
    for (int chIdx = 0; chIdx < static_cast<int>(conn.channels.size()); ++chIdx) {
        Channel& channel = conn.channels[static_cast<std::size_t>(chIdx)];
        for (const ChannelMessage* msg : getRetransmitMessages(channel, now, rto)) {   // pointers into the send buffer, no payload copy
            MessageWires mw = buildMessageWires(conn.config, chIdx, *msg);   // fragmented: only the pieces still unacked
            if (!mw.ok || mw.wires.empty()) continue;   // nothing missing left to resend
            int totalSize = 0;
            for (const MessageWire& w : mw.wires) totalSize += static_cast<int>(w.data.size());
            // Retransmits are budget-gated but never window-gated: they carry data the peer is already
            // missing, so blocking them behind a full window is exactly how a stalled connection stays
            // stalled. They are still charged at flush, so the window sees them.
            if (!ccCanSend(conn.congestion, totalSize)) break;   // budget gone -> leave the rest for next tick, state intact
            ccDeductBudget(conn.congestion, totalSize);
            const SequenceNum seq = msg->sequence;
            commitRetransmit(channel, seq, now);                 // advance send state only now that it is admitted
            for (MessageWire& w : mw.wires)
                enqueuePayload(conn, true, chIdx, seq, w.fragIndex, std::move(w.data));
        }
    }
}

// --- full reset (disconnect -> recycle) ---
inline void resetConnection(Connection& conn) {
    const NetworkConfig& config = conn.config;
    conn.startTime        = std::nullopt;
    conn.localSeq         = SequenceNum{ 0 };
    conn.sendQueue.clear();
    conn.pendingWires.clear();
    conn.clockSync        = ClockSync{};
    conn.lastTimeSyncTime = MonoTime{};
    conn.disconnectTime   = std::nullopt;
    conn.disconnectRetries = 0;
    conn.pendingAck       = false;
    conn.dataSentThisTick = false;
    for (Channel& ch : conn.channels) resetChannel(ch);
    conn.reliability  = newReliableEndpoint(config);
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

    if (conn.pendingAck && !conn.dataSentThisTick) sendAckOnly(conn);

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
    conn.localSeq  = SequenceNum{ 0 };
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
