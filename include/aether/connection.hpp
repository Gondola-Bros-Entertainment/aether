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
#include "aether/packet.hpp"
#include "aether/reliability.hpp"
#include "aether/stats.hpp"
#include "aether/types.hpp"
#include "aether/x25519.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
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

enum class ConnectionState { Disconnected, Connecting, Connected, Disconnecting };

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
    enum Kind {
        NotConnected, AlreadyConnected, ConnectionDenied, Timeout, ProtocolMismatch,
        InvalidPacket, InvalidChannel, ChannelErr, MessageTooLarge,
    };
    Kind         kind         = NotConnected;
    std::uint8_t deniedCode   = 0;                    // for ConnectionDenied
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
    MonoTime                     lastSendTime{};
    MonoTime                     lastRecvTime{};
    std::optional<MonoTime>      startTime;
    std::optional<MonoTime>      requestTime;
    int                          retryCount = 0;
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
    ReplayWindow                 recvReplay{};
    bool                         pendingAck        = false;
    bool                         dataSentThisTick  = false;
    ClockSync                    clockSync{};                 // estimated offset to the peer's clock
    MonoTime                     lastTimeSyncTime{};          // last TimeSyncPing send time
};

// --- construction ---
inline Connection newConnection(const NetworkConfig& config, std::uint64_t clientSalt, MonoTime now) {
    Connection c;
    c.config       = config;
    c.clientSalt   = clientSalt;
    c.lastSendTime = now;
    c.lastRecvTime = now;

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

    c.congestion = newCongestionController(config.sendRate, config.congestionBadLossThreshold,
                                           config.congestionGoodRttThreshold, config.congestionRecoveryTimeMs);
    if (config.useCwndCongestion) c.cwnd = newCongestionWindow(config.mtu);
    c.bandwidthUp   = newBandwidthTracker(bandwidthWindowMs);
    c.bandwidthDown = newBandwidthTracker(bandwidthWindowMs);
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
inline PacketHeader createHeader(Connection& conn) {
    const PacketHeader h = createHeaderInternal(conn);
    conn.localSeq = next(conn.localSeq);
    return h;
}

// --- send-queue helpers ---
inline void sendConnectionRequest(Connection& conn) {
    const PacketHeader header{ PacketType::ConnectionRequest, SequenceNum{ 0 }, SequenceNum{ 0 }, 0 };
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::ConnectionRequest, Bytes{} });
}
inline void enqueueEmptyPacket(Connection& conn) {   // keepalive / ack-only share this wire form
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::Keepalive;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::Keepalive, Bytes{} });
    conn.localSeq = next(conn.localSeq);
}
inline void sendKeepalive(Connection& conn) { enqueueEmptyPacket(conn); }
inline void sendAckOnly(Connection& conn)   { enqueueEmptyPacket(conn); }

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

// Wire form of a channel message: [channel:3 bits | reserved:5][seqHi][seqLo][payload].
inline Bytes encodeChannelWire(int chIdx, const ChannelMessage& msg) {
    const std::uint16_t seqRaw = msg.sequence.value;
    Bytes wire;
    wire.reserve(3 + msg.data.size());
    wire.push_back(static_cast<std::uint8_t>(chIdx & channelWireChannelMask));
    wire.push_back(static_cast<std::uint8_t>(seqRaw >> 8));
    wire.push_back(static_cast<std::uint8_t>(seqRaw & 0xFF));
    wire.insert(wire.end(), msg.data.begin(), msg.data.end());
    return wire;
}

// Accumulate a channel-message wire for this tick; flushPendingWires coalesces them into packets.
inline void enqueuePayload(Connection& conn, bool trackReliable, int chIdx,
                           const ChannelMessage& msg, const Bytes& wireData) {
    conn.pendingWires.push_back(
        PendingWire{ wireData, trackReliable, ChannelMsg{ static_cast<ChannelId>(chIdx), msg.sequence } });
}

// Coalesce this tick's accumulated wires into packets: a lone wire stays a plain Payload; several
// become one PayloadBatch ([u8 count][u16 len][wire]...). Each packet gets one sequence, and every
// reliable message it carries is registered under that sequence.
inline void flushPendingWires(Connection& conn, MonoTime now) {
    const int   mtu = conn.config.mtu;
    std::size_t i   = 0;
    while (i < conn.pendingWires.size()) {
        std::size_t n          = 0;
        int         groupBytes = batchHeaderSize;
        while (i + n < conn.pendingWires.size() && n < maxMsgsPerPacket) {
            const int add = batchLengthSize + static_cast<int>(conn.pendingWires[i + n].wire.size());
            if (n > 0 && groupBytes + add > mtu) break;   // keep within the MTU (always take >= 1)
            groupBytes += add;
            ++n;
        }
        std::array<ChannelMsg, maxMsgsPerPacket> relMsgs{};
        std::uint8_t relCount = 0;
        Bytes        payload;
        PacketType   type;
        if (n == 1) {
            type    = PacketType::Payload;
            payload = conn.pendingWires[i].wire;
            if (conn.pendingWires[i].reliable) relMsgs[relCount++] = conn.pendingWires[i].msg;
        } else {
            type = PacketType::PayloadBatch;
            payload.push_back(static_cast<std::uint8_t>(n));
            for (std::size_t k = 0; k < n; ++k) {
                const PendingWire& pw = conn.pendingWires[i + k];
                payload.push_back(static_cast<std::uint8_t>(pw.wire.size() >> 8));
                payload.push_back(static_cast<std::uint8_t>(pw.wire.size() & 0xFF));
                payload.insert(payload.end(), pw.wire.begin(), pw.wire.end());
                if (pw.reliable) relMsgs[relCount++] = pw.msg;
            }
        }
        PacketHeader header = createHeaderInternal(conn);
        header.type = type;
        conn.sendQueue.push_back(OutgoingPacket{ header, type, std::move(payload) });
        if (relCount > 0)
            onPacketSent(conn.reliability, conn.localSeq, now,
                         std::span<const ChannelMsg>(relMsgs.data(), relCount), groupBytes);
        conn.localSeq         = next(conn.localSeq);
        conn.dataSentThisTick = true;
        i += n;
    }
    conn.pendingWires.clear();
}

// --- operations ---
inline std::optional<ConnectionError> connect(Connection& conn, MonoTime now) {
    if (conn.state != ConnectionState::Disconnected) return ConnectionError{ ConnectionError::AlreadyConnected };
    conn.state       = ConnectionState::Connecting;
    conn.requestTime = now;
    conn.retryCount  = 0;
    sendConnectionRequest(conn);
    return std::nullopt;
}

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
        return ConnectionError{ ConnectionError::InvalidChannel, 0, channelId };
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

inline void receiveIncomingPayload(Connection& conn, ChannelId channelId, SequenceNum chSeq, const Bytes& payload, MonoTime now) {
    const int idx = toInt(channelId);
    if (idx < 0 || idx >= static_cast<int>(conn.channels.size())) return;
    onMessageReceived(conn.channels[static_cast<std::size_t>(idx)], chSeq, payload, now);
}

// Feed an incoming header into reliability: record it for acking, process the peer's acks,
// drive cwnd, and acknowledge the channel messages it confirms.
inline void processIncomingHeader(Connection& conn, const PacketHeader& header, MonoTime now) {
    const SequenceNum sn = header.sequence;
    onPacketsReceived(conn.reliability, &sn, 1);
    conn.pendingAck = true;

    const std::uint64_t ackBits64 = header.ackBits;   // 32-bit wire field widened to 64
    const AckResult     res       = processAcks(conn.reliability, header.ack, ackBits64, now);

    if (conn.cwnd) {
        const bool hasLoss    = !res.fastRetransmit.empty();
        const int  ackedBytes = static_cast<int>(res.acked.size()) * conn.config.mtu;
        if (hasLoss)             cwOnLoss(*conn.cwnd);
        else if (ackedBytes > 0) cwOnAck(*conn.cwnd, ackedBytes);
    }
    for (const ChannelMsg& m : res.acked) {
        const int idx = toInt(m.channel);
        if (idx >= 0 && idx < static_cast<int>(conn.channels.size()))
            acknowledgeMessage(conn.channels[static_cast<std::size_t>(idx)], m.seq);
    }
    for (const ChannelMsg& m : res.fastRetransmit) {   // triple-NACKed -> resend without waiting out the RTO
        const int idx = toInt(m.channel);
        if (idx >= 0 && idx < static_cast<int>(conn.channels.size()))
            markForRetransmit(conn.channels[static_cast<std::size_t>(idx)], m.seq);
    }
}

// --- per-tick channel output ---
inline void processChannelMessages(Connection& conn, MonoTime now, int chIdx) {
    Channel& channel = conn.channels[static_cast<std::size_t>(chIdx)];
    for (;;) {
        const auto peek = peekOutgoingMessage(channel);
        if (!peek) break;
        const Bytes wireData   = encodeChannelWire(chIdx, *peek);
        const int   wireSize   = static_cast<int>(wireData.size());
        const bool  isReliable = channelIsReliable(channel);
        if (!ccCanSend(conn.congestion, 0, wireSize)) break;       // rate gate, by actual message size

        // small reliable messages bypass cwnd; otherwise honor the window if present
        const bool cwndAllows = (isReliable && wireSize <= smallReliableThreshold)
                              || !conn.cwnd
                              || (cwCanSend(*conn.cwnd, wireSize) && cwCanSendPaced(*conn.cwnd, now));
        if (!cwndAllows) break;

        commitOutgoingMessage(channel, peek->sequence);
        ccDeductBudget(conn.congestion, wireSize);
        if (conn.cwnd) cwOnSend(*conn.cwnd, wireSize, now);
        enqueuePayload(conn, isReliable, chIdx, *peek, wireData);
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
        const std::vector<ChannelMessage> retransmits = getRetransmitMessages(conn.channels[static_cast<std::size_t>(chIdx)], now, rto);
        for (const ChannelMessage& msg : retransmits) {
            const Bytes wireData = encodeChannelWire(chIdx, msg);
            const int   wireSize = static_cast<int>(wireData.size());
            if (!ccCanSend(conn.congestion, 0, wireSize)) break;
            ccDeductBudget(conn.congestion, wireSize);
            enqueuePayload(conn, true, chIdx, msg, wireData);
        }
    }
}

// --- full reset (disconnect -> recycle) ---
inline void resetConnection(Connection& conn) {
    const NetworkConfig& config = conn.config;
    conn.startTime        = std::nullopt;
    conn.requestTime      = std::nullopt;
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
    conn.reliability  = ReliableEndpoint{};
    conn.congestion   = newCongestionController(config.sendRate, config.congestionBadLossThreshold,
                                                config.congestionGoodRttThreshold, config.congestionRecoveryTimeMs);
    conn.bandwidthUp   = newBandwidthTracker(bandwidthWindowMs);
    conn.bandwidthDown = newBandwidthTracker(bandwidthWindowMs);
}

// --- tick update ---
inline void updateConnectedPure(Connection& conn, MonoTime now) {
    const NetworkConfig& cfg = conn.config;

    ccUpdate(conn.congestion, conn.stats.packetLoss, conn.stats.rtt, now);
    ccRefillBudget(conn.congestion, cfg.mtu);

    if (conn.cwnd) {
        const double rto = conn.reliability.rto;
        cwSlowStartRestart(*conn.cwnd, rto, now);
        cwUpdatePacing(*conn.cwnd, rto);
    }

    if (elapsedMs(conn.lastSendTime, now) > cfg.keepaliveIntervalMs) sendKeepalive(conn);
    if (elapsedMs(conn.lastTimeSyncTime, now) > timeSyncIntervalMs)  sendTimeSyncPing(conn, now);

    processChannelOutput(conn, now);
    processRetransmissions(conn, now, conn.reliability.rto);
    flushPendingWires(conn, now);
    for (Channel& ch : conn.channels) channelUpdate(ch, now);

    if (conn.pendingAck && !conn.dataSentThisTick) sendAckOnly(conn);

    const CongestionLevel binaryLevel = ccCongestionLevel(conn.congestion);
    const CongestionLevel windowLevel = conn.cwnd ? cwCongestionLevel(*conn.cwnd) : CongestionLevel::None;
    const CongestionLevel congLevel   = static_cast<int>(binaryLevel) >= static_cast<int>(windowLevel) ? binaryLevel : windowLevel;

    conn.stats.rtt               = conn.reliability.srtt;
    conn.stats.packetLoss        = packetLossPercent(conn.reliability);
    conn.stats.bandwidthUp       = btBytesPerSecond(conn.bandwidthUp);
    conn.stats.bandwidthDown     = btBytesPerSecond(conn.bandwidthDown);
    conn.stats.connectionQuality = assessConnectionQuality(conn.reliability.srtt, packetLossPercent(conn.reliability) * 100.0);
    conn.stats.congestionLevel   = congLevel;
    conn.pendingAck              = false;
}

inline std::optional<ConnectionError> updateConnecting(Connection& conn, MonoTime now) {
    if (!conn.requestTime) return std::nullopt;
    if (elapsedMs(*conn.requestTime, now) <= conn.config.connectionRequestTimeoutMs) return std::nullopt;
    const int retries = conn.retryCount + 1;
    if (retries > conn.config.connectionRequestMaxRetries) return ConnectionError{ ConnectionError::Timeout };
    conn.retryCount  = retries;
    conn.requestTime = now;
    sendConnectionRequest(conn);
    return std::nullopt;
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
        case ConnectionState::Connecting:    return updateConnecting(conn, now);
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
    conn.congestion = newCongestionController(config.sendRate, config.congestionBadLossThreshold,
                                              config.congestionGoodRttThreshold, config.congestionRecoveryTimeMs);
    conn.cwnd          = config.useCwndCongestion ? std::optional<CongestionWindow>(newCongestionWindow(config.mtu)) : std::nullopt;
    conn.bandwidthUp   = newBandwidthTracker(bandwidthWindowMs);
    conn.bandwidthDown = newBandwidthTracker(bandwidthWindowMs);
    conn.stats         = NetworkStats{};
    conn.lastSendTime  = now;
    conn.lastRecvTime  = now;
}

} // namespace aether
