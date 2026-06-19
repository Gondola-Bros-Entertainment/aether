// aether - connection state machine for one peer: ties together the handshake state machine,
// channels, reliability tracking, and congestion control. Data-first: a plain Connection struct
// mutated by free functions; operations that can fail return std::optional<ConnectionError>
// (nullopt = success).
#pragma once

#include "aether/channel.hpp"
#include "aether/config.hpp"
#include "aether/congestion.hpp"
#include "aether/crypto.hpp"
#include "aether/packet.hpp"
#include "aether/reliability.hpp"
#include "aether/stats.hpp"
#include "aether/types.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

namespace aether {

inline constexpr double bandwidthWindowMs = 1000.0;

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
    NetworkStats                 stats{};
    std::optional<MonoTime>      disconnectTime;
    int                          disconnectRetries = 0;
    std::optional<EncryptionKey> encryptionKey;
    NonceCounter                 sendNonce{};
    std::optional<std::uint64_t> recvNonceMax;
    bool                         pendingAck        = false;
    bool                         dataSentThisTick  = false;
};

// --- construction ---
inline Connection newConnection(const NetworkConfig& config, std::uint64_t clientSalt, MonoTime now) {
    Connection c;
    c.config       = config;
    c.clientSalt   = clientSalt;
    c.lastSendTime = now;
    c.lastRecvTime = now;

    const int numChannels = config.maxChannels;
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
    c.encryptionKey = config.encryptionKey;
    return c;
}

// --- queries ---
inline ConnectionState     connectionState(const Connection& c) noexcept { return c.state; }
inline bool                isConnected(const Connection& c) noexcept { return c.state == ConnectionState::Connected; }
inline const NetworkStats& connectionStats(const Connection& c) noexcept { return c.stats; }
inline SequenceNum         connRemoteSeq(const Connection& c) noexcept { return c.reliability.remoteSeq; }
inline std::uint8_t        channelCount(const Connection& c) noexcept { return static_cast<std::uint8_t>(c.channels.size()); }

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

// Wire form of a channel message: [channel:3 bits | reserved:5][seqHi][seqLo][payload].
inline Bytes encodeChannelWire(int chIdx, const ChannelMessage& msg) {
    const std::uint16_t seqRaw = msg.sequence.value;
    Bytes wire;
    wire.reserve(3 + msg.data.size());
    wire.push_back(static_cast<std::uint8_t>(chIdx & 0x07));
    wire.push_back(static_cast<std::uint8_t>(seqRaw >> 8));
    wire.push_back(static_cast<std::uint8_t>(seqRaw & 0xFF));
    wire.insert(wire.end(), msg.data.begin(), msg.data.end());
    return wire;
}

// Enqueue a Payload packet; reliable messages are registered with the reliability tracker.
inline void enqueuePayload(Connection& conn, bool trackReliable, MonoTime now, int chIdx,
                           const ChannelMessage& msg, const Bytes& wireData, int wireSize) {
    PacketHeader header = createHeaderInternal(conn);
    header.type = PacketType::Payload;
    conn.sendQueue.push_back(OutgoingPacket{ header, PacketType::Payload, wireData });
    if (trackReliable)
        onPacketSent(conn.reliability, conn.localSeq, now, static_cast<ChannelId>(chIdx), msg.sequence, wireSize);
    conn.localSeq          = next(conn.localSeq);
    conn.dataSentThisTick  = true;
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
}

// --- per-tick channel output ---
inline void processChannelMessages(Connection& conn, MonoTime now, int chIdx) {
    const int mtu     = conn.config.mtu;
    Channel&  channel = conn.channels[static_cast<std::size_t>(chIdx)];
    for (;;) {
        if (!ccCanSend(conn.congestion, 0, mtu)) break;            // binary rate gate
        const auto peek = peekOutgoingMessage(channel);
        if (!peek) break;
        const Bytes wireData   = encodeChannelWire(chIdx, *peek);
        const int   wireSize   = static_cast<int>(wireData.size());
        const bool  isReliable = channelIsReliable(channel);

        // small reliable messages bypass cwnd; otherwise honor the window if present
        const bool cwndAllows = (isReliable && wireSize <= smallReliableThreshold)
                              || !conn.cwnd
                              || (cwCanSend(*conn.cwnd, wireSize) && cwCanSendPaced(*conn.cwnd, now));
        if (!cwndAllows) break;

        commitOutgoingMessage(channel);
        ccDeductBudget(conn.congestion, wireSize);
        if (conn.cwnd) cwOnSend(*conn.cwnd, wireSize, now);
        enqueuePayload(conn, isReliable, now, chIdx, *peek, wireData, wireSize);
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
    const int mtu = conn.config.mtu;
    for (int chIdx = 0; chIdx < static_cast<int>(conn.channels.size()); ++chIdx) {
        const std::vector<ChannelMessage> retransmits = getRetransmitMessages(conn.channels[static_cast<std::size_t>(chIdx)], now, rto);
        for (const ChannelMessage& msg : retransmits) {
            if (!ccCanSend(conn.congestion, 0, mtu)) break;
            const Bytes wireData = encodeChannelWire(chIdx, msg);
            const int   wireSize = static_cast<int>(wireData.size());
            ccDeductBudget(conn.congestion, wireSize);
            enqueuePayload(conn, true, now, chIdx, msg, wireData, wireSize);
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

    processChannelOutput(conn, now);
    processRetransmissions(conn, now, conn.reliability.rto);
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
