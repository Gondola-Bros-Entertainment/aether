// aether - network configuration. All tunable parameters
// with their defaults in the member initializers, plus validation. Data-first: a plain struct.
#pragma once

#include "aether/channel.hpp"
#include "aether/crypto.hpp"
#include "aether/fragment.hpp"
#include "aether/packet.hpp"
#include "aether/reliability.hpp"
#include "aether/security.hpp"

#include <cmath>
#include <cstdint>
#include <optional>
#include <vector>

namespace aether {

// --- defaults ---
inline constexpr std::uint32_t defaultProtocolId                   = 0x12345678u;
inline constexpr int           defaultMaxClients                   = 64;
inline constexpr double         defaultConnectionTimeoutMs         = 10000.0;
inline constexpr double         defaultKeepaliveIntervalMs         = 1000.0;
inline constexpr double         defaultConnectionRequestTimeoutMs  = 5000.0;
inline constexpr int           defaultConnectionRequestMaxRetries  = 5;
inline constexpr int           defaultMtu                          = 1200;
inline constexpr double        defaultFragmentTimeoutMs            = 5000.0;
inline constexpr int           defaultMaxFragments                 = 256;
inline constexpr int           defaultMaxReassemblyBufferSize      = 1024 * 1024;
inline constexpr int           defaultMaxChannels                  = 8;
inline constexpr double        defaultSendRateHz                   = 60.0;
inline constexpr double        defaultMaxPacketRateHz              = 120.0;
inline constexpr double        defaultCongestionGoodRttThresholdMs = 250.0;
inline constexpr double        defaultCongestionBadLossThreshold   = 0.1;
inline constexpr double        defaultCongestionRecoveryTimeMs     = 10000.0;
inline constexpr int           defaultDisconnectRetries            = 3;
inline constexpr double        defaultDisconnectRetryTimeoutMs     = 500.0;
inline constexpr int           minMtu                              = 576;
inline constexpr int           maxMtu                              = 65535;
inline constexpr int           defaultMtuProbeCeiling              = 1500;   // ethernet: what most real paths carry
inline constexpr int           maxChannelCount                     = 8;
inline constexpr int           defaultMaxPending                   = 256;
inline constexpr int           defaultRateLimitPerSecond           = 10;
inline constexpr int           smallReliableThreshold              = 64;

// --- wire sizing (single source; used to size fragments AND to validate maxMessageSize) ---
inline constexpr int channelWireSeqBytes = 2;   // [seqHi][seqLo] prefix on a channel message's inner wire
inline constexpr int packetWireOverhead  = static_cast<int>(packetHeaderBytes) + encryptionOverhead + crc32Size;   // header + AEAD + CRC per datagram

// Top-level network configuration. NetworkConfig{} is the default config, and every field here is read
// by the library -- a knob that tuned nothing would be worse than no knob at all.
struct NetworkConfig {
    std::uint32_t protocolId                  = defaultProtocolId;
    int           maxClients                  = defaultMaxClients;
    double        connectionTimeoutMs         = defaultConnectionTimeoutMs;
    double        keepaliveIntervalMs         = defaultKeepaliveIntervalMs;
    double        connectionRequestTimeoutMs  = defaultConnectionRequestTimeoutMs;
    int           connectionRequestMaxRetries = defaultConnectionRequestMaxRetries;
    int           mtu                         = defaultMtu;                   // the FLOOR: everything is sized + validated against it
    int           mtuProbeCeiling             = defaultMtuProbeCeiling;       // discovery probes up to this (== mtu turns discovery off)
    bool          enableMtuDiscovery          = true;                         // probe the path for headroom above mtu (mtu.hpp)
    double        fragmentTimeoutMs           = defaultFragmentTimeoutMs;         // drop a partial reassembly after this
    int           maxFragments                = defaultMaxFragments;              // concurrent in-flight fragmented messages
    int           maxReassemblyBufferSize     = defaultMaxReassemblyBufferSize;   // cap on total buffered fragment bytes
    std::uint16_t maxSequenceDistance         = defaultMaxSequenceDistance;       // largest sequence jump still treated as a reorder
    int           maxInFlight                 = defaultMaxInFlight;               // unresolved sent packets before the oldest is evicted
    int           maxChannels                 = defaultMaxChannels;
    ChannelConfig defaultChannelConfig        = ChannelConfig{};
    std::vector<ChannelConfig> channelConfigs;
    double        sendRate                    = defaultSendRateHz;
    double        maxPacketRate               = defaultMaxPacketRateHz;
    double        congestionGoodRttThreshold  = defaultCongestionGoodRttThresholdMs;
    double        congestionBadLossThreshold  = defaultCongestionBadLossThreshold;
    double        congestionRecoveryTimeMs    = defaultCongestionRecoveryTimeMs;
    int           disconnectRetries           = defaultDisconnectRetries;
    double        disconnectRetryTimeoutMs    = defaultDisconnectRetryTimeoutMs;
    int           maxPending                  = defaultMaxPending;   // cap on concurrent half-open (in-handshake) connections; distinct from maxClients (established)
    int           rateLimitPerSecond          = defaultRateLimitPerSecond;
    bool          useCwndCongestion           = false;
    bool          enableConnectionMigration   = true;
    std::optional<EncryptionKey> tokenKey;   // server: the connect-token sealing key K; if set, a valid token is required to connect
};

enum class ConfigError {
    InvalidChannelCount,
    InvalidMtu,
    TimeoutNotGreaterThanKeepalive,
    InvalidMaxClients,
    ChannelConfigsExceedMaxChannels,
    InvalidSendRate,
    InvalidMaxPacketRate,
    InvalidMaxInFlight,
    InvalidMaxSequenceDistance,
    SendRateExceedsMaxPacketRate,
    InvalidCongestionThreshold,
    InvalidMaxFragments,
    InvalidFragmentTimeout,
    InvalidReassemblyBufferSize,
    InvalidMaxPending,
    InvalidConnectionRequestRetries,
    InvalidChannelConfig,
    MessageTooLargeToFragment,
    InvalidMtuProbeCeiling,
};

// MTU-derived sizing. effectivePayloadBudget = the channel-message payload that fits one datagram;
// maxFragmentChunk = the largest fragment data chunk (a fragment wire is [channel byte][fragment
// header][chunk]); maxFragmentableMessage = the largest message that still fits maxFragmentCount
// fragments. validateConfig rejects a maxMessageSize above the last, so a message is never accepted
// by channelSend and then dropped at fragmentation. connection.hpp fragments against these.
//
// Everything here derives from config.mtu -- the FLOOR -- never from a probed path MTU. A probed
// size can shrink back at runtime; the floor cannot, so sizes validated here hold for the life of
// the connection. Discovery headroom feeds only the coalescing budget (payloadBudgetAt, from the
// live plpmtu), which is re-decided at every flush and so has nothing pinned to invalidate.
inline int  payloadBudgetAt(int mtu) noexcept { return mtu - packetWireOverhead; }
inline int  effectivePayloadBudget(const NetworkConfig& c) noexcept { return payloadBudgetAt(c.mtu); }
inline int  maxFragmentChunk(const NetworkConfig& c) noexcept { return effectivePayloadBudget(c) - 1 - fragmentHeaderSize; }   // minus channel byte + fragment header
inline long maxFragmentableMessage(const NetworkConfig& c) noexcept {
    return static_cast<long>(maxFragmentCount) * maxFragmentChunk(c) - channelWireSeqBytes;
}

// A channel's caps must be positive: a non-positive maxMessageSize / messageBufferSize /
// maxOrderedBufferSize otherwise passes setup but silently dead-ends or perma-stalls the channel
// (every send rejected, or every out-of-order message dropped), instead of failing loudly here.
inline bool channelConfigValid(const ChannelConfig& c) noexcept {
    return c.maxMessageSize > 0 && c.messageBufferSize > 0 && c.maxOrderedBufferSize > 0
        && c.maxReliableRetries >= 0 && c.maxReceiveBufferSize > 0;
}

// Validate a config; nullopt means valid.
inline std::optional<ConfigError> validateConfig(const NetworkConfig& c) {
    const auto validPositive = [](double x) { return x > 0.0 && !std::isnan(x); };
    if (c.maxChannels <= 0 || c.maxChannels > maxChannelCount)        return ConfigError::InvalidChannelCount;
    if (c.mtu < minMtu || c.mtu > maxMtu)                             return ConfigError::InvalidMtu;
    // The probe ceiling brackets the discovery search: at least the floor (== mtu disables the
    // search), never past the largest datagram the transport handles.
    if (c.mtuProbeCeiling < c.mtu || c.mtuProbeCeiling > maxMtu)      return ConfigError::InvalidMtuProbeCeiling;
    if (c.connectionTimeoutMs <= c.keepaliveIntervalMs)              return ConfigError::TimeoutNotGreaterThanKeepalive;
    if (c.maxClients <= 0)                                            return ConfigError::InvalidMaxClients;
    if (static_cast<int>(c.channelConfigs.size()) > c.maxChannels)    return ConfigError::ChannelConfigsExceedMaxChannels;
    if (!validPositive(c.sendRate))                                   return ConfigError::InvalidSendRate;
    if (!validPositive(c.maxPacketRate))                              return ConfigError::InvalidMaxPacketRate;
    // maxInFlight cannot exceed the sent ring's physical capacity: the ring indexes by seq & 255, so a
    // larger cap would not track more packets, it would displace them a full cycle early.
    if (c.maxInFlight <= 0 || c.maxInFlight > sentBufferSize)         return ConfigError::InvalidMaxInFlight;
    // A zero sequence distance would reject every packet that is not the one we just saw, killing the
    // connection the moment a single datagram reorders.
    if (c.maxSequenceDistance == 0)                                   return ConfigError::InvalidMaxSequenceDistance;
    if (c.sendRate > c.maxPacketRate)                                 return ConfigError::SendRateExceedsMaxPacketRate;
    if (!std::isfinite(c.congestionGoodRttThreshold)
        || !std::isfinite(c.congestionBadLossThreshold))              return ConfigError::InvalidCongestionThreshold;
    if (c.maxFragments <= 0)                                          return ConfigError::InvalidMaxFragments;
    // A non-positive reassembly timeout expires every partial message on the tick it arrives (elapsed
    // 0 >= timeout 0), so a fragmented message could never complete.
    if (!validPositive(c.fragmentTimeoutMs))                          return ConfigError::InvalidFragmentTimeout;
    if (c.maxReassemblyBufferSize <= 0)                              return ConfigError::InvalidReassemblyBufferSize;
    if (c.maxPending <= 0)                                            return ConfigError::InvalidMaxPending;
    // retryPendingConnections divides the request timeout by (retries + 1) to pace its retries, so a
    // negative count would invert the interval.
    if (c.connectionRequestMaxRetries < 0)                            return ConfigError::InvalidConnectionRequestRetries;
    if (!channelConfigValid(c.defaultChannelConfig))                 return ConfigError::InvalidChannelConfig;
    for (const ChannelConfig& cc : c.channelConfigs)
        if (!channelConfigValid(cc))                                 return ConfigError::InvalidChannelConfig;
    const long maxMsg = maxFragmentableMessage(c);   // a message must fit maxFragmentCount fragments at this MTU, else channelSend would accept it and the send path drop it
    if (c.defaultChannelConfig.maxMessageSize > maxMsg)              return ConfigError::MessageTooLargeToFragment;
    for (const ChannelConfig& cc : c.channelConfigs)
        if (cc.maxMessageSize > maxMsg)                              return ConfigError::MessageTooLargeToFragment;
    return std::nullopt;
}

} // namespace aether
