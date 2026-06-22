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
inline constexpr int           defaultFragmentThreshold            = 1024;
inline constexpr double         defaultFragmentTimeoutMs           = 5000.0;
inline constexpr int           defaultMaxFragments                 = 256;
inline constexpr int           defaultMaxReassemblyBufferSize      = 1024 * 1024;
inline constexpr int           defaultPacketBufferSize             = 256;
inline constexpr int           defaultAckBufferSize                = 256;
inline constexpr double         defaultReliableRetryTimeMs         = 100.0;
inline constexpr int           defaultMaxReliableRetries           = 10;
inline constexpr int           defaultMaxChannels                  = 8;
inline constexpr double         defaultSendRateHz                  = 60.0;
inline constexpr double         defaultMaxPacketRateHz             = 120.0;
inline constexpr double         defaultCongestionThreshold         = 0.1;
inline constexpr double         defaultCongestionGoodRttThresholdMs = 250.0;
inline constexpr double         defaultCongestionBadLossThreshold  = 0.1;
inline constexpr double         defaultCongestionRecoveryTimeMs    = 10000.0;
inline constexpr int           defaultDisconnectRetries            = 3;
inline constexpr double         defaultDisconnectRetryTimeoutMs    = 500.0;
inline constexpr std::uint8_t  defaultChannelPriority              = 128;
inline constexpr int           maxBackoffExponent                  = 5;
inline constexpr int           minMtu                              = 576;
inline constexpr int           maxMtu                              = 65535;
inline constexpr int           maxChannelCount                     = 8;
inline constexpr int           defaultMaxPending                   = 256;
inline constexpr int           defaultRateLimitPerSecond           = 10;
inline constexpr int           smallReliableThreshold              = 64;
inline constexpr double         defaultDeltaBaselineTimeoutMs      = 2000.0;
inline constexpr int           defaultMaxBaselineSnapshots         = 32;

// --- wire sizing (single source; used to size fragments AND to validate maxMessageSize) ---
inline constexpr int channelWireSeqBytes = 2;   // [seqHi][seqLo] prefix on a channel message's inner wire
inline constexpr int packetWireOverhead  = static_cast<int>(packetHeaderBytes) + encryptionOverhead + crc32Size;   // header + AEAD + CRC per datagram

// Network condition simulation (off by default).
struct SimulationConfig {
    double packetLoss               = 0.0;
    int    latencyMs                = 0;
    int    jitterMs                 = 0;
    double duplicateChance          = 0.0;
    double outOfOrderChance         = 0.0;
    int    bandwidthLimitBytesPerSec = 0;
};

// Top-level network configuration. NetworkConfig{} is the default config.
struct NetworkConfig {
    std::uint32_t protocolId                  = defaultProtocolId;
    int           maxClients                  = defaultMaxClients;
    double        connectionTimeoutMs         = defaultConnectionTimeoutMs;
    double        keepaliveIntervalMs         = defaultKeepaliveIntervalMs;
    double        connectionRequestTimeoutMs  = defaultConnectionRequestTimeoutMs;
    int           connectionRequestMaxRetries = defaultConnectionRequestMaxRetries;
    int           mtu                         = defaultMtu;
    int           fragmentThreshold           = defaultFragmentThreshold;
    double        fragmentTimeoutMs           = defaultFragmentTimeoutMs;
    int           maxFragments                = defaultMaxFragments;
    int           maxReassemblyBufferSize     = defaultMaxReassemblyBufferSize;
    int           packetBufferSize            = defaultPacketBufferSize;
    int           ackBufferSize               = defaultAckBufferSize;
    std::uint16_t maxSequenceDistance         = defaultMaxSequenceDistance;
    double        reliableRetryTimeMs         = defaultReliableRetryTimeMs;
    int           maxReliableRetries          = defaultMaxReliableRetries;
    int           maxInFlight                 = defaultMaxInFlight;
    int           maxChannels                 = defaultMaxChannels;
    ChannelConfig defaultChannelConfig        = ChannelConfig{};
    std::vector<ChannelConfig> channelConfigs;
    double        sendRate                    = defaultSendRateHz;
    double        maxPacketRate               = defaultMaxPacketRateHz;
    double        congestionThreshold         = defaultCongestionThreshold;
    double        congestionGoodRttThreshold  = defaultCongestionGoodRttThresholdMs;
    double        congestionBadLossThreshold  = defaultCongestionBadLossThreshold;
    double        congestionRecoveryTimeMs    = defaultCongestionRecoveryTimeMs;
    int           disconnectRetries           = defaultDisconnectRetries;
    double        disconnectRetryTimeoutMs    = defaultDisconnectRetryTimeoutMs;
    int           maxPending                  = defaultMaxPending;   // cap on concurrent half-open (in-handshake) connections; distinct from maxClients (established)
    int           rateLimitPerSecond          = defaultRateLimitPerSecond;
    bool          useCwndCongestion           = false;
    std::optional<SimulationConfig> simulation;
    bool          enableConnectionMigration   = true;
    double        deltaBaselineTimeoutMs      = defaultDeltaBaselineTimeoutMs;
    int           maxBaselineSnapshots        = defaultMaxBaselineSnapshots;
    std::optional<EncryptionKey> tokenKey;   // server: the connect-token sealing key K; if set, a valid token is required to connect
};

enum class ConfigError {
    FragmentThresholdExceedsMtu,
    InvalidChannelCount,
    InvalidPacketBufferSize,
    InvalidMtu,
    TimeoutNotGreaterThanKeepalive,
    InvalidMaxClients,
    ChannelConfigsExceedMaxChannels,
    InvalidSendRate,
    InvalidMaxPacketRate,
    InvalidMaxInFlight,
    InvalidFragmentThreshold,
    SendRateExceedsMaxPacketRate,
    InvalidCongestionThreshold,
    InvalidMaxFragments,
    InvalidReassemblyBufferSize,
    InvalidReplicationCaps,
    InvalidChannelConfig,
    MessageTooLargeToFragment,
};

// MTU-derived sizing. effectivePayloadBudget = the channel-message payload that fits one datagram;
// maxFragmentChunk = the largest fragment data chunk (a fragment wire is [channel byte][fragment
// header][chunk]); maxFragmentableMessage = the largest message that still fits maxFragmentCount
// fragments. validateConfig rejects a maxMessageSize above the last, so a message is never accepted
// by channelSend and then dropped at fragmentation. connection.hpp fragments against these.
inline int  effectivePayloadBudget(const NetworkConfig& c) noexcept { return c.mtu - packetWireOverhead; }
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
    if (c.fragmentThreshold > c.mtu)                                  return ConfigError::FragmentThresholdExceedsMtu;
    if (c.maxChannels <= 0 || c.maxChannels > maxChannelCount)        return ConfigError::InvalidChannelCount;
    if (c.packetBufferSize <= 0)                                      return ConfigError::InvalidPacketBufferSize;
    if (c.mtu < minMtu || c.mtu > maxMtu)                             return ConfigError::InvalidMtu;
    if (c.connectionTimeoutMs <= c.keepaliveIntervalMs)              return ConfigError::TimeoutNotGreaterThanKeepalive;
    if (c.maxClients <= 0)                                            return ConfigError::InvalidMaxClients;
    if (static_cast<int>(c.channelConfigs.size()) > c.maxChannels)    return ConfigError::ChannelConfigsExceedMaxChannels;
    if (!validPositive(c.sendRate))                                   return ConfigError::InvalidSendRate;
    if (!validPositive(c.maxPacketRate))                              return ConfigError::InvalidMaxPacketRate;
    if (c.maxInFlight <= 0)                                           return ConfigError::InvalidMaxInFlight;
    if (c.fragmentThreshold <= 0)                                     return ConfigError::InvalidFragmentThreshold;
    if (c.sendRate > c.maxPacketRate)                                 return ConfigError::SendRateExceedsMaxPacketRate;
    if (!std::isfinite(c.congestionGoodRttThreshold) || !std::isfinite(c.congestionBadLossThreshold)
        || !std::isfinite(c.congestionThreshold))                    return ConfigError::InvalidCongestionThreshold;
    if (c.maxFragments <= 0)                                          return ConfigError::InvalidMaxFragments;
    if (c.maxReassemblyBufferSize <= 0)                              return ConfigError::InvalidReassemblyBufferSize;
    if (c.maxPending <= 0 || c.maxBaselineSnapshots <= 0)            return ConfigError::InvalidReplicationCaps;
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
