#include "check.hpp"
#include <aether/config.hpp>
#include <array>
#include <limits>

int main() {
    using namespace aether;
    using aether::test::require;
    require(!validateConfig(NetworkConfig{}));
    constexpr std::array timers{&NetworkConfig::connectionTimeoutMs,
        &NetworkConfig::keepaliveIntervalMs, &NetworkConfig::connectionRequestTimeoutMs,
        &NetworkConfig::disconnectRetryTimeoutMs, &NetworkConfig::congestionRecoveryTimeMs};
    constexpr std::array invalid{0.0, -1.0, std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity(), std::numeric_limits<double>::quiet_NaN()};
    for (const auto timer : timers) for (const auto value : invalid) {
        NetworkConfig cfg;
        cfg.*timer = value;
        require(validateConfig(cfg) == ConfigError::InvalidTimeout);
    }
    for (const auto value : invalid) {
        NetworkConfig cfg;
        cfg.sendRate = value;
        require(validateConfig(cfg) == ConfigError::InvalidSendRate);
        cfg = {}; cfg.maxPacketRate = value;
        require(validateConfig(cfg) == ConfigError::InvalidMaxPacketRate);
        cfg = {}; cfg.fragmentTimeoutMs = value;
        require(validateConfig(cfg) == ConfigError::InvalidFragmentTimeout);
    }
    NetworkConfig cfg;
    cfg.connectionRequestMaxRetries = std::numeric_limits<int>::max();
    require(validateConfig(cfg) == ConfigError::InvalidConnectionRequestRetries);
    cfg = {}; cfg.connectionRequestMaxRetries = 0;
    require(!validateConfig(cfg));
    cfg.rateLimitPerSecond = 0;
    require(validateConfig(cfg) == ConfigError::InvalidRateLimit);
    cfg = {}; cfg.disconnectRetries = -1;
    require(validateConfig(cfg) == ConfigError::InvalidDisconnectRetries);
    cfg = {}; cfg.congestionBadLossThreshold = 1.01;
    require(validateConfig(cfg) == ConfigError::InvalidCongestionThreshold);
    cfg = {}; cfg.congestionGoodRttThreshold = -1;
    require(validateConfig(cfg) == ConfigError::InvalidCongestionThreshold);
    cfg = {}; cfg.mtu = cfg.mtuProbeCeiling = 65535;
    require(validateConfig(cfg) == ConfigError::InvalidMtu);
    cfg.mtu = cfg.mtuProbeCeiling = maxMtu;
    require(!validateConfig(cfg));
    cfg = {}; cfg.defaultChannelConfig.deliveryMode = static_cast<DeliveryMode>(99);
    require(validateConfig(cfg) == ConfigError::InvalidChannelConfig);
    cfg = {}; cfg.defaultChannelConfig.maxReliableRetries = std::numeric_limits<int>::max();
    require(validateConfig(cfg) == ConfigError::InvalidChannelConfig);
    cfg = {}; cfg.maxResumableSessions = -1;
    require(validateConfig(cfg) == ConfigError::InvalidMaxResumableSessions);
    cfg = {}; cfg.tokenKey = EncryptionKey{};
    require(validateConfig(cfg) == ConfigError::InvalidTokenScope);
    cfg.tokenAudience = 42;
    require(validateConfig(cfg) == ConfigError::InvalidTokenKey);
    cfg.tokenKey->front() = 1;
    require(!validateConfig(cfg));
}
