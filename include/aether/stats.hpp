// aether - connection health statistics. Plain structs of
// counters; free functions derive connection quality from RTT and loss. Defaults live in the
// member initializers, so NetworkStats{} is the "default" set of values.
#pragma once

#include <cstdint>

namespace aether {

// Connection quality, best to worst (ordered by enum value).
enum class ConnectionQuality { Excellent, Good, Fair, Poor, Bad };

// Assess connection quality from smoothed RTT (ms) and packet loss (percent).
inline ConnectionQuality assessConnectionQuality(double rttMs, double lossPercent) noexcept {
    if (lossPercent > 10.0 || rttMs > 500.0) return ConnectionQuality::Bad;
    if (lossPercent > 5.0  || rttMs > 250.0) return ConnectionQuality::Poor;
    if (lossPercent > 2.0  || rttMs > 150.0) return ConnectionQuality::Fair;
    if (lossPercent > 0.5  || rttMs > 80.0)  return ConnectionQuality::Good;
    return ConnectionQuality::Excellent;
}

// Congestion pressure reported to the application so it can adapt its send behaviour:
// None -> send freely, Elevated -> trim non-essentials, High -> drop low priority,
// Critical -> sends are being suppressed, only essential data gets through.
enum class CongestionLevel { None, Elevated, High, Critical };

// Per-connection network statistics.
struct NetworkStats {
    std::uint64_t     packetsSent        = 0;
    std::uint64_t     packetsReceived    = 0;
    std::uint64_t     bytesSent          = 0;
    std::uint64_t     bytesReceived      = 0;
    double            rtt                = 0.0;
    double            packetLoss         = 0.0;
    double            bandwidthUp        = 0.0;
    double            bandwidthDown      = 0.0;
    ConnectionQuality connectionQuality  = ConnectionQuality::Excellent;
    CongestionLevel   congestionLevel    = CongestionLevel::None;
    std::uint64_t     decryptionFailures = 0;
};

} // namespace aether
