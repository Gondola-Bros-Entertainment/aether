// Connect, send one message on reliable ordered channel 0, and verify its echo.
#include "common.hpp"
#include <aether/net.hpp>

#include <cstdio>
#include <optional>
#include <string>
#include <thread>

namespace {

std::optional<aether::Address> parseIpv4(const char* text, std::uint16_t port) {
    std::uint32_t ip = 0;
    const char* p = text;
    for (int octet = 0; octet < 4; ++octet) {
        if (*p < '0' || *p > '9') return std::nullopt;
        unsigned value = 0;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + static_cast<unsigned>(*p++ - '0');
            if (value > 255) return std::nullopt;
        }
        ip = (ip << 8) | value;
        if (octet < 3) {
            if (*p++ != '.') return std::nullopt;
        } else if (*p != '\0') {
            return std::nullopt;
        }
    }
    return aether::addrV4(ip, port);
}

int runEcho(aether::Host& host, const aether::Address& server, const std::string& message) {
    const aether::Bytes payload(message.begin(), message.end());
    const auto start = aether_example::monoNow();
    aether::hostConnect(host, server, start);
    bool sent = false;
    while (aether::elapsedMs(start, aether_example::monoNow()) < 10000.0) {
        const auto now = aether_example::monoNow();
        for (const auto& event : aether::hostTick(host, {}, now)) {
            if (!aether::addrEqual(event.peer.addr, server)) continue;
            if (event.kind == aether::PeerEvent::Connected && !sent) {
                if (const auto error = aether::hostSend(host, server, aether::ChannelId{0}, payload, now)) {
                    std::fprintf(stderr, "echo_client: send rejected (error %d)\n", static_cast<int>(error->kind));
                    return 1;
                }
                sent = true;
            } else if (event.kind == aether::PeerEvent::Message) {
                if (!sent || event.channel != aether::ChannelId{0} || event.data != payload) {
                    std::fprintf(stderr, "echo_client: reply did not match the request\n");
                    return 1;
                }
                std::printf("echo: %s\n", message.c_str());
                aether::hostDisconnect(host, server, now);
                aether::hostTick(host, {}, now); // Send the disconnect before closing the socket.
                return 0;
            } else if (event.kind == aether::PeerEvent::Disconnected) {
                std::fprintf(stderr, "echo_client: disconnected before receiving the echo\n");
                return 1;
            }
        }
        std::this_thread::sleep_for(aether_example::tickInterval);
    }
    std::fprintf(stderr, "echo_client: no echo within 10 seconds\n");
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    const auto port = aether_example::parsePort(argc > 2 ? argv[2] : "7777");
    const auto server = port ? parseIpv4(argc > 1 ? argv[1] : "127.0.0.1", *port) : std::nullopt;
    if (argc > 4 || !server) {
        std::fprintf(stderr, "usage: echo_client [IPv4 [port [message]]]; port must be 1..65535\n");
        return 1;
    }
    const std::string message = argc > 3 ? argv[3] : "hello aether";
    const aether::NetworkConfig config;
    if (message.size() > static_cast<std::size_t>(config.defaultChannelConfig.maxMessageSize)) {
        std::fprintf(stderr, "echo_client: message exceeds the default %d-byte channel limit\n",
                     config.defaultChannelConfig.maxMessageSize);
        return 1;
    }
    auto host = aether::openHost(aether::addrAny(0), config, aether_example::monoNow());
    if (!host) {
        std::fprintf(stderr, "echo_client: could not open a UDP socket\n");
        return 1;
    }
    const int result = runEcho(*host, *server, message);
    aether::closeHost(*host);
    return result;
}
