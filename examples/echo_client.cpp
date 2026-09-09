// Connect, send one message on reliable ordered channel 0, and verify its echo.
#include "credentials.hpp"
#include <aether/net.hpp>

#include <cstdio>
#include <optional>
#include <string>
#include <thread>

namespace {

int runEcho(aether::Host& host, const aether::Address& server, const std::string& message, const aether::ConnectCredential& credential) {
    const aether::Bytes payload(message.begin(), message.end());
    const auto start = aether_example::monoNow();
    if (aether::hostConnectWithToken(host, server, credential, start)) { std::fprintf(stderr, "echo_client: invalid credential or connect state\n"); return 1; }
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
                aether::hostShutdown(host, now);
                return aether_example::reportDiagnostics(host) ? 0 : 1;
            } else if (event.kind == aether::PeerEvent::Disconnected) {
                std::fprintf(stderr, "echo_client: disconnected before receiving the echo\n");
                return 1;
            }
        }
        if (!aether_example::reportDiagnostics(host)) return 1;
        std::this_thread::sleep_for(aether_example::tickInterval);
    }
    std::fprintf(stderr, "echo_client: no echo within 10 seconds\n");
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    const auto port = aether_example::parsePort(argc > 3 ? argv[3] : "7777");
    const auto credential = argc >= 2 ? aether_example::readCredential(argv[1]) : std::nullopt;
    if (argc > 5 || !port || !credential) {
        std::fprintf(stderr, "usage: echo_client CREDENTIAL_FILE [hostname [port [message]]]\n");
        return 1;
    }
    const auto addresses = aether::resolveAddresses(argc > 2 ? argv[2] : "127.0.0.1", *port, aether::AddressFamily::IPv4);
    if (addresses.error) { std::fprintf(stderr, "echo_client: address resolution failed\n"); return 1; }
    const auto& server = addresses.addresses.front();
    const std::string message = argc > 4 ? argv[4] : "hello aether";
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
    const int result = runEcho(*host, server, message, *credential);
    aether::closeHost(*host);
    return result;
}
