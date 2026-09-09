// Bind a UDP port and echo messages on their original channels until interrupted.
#include "credentials.hpp"
#include <aether/net.hpp>

#include <csignal>
#include <cstdio>
#include <thread>

namespace {
volatile std::sig_atomic_t stopping = 0;
void requestStop(int) { stopping = 1; }
} // namespace

int main(int argc, char** argv) {
    const auto port = aether_example::parsePort(argc > 2 ? argv[2] : "7777");
    const auto key = argc >= 2 ? aether_example::readServerKey(argv[1]) : std::nullopt;
    if (argc > 3 || !port || !key) {
        std::fprintf(stderr, "usage: echo_server SERVER_KEY_FILE [port]\n");
        return 1;
    }
    aether::NetworkConfig config;
    config.tokenKey = *key;
    config.tokenAudience = aether_example::echoAudience;
    auto host = aether::openHost(aether::addrAny(*port), config, aether_example::monoNow());
    if (!host) {
        std::fprintf(stderr, "echo_server: could not bind UDP port %u\n", static_cast<unsigned>(*port));
        return 1;
    }
    std::signal(SIGINT, requestStop);
    std::signal(SIGTERM, requestStop);
    std::printf("echo_server: listening on %u\n", static_cast<unsigned>(*port));
    std::fflush(stdout);

    while (!stopping) {
        const auto now = aether_example::monoNow();
        for (const auto& event : aether::hostTick(*host, {}, now)) {
            if (event.kind == aether::PeerEvent::Connected) {
                std::printf("+ peer connected (port %u)\n", static_cast<unsigned>(aether::addrPort(event.peer.addr)));
            } else if (event.kind == aether::PeerEvent::Disconnected) {
                std::printf("- peer disconnected (port %u)\n", static_cast<unsigned>(aether::addrPort(event.peer.addr)));
            } else if (event.kind == aether::PeerEvent::Message) {
                if (const auto error = aether::hostSend(*host, event.peer.addr, event.channel, event.data, now)) {
                    std::fprintf(stderr, "echo_server: cannot queue echo (error %d), disconnecting peer\n",
                                 static_cast<int>(error->kind));
                    aether::hostDisconnect(*host, event.peer.addr, now);
                }
            }
        }
        if (!aether_example::reportDiagnostics(*host)) { aether::closeHost(*host); return 1; }
        std::fflush(stdout);
        std::this_thread::sleep_for(aether_example::tickInterval);
    }
    aether::hostShutdown(*host, aether_example::monoNow());
    const bool ok = aether_example::reportDiagnostics(*host);
    aether::closeHost(*host);
    return ok ? 0 : 1;
}
