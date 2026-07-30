// aether example: echo server. Binds a UDP port, accepts connections, and echoes every message
// straight back to its sender. Talk to it with echo_client.
//
// This is the whole consumer shape: openHost once, then hostTick every frame and act on the events
// it returns. Time is caller-provided -- aether never reads a clock -- so a game passes its frame
// clock; here it is the steady clock. The default config gives an encrypted connection and a
// reliable-ordered channel 0 with nothing else to set up.
#include <aether/net.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace {

aether::MonoTime monoNow() {
    return aether::MonoTime{ static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) };
}

constexpr int tickMs = 16;   // ~60Hz -- the tick rate is the app's choice, not the library's

} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);   // line-buffered even when piped, so activity shows as it happens
    const auto port = static_cast<std::uint16_t>(argc > 1 ? std::atoi(argv[1]) : 7777);

    auto host = aether::openHost(aether::addrAny(port), aether::NetworkConfig{}, monoNow());
    if (!host) {
        std::fprintf(stderr, "echo_server: could not bind UDP port %u\n", port);
        return 1;
    }
    std::printf("echo_server: listening on %u\n", port);

    for (;;) {
        for (const aether::PeerEvent& ev : aether::hostTick(*host, {}, monoNow())) {
            switch (ev.kind) {
                case aether::PeerEvent::Connected:
                    std::printf("+ peer connected (port %u)\n", aether::addrPort(ev.peer.addr));
                    break;
                case aether::PeerEvent::Disconnected:
                    std::printf("- peer disconnected (port %u)\n", aether::addrPort(ev.peer.addr));
                    break;
                case aether::PeerEvent::Message:
                    std::printf("> %u bytes from port %u, echoing\n",
                                static_cast<unsigned>(ev.data.size()), aether::addrPort(ev.peer.addr));
                    aether::hostSend(*host, ev.peer.addr, ev.channel, ev.data, monoNow());
                    break;
                default:   // Migrated / Reconnected: nothing extra to do for an echo
                    break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(tickMs));
    }
}
