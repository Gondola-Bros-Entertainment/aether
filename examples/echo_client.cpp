// aether example: echo client. Connects to an echo_server, sends each line you type on the default
// reliable-ordered channel, and prints what comes back.
//
// stdin blocks, and the network loop must not -- so a reader thread hands typed lines to the tick
// loop through a small locked queue. That game-loop shape (tick every frame, never block on input)
// is the part worth copying into a real app.
#include <aether/net.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

aether::MonoTime monoNow() {
    return aether::MonoTime{ static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) };
}

std::optional<aether::Address> parseIpv4(const char* s, std::uint16_t port) {
    unsigned a{}, b{}, c{}, d{};
    if (std::sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
        return std::nullopt;
    return aether::addrV4(static_cast<std::uint32_t>((a << 24) | (b << 16) | (c << 8) | d), port);
}

constexpr int tickMs = 16;

} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);   // line-buffered even when piped, so echoes show as they land
    const char* ip   = argc > 1 ? argv[1] : "127.0.0.1";
    const auto  port = static_cast<std::uint16_t>(argc > 2 ? std::atoi(argv[2]) : 7777);
    const auto  server = parseIpv4(ip, port);
    if (!server) {
        std::fprintf(stderr, "echo_client: not an IPv4 address: %s\nusage: echo_client [ip] [port]\n", ip);
        return 1;
    }

    auto host = aether::openHost(aether::addrAny(0), aether::NetworkConfig{}, monoNow());
    if (!host) {
        std::fprintf(stderr, "echo_client: could not open a UDP socket\n");
        return 1;
    }
    aether::hostConnect(*host, *server, monoNow());
    std::printf("echo_client: connecting to %s:%u -- type a line to send it\n", ip, port);

    std::mutex               linesMutex;
    std::vector<std::string> typed;
    std::thread reader([&] {
        std::string line;
        while (std::getline(std::cin, line)) {
            const std::lock_guard<std::mutex> lock(linesMutex);
            typed.push_back(std::move(line));
        }
    });
    reader.detach();   // lives until the process exits; the loop below runs until ctrl-c or a disconnect

    bool up = false;
    for (;;) {
        for (const aether::PeerEvent& ev : aether::hostTick(*host, {}, monoNow())) {
            switch (ev.kind) {
                case aether::PeerEvent::Connected:
                    up = true;
                    std::printf("connected\n");
                    break;
                case aether::PeerEvent::Disconnected:
                    // Also how a failed connect reports itself (nothing listening -> timeout).
                    std::printf("disconnected\n");
                    return 0;
                case aether::PeerEvent::Message:
                    std::printf("echo: %.*s\n", static_cast<int>(ev.data.size()),
                                reinterpret_cast<const char*>(ev.data.data()));
                    break;
                default:
                    break;
            }
        }
        if (up) {
            std::vector<std::string> pending;
            {
                const std::lock_guard<std::mutex> lock(linesMutex);
                pending.swap(typed);
            }
            for (const std::string& line : pending)
                aether::hostSend(*host, *server, aether::ChannelId{ 0 },
                                 aether::Bytes(line.begin(), line.end()), monoNow());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(tickMs));
    }
}
