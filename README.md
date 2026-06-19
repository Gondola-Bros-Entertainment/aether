# aether

[![ci](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Reliable UDP netcode for games. C++20, header-only, zero dependencies.

Define a plain struct, and aether sends only the fields that changed since the last snapshot:
an automatic delta, computed by reflection. No macros, no codegen, no annotations.

```cpp
struct PlayerState {
    float x, y, z;
    float yaw;
    int   health;
    bool  firing;
};

std::uint8_t buf[256];
aether::Writer w{ buf, sizeof buf };
aether::deltaPack(w, prev, current);          // only the changed fields hit the wire

aether::Reader r{ buf, w.pos };
auto restored = aether::deltaUnpack(r, prev); // std::optional<PlayerState>; unchanged fields carried from prev
```

On top of that delta core, aether is a full reliable-UDP stack:

- reliable, unreliable, ordered, and sequenced channels
- sequence/ack reliability with RTT/RTO estimation and fast retransmit
- fragmentation and reassembly for messages larger than the MTU
- congestion control: a binary AIMD controller plus a TCP New Reno window
- ChaCha20-Poly1305 packet encryption, written from scratch and checked against the RFC 8439 test vectors
- a connection handshake with connect tokens and per-source rate limiting
- snapshot replication: delta, interest management, priority, and interpolation
- a deterministic in-memory network for fast, reproducible tests

## Design

Data-first: plain structs and free functions, no inheritance or virtuals. State is mutated in
place. One focused header per module under `include/aether/` -- include what you use, or pull
the whole library with `<aether/aether.hpp>`. The only translation unit is the platform socket
layer (`src/socket.cpp`); everything else is header-only.

## Build

```sh
cmake -B build
cmake --build build
ctest --test-dir build
```

Needs a C++20 compiler -- clang, gcc, or MSVC. The socket layer is the one platform file, split
`src/socket_posix.cpp` (BSD sockets) / `src/socket_win.cpp` (Winsock); CMake picks one. CI builds
and tests on all three compilers across Linux, macOS, and Windows.

## Getting started

A `Host` is a socket plus its peers -- the same type is client or server. Bind it, then pump one
step per frame: `hostTick` drains incoming datagrams, sends what you queued, and returns the
events that happened.

```cpp
#include <aether/net.hpp>

aether::NetworkConfig cfg;

// server: bind a port, tick each frame
auto server = aether::openHost(aether::addrAny(9000), cfg, now);
std::vector<std::pair<aether::ChannelId, aether::Bytes>> broadcast;
for (const aether::PeerEvent& ev : aether::hostTick(*server, broadcast, now)) {
    switch (ev.kind) {
        case aether::PeerEvent::Connected:    break;   // ev.peer joined
        case aether::PeerEvent::Message:      break;   // ev.data arrived on ev.channel
        case aether::PeerEvent::Disconnected: break;
        case aether::PeerEvent::Migrated:     break;   // ev.peer rebound to ev.other (NAT)
    }
}

// client: connect, then send to a peer on a channel
auto client = aether::openHost(aether::addrLocalhost(0), cfg, now);
aether::hostConnect(*client, serverAddr, now);
aether::hostSend(*client, serverAddr, aether::ChannelId{ 0 }, payload, now);
```

Each channel picks its own guarantee -- reliable-ordered, reliable-unordered, reliable-sequenced,
unreliable, or unreliable-sequenced -- so one packet stream carries mixed delivery semantics.

## Squeezing the wire

Optional: when you know a field's range, wrap it and it costs exactly the bits the range needs.

```cpp
struct Input {
    aether::Ranged<int, 0, 1023>       move;     // 10 bits, not 32
    aether::Quantized<-1.0f, 1.0f, 12> aimYaw;   // 12 bits, not a 32-bit float
    bool                               firing;   // 1 bit
};

aether::BitWriter bw{ buf, sizeof buf };
aether::packBits(bw, input);                      // 23 bits -> 3 bytes on the wire
```

## Wire size

On a 12-field snapshot with two fields changed, aether writes 8 bytes; zpp::bits writes 40. The
diff costs a few nanoseconds of CPU; on a bandwidth-bound network, fewer bytes on the wire is the
trade that matters. Reproduce:

```sh
cmake -B build -DAETHER_BENCH_COMPARE=ON
cmake --build build --target aether_bench_compare && ./build/aether_bench_compare
```

## Status

The netcode stack is complete and hardened. Reliable delivery is exercised under heavy simulated
packet loss -- a message that must arrive does, by retransmit -- and the encryption is verified
against the RFC 8439 vectors. CI is a staged pipeline: static analysis, then ASan/UBSan, then a
build-and-test matrix across gcc, clang, and MSVC on Linux, macOS, and Windows, all warning-clean
under -Werror. Planned next: NAT punch-through.

## License

MIT. See [LICENSE](LICENSE).
