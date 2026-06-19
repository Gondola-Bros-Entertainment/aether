# aether

[![ci](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Reliable UDP netcode for games. C++20, header-only, zero dependencies.

The headline: define a plain struct, and aether sends only the fields that changed since the
last snapshot -- an automatic delta, computed by reflection. No macros, no codegen, no
annotations.

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

When you want to squeeze the wire further, the serializer has an optional bit-packing layer:
wrap a field in `Ranged<Lo, Hi>` or `Quantized<Lo, Hi, Bits>` and it costs exactly the bits its
range needs. Never required.

## Build

```sh
cmake -B build
cmake --build build
ctest --test-dir build
```

Needs a C++20 compiler (clang or gcc). Sockets are POSIX; a Windows port touches only
`src/socket.cpp`.

## Use

```cpp
#include <aether/net.hpp>

aether::NetworkConfig cfg;
auto host = aether::openHost(aether::addrAny(9000), cfg, now);   // bind a server on :9000
for (const auto& ev : aether::hostTick(*host, outgoing, now)) {
    // ev.kind: Connected / Disconnected / Message / Migrated
}
```

## Status

The netcode stack is complete and hardened. Reliable delivery is exercised under heavy simulated
packet loss -- a message that must arrive does, by retransmit -- and the encryption is verified
against the RFC 8439 vectors. CI is a staged pipeline: static analysis, then ASan/UBSan, then a
build matrix across gcc and clang on Linux and macOS, all warning-clean under -Werror. Planned
next: serializer benchmarks against other libraries, a Windows (Winsock) build, and NAT
punch-through.

## License

MIT. See [LICENSE](LICENSE).
