# aether

[![ci](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Reliable, encrypted UDP netcode for games. C++20, header-only, zero dependencies.

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

- reliable, unreliable, ordered, and sequenced channels -- mixed delivery on one packet stream
- sequence/ack reliability with RTT/RTO estimation and fast retransmit
- packet coalescing -- many small messages ride a single datagram (one header, one auth tag)
- fragmentation and reassembly for messages larger than the MTU
- congestion control: a binary AIMD controller plus a TCP New Reno window
- encrypted by default -- an X25519 handshake derives per-direction ChaCha20-Poly1305 keys (no
  pre-shared secret); the packet header is authenticated and replays are windowed. Both primitives
  are from scratch, checked against the RFC 7748 / 8439 vectors
- a challenge/response handshake with per-source rate limiting and an OS CSPRNG for all key material
- optional connect-token authentication -- your backend seals a token after a login and the server
  verifies it during the handshake (provider-agnostic: Firebase, Steam, OIDC, custom), so connections
  are gated, a verified playerId arrives on the Connected event, and spoofed-source floods are
  shielded before any keygen
- reconnect -- a dropped session resumes via a token without a full re-handshake (Reconnected event)
- migration -- a live connection follows a peer across an IP change (NAT rebind)
- NAT traversal -- a rendezvous pairs two peers behind NATs and they hole-punch a direct path, with
  a relay fallback through the rendezvous when the punch fails (symmetric NATs)
- clock-offset sync -- a built-in ping/pong estimates the peer's clock for a shared timeline
- snapshot replication: delta, interest management, priority, and interpolation
- a deterministic in-memory network for fast, reproducible tests

## Design

Data-first: plain structs and free functions, no inheritance or virtuals. State is mutated in
place. One focused header per module under `include/aether/` -- include what you use, or pull
the whole library with `<aether/aether.hpp>`. The only translation units are the platform layer
(`src/socket_posix.cpp` / `src/socket_win.cpp`); everything else is header-only.

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
        case aether::PeerEvent::Reconnected:  break;   // ev.peer resumed a dropped session
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

Two peers behind NATs don't need each other's address: they join a shared room on a rendezvous
server, and aether establishes the link -- hole-punching a direct path, or relaying through the
rendezvous if the punch fails.

```cpp
aether::hostJoinRoom(host, rendezvousAddr, roomId, now);   // paired by room, then punched or relayed
```

## Authentication

Gate connections behind a signed token from your own auth backend -- Firebase, Steam, OIDC, anything.
Your backend holds a secret key `K` shared with the game servers, seals a token after a login, and
the server verifies it during the handshake. aether never talks to the provider, so it works with any
of them; the provider only ever touches your backend's seal step.

```cpp
// your backend, after the player logs in (Firebase/Steam/...), holding the shared key K:
aether::Bytes token = aether::sealConnectToken(K, aether::ConnectToken{ playerId, expiresAt, userData });
//                    ...hand the token bytes to the client over HTTPS...

// server: require a token by setting the key; the verified playerId arrives on Connected
cfg.tokenKey = K;   // open the server host with this config; ev.playerId is the authenticated id

// client: present the token your backend gave you
aether::hostConnectWithToken(*client, serverAddr, token, now);
```

The server validates the token *before* any keygen, so it also shields the handshake from
spoofed-source floods. A token is single-use (replay-protected); mint a fresh one per connect.

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

## Testing

Reliable delivery and large-message fragmentation are exercised under heavy simulated packet loss --
a message that must arrive does, by retransmit, and a fragmented one reassembles only once every
fragment lands. Every decoder is fuzzed against random and truncated input, and the serializer is
property-tested over arbitrary values, both under ASan/UBSan. CI is staged -- static analysis, then
ASan/UBSan, then a build-and-test matrix across gcc, clang, and MSVC on Linux, macOS, and Windows,
warning-clean under -Werror.

## License

MIT. See [LICENSE](LICENSE).

Built by Devon Tomlin (Novavero AI Inc.).
