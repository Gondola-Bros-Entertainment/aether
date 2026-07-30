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

- reliable, unreliable, ordered, and sequenced channels -- mixed delivery on one packet stream. Every
  mode delivers a message at most once: a retransmit whose ack was lost, or a datagram the network
  duplicated, is recognized and dropped rather than handed to the app twice
- a reliable channel does not lose data to its own buffers. Nothing is acknowledged until the receiving
  channel has taken it, so a full reorder or receive buffer turns into backpressure the sender feels --
  it retransmits, and `channelSend` reports `BufferFull` -- instead of a message the sender believes
  arrived. The per-channel counters keep those apart: dropped (gone), duplicate (already had it), and
  refused (backpressure, coming back)
- sequence/ack reliability with RTT/RTO estimation and fast retransmit
- packet coalescing -- many small messages ride a single datagram (one header, one auth tag)
- fragmentation and reassembly for messages larger than the MTU, with selective retransmit (a lost
  fragment costs one fragment, not the whole message) and paced emission (a large message spreads
  across ticks at the send rate instead of needing a burst that fits it whole)
- congestion control: a binary AIMD controller plus a TCP New Reno window
- path-MTU discovery -- probe-based (RFC 8899 style, never ICMP), raising the usable datagram size
  above the 1200 floor when the path carries more, with an immediate fallback if it stops
- encrypted by default -- an X25519 handshake derives per-direction ChaCha20-Poly1305 keys (no
  pre-shared secret); the packet header is authenticated and replays are windowed. Both primitives
  are from scratch, checked against the RFC 7748 / 8439 vectors
- a challenge/response handshake with per-source rate limiting and an OS CSPRNG for all key material.
  The client echoes the server's challenge salt, so a source-spoofing peer that never received the
  challenge cannot make the server commit a keypair or a connection slot to an address it cannot reach
- optional connect-token authentication -- your backend seals a token after a login and the server
  verifies it during the handshake (provider-agnostic: Firebase, Steam, OIDC, custom), so connections
  are gated, a verified playerId arrives on the Connected event, and spoofed-source floods are
  shielded before any keygen
- reconnect -- a dropped session resumes via a token without a full re-handshake, carrying the
  verified playerId across the resume (Reconnected event)
- migration -- a live connection follows a peer across an IP change (NAT rebind)
- NAT traversal -- a rendezvous pairs two peers behind NATs and they hole-punch a direct path, with
  a relay fallback through the rendezvous when the punch fails (symmetric NATs)
- clock-offset sync -- a built-in ping/pong estimates the peer's clock for a shared timeline
- snapshot replication: delta, interest management, priority, and interpolation
- a deterministic in-memory network (`testnet.hpp`) -- run two real peers against each other with
  configurable loss, latency, jitter, duplication and reordering, reproducible from a fixed seed and with
  no sockets. aether's own tests drive it, so your CI can test your netcode the same way

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

The build includes a runnable echo pair (`examples/`) -- start the server, then type lines at it
through the client and watch them come back over an encrypted reliable channel:

```sh
./build/aether_echo_server            # terminal 1: listens on 7777
./build/aether_echo_client            # terminal 2: connects to 127.0.0.1:7777
```

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

On a 12-field snapshot with two fields changed, aether writes 8 bytes; zpp::bits and bitsery both
write 40. The diff costs a few nanoseconds of CPU; on a bandwidth-bound network, fewer bytes on
the wire is the trade that matters. Past 16 fields the changemask itself adapts -- few changes are
sent as sparse indices instead of a full bitmap, so one changed field in a 32-field struct costs a
2-byte mask, not 4. Reproduce:

```sh
cmake -B build -DAETHER_BENCH_COMPARE=ON
cmake --build build --target aether_bench_compare && ./build/aether_bench_compare
```

## Testing

Reliable delivery and large-message fragmentation are exercised under heavy simulated packet loss -- a
message that must arrive does, by retransmit, and a fragmented one reassembles only once every fragment
lands. The handshake completes through 30% loss with latency, jitter, duplication and reordering all
applied at once. Reliability is also tested against the receiver's own limits: a run of messages that
overruns the reorder buffer behind a lost packet still arrives in full. Every decoder is fuzzed against random and truncated input, and each bit-packed field's
range is asserted to hold on hostile bytes, not just on bytes aether wrote. The serializer is
property-tested over arbitrary values, floats compared bit-exactly. All of it runs under ASan/UBSan.

CI is staged -- static analysis, then ASan/UBSan, then a build-and-test matrix across gcc, clang, and
MSVC on Linux, macOS, and Windows, warning-clean under -Werror, plus a job that installs the package and
builds a consumer against it.

Every configuration field is read by the library: there is no knob that validates and then tunes nothing.

## Trade-offs

Things worth knowing before you build on it. These are deliberate, not oversights.

- The X25519 handshake is unauthenticated, so it resists eavesdropping but not an active
  man-in-the-middle. Connect tokens add identity, access control and a DoS gate, but a token is a bearer
  credential. Full MITM resistance needs a keys-in-token model, which costs ephemeral keys and forward
  secrecy -- not a trade this library makes.
- `maxMessageSize` is bounded by the fragment count: a message must fit 255 fragments (~295KB at a
  1200 MTU), checked at `validateConfig` rather than at send. A message larger than one send-rate
  bucket is paced -- its fragments spread across as many ticks as the budget needs -- so big messages
  cost latency, never a config rejection.
- A reliable-ordered channel's ordering guarantee is bounded by `orderedBufferTimeout`. If a gap never
  fills, the channel eventually delivers what is behind it and moves on rather than stalling forever, and
  the skipped sequences are then a permanent hole.
- Backpressure is implicit: a receiver that cannot buffer withholds the ack and the sender retransmits. An
  app that stops draining entirely will eventually cost a message once the sender exhausts its retries
  (reported, not silent). See issue #3.
- `config.mtu` (default 1200) is the floor everything is sized against; probe-based path-MTU
  discovery (RFC 8899 style, never ICMP) then raises the usable datagram size up to
  `mtuProbeCeiling` (default 1500). The headroom feeds message coalescing only -- fragmentation
  stays chunked at the floor, so a path that shrinks back can never strand a fragmented message.
  Near-total loss above the floor collapses back to it immediately.
- `net.hpp` drains the socket non-blocking once per tick; there is no dedicated receive thread.
- The serializer reflects `std::array`, `string`, `vector`, `optional` and nested aggregates. Raw C-array
  members are not auto-reflected (a C++20 limitation) -- use `std::array<T,N>`; misuse is a clear
  `static_assert`, not silent breakage.

Roadmap and known work live in [issues](https://github.com/Gondola-Bros-Entertainment/aether/issues).

## License

MIT. See [LICENSE](LICENSE).

Built by Devon Tomlin (Novavero AI Inc.).
