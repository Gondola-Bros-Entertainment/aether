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

On top of that delta core, aether is a full reliable-UDP stack.

**Channels.** Reliable, unreliable, ordered, and sequenced channels share one packet stream, so a
single connection carries mixed delivery semantics. Every mode delivers a message at most once: a
retransmit whose ack was lost, or a datagram the network duplicated, is recognized and dropped
rather than handed to the application twice.

**Backpressure that does not lose data.** Nothing is acknowledged until the receiving channel has
taken it. A full reorder or receive buffer therefore becomes backpressure the sender feels: it
retransmits, and `channelSend` reports `BufferFull`. The per-channel counters keep the three cases
apart, because they mean different things to an application: dropped (the data is gone), duplicate
(already delivered, harmless), and refused (backpressure, coming back).

**Reliability.** Sequence and ack-bitfield tracking with Jacobson/Karels RTT and RTO estimation,
plus fast retransmit on a triple NACK.

**Coalescing and fragmentation.** Many small messages ride a single datagram under one header and
one auth tag. Messages larger than the MTU are fragmented and reassembled, with selective
retransmit so a lost fragment costs one fragment rather than the whole message. A large message is
paced: its fragments spread across as many ticks as the send budget needs, instead of requiring a
burst that fits it whole.

**Congestion control.** A binary AIMD rate controller, and optionally a TCP New Reno window
(`useCwndCongestion`).

**Path-MTU discovery.** Probe-based, in the style of RFC 8899, and never dependent on ICMP. It
raises the usable datagram size above the 1200-byte floor when the path carries more, and falls
back immediately when the path stops carrying it.

**Encrypted by default.** An X25519 handshake derives per-direction ChaCha20-Poly1305 keys with no
pre-shared secret. The packet header is authenticated as associated data, and replays are rejected
by a sliding window. Both primitives are written from scratch and checked against the RFC 7748 and
RFC 8439 test vectors.

**Handshake.** A challenge/response exchange with per-source rate limiting, keyed entirely from the
OS CSPRNG. The client echoes the server's challenge salt, so a peer spoofing its source address
never receives the challenge and cannot complete a handshake or make the server allocate a
connection.

**Connect tokens (optional).** Your backend seals a token after a login and the server verifies it
during the handshake. This is provider-agnostic, so Firebase, Steam, OIDC or a custom system all
work: connections are gated, a verified `playerId` arrives on the Connected event, and spoofed
floods are turned away before any key generation.

**Reconnect and migration.** A dropped session resumes from a token without a full re-handshake,
carrying the verified `playerId` across the resume (a Reconnected event). A live connection follows
a peer across an IP change, such as a NAT rebind.

**NAT traversal.** A rendezvous server pairs two peers behind NATs so they can hole-punch a direct
path, with a relay fallback through the rendezvous when the punch fails, as it does on symmetric
NATs.

**Clock sync.** A built-in ping/pong estimates the peer's clock offset, giving both ends a shared
timeline.

**Snapshot replication.** Delta encoding, interest management, priority accumulation, and
interpolation.

**A deterministic in-memory network** (`testnet.hpp`). Run two real peers against each other with
configurable loss, latency, jitter, duplication and reordering, reproducible from a fixed seed and
with no sockets involved. aether's own tests drive it, so your CI can test your netcode the same
way.

## Design

Data-first: plain structs and free functions, with no inheritance or virtuals. State is mutated in
place. One focused header per module under `include/aether/`, so you can include only what you use
or pull in the whole library with `<aether/aether.hpp>`. The only translation units are the
platform layer, `src/socket_posix.cpp` and `src/socket_win.cpp`; everything else is header-only.

## Build

```sh
cmake -B build
cmake --build build
ctest --test-dir build
```

aether needs a C++20 compiler: clang, gcc, or MSVC. CMake selects the one platform file, either
`src/socket_posix.cpp` for BSD sockets or `src/socket_win.cpp` for Winsock. CI builds and tests on
all three compilers across Linux, macOS, and Windows.

The build includes a runnable echo pair in `examples/`. Start the server, type lines at it through
the client, and watch them come back over an encrypted reliable channel:

```sh
./build/aether_echo_server            # terminal 1: listens on 7777
./build/aether_echo_client            # terminal 2: connects to 127.0.0.1:7777
```

## Getting started

A `Host` is a socket plus its peers, and the same type serves as client or server. Bind it, then
pump one step per frame: `hostTick` drains incoming datagrams, sends what you queued, and returns
the events that occurred.

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

Each channel picks its own guarantee, one of reliable-ordered, reliable-unordered,
reliable-sequenced, unreliable, or unreliable-sequenced, so one packet stream carries mixed
delivery semantics.

Two peers behind NATs do not need each other's address. They join a shared room on a rendezvous
server, and aether establishes the link by hole-punching a direct path, or by relaying through the
rendezvous if the punch fails.

```cpp
aether::hostJoinRoom(host, rendezvousAddr, roomId, now);   // paired by room, then punched or relayed
```

## Authentication

Gate connections behind a signed token from your own auth backend, whether that is Firebase, Steam,
OIDC or something custom. Your backend holds a secret key `K` shared with the game servers and
seals a token after a login; the server verifies it during the handshake. aether never talks to the
provider, so it works with any of them, and the provider only ever touches your backend's seal
step.

```cpp
// your backend, after the player logs in (Firebase/Steam/...), holding the shared key K:
aether::Bytes token = aether::sealConnectToken(K, aether::ConnectToken{ playerId, expiresAt, userData });
//                    ...hand the token bytes to the client over HTTPS...

// server: require a token by setting the key; the verified playerId arrives on Connected
cfg.tokenKey = K;   // open the server host with this config; ev.playerId is the authenticated id

// client: present the token your backend gave you
aether::hostConnectWithToken(*client, serverAddr, token, now);
```

The server validates the token before generating any keys, which also shields the handshake from
spoofed-source floods. A token is single-use and replay-protected, so mint a fresh one per connect.

## Squeezing the wire

Optional: when you know a field's range, wrap it and it costs exactly the bits that range needs.

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

On a 12-field snapshot with two fields changed, aether writes 8 bytes where zpp::bits and bitsery
both write 40. The diff costs a few nanoseconds of CPU, and on a bandwidth-bound network fewer
bytes on the wire is the trade that matters. Past 16 fields the changemask adapts: a small number
of changes is sent as sparse indices rather than a full bitmap, so one changed field in a 32-field
struct costs a 2-byte mask instead of 4. To reproduce:

```sh
cmake -B build -DAETHER_BENCH_COMPARE=ON
cmake --build build --target aether_bench_compare && ./build/aether_bench_compare
```

## Testing

Reliable delivery and large-message fragmentation are exercised under heavy simulated packet loss:
a message that must arrive does, by retransmit, and a fragmented one reassembles only once every
fragment lands. The handshake completes through 30% loss with latency, jitter, duplication and
reordering applied at once. Reliability is also tested against the receiver's own limits, so a run
of messages that overruns the reorder buffer behind a lost packet still arrives in full. Every
decoder is fuzzed against random and truncated input, and each bit-packed field's range is asserted
to hold on hostile bytes, not just on bytes aether wrote. The serializer is property-tested over
arbitrary values, with floats compared bit-exactly. All of it runs under ASan and UBSan.

CI is staged, running static analysis first, then ASan and UBSan, then a build-and-test matrix
across gcc, clang, and MSVC on Linux, macOS, and Windows, warning-clean under `-Werror`, plus a job
that installs the package and builds a consumer against it.

Every configuration field is read by the library: there is no knob that validates and then tunes
nothing.

## Trade-offs

Deliberate design decisions, and what they cost you.

- The X25519 handshake is unauthenticated. It resists eavesdropping but not an active
  man-in-the-middle. Connect tokens add identity, access control and a DoS gate, but a token is a
  bearer credential. Full MITM resistance needs a keys-in-token model, which costs ephemeral keys
  and forward secrecy, and that is not a trade this library makes.
- A fast reconnect is a 0-RTT resume, and it inherits the usual 0-RTT cost. The resume request is
  authenticated by a MAC over the ECDH master, so a passive observer of the original cleartext
  session token cannot forge one. An attacker who captures a live resume request in flight can
  still replay it and win the race against the real client, because closing that hole requires a
  challenge round-trip, which is exactly what 0-RTT resume exists to avoid.
- `maxMessageSize` is bounded by the fragment count: a message must fit 255 fragments, roughly
  295KB at a 1200-byte MTU. This is checked at `validateConfig` rather than at send. A message
  larger than one send-rate bucket is paced, with its fragments spread across as many ticks as the
  budget needs, so big messages cost latency and never a config rejection.
- A reliable-ordered channel's ordering guarantee is bounded by `orderedBufferTimeout`. If a gap
  never fills, the channel eventually delivers what is behind it and moves on rather than stalling
  forever, and the skipped sequences then become a permanent hole.
- `config.mtu` (default 1200) is the floor everything is sized against. Probe-based path-MTU
  discovery then raises the usable datagram size up to `mtuProbeCeiling` (default 1500). That
  headroom feeds message coalescing only; fragmentation stays chunked at the floor, so a path that
  shrinks back can never strand a fragmented message. Near-total loss above the floor collapses to
  it immediately.
- A rendezvous room id is a bearer credential. Anyone who presents the same 64-bit id is paired
  into the room and learns the other peer's public address, so treat room ids as unguessable
  secrets minted by your matchmaker, not as sequential lobby numbers.
- The serializer reflects `std::array`, `string`, `vector`, `optional` and nested aggregates. Raw
  C-array members are not auto-reflected, which is a C++20 limitation; use `std::array<T, N>`
  instead. Misuse is a clear `static_assert` rather than silent breakage.

## Known limitations

These are not design decisions, they are work that is not done yet. Each one has an issue.

- The handshake commits an ephemeral keypair and a half-open slot when the connection request
  arrives, before the challenge echo proves the source address, and the challenge reply is about
  four times the size of the request. Both are bounded by the per-source rate limit and
  `maxPending`, and a stateless retry cookie is the fix. See issue #6.
- Two connected peers exchange an ack-only packet per tick even when neither is sending anything,
  because a bare ack is itself treated as needing acknowledgement. It is wasted bandwidth on an
  idle link rather than a correctness problem. See issue #11.
- Backpressure is implicit: a receiver that cannot buffer withholds the ack and the sender
  retransmits. An application that stops draining entirely will eventually lose a message once the
  sender exhausts its retries, which is reported rather than silent. An advertised receive window
  is the fix. See issue #3.
- `net.hpp` drains the socket non-blocking once per tick, and there is no dedicated receive thread.
  Inbound traffic is therefore absorbed by the kernel socket buffer between ticks, and one core
  handles all packet processing.

Roadmap and known work live in [issues](https://github.com/Gondola-Bros-Entertainment/aether/issues).

## License

MIT. See [LICENSE](LICENSE).

Built by Devon Tomlin (Novavero AI Inc.).
