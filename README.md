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

On a 12-field snapshot with two fields changed, aether writes 8 bytes where zpp::bits and bitsery
both write 40. The diff costs a few nanoseconds of CPU, and on a bandwidth-bound network fewer
bytes on the wire is the trade that matters. Past 16 fields the changemask adapts: a small number
of changes is sent as sparse indices rather than a full bitmap, so one changed field in a 32-field
struct costs a 2-byte mask instead of 4. To reproduce:

```sh
cmake -B build -DAETHER_BENCH_COMPARE=ON
cmake --build build --target aether_bench_compare && ./build/aether_bench_compare
```

## The stack

On top of the delta core, aether is a full reliable-UDP transport.

**Delivery.** Five per-channel guarantees (reliable-ordered, reliable-unordered,
reliable-sequenced, unreliable, unreliable-sequenced) share one packet stream, so a single
connection carries mixed semantics. Every mode delivers a message at most once: a retransmit whose
ack was lost, or a datagram the network duplicated, is recognized and dropped rather than handed to
the application twice. Small messages coalesce into one datagram under a single header and auth
tag. Messages over the MTU are fragmented and reassembled with selective retransmit, so a lost
fragment costs one fragment rather than the whole message, and a large message is paced across as
many ticks as the send budget needs. Nothing is acknowledged until the receiving channel has taken
it, so a full buffer becomes backpressure the sender feels rather than data it loses, and the
receiver advertises its remaining room per channel so the sender throttles before it starts
retransmitting into a buffer with no space.

**Reliability and congestion.** Sequence and ack-bitfield tracking, Jacobson/Karels RTT and RTO
estimation, and fast retransmit on a triple NACK. Rate control is a binary AIMD controller driven
by measured loss and RTT; a TCP New Reno window is available behind `useCwndCongestion`. Path-MTU
discovery is probe-based in the style of RFC 8899 and never depends on ICMP, raising the usable
datagram size above the 1200-byte floor when the path carries more and falling back immediately
when it stops.

**Security.** An X25519 handshake derives per-direction ChaCha20-Poly1305 keys with no pre-shared
secret. The packet header is authenticated as associated data, and replays are rejected by a
sliding window. Both primitives are written from scratch and checked against the RFC 7748 and RFC
8439 test vectors; a degenerate peer public key is rejected rather than keyed from. The handshake is
challenge/response with per-source rate limiting, keyed entirely from the OS CSPRNG: the client
echoes the server's challenge salt, so a peer spoofing its source address never receives the
challenge and cannot complete a handshake. Before any of that, the server answers a connection
request with a stateless retry cookie it does not remember, so a spoofed source cannot make it
commit a half-open slot or generate a keypair either. Rate limits are keyed per host, so varying a
source port buys no extra budget.

**Staying connected.** A dropped session resumes from a token without a full re-handshake, carrying
its verified `playerId` across the resume. The session master ratchets on each resume, so a resume
request authenticates once and never again. A live connection follows a peer across an IP change,
such as a NAT rebind; the new address is confirmed by an encrypted challenge before the connection
moves, so possession of the keys alone cannot redirect a session. Two peers behind NATs join a
shared room on a rendezvous server, which pairs them so they can hole-punch a direct path, and
relays through itself as a fallback when the punch fails, as it does on symmetric NATs.

**Replication and tooling.** Delta encoding with baseline tracking, interest management, priority
accumulation, snapshot interpolation, and a ping/pong estimate of the peer's clock offset.
`testnet.hpp` runs two real peers against each other with configurable loss, latency, jitter,
duplication and reordering, reproducible from a fixed seed and with no sockets involved. aether's
own tests drive it, so your CI can test your netcode the same way.

## Build

```sh
cmake -B build
cmake --build build
ctest --test-dir build
```

aether needs a C++20 compiler: clang, gcc, or MSVC. CMake selects the one platform file, either
`src/socket_posix.cpp` for BSD sockets or `src/socket_win.cpp` for Winsock. CI runs cppcheck, then
ASan and UBSan, then a build-and-test matrix across gcc, clang and MSVC on Linux, macOS and
Windows, warning-clean under `-Werror`, plus a job that installs the package and builds a consumer
against it.

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

## Design

Data-first: plain structs and free functions, with no inheritance or virtuals. State is mutated in
place. One focused header per module under `include/aether/`, so you can include only what you use
or pull in the whole library with `<aether/aether.hpp>`. The only translation units are the
platform layer, `src/socket_posix.cpp` and `src/socket_win.cpp`; everything else is header-only.

## Trade-offs

Deliberate design decisions, and what they cost you.

- The X25519 handshake is unauthenticated. It resists eavesdropping but not an active
  man-in-the-middle. Connect tokens add identity, access control and a DoS gate, but a token is a
  bearer credential. Full MITM resistance needs a keys-in-token model, which costs ephemeral keys
  and forward secrecy, and that is not a trade this library makes.
- Connecting costs three round trips, not two: the stateless retry cookie always runs, rather than
  switching on only when the half-open table is filling up. One code path is worth more here than
  one saved round trip on a once-per-session exchange, because the version that engages only under
  attack is the version that is untested when the attack arrives. Reconnects are unaffected, since a
  resume authenticates itself with a MAC over the ECDH master and stays 0-RTT.
- A fast reconnect is a 0-RTT resume, and it inherits the usual 0-RTT cost. The request is
  authenticated by a MAC over the ECDH master, so observing the cleartext session token is not enough
  to forge one, and the master ratchets as each resume is accepted, so a captured request
  authenticates at most once. Within that one window an attacker who captures a live request can
  still replay it and beat the real client to it; closing that would need a challenge round trip,
  which is what 0-RTT resume exists to avoid. A resumed connection is anti-amplification capped until
  a packet decrypts from its address, sending at most three times what it has received, so a resume
  replayed with a forged source address cannot aim the server's output at a third party. The real
  client lifts the cap with its first packet.
- Connection migration costs one round trip. A packet from a new address is delivered if it decrypts,
  but the connection moves only once that address echoes an encrypted random challenge. Decryption
  proves the sender holds the key; the echo is what proves it is reachable where it claims to be.
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
  secrets minted by your matchmaker, not as sequential lobby numbers. A room with a live relay
  session is closed to newcomers until it expires, so presenting a leaked id cannot evict a pair
  that is already talking, and a peer whose own address changes mid-session waits out that expiry
  like anyone else.
- The serializer reflects `std::array`, `string`, `vector`, `optional` and nested aggregates. Raw
  C-array members are not auto-reflected, which is a C++20 limitation; use `std::array<T, N>`
  instead. Misuse is a compile error rather than silent breakage: a `static_assert` naming the cause
  when the field mis-count runs past the 32-field probe limit, and a structured-binding decomposition
  error inside `tieFields` when it does not.
- Decoding a struct from the wire is capped at `Reader::allocBudget` (8MB by default) of resident
  objects. Wire length bounds how many elements a container can claim but not how much memory they
  cost, since one wire byte can materialize an element of any size, so the budget is charged against
  what a decode actually allocates. Raise it on the `Reader` for genuinely large payloads, or lower
  it to tighten the bound on untrusted input.
- Clock sync uses Cristian's algorithm, which assumes the two one-way delays are equal. On an
  asymmetric path the offset is biased by half the difference between them: a route with 5ms out and
  145ms back reads exactly 70ms off, where a symmetric path has no error at all. `clockOffsetErrorMs`
  reports the bound on that error, which is half the recent-best round-trip. That best decays upward
  toward the prevailing RTT rather than holding a lifetime minimum, so the bound stays honest as a
  path changes instead of quoting a tightness a stale sample once had. Check it before doing lag
  compensation: a large bound means the shared timeline is a guess.
- Replication ships the codec, not the protocol. aether provides the delta encode and decode, the
  sender's pending-snapshot tracking, and the receiver's baseline ring. Numbering your snapshots
  and telling the sender which one the peer received stays yours, because only the application
  knows what a snapshot is and the transport reports delivery per connection, not per message.
- `net.hpp` drains the socket non-blocking once per tick, and there is no dedicated receive thread.
  Inbound traffic is therefore absorbed by the kernel socket buffer between ticks, and one core
  handles all packet processing.
- The advertised receive window carries the receiver's absorption capacity: sent once as the
  connection comes up, then again when that figure moves materially (a quarter of the buffer) or the
  receiver becomes restricted, and repeated on a 250ms persist timer until a header acknowledges it.
  A link whose receiver keeps up therefore costs one flow-control packet for the whole session, since
  the first advertisement is acked and nothing after it changes. `maxReceiveBufferSize` is a
  per-collection capacity rather than a standing queue depth, because `peerProcess` hands every
  buffered message to the application on every tick; occupancy only outlives a tick if you drive
  `Connection` directly and skip that collection.

Known work lives in [issues](https://github.com/Gondola-Bros-Entertainment/aether/issues).

## License

MIT. See [LICENSE](LICENSE).

Built by Devon Tomlin (Novavero AI Inc.).
