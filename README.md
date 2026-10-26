# aether

[![ci](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Reliable UDP netcode for games in C++20: authenticated, encrypted connections, channels with five
delivery modes, fragmentation, congestion control, and reflection-based delta compression for game
state. It has no external dependencies. Most of the library is headers; a small static library
provides sockets, address resolution, and OS randomness on Linux, macOS, and Windows.

Applications own their message schemas, accounts, simulation, and persistence.

## Requirements

- CMake 3.23 or later
- A C++20 compiler. CI builds and tests GCC 12 and GCC 16 on x86-64 Linux, the Ubuntu 24.04 GCC
  on x86-64 and ARM64, Clang on Ubuntu 24.04, Apple Clang on macOS 26, and MSVC on Windows
  Server 2025.

## Use from CMake

From a source tree, with `add_subdirectory` or `FetchContent`:

```cmake
add_subdirectory(path/to/aether)
target_link_libraries(my_app PRIVATE aether::aether)
```

From an installed package:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DAETHER_BUILD_TESTS=OFF -DAETHER_EXAMPLES=OFF
cmake --build build --config Release
cmake --install build --config Release --prefix /path/to/prefix
```

```cmake
find_package(aether CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE aether::aether)
```

Add the prefix to `CMAKE_PREFIX_PATH`. A versioned `find_package(aether 0.2 ...)` accepts only
0.2.x versions.

The `aether::aether` target carries the C++20 requirement, the include directory, and the Windows
libraries it needs (`ws2_32` and `bcrypt`). Include `<aether/aether.hpp>` for the whole library or
individual headers such as `<aether/net.hpp>`. Everything is in namespace `aether`.

| Option | Default when built directly | Purpose |
| --- | --- | --- |
| `AETHER_BUILD_TESTS` | On, unless `BUILD_TESTING=OFF` | Tests and header/ODR checks |
| `AETHER_BUILD_BENCHMARKS` | Value of `AETHER_BUILD_TESTS` | Benchmark (`aether_bench`) |
| `AETHER_EXAMPLES` | On | Credential issuer, echo client and server |
| `AETHER_INSTALL` | On | Package installation and export rules |
| `AETHER_WERROR` | Off | Treat compiler warnings as errors |
| `AETHER_BENCH_COMPARE` | Off | Comparison benchmark; downloads zpp::bits and bitsery |

Everything except the library itself is off by default when aether is not the top-level project.

## Transport

A `Host` owns a non-blocking UDP socket and all session state. Aether starts no threads; the
application drives it from its own loop.

- `openHost(bindAddress, config, now)` validates a `NetworkConfig` and binds the socket. It returns
  an empty optional on an invalid config or a bind failure; `validateConfig(config)` returns the
  `ConfigError` in the first case. Servers bind `addrAny(port)` (or `addrAny6` for IPv6); clients
  can bind `addrAny(0)`. A host bound with `addrAny` reaches only IPv4 addresses, so resolve the
  server with `aether::AddressFamily::IPv4`, as the echo client does.
- A client starts a connection with `hostConnectWithToken(host, serverAddress, credential, now)`
  (see [Authentication](#authentication)). Connect calls return `std::optional<ConnectError>`,
  empty when the attempt started.
- `hostTick(host, broadcasts, now)` receives a bounded batch of datagrams, advances timers, sends
  queued traffic, and returns `PeerEvent`s: `Connected`, `Disconnected` (with a
  `DisconnectReason`), `Message`, `Migrated`, and `Reconnected`. `broadcasts` is a list of
  `(ChannelId, Bytes)` messages for every connected peer. Call it every frame.
- `hostSend(host, peerAddress, channel, bytes, now)` queues a message for one peer. An error means
  it was rejected locally; success means queued, not delivered.
- `hostDisconnect` closes one connection. `hostShutdown` sends disconnects to every peer; keep
  ticking if you want them retried, then call `closeHost` to release the socket and session state.

`now` is a `MonoTime`: nanoseconds from a monotonic clock such as `std::chrono::steady_clock`.
`hostTakeDiagnostics` returns the socket and broadcast failures recorded since the last call, and
`peerStats(host.peer, aether::PeerId{address})` returns a connection's RTT, loss, bandwidth, and
`reliableDropped` count. `resolveAddresses` turns a host name into addresses; it blocks, so call it
outside the tick. The [examples](examples/) show the whole sequence. Both endpoints must use the
same wire format version (currently 2); there is no version negotiation.

A connection has up to 8 channels (`NetworkConfig::maxChannels`). `channelConfigs[i]` configures
channel `i`; channels without an entry use `defaultChannelConfig`, which is reliable ordered with a
1024-byte message limit. Both endpoints must use the same channel settings: they are not sent on
the wire, and a receiver drops messages on a channel beyond its own `maxChannels`. Each
`ChannelConfig` picks a `DeliveryMode`:

| Mode | Behavior |
| --- | --- |
| `ReliableOrdered` | Retransmits missing messages and delivers in order; a gap is recovered or fails the connection. |
| `ReliableUnordered` | Retransmits missing messages and delivers each once, without waiting for earlier ones. |
| `ReliableSequenced` | Retransmits until acknowledged; the receiver discards anything older than the newest message it has delivered. |
| `Unreliable` | Sends without retransmission or ordering. |
| `UnreliableSequenced` | Sends without retransmission and discards messages older than the newest received. |

Small messages share datagrams. Large messages are fragmented, paced across ticks, and
retransmitted per fragment. If a reliable message exhausts its retries, or a fragmented
reliable message stalls, the connection closes with `DisconnectReason::DeliveryFailed` instead of
continuing without it. Replayed datagrams are rejected.

The transport also estimates RTT and RTO, paces sending with AIMD rate control driven by RTT and
loss (`useCwndCongestion` adds a New Reno style congestion window that also gates larger reliable
sends), probes the path MTU, follows a peer to a new address, and pairs peers behind NAT through a
rendezvous server with relay fallback. The [behavior reference](docs/behavior.md) lists the limits,
defaults, and application obligations.

`peerProcess` runs the same transport without sockets, and `testnet.hpp` connects two peers over a
simulated link with seeded loss, latency, jitter, duplication, and reordering for deterministic
tests.

## Authentication

Clients connect with credentials from a trusted backend:

1. The backend authenticates the player, then calls
   `issueConnectCredential(issuerKey, ConnectToken{playerId, expiresAt, userData, scope})`.
   `expiresAt` is a `UnixTime` in nanoseconds since the Unix epoch, `userData` is up to 256 opaque
   bytes, and `scope` is a `TokenScope{protocolId, audience}`. The result is a
   `ConnectCredential`: a sealed token plus a separate random proof key for that client. It throws
   `std::invalid_argument` if the key, protocol ID, audience, or expiry is zero, or `userData` is
   too long. Send the whole credential to the client over the backend's authenticated, encrypted
   channel.
2. The server sets `NetworkConfig::tokenKey` to the issuer key and `tokenAudience` to the scope's
   audience. Both endpoints' `NetworkConfig::protocolId` must equal the scope's protocol ID.
3. The client calls `hostConnectWithToken`. Only the sealed token travels on the wire; the client
   proves it holds the proof key during the handshake. The server's `Connected` and `Reconnected`
   events carry the verified `playerId` and `userData`.

Each token admits one session per server host. The server remembers spent tokens in memory and
refuses new admissions while 65,536 unexpired tokens are tracked. A restarted server forgets them,
so rotate the issuer key after losing that state. Servers that share a key and audience do not
share spent tokens. `hostTick` reads the system clock for expiry checks; with `peerProcess`, pass
the Unix time as its fourth argument or the server admits no credentials.

After a timeout, `hostReconnect(host, address, token, now, fallback)` resumes the session for up to
30 seconds with a fresh handshake. Read `token` with
`peerSessionToken(host.peer, aether::PeerId{address})` while connected. If the server no longer has
the session, the optional `fallback` credential starts a normal connection instead. A successful
resume reports `Reconnected` on both endpoints; a fallback connection reports `Connected`. Explicit
disconnects are not resumable.

`hostConnect` opens an anonymous encrypted connection for development or peer-to-peer use. Both
endpoints must set `allowUnauthenticated = true`, and a host with a `tokenKey` refuses it. It
authenticates neither side.

The [authentication reference](docs/authentication.md) specifies the handshake, wire format,
resumption, and trust boundaries.

## Serialization

The codecs reflect over plain aggregates with no annotations:

- `serialize` / `deserialize`: fixed-width little-endian fields.
- `pack` / `unpack`: varint integers.
- `deltaPack` / `deltaUnpack`: only the fields that differ from a baseline.
- `packBits` / `unpackBits`: bit-packed, with `Ranged` and `Quantized` fields.

A reflected type must be an aggregate of at most 32 public fields, with no base classes, reference
members, or user-declared constructors. Fields may be integers, floating-point values, `bool`, enums
with a fixed underlying type, nested aggregates, `std::array` of up to 32 elements, `std::string`,
`std::vector`, and `std::optional`, except that `packBits` takes only fixed-size fields. Raw C
arrays are rejected; use `std::array`. Unsupported shapes fail to compile. The wire format carries
no field names or schema version, so both ends must use the same types in the same member order.

The delta codec writes a change mask followed by the changed values. The caller must supply the
same baseline to both operations:

```cpp
#include <aether/delta.hpp>
#include <cstdint>

int main() {
    struct State { float x, y; int health; };
    const State previous{0.0f, 0.0f, 100};
    const State current{1.5f, 0.0f, 95};
    std::uint8_t buffer[256]{};
    aether::Writer writer{buffer, sizeof buffer};
    aether::deltaPack(writer, previous, current);
    if (!writer.ok) return 1;

    aether::Reader reader{buffer, writer.pos};
    const auto restored = aether::deltaUnpack(reader, previous);
    if (!restored || reader.pos != writer.pos) return 1;
    return restored->x == current.x && restored->y == current.y
        && restored->health == current.health ? 0 : 1;
}
```

Integers are varints and floating-point values keep their exact bits. Structs with more than 16
fields send a list of changed field indices when that is smaller than the mask. A changed vector
is sent in full. The codec does not infer numeric tolerances, object identities, or element-level
vector edits.

### Bit packing

Use `Ranged` and `Quantized` when the application knows a field's range and acceptable precision:

```cpp
#include <aether/bitserialize.hpp>
#include <cstdint>

int main() {
    struct Input {
        aether::Ranged<int, 0, 1023> move;
        aether::Quantized<-1.0f, 1.0f, 12> aim;
        bool firing;
    };
    const Input input{{512}, {0.25f}, true};
    std::uint8_t buffer[3]{};
    aether::BitWriter writer{buffer, sizeof buffer};
    const auto size = aether::packBits(writer, input); // 10 + 12 + 1 bits, padded to 3 bytes
    return writer.ok && size == sizeof buffer ? 0 : 1;
}
```

Values outside a field's range are clamped, and quantization trades precision for fewer bits.

### Replication

`replication.hpp` builds snapshot replication on the delta codec. The application numbers its
snapshots with `BaselineSeq` IDs and acknowledges them itself:

1. The sender calls `deltaEncode(tracker, id, state)` with a `DeltaTracker<T>` and sends the result
   together with `id`. The payload names the baseline it was encoded against, not its own ID.
2. The receiver calls `deltaDecode(baselines, payload)` with a `BaselineManager<T>`, stores a
   successful result with `pushBaseline(baselines, id, state, now)`, and only then acknowledges
   `id`. Receiving the packet is not enough.
3. On that acknowledgement the sender calls `deltaOnAck(tracker, id)`, and later snapshots are
   encoded against it.

If `maxBaselineAge` (default 32) snapshots go out without an acknowledgement, `deltaEncode` sends
full state; zero or less turns that off. A `BaselineManager` keeps 64 snapshots for up to one second
by default (`newBaselineManager` sets both). The ID `noBaseline` (0xFFFF) is reserved.

`interest.hpp` (relevance filtering), `priority.hpp` (priority accumulation), `interpolation.hpp`
(snapshot interpolation), and `clocksync.hpp` (clock offset estimation) are separate helpers.

## Security

Authenticated sessions use the `Noise_NNpsk0_25519_ChaChaPoly_SHA256` handshake, and traffic
after the handshake is encrypted with ChaCha20-Poly1305. X25519, ChaCha20-Poly1305, SHA-256, HMAC,
and HKDF are implemented in this library and tested against published vectors. Neither the
cryptography nor the protocol has been independently audited.

## Examples

With `AETHER_EXAMPLES` on, the build produces a credential issuer, an echo server, and an echo
client:

```sh
./build/aether_echo_credentials /private/path/echo-demo
./build/aether_echo_server /private/path/echo-demo/server.key 7777
./build/aether_echo_client /private/path/echo-demo/client-1.credential localhost 7777 "hello aether"
./build/aether_echo_client /private/path/echo-demo/client-2.credential localhost 7777 "second client"
```

The issuer creates the directory, which must not already exist, restricts it to your user, and
writes the server key and two client credentials valid for ten minutes. On Windows, choose a parent
directory that your user ACL already protects. File-based provisioning is for the demo only. Each
credential admits one session per server run. The client resolves IPv4 names, sends one message of
up to 1024 bytes, and exits nonzero unless the echo matches. Ctrl+C shuts the server down.
Multi-configuration generators put the executables in a configuration directory such as
`build/Debug`.

## Building and testing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAETHER_WERROR=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

The header self-containment and ODR checks are build targets, so a failure breaks the build. The
`echo_process` test runs the example programs and is registered only when Python 3 is found.

## License

[MIT](LICENSE).
