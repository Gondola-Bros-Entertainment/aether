# aether

[![ci](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A C++20 library for reliable UDP transport, serialization, and state replication helpers.
It has no external runtime dependencies. Most implementation is in headers; a small static
library provides sockets and system randomness on Linux, macOS, and Windows.

Applications own their message schemas, account integration, simulation, and persistence.
Aether provides the networking mechanisms without depending on an application or engine.

## Development status

Version 0.2 uses authenticated, scoped credentials with the concrete
`Noise_NNpsk0_25519_ChaChaPoly_SHA256` handshake. Fresh key confirmation precedes
admission and resumption. Anonymous encrypted connections require an explicit
`allowUnauthenticated = true` opt-in at both endpoints.

Packet format version 2 retains the 17-byte header and changes the handshake and
credential formats. Upgrade both endpoints and reissue credentials together; there
is no downgrade negotiation. This is an implementation milestone, not an independent
security certification. See [authentication](docs/authentication.md), the
[behavior reference](docs/behavior.md), and [migration notes](docs/migration-0.2.md).

## Build and test

Requires CMake 3.23 or later and a C++20 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAETHER_WERROR=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

CI uses cppcheck 2.21.0, ASan/UBSan, compiler tests with GCC, Clang, and MSVC, and an installed-package
consumer on Linux, macOS, and Windows, including native Linux ARM64 transport tests. Keep test builds in Debug: some existing tests use
`assert`, which Release builds disable.

The [credential issuer](examples/echo_credentials.cpp), [echo server](examples/echo_server.cpp)
and [echo client](examples/echo_client.cpp) exercise the authenticated public API.
Create a new directory under a private parent, then run the server and clients in
separate terminals:

```sh
./build/aether_echo_credentials /private/path/echo-demo
./build/aether_echo_server /private/path/echo-demo/server.key 7777
./build/aether_echo_client /private/path/echo-demo/client-1.credential localhost 7777 "hello aether"
./build/aether_echo_client /private/path/echo-demo/client-2.credential localhost 7777 "second client"
```

The issuer creates two separate credentials valid for ten minutes. Each may establish
one session on that running server. The server key stays on the issuer/server; distribute
only each client's credential to that client. These files demonstrate provisioning,
not an account service. On Windows, use a directory protected by your user ACL.
Multi-configuration generators put executables in a configuration directory such as
`build/Debug`. The client verifies its echo and exits nonzero on failure. The default
channel message limit is 1024 bytes. The example resolves IPv4 names; the library
resolver also supports IPv6. Ctrl+C gracefully shuts down the server.

### Use from CMake

For a source checkout:

```cmake
add_subdirectory(path/to/aether)
target_link_libraries(my_app PRIVATE aether::aether)
```

For an installed package:

```cmake
find_package(aether CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE aether::aether)
```

The target exports its C++20 requirement and platform link dependencies. Tests, header checks,
benchmarks, examples, and install rules are off by default in an `add_subdirectory` build.

| Option | Default when built directly | Purpose |
| --- | --- | --- |
| `AETHER_BUILD_TESTS` | On, unless `BUILD_TESTING=OFF` | Tests and header/ODR checks |
| `AETHER_BUILD_BENCHMARKS` | Value of `AETHER_BUILD_TESTS` | Local benchmark |
| `AETHER_EXAMPLES` | On | Echo client and server |
| `AETHER_INSTALL` | On | Package installation and export rules |
| `AETHER_WERROR` | Off | Treat compiler warnings as errors |
| `AETHER_BENCH_COMPARE` | Off | Comparison benchmark; downloads zpp::bits and bitsery |

## Transport

A `Host` owns a UDP socket and peer state. `openHost` validates configuration and binds the socket;
check its optional result before use. Call `hostTick` regularly with monotonic time. It receives
a bounded batch, advances transport timers, sends queued traffic, and returns events.

Use `hostConnectWithToken` with a `ConnectCredential` to start an authenticated connection. After a `Connected` event, `hostSend` queues a message
for one peer. Its optional error reports local rejection; success means queued, not remotely
delivered. `hostTick` also accepts messages to broadcast. Take bounded socket and broadcast
failures with `hostTakeDiagnostics`; socket counters remain cumulative. `hostReconnect`
performs fresh resumption. `hostShutdown` flushes disconnects; continue ticking for retries
if desired, then call `closeHost` to release the socket and session state. The [examples](examples/) demonstrate this sequence.

Each channel chooses its delivery mode:

| Mode | Behavior |
| --- | --- |
| Reliable ordered | Retransmits missing messages and delivers in order; a gap is recovered or fails the connection. |
| Reliable unordered | Retransmits missing messages and suppresses duplicate deliveries without waiting for earlier messages. |
| Reliable sequenced | Retransmits while a message remains current; newer messages supersede older ones. |
| Unreliable | Sends without retransmission or ordering. |
| Unreliable sequenced | Sends without retransmission and discards messages older than the latest received sequence. |

The packet layer rejects replayed datagrams. Small messages can share a datagram. Large messages
use fragmentation, selective retransmission, and pacing across ticks. Reliable receive pressure
withholds acknowledgements; acknowledged fragments retain assembly storage until the channel
accepts the completed message. Retry exhaustion or an unrecoverable reliable assembly timeout
reports `DeliveryFailed` instead of silently losing a message and continuing.

Other transport modules provide RTT/RTO estimation, loss-based rate control, an optional
congestion window, path-MTU probes, encrypted address-migration challenges, and rendezvous
pairing with hole punching and relay fallback. These are custom UDP mechanisms; the congestion
controller does not claim TCP NewReno conformance.

`peerProcess` exposes the transport without sockets. `testnet.hpp` drives two peers with seeded
loss, latency, jitter, duplication, and reordering for deterministic application tests.

## Serialization and field deltas

The delta codec compares aggregate fields against a baseline and writes a change mask followed
by changed values. The caller must supply the same baseline to both operations:

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

Reflection uses compile-time aggregate decomposition and structured bindings, with a central
binding ladder for up to 32 fields per aggregate. It binds members directly; it does not guess
memory offsets. Supported fields include nested aggregates, `std::array`, `std::string`,
`std::vector`, and `std::optional`. Raw C-array members are unsupported; use `std::array`.
Changing member order or types changes the wire schema.

Integers use varints; floating-point values preserve their bits. Above 16 fields, change masks
use sparse indices when smaller. Changed vectors are encoded in full. The codec does not infer
numeric tolerances, object identities, or element-level vector edits.

`DeltaTracker` stores sender baselines and `BaselineManager` stores receiver baselines. The
application assigns snapshot IDs and acknowledges successful reconstruction. Packet receipt
alone is insufficient. Full-state fallback is enabled by default when snapshot acknowledgements
stop advancing. Interest management, priority accumulation, snapshot interpolation, and clock
offset estimation are separate helpers.

### Explicit bit packing

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

This is a separate codec from `deltaPack`. Quantization trades precision for fewer bits.

## Connect tokens

An authenticated application backend calls `issueConnectCredential` with an issuer/server
sealing key and `ConnectToken` claims: numeric `playerId`, Unix expiry, up to 256 bytes
of opaque `userData`, and `TokenScope{protocolId, audience}`. It generates a unique PSK
and returns both the opaque sealed token and the separate client proof key. Deliver
the complete `ConnectCredential` through that backend's trusted channel.

Set the server's `NetworkConfig::tokenKey` and nonzero `tokenAudience`. Clients call
`hostConnectWithToken`; the token alone cannot authenticate them. Server-side
`Connected` and `Reconnected` events carry the verified `playerId` and `userData`.
Game authentication credentials are separate from SSH, deployment keys and
Cloudflare service tokens.

Credential expiry uses `UnixTime` in Unix epoch nanoseconds; transport timers use
`MonoTime`. `hostTick` obtains Unix time from the system. Pure-core callers supply
it as `peerProcess`'s fourth argument when accepting credentials; omission fails
admission closed. Replay storage rejects new admissions when full. A Unix-time
high watermark prevents backwards clock corrections from reviving expired tokens.

Replay storage is local to an admission authority and held in memory. Preserve it
across restarts or rotate the sealing key after state loss. Independent validators
sharing a key and audience do not enforce global single use. Scope binds protocol
and audience but does not replace this operational requirement.

See [authentication and wire details](docs/authentication.md) for proof, expiry,
resumption and trust boundaries, and [0.2 migration](docs/migration-0.2.md) for API changes.

## License

[MIT](LICENSE).
