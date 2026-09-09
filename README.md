# aether

[![ci](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml/badge.svg)](https://github.com/Gondola-Bros-Entertainment/aether/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A C++20 library for reliable UDP transport, serialization, and state replication helpers.
It has no external runtime dependencies. Most implementation is in headers; a small static
library provides sockets and system randomness on Linux, macOS, and Windows.

Applications own their message schemas, account integration, simulation, and persistence.
Aether provides the networking mechanisms without depending on an application or engine.

## Development status

The current handshake encrypts traffic but does **not** authenticate the key exchange against an
active man-in-the-middle. Connect tokens provide bearer-token admission, not proof that the
presenter is the intended client. A captured, valid resume request can also win a replay race.
Authenticated key exchange and fresh proof during resumption remain required security work.

Packet format version 1 uses a 17-byte header, including an authenticated session routing ID.
It is incompatible with the earlier unversioned 9-byte header. Upgrade both endpoints together.

See [the behavior reference](docs/behavior.md) for delivery guarantees, resource bounds, and
current handshake behavior.

## Build and test

Requires CMake 3.23 or later and a C++20 compiler.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAETHER_WERROR=ON
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

CI uses cppcheck 2.21.0, ASan/UBSan, compiler tests with GCC, Clang, and MSVC, and an installed-package
consumer on Linux, macOS, and Windows. Keep test builds in Debug: some existing tests use
`assert`, which Release builds disable.

The [echo server](examples/echo_server.cpp) and [echo client](examples/echo_client.cpp) show the
socket API with a network loop and connection events. Run them in separate terminals:

```sh
./build/aether_echo_server
./build/aether_echo_client
```

They default to port 7777 and localhost. With a multi-configuration generator, the executables
are in the configuration directory, such as `build/Debug`.

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

Use `hostConnect` to start a connection. After a `Connected` event, `hostSend` queues a message
for one peer. Its optional error reports local rejection; success means queued, not remotely
delivered. `hostTick` also accepts messages to broadcast. Call `closeHost` when finished with
the socket. The [examples](examples/) demonstrate this sequence.

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

An application credential issuer uses `sealConnectToken` to seal an application-issued numeric
`playerId`, expiry, and opaque data. The issuer and admitting servers share an `EncryptionKey`;
the client receives only the sealed bytes through the application's authenticated service.

Set `NetworkConfig::tokenKey` before opening the server host to require tokens. Clients present
the bytes with `hostConnectWithToken`. The admitted identity arrives in `PeerEvent::playerId`.
This admission check does not yet authenticate the ephemeral key exchange.

Credential expiry uses `UnixTime` in Unix epoch nanoseconds. Transport timers use `MonoTime`.
`hostTick` obtains Unix time from the system; callers of `peerProcess` supply it as the fourth
argument when accepting tokens. Omitting it rejects token admission.

The replay validator retains each spent nonce until its token expires and rejects new admissions
when storage is full. `validateConnectToken` exposes `TokenError::ReplayCapacity`. A time high
watermark prevents backward clock corrections from reviving expired credentials.

Replay protection belongs to the authority retaining that table. Preserve its state across
restarts or rotate the sealing key when state is lost. Independent validators sharing a key do
not enforce global single use. Token scope binding and authenticated resumption remain part of
the unfinished authentication work described above.

## License

[MIT](LICENSE).
