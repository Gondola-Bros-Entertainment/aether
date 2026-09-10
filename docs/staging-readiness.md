# Aether 0.2 readiness and qualification

Version 0.2 was merged in [PR #14](https://github.com/Gondola-Bros-Entertainment/aether/pull/14)
at `33bfe09`. All ten [final PR CI checks](https://github.com/Gondola-Bros-Entertainment/aether/actions/runs/34421035424)
passed on `0e149cc`; the merged source tree is identical to that tested revision.
This records tested behavior and remaining application work; it is not a security
certification or a guarantee of production capacity. The audit baseline was
`ad3bd05` (2026-09-09).

## Assessment

The library has the transport features needed for Orivella's first dedicated
server: reliable/unreliable channels, fragmentation, flow control, bounded socket
intake, congestion/pacing, encrypted packets, migration, field deltas, replication
baselines, interpolation, clock sync, interest/priority helpers and deterministic
network impairment tests. Rendezvous and relay support already exist for P2P.

The implementation keeps the testable transport core separate from platform socket
adapters. Authenticated handshakes, initiation and peer state now have focused
modules, while the peer loop retains transport processing. The API remains
data-oriented C++20. Game commands, authority, accounts, persistence and deployment
belong to the application.

## Baseline findings addressed by 0.2

1. **Authenticated sessions and scoped credentials.** The baseline X25519 exchange
   lacked peer authentication. Noise now binds credentials, protocol, audience,
   ephemeral keys and roles to the transcript, with confirmation before admission.
   Anonymous development connections require explicit opt-in. Independent vectors
   verify the concrete Noise construction.
2. **Admission and resumption lifecycle.** The baseline spent single-use state
   before fresh proof and did not recheck credential expiry at completion. Both
   checks now precede admission. Resumption derives new traffic keys and a new
   master; retransmissions are idempotent. Forged plaintext terminal messages
   cannot advance or cancel authenticated handshakes. Restart, expiry, replay
   races and fallback have regression coverage.
3. **Configuration invariants.** Validation rejects non-finite or invalid
   rates/timers, invalid retry counts, missing credential scope and unsupported
   MTUs. The timeout resume cache is bounded and can be disabled.
4. **Observable socket and queue failures.** Hosts expose bounded socket and
   per-peer broadcast failure records alongside cumulative counters. Successful
   enqueueing still does not imply remote delivery.
5. **Host integration.** Hostname/IP resolution and numeric formatting are
   available outside the tick loop. Reconnect and shutdown use normal transport
   routing and error reporting. Connection queries exclude disconnecting peers.
6. **Qualification and examples.** Authenticated examples and installed consumers
   exercise the public API. Tests cover real UDP, incompatible wire versions,
   credential scopes, loss, delay, duplication, reordering and retransmission.
   Native Linux ARM64 CI and a bounded load profile qualify the transport for
   application integration without claiming a player-capacity guarantee.

## Historical baseline evidence

- At the audit baseline, `main` matched `origin/main`; no open GitHub issues were returned.
- A fresh Debug build with warnings as errors, standalone headers and ODR checks
  passed on macOS ARM64. All 27 CTest targets passed: 26 in the sandbox, with the
  real-socket roundtrip rerun successfully outside the socket-restricting sandbox.
- Local probes reproduced each configuration acceptance listed above, forged
  denial/acceptance behavior, token consumption before connection, and admission
  after expiry during an in-flight handshake. Permanent regressions now cover
  these findings in the configuration and authenticated-session tests.
- The nine-job hosted CI pass at that baseline qualified the previous repair.
  The ten-job 0.2 run linked above qualifies the authentication implementation.

## Hosted qualification

All 36 tests passed in Linux ASan/UBSan and each of the five platform builds:
Linux GCC, Linux Clang, native Linux ARM64 GCC, macOS Clang and Windows MSVC.
cppcheck passed, as did Release installation and an external `find_package`
consumer on Linux, macOS and Windows. CI retains the exact source revision and logs.

## Local qualification (macOS ARM64, AppleClang 21)

- cppcheck 2.21.0 passed with warning, performance and portability checks enabled.
- Debug warnings-as-errors build, every standalone public header and multi-TU ODR
  link checks passed. All 36 CTest targets passed, including real UDP and the separate
  authenticated issuer/server/client processes.
- All 36 targets also passed AddressSanitizer and UndefinedBehaviorSanitizer with
  recovery disabled. Release installation and a separate `find_package` consumer passed.
- Noise NNpsk0 matched the pinned independent Cacophony vector's two handshake
  ciphertexts, final transcript and four transport ciphertexts byte for byte. SHA-256,
  HMAC and HKDF known-answer tests and split-boundary tests passed.
- Auth tests cover every modified byte of a credential request, mismatched scope,
  forged terminal messages, stale/incorrect proof, expiry during admission, capacity
  rejection without spending, captured-request races, fresh resume generations,
  retry-work recovery and server-cache-loss fallback.
- Eight seeded impairment runs used 15% datagram loss, 35 ms one-way latency,
  up to 15 ms jitter, 20% duplication and 20% reordering. Both authenticated admission
  and reliable application delivery completed under a 576-byte datagram ceiling.
- The 64-client pure-core burst used a 1024 requests/second per-host budget, exchanged
  128 reliable 32-byte request/reply messages and checked a bounded eight-entry timeout
  cache. That Debug run took about 1.5 seconds of wall time during local qualification.
  This is a reproducible profile, not a concurrency/latency service-level guarantee.

No Orivella game server or OCI listener is deployed by these library tests.

## Completion boundary

The 0.2 transport milestone is complete and ready for Orivella's authoritative-server
integration. The game's server, session issuance and Linux build still require
their own verification before the first authenticated OCI staging playtest.
Application schemas, input prediction/reconciliation, game persistence, identity
providers, matchmaking and fleet orchestration remain application/service work.
Future defects and measured performance needs can still justify library changes.

Security design references: [Noise protocol framework](https://noiseprotocol.org/noise.html)
and [TLS 1.3 authentication/key confirmation](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4).
Selecting a standard construction does not by itself validate its integration.
