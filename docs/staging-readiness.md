# Staging readiness audit and qualification

Audit baseline: `ad3bd05` (2026-09-09). The 0.2 implementation addresses the findings
below. This records tested behavior and remaining application work; it is not a
security certification or a guarantee of production capacity.

## Assessment

The library has the transport features needed for Orivella's first dedicated
server: reliable/unreliable channels, fragmentation, flow control, bounded socket
intake, congestion/pacing, encrypted packets, migration, field deltas, replication
baselines, interpolation, clock sync, interest/priority helpers and deterministic
network impairment tests. Rendezvous and relay support already exist for P2P.

Keep the split between a testable transport core and platform socket adapters.
Keep game commands, authority, accounts, persistence and server deployment in
the application. Extract the new authenticated-handshake machinery into a focused
module rather than extending the 1,400-line peer header with another cryptographic
state machine. Preserve the existing data-oriented C++20 API where it remains useful.

## Baseline findings addressed by 0.2

1. **Authenticated sessions and scoped credentials.** The baseline X25519
   exchange has no peer authentication. Bind credentials, application protocol,
   audience, ephemeral keys and roles to an authenticated transcript, with key
   confirmation before reporting a connection. Require an explicit opt-in for
   anonymous development connections. Use an established handshake construction;
   verify it against independent vectors/implementations, not only self-roundtrips.
2. **Admission and resumption lifecycle.** A request consumed its token
   before key proof, and completion did not recheck credential expiry. A captured
   resume request can spend a session without answering a fresh server challenge.
   Commit single-use state only after proof, preserve it on rejected attempts,
   make retransmission idempotent, and test restart/expiry/fallback behavior.
   Ignore unauthenticated terminal control messages: a forged plaintext denial
   cancelled a pending connect, and a plaintext acceptance can report a
   connection after an untrusted challenge.
3. **Configuration invariants.** Baseline validation accepted NaN connection
   timeouts, negative handshake timeouts, infinite send rates, a zero request
   budget, and `INT_MAX` handshake retries (whose `+ 1` later overflows). Review
   all public rate/timer/retry/MTU inputs and reject values that cannot be honored.
4. **Observable socket and queue failures.** Baseline `hostTick` discarded send failures and
   treats hard receive errors like an empty socket. Broadcast discarded each peer's
   queue-rejection result. Expose bounded, actionable results and counters without
   changing a queued-send acknowledgement into a promise of remote delivery.
5. **Host integration.** Add address resolution/formatting for hostname and IP
   endpoints, with resolution outside the tick loop. Provide host-level reconnect
   and shutdown paths using the same routing/error handling as normal sends.
   Make connection queries reflect their stated lifecycle state.
6. **Qualification and examples.** Exercise the secure public API using real UDP
   sockets and repeatable loss, delay, duplication and reordering. Cover mixed
   client/server protocol versions, credential scopes and retransmitted handshake
   messages. Update examples, installed-consumer checks, wire/API migration notes
   and CI, including native Linux ARM64. Record tested load profiles rather than
   inventing a player-capacity guarantee.

## Audit evidence

- Current `main` matches `origin/main`; no open GitHub issues were returned.
- Fresh Debug build with warnings as errors, standalone headers and ODR checks
  passed on macOS ARM64. All 27 CTest targets passed: 26 in the sandbox, with the
  real-socket roundtrip rerun successfully outside the socket-restricting sandbox.
- Local probes reproduced each configuration acceptance listed above, forged
  denial/acceptance behavior, token consumption before connection, and admission
  after expiry during an in-flight handshake. Probe source is under ignored
  `build/readiness_probe.cpp`; permanent regression tests belong with the fixes.
- The existing nine-job hosted CI pass qualifies the previous repair, not the
  forthcoming authentication implementation.

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
- Hosted CI adds native `ubuntu-24.04-arm` alongside GCC, Clang, MSVC, sanitizers and
  installed consumers. Hosted results belong to the pull request's exact commit.

No Orivella game server or OCI listener is deployed by these library tests.

## Completion boundary

The intended result is a reviewed transport release ready for Orivella's
authoritative-server integration and first authenticated OCI staging playtest.
Application schemas, input prediction/reconciliation, game persistence, identity
providers, matchmaking and fleet orchestration remain application/service work.
Future defects and measured performance needs can still justify library changes.

Security design references: [Noise protocol framework](https://noiseprotocol.org/noise.html)
and [TLS 1.3 authentication/key confirmation](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4).
Selecting a standard construction does not by itself validate its integration.
