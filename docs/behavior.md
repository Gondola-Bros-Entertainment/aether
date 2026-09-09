# Behavior reference

This describes the 0.2 implementation. [Authentication](authentication.md) specifies
the session protocol and its application trust boundary.

## Handshake and resumption

A new authenticated connection takes three round trips: request/retry cookie,
cookied request/Noise reply, then client confirmation/server acceptance. The server
checks credential scope and the first Noise authenticator before generating a cookie.
A cookie precedes allocation of a pending slot and server X25519 work. Per-source
rate limits apply to all requests and are keyed by host, not source port. Client
challenge DH work is limited to three attempts per configured retry interval.

The concrete Noise NNpsk0 handshake uses X25519, ChaCha20-Poly1305 and SHA-256/HKDF.
The library matches independent Cacophony handshake, transcript and transport vectors,
plus RFC 7748, 8439, 4231 and 5869 primitive vectors. Cookies prove return reachability;
the credential PSK authenticates the transcript. The server only consumes a token after
fresh client confirmation and a second expiry/capacity check. The client reports a
connection only after authenticating the matching server acceptance. Secure pending
sessions ignore plaintext acceptance, denial and disconnect packets.

Timeout resumption uses the cached session secret as a new PSK, fresh ephemeral keys,
a fresh server challenge and confirmation in both directions. The old cached generation
is consumed only after proof; a captured request cannot win a replay race or recreate
traffic keys. Identity and application claims survive. There is no 0-RTT application
traffic. Unknown remote resume state falls back to a supplied fresh credential after
the local attempt timeout; unauthenticated denial cannot force fallback.

`maxResumableSessions` bounds the timeout cache (default 64; zero disables it). Cache
entries expire after 30 seconds. Full cache capacity leaves additional dropped sessions
requiring a fresh credential. Explicit disconnects are not resumable. A successful
resume creates a new generation; original credential expiry gates initial admission,
not the lifetime of the established session or its short resume window.

Anonymous development/P2P connections use the previous unauthenticated X25519 exchange
only when explicitly enabled. A token-gated host never admits an anonymous fallback.
Anonymous initial exchange does not protect against an active intermediary; its later
resume cannot retroactively establish identity. `hostJoinRoom` requires anonymous
opt-in: its room/pairing service is not a credential issuer.

Address migration selects a connection by session routing ID, verifies its packet tag,
and completes an encrypted path challenge before moving state. A forged routing ID or
replayed packet does not authorize migration. Packet headers are associated data and
a sliding window rejects replayed datagrams. Randomness comes from the operating system.

Replay-validator state persists until actual token expiry; exhaustion fails admission.
Applications preserve that state or rotate the sealing key after loss. Sharing an issuer
key and audience across independent validators does not establish global single use.

## Delivery and backpressure

Reliable ordered channels preserve order until delivery or explicit failure. `orderedBufferTimeout`
defaults to zero, disabling a separate gap deadline. A positive deadline makes an unresolved gap
fail the channel; it never skips the missing message. Retry exhaustion waits through the final
attempt's acknowledgement deadline before failing. `NetPeer` reports a `DeliveryFailed` disconnect.

Reliable unordered delivery tracks a contiguous receive frontier and a bounded window beyond it.
Senders backpressure before an outstanding reliable message spans that sequence window. Initial
sequence zero is valid in both sequenced modes; reset clears sequence initialization. Sequenced
modes intentionally discard messages superseded by a newer received sequence.

Acknowledged reliable fragments reserve their complete assembly capacity. Another message cannot
evict that reservation. A completed assembly facing channel backpressure is retained for retry.
An unrecoverable partial-assembly timeout fails the connection. Lower-level best-effort assembly
may evict or expire unreserved partial messages.

`maxReceiveBufferSize` limits messages waiting for collection. `peerProcess` collects them into its
returned events each tick; applications driving `Connection` directly must collect them themselves.
`hostSend` reports local queue rejection, not remote processing. Application-level acknowledgements
are still needed when a caller requires confirmation that a command was applied.

Receive credit is advertised on connection, when capacity changes by a quarter of the buffer, or
when the receiver becomes restricted. Unacknowledged updates repeat on a 250 ms persist timer.

## Resource bounds and sizing

`receiveBudget.maxDatagrams` and `receiveBudget.maxBytes` default to 256 and 256 KiB per socket tick.
Malformed and empty datagrams consume the datagram budget. A datagram crossing the remaining byte
budget is discarded before CRC validation or allocation; later datagrams remain queued. This
bounds socket intake, not total tick time. Connection count, queued work, and application scheduling
also affect tick cost. Aether does not start a receive thread.

`config.mtu` defaults to 1200 bytes and is the sizing floor. The supported UDP payload
ceiling is 65507 bytes for both IP families; normal internet paths need much smaller values. Path-MTU probes can raise the usable
datagram size up to `mtuProbeCeiling` (default 1500), but this headroom is used for coalescing.
Fragments remain sized to the floor so a drop in discovered MTU does not strand an assembly.

`maxFragmentableMessage(config)` computes the message ceiling from the floor and 255-fragment wire
limit. `validateConfig` rejects channel message sizes above that ceiling or assembly budgets too
small to reserve a maximum-sized message. Large messages are paced across ticks; they do not need
to fit in one send-rate bucket. Send-buffer and sequence-window caps make backpressure explicit.

Rendezvous relay requests add a 9-byte wrapper. Leave that headroom when choosing MTU settings for
a relay path. Room IDs act as bearer credentials: a matching registrant learns its partner's public
address. Applications must generate unguessable room IDs and distribute them through their own
authenticated service. Rendezvous pairing does not authenticate a user's account.

## Decoding and replication

`Reader::allocBudget` charges container element storage and string bytes, with an 8 MiB default.
It is not an exact heap ceiling: allocator overhead and container capacity growth may add memory.
Up-front vector reserves are separately limited.

`Reader::workBudget` limits recursive value visits to 1,048,576 by default. Empty aggregates use
zero wire bytes but still consume decode work. Tune both budgets for accepted message shapes.
Varint values outside the destination integer type's range fail before narrowing.

The aggregate codec supports up to 32 members. Nested aggregates and supported containers recurse;
the field ladder binds members directly using structured bindings. Raw C-array fields are unsupported.
The codec does not transmit a schema version or field names. Both endpoints must agree on types and
member order. A changed field carries its complete value, including complete changed vectors.

`DeltaTracker` only promotes a baseline after `deltaOnAck`. The application must send that
acknowledgement after successful `deltaDecode` and storage at the receiver, and provide matching
snapshot sequence IDs. Receiving an outer packet is insufficient if reconstruction failed.
`maxBaselineAge` enables full-state fallback when acknowledgements stall; setting it to zero or
less disables that recovery. `noBaseline` is a reserved sequence value, not a usable baseline ID.

## Clock sync

The offset estimate uses the midpoint of a local round trip and the remote reply timestamp.
Unequal one-way delays bias that midpoint estimate by half their difference.

`clockOffsetErrorMs` includes the distance between the smoothed estimate and latest measured
offset, plus half that measurement's RTT. This accounts for smoothing lag after an offset change.
The bound applies at the latest measurement, assuming nonnegative network delays and an offset
constant during that round trip. It cannot bound future drift or a clock step within that trip.
`ClockSync::lastSampleTimeMs` exposes sample age. Before any sample, the error bound is infinite.

## Metrics and socket errors

Connection `packetsSent` counts framed datagrams placed in the outgoing queue, including control
packets. `bytesSent` counts their bytes. These counters do not prove socket transmission or receipt.
Socket counters separately record successful local I/O.

`sendTo` and `recvFrom` retain byte-count/`-1` results and set `lastSendError` or
`lastReceiveError`: would-block, oversize, invalid address, closed socket or native
system error. Socket send/receive error counters are distinct from successful I/O;
a receive would-block is a normal empty queue. Reliable retries can recover transient
send failures; a local success still does not prove remote receipt.

`hostTakeDiagnostics` drains bounded records for socket failures and per-peer broadcast
rejections (32 of each, plus omitted counts). They accumulate between calls, including
calls outside the tick. `peerBroadcast` directly returns its per-peer rejections.
`hostShutdown` uses the same direct/relay send path, and `closeHost` clears sessions.
Connection queries count only the Connected state; disconnecting entries may still
occupy admission slots while their shutdown completes.

`resolveAddresses` performs blocking DNS/numeric resolution outside the tick. Results
retain system preference order, preserve IPv6 scope IDs, and contain at most 16 unique
endpoints. `addressToString` produces numeric IPv4 or bracketed IPv6 endpoints without
reverse DNS. Applications choose and retry appropriate addresses; the library does
not run background resolver threads or promise Happy Eyeballs connection racing.
