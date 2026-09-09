# Behavior reference

This describes the current implementation. Authentication gaps are listed explicitly; they are
not guarantees provided by the current protocol.

## Handshake and resumption

A new connection takes three round trips: request/retry cookie, cookied request/key challenge,
then key response/acceptance. The cookie runs on every new connection before allocating a pending
slot or generating an ephemeral keypair. Requests are padded to at least the retry response size;
shorter requests receive no retry. Per-source rate limits are keyed by host, not source port.
Client challenge processing also bounds expensive key attempts, including rejected public keys.

The exchange uses X25519 to derive directional ChaCha20-Poly1305 traffic keys. Packet headers
are authenticated as associated data, and a sliding window rejects packet replays. Randomness
comes from the operating system. Crypto tests include RFC 7748 and RFC 8439 vectors.

**The exchange is unauthenticated.** A connect token authenticates its issuer's sealed claims,
but possession of those bearer bytes is not bound to a client's handshake key. Cookies prove
return reachability, not peer identity. An active intermediary is outside the current handshake's
security guarantees. The planned repair must bind credentials and protocol context to the key
exchange and confirm possession before admitting the session.

Current resumption skips the new-connection handshake. It authenticates a request with the cached
session master and ratchets that master on acceptance. This prevents reuse after acceptance but
does not prevent a captured valid request from winning a race against the legitimate client.
Fresh challenge proof before committing a resume remains required work. Until an encrypted packet
arrives from the resumed address, server output is capped at three times bytes received.

Address migration uses the explicit session routing ID to select a candidate connection, verifies
the packet's authentication tag, and requires an encrypted path challenge round trip before moving
the connection. A forged routing ID does not authorize migration.

Connect-token replay state is retained until actual expiry. Storage exhaustion rejects new tokens
rather than evicting live replay records. Its scope is one admission authority; applications must
preserve the validator state or rotate the sealing key after state loss. The current token format
does not bind an application audience or protocol ID. Do not share a sealing key across unrelated
trust domains.

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

`config.mtu` defaults to 1200 bytes and is the sizing floor. Path-MTU probes can raise the usable
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

The low-level `sendTo` returns a byte count or `-1`. The current `hostTick` adapter discards that
return value; it does not emit socket-send error events. Reliable retries can recover transient
loss, but the adapter does not distinguish a local send failure from network loss.
