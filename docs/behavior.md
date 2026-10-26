# Behavior reference

Limits, defaults, and application obligations behind the API in the [README](../README.md).
`NetworkConfig` and `ChannelConfig` fields are named without their struct; times are in
milliseconds. [Authentication](authentication.md) specifies the session protocol.

## Connections

Connection requests pass a per-source rate limit first: `rateLimitPerSecond` (default 10 per
second), keyed by source host rather than port. A new connection takes three round trips.
`maxPending` (default 256) caps handshakes in progress and `maxClients` (default 64) caps
connections. A client retries its request up to `connectionRequestMaxRetries` (default 5) times
within `connectionRequestTimeoutMs` (default 5000).

A connection that receives nothing for `connectionTimeoutMs` (default 10000) drops with
`DisconnectReason::Timeout`, and a side that has sent nothing for `keepaliveIntervalMs` (default
1000) sends a keepalive. A disconnect is repeated up to `disconnectRetries` (default 3) times,
`disconnectRetryTimeoutMs` (default 500) apart, while the host keeps ticking. Until it finishes,
the disconnecting peer still holds an admission slot, although connection queries such as
`peerCount` and `peerIsConnected` count only connected peers.

Timeouts arm a resume cache of `maxResumableSessions` entries (default 64; zero disables
resumption). Entries expire after 30 seconds, and a session that times out while the cache is full
needs a fresh credential.

Anonymous connections (`allowUnauthenticated`) encrypt traffic after an unauthenticated X25519
exchange. They do not protect against an active man in the middle, and resuming one does not add
authentication.

## Address migration

When a peer's packets arrive from a new address, the host finds the connection by the session
routing ID in the packet header, authenticates the packet, and sends an encrypted path challenge to
the new address. The connection moves only after that address answers. The host then reports
`PeerEvent::Migrated` with `peer` set to the old ID and `other` to the new one; later events and
sends use the new address. A forged routing ID or a replayed packet cannot move a connection, and a
connection that has just moved cannot move again for 5 seconds. Set
`enableConnectionMigration = false` to turn migration off.

## Delivery and backpressure

A reliable ordered channel delivers in order or fails. `orderedBufferTimeout` (default 0) bounds
how long a gap may stay open: zero waits for retransmission or a connection failure, and a positive
value fails the channel rather than skipping the missing message. A reliable message still
unacknowledged after `maxReliableRetries` (default 10) retransmissions fails the channel once its
last acknowledgement deadline passes. A failed channel disconnects the peer with
`DisconnectReason::DeliveryFailed`.

When a channel's send buffer is full, `hostSend` returns an error whose `channelError` is
`ChannelError::BufferFull`. A reliable channel holds at most `messageBufferSize` (default 256)
queued or unacknowledged messages and never drops one to make room; an unreliable channel drops its
oldest queued message unless `blockOnFull` is set. Delivered messages wait in a buffer of
`maxReceiveBufferSize` (default 8192) per channel until collected. `hostTick` and `peerProcess`
collect them into events every tick; code that drives a `Connection` directly must call
`receiveMessage` itself. A receiver with no room leaves a reliable message unacknowledged, and the
sender retransmits it.

A message larger than one datagram is split into at most 255 fragments.
`maxFragmentableMessage(config)` returns the largest message the configured `mtu` allows, and
`validateConfig` rejects a channel `maxMessageSize` above it or a `maxReassemblyBufferSize` too
small to hold one such message. The receiver reserves a reliable message's whole assembly before
acknowledging any of its fragments. A reliable assembly that receives no fragment for
`fragmentTimeoutMs` (default 5000) fails the connection with `DeliveryFailed`; unreliable partial
messages can be evicted or expire.

## Sizing and socket intake

`mtu` (default 1200, valid from 576 to 65507) is the UDP payload size the transport is sized and
validated against. Path-MTU probing can raise the usable datagram size up to `mtuProbeCeiling`
(default 1500), and that extra room is used only to coalesce messages; fragments stay sized to
`mtu`. `mtuProbeCeiling` must be at least `mtu`, so raise it as well when setting `mtu` above 1500.
Setting it equal to `mtu`, or `enableMtuDiscovery` to false, turns probing off.

Each `hostTick` reads at most `receiveBudget.maxDatagrams` (default 256) datagrams and
`receiveBudget.maxBytes` (default 256 KiB, minimum 64 KiB) from the socket, counting malformed and
empty datagrams. A datagram that would cross the byte budget is discarded, and the rest stay queued
for the next tick. The budget bounds socket intake, not total tick time.

## Rendezvous

A rendezvous server is a `RendezvousServer` driven by `rendezvousTick` on its own UDP socket. Two
hosts that call `hostJoinRoom` with the same room ID are paired: one connects and the other sends
hole-punch datagrams. Both hosts must set `allowUnauthenticated = true` and no `tokenKey`, since a
rendezvous server pairs peers but issues no credentials; otherwise `hostJoinRoom` returns
`ConnectError::AuthenticationRequired`. If they have not connected after `Host::punchTimeoutMs`
(default 5000), both relay through the server. Relayed packets carry a 9-byte wrapper, so leave
that headroom when choosing `mtu` for a relay path. The server accepts at most 10 datagrams per
second from each source host, relayed traffic included, so a relayed connection carries at most 10
packets per second in each direction; raise the server's `limiter.maxRequestsPerSecond` for
real-time traffic. Waiting registrations and idle relay sessions expire after 5 minutes.

Room IDs act as bearer credentials: anyone registering the same ID learns its partner's public
address. Generate unguessable room IDs and distribute them through your own authenticated service.
Pairing does not authenticate a user's account.

## Decoding untrusted data

`Reader::allocBudget` (default 8 MiB) limits the container elements and string bytes one decode may
allocate; allocator overhead and capacity growth are not counted. `Reader::workBudget` (default
1,048,576) limits recursive value visits, which also bounds empty aggregates that occupy no wire
bytes. Lower both to fit the messages you accept. A varint outside the destination integer's range
fails the decode.

## Clock sync

Connected peers exchange time-sync pings every second. `clockOffsetMs(connection)` estimates the
remote clock minus the local clock from the midpoint of a round trip, so unequal one-way delays
bias it by half their difference. `clockOffsetErrorMs(connection)` bounds that estimate's error as
of the latest sample, assuming nonnegative network delays and an offset that held still during the
round trip. It cannot bound later drift or a clock step, and it is infinite before the first sample.
`ClockSync::lastSampleTimeMs` is the local `MonoTime`, in milliseconds, when the latest sample
arrived; subtract it from the current time for the sample's age. For a host, the connection is
`host.peer.connections.at(aether::PeerId{address})`.

## Metrics and socket errors

`NetworkStats::packetsSent` and `bytesSent` count datagrams placed in the send queue, not socket
transmissions or receipt. The `Socket` counters record actual socket I/O. `sendTo` and `recvFrom`
return a byte count or -1 and set `lastSendError` or `lastReceiveError`: would block, message too
large, invalid address, closed socket, or a native system error. An empty receive queue is not
counted as an error.

`hostTakeDiagnostics` returns up to 32 socket failures and 32 per-peer broadcast rejections
recorded since the last call, plus counts of any omitted. Records accumulate between calls,
including from host calls made outside `hostTick`. `peerBroadcast` returns its rejections directly.

## Address resolution

`resolveAddresses` blocks, so call it during setup or on a worker thread, never in the tick. It
returns up to 16 unique addresses in system preference order and keeps IPv6 scope IDs. It does not
race connection attempts across addresses; the application chooses an address and retries.
`addressToString` formats a numeric `address:port`, bracketing IPv6, without reverse DNS.
