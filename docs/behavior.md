# Behaviour reference

Current behaviour of the transport, for when you hit it and want the detail. The README's Trade-offs
section carries what you need before adopting aether; this is the rest.

## Handshake

Connecting costs three round trips. The stateless retry cookie always runs rather than engaging only
once the half-open table fills, because a path that engages only under attack is untested when the
attack arrives. Reconnects skip it and stay 0-RTT.

A connection request datagram is zero-padded to at least the size of the retry it draws, so the reply
is never larger than the request. A shorter request gets no reply at all: the server would otherwise
be a bandwidth multiplier pointed at whatever source address the request claimed. Clients pad
automatically, so this only matters to another implementation of the wire format.

A fast reconnect is a 0-RTT resume and inherits the usual 0-RTT cost: an attacker who captures a live
resume request can replay it and beat the real client to it. Closing that needs a challenge round
trip, which is what 0-RTT exists to avoid. Two things bound it. The session master ratchets on each
accepted resume, so captured bytes authenticate at most once. And a resumed connection may send only
three times what it has received until a packet decrypts from its address, so a resume replayed with
a forged source cannot aim the server's output at a third party. The real client lifts that cap with
its first packet.

Connection migration costs one round trip: a new address must echo an encrypted challenge before the
connection follows a peer there. Decryption alone proves the sender holds the key, not that it is
reachable where it claims to be.

## Delivery

A reliable-ordered channel's ordering is bounded by `orderedBufferTimeout`. A gap that never fills is
eventually skipped rather than stalling the channel forever, and those sequences become a permanent
hole.

`maxReceiveBufferSize` is a per-collection capacity, not a standing queue depth. `peerProcess` hands
every buffered message to the application each tick, so occupancy outlives a tick only if you drive
`Connection` directly and skip that collection.

The receive window is advertised once as the connection comes up, then again when the figure moves by
a quarter of the buffer or the receiver becomes restricted, and repeated on a 250ms persist timer
until a header acknowledges it. A link whose receiver keeps up costs one flow-control packet for the
whole session.

## Sizing

`config.mtu` (default 1200) is the floor everything is sized against. Path-MTU discovery raises the
usable datagram size up to `mtuProbeCeiling` (default 1500), but that headroom feeds message
coalescing only. Fragmentation stays chunked at the floor, so a path that shrinks back can never
strand a fragmented message.

## Decoding

Decoding a struct from the wire is capped at `Reader::allocBudget`, 8MB by default, of resident
objects. Wire length bounds how many elements a container can claim but not what they cost in memory,
since one wire byte can materialize an element of any size. Raise it for genuinely large payloads,
lower it to tighten the bound on untrusted input.

## Clock sync

Cristian's algorithm assumes the two one-way delays are equal. An asymmetric path biases the offset by
half the difference between them: 5ms out and 145ms back reads exactly 70ms off, where a symmetric
path has no error at all.

`clockOffsetErrorMs` reports the bound, which is half the recent-best round-trip. That best decays
upward toward the prevailing RTT rather than holding a lifetime minimum, so it stays honest as a path
changes instead of quoting a tightness a stale sample once had. Check it before doing lag
compensation: a large bound means the shared timeline is a guess.
