#pragma once

#include "aether/peer_state.hpp"
#include "aether/peer_auth.hpp"
#include "aether/peer_connect.hpp"

namespace aether {

// --- handshake handlers ---
inline std::vector<PeerEvent> handleNewConnectionRequest(NetPeer& peer, const PeerId& pid, const Bytes& body, MonoTime now) {
    (void)body;
    if (!peer.config.allowUnauthenticated || peer.config.tokenKey) return {};
    if (static_cast<int>(peer.pending.size()) >= peer.config.maxPending) { ++peer.rateLimitDrops; return {}; }
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::ServerFull), pid);
        return {};
    }
    PendingConnection pend;
    pend.direction  = ConnectionDirection::Inbound;
    pend.serverSalt = secureRandom64();   // anti-spoof challenge salt, from the CSPRNG (not the game PRNG)
    pend.createdAt  = now;
    pend.lastRetry  = now;
    genEphemeralKeypair(pend.ephemeralPriv, pend.ephemeralPub);   // server's ephemeral X25519 keypair
    pend.ephemeralReady = true;
    peer.pending[pid] = pend;
    queueControlPacket(peer, PacketType::ConnectionChallenge, encodeSaltAndKey(pend.serverSalt, pend.ephemeralPub), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionRequest(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    // One per-source rate gate covering every reflective reply below (the idempotent Accepted, the
    // resume Accepted, the challenge resend, and a fresh request via handleNewConnectionRequest, its
    // sole caller, which trusts this gate) -- so a spoofed source cannot bounce an amplified stream off
    // the server.
    if (!rateLimiterAllow(peer.rateLimiter, sockAddrToKey(pid.addr, peer.addrHashSeed), now)) { peer.rateLimitDrops += 1; return {}; }
    const auto req = decodeConnectionRequest(pkt.payload);
    if (!req) return {};   // malformed framing: not something a retry would fix
    if (!req->body.empty() && req->body[0] == authEnvelopeTag)
        return handleAuthRequest(peer, pid, *req, now);
    if (!peer.config.allowUnauthenticated || peer.config.tokenKey) return {};
    // Return-routability gate. Everything past this point either commits server state (a pending slot
    // plus an X25519 keypair) or emits a reply larger than the request that asked for it, so none of it
    // happens for an address that has not echoed a cookie only this server could have minted. Minting
    // one costs a single AEAD tag and remembers nothing -- but it is still retryDatagramBytes sent to
    // an address that has proven nothing, so a request too small to have paid for its own reply gets
    // no reply at all (see minConnectionRequestBytes; a real client pads up to it).
    if (!retryCookieValid(peer.cookieSecret, pid.addr, req->cookie, now)) {
        if (requestDatagramBytes(pkt.payload) < minConnectionRequestBytes) return {};
        queueControlPacket(peer, PacketType::ConnectionRetry, makeRetryCookie(peer.cookieSecret, pid.addr, now), pid);
        return {};
    }
    if (const auto live = peer.connections.find(pid); live != peer.connections.end()) {
        if (!live->second.handshakeReceipt) queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid);
        return {};
    }
    if (const auto it = peer.pending.find(pid); it != peer.pending.end()) {
        if (it->second.auth) return {};
        if (it->second.direction == ConnectionDirection::Inbound) {   // resend the challenge we already committed to
            queueControlPacket(peer, PacketType::ConnectionChallenge, encodeSaltAndKey(it->second.serverSalt, it->second.ephemeralPub), pid);
            return {};
        }
        // Simultaneous connect: both ends called peerConnect on each other, so the pending here is one
        // WE opened and it holds no challenge material -- peerConnect mints a clientSalt and nothing
        // else. Answering from it would send a zero salt and an all-zero public key, which x25519Shared
        // refuses, leaving the peer a pending it can never key. Resolve the roles instead, on the one
        // ordering both ends compute the same way: the lower address takes the accepting role, the
        // higher stays the client and keeps asking (its request is already retrying, so it needs no
        // reply here).
        if (!(peerIdFromAddr(peer.localAddr) < pid)) return {};
        auto       events = handleNewConnectionRequest(peer, pid, req->body, now);
        const auto pend   = peer.pending.find(pid);
        // The pending is replaced only if that admitted the request; if a cap or the token turned it
        // away, ours is still here, still outbound, still retrying and still due to report its timeout.
        // Either way the caller that asked for this connection is never left without a pending to hear
        // about -- which is also why localInitiated survives the role change.
        if (pend != peer.pending.end() && pend->second.direction == ConnectionDirection::Inbound)
            pend->second.localInitiated = true;
        return events;
    }
    return handleNewConnectionRequest(peer, pid, req->body, now);
}

// Client side: the server handed us a cookie instead of a challenge. Store it and re-send the same
// request carrying it.
//
// This must NOT spend the retransmission budget. A ConnectionRetry is unauthenticated (it necessarily
// precedes any key), so an off-path attacker spoofing the server's address could send
// connectionRequestMaxRetries of them, exhaust retryCount, and kill the connect attempt outright --
// retryPendingConnections would never fire again and the client would report a timeout. A cookie
// handoff is a protocol step, not a retransmission, so it gets its own small bound: enough for the
// server to rotate its cookie secret across an epoch boundary, nowhere near enough to loop. Repeating
// a cookie we already hold is ignored, so a replayed Retry costs nothing at all.
inline constexpr int maxCookieHandoffs = 3;

inline std::vector<PeerEvent> handleConnectionRetry(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    if (pkt.payload.size() != retryCookieSize) return {};
    const double interval = peer.config.connectionRequestTimeoutMs
        / static_cast<double>(peer.config.connectionRequestMaxRetries + 1);
    if (elapsedMs(it->second.cookieBudgetAt, now) >= interval) {
        it->second.cookieBudgetAt = now;
        it->second.cookieHandoffs = 0;
    }
    if (it->second.cookieHandoffs >= maxCookieHandoffs) return {};
    if (it->second.retryCookie == pkt.payload) return {};   // same cookie again -> nothing new to present
    it->second.retryCookie = pkt.payload;
    it->second.cookieHandoffs += 1;
    it->second.lastRetry   = now;
    queueControlPacket(peer, PacketType::ConnectionRequest,
                       encodeConnectionRequest(it->second.retryCookie, pendingRequestBody(it->second)), pid);
    return {};
}
// In anonymous mode a challenge is unauthenticated, so any
// number of them can arrive from the server's claimed address, in any order. The salt we echo and the
// key we derive MUST come from the same one: echoing a later challenge's salt while the session key
// still derives from an earlier challenge's public key produces two peers that both report Connected
// and neither of which can decrypt the other. So a challenge is committed to as a unit -- salt, peer
// public key and shared secret together -- and a later challenge is either identical to the committed
// one (a retransmit, answered with the same response) or replaces it whole.
//
// Replacing means a fresh keypair and a fresh ECDH, which is real work per challenge, so it is bounded
// like the cookie handoff: enough for a server that legitimately re-challenges with new material,
// nowhere near enough to be a CPU sink for an off-path source spoofing the server's address.
inline constexpr int maxChallengeKeyAttempts = 3;

inline std::vector<PeerEvent> handleConnectionChallenge(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    if (it->second.auth) return handleAuthChallenge(peer, pid, pkt, now);
    const auto sk = decodeSaltAndKey(pkt.payload);
    if (!sk) return {};
    PendingConnection& pend = it->second;
    const bool committed = pend.ephemeralReady && pend.serverSalt == sk->first && pend.peerEphemeralPub == sk->second;
    if (!committed) {
        if (pend.challengeKeyAttempts >= maxChallengeKeyAttempts) return {};
        ++pend.challengeKeyAttempts; // Charge the expensive attempt even when the peer key is rejected.
        X25519Key priv{}, pub{};
        genEphemeralKeypair(priv, pub);
        const auto shared = x25519Shared(priv, sk->second);
        // The shared secret is captured; the private scalar has no further use, so it does not stay in
        // the pending table (which lives until the handshake completes or times out).
        detail::secureZero(priv.data(), priv.size());
        // Fail closed on a degenerate public key: a low-order point yields an all-zero shared secret
        // anyone can compute. Commit nothing -- not the salt, not the keypair, not the ready flag -- so
        // this pending stays unkeyed (and so unable to report Connected) and a genuine challenge
        // arriving afterwards can still key it.
        if (!shared) return {};
        pend.serverSalt        = sk->first;
        pend.peerEphemeralPub  = sk->second;
        pend.ephemeralPub      = pub;
        pend.sessionShared     = shared;
        pend.ephemeralReady    = true;
    }
    queueControlPacket(peer, PacketType::ConnectionResponse,
                       encodeConnectionResponse(pend.clientSalt, pend.ephemeralPub, pend.serverSalt), pid);
    return {};
}
inline std::vector<PeerEvent> handleConnectionResponse(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    if (!pkt.payload.empty() && pkt.payload[0] == authEnvelopeTag)
        return handleAuthResponse(peer, pid, pkt, now);
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Inbound) return {};
    if (it->second.auth) return {};
    const auto resp = decodeConnectionResponse(pkt.payload);
    if (!resp) return {};
    // Return-routability gate. A wrong echo is DROPPED silently -- no deny, and crucially the pending
    // survives: replying would make the server a reflector, and cancelling the pending would let
    // anyone who can guess an in-progress client's address abort its handshake. The real client's
    // request retry re-drives the same (retransmit-stable) challenge.
    if (resp->serverSaltEcho != it->second.serverSalt) return {};
    const std::uint64_t clientSalt = resp->clientSalt;
    if (clientSalt == 0 || clientSalt == it->second.serverSalt) {
        removePending(peer, pid);
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::InvalidChallenge), pid);
        return {};
    }
    // Re-check the client cap here, not only at the request: several handshakes admitted while there was
    // room can complete in the same tick, and inserting unconditionally would take the connection table
    // past maxClients. maxPending bounds how far it could overshoot, but "bounded overshoot" is still an
    // exceeded limit, so the last arrivals are denied ServerFull instead.
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        removePending(peer, pid);
        queueControlPacket(peer, PacketType::ConnectionDenied, encodeDenyReason(DenyReason::ServerFull), pid);
        return {};
    }
    // Fail closed on a degenerate public key: a low-order point yields an all-zero shared secret that
    // anyone can compute, so there is no session to bring up. Drop the pending rather than key from it.
    const auto shared = x25519Shared(it->second.ephemeralPriv, resp->pub);
    detail::secureZero(it->second.ephemeralPriv.data(), it->second.ephemeralPriv.size());   // used once, done
    if (!shared) { removePending(peer, pid); return {}; }
    Connection conn = newConnection(peer.config, clientSalt, now);
    conn.playerId = it->second.playerId;   // the identity validated from the client's connect token (0 if auth off)
    applySessionKeys(conn, *shared, clientSalt, /*isServer=*/true);   // salt = the client's fresh salt
    touchRecvTime(conn, now);
    markConnected(conn, now);
    const std::uint64_t playerId = conn.playerId;
    // A pending this side opened (peerConnect) that resolved into the accepting role on a simultaneous
    // connect still reports Outbound: the caller asked for this connection, and which end ran the
    // challenge is not something it asked about.
    const ConnectionDirection dir = it->second.localInitiated ? ConnectionDirection::Outbound : ConnectionDirection::Inbound;
    peer.connections[pid] = std::move(conn);
    peer.pending.erase(pid);
    queueControlPacket(peer, PacketType::ConnectionAccepted, {}, pid);
    return { evConnected(pid, dir, playerId) };
}
inline std::vector<PeerEvent> handleConnectionAccepted(NetPeer& peer, const PeerId& pid, const Packet& pkt, MonoTime now) {
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Outbound) return {};
    if (it->second.auth) return handleAuthAccepted(peer, pid, pkt, now);
    Connection conn = newConnection(peer.config, it->second.clientSalt, now);
    if (it->second.sessionShared) {
        applySessionKeys(conn, *it->second.sessionShared, it->second.clientSalt, /*isServer=*/false);
    }
    // Fail closed: never bring up an unkeyed connection, which would be a plaintext zombie. An
    // Accepted can reach an unkeyed pending several ways -- it can overtake the challenge that keys
    // us, the challenge can be lost, a reconnect can race its own resume-grace eviction, and being
    // cleartext it can simply be injected by anyone who knows the address pair. So refuse it and leave
    // the pending alone: the handshake that is still in flight completes normally afterwards, and if
    // nothing ever keys it, cleanupPending reports the timeout. Tearing down here would hand one
    // unauthenticated packet the power to abort any connect attempt.
    if (!conn.sendKey || !conn.recvKey) return {};
    touchRecvTime(conn, now);
    markConnected(conn, now);
    peer.connections[pid] = std::move(conn);
    peer.pending.erase(pid);
    return { evConnected(pid, ConnectionDirection::Outbound) };
}
// A keyed connection's Disconnect is authenticated + handled inline in handlePacket, so a Disconnect
// reaching the cold path is unauthenticated cleartext from an address holding no keyed connection.
// It changes nothing. It cannot take a connection down, and it must not be able to erase a half-open
// handshake either: that would let one spoofed packet abort any connect attempt, and abort it
// silently, since an erased pending is no longer there for cleanupPending to time out and report.
inline std::vector<PeerEvent> handleDisconnect(NetPeer&, const PeerId&) { return {}; }

// --- migration ---
inline std::uint64_t migrationTokenFor(const Connection& conn) noexcept { return conn.clientSalt; }
struct MigrationCandidate { PeerId oldPeer; std::uint64_t token = 0; };
// Address changes do not change session identity. Select only an exact routing-ID match;
// nearby or wrapped packet sequences from other connections cannot influence this lookup.
// An ambiguous ID fails closed. AEAD authentication and path validation still follow below.
inline std::optional<MigrationCandidate> findMigrationCandidate(const NetPeer& peer, const Packet& pkt, MonoTime) {
    std::optional<MigrationCandidate> match;
    for (const auto& [pid, conn] : peer.connections) {
        if (!conn.recvKey || conn.connectionId != pkt.header.connectionId) continue;
        if (match) return std::nullopt;
        match = MigrationCandidate{pid, migrationTokenFor(conn)};
    }
    return match;
}

// --- payload / fragment / migration dispatch ---
// Reserve a reliable message's entire assembly before acknowledging any piece. Completion stays
// retained through channel backpressure; only delivery (or an explicit disconnect) releases it.
inline bool handleFragment(NetPeer& peer, const PeerId& pid, ChannelId channel, ByteSpan data, MonoTime now) {
    auto connection = peer.connections.find(pid);
    if (connection == peer.connections.end()) return false;
    auto& conn = connection->second;
    const auto index = static_cast<std::size_t>(toInt(channel));
    if (index >= conn.channels.size() || conn.state != ConnectionState::Connected) return false;
    auto& ch = conn.channels[index];
    const auto header = readFragmentHeader(data.data(), data.size());
    const auto chunk = maxFragmentChunk(peer.config);
    if (!header || header->count == 0 || header->index >= header->count || chunk <= 0
        || static_cast<std::uint32_t>(header->messageId) >> 16 != index) return false;
    const auto size = data.size() - fragmentHeaderSize;
    if (size == 0 || size > static_cast<std::size_t>(chunk)
        || (header->index + 1 < header->count && size != static_cast<std::size_t>(chunk))) return false;
    const SequenceNum seq{static_cast<std::uint16_t>(header->messageId)};
    if (ch.failure) return false;
    if (channelHasReceived(ch, seq)) return true; // A missing fragment ACK does not require assembling it again.
    auto& assembler = peer.fragmentAssemblers.try_emplace(pid,
        newFragmentAssembler(peer.config.fragmentTimeoutMs, peer.config.maxReassemblyBufferSize, peer.config.maxFragments)).first->second;
    const auto maxInner = static_cast<std::size_t>(ch.config.maxMessageSize) + channelWireSeqBytes;
    if ((static_cast<std::size_t>(header->count) - 1) * static_cast<std::size_t>(chunk) >= maxInner) return false;
    const auto reservation = channelIsReliable(ch)
        ? std::min(maxInner, static_cast<std::size_t>(header->count) * static_cast<std::size_t>(chunk))
            + header->count * fragmentOverheadBytes
        : 0;
    auto received = acceptFragment(assembler, data.data(), data.size(), now, reservation);
    if (!received.accepted || !received.message) return received.accepted;
    const auto inner = decodeChannelSeq(*received.message);
    if (!inner || inner->first != seq || inner->second.size() > static_cast<std::size_t>(ch.config.maxMessageSize)) {
        disconnect(conn, DisconnectReason::ProtocolMismatch, now);
        return false;
    }
    if (!receiveIncomingPayload(conn, channel, seq, Bytes(inner->second.begin(), inner->second.end()), now)) return false;
    releaseFragment(assembler, header->messageId);
    return true;
}
// Route one channel-wire ([channel/fragment byte][seq][data]) into the connection's channels. Takes a
// span into the decrypted scratch; the single owned copy is materialized here, where a message is handed
// off to persist in the channel buffer -- everything upstream of this point is alloc-free. Returns
// whether the wire was accepted, which decides whether the carrying packet may be acked.
inline bool receiveChannelWire(NetPeer& peer, const PeerId& pid, Connection& conn, ByteSpan wire, MonoTime now) {
    if (wire.empty()) return true;
    const auto [channel, isFragment] = decodePayloadHeader(wire[0]);
    const ByteSpan rest = wire.subspan(1);
    if (isFragment) return handleFragment(peer, pid, channel, rest, now);
    if (wire.size() < static_cast<std::size_t>(minPayloadSize)) return true;   // truncated wire, not a capacity problem
    if (const auto cs = decodeChannelSeq(rest))
        return receiveIncomingPayload(conn, channel, cs->first, Bytes(cs->second.begin(), cs->second.end()), now);
    return true;
}
// Route a decrypted payload (one wire, or a coalesced batch) and report whether ALL of it was accepted.
// A batch is all-or-nothing for acking purposes: if any message was refused the packet goes unacked, the
// sender retransmits every message it carried, and the ones that did land are recognized as duplicates.
inline bool routeDecryptedPayload(NetPeer& peer, const PeerId& pid, Connection& conn, PacketType ptype,
                                  ByteSpan payload, MonoTime now) {
    if (ptype != PacketType::PayloadBatch) return receiveChannelWire(peer, pid, conn, payload, now);
    bool accepted = true;
    forEachBatchWire(payload, [&](ByteSpan w) { accepted = receiveChannelWire(peer, pid, conn, w, now) && accepted; });
    return accepted;
}
// The AAD every decrypt on every path authenticates is the header EXACTLY as it arrived, so
// `wireHeader` points at the first packetHeaderBytes of the datagram rather than at anything
// re-serialized from parsed fields. This authenticates the wire version and session routing ID
// together with type, sequence, and ACK metadata.
inline std::vector<PeerEvent> handleMigration(NetPeer& peer, const PeerId& newPid, const Packet& pkt,
                                              const std::uint8_t* wireHeader, MonoTime now) {
    if (!peer.config.enableConnectionMigration) return {};
    // Gate the candidate scan + trial-decrypt behind the per-source rate limiter: an off-path attacker
    // must not be able to force an O(connections) scan + an AEAD-open per spoofed payload, and the
    // maxTrackedSources cap bounds the total even under a spoofed-source flood. A real migrating client
    // needs exactly one accepted attempt (it is keyed by the new address the moment it migrates).
    if (!rateLimiterAllow(peer.rateLimiter, sockAddrToKey(newPid.addr, peer.addrHashSeed), now)) { peer.rateLimitDrops += 1; return {}; }
    const auto cand = findMigrationCandidate(peer, pkt, now);
    if (!cand) return {};
    if (const auto it = peer.migrationCooldowns.find(cand->token);
        it != peer.migrationCooldowns.end() && elapsedMs(it->second, now) < migrationCooldownMs) return {};
    const auto connIt = peer.connections.find(cand->oldPeer);
    if (connIt == peer.connections.end() || !connIt->second.recvKey) return {};

    // KEY authentication: decrypting proves the sender holds the session key, so an off-path attacker
    // cannot forge this. It is necessary but NOT sufficient to move the connection -- a replayed genuine
    // packet decrypts just as well, and the source address is still unverified. The routing ID selects
    // the key; it is never the proof.
    const auto dec = decrypt(*connIt->second.recvKey, peer.config.protocolId, wireHeader, packetHeaderBytes,
                             pkt.payload.data(), pkt.payload.size());
    if (!dec || !replayAccept(connIt->second.recvReplay, dec->counter.value)) return {};

    // The payload is authentic, so deliver it on the connection where it already lives. Nothing about
    // this packet justifies moving that connection, so nothing moves: the reply path is unchanged until
    // the candidate address answers a challenge.
    Connection& conn = connIt->second;
    processIncomingAcks(conn, pkt.header, now);
    touchRecvTime(conn, now);
    const ByteSpan mpayload(dec->plaintext.data(), dec->plaintext.size());
    if (routeDecryptedPayload(peer, cand->oldPeer, conn, pkt.header.type, mpayload, now))
        recordReceivedPacket(conn, pkt.header);   // ack only what the channels took

    // Probe the candidate. One outstanding challenge per address, refreshed once it expires, and the
    // table is capped -- an attacker that can drive this path is already through the rate limiter, and
    // must not be able to grow it without bound.
    if (const auto ex = peer.pathValidations.find(newPid); ex != peer.pathValidations.end()) {
        if (elapsedMs(ex->second.sentAt, now) < pathValidationTimeoutMs) return {};   // one in flight already
        peer.pathValidations.erase(ex);
    }
    if (peer.pathValidations.size() >= maxPathValidations) return {};
    if (!conn.sendKey || conn.sendNonce.value == UINT64_MAX) return {};   // fail closed: never send unencrypted

    PendingPathValidation pv;
    pv.current = cand->oldPeer;
    pv.token   = cand->token;
    pv.sentAt  = now;
    secureRandomBytes(pv.challenge.data(), pv.challenge.size());   // unpredictable: the whole proof rests on this

    PacketHeader ch = createHeaderInternal(conn);
    ch.type = PacketType::PathChallenge;
    const NonceCounter nonce = conn.sendNonce;
    conn.sendNonce = NonceCounter{ nonce.value + 1 };
    conn.localSeq  = next(conn.localSeq);
    peer.sendQueue.push_back(RawPacket{ newPid,
        sealDatagram(*conn.sendKey, nonce, peer.config.protocolId, ch,
                     Bytes(pv.challenge.begin(), pv.challenge.end())) });
    peer.pathValidations[newPid] = pv;
    return {};   // no migration yet -- handlePathResponse completes it
}

// The candidate address echoed the challenge, so it demonstrably RECEIVES there and holds the key.
// That is the full proof migration needs, and only now does anything move.
inline std::vector<PeerEvent> handlePathResponse(NetPeer& peer, const PeerId& newPid, const Packet& pkt,
                                                 const std::uint8_t* wireHeader, MonoTime now) {
    const auto pv = peer.pathValidations.find(newPid);
    if (pv == peer.pathValidations.end()) return {};
    if (elapsedMs(pv->second.sentAt, now) >= pathValidationTimeoutMs) { peer.pathValidations.erase(pv); return {}; }
    const auto connIt = peer.connections.find(pv->second.current);
    if (connIt == peer.connections.end() || !connIt->second.recvKey) { peer.pathValidations.erase(pv); return {}; }

    const auto dec = decrypt(*connIt->second.recvKey, peer.config.protocolId, wireHeader, packetHeaderBytes,
                             pkt.payload.data(), pkt.payload.size());   // the wire bytes, as everywhere else
    if (!dec || !replayAccept(connIt->second.recvReplay, dec->counter.value)) return {};
    if (dec->plaintext.size() != pathChallengeBytes) return {};
    if (!detail::constTimeEq(dec->plaintext.data(), pv->second.challenge.data(), pathChallengeBytes)) return {};

    const PeerId oldPid = pv->second.current;
    const std::uint64_t token = pv->second.token;
    peer.pathValidations.erase(pv);

    Connection migrated = std::move(connIt->second);
    peer.connections.erase(connIt);
    resetTransportMetrics(migrated, now);
    peer.connections[newPid] = std::move(migrated);
    peer.migrationCooldowns[token] = now;
    if (const auto fa = peer.fragmentAssemblers.find(oldPid); fa != peer.fragmentAssemblers.end()) {
        peer.fragmentAssemblers[newPid] = std::move(fa->second);
        peer.fragmentAssemblers.erase(fa);
    }
    Connection& mconn = peer.connections[newPid];
    processIncomingAcks(mconn, pkt.header, now);
    touchRecvTime(mconn, now);
    recordReceivedPacket(mconn, pkt.header);
    return { evMigrated(oldPid, newPid) };
}

// Cold-path dispatch: control/handshake packets (cleartext) plus post-handshake packets from a peer we
// have no keyed connection for. A keyed connection's post-handshake traffic is decrypted and routed in
// handlePacket and never reaches here -- so Payload/PayloadBatch here is always a migration probe (which
// handleMigration authenticates by decryption and then answers with a path challenge), PathResponse is
// that challenge coming back, and TimeSync/Keepalive without a connection are noise.
inline std::vector<PeerEvent> handlePacketByType(NetPeer& peer, const PeerId& pid, const Packet& pkt,
                                                 const std::uint8_t* wireHeader, MonoTime now, PacketType ptype) {
    switch (ptype) {
        case PacketType::ConnectionRequest:   return handleConnectionRequest(peer, pid, pkt, now);
        case PacketType::ConnectionRetry:     return handleConnectionRetry(peer, pid, pkt, now);
        case PacketType::ConnectionChallenge: return handleConnectionChallenge(peer, pid, pkt, now);
        case PacketType::ConnectionResponse:  return handleConnectionResponse(peer, pid, pkt, now);
        case PacketType::ConnectionAccepted:  return handleConnectionAccepted(peer, pid, pkt, now);
        case PacketType::ConnectionDenied: {
            const auto pend = peer.pending.find(pid);   // only a connect WE initiated can be denied -- ignore a stray/spoofed deny
            if (pend == peer.pending.end() || pend->second.direction != ConnectionDirection::Outbound) return {};
            if (pend->second.auth) return handleAuthDenied(peer, pid, pkt);
            const DenyReason reason = decodeDenyReason(pkt.payload);
            removePending(peer, pid);
            return { evDisconnected(pid, denyToDisconnectReason(reason)) };
        }
        case PacketType::Disconnect:    return handleDisconnect(peer, pid);
        case PacketType::Payload:
        case PacketType::PayloadBatch:  return handleMigration(peer, pid, pkt, wireHeader, now);
        // The one packet type that is MEANT to arrive from an address we have no connection for: it is
        // the candidate answering our challenge, and it is what completes a migration.
        case PacketType::PathResponse:  return handlePathResponse(peer, pid, pkt, wireHeader, now);
        case PacketType::TimeSyncPing:
        case PacketType::TimeSyncPong:
        case PacketType::Keepalive:
        case PacketType::WindowUpdate:
        case PacketType::PathChallenge:
        case PacketType::MtuProbe:      return {};   // only meaningful on a keyed connection -> handled in handlePacket
    }
    return {};
}

// --- incoming packet handling: decrypt + anti-replay + route ---
// The keyed post-handshake path copies nothing: it reads the header in place, decrypts the ciphertext
// into a reused thread-local scratch, and routes the plaintext by span -- the single owned copy is
// materialized only where a message must outlive the packet (the channel buffer). Control/handshake
// packets and migration probes take the owned cold path below.
inline std::vector<PeerEvent> handlePacket(NetPeer& peer, const PeerId& pid, const Bytes& dat, MonoTime now) {
    Reader     r{ dat.data(), dat.size(), 0 };
    const auto header = readHeader(r);   // header only -- no payload copy
    if (!header) return {};
    const PacketType ptype = header->type;
    const int        bytes = static_cast<int>(dat.size());

    const auto connIt = peer.connections.find(pid);
    const bool keyed  = connIt != peer.connections.end() && connIt->second.recvKey.has_value();

    if (isPostHandshake(ptype) && keyed) {
        Connection&         conn   = connIt->second;
        if (header->connectionId != conn.connectionId) return {};
        const std::uint8_t* enc    = dat.data() + packetHeaderBytes;   // [counter:8][ciphertext][tag:16]
        const std::size_t   encLen = dat.size() - packetHeaderBytes;   // dat.size() >= packetHeaderBytes (readHeader checked)
        recordBytesReceived(conn, bytes, now);

        static thread_local Bytes scratch;                             // reused -> no per-packet plaintext alloc
        if (scratch.size() < encLen) scratch.resize(encLen);           // grows once; the span below is valid only for this packet
        const auto info = decryptInto(*conn.recvKey, peer.config.protocolId,
                                      dat.data(), packetHeaderBytes,   // the cleartext header, authenticated as AAD
                                      enc, encLen, scratch.data());
        if (!info) { conn.stats.decryptionFailures += 1; return {}; }
        if (!replayAccept(conn.recvReplay, info->counter.value)) return {};   // replayed or outside the window
        // Established sessions have already proven return reachability. This also lifts
        // the cap for explicitly constructed low-level unvalidated connections.
        if (!conn.pathValidated) markPathValidated(conn);
        const ByteSpan payload(scratch.data(), info->length);

        if (ptype == PacketType::Disconnect) {   // erases conn -- read the reason, then stop touching it
            const DisconnectReason reason = info->length == 0 ? DisconnectReason::Requested : parseDisconnectReason(scratch[0]);
            peer.connections.erase(pid);
            cleanupPeer(peer, pid);
            return { evDisconnected(pid, reason) };
        }
        processIncomingAcks(conn, *header, now);   // the peer's acks always land, whatever we do with the payload
        touchRecvTime(conn, now);
        switch (ptype) {
            case PacketType::Payload:
            case PacketType::PayloadBatch:
                // Ack this packet only if every message it carried was accepted. A refused message stays
                // unacknowledged, so the sender retransmits it instead of believing it was delivered.
                if (!routeDecryptedPayload(peer, pid, conn, ptype, payload, now)) return {};
                break;
            case PacketType::TimeSyncPing:
                if (payload.size() >= 8) sendTimeSyncPong(conn, getU64(payload.data()), now);   // echo our reply stamped with our clock
                break;
            case PacketType::TimeSyncPong:
                if (payload.size() >= 16)                                                       // fold the round-trip into the offset estimate
                    clockSyncObserve(conn.clockSync, static_cast<double>(getU64(payload.data())) / nsPerMs,
                                     static_cast<double>(getU64(payload.data() + 8)) / nsPerMs, static_cast<double>(now.ns) / nsPerMs);
                break;
            case PacketType::WindowUpdate:
                applyWindowUpdate(conn, *header, payload);   // malformed or reordered is ignored; the peer re-sends until acked
                break;
            case PacketType::PathChallenge:
                // Echo it straight back, encrypted. Answering proves we receive at this address; the
                // challenge is unpredictable, so no observer can answer on our behalf. It rides the
                // ordinary send queue because our view of the peer's address has not changed.
                if (payload.size() == pathChallengeBytes) {
                    PacketHeader resp = createHeaderInternal(conn);
                    resp.type = PacketType::PathResponse;
                    conn.sendQueue.push_back(OutgoingPacket{ resp, PacketType::PathResponse,
                                                             Bytes(payload.begin(), payload.end()) });
                    conn.localSeq = next(conn.localSeq);
                }
                break;
            case PacketType::PathResponse:
                break;   // a response on an ALREADY-current address proves nothing new; nothing to do
            default: break;   // Keepalive / MtuProbe: the header processing above is all they need
                              // (a probe's padding means nothing; ACKING it below is the discovery signal)
        }
        recordReceivedPacket(conn, *header);   // fully consumed -> our next header acks it
        return {};
    }

    // cold path: control/handshake (cleartext) + a payload from an unknown source (a migration probe)
    Packet pkt{ *header, Bytes(dat.begin() + static_cast<std::ptrdiff_t>(packetHeaderBytes), dat.end()) };
    if (connIt != peer.connections.end()) recordBytesReceived(connIt->second, bytes, now);
    return handlePacketByType(peer, pid, pkt, dat.data(), now, ptype);   // dat.data(): the header bytes as they arrived
}

// --- outgoing: build the datagram in its final layout, in one allocation ---
// A datagram is [header:9][payload][crc:4] in the clear, or [header:9][counter:8][ciphertext][tag:16][crc:4]
// once keyed. Both are assembled directly into one exactly-sized buffer: the size is known before any
// bytes are written, so the ciphertext is encrypted straight into place and the CRC is computed over the
// finished bytes. (Serializing, slicing off the header, encrypting into a second buffer, appending it, then
// copying the whole thing again to add a CRC cost five allocations and four copies of the payload per
// packet -- on the hot path, for every datagram, while the receive path next door copies nothing.)


// The keyed form. The cleartext header is authenticated as AAD (so tampering with it fails the tag), and
// the nonce counter travels in the clear ahead of the ciphertext, exactly as the receive path expects.
inline Bytes sealDatagram(const EncryptionKey& key, NonceCounter counter, std::uint32_t protocolId,
                          const PacketHeader& header, const Bytes& payload) {
    const std::size_t ctOffset = packetHeaderBytes + static_cast<std::size_t>(nonceSize);
    Bytes out(ctOffset + payload.size() + static_cast<std::size_t>(authTagSize) + static_cast<std::size_t>(crc32Size));
    Writer w{ out.data(), packetHeaderBytes, 0, true };
    writeHeader(w, header);

    std::uint8_t nonce[12];
    buildNonce(counter.value, protocolId, nonce);
    std::memcpy(out.data() + packetHeaderBytes, nonce, static_cast<std::size_t>(nonceSize));   // counter, 8 bytes BE
    aeadSeal(key.data(), nonce, out.data(), packetHeaderBytes,                                 // AAD: the header just written
             payload.data(), payload.size(),
             out.data() + ctOffset,                                                            // ciphertext, in place
             out.data() + ctOffset + payload.size());                                          // tag, straight after it
    writeCrc32Trailer(out);
    return out;
}

// --- outgoing: encrypt post-handshake payloads, append CRC ---
inline std::vector<RawPacket> encryptOutgoing(NetPeer& peer, const PeerId& pid, Connection& conn, const std::vector<OutgoingPacket>& packets) {
    std::vector<RawPacket> out;
    out.reserve(packets.size());
    for (const OutgoingPacket& op : packets) {
        PacketHeader header = op.header;
        header.type = op.type;
        if (conn.sendKey && isPostHandshake(op.type)) {
            // Fail closed: never wrap the send counter -- reusing a (key,nonce) pair would be
            // catastrophic for ChaCha20-Poly1305. 2^64 packets on one un-rekeyed session is unreachable
            // (~585,000 years at 1M pkt/s); a session that somehow reached it stops sending and times
            // out rather than reuse a nonce.
            if (conn.sendNonce.value == UINT64_MAX) continue;
            const NonceCounter nonce = conn.sendNonce;
            out.push_back(RawPacket{ pid, sealDatagram(*conn.sendKey, nonce, peer.config.protocolId, header, op.payload) });
            conn.sendNonce = NonceCounter{ nonce.value + 1 };
        } else {
            out.push_back(RawPacket{ pid, frameCleartextDatagram(header, op.payload) });
        }
    }
    return out;
}
inline void drainAllConnectionQueues(NetPeer& peer, MonoTime now) {
    for (auto& [pid, conn] : peer.connections) {
        const std::vector<OutgoingPacket> connPackets = drainSendQueue(conn);
        std::vector<RawPacket>            raws        = encryptOutgoing(peer, pid, conn, connPackets);
        int bytesSent = 0;
        std::uint64_t datagramsSent = 0;
        for (RawPacket& r : raws) {
            const int n = static_cast<int>(r.data.size());
            // Until the address proves it receives, hold to the anti-amplification ratio. Dropping here
            // rather than at enqueue keeps the decision in one place: reliable data is still in the send
            // buffer and retransmits once the cap lifts, and unreliable data is droppable by contract.
            if (!amplificationAllowsSend(conn, n)) break;
            if (!conn.pathValidated) conn.unvalidatedSentBytes += static_cast<std::uint64_t>(n);
            bytesSent += n;
            ++datagramsSent;
            peer.sendQueue.push_back(std::move(r));
        }
        if (bytesSent > 0) recordBytesSent(conn, bytesSent, now, datagramsSent);   // zero would reset the keepalive timer
    }
}

// --- per-tick connection update + pending maintenance ---
inline std::vector<PeerEvent> updateConnections(NetPeer& peer, MonoTime now) {
    for (auto it = peer.resumableTokens.begin(); it != peer.resumableTokens.end();)
        if (elapsedMs(it->second.at, now) >= resumeGraceMs) it = peer.resumableTokens.erase(it);
        else                                             ++it;

    std::vector<PeerEvent> events;
    std::vector<PeerId>    disconnected;
    for (auto& [pid, conn] : peer.connections) {
        if (auto found = peer.fragmentAssemblers.find(pid); found != peer.fragmentAssemblers.end()) {
            auto& assembler = found->second;
            cleanupFragments(assembler, now);
            for (auto it = assembler.buffers.begin(); it != assembler.buffers.end();) {
                const auto id = it->first;
                const auto channel = static_cast<std::uint32_t>(id) >> 16;
                const SequenceNum seq{static_cast<std::uint16_t>(id)};
                if (channel < conn.channels.size() && channelHasReceived(conn.channels[channel], seq)) {
                    ++it;
                    releaseFragment(assembler, id); // A newer sequenced message can supersede a partial one.
                    continue;
                }
                if (it->second.reservedBytes && conn.state == ConnectionState::Connected
                    && elapsedMs(it->second.lastFragmentAt, now) >= assembler.timeoutMs) {
                    conn.sendQueue.clear();
                    conn.pendingWires.clear();
                    disconnect(conn, DisconnectReason::DeliveryFailed, now);
                }
                ++it;
            }
        }
        if (updateTick(conn, now)) {
            // Arm the resumable (token + shared secret + identity, to restore on reconnect) unless this
            // token is already held by a DIFFERENT live session: the clientSalt keying it is
            // wire-supplied, so a collision is the peer's to cause, and overwriting would replace the
            // other session's master with this one's -- leaving the peer that actually holds that master
            // unable to resume even with a correct MAC. First writer keeps the entry until it expires.
            const auto rit = peer.resumableTokens.find(conn.clientSalt);
            if (conn.resumeMaster && peer.config.maxResumableSessions > 0
                && (rit != peer.resumableTokens.end()
                    || peer.resumableTokens.size() < static_cast<std::size_t>(peer.config.maxResumableSessions))
                && (rit == peer.resumableTokens.end() || rit->second.owner == pid
                    || elapsedMs(rit->second.at, now) >= resumeGraceMs))
                peer.resumableTokens[conn.clientSalt] = { now, conn.resumeMaster, conn.playerId, pid, conn.authenticated, conn.authScope, conn.authenticatedUserData };
            events.push_back(evDisconnected(pid, DisconnectReason::Timeout));
            disconnected.push_back(pid);
        } else if (connectionState(conn) == ConnectionState::Disconnected) {
            events.push_back(evDisconnected(pid, conn.disconnectReason));
            disconnected.push_back(pid);
        } else if (connectionState(conn) == ConnectionState::Connected) {
            const std::uint8_t numCh = channelCount(conn);
            for (std::uint8_t ch = 0; ch < numCh; ++ch)
                for (Bytes& m : receiveMessage(conn, static_cast<ChannelId>(ch)))
                    events.push_back(evMessage(pid, static_cast<ChannelId>(ch), std::move(m)));
            // Credit is advertised HERE, after the collection above, so it reports what the receiver
            // can absorb before the next one rather than the trough it sits at mid-tick. The packet
            // goes out with the rest of this tick's queue in drainAllConnectionQueues below.
            maybeAdvertiseWindow(conn, now);
        }
    }
    for (const PeerId& pid : disconnected) { peer.connections.erase(pid); cleanupPeer(peer, pid); }
    for (auto it = peer.migrationCooldowns.begin(); it != peer.migrationCooldowns.end();)
        if (!(elapsedMs(it->second, now) < migrationCooldownMs)) it = peer.migrationCooldowns.erase(it);
        else                                                     ++it;
    // An unanswered path challenge is a candidate that never proved it receives -- drop it, so the table
    // holds only live probes and a spoofed-source burst cannot pin entries until the connection ends.
    for (auto it = peer.pathValidations.begin(); it != peer.pathValidations.end();)
        if (elapsedMs(it->second.sentAt, now) >= pathValidationTimeoutMs) it = peer.pathValidations.erase(it);
        else                                                              ++it;
    return events;
}
inline void retryPendingConnections(NetPeer& peer, MonoTime now) {
    const NetworkConfig& cfg           = peer.config;
    const double         retryInterval = cfg.connectionRequestTimeoutMs / static_cast<double>(cfg.connectionRequestMaxRetries + 1);
    for (auto& [pid, pending] : peer.pending) {
        if (pending.direction != ConnectionDirection::Outbound) continue;
        if (elapsedMs(pending.lastRetry, now) > retryInterval && pending.retryCount < cfg.connectionRequestMaxRetries) {
            pending.retryCount += 1;
            pending.lastRetry   = now;
            queueControlPacket(peer, PacketType::ConnectionRequest,
                               encodeConnectionRequest(pending.retryCookie, pendingRequestBody(pending)), pid);
        }
    }
}
// Expire half-open handshakes. Only a pending this side ASKED for reports a timeout: we wanted to
// connect and the attempt failed, which the caller is waiting to hear about. An inbound pending that
// never completed is a peer that walked away (or never existed -- a spoofed request); surfacing
// Disconnected for it would report a disconnect for a peer that was never connected, once per
// abandoned handshake. localInitiated is what keeps that true across a simultaneous connect, where our
// own connect attempt ends up holding the accepting role.
inline std::vector<PeerEvent> cleanupPending(NetPeer& peer, MonoTime now) {
    const double           timeout = peer.config.connectionRequestTimeoutMs;
    std::vector<PeerEvent> events;
    for (auto it = peer.pending.begin(); it != peer.pending.end();) {
        if (elapsedMs(it->second.createdAt, now) > timeout) {
            if (it->second.isReconnect && it->second.fallbackCredential) {
                const auto pid = it->first;
                auto credential = std::move(*it->second.fallbackCredential);
                it = peer.pending.erase(it);
                if (peerConnectWithToken(peer, pid, credential, now))
                    events.push_back(evDisconnected(pid, DisconnectReason::ProtocolMismatch));
                continue;
            }
            if (it->second.direction == ConnectionDirection::Outbound || it->second.localInitiated)
                events.push_back(evDisconnected(it->first, DisconnectReason::Timeout));
            it = peer.pending.erase(it);
        } else {
            ++it;
        }
    }
    return events;
}

// --- the pure game-loop core ---
struct PeerProcessResult { std::vector<PeerEvent> events; std::vector<RawPacket> outgoing; };

// Token-gated admission requires an explicit Unix clock; omitting it fails admission closed.
// Other processing uses only now (monotonic), so a wall-clock correction cannot fire transport timers.
inline PeerProcessResult peerProcess(NetPeer& peer, MonoTime now, const std::vector<IncomingPacket>& packets,
                                     std::optional<UnixTime> tokenTime = std::nullopt) {
    peer.tokenTime = tokenTime ? std::optional{advanceTokenTime(peer.tokenValidator, *tokenTime)} : std::nullopt;
    std::vector<PeerEvent> events;
    for (const IncomingPacket& ip : packets)
        for (auto& e : handlePacket(peer, ip.from, ip.data, now)) events.push_back(std::move(e));
    for (auto& e : updateConnections(peer, now)) events.push_back(std::move(e));
    drainAllConnectionQueues(peer, now);
    retryPendingConnections(peer, now);
    for (auto& e : cleanupPending(peer, now)) events.push_back(std::move(e));

    std::vector<RawPacket> outgoing = std::move(peer.sendQueue);
    peer.sendQueue.clear();
    peer.tokenTime.reset();
    return { std::move(events), std::move(outgoing) };
}

// --- connection management + sending ---
// Disconnect a peer, telling it why. The reason travels on the wire and arrives as the remote's
// Disconnected event, so a server can distinguish a kick from an ordinary close (default Requested).
inline void peerDisconnect(NetPeer& peer, const PeerId& pid, MonoTime now,
                           DisconnectReason reason = DisconnectReason::Requested) {
    if (const auto it = peer.connections.find(pid); it != peer.connections.end()) disconnect(it->second, reason, now);
}
// Gracefully shut the whole peer down: move every connection to Disconnecting and drain the
// resulting Disconnect packets, returned for the caller to flush before closing the socket.
// Without this, a process that exits right after disconnect skips the Disconnect, so remote
// peers wait out the full connection timeout instead of dropping promptly.
inline std::vector<RawPacket> peerShutdown(NetPeer& peer, MonoTime now) {
    peer.pending.clear();
    peer.sendQueue.clear();
    peer.resumableTokens.clear();
    for (auto& [pid, conn] : peer.connections) { (void)pid; disconnect(conn, DisconnectReason::Requested, now); }
    drainAllConnectionQueues(peer, now);
    std::vector<RawPacket> outgoing = std::move(peer.sendQueue);
    peer.sendQueue.clear();
    return outgoing;
}
inline std::optional<ConnectionError> peerSend(NetPeer& peer, const PeerId& pid, ChannelId channel, const Bytes& dat, MonoTime now) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return ConnectionError{ ConnectionError::NotConnected };
    return sendMessage(it->second, channel, dat, now);
}
struct BroadcastFailure { PeerId peer; ChannelId channel{}; ConnectionError error; };
// Queue to every connected peer and return individual rejections. Success means queued,
// not delivered: reliable delivery failures still arrive through Disconnected events.
inline std::vector<BroadcastFailure> peerBroadcast(NetPeer& peer, ChannelId channel, const Bytes& dat,
                                                  const std::optional<PeerId>& except, MonoTime now) {
    std::vector<BroadcastFailure> failures;
    for (auto& [pid, conn] : peer.connections) {
        if (conn.state != ConnectionState::Connected || (except && *except == pid)) continue;
        if (const auto error = sendMessage(conn, channel, dat, now)) failures.push_back({pid, channel, *error});
    }
    return failures;
}

// --- queries ---
inline int peerCount(const NetPeer& peer) noexcept {
    return static_cast<int>(std::count_if(peer.connections.begin(), peer.connections.end(),
        [](const auto& item) { return item.second.state == ConnectionState::Connected; }));
}
inline bool peerIsConnected(const NetPeer& peer, const PeerId& pid) {
    const auto found = peer.connections.find(pid);
    return found != peer.connections.end() && found->second.state == ConnectionState::Connected;
}
// The session token (clientSalt) for a live connection. Capture it while connected; pass it to
// peerReconnect after a drop to re-establish fast.
inline std::optional<std::uint64_t> peerSessionToken(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.connections.find(pid);
    return it == peer.connections.end() ? std::nullopt : std::optional<std::uint64_t>(it->second.clientSalt);
}
// The connect-token identity this connection authenticated (0 when auth is off). Survives a fast
// reconnect, so a server can attribute a resumed session without having cached the Connected event.
inline std::optional<std::uint64_t> peerPlayerId(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.connections.find(pid);
    return it == peer.connections.end() ? std::nullopt : std::optional<std::uint64_t>(it->second.playerId);
}
inline std::optional<NetworkStats> peerStats(const NetPeer& peer, const PeerId& pid) {
    const auto it = peer.connections.find(pid);
    if (it == peer.connections.end()) return std::nullopt;
    return connectionStats(it->second);
}
inline const Address& peerLocalAddr(const NetPeer& peer) noexcept { return peer.localAddr; }
inline std::vector<PeerId> peerConnectedIds(const NetPeer& peer) {
    std::vector<PeerId> ids;
    ids.reserve(peer.connections.size());
    for (const auto& [pid, conn] : peer.connections) if (conn.state == ConnectionState::Connected) ids.push_back(pid);
    return ids;
}

} // namespace aether
