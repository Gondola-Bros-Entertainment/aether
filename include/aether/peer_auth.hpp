// Authenticated admission and resumption. The peer core supplies clocks and datagrams;
// this module commits a session only after fresh key confirmation in both directions.
#pragma once

#include "aether/peer_state.hpp"

namespace aether {

inline void applyAuthKeys(Connection& conn, const AuthHandshake& auth, bool server) {
    const auto& keys = *auth.keys;
    conn.sendKey = server ? keys.serverToClient : keys.clientToServer;
    conn.recvKey = server ? keys.clientToServer : keys.serverToClient;
    conn.resumeMaster = keys.resumeMaster;
    conn.connectionId = keys.connectionId;
    conn.authenticated = auth.authenticated;
    conn.authScope = auth.scope;
    conn.authenticatedUserData = auth.userData;
    conn.handshakeReceipt = HandshakeReceipt{auth.requestId, keys.clientProof, keys.serverProof};
}

inline void queueAuthDenial(NetPeer& peer, const PeerId& pid, const AuthHandshake& auth, DenyReason reason) {
    Bytes proof = encodeDenyReason(reason);
    const auto mac = detail::hmacSha256(auth.denialKey, proof);
    proof.insert(proof.end(), mac.begin(), mac.end());
    queueControlPacket(peer, PacketType::ConnectionDenied, authReply(auth.requestId, proof), pid);
}

inline bool resumeAvailable(const NetPeer& peer, std::uint64_t token, const AuthHandshake& auth, MonoTime now) {
    const auto found = peer.resumableTokens.find(token);
    return found != peer.resumableTokens.end() && found->second.master && auth.resumeBefore
        && elapsedMs(found->second.at, now) < resumeGraceMs
        && found->second.scope == auth.scope && found->second.authenticated == auth.authenticated
        && detail::constTimeEq(found->second.master->data(), auth.resumeBefore->data(), x25519KeySize);
}

inline std::vector<PeerEvent> handleAuthRequest(NetPeer& peer, const PeerId& pid,
                                               const ConnectionRequestPayload& envelope, MonoTime now) {
    const auto request = decodeAuthRequest(envelope.body);
    if (!request || request->scope.protocolId != peer.config.protocolId) return {};
    const auto requestId = detail::sha256(envelope.body);
    // Retransmission after commit only acknowledges the exact handshake this address completed.
    if (const auto live = peer.connections.find(pid); live != peer.connections.end()) {
        if (live->second.state != ConnectionState::Connected) return {};
        const auto& receipt = live->second.handshakeReceipt;
        if (receipt && receipt->requestId == requestId)
            queueControlPacket(peer, PacketType::ConnectionAccepted, authReply(requestId, receipt->serverProof), pid);
        return {};
    }
    if (const auto pending = peer.pending.find(pid); pending != peer.pending.end()) {
        if (pending->second.direction == ConnectionDirection::Inbound && pending->second.auth
            && pending->second.auth->requestId == requestId)
            queueControlPacket(peer, PacketType::ConnectionChallenge, pending->second.auth->challenge, pid);
        return {}; // A different request cannot replace a handshake that is still in flight.
    }
    AuthHandshake auth;
    auth.requestId = requestId;
    auth.scope = request->scope;
    auth.mode = request->mode;
    ConnectToken claims; // owns and wipes the proof key on every exit
    std::uint64_t playerId = 0;
    if (request->mode == AuthRequestMode::Credential) {
        if (!peer.config.tokenKey || !peer.tokenTime || request->scope.audience != peer.config.tokenAudience) return {};
        // Opening without the expiry check lets the holder receive an authenticated expiry denial.
        // Admission checks the explicit Unix clock below, and again at proof completion.
        const auto opened = openConnectToken(*peer.config.tokenKey, Bytes(request->sealed.begin(), request->sealed.end()), UnixTime{});
        if (!opened || opened->token.scope != request->scope || !nonzeroKey(opened->token.proofKey)) return {};
        claims = opened->token;
        auth.tokenNonce = opened->nonce;
        auth.expiresAt = claims.expiresAt;
        auth.userData = claims.userData;
        playerId = claims.playerId;
    } else {
        const auto cached = peer.resumableTokens.find(request->token);
        if (cached == peer.resumableTokens.end() || !cached->second.master
            || elapsedMs(cached->second.at, now) >= resumeGraceMs || cached->second.scope != request->scope
            || (!cached->second.authenticated && (!peer.config.allowUnauthenticated || peer.config.tokenKey))
            || (cached->second.authenticated && peer.config.tokenKey && request->scope.audience != peer.config.tokenAudience)) return {};
        claims.proofKey = *cached->second.master;
        auth.resumeBefore = claims.proofKey;
        auth.authenticated = cached->second.authenticated;
        auth.userData = cached->second.userData;
        playerId = cached->second.playerId;
    }
    auth.denialKey = authDenialKey(claims.proofKey, requestId);
    auth.noise = detail::noiseStart(claims.proofKey, authPrologue(request->context));
    if (!detail::noiseReadFirst(auth.noise, request->noise)) return {}; // PSK proof before cookie or X25519 work
    if (auth.tokenNonce && (auth.expiresAt.ns <= peer.tokenTime->ns || tokenNonceSpent(peer.tokenValidator, *auth.tokenNonce))) {
        queueAuthDenial(peer, pid, auth, DenyReason::InvalidToken);
        return {};
    }
    if (!retryCookieValid(peer.cookieSecret, pid.addr, envelope.cookie, now)) {
        if (requestDatagramBytes(encodeConnectionRequest({}, envelope.body)) >= minConnectionRequestBytes)
            queueControlPacket(peer, PacketType::ConnectionRetry, makeRetryCookie(peer.cookieSecret, pid.addr, now), pid);
        return {};
    }
    if (static_cast<int>(peer.pending.size()) >= peer.config.maxPending) { ++peer.rateLimitDrops; return {}; }
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        queueAuthDenial(peer, pid, auth, DenyReason::ServerFull);
        return {};
    }
    X25519Key privateKey{};
    secureRandomBytes(privateKey.data(), privateKey.size());
    const auto second = detail::noiseWriteSecond(auth.noise, privateKey);
    detail::secureZero(privateKey.data(), privateKey.size());
    if (!second) return {};
    auth.keys = detail::noiseFinish(auth.noise);
    if (!auth.keys) return {};
    auth.request = envelope.body;
    auth.challenge = authReply(requestId, *second);
    PendingConnection pending;
    pending.clientSalt = request->token;
    pending.playerId = playerId;
    pending.createdAt = pending.lastRetry = now;
    pending.isReconnect = request->mode == AuthRequestMode::Resume;
    pending.auth = std::move(auth);
    queueControlPacket(peer, PacketType::ConnectionChallenge, pending.auth->challenge, pid);
    peer.pending.emplace(pid, std::move(pending));
    return {};
}

inline std::vector<PeerEvent> handleAuthChallenge(NetPeer& peer, const PeerId& pid, const Packet& packet, MonoTime now) {
    auto& pending = peer.pending.at(pid);
    auto& auth = *pending.auth;
    const auto second = decodeAuthReply(packet.payload, auth.requestId, authNoiseMessageBytes);
    if (!second) return {};
    if (auth.keys) {
        if (packet.payload != auth.challenge) return {};
    } else {
        // Limit expensive invalid DH work per interval, without letting three forged
        // replies permanently exhaust the real client's handshake.
        const double interval = peer.config.connectionRequestTimeoutMs
            / static_cast<double>(peer.config.connectionRequestMaxRetries + 1);
        if (elapsedMs(pending.challengeBudgetAt, now) >= interval) {
            pending.challengeBudgetAt = now;
            pending.challengeKeyAttempts = 0;
        }
        if (pending.challengeKeyAttempts >= 3) return {};
        ++pending.challengeKeyAttempts;
        if (!detail::noiseReadSecond(auth.noise, *second)) return {};
        auth.keys = detail::noiseFinish(auth.noise);
        if (!auth.keys) return {};
        auth.challenge = packet.payload;
    }
    queueControlPacket(peer, PacketType::ConnectionResponse, authReply(auth.requestId, auth.keys->clientProof), pid);
    return {};
}

inline std::vector<PeerEvent> handleAuthResponse(NetPeer& peer, const PeerId& pid, const Packet& packet, MonoTime now) {
    if (const auto live = peer.connections.find(pid); live != peer.connections.end()) {
        if (live->second.state != ConnectionState::Connected) return {};
        const auto& receipt = live->second.handshakeReceipt;
        if (receipt) {
            const auto proof = decodeAuthReply(packet.payload, receipt->requestId, receipt->clientProof.size());
            if (proof && detail::constTimeEq(proof->data(), receipt->clientProof.data(), proof->size()))
                queueControlPacket(peer, PacketType::ConnectionAccepted, authReply(receipt->requestId, receipt->serverProof), pid);
        }
        return {};
    }
    const auto it = peer.pending.find(pid);
    if (it == peer.pending.end() || it->second.direction != ConnectionDirection::Inbound || !it->second.auth) return {};
    auto& pending = it->second;
    const auto& auth = *pending.auth;
    if (!auth.keys || elapsedMs(pending.createdAt, now) > peer.config.connectionRequestTimeoutMs) return {};
    const auto proof = decodeAuthReply(packet.payload, auth.requestId, auth.keys->clientProof.size());
    if (!proof || !detail::constTimeEq(proof->data(), auth.keys->clientProof.data(), proof->size())) return {};
    if (static_cast<int>(peer.connections.size()) >= peer.config.maxClients) {
        queueAuthDenial(peer, pid, auth, DenyReason::ServerFull);
        removePending(peer, pid);
        return {};
    }
    if (auth.mode == AuthRequestMode::Credential) {
        if (!peer.tokenTime || !auth.tokenNonce
            || consumeTokenNonce(peer.tokenValidator, *auth.tokenNonce, auth.expiresAt, *peer.tokenTime)) {
            queueAuthDenial(peer, pid, auth, DenyReason::InvalidToken);
            removePending(peer, pid);
            return {};
        }
    } else {
        if (!resumeAvailable(peer, pending.clientSalt, auth, now)) {
            queueAuthDenial(peer, pid, auth, DenyReason::InvalidToken);
            removePending(peer, pid);
            return {};
        }
        peer.resumableTokens.erase(pending.clientSalt);
    }
    Connection conn = newConnection(peer.config, pending.clientSalt, now);
    conn.playerId = pending.playerId;
    applyAuthKeys(conn, auth, true);
    touchRecvTime(conn, now);
    markConnected(conn, now);
    auto event = pending.isReconnect ? evReconnected(pid, conn.playerId)
                                    : evConnected(pid, ConnectionDirection::Inbound, conn.playerId);
    event.userData = auth.userData;
    queueControlPacket(peer, PacketType::ConnectionAccepted, authReply(auth.requestId, auth.keys->serverProof), pid);
    peer.connections.emplace(pid, std::move(conn));
    removePending(peer, pid);
    return {std::move(event)};
}

inline std::vector<PeerEvent> handleAuthAccepted(NetPeer& peer, const PeerId& pid, const Packet& packet, MonoTime now) {
    auto& pending = peer.pending.at(pid);
    const auto& auth = *pending.auth;
    if (!auth.keys || elapsedMs(pending.createdAt, now) > peer.config.connectionRequestTimeoutMs) return {};
    const auto proof = decodeAuthReply(packet.payload, auth.requestId, auth.keys->serverProof.size());
    if (!proof || !detail::constTimeEq(proof->data(), auth.keys->serverProof.data(), proof->size())) return {};
    Connection conn = newConnection(peer.config, pending.clientSalt, now);
    applyAuthKeys(conn, auth, false);
    touchRecvTime(conn, now);
    markConnected(conn, now);
    auto event = pending.isReconnect ? evReconnected(pid) : evConnected(pid, ConnectionDirection::Outbound);
    if (pending.isReconnect) peer.resumableTokens.erase(pending.clientSalt);
    peer.connections.emplace(pid, std::move(conn));
    removePending(peer, pid);
    return {std::move(event)};
}

inline std::vector<PeerEvent> handleAuthDenied(NetPeer& peer, const PeerId& pid, const Packet& packet) {
    const auto& auth = *peer.pending.at(pid).auth;
    const auto proof = decodeAuthReply(packet.payload, auth.requestId, 33);
    if (!proof) return {};
    const auto expected = detail::hmacSha256(auth.denialKey, proof->first(1));
    if (!detail::constTimeEq(expected.data(), proof->data() + 1, expected.size())) return {};
    const auto reason = static_cast<DenyReason>((*proof)[0]);
    if (reason == DenyReason::InvalidToken && peer.pending.at(pid).isReconnect
        && peer.pending.at(pid).fallbackCredential) return {};
    removePending(peer, pid);
    return {evDisconnected(pid, denyToDisconnectReason(reason))};
}

} // namespace aether
