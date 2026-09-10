// Initiating sessions is separate from advancing them. Every refusal is observable.
#pragma once

#include "aether/peer_auth.hpp"

namespace aether {

enum class ConnectError { InvalidAddress, AlreadyConnected, AlreadyPending, Capacity, AuthenticationRequired, InvalidCredential };

inline std::optional<ConnectError> canConnect(const NetPeer& peer, const PeerId& pid) {
    if (!addressValid(pid.addr) || addrPort(pid.addr) == 0) return ConnectError::InvalidAddress;
    if (peer.connections.count(pid)) return ConnectError::AlreadyConnected;
    if (peer.pending.count(pid)) return ConnectError::AlreadyPending;
    if (static_cast<int>(peer.pending.size()) >= peer.config.maxPending
        || static_cast<int>(peer.connections.size()) >= peer.config.maxClients) return ConnectError::Capacity;
    return std::nullopt;
}

inline PendingConnection newOutboundPending(MonoTime now) {
    PendingConnection pending;
    pending.direction = ConnectionDirection::Outbound;
    pending.localInitiated = true;
    while (pending.clientSalt == 0) pending.clientSalt = secureRandom64();
    pending.createdAt = pending.lastRetry = now;
    return pending;
}

// Anonymous development/P2P mode must be explicitly enabled at both ends. Its initial
// key exchange encrypts traffic but does not establish who owns the remote endpoint.
inline std::optional<ConnectError> peerConnect(NetPeer& peer, const PeerId& pid, MonoTime now) {
    if (const auto error = canConnect(peer, pid)) return error;
    if (!peer.config.allowUnauthenticated || peer.config.tokenKey) return ConnectError::AuthenticationRequired;
    peer.pending.emplace(pid, newOutboundPending(now));
    queueControlPacket(peer, PacketType::ConnectionRequest, encodeConnectionRequest({}, {}), pid);
    return std::nullopt;
}

inline bool credentialValid(const ConnectCredential& credential, std::uint32_t protocolId) noexcept {
    return credential.scope.protocolId == protocolId && protocolId != 0 && credential.scope.audience != 0
        && credential.expiresAt.ns != 0 && nonzeroKey(credential.proofKey)
        && credential.token.size() >= connectTokenNonceBytes + connectTokenClaimsBytes + authTagSize
        && credential.token.size() <= maxSealedConnectTokenBytes;
}

// The trusted application backend supplies BOTH the sealed token and its separate proof
// key. Only the token is transmitted. Identity and userData arrive in the server's event.
inline std::optional<ConnectError> peerConnectWithToken(NetPeer& peer, const PeerId& pid,
                                                      const ConnectCredential& credential, MonoTime now) {
    if (const auto error = canConnect(peer, pid)) return error;
    if (!credentialValid(credential, peer.config.protocolId)) return ConnectError::InvalidCredential;
    auto pending = newOutboundPending(now);
    pending.auth = startAuthHandshake(AuthRequestMode::Credential, pending.clientSalt, credential.scope,
                                      credential.token, credential.proofKey);
    pending.auth->expiresAt = credential.expiresAt;
    queueControlPacket(peer, PacketType::ConnectionRequest, encodeConnectionRequest({}, pending.auth->request), pid);
    peer.pending.emplace(pid, std::move(pending));
    return std::nullopt;
}

// A resume performs fresh Noise DH and proof of receipt. No application data or session
// state is accepted in 0-RTT. If the remote cache is gone, a supplied fresh credential is
// tried after the bounded resume timeout; unauthenticated network packets cannot force it.
inline std::optional<ConnectError> peerReconnect(NetPeer& peer, const PeerId& pid, std::uint64_t token,
                                                MonoTime now, std::optional<ConnectCredential> fallback = std::nullopt) {
    if (const auto error = canConnect(peer, pid)) return error;
    if (fallback && !credentialValid(*fallback, peer.config.protocolId)) return ConnectError::InvalidCredential;
    const auto cached = peer.resumableTokens.find(token);
    if (cached == peer.resumableTokens.end() || !cached->second.master
        || elapsedMs(cached->second.at, now) >= resumeGraceMs) {
        if (fallback) return peerConnectWithToken(peer, pid, *fallback, now);
        return peerConnect(peer, pid, now);
    }
    if (cached->second.scope.protocolId != peer.config.protocolId
        || (!cached->second.authenticated && (!peer.config.allowUnauthenticated || peer.config.tokenKey)))
        return ConnectError::AuthenticationRequired;
    auto pending = newOutboundPending(now);
    pending.clientSalt = token;
    pending.isReconnect = true;
    pending.fallbackCredential = std::move(fallback);
    pending.auth = startAuthHandshake(AuthRequestMode::Resume, token, cached->second.scope, {}, *cached->second.master);
    pending.auth->authenticated = cached->second.authenticated;
    pending.auth->resumeBefore = cached->second.master;
    queueControlPacket(peer, PacketType::ConnectionRequest, encodeConnectionRequest({}, pending.auth->request), pid);
    peer.pending.emplace(pid, std::move(pending));
    return std::nullopt;
}

} // namespace aether
