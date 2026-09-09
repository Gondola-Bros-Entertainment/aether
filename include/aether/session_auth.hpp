// Aether's bounded credential/resumption envelope around the Noise handshake.
#pragma once

#include "aether/handshake.hpp"
#include "aether/packet.hpp"
#include "aether/random.hpp"
#include "aether/security.hpp"

namespace aether {

enum class AuthRequestMode : std::uint8_t { Credential = 1, Resume = 2 };
inline constexpr std::uint8_t authEnvelopeTag = 0xa2;
inline constexpr std::size_t authRequestPrefixBytes = 32;
inline constexpr std::size_t authNoiseMessageBytes = 48; // ephemeral public key + empty-payload tag
inline constexpr std::size_t authReplyPrefixBytes = 33;  // envelope tag + request hash

struct AuthRequest {
    AuthRequestMode mode{};
    std::uint64_t token = 0;
    std::uint64_t attempt = 0;
    TokenScope scope{};
    ByteSpan sealed;
    ByteSpan context;
    ByteSpan noise;
};

inline std::optional<AuthRequest> decodeAuthRequest(ByteSpan body) {
    if (body.size() < authRequestPrefixBytes + authNoiseMessageBytes
        || body.size() > authRequestPrefixBytes + maxSealedConnectTokenBytes + authNoiseMessageBytes
        || body[0] != authEnvelopeTag) return std::nullopt;
    if (body[1] != static_cast<std::uint8_t>(AuthRequestMode::Credential)
        && body[1] != static_cast<std::uint8_t>(AuthRequestMode::Resume)) return std::nullopt;
    const std::size_t tokenSize = std::size_t(body[30]) | (std::size_t(body[31]) << 8);
    if (body.size() != authRequestPrefixBytes + tokenSize + authNoiseMessageBytes) return std::nullopt;
    AuthRequest request;
    request.mode = static_cast<AuthRequestMode>(body[1]);
    request.token = getU64(body.data() + 2);
    request.attempt = getU64(body.data() + 10);
    request.scope = {detail::cryptoLe32(body.data() + 18), getU64(body.data() + 22)};
    if (request.token == 0 || request.attempt == 0 || request.scope.protocolId == 0) return std::nullopt;
    if (request.mode == AuthRequestMode::Credential && (tokenSize == 0 || request.scope.audience == 0)) return std::nullopt;
    if (request.mode == AuthRequestMode::Resume && tokenSize != 0) return std::nullopt;
    request.sealed = body.subspan(authRequestPrefixBytes, tokenSize);
    request.context = body.first(authRequestPrefixBytes + tokenSize);
    request.noise = body.last(authNoiseMessageBytes);
    return request;
}

inline Bytes authPrologue(ByteSpan context) {
    const auto domain = detail::handshakeBytes("aether-session");
    Bytes prologue(domain.begin(), domain.end());
    prologue.push_back(packetWireVersion);
    prologue.insert(prologue.end(), context.begin(), context.end());
    return prologue;
}

inline Bytes authReply(const detail::Digest256& requestId, ByteSpan payload) {
    Bytes body{authEnvelopeTag};
    body.insert(body.end(), requestId.begin(), requestId.end());
    body.insert(body.end(), payload.begin(), payload.end());
    return body;
}

inline std::optional<ByteSpan> decodeAuthReply(ByteSpan body, const detail::Digest256& requestId,
                                              std::size_t payloadSize) {
    if (body.size() != authReplyPrefixBytes + payloadSize || body[0] != authEnvelopeTag
        || !detail::constTimeEq(body.data() + 1, requestId.data(), requestId.size())) return std::nullopt;
    return body.subspan(authReplyPrefixBytes);
}

struct HandshakeReceipt {
    detail::Digest256 requestId{};
    detail::Digest256 clientProof{};
    detail::Digest256 serverProof{};
};

struct AuthHandshake {
    detail::NoiseState noise;
    std::optional<detail::HandshakeSecrets> keys;
    Bytes request;                     // cached first message, retransmitted verbatim
    Bytes challenge;                   // cached second message, retransmitted verbatim
    detail::Digest256 requestId{};
    EncryptionKey denialKey{};
    std::optional<EncryptionKey> resumeBefore; // expected cached generation until proof commits it
    std::optional<TokenNonce> tokenNonce;
    UnixTime expiresAt{};
    TokenScope scope{};
    AuthRequestMode mode = AuthRequestMode::Credential;
    bool authenticated = true;
    Bytes userData;

    ~AuthHandshake() {
        detail::secureZero(denialKey.data(), denialKey.size());
        if (resumeBefore) detail::secureZero(resumeBefore->data(), resumeBefore->size());
    }
};

inline EncryptionKey authDenialKey(const EncryptionKey& psk, const detail::Digest256& requestId) {
    return detail::hmacSha256(psk, detail::handshakeBytes("aether-v2/denial"), requestId);
}

inline AuthHandshake startAuthHandshake(AuthRequestMode mode, std::uint64_t token, TokenScope scope,
                                        ByteSpan sealed, const EncryptionKey& psk) {
    if ((mode != AuthRequestMode::Credential && mode != AuthRequestMode::Resume)
        || token == 0 || scope.protocolId == 0 || !nonzeroKey(psk)
        || (mode == AuthRequestMode::Credential && (sealed.empty() || scope.audience == 0))
        || (mode == AuthRequestMode::Resume && !sealed.empty())
        || sealed.size() > maxSealedConnectTokenBytes)
        throw std::invalid_argument("Invalid authenticated handshake parameters");
    AuthHandshake auth;
    auth.mode = mode;
    auth.scope = scope;
    auth.request.resize(authRequestPrefixBytes);
    auth.request[0] = authEnvelopeTag;
    auth.request[1] = static_cast<std::uint8_t>(mode);
    putU64(auth.request.data() + 2, token);
    std::uint64_t attempt = 0;
    while (attempt == 0) attempt = secureRandom64();
    putU64(auth.request.data() + 10, attempt);
    for (std::size_t i = 0; i < 4; ++i) auth.request[18 + i] = static_cast<std::uint8_t>(scope.protocolId >> (i * 8));
    putU64(auth.request.data() + 22, scope.audience);
    auth.request[30] = static_cast<std::uint8_t>(sealed.size());
    auth.request[31] = static_cast<std::uint8_t>(sealed.size() >> 8);
    auth.request.insert(auth.request.end(), sealed.begin(), sealed.end());
    auth.noise = detail::noiseStart(psk, authPrologue(auth.request));
    X25519Key privateKey{};
    secureRandomBytes(privateKey.data(), privateKey.size());
    const auto first = detail::noiseWriteFirst(auth.noise, privateKey);
    detail::secureZero(privateKey.data(), privateKey.size());
    // A fresh, fixed-size first message cannot fail; no caller-controlled length reaches Noise.
    if (!first) throw std::runtime_error("Could not create authenticated handshake");
    auth.request.insert(auth.request.end(), first->begin(), first->end());
    auth.requestId = detail::sha256(auth.request);
    auth.denialKey = authDenialKey(psk, auth.requestId);
    return auth;
}

} // namespace aether
