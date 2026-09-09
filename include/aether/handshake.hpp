// Noise_NNpsk0_25519_ChaChaPoly_SHA256, dedicated to Aether's authenticated setup.
// This is the standard two-message Noise handshake, not a generic pattern engine.
// Applications must provision a unique credential PSK through a trusted channel.
// Aether's peer layer additionally confirms the initiator's fresh key before admission.
#pragma once

#include "aether/handshake_crypto.hpp"
#include "aether/x25519.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace aether::detail {

inline ByteSpan handshakeBytes(std::string_view text) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

enum class NoisePhase { Initial, AwaitingReply, ReadyToReply, Complete };
struct NoiseState {
    Digest256 chainingKey{};
    Digest256 hash{};
    EncryptionKey key{};
    X25519Key ephemeralPrivate{};
    X25519Key remotePublic{};
    NoisePhase phase = NoisePhase::Initial;

    ~NoiseState() {
        secureZero(chainingKey.data(), chainingKey.size());
        secureZero(key.data(), key.size());
        secureZero(ephemeralPrivate.data(), ephemeralPrivate.size());
    }
};

inline void noiseMixHash(NoiseState& state, ByteSpan data) noexcept {
    Sha256 hash;
    sha256Update(hash, state.hash);
    sha256Update(hash, data);
    state.hash = sha256Finish(hash);
}

inline void noiseMixKey(NoiseState& state, ByteSpan data) noexcept {
    auto keys = noiseHkdf<2>(state.chainingKey, data);
    state.chainingKey = keys[0];
    state.key = keys[1];
    secureZero(keys.data(), sizeof keys);
}

inline NoiseState noiseStart(const EncryptionKey& psk, ByteSpan prologue) noexcept {
    NoiseState state;
    state.hash = sha256(handshakeBytes("Noise_NNpsk0_25519_ChaChaPoly_SHA256"));
    state.chainingKey = state.hash;
    noiseMixHash(state, prologue);
    // The psk0 token is the first token for both reader and writer.
    auto keys = noiseHkdf<3>(state.chainingKey, psk);
    state.chainingKey = keys[0];
    noiseMixHash(state, keys[1]);
    state.key = keys[2];
    secureZero(keys.data(), sizeof keys);
    return state;
}

// Noise encodes its nonce as four zero bytes followed by a little-endian u64.
inline std::array<std::uint8_t, 12> noiseNonce(std::uint64_t counter) noexcept {
    std::array<std::uint8_t, 12> nonce{};
    for (std::size_t i = 0; i < 8; ++i) nonce[4 + i] = static_cast<std::uint8_t>(counter >> (8 * i));
    return nonce;
}

inline std::optional<Bytes> noiseSeal(const EncryptionKey& key, std::uint64_t counter,
                                     ByteSpan associatedData, ByteSpan plaintext) {
    if (counter == UINT64_MAX || plaintext.size() > 65535 - authTagSize) return std::nullopt;
    const auto nonce = noiseNonce(counter);
    Bytes out(plaintext.size() + authTagSize);
    aeadSeal(key.data(), nonce.data(), associatedData.data(), associatedData.size(),
             plaintext.data(), plaintext.size(), out.data(), out.data() + plaintext.size());
    return out;
}

inline std::optional<Bytes> noiseOpen(const EncryptionKey& key, std::uint64_t counter,
                                     ByteSpan associatedData, ByteSpan ciphertext) {
    if (counter == UINT64_MAX || ciphertext.size() < authTagSize || ciphertext.size() > 65535)
        return std::nullopt;
    const auto nonce = noiseNonce(counter);
    const auto size = ciphertext.size() - authTagSize;
    return aeadOpen(key.data(), nonce.data(), associatedData.data(), associatedData.size(),
                    ciphertext.data(), size, ciphertext.data() + size);
}

inline std::optional<X25519Key> noiseDh(const X25519Key& privateKey, const X25519Key& publicKey) {
    X25519Key shared{};
    x25519(shared, privateKey, publicKey);
    std::uint8_t nonzero = 0;
    for (const auto byte : shared) nonzero |= byte;
    if (nonzero == 0) return std::nullopt;
    return shared;
}

// Supplying fixed private keys is for the vector tests. The peer layer always draws fresh keys
// from the OS CSPRNG. Each writer is permitted once; retransmission uses its cached wire bytes.
inline std::optional<Bytes> noiseWriteFirst(NoiseState& state, const X25519Key& privateKey, ByteSpan payload = {}) {
    if (state.phase != NoisePhase::Initial || payload.size() > 65535 - 32 - authTagSize) return std::nullopt;
    NoiseState next = state;
    next.ephemeralPrivate = privateKey;
    X25519Key publicKey{};
    x25519Base(publicKey, privateKey);
    noiseMixHash(next, publicKey);
    noiseMixKey(next, publicKey); // every e token in PSK mode also mixes the public key into ck
    const auto encrypted = noiseSeal(next.key, 0, next.hash, payload);
    if (!encrypted) return std::nullopt;
    noiseMixHash(next, *encrypted);
    Bytes message(publicKey.begin(), publicKey.end());
    message.insert(message.end(), encrypted->begin(), encrypted->end());
    next.phase = NoisePhase::AwaitingReply;
    state = next;
    return message;
}

inline std::optional<Bytes> noiseReadFirst(NoiseState& state, ByteSpan message) {
    if (state.phase != NoisePhase::Initial || message.size() < 32 + authTagSize || message.size() > 65535)
        return std::nullopt;
    NoiseState next = state;
    std::copy_n(message.begin(), next.remotePublic.size(), next.remotePublic.begin());
    noiseMixHash(next, next.remotePublic);
    noiseMixKey(next, next.remotePublic);
    const auto payload = noiseOpen(next.key, 0, next.hash, message.subspan(32));
    if (!payload) return std::nullopt;
    noiseMixHash(next, message.subspan(32));
    next.phase = NoisePhase::ReadyToReply;
    state = next;
    return payload;
}

inline std::optional<Bytes> noiseWriteSecond(NoiseState& state, const X25519Key& privateKey, ByteSpan payload = {}) {
    if (state.phase != NoisePhase::ReadyToReply || payload.size() > 65535 - 32 - authTagSize)
        return std::nullopt;
    NoiseState next = state;
    X25519Key publicKey{};
    x25519Base(publicKey, privateKey);
    noiseMixHash(next, publicKey);
    noiseMixKey(next, publicKey);
    auto shared = noiseDh(privateKey, next.remotePublic);
    if (!shared) return std::nullopt;
    noiseMixKey(next, *shared);
    secureZero(shared->data(), shared->size());
    const auto encrypted = noiseSeal(next.key, 0, next.hash, payload);
    if (!encrypted) return std::nullopt;
    noiseMixHash(next, *encrypted);
    Bytes message(publicKey.begin(), publicKey.end());
    message.insert(message.end(), encrypted->begin(), encrypted->end());
    next.phase = NoisePhase::Complete;
    state = next;
    return message;
}

inline std::optional<Bytes> noiseReadSecond(NoiseState& state, ByteSpan message) {
    if (state.phase != NoisePhase::AwaitingReply || message.size() < 32 + authTagSize || message.size() > 65535)
        return std::nullopt;
    NoiseState next = state;
    std::copy_n(message.begin(), next.remotePublic.size(), next.remotePublic.begin());
    noiseMixHash(next, next.remotePublic);
    noiseMixKey(next, next.remotePublic);
    auto shared = noiseDh(next.ephemeralPrivate, next.remotePublic);
    if (!shared) return std::nullopt;
    noiseMixKey(next, *shared);
    secureZero(shared->data(), shared->size());
    const auto payload = noiseOpen(next.key, 0, next.hash, message.subspan(32));
    if (!payload) return std::nullopt;
    noiseMixHash(next, message.subspan(32));
    secureZero(next.ephemeralPrivate.data(), next.ephemeralPrivate.size());
    next.phase = NoisePhase::Complete;
    state = next;
    return payload;
}

struct HandshakeSecrets {
    EncryptionKey clientToServer{};
    EncryptionKey serverToClient{};
    EncryptionKey resumeMaster{};
    Digest256 clientProof{};
    Digest256 serverProof{};
    std::uint64_t connectionId = 0;
    ~HandshakeSecrets() {
        secureZero(clientToServer.data(), clientToServer.size());
        secureZero(serverToClient.data(), serverToClient.size());
        secureZero(resumeMaster.data(), resumeMaster.size());
    }
};

inline std::optional<HandshakeSecrets> noiseFinish(const NoiseState& state) {
    if (state.phase != NoisePhase::Complete) return std::nullopt;
    HandshakeSecrets result;
    auto traffic = noiseHkdf<2>(state.chainingKey, {}); // standard Noise Split
    result.clientToServer = traffic[0];
    result.serverToClient = traffic[1];
    secureZero(traffic.data(), sizeof traffic);
    // Aether-specific exports have distinct labels and bind the completed Noise transcript.
    const auto exportKey = [&](std::string_view label) {
        return hmacSha256(state.chainingKey, handshakeBytes(label), state.hash);
    };
    result.resumeMaster = exportKey("aether-v2/resumption");
    result.clientProof = exportKey("aether-v2/client-finished");
    result.serverProof = exportKey("aether-v2/server-finished");
    const auto routing = exportKey("aether-v2/routing");
    for (std::size_t i = 0; i < 8; ++i) result.connectionId |= std::uint64_t(routing[i]) << (i * 8);
    if (result.connectionId == 0) result.connectionId = 1;
    return result;
}

} // namespace aether::detail
