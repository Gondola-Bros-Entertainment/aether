#include "check.hpp"
#include <aether/handshake.hpp>
#include <string_view>

namespace {
aether::Bytes unhex(std::string_view text) {
    aether::test::require(text.size() % 2 == 0);
    const auto nibble = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        aether::test::require(c >= 'a' && c <= 'f');
        return c - 'a' + 10;
    };
    aether::Bytes data;
    for (std::size_t i = 0; i < text.size(); i += 2)
        data.push_back(static_cast<std::uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
    return data;
}
aether::EncryptionKey key(std::string_view text) {
    const auto data = unhex(text);
    aether::test::require(data.size() == 32);
    aether::EncryptionKey result{};
    std::copy(data.begin(), data.end(), result.begin());
    return result;
}
}

int main() {
    using namespace aether;
    using namespace aether::detail;
    using aether::test::require;
    // Public-domain Cacophony vector, pinned independently of Aether:
    // https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt
    // Noise_NNpsk0_25519_ChaChaPoly_SHA256. Source license: Unlicense.
    const auto psk = key("54686973206973206d7920417573747269616e20706572737065637469766521");
    const auto initiatorPrivate = key("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
    const auto responderPrivate = key("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
    const auto prologue = unhex("4a6f686e2047616c74");
    const std::array<std::string_view, 6> plaintexts{
        "4c756477696720766f6e204d69736573", "4d757272617920526f746862617264",
        "462e20412e20486179656b", "4361726c204d656e676572",
        "4a65616e2d426170746973746520536179", "457567656e2042f6686d20766f6e2042617765726b"};
    const std::array<std::string_view, 6> ciphertexts{
        "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479b962b8aff8485742ac32f905ba45369e2465fb59e138a93d67a0d1266b6a54",
        "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d6062704d5a9c422a8e834423f8c1feada7e8d0d910a1a2cd030fb584221e3",
        "e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f",
        "64c6bee32ea91c8474bb4c21d7a700109ad45af77b29764ba5eb1e",
        "e2fa0bed0603b62d3ccac2ecabbf3fe33f3e86514909b323361626266cb2471cc8",
        "0c01dc9cec1fe4ddd692e8dd32188aa351088dc91183639a53b57aa4692b5ebdef8b8ca111"};
    auto initiator = noiseStart(psk, prologue);
    auto responder = noiseStart(psk, prologue);
    const auto first = noiseWriteFirst(initiator, initiatorPrivate, unhex(plaintexts[0]));
    require(first && *first == unhex(ciphertexts[0]));
    require(!noiseWriteFirst(initiator, initiatorPrivate)); // retransmit cached bytes; never encrypt twice
    require(!noiseFinish(initiator));
    const auto readFirst = noiseReadFirst(responder, *first);
    require(readFirst && *readFirst == unhex(plaintexts[0]));
    const auto second = noiseWriteSecond(responder, responderPrivate, unhex(plaintexts[1]));
    require(second && *second == unhex(ciphertexts[1]));
    const auto readSecond = noiseReadSecond(initiator, *second);
    require(readSecond && *readSecond == unhex(plaintexts[1]));
    require(initiator.hash == key("f4d03dc34495c95729ea6de9e1b59004b59733102488b3e24bc441e0be208eaf"));
    require(initiator.hash == responder.hash);
    const auto clientKeys = noiseFinish(initiator), serverKeys = noiseFinish(responder);
    require(clientKeys && serverKeys);
    require(clientKeys->clientToServer == serverKeys->clientToServer);
    require(clientKeys->serverToClient == serverKeys->serverToClient);
    require(clientKeys->resumeMaster == serverKeys->resumeMaster);
    require(clientKeys->clientProof == serverKeys->clientProof);
    require(clientKeys->clientProof != clientKeys->serverProof);
    require(clientKeys->connectionId == serverKeys->connectionId);
    for (std::size_t i = 2; i < ciphertexts.size(); ++i) {
        const auto& traffic = i % 2 == 0 ? clientKeys->clientToServer : clientKeys->serverToClient;
        const auto nonce = (i - 2) / 2;
        const auto encrypted = noiseSeal(traffic, nonce, {}, unhex(plaintexts[i]));
        require(encrypted && *encrypted == unhex(ciphertexts[i]));
        const auto decrypted = noiseOpen(traffic, nonce, {}, *encrypted);
        require(decrypted && *decrypted == unhex(plaintexts[i]));
    }

    auto wrongPsk = psk; wrongPsk[0] ^= 1;
    auto wrong = noiseStart(wrongPsk, prologue);
    require(!noiseReadFirst(wrong, *first));
    wrong = noiseStart(psk, {});
    require(!noiseReadFirst(wrong, *first));
    for (std::size_t offset = 0; offset < first->size(); ++offset) {
        auto changed = *first; changed[offset] ^= 1;
        auto receiver = noiseStart(psk, prologue);
        require(!noiseReadFirst(receiver, changed));
        require(receiver.phase == NoisePhase::Initial);
    }
    for (std::size_t offset = 0; offset < second->size(); ++offset) {
        auto sender = noiseStart(psk, prologue);
        require(noiseWriteFirst(sender, initiatorPrivate, unhex(plaintexts[0])));
        auto changed = *second; changed[offset] ^= 1;
        require(!noiseReadSecond(sender, changed));
        require(sender.phase == NoisePhase::AwaitingReply);
        require(noiseReadSecond(sender, *second)); // failed authentication did not corrupt the state
    }
    auto replayed = noiseStart(psk, prologue);
    require(noiseReadFirst(replayed, *first));
    auto freshPrivate = responderPrivate; freshPrivate[10] ^= 1;
    require(noiseWriteSecond(replayed, freshPrivate, unhex(plaintexts[1])));
    const auto freshKeys = noiseFinish(replayed);
    require(freshKeys && freshKeys->clientProof != clientKeys->clientProof);
    require(freshKeys->resumeMaster != clientKeys->resumeMaster);
    require(!noiseSeal(psk, UINT64_MAX, {}, {}));
    require(!noiseDh(initiatorPrivate, X25519Key{}));
}
