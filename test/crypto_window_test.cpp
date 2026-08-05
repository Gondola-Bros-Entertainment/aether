// aether - published crypto vectors + anti-replay window boundaries (crypto.hpp, x25519.hpp).
//
// Two jobs. The VECTORS come first: ChaCha20, Poly1305, the AEAD in both directions, and X25519,
// each against RFC 8439 / RFC 7748. These primitives are hand-rolled (26-bit Poly1305 limbs, a
// radix-2^16 field, a custom incremental absorb), and a break in any of them is invisible to a
// round-trip test where both ends run the same broken code -- it only shows up against a peer, or
// against the RFC. So the RFC is what they are pinned to. The WINDOW EDGES come second: advancing by
// exactly the full window width, the oldest still-representable counter, the counter that just fell
// out, a duplicate of the high-water mark, and an in-window skip-then-fill -- the cases roundtrip.cpp's
// basic reorder/replay path does not reach.
//
// Standalone: assert() IS the check, so build WITHOUT -DNDEBUG. No framework.

#include "aether/crypto.hpp"
#include "aether/peer.hpp"     // x25519Shared: the fail-closed gate on a degenerate peer public key
#include "aether/x25519.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace {

// Decode a vector from the hex the RFCs print, skipping ':' and whitespace separators so a published
// vector can be pasted as printed.
std::vector<std::uint8_t> hexBytes(const char* h) {
    std::vector<std::uint8_t> out;
    int hi = -1;
    for (const char* p = h; *p != '\0'; ++p) {
        int v = 0;
        if      (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else continue;                                                    // separator
        if (hi < 0) hi = v;
        else { out.push_back(static_cast<std::uint8_t>((hi << 4) | v)); hi = -1; }
    }
    assert(hi < 0);   // an odd digit count means the pasted vector is truncated
    return out;
}

aether::X25519Key hexKey(const char* h) {
    const auto b = hexBytes(h);
    assert(b.size() == 32);
    aether::X25519Key k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = b[i];
    return k;
}

bool sameBytes(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    return std::memcmp(a, b, n) == 0;
}

// The RFC 8439 key used for the AEAD shapes below (A.5's key; any fixed key does, the vectors that
// must match a published tag carry their own).
const char* const aeadTestKey = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";

// --- ChaCha20 -------------------------------------------------------------------------------

// RFC 8439 section 2.3.2: the block function, key 00..1f, nonce 00:00:00:09:00:00:00:4a:00:00:00:00,
// block counter 1.
void testChacha20Block() {
    const auto key   = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto nonce = hexBytes("000000090000004a00000000");
    const auto want  = hexBytes("10f1e7e4d13b5915500fdd1fa32071c4"
                                "c7d1f4c733c068030422aa9ac3d46c4e"
                                "d2826446079faa0914c2d705d98b02a2"
                                "b5129cd1de164eb9cbd083e8a2503c4e");
    assert(key.size() == 32 && nonce.size() == 12 && want.size() == 64);
    std::uint8_t got[64];
    aether::detail::chacha20Block(key.data(), 1, nonce.data(), got);
    assert(sameBytes(got, want.data(), want.size()));
    std::printf("  chacha20 block          RFC 8439 2.3.2 OK\n");
}

// RFC 8439 section 2.4.2: 114 bytes from block counter 1, so the keystream crosses a block boundary
// at offset 64 and the second half must come from counter 2.
void testChacha20Stream() {
    const auto key   = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto nonce = hexBytes("000000000000004a00000000");
    const auto pt    = hexBytes("4c616469657320616e642047656e746c"
                                "656d656e206f662074686520636c6173"
                                "73206f66202739393a20496620492063"
                                "6f756c64206f6666657220796f75206f"
                                "6e6c79206f6e652074697020666f7220"
                                "746865206675747572652c2073756e73"
                                "637265656e20776f756c642062652069"
                                "742e");
    const auto want  = hexBytes("6e2e359a2568f98041ba0728dd0d6981"
                                "e97e7aec1d4360c20a27afccfd9fae0b"
                                "f91b65c5524733ab8f593dabcd62b357"
                                "1639d624e65152ab8f530c359f0861d8"
                                "07ca0dbf500d6a6156a38e088a22b65e"
                                "52bc514d16ccf806818ce91ab7793736"
                                "5af90bbf74a35be6b40b8eedf2785e42"
                                "874d");
    assert(pt.size() == 114 && want.size() == 114);
    std::vector<std::uint8_t> ct(pt.size());
    aether::detail::chacha20Xor(key.data(), 1, nonce.data(), pt.data(), ct.data(), pt.size());
    assert(sameBytes(ct.data(), want.data(), want.size()));

    // The counter must ADVANCE across the boundary: bytes 64.. are block 2's keystream, not a repeat
    // of block 1's. A stalled counter still round-trips locally, so only this catches it.
    std::uint8_t block2[64];
    aether::detail::chacha20Block(key.data(), 2, nonce.data(), block2);
    for (std::size_t i = 64; i < pt.size(); ++i)
        assert(ct[i] == static_cast<std::uint8_t>(pt[i] ^ block2[i - 64]));

    std::vector<std::uint8_t> back(pt.size());
    aether::detail::chacha20Xor(key.data(), 1, nonce.data(), ct.data(), back.data(), ct.size());
    assert(sameBytes(back.data(), pt.data(), pt.size()));   // the stream is its own inverse
    std::printf("  chacha20 stream         RFC 8439 2.4.2 OK (counter crosses a block)\n");
}

// --- Poly1305 -------------------------------------------------------------------------------

// The RFC prints the one-time key as r || s; msgHex may be empty.
void checkPoly1305(const char* keyHex, const char* msgHex, const char* tagHex) {
    const auto key  = hexBytes(keyHex);
    const auto msg  = hexBytes(msgHex);
    const auto want = hexBytes(tagHex);
    assert(key.size() == 32 && want.size() == 16);
    std::uint8_t tag[16];
    aether::detail::poly1305(key.data(), msg.data(), msg.size(), tag);
    assert(sameBytes(tag, want.data(), want.size()));
}

// A.3 prints r and s as separate 16-byte halves; the key is their concatenation.
void checkPoly1305RS(const char* rHex, const char* sHex, const char* msgHex, const char* tagHex) {
    const std::string key = std::string(rHex) + sHex;
    checkPoly1305(key.c_str(), msgHex, tagHex);
}

void testPoly1305Vectors() {
    // The IETF submission text, shared by A.3 vectors #2 and #3 (375 bytes: not a block multiple, so
    // it also exercises the final short block).
    const char* const ietfText =
        "416e79207375626d697373696f6e2074" "6f20746865204945544620696e74656e"
        "6465642062792074686520436f6e7472" "696275746f7220666f72207075626c69"
        "636174696f6e20617320616c6c206f72" "2070617274206f6620616e2049455446"
        "20496e7465726e65742d447261667420" "6f722052464320616e6420616e792073"
        "746174656d656e74206d616465207769" "7468696e2074686520636f6e74657874"
        "206f6620616e20494554462061637469" "7669747920697320636f6e7369646572"
        "656420616e20224945544620436f6e74" "7269627574696f6e222e205375636820"
        "73746174656d656e747320696e636c75" "6465206f72616c2073746174656d656e"
        "747320696e2049455446207365737369" "6f6e732c2061732077656c6c20617320"
        "7772697474656e20616e6420656c6563" "74726f6e696320636f6d6d756e696361"
        "74696f6e73206d61646520617420616e" "792074696d65206f7220706c6163652c"
        "20776869636820617265206164647265" "7373656420746f";

    // Section 2.5.2: "Cryptographic Forum Research Group".
    checkPoly1305("85d6be7857556d337f4452fe42d506a8" "0103808afb0db2fd4abff6af4149f51b",
                  "43727970746f6772617068696320466f" "72756d2052657365617263682047726f" "7570",
                  "a8061dc1305136c6c22b8baf0c0127a9");

    // A.3 #1: an all-zero key over an all-zero message -- r = 0 makes the polynomial vanish, s = 0
    // adds nothing, so the tag is zero. A "tag is never all-zero" shortcut would fail here.
    checkPoly1305RS("00000000000000000000000000000000", "00000000000000000000000000000000",
                    "00000000000000000000000000000000" "00000000000000000000000000000000"
                    "00000000000000000000000000000000" "00000000000000000000000000000000",
                    "00000000000000000000000000000000");
    // A.3 #2: r = 0, so the tag is s regardless of the text.
    checkPoly1305RS("00000000000000000000000000000000", "36e5f6b5c5e06070f0efca96227a863e",
                    ietfText, "36e5f6b5c5e06070f0efca96227a863e");
    // A.3 #3: s = 0, so the tag is the polynomial alone.
    checkPoly1305RS("36e5f6b5c5e06070f0efca96227a863e", "00000000000000000000000000000000",
                    ietfText, "f3477e7cd95417af89a6b8794c310cf0");
    // A.3 #4: 127 bytes, a full-length text with both halves of the key set.
    checkPoly1305RS("1c9240a5eb55d38af333888604f6b5f0", "473917c1402b80099dca5cbc207075c0",
                    "2754776173206272696c6c69672c2061" "6e642074686520736c6974687920746f"
                    "7665730a446964206779726520616e64" "2067696d626c6520696e207468652077"
                    "6162653a0a416c6c206d696d73792077" "6572652074686520626f726f676f7665"
                    "732c0a416e6420746865206d6f6d6520" "7261746873206f757467726162652e",
                    "4541669a7eaaee61e708dc7cbcc5eb62");

    // A.3 #5-#11: the reduction and carry edge cases. Each one is a shape a 26-bit-limb
    // implementation gets wrong in its own way, which is why they are here individually.
    // #5: a partially reduced final result that is still >= p.
    checkPoly1305RS("02000000000000000000000000000000", "00000000000000000000000000000000",
                    "ffffffffffffffffffffffffffffffff", "03000000000000000000000000000000");
    // #6: adding s overflows 2^128.
    checkPoly1305RS("02000000000000000000000000000000", "ffffffffffffffffffffffffffffffff",
                    "02000000000000000000000000000000", "03000000000000000000000000000000");
    // #7: an all-ones data limb with a carry coming in from the limb below.
    checkPoly1305RS("01000000000000000000000000000000", "00000000000000000000000000000000",
                    "ffffffffffffffffffffffffffffffff" "f0ffffffffffffffffffffffffffffff"
                    "11000000000000000000000000000000",
                    "05000000000000000000000000000000");
    // #8: the polynomial part lands on exactly 2^130-5 == p, which must reduce to zero.
    checkPoly1305RS("01000000000000000000000000000000", "00000000000000000000000000000000",
                    "ffffffffffffffffffffffffffffffff" "fbfefefefefefefefefefefefefefefe"
                    "01010101010101010101010101010101",
                    "00000000000000000000000000000000");
    // #9: the polynomial part lands on exactly 2^130-6, one below p, which must NOT reduce.
    checkPoly1305RS("02000000000000000000000000000000", "00000000000000000000000000000000",
                    "fdffffffffffffffffffffffffffffff", "faffffffffffffffffffffffffffffff");
    // #10: the 5*H+L fold produces a 131-bit intermediate.
    checkPoly1305RS("01000000000000000400000000000000", "00000000000000000000000000000000",
                    "e33594d7505e43b90000000000000000" "3394d7505e4379cd0100000000000000"
                    "00000000000000000000000000000000" "01000000000000000000000000000000",
                    "14000000000000005500000000000000");
    // #11: the 5*H+L fold produces a 131-bit FINAL result.
    checkPoly1305RS("01000000000000000400000000000000", "00000000000000000000000000000000",
                    "e33594d7505e43b90000000000000000" "3394d7505e4379cd0100000000000000"
                    "00000000000000000000000000000000",
                    "13000000000000000000000000000000");

    // The empty message: no block is ever absorbed, so the accumulator stays 0 and the tag is s
    // verbatim. resumeMac and makeRetryCookie both seal an empty plaintext, so this shape is live.
    const auto emptyKey = hexBytes("85d6be7857556d337f4452fe42d506a8" "0103808afb0db2fd4abff6af4149f51b");
    std::uint8_t emptyTag[16];
    aether::detail::poly1305(emptyKey.data(), nullptr, 0, emptyTag);
    assert(sameBytes(emptyTag, emptyKey.data() + 16, 16));
    std::printf("  poly1305 vectors        RFC 8439 2.5.2 + A.3 #1-#11 + empty message OK\n");
}

// poly1305Update carries a partial block across calls by hand, so an incremental absorb split at any
// offset must land on the same tag as the one-shot. Every one- and two-cut split of a message that
// spans several blocks, so a partial block gets topped up by another partial block.
void testPoly1305Incremental() {
    const auto key = hexBytes("1c9240a5eb55d38af333888604f6b5f0" "473917c1402b80099dca5cbc207075c0");
    std::vector<std::uint8_t> msg(83);   // not a block multiple
    for (std::size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<std::uint8_t>(i * 7 + 1);

    std::uint8_t want[16];
    aether::detail::poly1305(key.data(), msg.data(), msg.size(), want);

    const std::size_t n = msg.size();
    for (std::size_t i = 0; i <= n; ++i) {
        for (std::size_t j = i; j <= n; ++j) {
            aether::detail::Poly1305State st;
            aether::detail::poly1305Init(st, key.data());
            aether::detail::poly1305Update(st, msg.data(), i);
            aether::detail::poly1305Update(st, msg.data() + i, j - i);
            aether::detail::poly1305Update(st, msg.data() + j, n - j);
            std::uint8_t got[16];
            aether::detail::poly1305Finish(st, got);
            assert(sameBytes(got, want, 16));
        }
    }
    std::printf("  poly1305 incremental    every 1- and 2-cut split of 83 bytes matches one-shot\n");
}

// --- AEAD -----------------------------------------------------------------------------------

// RFC 8439 A.5: the DECRYPT direction, which no round-trip test exercises on its own (a seal/open
// pair agrees with itself even when both are wrong).
void testAeadDecryptVector() {
    const auto key   = hexBytes(aeadTestKey);
    const auto nonce = hexBytes("000000000102030405060708");
    const auto aad   = hexBytes("f33388860000000000004e91");
    const auto tag   = hexBytes("eead9d67890cbb22392336fea1851f38");
    const auto ct    = hexBytes("64a0861575861af460f062c79be643bd" "5e805cfd345cf389f108670ac76c8cb2"
                                "4c6cfc18755d43eea09ee94e382d26b0" "bdb7b73c321b0100d4f03b7f355894cf"
                                "332f830e710b97ce98c8a84abd0b9481" "14ad176e008d33bd60f982b1ff37c855"
                                "9797a06ef4f0ef61c186324e2b350638" "3606907b6a7c02b0f9f6157b53c867e4"
                                "b9166c767b804d46a59b5216cde7a4e9" "9040c5a40433225ee282a1b0a06c523e"
                                "af4534d7f83fa1155b0047718cbc546a" "0d072b04b3564eea1b422273f548271a"
                                "0bb2316053fa76991955ebd63159434e" "cebb4e466dae5a1073a6727627097a10"
                                "49e617d91d361094fa68f0ff77987130" "305beaba2eda04df997b714d6c6f2c29"
                                "a6ad5cb4022b02709b");
    const auto want  = hexBytes("496e7465726e65742d44726166747320" "61726520647261667420646f63756d65"
                                "6e74732076616c696420666f72206120" "6d6178696d756d206f6620736978206d"
                                "6f6e74687320616e64206d6179206265" "20757064617465642c207265706c6163"
                                "65642c206f72206f62736f6c65746564" "206279206f7468657220646f63756d65"
                                "6e747320617420616e792074696d652e" "20497420697320696e617070726f7072"
                                "6961746520746f2075736520496e7465" "726e65742d4472616674732061732072"
                                "65666572656e6365206d617465726961" "6c206f7220746f206369746520746865"
                                "6d206f74686572207468616e20617320" "2fe2809c776f726b20696e2070726f67"
                                "726573732e2fe2809d");
    assert(ct.size() == 265 && want.size() == 265 && aad.size() == 12);

    std::vector<std::uint8_t> out(ct.size(), 0xAA);
    const bool ok = aether::aeadOpenInto(key.data(), nonce.data(), aad.data(), aad.size(),
                                         ct.data(), ct.size(), tag.data(), out.data());
    assert(ok);
    assert(sameBytes(out.data(), want.data(), want.size()));

    // Each of a flipped tag, ciphertext and aad byte must be rejected, and rejection must leave `out`
    // untouched -- the tag is checked before a single plaintext byte is written.
    auto rejects = [&](const std::vector<std::uint8_t>& a, const std::vector<std::uint8_t>& c,
                       const std::vector<std::uint8_t>& t) {
        std::vector<std::uint8_t> sink(c.size(), 0xAA);
        const bool opened = aether::aeadOpenInto(key.data(), nonce.data(), a.data(), a.size(),
                                                 c.data(), c.size(), t.data(), sink.data());
        for (const std::uint8_t b : sink)
            if (b != 0xAA) return false;   // wrote plaintext despite the failure
        return !opened;
    };
    auto flipped = [](std::vector<std::uint8_t> v, std::size_t i) {
        v[i] = static_cast<std::uint8_t>(v[i] ^ 0x01);
        return v;
    };
    const bool badTag = rejects(aad, ct, flipped(tag, 0));
    const bool badCt  = rejects(aad, flipped(ct, ct.size() - 1), tag);
    const bool badAad = rejects(flipped(aad, 0), ct, tag);
    assert(badTag && badCt && badAad);
    std::printf("  aead decrypt            RFC 8439 A.5 OK (tampered tag/ct/aad all rejected)\n");
}

// The empty-plaintext, empty-aad shape, passed as NULL pointers: exactly what resumeMac and
// makeRetryCookie do. The MAC input is then only le64(0) || le64(0), so the tag must equal Poly1305
// over sixteen zero bytes under the block-0 one-time key -- computed here from the primitives the
// vectors above already pinned, so this checks the AEAD framing rather than restating it.
void testAeadEmptyShapes() {
    const auto key = hexBytes(aeadTestKey);
    std::uint8_t nonce[12];
    aether::buildNonce(7, 0x1a2b3c4du, nonce);

    std::uint8_t tag[16];
    aether::aeadSeal(key.data(), nonce, nullptr, 0, nullptr, 0, nullptr, tag);

    std::uint8_t polyKey[64];
    aether::detail::chacha20Block(key.data(), 0, nonce, polyKey);
    const std::uint8_t lengths[16] = {};
    std::uint8_t       want[16];
    aether::detail::poly1305(polyKey, lengths, sizeof lengths, want);
    assert(sameBytes(tag, want, 16));

    const bool ok = aether::aeadOpenInto(key.data(), nonce, nullptr, 0, nullptr, 0, tag, nullptr);
    assert(ok);
    const auto badTag = hexBytes("00000000000000000000000000000000");
    const bool bad    = aether::aeadOpenInto(key.data(), nonce, nullptr, 0, nullptr, 0, badTag.data(), nullptr);
    assert(!bad);

    // makeRetryCookie's real shape: aad present, plaintext empty. The aad must still be bound.
    const auto aad = hexBytes("0011223344556677" "8899aabbccddeeff");
    std::uint8_t cookieTag[16];
    aether::aeadSeal(key.data(), nonce, aad.data(), aad.size(), nullptr, 0, nullptr, cookieTag);
    const bool cookieOk = aether::aeadOpenInto(key.data(), nonce, aad.data(), aad.size(),
                                               nullptr, 0, cookieTag, nullptr);
    assert(cookieOk);
    auto otherAad = aad;
    otherAad[0]   = static_cast<std::uint8_t>(otherAad[0] ^ 0x01);
    const bool cookieBad = aether::aeadOpenInto(key.data(), nonce, otherAad.data(), otherAad.size(),
                                                nullptr, 0, cookieTag, nullptr);
    assert(!cookieBad);
    std::printf("  aead empty shapes       null pt/aad seal+open OK, aad still bound\n");
}

// The AEAD MAC input is aad || pad16 || ct || pad16 || le64(aadLen) || le64(ctLen), the one-time key
// is keystream block 0 and the ciphertext starts at block 1 (RFC 8439 section 2.8). Rebuild all of
// that by hand from the primitives pinned above and check the seal agrees.
//
// This is what pins the LENGTH BLOCK in particular: both lengths are 64-bit little-endian no matter
// how wide the host's size_t is. The hand-built side widens to uint64 explicitly, so a build where
// size_t is 32 bits -- where shifting one by 32 or more is undefined and typically repeats the low
// four bytes -- cannot agree with it.
void testAeadMacInputFraming() {
    const auto key = hexBytes(aeadTestKey);
    std::uint8_t nonce[12];
    aether::buildNonce(3, 0x1a2b3c4du, nonce);

    std::vector<std::uint8_t> pt(37), aad(21);   // neither is block-aligned, so both pads are non-empty
    for (std::size_t i = 0; i < pt.size(); ++i)  pt[i]  = static_cast<std::uint8_t>(i * 11 + 3);
    for (std::size_t i = 0; i < aad.size(); ++i) aad[i] = static_cast<std::uint8_t>(i * 17 + 9);

    std::vector<std::uint8_t> ct(pt.size());
    std::uint8_t              tag[16];
    aether::aeadSeal(key.data(), nonce, aad.data(), aad.size(), pt.data(), pt.size(), ct.data(), tag);

    std::vector<std::uint8_t> macInput;
    macInput.insert(macInput.end(), aad.begin(), aad.end());
    while (macInput.size() % 16 != 0) macInput.push_back(0);
    macInput.insert(macInput.end(), ct.begin(), ct.end());
    while (macInput.size() % 16 != 0) macInput.push_back(0);
    const std::uint64_t aadLen64 = aad.size();
    const std::uint64_t ctLen64  = ct.size();
    for (int i = 0; i < 8; ++i) macInput.push_back(static_cast<std::uint8_t>(aadLen64 >> (8 * i)));
    for (int i = 0; i < 8; ++i) macInput.push_back(static_cast<std::uint8_t>(ctLen64  >> (8 * i)));
    assert(macInput.size() % 16 == 0);

    std::uint8_t polyKey[64];
    aether::detail::chacha20Block(key.data(), 0, nonce, polyKey);
    std::uint8_t want[16];
    aether::detail::poly1305(polyKey, macInput.data(), macInput.size(), want);
    assert(sameBytes(tag, want, 16));

    std::vector<std::uint8_t> wantCt(pt.size());
    aether::detail::chacha20Xor(key.data(), 1, nonce, pt.data(), wantCt.data(), pt.size());
    assert(sameBytes(ct.data(), wantCt.data(), ct.size()));   // ciphertext starts at block 1, not 0
    std::printf("  aead mac framing        pad16 + le64 lengths + block 0/1 split match by hand\n");
}

// Sweep the lengths that straddle the AEAD's two pad16 boundaries (0/15/16/17 and 63/64/65 are all in
// range), with the aad length moving independently so aad padding and ciphertext padding cannot mask
// each other. Round-trip plus a one-bit tamper at every length.
void testAeadLengthSweep() {
    const auto key = hexBytes(aeadTestKey);
    for (std::size_t len = 0; len <= 129; ++len) {
        std::uint8_t nonce[12];
        aether::buildNonce(len, 0x1a2b3c4du, nonce);   // a fresh nonce per message, as the transport does

        std::vector<std::uint8_t> pt(len);
        for (std::size_t i = 0; i < len; ++i) pt[i] = static_cast<std::uint8_t>(i * 31 + len);
        std::vector<std::uint8_t> aad(len % 19);
        for (std::size_t i = 0; i < aad.size(); ++i) aad[i] = static_cast<std::uint8_t>(i * 13 + 5);

        std::vector<std::uint8_t> ct(len);
        std::uint8_t              tag[16];
        aether::aeadSeal(key.data(), nonce, aad.data(), aad.size(), pt.data(), len, ct.data(), tag);

        std::vector<std::uint8_t> out(len, 0xAA);
        const bool ok = aether::aeadOpenInto(key.data(), nonce, aad.data(), aad.size(),
                                             ct.data(), len, tag, out.data());
        assert(ok);
        assert(len == 0 || sameBytes(out.data(), pt.data(), len));

        if (len > 0) {
            ct[len - 1] = static_cast<std::uint8_t>(ct[len - 1] ^ 0x01);
            const bool bad = aether::aeadOpenInto(key.data(), nonce, aad.data(), aad.size(),
                                                  ct.data(), len, tag, out.data());
            assert(!bad);
            ct[len - 1] = static_cast<std::uint8_t>(ct[len - 1] ^ 0x01);
        }
        if (!aad.empty()) {
            aad[0] = static_cast<std::uint8_t>(aad[0] ^ 0x01);
            const bool bad = aether::aeadOpenInto(key.data(), nonce, aad.data(), aad.size(),
                                                  ct.data(), len, tag, out.data());
            assert(!bad);
        }
    }
    std::printf("  aead length sweep       0..129 round-trip + tamper OK (both pad16 boundaries)\n");
}

// --- X25519 ---------------------------------------------------------------------------------

// RFC 7748 section 5.2 (both scalar-multiply vectors) and section 6.1 (the ECDH example, which is
// what pins x25519Base and the two-sided agreement).
void testX25519Vectors() {
    struct MulVector { const char* scalar; const char* point; const char* want; };
    const MulVector muls[] = {
        { "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
          "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" },
        { "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
          "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957" },
    };
    for (const MulVector& v : muls) {
        aether::X25519Key out{};
        aether::x25519(out, hexKey(v.scalar), hexKey(v.point));
        assert(sameBytes(out.data(), hexKey(v.want).data(), out.size()));
    }

    const aether::X25519Key alicePriv = hexKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const aether::X25519Key bobPriv   = hexKey("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    aether::X25519Key alicePub{}, bobPub{}, sharedA{}, sharedB{};
    aether::x25519Base(alicePub, alicePriv);
    aether::x25519Base(bobPub, bobPriv);
    assert(sameBytes(alicePub.data(), hexKey("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").data(), 32));
    assert(sameBytes(bobPub.data(),   hexKey("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").data(), 32));
    aether::x25519(sharedA, alicePriv, bobPub);
    aether::x25519(sharedB, bobPriv, alicePub);
    assert(sameBytes(sharedA.data(), hexKey("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").data(), 32));
    assert(sameBytes(sharedB.data(), sharedA.data(), 32));
    std::printf("  x25519 vectors          RFC 7748 5.2 (x2) + 6.1 ECDH example OK\n");
}

// RFC 7748 section 5.2's iterated vector: k and u start at 9; each round sets k to x25519(k, u) and u
// to the old k. Stopping at 1000 -- the RFC's next checkpoint is 1,000,000, which is minutes of
// ladder here for no assurance a thousand chained results have not already given.
void testX25519Iterated() {
    aether::X25519Key k{}, u{};
    k[0] = 9;
    u[0] = 9;
    for (int i = 0; i < 1000; ++i) {
        aether::X25519Key next{};
        aether::x25519(next, k, u);
        u = k;
        k = next;
        if (i == 0)
            assert(sameBytes(k.data(), hexKey("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079").data(), 32));
    }
    assert(sameBytes(k.data(), hexKey("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51").data(), 32));
    std::printf("  x25519 iterated         RFC 7748 5.2 after 1 and after 1000 OK\n");
}

// The known small-order Curve25519 u-coordinates. Every one drives the ladder to an all-zero shared
// secret -- a constant any observer can compute -- so x25519Shared must return nullopt and kill the
// handshake rather than key a session from it.
void testX25519SmallOrder() {
    const char* const smallOrder[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",   // 0, order 4
        "0100000000000000000000000000000000000000000000000000000000000000",   // 1, order 1
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",   // order 8
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",   // order 8
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   // p-1, order 2
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   // p, order 4
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",   // p+1, order 1
    };
    const aether::X25519Key priv = hexKey("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    for (const char* hex : smallOrder) {
        const aether::X25519Key point = hexKey(hex);
        aether::X25519Key       raw{};
        aether::x25519(raw, priv, point);
        std::uint8_t acc = 0;
        for (const std::uint8_t b : raw) acc = static_cast<std::uint8_t>(acc | b);
        assert(acc == 0);                                        // the ladder really does collapse
        const auto gated = aether::x25519Shared(priv, point);
        assert(!gated);                                          // and the gate really does reject
    }
    // A real peer key still passes the gate, so the check is not rejecting everything.
    aether::X25519Key peerPub{};
    aether::x25519Base(peerPub, hexKey("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    const auto good = aether::x25519Shared(priv, peerPub);
    assert(good);
    std::printf("  x25519 small order      7 low-order points rejected, real key accepted\n");
}

// --- anti-replay window ---------------------------------------------------------------------

void testReplayWindow() {
    using aether::ReplayWindow;
    using aether::replayAccept;
    using aether::replayWindowBits;   // 64
    static_assert(replayWindowBits == 64);

    // Advance by exactly the full window width: the jump is accepted and zeroes the window (every old
    // bit shifts out), so only the new high-water counter is marked. The counter at age 63 (max - 63)
    // is then the oldest the window can still represent -> accepted; the one at age 64 (the original
    // counter) has fallen out -> rejected as too-old. (off-by-one edge of the window.)
    {
        ReplayWindow w;
        const std::uint64_t n = 1000;
        const bool base = replayAccept(w, n);          assert(base);          // first seen -> high-water = n
        const bool jump = replayAccept(w, n + replayWindowBits); assert(jump); // +64: window zeroed, max = n+64
        const bool edge = replayAccept(w, n + 1);      assert(edge);          // age 63: oldest in-window -> accepted
        const bool fell = replayAccept(w, n);          assert(!fell);         // age 64: fell out -> rejected (too-old)
    }

    // Fresh window: accept a high counter, then a counter exactly at the far edge (age 63) is in-window
    // -> accepted; one past it (age 64) is older than the window -> rejected.
    {
        ReplayWindow w;
        const std::uint64_t n = 1000;
        const bool base  = replayAccept(w, n);                       assert(base);    // high-water = n
        const bool inWin = replayAccept(w, n - (replayWindowBits - 1)); assert(inWin);  // age 63 -> accepted
        const bool stale = replayAccept(w, n - replayWindowBits);    assert(!stale);  // age 64 -> rejected
    }

    // A counter equal to the current high-water mark is a duplicate of the max -> rejected as replay.
    {
        ReplayWindow w;
        const bool first = replayAccept(w, 500); assert(first);   // max = 500
        const bool dup   = replayAccept(w, 500); assert(!dup);    // same as max -> replay
    }

    // In-window reorder: skip a counter (advancing the window), then fill the gap -> accepted; the
    // window records it, so re-delivering that same counter -> rejected as replay.
    {
        ReplayWindow w;
        const bool a    = replayAccept(w, 10); assert(a);    // max = 10
        const bool b    = replayAccept(w, 12); assert(b);    // skip 11, max = 12 (bit for 11 still clear)
        const bool fill = replayAccept(w, 11); assert(fill); // in-window, not yet seen -> accepted
        const bool re   = replayAccept(w, 11); assert(!re);  // now seen -> replay
    }

    std::printf("  replay window           full-width jump zeroes window, age-63 in / age-64 out,"
                " dup-of-max + redeliver rejected\n");
}

} // namespace

int main() {
    testChacha20Block();
    testChacha20Stream();
    testPoly1305Vectors();
    testPoly1305Incremental();
    testAeadDecryptVector();
    testAeadEmptyShapes();
    testAeadMacInputFraming();
    testAeadLengthSweep();
    testX25519Vectors();
    testX25519SmallOrder();
    testX25519Iterated();   // slowest; last so a broken primitive reports first
    testReplayWindow();
    std::printf("aether crypto-vectors + replay-window OK\n");
    return 0;
}
