#include "check.hpp"
#include <aether/handshake_crypto.hpp>
#include <string>
#include <string_view>

namespace {
aether::ByteSpan bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
}
std::string hex(aether::ByteSpan value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (const auto byte : value) { out += digits[byte >> 4]; out += digits[byte & 15]; }
    return out;
}
}

int main() {
    using namespace aether;
    using namespace aether::detail;
    using aether::test::require;
    require(hex(sha256({})) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    require(hex(sha256(bytes("abc"))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    require(hex(sha256(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")))
        == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    Sha256 incremental;
    const std::string block(1000, 'a');
    for (int i = 0; i < 1000; ++i) sha256Update(incremental, bytes(block));
    require(hex(sha256Finish(incremental)) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    // RFC 4231 cases 1 and 6 (the latter hashes an overlong HMAC key first).
    require(hex(hmacSha256(Bytes(20, 0x0b), bytes("Hi There")))
        == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    require(hex(hmacSha256(Bytes(131, 0xaa), bytes("Test Using Larger Than Block-Size Key - Hash Key First")))
        == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    // RFC 5869 case 3: SHA-256 with empty salt and info, the HKDF shape Noise uses.
    const auto expanded = noiseHkdf<2>({}, Bytes(22, 0x0b));
    const auto hkdfHex = hex(expanded[0]) + hex(expanded[1]);
    require(hkdfHex.substr(0, 84)
        == "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    for (std::size_t length = 0; length < 150; ++length) {
        Bytes data(length, 0x42);
        const auto expected = sha256(data);
        for (std::size_t split = 0; split <= length; ++split) {
            Sha256 state;
            sha256Update(state, ByteSpan(data).first(split));
            sha256Update(state, ByteSpan(data).subspan(split));
            require(sha256Finish(state) == expected);
        }
    }
}
