// File provisioning for the echo demo only. A real application distributes credentials
// through its authenticated backend, and never sends the issuer's sealing key to clients.
#pragma once
#include "common.hpp"
#include <aether/security.hpp>
#include <aether/net.hpp>
#include <aether/config.hpp>
#include <fstream>
#include <cstdio>
#include <filesystem>

namespace aether_example {
inline constexpr std::uint64_t echoAudience = 0x4543484f;
inline std::optional<aether::Bytes> readPrivateFile(const std::filesystem::path& path, std::size_t limit) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return std::nullopt;
    aether::Bytes bytes(limit + 1);
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    const auto count = static_cast<std::size_t>(file.gcount());
    if (count > limit || file.bad()) return std::nullopt;
    bytes.resize(count);
    return bytes;
}
inline std::optional<aether::EncryptionKey> readServerKey(const std::filesystem::path& path) {
    auto bytes = readPrivateFile(path, aether::EncryptionKey{}.size());
    if (!bytes || bytes->size() != aether::EncryptionKey{}.size()) return std::nullopt;
    aether::EncryptionKey key{};
    std::copy(bytes->begin(), bytes->end(), key.begin());
    aether::detail::secureZero(bytes->data(), bytes->size());
    return aether::nonzeroKey(key) ? std::optional{key} : std::nullopt;
}
inline aether::Bytes credentialFileBytes(const aether::ConnectCredential& credential) {
    // Demo file v2: version, protocol u32 LE, audience u64 LE, expiry u64 LE, PSK32, sealed token.
    aether::Bytes bytes(53);
    bytes[0] = 2;
    aether::putU32(bytes.data() + 1, credential.scope.protocolId);
    aether::putU64(bytes.data() + 5, credential.scope.audience);
    aether::putU64(bytes.data() + 13, credential.expiresAt.ns);
    std::copy(credential.proofKey.begin(), credential.proofKey.end(), bytes.begin() + 21);
    bytes.insert(bytes.end(), credential.token.begin(), credential.token.end());
    return bytes;
}
inline std::optional<aether::ConnectCredential> readCredential(const std::filesystem::path& path) {
    auto bytes = readPrivateFile(path, 53 + aether::maxSealedConnectTokenBytes);
    if (!bytes || bytes->size() < 53 || (*bytes)[0] != 2) return std::nullopt;
    aether::ConnectCredential credential;
    credential.scope = {aether::detail::cryptoLe32(bytes->data() + 1), aether::getU64(bytes->data() + 5)};
    credential.expiresAt = {aether::getU64(bytes->data() + 13)};
    std::copy_n(bytes->begin() + 21, credential.proofKey.size(), credential.proofKey.begin());
    credential.token.assign(bytes->begin() + 53, bytes->end());
    aether::detail::secureZero(bytes->data(), bytes->size());
    return credential;
}
inline bool reportDiagnostics(aether::Host& host) {
    const auto diagnostics = aether::hostTakeDiagnostics(host);
    for (const auto& failure : diagnostics.ioErrors)
        std::fprintf(stderr, "socket %s failed (code %d, native %d)\n",
            failure.operation == aether::HostIoOperation::Send ? "send" : "receive",
            static_cast<int>(failure.error.code), failure.error.nativeCode);
    return diagnostics.ioErrors.empty() && diagnostics.queueErrors.empty();
}
} // namespace aether_example
