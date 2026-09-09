// Create an isolated demo issuer key and two short-lived client credentials.
#include <aether/net.hpp>
#include "credentials.hpp"
#include <cstdio>

int main(int argc, char** argv) try {
    if (argc != 2) { std::fprintf(stderr, "usage: aether_echo_credentials NEW_PRIVATE_DIRECTORY\n"); return 1; }
    const std::filesystem::path directory(argv[1]);
    std::error_code error;
    if (!std::filesystem::create_directory(directory, error) || error) {
        std::fprintf(stderr, "credential directory must be new and its parent must exist\n"); return 1;
    }
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, error);
    if (error) { std::fprintf(stderr, "could not restrict credential directory\n"); return 1; }
    aether::EncryptionKey key{};
    aether::secureRandomBytes(key.data(), key.size());
    const auto write = [&](const char* name, aether::ByteSpan bytes) {
        std::ofstream file(directory / name, std::ios::binary);
        file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        file.close();
        return static_cast<bool>(file);
    };
    bool ok = write("server.key", key);
    const auto epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const aether::UnixTime expiry{static_cast<std::uint64_t>(epoch) + 600ull * 1000000000};
    for (std::uint64_t i = 1; i <= 2; ++i) {
        const auto credential = aether::issueConnectCredential(key, {i, expiry, {}, {aether::defaultProtocolId, aether_example::echoAudience}});
        auto bytes = aether_example::credentialFileBytes(credential);
        ok = write(i == 1 ? "client-1.credential" : "client-2.credential", bytes) && ok;
        aether::detail::secureZero(bytes.data(), bytes.size());
    }
    aether::detail::secureZero(key.data(), key.size());
    if (!ok) { std::fprintf(stderr, "could not write credential files\n"); return 1; }
    std::puts("Created server.key and two client credentials, valid for 10 minutes. Keep these files private.");
    return 0;
}
 catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
