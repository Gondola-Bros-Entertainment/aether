// aether - security + handshake unit tests that need the static lib (the connect-token seal draws an
// OS-CSPRNG nonce; the handshake draws CSPRNG salts). Pins audit-flagged edges: replay-table eviction
// order, the inclusive token-expiry boundary, the fail-closed unkeyed-accept branch (no plaintext
// zombie), and the hoisted per-source rate gate that bounds the connect-request reflection surface.
#include <aether/aether.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>

int main() {
    // token replay-table eviction: past the cap the OLDEST nonce is evicted, the most-recent survives.
    // Pins the documented bounded-cache tradeoff -- an evicted nonce's token can replay once, while a
    // just-burned recent token stays rejected.
    {
        aether::EncryptionKey K{};
        for (std::size_t i = 0; i < K.size(); ++i) K[i] = static_cast<std::uint8_t>(i * 7 + 1);
        aether::TokenValidator tv = aether::newTokenValidator(/*lifetimeMs=*/1.0e12, /*maxTracked=*/2);
        const aether::ConnectToken tk{ 1, aether::MonoTime{ 1000000000000000000ull }, {} };
        const aether::Bytes a = aether::sealConnectToken(K, tk);   // each seal draws a fresh random
        const aether::Bytes b = aether::sealConnectToken(K, tk);   // nonce, so a/b/c are distinct
        const aether::Bytes c = aether::sealConnectToken(K, tk);   // replay identities

        const auto ra = aether::validateConnectToken(K, tv, a, aether::MonoTime{ 100 });
        const auto rb = aether::validateConnectToken(K, tv, b, aether::MonoTime{ 200 });
        const auto rc = aether::validateConnectToken(K, tv, c, aether::MonoTime{ 300 });   // size 3 > cap 2 -> evict oldest (a)
        assert(!ra.error && !rb.error && !rc.error);

        const auto rcReplay  = aether::validateConnectToken(K, tv, c, aether::MonoTime{ 400 });   // newest, still tracked
        assert(rcReplay.error && *rcReplay.error == aether::TokenError::Replayed);
        const auto raEvicted = aether::validateConnectToken(K, tv, a, aether::MonoTime{ 400 });   // oldest, was evicted
        assert(!raEvicted.error);
        std::printf("aether token-eviction OK: oldest nonce evicted past cap, newest still rejected as replay\n");
    }

    // token expiry is inclusive: rejected at exactly expiresAt (now.ns >= expiresAt.ns).
    {
        aether::EncryptionKey K{};
        for (std::size_t i = 0; i < K.size(); ++i) K[i] = static_cast<std::uint8_t>(i * 3 + 9);
        const std::uint64_t exp = 5000000;
        const aether::Bytes sealed = aether::sealConnectToken(K, aether::ConnectToken{ 7, aether::MonoTime{ exp }, {} });
        const auto before = aether::openConnectToken(K, sealed, aether::MonoTime{ exp - 1 });
        const auto atExp  = aether::openConnectToken(K, sealed, aether::MonoTime{ exp });
        assert(before.has_value());     // one ns before -> valid
        assert(!atExp.has_value());     // exactly at expiry -> rejected
        std::printf("aether token-expiry OK: valid at expiresAt-1, rejected at expiresAt (inclusive)\n");
    }

    // fail closed: a ConnectionAccepted that lands before the session is keyed (no sessionShared, no
    // live resumable master) must NOT bring up an unkeyed (plaintext) connection -- it drops and
    // surfaces a disconnect so the caller re-initiates (peer.hpp handleConnectionAccepted guard).
    {
        const aether::NetworkConfig cfg;
        const aether::Address addrC = aether::addrLocalhost(50001);
        const aether::Address addrS = aether::addrLocalhost(50002);
        const aether::PeerId  idS{ addrS };
        aether::NetPeer C = aether::newPeerState(addrC, cfg, aether::MonoTime{ 0 });
        aether::peerConnect(C, idS, aether::MonoTime{ 0 });   // Outbound pending: no sessionShared, no resumable
        assert(C.pending.count(idS) == 1);

        const auto events = aether::handleConnectionAccepted(C, idS, aether::MonoTime{ 1000000 });
        bool disconnected = false;
        for (const auto& e : events)
            if (e.kind == aether::PeerEvent::Disconnected && e.reason == aether::DisconnectReason::Timeout) disconnected = true;
        assert(disconnected);                    // surfaced a disconnect
        assert(C.connections.count(idS) == 0);   // never came up unkeyed
        assert(C.pending.count(idS) == 0);       // pending cleared
        std::printf("aether fail-closed-accept OK: an unkeyed Accepted drops instead of a plaintext zombie\n");
    }

    // the hoisted per-source rate gate bounds the connect-request reflection surface: a flood of
    // ConnectionRequests from one (spoofable) source elicits at most ~rate challenge replies, not one
    // per request. Before the fix the challenge resend bypassed the limiter (one reply per request).
    {
        aether::NetworkConfig cfg;        // no tokenKey -> no-auth handshake
        cfg.rateLimitPerSecond = 5;
        const aether::Address addrS = aether::addrLocalhost(50010);
        aether::NetPeer S = aether::newPeerState(addrS, cfg, aether::MonoTime{ 0 });
        const aether::PeerId attacker{ aether::addrLocalhost(40000) };
        const aether::Packet req{ aether::PacketHeader{ aether::PacketType::ConnectionRequest,
                                                        aether::SequenceNum{ 0 }, aether::SequenceNum{ 0 }, 0 }, {} };
        const aether::MonoTime now{ 1000000 };
        const int floods = 100;
        for (int i = 0; i < floods; ++i) (void) aether::handleConnectionRequest(S, attacker, req, now);   // all at one instant

        const std::size_t challenges = S.sendQueue.size();   // each queued reply is one challenge datagram
        assert(challenges >= 1);     // the gate still lets legit requests through up to the rate
        assert(challenges < 20);     // ...but bounds the flood -- not one reply per request (~100)
        assert(S.rateLimitDrops >= 60);
        std::printf("aether connect-reflection OK: %zu challenges from %d spoofed requests (rate-gated)\n", challenges, floods);
    }

    std::printf("aether security tests OK\n");
    return 0;
}
