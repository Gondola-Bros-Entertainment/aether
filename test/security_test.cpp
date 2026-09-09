#include "check.hpp"
// aether - security + handshake unit tests that need the static lib (the connect-token seal draws an
// OS-CSPRNG nonce; the handshake draws CSPRNG salts). Pins audit-flagged edges: replay-table capacity
// rejection, the inclusive token-expiry boundary, the fail-closed unkeyed-accept branch (no plaintext
// zombie), the hoisted per-source rate gate that bounds the connect-request reflection surface, and
// who the rate limiter sheds when its table is full.
#include <aether/aether.hpp>

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>

int main() {
    // Full replay storage rejects new admissions and preserves every unexpired spent token.
    {
        aether::EncryptionKey key{};
        auto tv = aether::newTokenValidator(2);
        const aether::ConnectToken token{1, aether::UnixTime{1000}, {}};
        const auto a = aether::sealConnectToken(key, token);
        const auto b = aether::sealConnectToken(key, token);
        const auto c = aether::sealConnectToken(key, {1, aether::UnixTime{2000}, {}});
        aether::test::require(!aether::validateConnectToken(key, tv, a, {100}).error);
        aether::test::require(!aether::validateConnectToken(key, tv, b, {200}).error);
        aether::test::require(aether::validateConnectToken(key, tv, c, {300}).error == aether::TokenError::ReplayCapacity);
        aether::test::require(aether::validateConnectToken(key, tv, a, {400}).error == aether::TokenError::Replayed);
        aether::test::require(aether::validateConnectToken(key, tv, b, {400}).error == aether::TokenError::Replayed);
        assert(tv.usedNonces.size() == 2);
        // Actual expiry frees capacity; a wall-clock rollback cannot revive the forgotten token.
        aether::test::require(!aether::validateConnectToken(key, tv, c, {1000}).error);
        assert(tv.usedNonces.size() == 1);
        aether::test::require(aether::validateConnectToken(key, tv, a, {500}).error == aether::TokenError::Invalid);
        aether::test::require(aether::validateConnectToken(key, tv, c, {1100}).error == aether::TokenError::Replayed);
        auto disabled = aether::newTokenValidator(0);
        aether::test::require(aether::validateConnectToken(key, disabled, c, {1000}).error == aether::TokenError::ReplayCapacity);
        assert(disabled.usedNonces.empty());
    }

    // token expiry is inclusive: rejected at exactly expiresAt (now.ns >= expiresAt.ns).
    {
        aether::EncryptionKey K{};
        for (std::size_t i = 0; i < K.size(); ++i) K[i] = static_cast<std::uint8_t>(i * 3 + 9);
        const std::uint64_t exp = 5000000;
        const aether::Bytes sealed = aether::sealConnectToken(K, aether::ConnectToken{ 7, aether::UnixTime{ exp }, {} });
        const auto before = aether::openConnectToken(K, sealed, aether::UnixTime{ exp - 1 });
        const auto atExp  = aether::openConnectToken(K, sealed, aether::UnixTime{ exp });
        assert(before.has_value());     // one ns before -> valid
        assert(!atExp.has_value());     // exactly at expiry -> rejected
        std::printf("aether token-expiry OK: valid at expiresAt-1, rejected at expiresAt (inclusive)\n");
    }

    // fail closed: a ConnectionAccepted that lands before the session is keyed (no sessionShared, no
    // live resumable master) must NOT bring up an unkeyed (plaintext) connection. It must not tear the
    // pending down either: an Accepted is cleartext and unauthenticated by definition, so cancelling a
    // handshake on one hands a single injected packet the power to abort any connect attempt -- and
    // silently, because the erased pending is no longer there for cleanupPending to time out on.
    {
        const aether::NetworkConfig cfg;
        const aether::Address addrC = aether::addrLocalhost(50001);
        const aether::Address addrS = aether::addrLocalhost(50002);
        const aether::PeerId  idS{ addrS };
        aether::NetPeer C = aether::newPeerState(addrC, cfg, aether::MonoTime{ 0 });
        aether::peerConnect(C, idS, aether::MonoTime{ 0 });   // Outbound pending: no sessionShared, no resumable
        assert(C.pending.count(idS) == 1);

        const auto events = aether::handleConnectionAccepted(C, idS, aether::MonoTime{ 1000000 });
        assert(events.empty());                  // nothing to report yet: the attempt has not failed
        assert(C.connections.count(idS) == 0);   // never came up unkeyed
        assert(C.pending.count(idS) == 1);       // ...and the handshake in flight is untouched

        // and if nothing ever keys it, the caller still hears the outcome
        const std::uint64_t past = static_cast<std::uint64_t>(cfg.connectionRequestTimeoutMs) * 2000000ull;
        const auto expired = aether::peerProcess(C, aether::MonoTime{ past }, {});
        bool timedOut = false;
        for (const auto& e : expired.events)
            if (e.kind == aether::PeerEvent::Disconnected && e.reason == aether::DisconnectReason::Timeout) timedOut = true;
        assert(timedOut);
        std::printf("aether fail-closed-accept OK: an unkeyed Accepted keys nothing and cancels nothing\n");
    }

    // at maxTrackedSources the limiter must evict the STALEST source rather than shed every new one.
    // A flood from spoofed sources keeps all of its own entries inside the window, so a prune frees
    // nothing and shedding the newcomer hands the whole table to whoever is flooding. This gate also
    // runs ahead of the retry cookie, so a shed address cannot prove routability to earn its way back:
    // every new connection, resume and migration on the server stops until the flood does.
    {
        aether::RateLimiter rl = aether::newRateLimiter(/*maxReqs=*/10, aether::MonoTime{ 0 });
        constexpr std::uint64_t floodBase = 1000, freshBase = 900000;
        for (int i = 0; i < aether::rateLimiterMaxSources; ++i)
            (void) aether::rateLimiterAllow(rl, floodBase + static_cast<std::uint64_t>(i), aether::MonoTime{ 0 });
        assert(static_cast<int>(rl.requests.size()) == aether::rateLimiterMaxSources);

        int admitted = 0;
        for (int round = 1; round <= 3; ++round) {
            // 100ms apart, so every flooded entry stays well inside the 1s window and a prune has
            // nothing to reclaim -- occupancy is entirely the flooder's doing, which is the point.
            const aether::MonoTime now{ static_cast<std::uint64_t>(round) * 100000000ull };
            for (int i = 0; i < 512; ++i) (void) aether::rateLimiterAllow(rl, floodBase + static_cast<std::uint64_t>(i), now);
            if (aether::rateLimiterAllow(rl, freshBase + static_cast<std::uint64_t>(round), now)) admitted += 1;
        }
        assert(admitted == 3);                                                             // every new source got in
        assert(static_cast<int>(rl.requests.size()) <= aether::rateLimiterMaxSources);     // ...and the cap still holds
        std::printf("aether rate-limit capacity OK: %d new sources admitted with the table pinned full (%zu tracked)\n",
                    admitted, rl.requests.size());
    }

    // ...and the same thing at the peer: a genuine client still earns its retry cookie from a server
    // whose tracked-source table is full.
    {
        aether::NetPeer S = aether::newPeerState(aether::addrLocalhost(50020), aether::NetworkConfig{}, aether::MonoTime{ 0 });
        const aether::MonoTime now{ 1000000 };
        for (int i = 0; i < aether::rateLimiterMaxSources; ++i)
            (void) aether::rateLimiterAllow(S.rateLimiter, static_cast<std::uint64_t>(i) + 1, now);
        assert(static_cast<int>(S.rateLimiter.requests.size()) == aether::rateLimiterMaxSources);

        const aether::PeerId client{ aether::addrV4(0x0A000001u, 5000) };
        const aether::Packet req{ aether::PacketHeader{ aether::PacketType::ConnectionRequest,
                                                        aether::SequenceNum{ 0 }, aether::SequenceNum{ 0 }, 0 },
                                  aether::encodeConnectionRequest({}, {}) };
        (void) aether::handleConnectionRequest(S, client, req, now);
        assert(S.sendQueue.size() == 1);   // answered, not shed
        std::printf("aether rate-limit capacity OK: a new client is still answered under a full table\n");
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
        // Well-formed but uncookied: the reply is now a stateless retry cookie rather than a
        // challenge, which is the reflection surface the rate gate has to bound.
        const aether::Packet req{ aether::PacketHeader{ aether::PacketType::ConnectionRequest,
                                                        aether::SequenceNum{ 0 }, aether::SequenceNum{ 0 }, 0 },
                                  aether::encodeConnectionRequest({}, {}) };
        const aether::MonoTime now{ 1000000 };
        const int floods = 100;
        for (int i = 0; i < floods; ++i) (void) aether::handleConnectionRequest(S, attacker, req, now);   // all at one instant

        const std::size_t replies = S.sendQueue.size();   // each queued reply is one datagram back to the (spoofable) source
        assert(replies >= 1);        // the gate still lets legit requests through up to the rate
        assert(replies < 20);        // ...but bounds the flood -- not one reply per request (~100)
        assert(S.rateLimitDrops >= 60);
        assert(S.pending.empty());   // and a flood without a valid cookie allocates nothing at all
        std::printf("aether connect-reflection OK: %zu retries from %d spoofed requests (rate-gated, 0 pending)\n", replies, floods);
    }

    std::printf("aether security tests OK\n");
    return 0;
}
