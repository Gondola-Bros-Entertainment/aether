// Rendezvous pairing: a Register from a NEW address pairs, a Register from the address already
// waiting is a retry and must not. assert() is the check, so build WITHOUT NDEBUG.
#include "aether/rendezvous.hpp"

#include <cassert>
#include <cstdio>
#include <vector>

using namespace aether;

namespace {
std::vector<std::pair<Address, Bytes>> registerFrom(RendezvousServer& rv, const Address& src,
                                                    std::uint64_t room, MonoTime now) {
    const std::vector<std::pair<Address, Bytes>> in = { { src, encodeRegister(room) } };
    return rendezvousProcess(rv, in, now);
}
MonoTime atSec(double s) { return MonoTime{ static_cast<std::uint64_t>(s * 1.0e9) }; }
} // namespace

int main() {
    const Address a = addrV4(0xC0A80005, 5555);
    const Address b = addrV4(0xC0A80006, 6666);

    // A peer that re-registers before a partner arrives must NOT be paired with itself. hostTick
    // re-sends Register every registerRetryMs until a Paired reply lands, so the first peer into a
    // room always reaches this. Self-pairing handed that peer its own address AND made it stop
    // retrying (a Paired reply clears pendingRoom), so the partner arriving later found the room
    // already consumed and waited out the full TTL: NAT traversal failed for the ordinary case of
    // one peer arriving more than a second before the other.
    {
        RendezvousServer rv;
        assert(registerFrom(rv, a, 77, atSec(0.0)).empty());   // first peer waits, no reply
        assert(rv.waiting.count(77) == 1);

        for (double t = 1.0; t <= 5.0; t += 1.0) {             // the retries hostTick would send
            const auto out = registerFrom(rv, a, 77, atSec(t));
            assert(out.empty());                               // a retry pairs with nothing
        }
        assert(rv.waiting.count(77) == 1);                     // still waiting, not consumed
        assert(rv.sessions.empty());                           // and no bogus self-session
        assert(addrEqual(rv.waiting[77].first, a));
        // the retry refreshed the waiter's TTL clock rather than being ignored outright
        assert(rv.waiting[77].second.ns == atSec(5.0).ns);

        // the real partner then pairs normally, and each side is told about the OTHER one
        const auto paired = registerFrom(rv, b, 77, atSec(6.0));
        assert(paired.size() == 2);
        assert(rv.waiting.empty());                            // room consumed by a real pairing
        assert(rv.sessions.count(77) == 1);
        for (const auto& [to, data] : paired) {
            const auto pr = decodePaired(data);
            assert(pr);
            assert(!addrEqual(to, pr->second));                // never your own address
            if (addrEqual(to, a)) { assert(pr->first == PunchRole::Accept);  assert(addrEqual(pr->second, b)); }
            else                  { assert(pr->first == PunchRole::Connect); assert(addrEqual(pr->second, a)); }
        }
        // the relay session records the two DISTINCT peers, so the relay fallback has a real target
        assert(!addrEqual(rv.sessions[77].a, rv.sessions[77].b));
    }

    // The waiter's TTL refresh is real: without it a peer whose partner is slow would be swept at
    // rendezvousTtlMs even though it kept registering the whole time.
    {
        RendezvousServer rv;
        registerFrom(rv, a, 88, atSec(0.0));
        for (double t = 100.0; t <= 400.0; t += 100.0) registerFrom(rv, a, 88, atSec(t));   // past the 300s TTL
        assert(rv.waiting.count(88) == 1);                     // kept alive by its own retries
        assert(registerFrom(rv, b, 88, atSec(450.0)).size() == 2);
    }

    // Two different rooms stay independent, and a peer registering for a second room does not
    // disturb the first.
    {
        RendezvousServer rv;
        registerFrom(rv, a, 1, atSec(0.0));
        registerFrom(rv, a, 2, atSec(0.0));
        assert(rv.waiting.size() == 2);
        assert(registerFrom(rv, b, 1, atSec(1.0)).size() == 2);
        assert(rv.waiting.count(2) == 1);                      // room 2 untouched
        assert(rv.sessions.count(1) == 1);
    }

    // A third party presenting a known room id must not be able to terminate a LIVE relay session.
    // Registering for a paired room used to fall through to the waiting branch, and the next
    // registration then overwrote the pair -- the two real peers' Relay frames failed the membership
    // test from then on, so anyone who learned a room id could silently kill the relay.
    {
        RendezvousServer rv;
        const Address    evil = addrV4(0xC0A800FF, 9999);
        assert(registerFrom(rv, a, 42, atSec(0)).empty());               // a waits
        assert(registerFrom(rv, b, 42, atSec(0.1)).size() == 2);         // b pairs with it
        assert(rv.sessions.count(42) == 1);
        const RendezvousSession before = rv.sessions.at(42);

        assert(registerFrom(rv, evil, 42, atSec(0.2)).empty());          // stranger: ignored outright
        assert(rv.waiting.count(42) == 0);                               // ...and it did not become a waiter
        assert(registerFrom(rv, evil, 42, atSec(0.3)).empty());
        assert(rv.sessions.count(42) == 1);
        assert(addrEqual(rv.sessions.at(42).a, before.a));               // the live pair is intact
        assert(addrEqual(rv.sessions.at(42).b, before.b));

        // A relay from a real member still works, so the session was not merely frozen.
        const Bytes inner{ 1, 2, 3 };
        const std::vector<std::pair<Address, Bytes>> relay = { { a, encodeRelay(42, inner.data(), inner.size()) } };
        const auto fwd = rendezvousProcess(rv, relay, atSec(0.4));
        assert(fwd.size() == 1 && addrEqual(fwd[0].first, before.b));
    }

    // The rendezvous is a public host, so every frame it accepts is attacker-reachable. Unlimited, two
    // spoofed Registers make it send two Paired replies to addresses of the attacker's choosing.
    {
        RendezvousServer rv;
        const Address    flood = addrV4(0xC0A80010, 1234);
        int              accepted = 0;
        for (std::uint64_t k = 0; k < 200; ++k) {
            registerFrom(rv, flood, 1000 + k, atSec(0.001 * static_cast<double>(k)));
            accepted = static_cast<int>(rv.waiting.size());
        }
        assert(rv.rateLimitDrops > 0);                                   // the limiter actually engaged
        assert(accepted <= rendezvousMaxRequestsPerSecond);              // ...and bounded what one host could claim
    }

    std::printf("rendezvous_test: all assertions passed\n");
    return 0;
}
