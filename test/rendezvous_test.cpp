#include "check.hpp"
// Rendezvous pairing: a Register from a NEW address pairs, a Register from the address already
// waiting is a retry and must not.
#include "aether/rendezvous.hpp"

#include <cstdio>
#include <vector>

using namespace aether;
using aether::test::require;

namespace {
std::vector<std::pair<Address, Bytes>> registerFrom(RendezvousServer& rv, const Address& src,
                                                    std::uint64_t room, MonoTime now) {
    const std::vector<std::pair<Address, Bytes>> in = { { src, encodeRegister(room) } };
    return rendezvousProcess(rv, in, now);
}
MonoTime atSec(double s) { return MonoTime{ static_cast<std::uint64_t>(s * 1.0e9) }; }
} // namespace

int main() {
    // Only the newcomer receives Paired. The waiting peer's next Register recovers its same role.
    {
        aether::RendezvousServer rv;
        const auto a = aether::addrLocalhost(17001), b = aether::addrLocalhost(17002);
        const auto request = aether::encodeRegister(42);
        require(aether::rendezvousProcess(rv, {{a, request}}, aether::MonoTime{1}).empty());
        const auto pair = aether::rendezvousProcess(rv, {{b, request}}, aether::MonoTime{2});
        require(pair.size() == 2);
        for (std::uint64_t second = 1; second <= 10; ++second) {
            const auto retry = aether::rendezvousProcess(rv, {{a, request}}, aether::MonoTime{second * 1000000000});
            require(retry.size() == 1 && aether::addrEqual(retry[0].first, a));
            const auto paired = aether::decodePaired(retry[0].second);
            require(paired && paired->first == aether::PunchRole::Accept && aether::addrEqual(paired->second, b));
            require(rv.waiting.empty() && rv.sessions.size() == 1);
        }
    }
    const Address a = addrV4(0xC0A80005, 5555);
    const Address b = addrV4(0xC0A80006, 6666);

    // A peer that re-registers before a partner arrives must NOT be paired with itself. hostTick
    // re-sends Register every registerRetryMs until a Paired reply lands, so the first peer into a
    // room always reaches this. Self-pairing would hand that peer its own address AND make it stop
    // retrying (a Paired reply clears pendingRoom), so the partner arriving later would find the room
    // already consumed and wait out the full TTL: NAT traversal would fail for the ordinary case of
    // one peer arriving more than a second before the other.
    {
        RendezvousServer rv;
        require(registerFrom(rv, a, 77, atSec(0.0)).empty());   // first peer waits, no reply
        require(rv.waiting.count(77) == 1);

        for (double t = 1.0; t <= 5.0; t += 1.0) {             // the retries hostTick would send
            const auto out = registerFrom(rv, a, 77, atSec(t));
            require(out.empty());                              // a retry pairs with nothing
        }
        require(rv.waiting.count(77) == 1);                    // still waiting, not consumed
        require(rv.sessions.empty());                          // and no bogus self-session
        require(addrEqual(rv.waiting[77].first, a));
        // the retry refreshed the waiter's TTL clock rather than being ignored outright
        require(rv.waiting[77].second.ns == atSec(5.0).ns);

        // the real partner then pairs normally, and each side is told about the OTHER one
        const auto paired = registerFrom(rv, b, 77, atSec(6.0));
        require(paired.size() == 2);
        require(rv.waiting.empty());                           // room consumed by a real pairing
        require(rv.sessions.count(77) == 1);
        for (const auto& [to, data] : paired) {
            const auto pr = decodePaired(data);
            require(pr);
            require(!addrEqual(to, pr->second));               // never your own address
            if (addrEqual(to, a)) { require(pr->first == PunchRole::Accept);  require(addrEqual(pr->second, b)); }
            else                  { require(pr->first == PunchRole::Connect); require(addrEqual(pr->second, a)); }
        }
        // the relay session records the two DISTINCT peers, so the relay fallback has a real target
        require(!addrEqual(rv.sessions[77].a, rv.sessions[77].b));
    }

    // The waiter's TTL refresh is real: without it a peer whose partner is slow would be swept at
    // rendezvousTtlMs even though it kept registering the whole time.
    {
        RendezvousServer rv;
        registerFrom(rv, a, 88, atSec(0.0));
        for (double t = 100.0; t <= 400.0; t += 100.0) registerFrom(rv, a, 88, atSec(t));   // past the 300s TTL
        require(rv.waiting.count(88) == 1);                    // kept alive by its own retries
        require(registerFrom(rv, b, 88, atSec(450.0)).size() == 2);
    }

    // Two different rooms stay independent, and a peer registering for a second room does not
    // disturb the first.
    {
        RendezvousServer rv;
        registerFrom(rv, a, 1, atSec(0.0));
        registerFrom(rv, a, 2, atSec(0.0));
        require(rv.waiting.size() == 2);
        require(registerFrom(rv, b, 1, atSec(1.0)).size() == 2);
        require(rv.waiting.count(2) == 1);                     // room 2 untouched
        require(rv.sessions.count(1) == 1);
    }

    // A third party presenting a known room id must not be able to terminate a LIVE relay session.
    // If registering for a paired room fell through to the waiting branch, the next registration
    // would overwrite the pair -- the two real peers' Relay frames would fail the membership test
    // from then on, so anyone who learned a room id could silently kill the relay.
    {
        RendezvousServer rv;
        const Address    evil = addrV4(0xC0A800FF, 9999);
        require(registerFrom(rv, a, 42, atSec(0)).empty());              // a waits
        require(registerFrom(rv, b, 42, atSec(0.1)).size() == 2);        // b pairs with it
        require(rv.sessions.count(42) == 1);
        const RendezvousSession before = rv.sessions.at(42);

        require(registerFrom(rv, evil, 42, atSec(0.2)).empty());         // stranger: ignored outright
        require(rv.waiting.count(42) == 0);                              // ...and it did not become a waiter
        require(registerFrom(rv, evil, 42, atSec(0.3)).empty());
        require(rv.sessions.count(42) == 1);
        require(addrEqual(rv.sessions.at(42).a, before.a));              // the live pair is intact
        require(addrEqual(rv.sessions.at(42).b, before.b));

        // A relay from a real member still works, so the session was not merely frozen.
        const Bytes inner{ 1, 2, 3 };
        const std::vector<std::pair<Address, Bytes>> relay = { { a, encodeRelay(42, inner.data(), inner.size()) } };
        const auto fwd = rendezvousProcess(rv, relay, atSec(0.4));
        require(fwd.size() == 1 && addrEqual(fwd[0].first, before.b));
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
        require(rv.rateLimitDrops > 0);                                  // the limiter actually engaged
        require(accepted <= rendezvousMaxRequestsPerSecond);             // ...and bounded what one host could claim
    }

    std::printf("rendezvous_test: all assertions passed\n");
    return 0;
}
