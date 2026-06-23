// aether - boundary tests for the 64-bit anti-replay sliding window (replayAccept, crypto.hpp).
// The basic reorder/replay path is covered in roundtrip.cpp; this pins the WINDOW EDGES that test
// skips: advancing by exactly the full window width, the oldest still-representable counter, the
// counter that just fell out, a duplicate of the high-water mark, and an in-window skip-then-fill.
// Standalone: assert() IS the check, so build WITHOUT -DNDEBUG. No framework.

#include "aether/crypto.hpp"

#include <cassert>
#include <cstdint>
#include <cstdio>

int main() {
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

    std::printf("aether replay-window-boundary OK: full-width jump zeroes window, age-63 in / age-64 out, dup-of-max + redeliver rejected\n");
    return 0;
}
