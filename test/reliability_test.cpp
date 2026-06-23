// Loss-window unit test: pins lossCount() + the sliding 256-bit LossWindow
// (recordLossSample / packetLossPercent). assert() is the check, so build WITHOUT
// NDEBUG. Data-first: plain structs + free functions, no framework.
#include "aether/reliability.hpp"

#include <cassert>
#include <cstdio>

int main() {
    using namespace aether;

    // lossCount over a hand-set window. Exercises every branch of the per-word loop,
    // especially take==64 (the boundary the code special-cases to dodge 1<<64 UB).
    {
        LossWindow w{};

        // empty window: nothing lost regardless of how many positions we count
        assert(lossCount(w, 0)   == 0);
        assert(lossCount(w, 1)   == 0);
        assert(lossCount(w, 256) == 0);

        // n clamps to [0, 256]; negative/zero -> 0, oversized -> 256 positions
        assert(lossCount(w, -5)   == 0);
        assert(lossCount(w, 9999) == 0);

        // mark every bit lost across all four 64-bit words
        for (int i = 0; i < lossWindowSize; ++i) lossSet(w, i, true);
        // n < 64 (the take=n, mask=(1<<n)-1 branch): only the low n bits of word 0
        assert(lossCount(w, 1)  == 1);
        assert(lossCount(w, 13) == 13);
        assert(lossCount(w, 63) == 63);
        // n == 64 exactly: take==64 special-case mask (~0), whole first word, no 1<<64
        assert(lossCount(w, 64) == 64);
        // spilling into the second word: 64 (take==64) + remainder (n<64) branch
        assert(lossCount(w, 65)  == 65);
        assert(lossCount(w, 128) == 128);   // two full words, both via take==64
        assert(lossCount(w, 200) == 200);   // three full words + 8 remainder
        assert(lossCount(w, 256) == 256);   // all four words via take==64

        // a known partial pattern: clear the even indices, every odd index stays lost
        for (int i = 0; i < lossWindowSize; i += 2) lossSet(w, i, false);
        assert(lossCount(w, 256) == 128);   // half of 256 lost
        assert(lossCount(w, 64)  == 32);    // half of the take==64 word lost
        assert(lossCount(w, 10)  == 5);     // 1,3,5,7,9 lost in [0,10)
    }

    // sliding window via recordLossSample: count caps at the window size, index wraps
    // modulo it, and packetLossPercent = lostInWindow / countInWindow.

    // all-received -> 0% loss
    {
        ReliableEndpoint ep{};
        for (int i = 0; i < 100; ++i) recordLossSample(ep, false);
        assert(ep.lossWindowCount == 100 && ep.lossWindowIndex == 100);
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == 0);
        assert(packetLossPercent(ep) == 0.0);
    }

    // a known partial-loss ratio: every 4th packet lost over a sub-full window -> 25%
    {
        ReliableEndpoint ep{};
        const int n = 200;
        int expectLost = 0;
        for (int i = 0; i < n; ++i) {
            const bool lost = (i % 4 == 0);
            if (lost) ++expectLost;
            recordLossSample(ep, lost);
        }
        assert(ep.lossWindowCount == n);   // still under the 256 cap, no aging yet
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == expectLost);
        assert(expectLost == 50);
        const double pct = packetLossPercent(ep);
        assert(pct > 0.249 && pct < 0.251);   // 50/200 == 0.25
    }

    // overflowing window: feed > 256 samples so the oldest age out (index wraps mod 256).
    // First fill 256 as all-lost, then push 256 all-received: every original lost sample
    // is overwritten, so the window reads 0% even though half of all samples were lost.
    {
        ReliableEndpoint ep{};
        for (int i = 0; i < lossWindowSize; ++i) recordLossSample(ep, true);    // window full, all lost
        assert(ep.lossWindowCount == lossWindowSize);
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == lossWindowSize); // 256 lost
        assert(packetLossPercent(ep) == 1.0);                                   // 100%

        for (int i = 0; i < lossWindowSize; ++i) recordLossSample(ep, false);   // overwrite all 256 slots
        assert(ep.lossWindowCount == lossWindowSize);                           // count stays capped at 256
        assert(ep.lossWindowIndex == 2 * lossWindowSize);                       // index keeps climbing
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == 0);              // old losses aged out
        assert(packetLossPercent(ep) == 0.0);

        // one more wrapped write lands at slot (512 % 256 == 0): mark it lost -> exactly 1 in 256
        recordLossSample(ep, true);
        assert(ep.lossWindowCount == lossWindowSize);
        assert(lossCount(ep.lossWindow, ep.lossWindowCount) == 1);
        const double pct = packetLossPercent(ep);
        assert(pct > 0.0039 && pct < 0.0040);   // 1/256 ~= 0.00390625
    }

    std::printf("aether loss-window OK: lossCount take==64 mask, overflow aging, 0%%/25%%/100%% ratios exact\n");
    return 0;
}
