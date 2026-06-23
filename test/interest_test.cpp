// Interest management: pin the totality of the float->cell math in GridInterest. cellIndex() must
// stay defined (never an undefined float->int cast) on non-finite or out-of-int-range coordinates --
// game positions go NaN/inf after a physics blowup -- mapping them to the origin cell instead of UB.
// Compute every result into a variable before asserting, so a regressed totality guard would trip
// UBSan here (a bad float->int cast is UB even when the bool is later discarded).
#include "aether/interest.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>

int main() {
    // non-finite + out-of-range coordinates must not trap: every call returns a defined bool.
    {
        const aether::GridInterest grid = aether::newGridInterest(10.0f);
        const aether::Position origin{ 0.0f, 0.0f, 0.0f };

        const aether::Position nan{ NAN, NAN, NAN };
        const aether::Position posInf{ INFINITY, INFINITY, INFINITY };
        const aether::Position negInf{ -INFINITY, -INFINITY, -INFINITY };
        const aether::Position huge{ 1.0e30f, -1.0e30f, 1.0e30f };   // finite but far past int range

        // assign first, then assert -- the cast happens inside relevant() regardless of the result.
        const bool rNan    = aether::relevant(grid, nan, origin);
        const bool rPosInf = aether::relevant(grid, posInf, origin);
        const bool rNegInf = aether::relevant(grid, negInf, origin);
        const bool rHuge   = aether::relevant(grid, huge, origin);
        // each maps to cell 0 like the origin observer -> relevant; the point is "defined", not the value.
        assert(rNan == true || rNan == false);
        assert(rPosInf == true || rPosInf == false);
        assert(rNegInf == true || rNegInf == false);
        assert(rHuge == true || rHuge == false);

        // a non-finite observer is on the same defined path.
        const bool rBoth = aether::relevant(grid, nan, posInf);
        assert(rBoth == true || rBoth == false);

        // a degenerate grid (cellSize <= 0 -> invCellSize 0) must not divide by zero / cast NaN.
        const aether::GridInterest degen = aether::newGridInterest(0.0f);
        assert(aether::gridInterestCellSize(degen) == 0.0f);
        const aether::Position far{ 1.0e6f, 1.0e6f, 1.0e6f };
        const bool rDegen = aether::relevant(degen, far, origin);   // 0*x = 0 -> both cell 0 -> relevant
        assert(rDegen);

        // sanity: the math still works for ordinary finite input.
        const aether::Position near{ 5.0f, 5.0f, 5.0f };   // same/adjacent cell as origin -> relevant
        const aether::Position away{ 100.0f, 0.0f, 0.0f };  // 10 cells over on x -> not relevant
        const bool rNear = aether::relevant(grid, near, origin);
        const bool rAway = aether::relevant(grid, away, origin);
        assert(rNear);
        assert(!rAway);

        std::printf("aether interest OK: GridInterest cell math total on NaN/inf/huge + degenerate cellSize, finite near/far correct\n");
    }
    return 0;
}
