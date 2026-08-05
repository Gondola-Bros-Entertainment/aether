// Interest management: pin the totality of both filters on non-finite input. GridInterest's
// cellIndex() must stay defined (never an undefined float->int cast) on non-finite or
// out-of-int-range coordinates -- game positions go NaN/inf after a physics blowup -- mapping them to
// the origin cell instead of UB. RadiusInterest's priorityMod() must return a number on the same
// input and agree with relevant() about what is in range, since its result is multiplied into a
// priority that a stable_sort comparator then orders.
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
        assert(degen.cellSize == 0.0f && degen.invCellSize == 0.0f);
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

    // --- RadiusInterest::priorityMod is total, and cuts where relevant() cuts ---
    // The modifier is multiplied into an entity's accumulated priority and the result is sorted; a
    // NaN there compares false against everything, so the comparator stops being a strict weak
    // ordering and the sort is undefined. A non-finite position therefore has to score a number.
    {
        const aether::RadiusInterest ri = aether::newRadiusInterest(10.0f);
        const aether::Position origin{ 0.0f, 0.0f, 0.0f };

        const aether::Position nan{ NAN, NAN, NAN };
        const aether::Position posInf{ INFINITY, INFINITY, INFINITY };
        const aether::Position negInf{ -INFINITY, -INFINITY, -INFINITY };

        const float pNan    = aether::priorityMod(ri, nan, origin);
        const float pPosInf = aether::priorityMod(ri, posInf, origin);
        const float pNegInf = aether::priorityMod(ri, negInf, origin);
        const float pBoth   = aether::priorityMod(ri, nan, posInf);   // observer non-finite too
        assert(!std::isnan(pNan) && pNan == 0.0f);       // scored out of range, not NaN
        assert(!std::isnan(pPosInf) && pPosInf == 0.0f);
        assert(!std::isnan(pNegInf) && pNegInf == 0.0f);
        assert(!std::isnan(pBoth) && pBoth == 0.0f);

        // relevant() and priorityMod() must agree on the boundary: distSq == radiusSq is in range,
        // and the falloff is exactly 0 there rather than the range test cutting it away early.
        const aether::Position edge{ 10.0f, 0.0f, 0.0f };
        const bool  relEdge = aether::relevant(ri, edge, origin);
        const float pEdge   = aether::priorityMod(ri, edge, origin);
        assert(relEdge);
        assert(pEdge >= 0.0f && pEdge < 1e-6f);

        // A zero radius is the case where the falloff would divide 0 by 0: relevant() calls a
        // co-located entity relevant, so the modifier must be a number, and full priority at that.
        const aether::RadiusInterest zero = aether::newRadiusInterest(0.0f);
        const bool  relZero = aether::relevant(zero, origin, origin);
        const float pZero   = aether::priorityMod(zero, origin, origin);
        assert(relZero);
        assert(!std::isnan(pZero) && pZero == 1.0f);
        const float pZeroAway = aether::priorityMod(zero, aether::Position{ 1.0f, 0.0f, 0.0f }, origin);
        assert(pZeroAway == 0.0f);

        // Sweep: every position agrees between the two, and no modifier is ever NaN or out of [0,1].
        for (int i = -30; i <= 30; ++i) {
            const aether::Position p{ static_cast<float>(i) * 0.5f, 0.0f, 0.0f };
            const bool  rel = aether::relevant(ri, p, origin);
            const float mod = aether::priorityMod(ri, p, origin);
            assert(!std::isnan(mod) && mod >= 0.0f && mod <= 1.0f);
            assert(rel || mod == 0.0f);   // out of range always scores 0
        }

        std::printf("aether interest OK: RadiusInterest priorityMod total on NaN/inf, 0 outside, agrees with relevant() at the radius and at radius 0\n");
    }
    return 0;
}
