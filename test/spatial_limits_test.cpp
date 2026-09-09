#include "check.hpp"
#include "aether/interest.hpp"
#include "aether/interpolation.hpp"

#include <cassert>
#include <cmath>
#include <limits>

int main() {
    using namespace aether;
    const auto radius = newRadiusInterest(1.0e20f);
    aether::test::require(!relevant(radius, {2.0e20f, 0, 0}, {}));
    aether::test::require(priorityMod(radius, {2.0e20f, 0, 0}, {}) == 0.0f);
    const float nearPriority = priorityMod(radius, {5.0e19f, 0, 0}, {});
    aether::test::require(std::isfinite(nearPriority) && std::abs(nearPriority - 0.5f) < 0.00001f);
    const float largest = std::numeric_limits<float>::max();
    aether::test::require(!relevant(newRadiusInterest(largest), {largest, 0, 0}, {-largest, 0, 0}));
    aether::test::require(!relevant(newRadiusInterest(std::numeric_limits<float>::infinity()), {}, {}));
    const auto grid = newGridInterest(1.0f);
    aether::test::require(!relevant(grid, {1.5e9f, 0, 0}, {-1.5e9f, 0, 0}));
    aether::test::require(!relevant(grid, {-1.5e9f, 0, 0}, {1.5e9f, 0, 0}));
    auto snapshots = newSnapshotBufferWithConfig<float>(2, 0.0);
    pushSnapshot(snapshots, 0.0, 0.0f);
    pushSnapshot(snapshots, std::numeric_limits<double>::infinity(), 1000.0f);
    pushSnapshot(snapshots, std::numeric_limits<double>::quiet_NaN(), 2000.0f);
    pushSnapshot(snapshots, 100.0, 100.0f);
    aether::test::require(snapshotCount(snapshots) == 2);
    aether::test::require(sampleSnapshot(snapshots, 50.0) == 50.0f);
    pushSnapshot(snapshots, 200.0, 200.0f);
    aether::test::require(sampleSnapshot(snapshots, 150.0) == 150.0f);
    aether::test::require(!sampleSnapshot(snapshots, std::numeric_limits<double>::infinity()));
}
