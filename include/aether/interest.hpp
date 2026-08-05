// aether - interest management. Decides which entities are relevant to an observer, to cut
// replication bandwidth. RadiusInterest does sphere filtering with distance falloff; GridInterest
// does cell-based filtering. Customized via overloaded free functions relevant()/priorityMod().
#pragma once

#include <cmath>
#include <cstdlib>

namespace aether {

struct Position { float x = 0.0f; float y = 0.0f; float z = 0.0f; };

// --- radius-based: entities within `radius` are relevant; closer = higher priority ---
struct RadiusInterest { float radius = 0.0f; float radiusSq = 0.0f; };
inline RadiusInterest newRadiusInterest(float radius) { return { radius, radius * radius }; }

inline bool relevant(const RadiusInterest& ri, Position entity, Position observer) noexcept {
    const float dx = entity.x - observer.x, dy = entity.y - observer.y, dz = entity.z - observer.z;
    return dx * dx + dy * dy + dz * dz <= ri.radiusSq;
}
// Total for every float input, and cutting at the same place relevant() does. A non-finite position
// (a physics blowup reaches here as readily as it reaches the grid) fails the range test, since every
// comparison against NaN is false, and scores 0 like anything out of range -- a NaN would otherwise
// travel through priorityApplyModifier into the drain comparator, where it compares false both ways
// and stops being the strict weak ordering stable_sort requires.
inline float priorityMod(const RadiusInterest& ri, Position entity, Position observer) noexcept {
    const float dx = entity.x - observer.x, dy = entity.y - observer.y, dz = entity.z - observer.z;
    const float distSq = dx * dx + dy * dy + dz * dz;
    if (!(distSq <= ri.radiusSq)) return 0.0f;       // out of range, or non-finite
    if (ri.radiusSq <= 0.0f) return 1.0f;            // a zero radius has no falloff, and only distSq 0 is in range
    return 1.0f - std::sqrt(distSq / ri.radiusSq);   // linear falloff, exactly 0 at the boundary relevant() includes
}

// --- grid-based: entities in the same or a neighboring cell are relevant ---
struct GridInterest { float cellSize = 0.0f; float invCellSize = 0.0f; };
// cellSize <= 0 is degenerate; map everything to one cell (invCellSize 0) rather than divide by zero
// (which would feed NaN into the int casts in relevant() -- undefined behavior).
inline GridInterest newGridInterest(float cellSize) { return { cellSize, cellSize > 0.0f ? 1.0f / cellSize : 0.0f }; }

namespace detail {
// floor(coord * invCellSize) as an int, total for every float input: a NaN, +/-inf, or out-of-int-
// range product maps to the origin cell (0) instead of an undefined float->int cast. Game positions
// can go non-finite after a physics blowup, so this stays defined rather than UB.
inline int cellIndex(float coord, float invCellSize) noexcept {
    const float c = std::floor(coord * invCellSize);
    return (c >= -2.0e9f && c <= 2.0e9f) ? static_cast<int>(c) : 0;   // the comparison is false for NaN/inf -> 0
}
} // namespace detail

inline bool relevant(const GridInterest& gi, Position entity, Position observer) noexcept {
    const int ex = detail::cellIndex(entity.x, gi.invCellSize),   ey = detail::cellIndex(entity.y, gi.invCellSize),   ez = detail::cellIndex(entity.z, gi.invCellSize);
    const int ox = detail::cellIndex(observer.x, gi.invCellSize), oy = detail::cellIndex(observer.y, gi.invCellSize), oz = detail::cellIndex(observer.z, gi.invCellSize);
    return std::abs(ex - ox) <= 1 && std::abs(ey - oy) <= 1 && std::abs(ez - oz) <= 1;
}
inline float priorityMod(const GridInterest&, Position, Position) noexcept { return 1.0f; }

} // namespace aether
