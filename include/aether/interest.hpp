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
inline float radiusInterestRadius(const RadiusInterest& ri) noexcept { return ri.radius; }

inline bool relevant(const RadiusInterest& ri, Position entity, Position observer) noexcept {
    const float dx = entity.x - observer.x, dy = entity.y - observer.y, dz = entity.z - observer.z;
    return dx * dx + dy * dy + dz * dz <= ri.radiusSq;
}
inline float priorityMod(const RadiusInterest& ri, Position entity, Position observer) noexcept {
    const float dx = entity.x - observer.x, dy = entity.y - observer.y, dz = entity.z - observer.z;
    const float distSq = dx * dx + dy * dy + dz * dz;
    if (distSq >= ri.radiusSq) return 0.0f;
    return 1.0f - std::sqrt(distSq / ri.radiusSq);   // linear falloff
}

// --- grid-based: entities in the same or a neighboring cell are relevant ---
struct GridInterest { float cellSize = 0.0f; float invCellSize = 0.0f; };
inline GridInterest newGridInterest(float cellSize) { return { cellSize, 1.0f / cellSize }; }
inline float gridInterestCellSize(const GridInterest& gi) noexcept { return gi.cellSize; }

inline bool relevant(const GridInterest& gi, Position entity, Position observer) noexcept {
    const int ex = static_cast<int>(std::floor(entity.x * gi.invCellSize));
    const int ey = static_cast<int>(std::floor(entity.y * gi.invCellSize));
    const int ez = static_cast<int>(std::floor(entity.z * gi.invCellSize));
    const int ox = static_cast<int>(std::floor(observer.x * gi.invCellSize));
    const int oy = static_cast<int>(std::floor(observer.y * gi.invCellSize));
    const int oz = static_cast<int>(std::floor(observer.z * gi.invCellSize));
    return std::abs(ex - ox) <= 1 && std::abs(ey - oy) <= 1 && std::abs(ez - oz) <= 1;
}
inline float priorityMod(const GridInterest&, Position, Position) noexcept { return 1.0f; }

} // namespace aether
