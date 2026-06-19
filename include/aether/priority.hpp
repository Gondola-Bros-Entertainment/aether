// aether - priority accumulator. Per-entity
// priority grows over time so every entity is eventually sent even under a tight byte budget.
// Generic over the entity id type. (register is a reserved word in C++, so the ops are prefixed
// priority*.) Data-first: a plain map of entries + free functions.
#pragma once

#include <algorithm>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace aether {

struct PriorityEntry { float base = 0.0f; float accumulated = 0.0f; };

template <class Id>
struct PriorityAccumulator { std::map<Id, PriorityEntry> entries; };

// Register an entity with a base priority (units/sec accumulated each tick).
template <class Id> void priorityRegister(PriorityAccumulator<Id>& pa, const Id& id, float basePriority) {
    pa.entries[id] = PriorityEntry{ basePriority, 0.0f };
}
template <class Id> void priorityUnregister(PriorityAccumulator<Id>& pa, const Id& id) { pa.entries.erase(id); }

// Advance accumulated priority by dt seconds for every entity.
template <class Id> void priorityAccumulate(PriorityAccumulator<Id>& pa, float dt) {
    for (auto& [id, e] : pa.entries) { (void)id; e.accumulated += e.base * dt; }
}
// Scale one entity's accumulated priority (e.g. by an interest modifier).
template <class Id> void priorityApplyModifier(PriorityAccumulator<Id>& pa, const Id& id, float modifier) {
    if (const auto it = pa.entries.find(id); it != pa.entries.end()) it->second.accumulated *= modifier;
}

// Select the highest-priority entities that fit in budgetBytes (sizeFunc(id) -> bytes), in
// priority order; resets the selected entities' accumulated priority.
template <class Id, class SizeFn>
std::vector<Id> priorityDrainTop(PriorityAccumulator<Id>& pa, int budgetBytes, SizeFn sizeFunc) {
    std::vector<std::pair<Id, float>> sorted;
    sorted.reserve(pa.entries.size());
    for (const auto& [id, e] : pa.entries) sorted.emplace_back(id, e.accumulated);
    std::stable_sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

    std::vector<Id> selected;
    int remaining = budgetBytes;
    for (const auto& [id, prio] : sorted) {
        (void)prio;
        const int size = sizeFunc(id);
        if (size > remaining) continue;     // skip; a smaller later entity may still fit
        remaining -= size;
        selected.push_back(id);
    }
    for (const Id& id : selected)
        if (const auto it = pa.entries.find(id); it != pa.entries.end()) it->second.accumulated = 0.0f;
    return selected;
}

template <class Id> int priorityCount(const PriorityAccumulator<Id>& pa) { return static_cast<int>(pa.entries.size()); }
template <class Id> bool priorityIsEmpty(const PriorityAccumulator<Id>& pa) { return pa.entries.empty(); }
template <class Id> std::optional<float> priorityGet(const PriorityAccumulator<Id>& pa, const Id& id) {
    const auto it = pa.entries.find(id);
    if (it == pa.entries.end()) return std::nullopt;
    return it->second.accumulated;
}

} // namespace aether
