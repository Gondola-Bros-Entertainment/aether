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
struct PriorityAccumulator {
    std::map<Id, PriorityEntry>                      entries;
    std::vector<std::pair<const Id, PriorityEntry>*> scratch;   // reused by priorityDrainTop (rebuilt per call); avoids a per-tick alloc
};

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
    pa.scratch.clear();                                        // reused buffer -> no per-call allocation
    for (auto& kv : pa.entries) pa.scratch.push_back(&kv);     // pointers into entries, no Id copy
    std::stable_sort(pa.scratch.begin(), pa.scratch.end(),
                     [](const auto* a, const auto* b) { return a->second.accumulated > b->second.accumulated; });

    std::vector<Id> selected;
    int remaining = budgetBytes;
    for (auto* kv : pa.scratch) {
        const int size = sizeFunc(kv->first);
        if (size > remaining) continue;          // skip; a smaller later entity may still fit
        remaining -= size;
        selected.push_back(kv->first);
        kv->second.accumulated = 0.0f;           // reset through the pointer -- no second find
    }
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
