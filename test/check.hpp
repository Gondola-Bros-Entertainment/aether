#pragma once

#include <cstdio>
#include <cstdlib>
#include <source_location>

namespace aether::test {
// Unlike assert(), this evaluates state-changing test operations in every build configuration.
template<class Condition>
void require(const Condition& condition, std::source_location where = std::source_location::current()) {
    if (static_cast<bool>(condition)) return;
    std::fprintf(stderr, "Check failed at %s:%u (%s)\n", where.file_name(), where.line(), where.function_name());
    std::abort();
}
} // namespace aether::test
