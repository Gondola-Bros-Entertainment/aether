#pragma once

#include <cstdio>
#include <cstdlib>
#include <source_location>

namespace aether::test {
// Checks a test condition in every build configuration: unlike the assert macro, NDEBUG does not
// remove it, so the condition and any call inside it always run.
template<class Condition>
void require(const Condition& condition, std::source_location where = std::source_location::current()) {
    if (static_cast<bool>(condition)) return;
    std::fprintf(stderr, "Check failed at %s:%u (%s)\n", where.file_name(), where.line(), where.function_name());
    std::abort();
}
// Anonymous transport scenarios opt in without changing production defaults.
template<class Config>
Config anonymousConfig() { Config config; config.allowUnauthenticated = true; return config; }
} // namespace aether::test
