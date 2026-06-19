// ODR / inline check (paired with odr_tu_b.cpp): the umbrella header is included in two
// translation units linked into one shared library. If any header defined a function at
// namespace scope without `inline`, it would be a duplicate symbol here and the link would
// fail. No main -- the link step is the test.
#include <aether/aether.hpp>
