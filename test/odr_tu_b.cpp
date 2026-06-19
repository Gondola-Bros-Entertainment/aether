// Intentionally identical to odr_tu_a.cpp -- and that's the point. The ODR / inline check needs
// the umbrella compiled in TWO separate translation units, then linked: a single TU can't collide
// with itself, so two are the minimum to surface a missing `inline` as a duplicate-symbol error.
#include <aether/aether.hpp>
