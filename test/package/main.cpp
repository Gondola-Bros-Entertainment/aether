// Minimal package smoke test: include the umbrella (which needs C++20) and link the imported
// target. Compiles only if find_package located the installed headers AND aether::aether
// propagated the C++20 requirement. The CI "package" job builds this against an installed prefix.
#include <aether/aether.hpp>

int main() { return 0; }
