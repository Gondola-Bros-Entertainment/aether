// Compile check: the umbrella header must pull in the whole library on its own. Granular
// per-module headers are the primary interface (include what you use); aether.hpp is the
// optional single-include convenience, like <boost/asio.hpp> or <Eigen/Dense>.
#include "aether/aether.hpp"

int main() {
    // touch a real type through the umbrella, so the include is genuinely used (no pragma needed)
    // and we prove the library is reachable, not just that the header parses.
    aether::NetworkConfig cfg{};
    return cfg.maxClients > 0 ? 0 : 1;   // sane default reached through the umbrella
}
