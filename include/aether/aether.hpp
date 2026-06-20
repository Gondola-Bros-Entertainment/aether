// aether - single-include umbrella header. #include <aether/aether.hpp> to pull in the whole library:
// serialization (generic + varint + automatic delta + bit-pack), the reliable-UDP transport
// (reliability, fragment, channels, congestion, crypto, connection), the peer API + handshake,
// replication (delta / interest / priority / interpolation), the real socket loop, and the
// deterministic TestNet for tests.
#pragma once

// This is an umbrella header: it re-exports the whole library. The includes below are intentional public
// exports, not used-by-this-file, so the include-cleaner / IWYU pragmas below stop the tooling
// from flagging every one as "unused".
// IWYU pragma: begin_exports

// serialization
#include "aether/types.hpp"
#include "aether/serialize.hpp"
#include "aether/reflect.hpp"
#include "aether/varint.hpp"
#include "aether/delta.hpp"
#include "aether/bitpack.hpp"
#include "aether/wire.hpp"
#include "aether/bitserialize.hpp"

// transport
#include "aether/packet.hpp"
#include "aether/socket.hpp"
#include "aether/reliability.hpp"
#include "aether/fragment.hpp"
#include "aether/channel.hpp"
#include "aether/stats.hpp"
#include "aether/crypto.hpp"
#include "aether/x25519.hpp"
#include "aether/random.hpp"
#include "aether/config.hpp"
#include "aether/congestion.hpp"
#include "aether/connection.hpp"

// peer + security
#include "aether/util.hpp"
#include "aether/security.hpp"
#include "aether/peer.hpp"

// replication
#include "aether/interest.hpp"
#include "aether/priority.hpp"
#include "aether/interpolation.hpp"
#include "aether/clocksync.hpp"
#include "aether/replication.hpp"

// IO + testing
#include "aether/net.hpp"
#include "aether/rendezvous.hpp"
#include "aether/simulator.hpp"
#include "aether/testnet.hpp"
// IWYU pragma: end_exports
