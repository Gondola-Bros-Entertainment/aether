# Migrating to 0.2

0.2 changes the wire and authentication APIs. Upgrade client and server together.
Packet version 2 keeps the 17-byte header but rejects version 1. Tokens use the
`TKN2` AEAD domain and include scope and a client PSK; reissue old tokens. Cached
sessions do not cross process/version boundaries. There is no fallback to old wire formats.

- Replace `sealConnectToken` as the normal issuer entry point with
  `issueConnectCredential(key, claims)`, including a nonzero protocol/audience scope.
  Send its complete `ConnectCredential` through your trusted application backend.
- Set the admitting host's `tokenKey` and `tokenAudience`. The client's `protocolId`
  must match its credential. `peerConnectWithToken`/`hostConnectWithToken` now accept
  the credential object, not bearer bytes. Token/credential user data is capped at 256 bytes.
- `peerConnect`, credential connect and reconnect, plus their host wrappers, return
  `optional<ConnectError>` (empty means started). Handle invalid address, state,
  capacity, credential and missing-authentication failures.
- `peerConnect`/`hostConnect` are anonymous development/P2P entry points. Set
  `allowUnauthenticated = true` explicitly to use them; this does not authenticate
  initial keys. The built-in room helper requires that same opt-in.
- Resume now performs fresh proof. `peerReconnect` and `hostReconnect` take an optional
  fresh fallback credential. Unknown server state waits for the local resume deadline
  before using it. Both endpoints report `Reconnected` for successful resumption.
- Preserve `PeerEvent::userData` alongside `playerId` when using backend claims.
  The admitting server emits both; the client does not self-assert a verified player ID.
- `peerBroadcast` returns failures. Drain `hostTakeDiagnostics` for broadcast/socket
  failures and inspect cumulative socket counters. A successful enqueue is not delivery.
- Connection queries exclude Disconnecting state. `hostShutdown` flushes disconnects;
  keep ticking if retries are wanted, then call `closeHost`. Closing clears session state.
- `validateConnectToken` now requires an explicit expected `TokenScope`. It is a
  low-level claim-and-spend helper for authorities that already checked possession;
  it is not a substitute for the network handshake.

Finite timers/rates, positive request budgets, bounded retry counts and the 65507-byte
UDP ceiling are now validated. `maxResumableSessions` defaults to 64 and may be zero
when resumption should be disabled. Resolution/formatting APIs live in `socket.hpp`;
perform DNS work outside the game loop.

Account authentication, credential issuance policy, revocation, durable/global replay
storage, game commands and server deployment remain application responsibilities.
