# Authenticated Aether sessions

Aether 0.2 instantiates `Noise_NNpsk0_25519_ChaChaPoly_SHA256` and wraps it in bounded
UDP admission, retry and key-confirmation messages. Noise has a formal specification
for a family of protocols; this implementation supports one concrete pattern.
The Noise messages match independent vectors. The envelope and exported confirmation
values below are Aether protocol choices, not additional Noise-standard messages.

## Trust and issuance

A trusted application backend authenticates the player, then calls
`issueConnectCredential(issuerKey, ConnectToken{playerId, expiry, userData, scope})`.
It draws a unique 32-byte PSK from the OS CSPRNG, seals the claims, and returns a
`ConnectCredential` containing the sealed bytes, separate PSK, scope and expiry.
Deliver that complete object through the backend's authenticated confidential channel.
The issuer key belongs only on the backend and admitting servers. Each client receives
its own PSK; it cannot open another player's token. Cloudflare, SSH and CI credentials
have no role in this protocol.

The client authenticates a responder that possesses its credential PSK, obtained here
by opening its token with the issuer key. The server authenticates possession of that
same PSK and the issuer's player claims. This is symmetric credential authentication,
not a certificate system or a human/account login. The application chooses a nonzero
protocol ID and audience; the server requires exact matches. Compromise of the issuer
key permits issuing credentials and impersonating servers in that trust domain.

Token plaintext is little-endian `playerId:u64`, `expiresAtUnixNs:u64`,
`protocolId:u32`, `audience:u64`, `psk:32`, then up to 256 opaque user-data bytes.
ChaCha20-Poly1305 seals it with AAD `TKN2` and a random 12-byte nonce. The wire token
is nonce, ciphertext, tag (88..344 bytes). The PSK travels inside this seal, not as a
clear field in a game datagram. Expiry is checked at request and proof completion.
The replay table spends the nonce only at successful admission, failing closed when full.

Replay protection is in memory and local to one validator. Keep the table or rotate
the issuer key after state loss. Multiple servers sharing a key/audience need shared
application policy/state if global single use is required. Credentials should be
short-lived; revocation and long-lived session policy belong to the application.

## Wire transcript

The outer 17-byte packet header carries wire version 2. Handshake datagrams use
CRC32C for accidental corruption; the CRC does not authenticate them. Integers in
the following envelope are little-endian.

`ConnectionRequest` carries `cookieLength:u8`, an optional 28-byte cookie, and:

| Offset | Field |
| --- | --- |
| 0 | Tag `0xa2` |
| 1 | Mode: 1 credential, 2 resume |
| 2 | Nonzero session handle, u64 |
| 10 | Fresh nonzero attempt ID, u64 |
| 18 | Protocol ID, u32 |
| 22 | Audience, u64 |
| 30 | Sealed-token length, u16 |
| 32 | Sealed token; empty for resume |
| after token | Noise first message, exactly 48 bytes |

The Noise prologue is ASCII `aether-session`, byte `2`, and the request fields up
through the sealed token. Thus scope, mode, handle, attempt and opaque token are
transcript-bound; retry cookies can change without changing a handshake. Request ID
is SHA-256 over that envelope including the first Noise message.

Noise messages are `-> psk,e` and `<- e,ee`, both with empty payloads. In PSK mode,
each ephemeral public key is mixed into both the hash and key state as specified by
Noise. Both sides reject an all-zero X25519 result. The server verifies the first
message's authenticator before issuing a cookie or doing DH. After return-routability
proof, it generates fresh ephemeral material and caches the second Noise message.

`ConnectionChallenge` is tag `0xa2`, request ID (32 bytes), and the second Noise
message (48 bytes). With final Noise chaining key `ck` and handshake hash `h`,
standard `Split()` derives client-to-server and server-to-client traffic keys.
Additional Aether exports are `HMAC-SHA256(ck, ASCII(label) || h)`:

| Label | Use |
| --- | --- |
| `aether-v2/resumption` | Next session's resumption master |
| `aether-v2/client-finished` | Client confirmation, 32 bytes |
| `aether-v2/server-finished` | Server acceptance, 32 bytes |
| `aether-v2/routing` | First eight bytes, little-endian, as routing ID; zero maps to one |

`ConnectionResponse` and `ConnectionAccepted` each carry tag, request ID and the
corresponding 32-byte confirmation. These values bind the final transcript and the
roles. The server commits only after fresh client confirmation, expiry, capacity
and single-use-state checks; the client commits only after matching acceptance.
Captured first messages or client responses do not confirm a different server challenge.
Exact retransmissions reuse cached messages and report no duplicate connection events.

A valid-PSK rejection uses `ConnectionDenied`: tag, request ID, reason byte, and
`HMAC-SHA256(denialKey, reasonByte)`, where
`denialKey = HMAC-SHA256(psk, "aether-v2/denial" || requestID)`.
Unknown credentials or invalid authenticators are silently discarded. An authenticated
pending ignores plaintext denial/acceptance/disconnect. Cookie handoffs and expensive
challenge attempts have separate limits from retransmission attempts.

Traffic uses Aether's packet AEAD framing, nonces, acknowledgement and replay machinery,
not Noise's transport-message framing. Traffic direction keys are standard Noise Split
outputs; Aether binds the outer header and application protocol in its packet AEAD.

## Resumption and lifecycle

Only timeout drops arm the bounded 30-second resume cache. The cached master becomes
the PSK for a new Noise exchange with new client/server ephemeral keys and attempt ID.
The cache also retains verified identity, claims and scope. No cache entry is consumed
until the fresh client confirmation succeeds and still matches its cached generation.
A captured request raced from another address receives a different challenge, so a copied
response cannot commit it. Successful resumption derives new traffic keys and a new master.

Unknown remote cache state cannot produce an authentic denial. With a fresh fallback
credential, the client waits its local handshake deadline and starts normal admission.
Spoofed control packets cannot trigger that transition. Original credential expiry
controls initial admission, not an already admitted session or its short resume window.
Process restart discards cached sessions. Explicit close/kick does not arm resumption.

Ephemeral and stored session secrets are erased at their owning objects' teardown.
The API is data-oriented and objects are copyable; applications must also protect and
erase their own credential copies. This implementation is not an independent audit or
formal verification of the complete transport.

## Verification sources

- [Noise specification](https://noiseprotocol.org/noise.html): NNpsk0 state transitions,
  PSK mixing, SHA-256 HKDF and ChaChaPoly nonce rules.
- [Cacophony vectors](https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt):
  fixed public-domain first/second messages, transcript hash and four transport ciphertexts.
- RFC [7748](https://www.rfc-editor.org/rfc/rfc7748),
  [8439](https://www.rfc-editor.org/rfc/rfc8439),
  [4231](https://www.rfc-editor.org/rfc/rfc4231) and
  [5869](https://www.rfc-editor.org/rfc/rfc5869): primitive known-answer vectors.
