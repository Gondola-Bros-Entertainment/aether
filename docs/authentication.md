# Authenticated sessions

Aether authenticates sessions with `Noise_NNpsk0_25519_ChaChaPoly_SHA256`, wrapped in UDP
admission, retry, and key-confirmation messages. It implements only this Noise pattern. The
envelope and the exported confirmation values below are Aether's own, not Noise messages.

## Trust and issuance

`issueConnectCredential` draws a random nonzero 32-byte PSK from the OS CSPRNG, seals it with the
claims, and also returns it as the credential's `proofKey`. The issuer key belongs only on the
backend and admitting servers. Each client receives its own PSK and cannot open another client's
token.

The client authenticates a responder that holds its credential PSK, which a server obtains by
opening the token with the issuer key. The server authenticates possession of that same PSK and the
issuer's player claims. This is symmetric credential authentication, not a certificate system or an
account login. The application chooses a nonzero protocol ID and audience; the server requires
exact matches. Anyone holding the issuer key can issue credentials and impersonate servers in that
trust domain.

Token plaintext is little-endian `playerId:u64`, `expiresAtUnixNs:u64`, `protocolId:u32`,
`audience:u64`, `psk:32`, then up to 256 opaque user-data bytes. ChaCha20-Poly1305 seals it with
AAD `TKN2` and a random 12-byte nonce. The wire token is nonce, ciphertext, tag (88 to 344 bytes).
The PSK travels inside this seal, never as a clear field in a datagram. Expiry is checked when the
request arrives and again when the client's proof completes. The replay table spends the nonce only
at successful admission and fails closed when full.

Credentials should be short-lived; revocation and long-lived session policy belong to the
application.

`validateConnectToken` opens and spends a token without any proof that the caller holds its PSK. It
is for an authority that has verified possession some other way, not a replacement for the
handshake.

## Wire transcript

The outer 17-byte packet header carries wire version 2. Handshake datagrams use CRC32C to detect
accidental corruption; the CRC does not authenticate them. Integers in the following envelope are
little-endian.

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

The Noise prologue is ASCII `aether-session`, byte `2`, and the request fields up through the sealed
token. Scope, mode, handle, attempt, and token are therefore bound to the transcript, while the
retry cookie can change without changing the handshake. The request ID is SHA-256 over that envelope
including the first Noise message.

Noise messages are `-> psk,e` and `<- e,ee`, both with empty payloads. In PSK mode each ephemeral
public key is mixed into both the hash and key state, as Noise specifies. Both sides reject an
all-zero X25519 result. The server verifies the first message's authenticator before issuing a
cookie or doing DH. After return-routability proof, it generates fresh ephemeral material and caches
the second Noise message.

`ConnectionChallenge` is tag `0xa2`, the request ID (32 bytes), and the second Noise message (48
bytes). With final Noise chaining key `ck` and handshake hash `h`, standard `Split()` derives the
client-to-server and server-to-client traffic keys. Aether's additional exports are
`HMAC-SHA256(ck, ASCII(label) || h)`:

| Label | Use |
| --- | --- |
| `aether-v2/resumption` | Next session's resumption master |
| `aether-v2/client-finished` | Client confirmation, 32 bytes |
| `aether-v2/server-finished` | Server acceptance, 32 bytes |
| `aether-v2/routing` | First eight bytes, little-endian, as routing ID; zero maps to one |

`ConnectionResponse` and `ConnectionAccepted` each carry the tag, the request ID, and the
corresponding 32-byte confirmation, which binds the final transcript and the roles. The server
commits only after fresh client confirmation and its expiry, capacity, and single-use checks; the
client commits only after a matching acceptance. A captured first message or client response does
not confirm a different server challenge. Exact retransmissions get the cached replies and produce
no duplicate connection events.

A rejection for a valid PSK uses `ConnectionDenied`: tag, request ID, reason byte, and
`HMAC-SHA256(denialKey, reasonByte)`, where
`denialKey = HMAC-SHA256(psk, "aether-v2/denial" || requestID)`.
Requests with unknown credentials or invalid authenticators are silently discarded. An
authenticated pending handshake ignores plaintext denial, acceptance, and disconnect packets.
Cookie handoffs and challenge attempts that cost DH work have their own limits, separate from
request retransmissions.

Traffic uses Aether's packet AEAD framing, nonces, acknowledgements, and replay window, not Noise's
transport-message framing. The traffic keys are the standard Noise `Split()` outputs; the packet
AEAD also authenticates the outer header and binds the protocol ID into the nonce.

## Resumption and lifecycle

The cached master of a timed-out session becomes the PSK for a new Noise exchange with new ephemeral
keys on both sides and a new attempt ID. The cache also keeps the verified identity, claims, and
scope. No entry is consumed until a fresh client confirmation succeeds and still matches the cached
generation, so a captured request raced from another address receives a different challenge and a
copied response cannot commit it. Successful resumption derives new traffic keys and a new master.

A server without the cached session cannot send an authentic denial. With a fresh fallback
credential, the client waits out its local handshake deadline and then starts normal admission;
spoofed control packets cannot trigger that switch. The original credential's expiry governs initial
admission only, not an admitted session or its resume window. Restarting the process discards cached
sessions.

Ephemeral and stored session secrets, including the proof key in a `ConnectCredential`, are erased
when the objects that hold them are destroyed. Credential bytes the application stores or
serializes elsewhere are its own to protect and erase.

## Verification sources

- [Noise specification](https://noiseprotocol.org/noise.html): NNpsk0 state transitions, PSK mixing,
  SHA-256 HKDF, and ChaChaPoly nonce rules.
- [Cacophony vectors](https://github.com/haskell-cryptography/cacophony/blob/8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247/vectors/cacophony.txt):
  public-domain first and second messages, transcript hash, and four transport ciphertexts.
- RFC [7748](https://www.rfc-editor.org/rfc/rfc7748), [8439](https://www.rfc-editor.org/rfc/rfc8439),
  [4231](https://www.rfc-editor.org/rfc/rfc4231), and [5869](https://www.rfc-editor.org/rfc/rfc5869):
  primitive known-answer vectors.
