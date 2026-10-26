# Security policy

Aether is under active development and has no releases yet. Security fixes target the current `main` branch.

## Report a vulnerability

Use GitHub's [private vulnerability reporting form](https://github.com/Gondola-Bros-Entertainment/aether/security/advisories/new)
to report suspected vulnerabilities. Include the affected revision, compiler, platform, `NetworkConfig` settings,
reproduction steps and expected impact. A minimal program or a packet capture that reproduces the issue is especially
useful.

Keep exploit details and sensitive data out of public issues and pull requests. Do not include live credentials, keys
or traffic you cannot share. The maintainers will review reports privately and coordinate fixes and disclosure through
GitHub security advisories.

## Scope

Reports may cover anything a remote peer can reach: packet and handshake parsing, connect credentials and tokens,
session resumption, the ChaCha20-Poly1305 and X25519 implementations, fragment reassembly, deserialization and delta
decoding of received data, and the rendezvous server. Repository automation is in scope too. Ordinary build failures
and feature requests belong in public issues.
