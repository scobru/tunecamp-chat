# Changelog

All notable changes to this package will be documented in this file.

## [2.0.0] - 2026-08-06

Breaking: the vault write format changed and `sendMessage` can now refuse to
send. Old vaults are still readable, so nobody loses an identity on upgrade.

### Security

- **`encryptPairVault` stretches the password before it reaches the cipher.** `Zen.encrypt(pair, password)` derives its AES key with a single SHA-256 (`aeskey()`), so whoever holds the sealed vault — the server does — could test billions of candidate passwords per second offline. Vaults are now written as `tcv1:<iterations>:<saltHex>:<zenBlob>` with PBKDF2-HMAC-SHA256 at 600 000 iterations over a 16-byte random salt.
  - Iterations and salt travel with the blob, so the cost can be raised later without invalidating existing vaults.
  - A blob declaring fewer than 100 000 iterations is refused: otherwise whoever serves the vault could also choose a KDF cost they can brute-force.
  - `decryptPairVault` still opens pre-`tcv1` blobs, and `isLegacyPairVault()` tells the caller to re-seal one while it still holds the password.
- **Peer keys are pinned trust-on-first-use.** Whoever serves a public key chooses which one to serve, so possessing a key proves nothing about whose it is. The first key seen for a peer is pinned as `keyFingerprint(pub)` — `SHA-256` truncated to 128 bits, rendered in groups of four for reading aloud. A later key with a different fingerprint is **refused**: the pinned key stays in force, the new one is quarantined, and `onKeyChange` fires. Only `acceptPeerKeyChange(peerId)` re-pins, and it is meant to be driven by a user who has compared fingerprints out of band.
- **A DM is never sent in the clear.** Previously a direct message with no resolved recipient key went out as plaintext, which the sender had no way to notice — and withholding a key is something a malicious relay can do at will, making it a downgrade under its control. `sendMessage` now returns `false` and emits a system message explaining why.

### Added

- `keyFingerprint(pub)`, `isLegacyPairVault(blob)`.
- `TuneCampChatClient`: `onKeyChange`, `getPeerFingerprint`, `getPendingKeyChange`, `acceptPeerKeyChange`, and an optional `KeyPinStore` constructor argument (defaults to `localStorage`, falling back to memory so Node and Electron work unchanged).
- `useTuneCampChat`: `keyChanges`, `acceptKeyChange`, `getPeerFingerprint`.

### Changed

- `kdf()` takes an iteration count. `deriveKeyPairFromPassword` pins it at 100 000 forever — that value determines which identity a password derives, so it can never move — while the vault records its own per blob.
