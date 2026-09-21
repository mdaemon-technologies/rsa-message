# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.3] - 2026-05-19

### Changed
- Updated the distribution files and type declarations. The README examples and API docs now reflect the current signatures: `init()` returns `{ publicKey, verifyKey }`, `generateECDHKeyPair()` returns an object, `deriveSharedKey()` returns the salt, `encryptWithSharedKey()` returns `SharedKeyData`, shared-key export/import accept and return `SharedKeyData`, `setECDHPublicKey()` is awaited, and `removeSharedKey()`/`removeECDHPublicKey()` no longer return booleans.
- CI now tests Node.js 18, 20, 22, 24 and 26.
- The Rollup config loads `package.json` with `createRequire` instead of an import attribute.

## [2.2.2] - 2026-05-18

### Added
- `exports` map in `package.json` with explicit ES module, CommonJS and browser UMD entry points.

### Fixed
- A typo in `package.json` (`filest` instead of `files`) kept the `files` list from taking effect.

## [2.2.1] - 2025-10-31

### Fixed
- Published with rebuilt distribution files for the 2.2.0 changes.

## [2.2.0] - 2025-10-31

### Changed
- `setMasterAESKeyFromEncrypted()` re-encrypts the master key with the user's own key, so the key can still be decrypted if the sending user's verify key changes.

## [2.1.1] - 2025-06-16

### Added
- "Unsafe" decrypt variants that return `{ message, verified }` instead of throwing when signature verification fails: `decryptMessageUnsafe()`, `decryptWithMasterAESKeyUnsafe()` and `decryptWithSharedKeyUnsafe()`.
- `encryptMessage()` and `decryptMessage()` accept an optional `useMasterKey` flag to use the master AES key.

### Changed
- Readability and test fixes.

## [2.1.0] - 2025-06-13

- See the [git history](https://github.com/mdaemon-technologies/rsa-message/commits/main).

## [2.0.3] - 2025-06-13

### Changed
- `setEncryptedMasterAESKey()` accepts an optional `encryptor` user ID (defaults to `"self"`).
- `setMasterAESKeyFromEncrypted()` validates the key immediately by attempting decryption.

## [2.0.2] - 2025-06-12

### Changed
- Updated the TypeScript declarations.

## [2.0.1] - 2025-06-12

### Added
- Master AES key encryption for group/room scenarios: `generateAndSetMasterAESKey()`, `setEncryptedMasterAESKey()`, `getDecryptedMasterAESKey()`, `exportMasterAESKeyForUser()`, `setMasterAESKeyFromEncrypted()`, `encryptWithMasterAESKey()` and `decryptWithMasterAESKey()`.

### Changed
- `generateAESKey()` is now public.

## [2.0.0] - 2025-06-12

### Added
- ECDH key exchange and shared-key (derived key) encryption: `generateECDHKeyPair()`, `setECDHPublicKey()`, `deriveSharedKey()`, `encryptWithSharedKey()`, `decryptWithSharedKey()`, `exportSharedKeyData()`, `importSharedKeyData()`, `hasSharedKey()`, `hasECDHPublicKey()`, `removeSharedKey()` and `removeECDHPublicKey()`.

## [1.2.2] - 2025-04-24

### Changed
- Updated dependencies.

## [1.2.1] - 2025-03-14

### Changed
- Updated dependencies.

## [1.2.0] - 2025-01-30

- See the [git history](https://github.com/mdaemon-technologies/rsa-message/commits/main).

## [1.1.3] - 2024-12-04

### Added
- `setVerifyKey()` and `hasVerifyKey()`.

### Changed
- The `verifyKey` argument of `setPublicKey()` is optional again, for backwards compatibility.

## [1.1.1] - 2024-12-04

### Changed
- The build output is minified with Terser again.

## [1.1.0] - 2024-12-04

### Added
- A second key pair for message signing and verification: `init()` accepts `verifyKey` and `signKey`, and the `verifykey` and `signkey` getters return them.

### Changed
- `setPublicKey()` takes the other user's verify key as a third argument.

## [1.0.3] - 2024-12-03

- See the [git history](https://github.com/mdaemon-technologies/rsa-message/commits/main).

## [1.0.2] - 2024-12-03

### Added
- `hasPublicKey()`.
- More error checking.

## [1.0.1] - 2024-12-02

### Fixed
- The TypeScript exports.

## [1.0.0] - 2024-12-02

### Added
- Initial release: RSA message encryption, signing, decryption and verification using Web Crypto or Node.js crypto.

[2.2.3]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.2.3
[2.2.2]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.2.2
[2.2.1]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.2.1
[2.2.0]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.2.0
[2.1.1]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.1.1
[2.1.0]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.1.0
[2.0.3]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.0.3
[2.0.2]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.0.2
[2.0.1]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.0.1
[2.0.0]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/2.0.0
[1.2.2]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.2.2
[1.2.1]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.2.1
[1.2.0]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.2.0
[1.1.3]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.1.3
[1.1.1]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.1.1
[1.1.0]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.1.0
[1.0.3]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.0.3
[1.0.2]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.0.2
[1.0.1]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.0.1
[1.0.0]: https://www.npmjs.com/package/@mdaemon/rsa-message/v/1.0.0
