# @mdaemon/rsa-message

[![npm](https://img.shields.io/npm/v/@mdaemon/rsa-message?color=blue)](https://www.npmjs.com/package/@mdaemon/rsa-message)
[![license](https://img.shields.io/npm/l/@mdaemon/rsa-message?color=green)](LICENSE)
[![node](https://img.shields.io/node/v/@mdaemon/rsa-message)](https://nodejs.org)
[![install size](https://img.shields.io/npm/unpacked-size/@mdaemon/rsa-message)](https://packagephobia.com/result?p=@mdaemon/rsa-message)
[![CI](https://github.com/mdaemon-technologies/rsa-message/actions/workflows/node.js.yml/badge.svg)](https://github.com/mdaemon-technologies/rsa-message/actions/workflows/node.js.yml)

RSA message encryption, signing, decryption, and verification using webcrypto or node crypto

It also supports ECDH key exchange for derived (shared) key encryption.

## Note
This library uses the browser's Web Crypto API for key generation and encryption. This means that it is not compatible with older browsers that do not support the Web Crypto API. 

Keys are not persistent between browser sessions. This means that if you close your browser and reopen it, you will need to re-initialize the RSAMessage instance.

To keep keys between sessions, use `initKeySet()`: its private keys are non-extractable `CryptoKey`s that you can store in IndexedDB and reload later, but that no script can export. Avoid saving the private key strings from `init()` in `localStorage` or similar storage, where any script on the page can read them. See [Keeping keys between visits](#keeping-keys-between-visits-non-extractable).

## Install

```bash
npm install @mdaemon/rsa-message
```

## Usage

### ES modules

```js
import RSAMessage from "@mdaemon/rsa-message";
```

### CommonJS

```js
const RSAMessage = require("@mdaemon/rsa-message");
```

### Browser (UMD)

```html
<script type="text/javascript" src="/path_to_modules/@mdaemon/rsa-message/dist/rsa-message.umd.js"></script>
```

## Examples

```js
// Initialize RSA for a user
const sender = new RSAMessage();
const { publicKey, verifyKey } = await sender.initKeySet();

const recipient = new RSAMessage();
const { publicKey: theirPublicKey, verifyKey: theirVerifyKey } = await recipient.initKeySet();
// Store public key from another user to use for encryption and verification
sender.setPublicKey('otherUserId', theirPublicKey, theirVerifyKey);
recipient.setPublicKey('senderId', publicKey, verifyKey);

// Encrypt a message
const encrypted = await sender.encryptMessage('Hello, World!', 'otherUserId');

// Encode a message for transport
const encoded = sender.exportEncryptedMessage(encrypted);

// Decode a message from transport
const decoded = recipient.importEncryptedMessage(encoded);

// Decrypt a message
const decrypted = await recipient.decryptMessage(decoded, 'senderId');
```

### Derived Key Encryption (ECDH + AES-GCM)

For efficient symmetric encryption between two users, you can derive a shared AES key with ECDH key exchange. An instance's ECDH key pair exists only in memory for the life of that instance, and each shared key is reused for every message to that user. To rotate keys, generate new ECDH key pairs, exchange the new public keys, and derive the shared keys again:

```js
// Initialize RSA instances for both users
const alice = new RSAMessage();
const bob = new RSAMessage();

await alice.initKeySet();
await bob.initKeySet();

// Generate ECDH key pairs for both users
const { publicKey: aliceECDHPublicKey } = await alice.generateECDHKeyPair();
const { publicKey: bobECDHPublicKey } = await bob.generateECDHKeyPair();

// Exchange ECDH public keys
await alice.setECDHPublicKey('bob', bobECDHPublicKey);
await bob.setECDHPublicKey('alice', aliceECDHPublicKey);

// Derive shared keys
await alice.deriveSharedKey('bob');
await bob.deriveSharedKey('alice');

// Encrypt and decrypt messages using shared keys
const encrypted = await alice.encryptWithSharedKey('Hello, Bob!', 'bob');
const decrypted = await bob.decryptWithSharedKey(encrypted, 'alice');

// Export/import shared key data for transport
const exported = alice.exportSharedKeyData(encrypted);
const imported = bob.importSharedKeyData(exported);
```

### Master AES Key Encryption (Group/Room Scenarios)

For scenarios where multiple users need to share the same encryption key (like group chats or rooms), you can use the master AES key functionality:

```js
// Initialize RSA instances for group members
const admin = new RSAMessage();
const member1 = new RSAMessage();
const member2 = new RSAMessage();

await admin.initKeySet();
await member1.initKeySet();
await member2.initKeySet();

// Set up public keys for encryption/verification
admin.setPublicKey('self', admin.publickey, admin.verifykey);
admin.setPublicKey('member1', member1.publickey, member1.verifykey);
admin.setPublicKey('member2', member2.publickey, member2.verifykey);

// Admin generates a master AES key for the group
const masterKey = await admin.generateAndSetMasterAESKey();

// Admin shares the master key with group members
const keyForMember1 = await admin.exportMasterAESKeyForUser('member1');
const keyForMember2 = await admin.exportMasterAESKeyForUser('member2');

// Members receive and set up the master key
member1.setPublicKey('admin', admin.publickey, admin.verifykey);
member1.setVerifyKey('admin', admin.verifykey);
await member1.setMasterAESKeyFromEncrypted(keyForMember1, 'admin');

member2.setPublicKey('admin', admin.publickey, admin.verifykey);
member2.setVerifyKey('admin', admin.verifykey);
// Alternative: using setEncryptedMasterAESKey with encryptor parameter
member2.setEncryptedMasterAESKey(keyForMember2, 'admin');

// Now all members can encrypt/decrypt using the shared master key
const message = 'Hello, group!';

// Using dedicated master key methods (no RSA overhead)
const encrypted = await admin.encryptWithMasterAESKey(message);
const decrypted1 = await member1.decryptWithMasterAESKey(encrypted, 'admin');
const decrypted2 = await member2.decryptWithMasterAESKey(encrypted, 'admin');

// Or using regular methods with master key flag (backwards compatible)
const encrypted2 = await member1.encryptMessage(message, 'member2', true);
const decrypted3 = await member2.decryptMessage(encrypted2, 'member1', true);
```

### Keeping keys between visits (non-extractable)

`initKeySet()` returns a key set whose private keys are `CryptoKey`s that cannot be exported. Store it in IndexedDB (which keeps `CryptoKey`s through structured clone) and pass it back to `initKeySet()` on the next visit. Keys saved earlier as strings can be converted once with `importKeySet()`; the public keys stay the same, so earlier messages can still be decrypted.

```js
const rsa = new RSAMessage();
let keySet = await idbGet("rsa-keys");          // your own IndexedDB helper

if (keySet) {
  await rsa.initKeySet(keySet);                  // reuse the stored key set
} else if (localStorage.getItem("rsa-private")) {
  // one-time migration from keys saved as strings; throws (and keeps the strings) if they don't match
  keySet = await rsa.importKeySet(
    localStorage.getItem("rsa-public"), localStorage.getItem("rsa-private"),
    localStorage.getItem("rsa-verify"), localStorage.getItem("rsa-sign"));
  await idbPut("rsa-keys", keySet);
  ["rsa-public", "rsa-private", "rsa-verify", "rsa-sign"].forEach(k => localStorage.removeItem(k));
} else {
  keySet = await rsa.initKeySet();               // first visit: generate
  await idbPut("rsa-keys", keySet);
}

// register rsa.publickey / rsa.verifykey with your server as before
```

Deleting the strings cannot be undone: the converted private keys cannot be exported back to strings. If other code still reads the same strings, migrate it before any of it deletes them.

## Deprecated APIs

These still work in 2.x, but they expose private keys as strings that any script on the page can copy, so they will be removed in 3.0.0.

| Deprecated | Replacement |
|---|---|
| `init()` with no arguments | `initKeySet()` |
| `init(publicKey, privateKey, verifyKey, signKey)` | `importKeySet(...)` once with the saved strings, then store the returned key set and pass it to `initKeySet(keySet)` on later visits |
| `privatekey`, `signkey` getters | Store the `RSAKeySet` returned by `initKeySet()` or `importKeySet()` |

`importKeySet()` is not deprecated; it stays in 3.0.0 so keys saved as strings can still be converted.

Each deprecated API logs a warning the first time it is used on a page or in a process: in Node through `process.emitWarning()` as a `DeprecationWarning` (codes `RSA_MESSAGE_DEP_INIT`, `RSA_MESSAGE_DEP_PRIVATEKEY`, `RSA_MESSAGE_DEP_SIGNKEY`; silence with `--no-deprecation`), and in browsers through `console.warn()`.

## API Reference

### `new RSAMessage()`
Creates a new instance of the RSAMessage class.

### `init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string): Promise<{publicKey: string, verifyKey: string}>`
**Deprecated since 2.3.0; will be removed in 3.0.0.** Use `initKeySet()`, or `importKeySet()` to convert keys saved as strings. See [Deprecated APIs](#deprecated-apis).

Initializes the keys for the user. Can either generate new keys or use existing keys.
- `publicKey`: Optional base64 encoded public key
- `privateKey`: Optional base64 encoded private key
- `verifyKey`: Optional base64 encoded verification key
- `signKey`: Optional base64 encoded signing key
- Returns: Object with `publicKey` and `verifyKey` strings

### `initKeySet(keySet?: RSAKeySet): Promise<RSAKeySet>`
Initializes keys whose private halves cannot be exported. With no argument, new key pairs are generated. Pass a key set returned earlier (for example read back from IndexedDB) to reuse it.
- `keySet`: Optional key set returned by an earlier `initKeySet()` or `importKeySet()`
- Returns: The `RSAKeySet` in use; store it to reuse on the next visit
- Throws `KeyImportError` if the key set is incomplete, a private key is extractable or has the wrong algorithm, or the private keys do not belong to the public keys
- Afterwards `privatekey` and `signkey` return `""`; calling the deprecated `init()` switches back to string keys

### `importKeySet(publicKey: string, privateKey: string, verifyKey: string, signKey: string): Promise<RSAKeySet>`
Converts keys saved as strings (from `init()` and the `privatekey`/`signkey` getters) into a non-extractable key set **with the same public keys**, and initializes with it. Anything encrypted for the old keys can still be decrypted. Use it once to migrate, then store the returned key set in place of the strings.
- Returns: The converted `RSAKeySet`
- Throws `KeyImportError` if a key is missing, a private key string cannot be imported, or the private keys do not belong to the public keys

### `RSAKeySet`
```ts
interface RSAKeySet {
  publicKey: string;     // public encryption key, same format init() returns
  verifyKey: string;     // public verification key
  privateKey: CryptoKey; // non-extractable RSA-OAEP decryption key
  signKey: CryptoKey;    // non-extractable RSA-PSS signing key
}
```
TypeScript: `import RSAMessage, { RSAKeySet } from "@mdaemon/rsa-message";`

### `publickey: string`
Getter that returns the base64 encoded public key.

### `privatekey: string`
**Deprecated since 2.3.0; will be removed in 3.0.0.** Store the `RSAKeySet` from `initKeySet()` instead.

Getter that returns the base64 encoded private key, or `""` after `initKeySet()` or `importKeySet()`.

### `verifykey: string`
Getter that returns the base64 encoded verification key used for signature verification.

### `signkey: string`
**Deprecated since 2.3.0; will be removed in 3.0.0.** Store the `RSAKeySet` from `initKeySet()` instead.

Getter that returns the base64 encoded signing key used for creating message signatures, or `""` after `initKeySet()` or `importKeySet()`.

### `signMessage(message: string): Promise<ArrayBuffer>`
Signs a message using the private signing key.
- `message`: The message to sign
- Returns: Signature as ArrayBuffer

### `verifySignature(signature: ArrayBuffer, message: string, userId: string): Promise<boolean>`
Verifies a message signature using the sender's public verification key.
- `signature`: The signature to verify as ArrayBuffer
- `message`: The original message that was signed
- `userId`: The sender's user ID
- Returns: Promise resolving to true if signature is valid, false otherwise
- Throws: Error if no verification key is stored for `userId`, or `CryptoOperationError` if the stored key cannot be imported

### `setPublicKey(userId: string, publicKey: string, verifyKey?: string): void`
Stores another user's public key, and their verification key when given.
- `userId`: Unique identifier for the other user
- `publicKey`: Base64 encoded public key
- `verifyKey`: Optional base64 encoded verification key
- Throws: Error if `userId` or `publicKey` is empty

### `setVerifyKey(userId: string, verifyKey: string): void`
Stores or replaces another user's verification key.
- `userId`: Unique identifier for the other user
- `verifyKey`: Base64 encoded verification key
- Throws: Error if `userId` or `verifyKey` is empty

### `hasPublicKey(userId: string): boolean`
Checks if a user's public key is stored.
- `userId`: Unique identifier for the user
- Returns: `true` if the user's public key is stored, `false` otherwise

### `hasVerifyKey(userId: string): boolean`
Checks if a user's verification key is stored.
- `userId`: Unique identifier for the user
- Returns: `true` if the user's verification key is stored, `false` otherwise

### `encryptMessage(message: string, userId: string, useMasterAESKey?: boolean): Promise<IRSAEncryptedMessage>`
Encrypts and signs a message for a specific user.
- `message`: The message to encrypt
- `userId`: The recipient's user ID; their public key must be stored, even when the master AES key is used
- `useMasterAESKey`: Optional - if true and a master AES key is set, uses it instead of generating a new AES key
- Returns: Encrypted message object (`encryptedAESKey` is undefined when the master AES key is used)

### `decryptMessage(encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey?: boolean): Promise<string>`
Decrypts and verifies a message from a specific user.
- `encryptedData`: The encrypted message object
- `sender`: The sender's user ID
- `useMasterAESKey`: Optional - if true and a master AES key is set, uses it for decryption
- Returns: Decrypted message

### `generateAESKey(): Promise<CryptoKey>`
Generates a new extractable 256-bit AES-GCM key.

### `exportEncryptedMessage(message: IRSAEncryptedMessage): string`
Exports an encrypted message object to a base64 encoded string for transport or storage.
- `message`: The encrypted message object containing iv, encryptedMessage, encryptedAESKey and signature
- Returns: Base64 encoded string representation of the encrypted message

### `importEncryptedMessage(encoded: string): IRSAEncryptedMessage`
Imports a base64 encoded encrypted message string back into an encrypted message object.
- `encoded`: Base64 encoded string previously created by exportEncryptedMessage
- Returns: Decoded IRSAEncryptedMessage object containing iv, encryptedMessage, encryptedAESKey and signature

## Master AES Key Methods

The master AES key functionality allows for efficient group or room-based encryption scenarios where multiple users share the same AES key, eliminating the need for RSA encryption/decryption of individual AES keys.

### `generateAndSetMasterAESKey(): Promise<string>`
Generates a new AES master key, encrypts it with the current user's RSA public key, and stores it.
- Returns: Base64 encoded encrypted master AES key

### `setEncryptedMasterAESKey(encryptedKey: string, encryptor?: string): void`
Sets an encrypted master AES key (encrypted with this user's RSA public key).
- `encryptedKey`: Base64 encoded encrypted master AES key
- `encryptor`: Optional user ID who encrypted the key (defaults to "self")

### `getDecryptedMasterAESKey(): Promise<CryptoKey>`
Decrypts and returns the master AES key as a CryptoKey for direct use.
- Returns: The decrypted AES-GCM CryptoKey
- Throws: Error if no master key is set

### `exportMasterAESKeyForUser(userId: string): Promise<string>`
Encrypts the current master AES key with another user's RSA public key for sharing.
- `userId`: The user ID to encrypt the master key for
- Returns: Base64 encoded encrypted master AES key for the specified user
- Throws: Error if no master key is set or user's public key not found

### `setMasterAESKeyFromEncrypted(encryptedKey: string, encryptor?: string): Promise<void>`
Sets the master AES key from an encrypted key received from another user and immediately validates it by attempting decryption. Re-encrypts the key with the self key, so that if the from user's verifyKey changes the key can still be decrypted
- `encryptedKey`: Base64 encoded encrypted master AES key
- `encryptor`: Optional user ID who encrypted the key (defaults to "self")

**Note**: This method is equivalent to `setEncryptedMasterAESKey()` but performs immediate validation by testing decryption. Both methods now accept the same parameters for consistency.

### `encryptWithMasterAESKey(message: string): Promise<IRSAEncryptedMessage>`
Encrypts a message using the master AES key (no RSA encryption of AES key).
- `message`: The plaintext message to encrypt
- Returns: Encrypted message object without encryptedAESKey field
- Throws: Error if no master key is set

### `decryptWithMasterAESKey(encryptedData: IRSAEncryptedMessage, sender: string): Promise<string>`
Decrypts a message using the master AES key (no RSA decryption needed).
- `encryptedData`: The encrypted message object (should not include encryptedAESKey)
- `sender`: The user ID who sent the message (for signature verification)
- Returns: Decrypted message
- Throws: Error if no master key is set or signature verification fails

### `decryptWithMasterAESKeyUnsafe(encryptedData: IRSAEncryptedMessage, sender: string): Promise<IDecryptionResult>`
Decrypts a message using the master AES key without throwing on signature verification failure.
- `encryptedData`: The encrypted message object (should not include encryptedAESKey)
- `sender`: The user ID who sent the message (for signature verification)
- Returns: Object with `{ message: string, verified: boolean }`
- Throws: Error if no master key is set or decryption fails (but not signature verification)

### `encryptMessage()` and `decryptMessage()` with the master AES key
Pass `true` as the third argument of `encryptMessage()` or `decryptMessage()` to use the master AES key when one is set.

## Derived Key Encryption Methods (ECDH + PBKDF2)

### `generateECDHKeyPair(): Promise<{publicKey: string}>`
Generates an ECDH key pair for key exchange and returns the public key.
- Returns: Object with `publicKey` as a base64 encoded ECDH public key

### `setECDHPublicKey(userId: string, publicKey: string): Promise<void>`
Imports and stores another user's ECDH public key for key derivation.
- `userId`: Unique identifier for the other user
- `publicKey`: Base64 encoded ECDH public key

### `deriveSharedKey(userId: string, salt?: Uint8Array): Promise<Uint8Array>`
Derives a shared AES key using ECDH key exchange and PBKDF2 key derivation.
- `userId`: The other user's identifier
- `salt`: Optional salt for key derivation (generates random salt if not provided)
- Returns: The salt used for key derivation

### `encryptWithSharedKey(message: string, userId: string): Promise<SharedKeyData>`
Encrypts a message using the shared key derived with the specified user.
- `message`: The message to encrypt
- `userId`: The user identifier for the shared key
- Returns: SharedKeyData object containing `salt`, `encryptedMessage`, and `iv`

### `decryptWithSharedKey(encryptedData: SharedKeyData, userId: string): Promise<string>`
Decrypts a message using the shared key derived with the specified user.
- `encryptedData`: SharedKeyData object from `encryptWithSharedKey`
- `userId`: The user identifier for the shared key
- Returns: Decrypted message

### `decryptWithSharedKeyUnsafe(encryptedData: SharedKeyData, userId: string): Promise<IDecryptionResult>`
Unsafe variant that returns verification status. Note: SharedKeyData doesn't include signatures, so verified is always true.
- `encryptedData`: SharedKeyData object from `encryptWithSharedKey`
- `userId`: The user identifier for the shared key
- Returns: Object with `{ message: string, verified: boolean }` (verified is always true for shared keys)

### `exportSharedKeyData(data: SharedKeyData): string`
Exports shared key encrypted message data to a string format for storage or transport.
- `data`: The SharedKeyData object to export
- Returns: Base64 encoded shared key data

### `importSharedKeyData(encoded: string): SharedKeyData`
Imports an encoded string back into a shared key data object.
- `encoded`: Base64 encoded string previously created by `exportSharedKeyData`
- Returns: The decoded SharedKeyData object

### `hasSharedKey(userId: string): boolean`
Checks if a shared key exists for the specified user.
- `userId`: The user identifier
- Returns: `true` if shared key exists, `false` otherwise

### `hasECDHPublicKey(userId: string): boolean`
Checks if an ECDH public key is stored for the specified user.
- `userId`: The user identifier
- Returns: `true` if ECDH public key exists, `false` otherwise

### `removeSharedKey(userId: string): void`
Removes the shared key for the specified user.
- `userId`: The user identifier

### `removeECDHPublicKey(userId: string): void`
Removes the ECDH public key for the specified user.
- `userId`: The user identifier

## Security Features
- Uses RSA-OAEP for encryption and RSA-PSS for signatures
- AES-GCM for symmetric message encryption
- Implements message signing and signature verification
- Master AES key functionality for efficient group/room encryption scenarios
- ECDH key exchange with the P-256 elliptic curve for shared (derived) keys
- PBKDF2 key derivation with 100,000 iterations for enhanced security
- Derived key encryption using AES-GCM with 256-bit keys
- Base64 encoding for message transport

## Unsafe Decryption Methods

For scenarios where you want to decrypt a message even if signature verification fails, the library provides "unsafe" variants of the decrypt methods. These methods return both the decrypted message and verification status instead of throwing errors on signature verification failure.

### IDecryptionResult Interface

All unsafe methods return an object implementing the `IDecryptionResult` interface:

```ts
interface IDecryptionResult {
  message: string;    // The decrypted message
  verified: boolean;  // Whether signature verification succeeded
}
```

### Available Unsafe Methods

- `decryptMessageUnsafe()` - For regular RSA-AES encrypted messages
- `decryptWithMasterAESKeyUnsafe()` - For master AES key encrypted messages  
- `decryptWithSharedKeyUnsafe()` - For shared key encrypted messages (always verified: true)

### Usage Example

```js
try {
  const result = await receiver.decryptMessageUnsafe(encryptedData, 'sender');
  
  if (result.verified) {
    console.log('Message verified:', result.message);
  } else {
    console.log('Message unverified but readable:', result.message);
    console.warn('Signature verification failed - treat with caution');
  }
} catch (error) {
  console.error('Decryption failed:', error.message);
}
```

These methods are useful when you want to read the message content regardless of signature verification status, while still being informed about the verification result.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Releasing

Releases are published to npm from GitHub Actions ([publish.yml](.github/workflows/publish.yml)) through npm trusted publishing, so no npm token is stored in the repository.

1. Update `CHANGELOG.md` and run `npm version <patch|minor|major>`, which bumps `package.json` and creates the matching `v<version>` tag.
2. Push the commit and the tag (`git push --follow-tags`) and wait for CI to pass.
3. Publish a GitHub Release for the tag. The workflow builds, tests, checks that the tag matches `package.json`, and stages the version on npm.
4. A maintainer approves the staged version with 2FA on npmjs.com or with `npm stage approve`. Only then is it public.

## License

Published under the [LGPL-2.1](LICENSE) license.

Published by **MDaemon Technologies, Ltd.**  
Simple Secure Email  
[https://www.mdaemon.com](https://www.mdaemon.com)
