# @mdaemon/rsa-message - RSA message encryption, signing, decryption, verification, and ECDH key exchange using webcrypto or node crypto
[![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmdaemon-technologies%2Frsa-message%2Fmain%2Fpackage.json&query=%24.version&prefix=v&label=npm&color=blue)](https://www.npmjs.com/package/@mdaemon/rsa-message) [![Static Badge](https://img.shields.io/badge/node-v18%2B-blue?style=flat&label=node&color=blue)](https://nodejs.org) [![install size](https://packagephobia.com/badge?p=@mdaemon/rsa-message)](https://packagephobia.com/result?p=@mdaemon/rsa-message) [![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fmdaemon-technologies%2Frsa-message%2Fmain%2Fpackage.json&query=%24.license&prefix=v&label=license&color=green)](https://github.com/mdaemon-technologies/rsa-message/blob/main/LICENSE) [![Node.js CI](https://github.com/mdaemon-technologies/rsa-message/actions/workflows/node.js.yml/badge.svg)](https://github.com/mdaemon-technologies/rsa-message/actions/workflows/node.js.yml)

[ [@mdaemon/rsa-message on npm](https://www.npmjs.com/package/@mdaemon/rsa-message "npm") ]

## Note
This library uses the browser's Web Crypto API for key generation and encryption. This means that it is not compatible with older browsers that do not support the Web Crypto API. 

Keys are not persistent between browser sessions. This means that if you close your browser and reopen it, you will need to re-initialize the RSAMessage instance.

This library is ideal for temporary use cases where you don't need to persist keys between sessions. If you need to persist keys between sessions, you should use a library like [localForage](https://localforage.github.io/localForage/) to store them in the browser's local storage.

## Install

```cmd
$ npm install @mdaemon/rsa-message --save
```

## Usage

### Node CommonJS
```js
const RSAMessage = require("@mdaemon/emitter/dist/rsa-message.cjs");
```

### Node Modules
```js
import RSAMessage from "@mdaemon/emitter/dist/rsa-message.mjs";
```

### Web
```html
<script type="text/javascript" src="/path_to_modules/dist/rsa-message.umd.js">
```


## Usage

```js
// Initialize RSA for a user
const sender = new RSAMessage();
const { publicKey, verifyKey } = await sender.init();

const recipient = new RSAMessage();
const { publicKey: theirPublicKey, verifyKey: theirVerifyKey } = await recipient.init();
// Store public key from another user to use for encryption and verification
sender.setPublicKey('otherUserId', theirPublicKey, theirVerifyKey);
recipient.setPublicKey('senderId', publicKey, verifyKey);

// Encrypt a message
const encrypted = await rsa.encryptMessage('Hello, World!', 'otherUserId');

// Encode a message for transport
const encoded = rsa.exportEncryptedMessage(encrypted);

// Decode a message from transport
const decoded = rsa.importEncryptedMessage(encoded);

// Decrypt a message
const decrypted = await rsa.decryptMessage(decoded, 'senderId');
```

### Derived Key Encryption (ECDH + AES-GCM)

For scenarios requiring perfect forward secrecy and efficient symmetric encryption, you can use ECDH key exchange:

```js
// Initialize RSA instances for both users
const alice = new RSAMessage();
const bob = new RSAMessage();

await alice.init();
await bob.init();

// Generate ECDH key pairs for both users
const aliceECDHPublicKey = await alice.generateECDHKeyPair();
const bobECDHPublicKey = await bob.generateECDHKeyPair();

// Exchange ECDH public keys
alice.setECDHPublicKey('bob', bobECDHPublicKey);
bob.setECDHPublicKey('alice', aliceECDHPublicKey);

// Derive shared keys
await alice.deriveSharedKey('bob');
await bob.deriveSharedKey('alice');

// Encrypt and decrypt messages using shared keys
const encrypted = await alice.encryptWithSharedKey('Hello, Bob!', 'bob');
const decrypted = await bob.decryptWithSharedKey(encrypted, 'alice');

// Export/import shared key data for persistence
const sharedKeyData = alice.exportSharedKeyData('bob');
// Later, import the shared key data
alice.importSharedKeyData('bob', sharedKeyData);
```

### Master AES Key Encryption (Group/Room Scenarios)

For scenarios where multiple users need to share the same encryption key (like group chats or rooms), you can use the master AES key functionality:

```js
// Initialize RSA instances for group members
const admin = new RSAMessage();
const member1 = new RSAMessage();
const member2 = new RSAMessage();

await admin.init();
await member1.init();
await member2.init();

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

## API Reference

### `new RSAMessage()`
Creates a new instance of the RSAMessage class.

### `init(publicKey?: string, privateKey?: string): Promise<string>`
Initializes the keys for the user. Can either generate new keys or use existing keys.
- `publicKey`: Optional base64 encoded public key
- `privateKey`: Optional base64 encoded private key
- Returns: Base64 encoded public key

### `publickey: string`
Getter that returns the base64 encoded public key.

### `privatekey: string`
Getter that returns the base64 encoded private key.

### `verifykey: string`
Getter that returns the base64 encoded verification key used for signature verification.

### `signkey: string`
Getter that returns the base64 encoded signing key used for creating message signatures.

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

### `setPublicKey(userId: string, publicKey: string, verifyKey: string): void`
Stores another user's public key.
- `userId`: Unique identifier for the other user
- `publicKey`: Base64 encoded public key
- `verifyKey`: Base64 encoded verification key

### `hasPublicKey(userId: string): boolean`
Checks if a user's public key is stored.
- `userId`: Unique identifier for the user
- Returns: `true` if the user's public key is stored, `false` otherwise

### `encryptMessage(message: string, userId: string, useMasterKey?: boolean): Promise<IRSAEncryptedMessage>`
Encrypts and signs a message for a specific user.
- `message`: The message to encrypt
- `userId`: The recipient's user ID
- `useMasterKey`: Optional - if true and master key is set, uses master AES key instead of generating new AES key
- Returns: Encrypted message object

### `decryptMessage(encryptedData: IRSAEncryptedMessage, sender: string, useMasterKey?: boolean): Promise<string>`
Decrypts and verifies a message from a specific user.
- `encryptedData`: The encrypted message object
- `sender`: The sender's user ID
- `useMasterKey`: Optional - if true and master key is set, uses master AES key for decryption
- Returns: Decrypted message

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
Sets the master AES key from an encrypted key received from another user and immediately validates it by attempting decryption.
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

### Enhanced `encryptMessage(message: string, userId: string, useMasterKey?: boolean): Promise<IRSAEncryptedMessage>`
The standard encrypt method now supports an optional parameter to use the master AES key.
- `message`: The message to encrypt
- `userId`: The recipient's user ID
- `useMasterKey`: If true and master key is set, uses master AES key instead of generating new AES key
- Returns: Encrypted message object (encryptedAESKey will be undefined if master key is used)

### Enhanced `decryptMessage(encryptedData: IRSAEncryptedMessage, sender: string, useMasterKey?: boolean): Promise<string>`
The standard decrypt method now supports an optional parameter to use the master AES key.
- `encryptedData`: The encrypted message object
- `sender`: The sender's user ID
- `useMasterKey`: If true and master key is set, uses master AES key for decryption
- Returns: Decrypted message

## Derived Key Encryption Methods (ECDH + PBKDF2)

### `generateECDHKeyPair(): Promise<string>`
Generates an ECDH key pair for key exchange and returns the public key.
- Returns: Base64 encoded ECDH public key

### `setECDHPublicKey(userId: string, publicKey: string): Promise<void>`
Imports and stores another user's ECDH public key for key derivation.
- `userId`: Unique identifier for the other user
- `publicKey`: Base64 encoded ECDH public key

### `deriveSharedKey(userId: string, salt?: Uint8Array): Promise<void>`
Derives a shared AES key using ECDH key exchange and PBKDF2 key derivation.
- `userId`: The other user's identifier
- `salt`: Optional salt for key derivation (generates random salt if not provided)

### `encryptWithSharedKey(message: string, userId: string): Promise<string>`
Encrypts a message using the shared key derived with the specified user.
- `message`: The message to encrypt
- `userId`: The user identifier for the shared key
- Returns: Base64 encoded encrypted message

### `decryptWithSharedKey(encryptedMessage: string, userId: string): Promise<string>`
Decrypts a message using the shared key derived with the specified user.
- `encryptedMessage`: Base64 encoded encrypted message
- `userId`: The user identifier for the shared key
- Returns: Decrypted message

### `decryptWithSharedKeyUnsafe(encryptedMessage: string, userId: string): Promise<IDecryptionResult>`
Unsafe variant that returns verification status. Note: SharedKeyData doesn't include signatures, so verified is always true.
- `encryptedMessage`: Base64 encoded encrypted message
- `userId`: The user identifier for the shared key
- Returns: Object with `{ message: string, verified: boolean }` (verified is always true for shared keys)

### `exportSharedKeyData(userId: string): string`
Exports shared key data for storage or transport.
- `userId`: The user identifier for the shared key
- Returns: Base64 encoded shared key data

### `importSharedKeyData(userId: string, data: string): Promise<void>`
Imports previously exported shared key data.
- `userId`: The user identifier for the shared key
- `data`: Base64 encoded shared key data

### `hasSharedKey(userId: string): boolean`
Checks if a shared key exists for the specified user.
- `userId`: The user identifier
- Returns: `true` if shared key exists, `false` otherwise

### `hasECDHPublicKey(userId: string): boolean`
Checks if an ECDH public key is stored for the specified user.
- `userId`: The user identifier
- Returns: `true` if ECDH public key exists, `false` otherwise

### `removeSharedKey(userId: string): boolean`
Removes the shared key for the specified user.
- `userId`: The user identifier
- Returns: `true` if key was removed, `false` if key didn't exist

### `removeECDHPublicKey(userId: string): boolean`
Removes the ECDH public key for the specified user.
- `userId`: The user identifier
- Returns: `true` if key was removed, `false` if key didn't exist

## Security Features
- Uses RSA-OAEP for encryption and RSA-PSS for signatures
- AES-GCM for symmetric message encryption
- Implements message signing and signature verification
- Master AES key functionality for efficient group/room encryption scenarios
- ECDH key exchange with P-256 elliptic curve for perfect forward secrecy
- PBKDF2 key derivation with 100,000 iterations for enhanced security
- Derived key encryption using AES-GCM with 256-bit keys
- Base64 encoding for message transport

## Unsafe Decryption Methods

For scenarios where you want to decrypt a message even if signature verification fails, the library provides "unsafe" variants of the decrypt methods. These methods return both the decrypted message and verification status instead of throwing errors on signature verification failure.

### IDecryptionResult Interface

All unsafe methods return an object implementing the `IDecryptionResult` interface:

```typescript
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

# License #

Published under the [LGPL-2.1 license](https://github.com/mdaemon-technologies/rsa-message/blob/main/LICENSE "LGPL-2.1 License").

Published by<br/> 
<b>MDaemon Technologies, Ltd.<br/>
Simple Secure Email</b><br/>
[https://www.mdaemon.com](https://www.mdaemon.com)