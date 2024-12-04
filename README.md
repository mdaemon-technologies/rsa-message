# @mdaemon/rsa-message - RSA message encryption, signing, decryption, and verification using webcrypto or node crypto
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

### `encryptMessage(message: string, userId: string): Promise<string>`
Encrypts and signs a message for a specific user.
- `message`: The message to encrypt
- `userId`: The recipient's user ID
- Returns: Base64 encoded encrypted message

### `decryptMessage(encryptedMessage: string, userId: string): Promise<string>`
Decrypts and verifies a message from a specific user.
- `encryptedMessage`: Base64 encoded encrypted message
- `userId`: The sender's user ID
- Returns: Decrypted message

### `exportEncryptedMessage(message: IRSAEncryptedMessage): string`
Exports an encrypted message object to a base64 encoded string for transport or storage.
- `message`: The encrypted message object containing iv, encryptedMessage, encryptedAESKey and signature
- Returns: Base64 encoded string representation of the encrypted message

### `importEncryptedMessage(encoded: string): IRSAEncryptedMessage`
Imports a base64 encoded encrypted message string back into an encrypted message object.
- `encoded`: Base64 encoded string previously created by exportEncryptedMessage
- Returns: Decoded IRSAEncryptedMessage object containing iv, encryptedMessage, encryptedAESKey and signature

## Security Features
- Uses RSA-OAEP for encryption and RSA-PSS for signatures
- AES-GCM for symmetric message encryption
- Implements message signing and signature verification
- Base64 encoding for message transport

# License #

Published under the [LGPL-2.1 license](https://github.com/mdaemon-technologies/rsa-message/blob/main/LICENSE "LGPL-2.1 License").

Published by<br/> 
<b>MDaemon Technologies, Ltd.<br/>
Simple Secure Email</b><br/>
[https://www.mdaemon.com](https://www.mdaemon.com)