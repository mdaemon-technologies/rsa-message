import { KeyPairOutput, ECDHPublicKey, SharedKeyData, RSAKeySet } from "./crypto-types";
export type { RSAKeySet } from "./crypto-types";
export interface IDecryptionResult {
    message: string;
    verified: boolean;
}
export interface IRSAEncryptedMessage {
    iv: Uint8Array;
    encryptedMessage: ArrayBuffer;
    signature: ArrayBuffer;
    encryptedAESKey?: ArrayBuffer;
}
declare class RSAMessage {
    private privateKey;
    private publicKey;
    private verifyKey;
    private signKey;
    private privateCryptoKey;
    private signCryptoKey;
    private publicKeys;
    private verifyKeys;
    private ecdhPrivateKey;
    private ecdhPublicKeys;
    private sharedKeys;
    private encryptedMasterAESKey;
    private masterAESKeyEncryptor;
    /**
     * Generates a new AES master key, encrypts it with the current user's publicKey, and sets it as the master key.
     * @returns {Promise<string>} The encrypted master AES key (base64 string)
     */
    generateAndSetMasterAESKey(): Promise<string>;
    /**
     * Sets the encrypted master AES key (base64 string, encrypted with this user's publicKey)
     * @param {string} encryptedKey - The encrypted master AES key (base64 string)
     * @param {string} encryptor - The user ID who encrypted the key (defaults to "self")
     */
    setEncryptedMasterAESKey(encryptedKey: string, encryptor?: string): void;
    /**
     * Decrypts and returns the master AES key as a CryptoKey. Always decrypts fresh (no persistent cache).
     * @returns {Promise<CryptoKey>} The decrypted AES-GCM key
     */
    getDecryptedMasterAESKey(): Promise<CryptoKey>;
    /**   * Encrypts the current master AES key with another user's publicKey and exports it (base64 string).
     * @param {string} userId - The user to encrypt the key for
     * @returns {Promise<string>} The encrypted master AES key (base64 string)
     */
    exportMasterAESKeyForUser(userId: string): Promise<string>;
    /**
     * Sets the master AES key from an encrypted key (base64 string, encrypted with this user's publicKey)
     * @param {string} encryptedKey - The encrypted master AES key (base64 string)
     * @param {string} encryptor - The user ID who encrypted the key (for proper signature verification)
     */
    setMasterAESKeyFromEncrypted(encryptedKey: string, encryptor?: string): Promise<void>;
    /**
     * Encrypts a message using the master AES key (must be set). No RSA is used. Output does not include encryptedAESKey.
     * @param message - The plaintext message to encrypt
     * @returns {Promise<IRSAEncryptedMessage>} Object containing the encrypted message, iv, and signature
     */
    encryptWithMasterAESKey(message: string): Promise<IRSAEncryptedMessage>;
    /**
     * Decrypts a message using the master AES key (must be set). No RSA is used. Input should not include encryptedAESKey.
     * @param encryptedData - The encrypted message object (no encryptedAESKey)
     * @param sender - The ID of the user who sent the message (for signature verification)
     * @returns {Promise<string>} The decrypted message
     */
    decryptWithMasterAESKey(encryptedData: IRSAEncryptedMessage, sender: string): Promise<string>;
    /**
     * Decrypts a message using the master AES key and returns verification status (does not throw on signature verification failure).
     * @param encryptedData - The encrypted message object (no encryptedAESKey)
     * @param sender - The ID of the user who sent the message (for signature verification)
     * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
     */
    decryptWithMasterAESKeyUnsafe(encryptedData: IRSAEncryptedMessage, sender: string): Promise<IDecryptionResult>;
    constructor();
    get publickey(): string;
    get verifykey(): string;
    /**
     * @deprecated Since 2.3.0; will be removed in 3.0.0. Private keys from initKeySet() cannot be exported,
     * so store the RSAKeySet it returns instead of this string.
     */
    get privatekey(): string;
    /**
     * @deprecated Since 2.3.0; will be removed in 3.0.0. Private keys from initKeySet() cannot be exported,
     * so store the RSAKeySet it returns instead of this string.
     */
    get signkey(): string;
    generateAESKey(): Promise<CryptoKey>;
    /**
     * Initializes RSA keys for encryption and signing. If keys are provided, they will be used.
     * Otherwise, new key pairs will be generated.
     *
     * @param {string} [publicKey] - The public key for encryption
     * @param {string} [privateKey] - The private key for decryption
     * @param {string} [verifyKey] - The public key for signature verification
     * @param {string} [signKey] - The private key for signing
     * @returns {Promise<{publicKey: string, verifyKey: string}>} The public keys for encryption and verification
     * @deprecated Since 2.3.0; will be removed in 3.0.0. Use initKeySet() to generate or reuse keys whose private
     * halves cannot be exported, and importKeySet() once to convert keys saved as strings.
     */
    init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string): Promise<KeyPairOutput>;
    /**
     * Initializes RSA keys whose private halves cannot be exported. Pass a key set returned by an
     * earlier initKeySet() or importKeySet() (for example read back from IndexedDB) to reuse it;
     * otherwise new key pairs are generated. The private CryptoKeys survive structured clone, so
     * they can be stored, but exportKey() rejects them and the privatekey and signkey getters
     * return "".
     *
     * @param {RSAKeySet} [keySet] - A key set to reuse
     * @returns {Promise<RSAKeySet>} The key set in use, to store for the next session
     * @throws {KeyImportError} If the key set is incomplete, its private keys are extractable or
     *   have the wrong algorithm, or they do not belong to its public keys
     */
    initKeySet(keySet?: RSAKeySet): Promise<RSAKeySet>;
    /**
     * Converts keys saved from init()'s exported strings into a key set whose private halves
     * cannot be exported, and initializes with it. The public keys are unchanged, so anything
     * encrypted for the old keys can still be decrypted.
     *
     * @param {string} publicKey - The saved public key for encryption
     * @param {string} privateKey - The saved private key for decryption
     * @param {string} verifyKey - The saved public key for signature verification
     * @param {string} signKey - The saved private key for signing
     * @returns {Promise<RSAKeySet>} The converted key set, to store in place of the strings
     * @throws {KeyImportError} If a key is missing, a private key string cannot be imported, or the
     *   private keys do not belong to the public keys
     */
    importKeySet(publicKey: string, privateKey: string, verifyKey: string, signKey: string): Promise<RSAKeySet>;
    private checkKeySet;
    private useKeySet;
    private genKeySetPair;
    private getPrivateKey;
    private genKeyPair;
    private importPrivateKey;
    private importPublicKey;
    /**
     * Encrypts a message using RSA-AES hybrid encryption
     * @param message - The plaintext message to encrypt
     * @param userId - The ID of the recipient user whose public key will be used
     * @returns {Promise<IRSAEncryptedMessage>} Object containing the encrypted message components:
     *  - iv: Initialization vector for AES-GCM
     *  - encryptedMessage: The AES encrypted message
     *  - encryptedAESKey: The RSA encrypted AES key
     *  - signature: Digital signature of the message
     * @throws {Error} If public key is not found for the user
     */
    /**
     * Encrypts a message using RSA-AES hybrid encryption, using the master AES key if set, otherwise generates a new AES key.
     * @param message - The plaintext message to encrypt
     * @param userId - The ID of the recipient user whose public key will be used
     * @param useMasterAESKey - If true, use the master AES key (if set)
     * @returns {Promise<IRSAEncryptedMessage>} Object containing the encrypted message components
     */
    encryptMessage: (message: string, userId: string, useMasterAESKey?: boolean) => Promise<IRSAEncryptedMessage>;
    /**
     * Decrypts an encrypted message and verifies its signature. If useMasterAESKey is true and the master key is set, uses it for decryption.
     * @param {IRSAEncryptedMessage} encryptedData - Object containing the encrypted message components:
     *  - iv: Initialization vector for AES-GCM
     *  - encryptedMessage: The AES encrypted message
     *  - encryptedAESKey: The RSA encrypted AES key (optional for master AES encryption)
     *  - signature: Digital signature of the message
     * @param {string} sender - The ID of the user who sent the message
     * @param {boolean} useMasterAESKey - If true, use the master AES key (if set)
     * @returns {Promise<string>} The decrypted message
     * @throws {Error} If private key import fails
     * @throws {Error} If AES key decryption fails
     * @throws {Error} If AES key import fails
     * @throws {Error} If message decryption fails
     * @throws {Error} If signature verification fails
     */
    decryptMessage: (encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey?: boolean) => Promise<string>;
    /**
     * Decrypts an encrypted message and returns verification status (does not throw on signature verification failure).
     * @param encryptedData - Object containing the encrypted message components
     * @param sender - The ID of the user who sent the message
     * @param useMasterAESKey - If true, use the master AES key (if set)
     * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
     */
    decryptMessageUnsafe(encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey?: boolean): Promise<IDecryptionResult>;
    /**
     * Signs a message using RSA-PSS with the user's private signing key
     * @param message - The message string to sign
     * @returns Promise that resolves with the signature as an ArrayBuffer
     * @throws Error if signing fails
     */
    signMessage: (message: string) => Promise<ArrayBuffer>;
    /**
     * Verifies a message signature using RSA-PSS with the sender's public verification key
     * @param signature - The signature to verify as an ArrayBuffer
     * @param message - The original message string that was signed
     * @param userId - The ID of the user who signed the message
     * @returns Promise that resolves with boolean indicating if signature is valid
     * @throws Error if verification fails or public key not found
     */
    verifySignature: (signature: ArrayBuffer, message: string, userId: string) => Promise<boolean>;
    /**
   * Sets a user's public encryption key and optionally their verification key
   * @param userId - The ID of the user to set keys for
   * @param publicKey - The public encryption key string
   * @param verifyKey - Optional verification key string for backwards compatibility
   * @throws Error if userId or publicKey are invalid
   */
    setPublicKey(userId: string, publicKey: string, verifyKey?: string): void;
    /**
     * Sets a user's public verification key used for signature verification
     * @param userId - The ID of the user to set the verify key for
     * @param verifyKey - The verification key string
     * @throws Error if userId or verifyKey are invalid
     */
    setVerifyKey(userId: string, verifyKey: string): void;
    /**
     * Checks if a public encryption key exists for a user
     * @param userId - The ID of the user to check
     * @returns True if a public key exists for the user, false otherwise
     */
    hasPublicKey(userId: string): boolean;
    /**
     * Checks if a public verification key exists for a user
     * @param userId - The ID of the user to check
     * @returns True if a verification key exists for the user, false otherwise
     */
    hasVerifyKey(userId: string): boolean;
    /**
     * Exports an encrypted message object to a string format
     * @param message - The encrypted message object to export
     * @returns An encoded string representation of the encrypted message
     */
    exportEncryptedMessage(message: IRSAEncryptedMessage): string;
    /**
     * Imports an encoded string back into an encrypted message object
     * @param encoded - The encoded string to import
     * @returns The decoded IRSAEncryptedMessage object
     */
    importEncryptedMessage(encoded: string): IRSAEncryptedMessage;
    /**
     * Generates ECDH key pair for key exchange
     * @returns Promise that resolves with the public key in exportable format
     * @throws Error if key generation fails
     */
    generateECDHKeyPair(): Promise<ECDHPublicKey>;
    /**
     * Imports another user's ECDH public key for key exchange
     * @param userId - The ID of the user whose public key to import
     * @param publicKey - The base64 encoded ECDH public key
     * @throws Error if key import fails
     */
    setECDHPublicKey(userId: string, publicKey: string): Promise<void>;
    /**
     * Derives a shared secret key using ECDH and stores it for the user
     * @param userId - The ID of the user to derive shared key with
     * @param salt - Optional salt for key derivation. If not provided, a random salt is generated
     * @returns The salt used for key derivation
     * @throws Error if key derivation fails or required keys are missing
     */
    deriveSharedKey(userId: string, salt?: Uint8Array): Promise<Uint8Array>;
    /**
     * Encrypts a message using a derived shared key
     * @param message - The plaintext message to encrypt
     * @param userId - The ID of the user to encrypt for (must have shared key derived)
     * @returns Object containing the encrypted message components
     * @throws Error if shared key is not found or encryption fails
     */
    encryptWithSharedKey(message: string, userId: string): Promise<SharedKeyData>;
    /**
     * Decrypts a message using a derived shared key
     * @param encryptedData - Object containing the encrypted message components
     * @param userId - The ID of the user who encrypted the message
     * @returns The decrypted message
     * @throws Error if shared key is not found or decryption fails
     */
    decryptWithSharedKey(encryptedData: SharedKeyData, userId: string): Promise<string>;
    /**
     * Exports shared key encrypted message data to a string format
     * @param data - The shared key encrypted data object to export
     * @returns An encoded string representation of the encrypted data
     */
    exportSharedKeyData(data: SharedKeyData): string;
    /**
     * Imports an encoded string back into a shared key data object
     * @param encoded - The encoded string to import
     * @returns The decoded SharedKeyData object
     */
    importSharedKeyData(encoded: string): SharedKeyData;
    /**
     * Checks if a shared key exists for a user
     * @param userId - The ID of the user to check
     * @returns True if a shared key exists for the user, false otherwise
     */
    hasSharedKey(userId: string): boolean;
    /**
     * Checks if an ECDH public key exists for a user
     * @param userId - The ID of the user to check
     * @returns True if an ECDH public key exists for the user, false otherwise
     */
    hasECDHPublicKey(userId: string): boolean;
    /**
     * Removes shared key for a user (useful for key rotation)
     * @param userId - The ID of the user whose shared key to remove
     */
    removeSharedKey(userId: string): void;
    /**
     * Removes ECDH public key for a user
     * @param userId - The ID of the user whose ECDH public key to remove
     */
    removeECDHPublicKey(userId: string): void;
    /**
     * Decrypts a message using a derived shared key and returns verification status (does not throw on signature verification failure).
     * Note: SharedKeyData does not include signatures, so this method always returns verified: true for consistency.
     * @param encryptedData - Object containing the encrypted message components
     * @param userId - The ID of the user who encrypted the message
     * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
     * @throws Error if shared key is not found or decryption fails
     */
    decryptWithSharedKeyUnsafe(encryptedData: SharedKeyData, userId: string): Promise<IDecryptionResult>;
}
export default RSAMessage;
