import {
  getCrypto,
  getTextEncoder,
  getTextDecoder,
  bufferToBase64,
  base64ToBuffer,
  encodeJson,
  decodeJson,
  bytesToBinaryString,
  binaryStringToBytes,
  warnDeprecated
} from "./util";
import {
  RSAKeyPair,
  KeyPairOutput,
  AESConfig,
  ECDHKeyPair,
  ECDHPublicKey,
  SharedKeyData,
  DerivedKeyConfig,
  ECDHConfig,
  RSAKeySet
} from "./crypto-types";
import { KeyImportError, cryptoOperationError, keyImportError } from "./error-types";
import { AES_GCM_256, ECDH_P256, RSA_OAEP, RSA_PSS } from "./crypto-params";
import { generateRSAKeyPair, exportKeyString, importRSAKey, aesGcmEncrypt, aesGcmDecrypt } from "./crypto-ops";

export type { RSAKeySet } from "./crypto-types";

export interface IDecryptionResult {
  message: string;
  verified: boolean;
}

export interface IRSAEncryptedMessage {
  iv: Uint8Array;
  encryptedMessage: ArrayBuffer;
  signature: ArrayBuffer;
  encryptedAESKey?: ArrayBuffer; // Optional for master AES encryption
}

const isNonExtractablePrivate = (key: CryptoKey, algorithm: "RSA-OAEP" | "RSA-PSS"): boolean =>
  !!key && key.type === "private" && key.extractable === false && key.algorithm?.name === algorithm;

class RSAMessage {
  // Private key strings from the deprecated init(); remove privateKey and signKey in 3.0.0
  private privateKey: string;
  private publicKey: string;
  private verifyKey: string;
  private signKey: string;
  // Set by initKeySet() / importKeySet(); used instead of the private key strings above
  private privateCryptoKey: CryptoKey | null = null;
  private signCryptoKey: CryptoKey | null = null;
  private publicKeys: Map<string, string> = new Map();
  private verifyKeys: Map<string, string> = new Map();
  private ecdhPrivateKey: CryptoKey | null = null;
  private ecdhPublicKeys: Map<string, CryptoKey> = new Map();
  private sharedKeys: Map<string, CryptoKey> = new Map();
  // Master AES key (encrypted, as base64 string)
  private encryptedMasterAESKey: string | null = null;
  // Track who encrypted the master AES key for proper verification
  private masterAESKeyEncryptor: string | null = null;

  /**
   * Generates a new AES master key, encrypts it with the current user's publicKey, and sets it as the master key.
   * @returns {Promise<string>} The encrypted master AES key (base64 string)
   */
  public async generateAndSetMasterAESKey(): Promise<string> {
    const exportedEncrypted = await this.encryptKeyForUser(await this.generateAESKey(), "self");
    this.encryptedMasterAESKey = exportedEncrypted;
    this.masterAESKeyEncryptor = "self"; // We encrypted it ourselves
    return exportedEncrypted;
  }

  /**
   * Sets the encrypted master AES key (base64 string, encrypted with this user's publicKey)
   * @param {string} encryptedKey - The encrypted master AES key (base64 string)
   * @param {string} encryptor - The user ID who encrypted the key (defaults to "self")
   */
  public setEncryptedMasterAESKey(encryptedKey: string, encryptor: string = "self") {
    this.encryptedMasterAESKey = encryptedKey;
    this.masterAESKeyEncryptor = encryptor;
  }

  /**
   * Decrypts and returns the master AES key as a CryptoKey. Always decrypts fresh (no persistent cache).
   * @returns {Promise<CryptoKey>} The decrypted AES-GCM key
   */
  public async getDecryptedMasterAESKey(): Promise<CryptoKey> {
    const { iv, encryptedMessage, encryptedAESKey, signature } = this.importEncryptedMessage(this.requireMasterAESKey());
    if (!encryptedAESKey) {
      throw new Error("Master AES key must have been encrypted with RSA");
    }

    // Decrypt with our own private key, but verify the signature of whoever encrypted it
    const aesKey = await this.unwrapAESKey(encryptedAESKey);
    const message = getTextDecoder().decode(await aesGcmDecrypt(aesKey, iv, encryptedMessage, "Failed to decrypt message"));
    await this.requireVerifiedSignature(signature, message, this.masterAESKeyEncryptor || "self");

    // A payload that is not a JWK fails as a "verify" error, as it always has
    try {
      return await getCrypto().subtle.importKey(
        "jwk",
        JSON.parse(message),
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      throw cryptoOperationError("Failed to verify signature", "verify", error);
    }
  }

  /**
   * Encrypts the current master AES key with another user's publicKey and exports it (base64 string).
   * @param {string} userId - The user to encrypt the key for
   * @returns {Promise<string>} The encrypted master AES key (base64 string)
   */
  public async exportMasterAESKeyForUser(userId: string): Promise<string> {
    return await this.encryptKeyForUser(await this.getDecryptedMasterAESKey(), userId);
  }

  /**
   * Sets the master AES key from an encrypted key (base64 string, encrypted with this user's publicKey)
   * @param {string} encryptedKey - The encrypted master AES key (base64 string)
   * @param {string} encryptor - The user ID who encrypted the key (for proper signature verification)
   */
  public async setMasterAESKeyFromEncrypted(encryptedKey: string, encryptor: string = "self"): Promise<void> {
    this.encryptedMasterAESKey = encryptedKey;
    this.masterAESKeyEncryptor = encryptor;
    // Decrypting now verifies the key before it is used
    const aesKey = await this.getDecryptedMasterAESKey();
    if (encryptor !== "self") {
      // Ensure our own public key is set up for re-encryption
      if (!this.publicKeys.has("self")) {
        this.setPublicKey("self", this.publicKey, this.verifyKey);
      }

      // Re-encrypt with our own publicKey, so that if the encryptor's verify key changes we still have a valid copy
      this.encryptedMasterAESKey = await this.encryptKeyForUser(aesKey, "self");
      this.masterAESKeyEncryptor = "self"; // We encrypted it ourselves
    }
  }

  /**
   * Encrypts a message using the master AES key (must be set). No RSA is used. Output does not include encryptedAESKey.
   * @param message - The plaintext message to encrypt
   * @returns {Promise<IRSAEncryptedMessage>} Object containing the encrypted message, iv, and signature
   */
  public async encryptWithMasterAESKey(message: string): Promise<IRSAEncryptedMessage> {
    return await this.encryptAndSign(await this.getDecryptedMasterAESKey(), message);
  }

  /**
   * Decrypts a message using the master AES key (must be set). No RSA is used. Input should not include encryptedAESKey.
   * @param encryptedData - The encrypted message object (no encryptedAESKey)
   * @param sender - The ID of the user who sent the message (for signature verification)
   * @returns {Promise<string>} The decrypted message
   */
  public async decryptWithMasterAESKey(encryptedData: IRSAEncryptedMessage, sender: string): Promise<string> {
    const message = await this.decryptMasterAESKeyMessage(encryptedData);
    await this.requireVerifiedSignature(encryptedData.signature, message, sender);
    return message;
  }

  /**
   * Decrypts a message using the master AES key and returns verification status (does not throw on signature verification failure).
   * @param encryptedData - The encrypted message object (no encryptedAESKey)
   * @param sender - The ID of the user who sent the message (for signature verification)
   * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
   */
  public async decryptWithMasterAESKeyUnsafe(encryptedData: IRSAEncryptedMessage, sender: string): Promise<IDecryptionResult> {
    const message = await this.decryptMasterAESKeyMessage(encryptedData);
    return { message, verified: await this.isSignatureVerified(encryptedData.signature, message, sender) };
  }

  constructor() {
    this.privateKey = "";
    this.publicKey = "";
    this.verifyKey = "";
    this.signKey = "";
  }

  get publickey() {
    return this.publicKey;
  }

  get verifykey() {
    return this.verifyKey;
  }

  /**
   * @deprecated Since 2.3.0; will be removed in 3.0.0. Private keys from initKeySet() cannot be exported,
   * so store the RSAKeySet it returns instead of this string.
   */
  get privatekey() {
    warnDeprecated("RSA_MESSAGE_DEP_PRIVATEKEY",
      "RSAMessage.privatekey is deprecated and will be removed in 3.0.0. Use initKeySet() and store the key set it returns instead.");
    return this.privateKey;
  }

  /**
   * @deprecated Since 2.3.0; will be removed in 3.0.0. Private keys from initKeySet() cannot be exported,
   * so store the RSAKeySet it returns instead of this string.
   */
  get signkey() {
    warnDeprecated("RSA_MESSAGE_DEP_SIGNKEY",
      "RSAMessage.signkey is deprecated and will be removed in 3.0.0. Use initKeySet() and store the key set it returns instead.");
    return this.signKey;
  }


  public async generateAESKey() {
    return await getCrypto().subtle.generateKey(AES_GCM_256, true, ["encrypt", "decrypt"]);
  }

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
  public async init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string) : Promise<KeyPairOutput> {
    warnDeprecated("RSA_MESSAGE_DEP_INIT",
      "RSAMessage.init() is deprecated and will be removed in 3.0.0. Use initKeySet() to generate or reuse keys, or importKeySet() to convert keys saved as strings.");
    this.privateCryptoKey = null;
    this.signCryptoKey = null;

    if (publicKey && privateKey && verifyKey && signKey) {
      this.publicKey = publicKey;
      this.privateKey = privateKey;
      this.verifyKey = verifyKey;
      this.signKey = signKey;
      return { publicKey: this.publicKey, verifyKey: this.verifyKey };
    }

    const encryptionKeys = await this.genKeyPair();
    const signatureKeys = await this.genKeyPair("sign");
    this.publicKey = encryptionKeys.publicKey;
    this.privateKey = encryptionKeys.privateKey;
    this.verifyKey = signatureKeys.publicKey;
    this.signKey = signatureKeys.privateKey;
    return { publicKey: encryptionKeys.publicKey, verifyKey: signatureKeys.publicKey };
  }

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
  public async initKeySet(keySet?: RSAKeySet): Promise<RSAKeySet> {
    if (!keySet) {
      const encryption = await this.genKeySetPair("decrypt");
      const signature = await this.genKeySetPair("sign");
      keySet = {
        publicKey: encryption.publicKey,
        privateKey: encryption.privateKey,
        verifyKey: signature.publicKey,
        signKey: signature.privateKey,
      };
    }
    else {
      if (!keySet.publicKey || !keySet.verifyKey ||
          !isNonExtractablePrivate(keySet.privateKey, "RSA-OAEP") || !isNonExtractablePrivate(keySet.signKey, "RSA-PSS")) {
        throw new KeyImportError("A key set needs both public keys and two non-extractable private keys", "private");
      }
      await this.checkKeySet(keySet);
    }

    this.useKeySet(keySet);
    return keySet;
  }

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
  public async importKeySet(publicKey: string, privateKey: string, verifyKey: string, signKey: string): Promise<RSAKeySet> {
    if (!publicKey || !verifyKey) {
      throw new KeyImportError("A key set needs both public keys", "public");
    }
    const keySet: RSAKeySet = {
      publicKey,
      verifyKey,
      privateKey: await this.importPrivateKey(privateKey, "decrypt"),
      signKey: await this.importPrivateKey(signKey, "sign"),
    };
    await this.checkKeySet(keySet);
    this.useKeySet(keySet);
    return keySet;
  }

  // Proves each private key belongs to its public key, so a mismatched set fails here, not on first use
  private checkKeySet = async (keySet: RSAKeySet): Promise<void> => {
    const probe = getCrypto().getRandomValues(new Uint8Array(32));
    let matches = false;
    let cause: Error | undefined;
    try {
      const encrypted = await getCrypto().subtle.encrypt(RSA_OAEP, await this.importPublicKey(keySet.publicKey, "encrypt"), probe);
      const decrypted = new Uint8Array(await getCrypto().subtle.decrypt(RSA_OAEP, keySet.privateKey, encrypted));
      const signature = await getCrypto().subtle.sign(RSA_PSS, keySet.signKey, probe);
      matches = decrypted.length === probe.length && decrypted.every((b, i) => b === probe[i]) &&
        await getCrypto().subtle.verify(RSA_PSS, await this.importPublicKey(keySet.verifyKey, "verify"), signature, probe);
    } catch (error) {
      cause = error instanceof Error ? error : undefined;
    }
    if (!matches) {
      throw new KeyImportError("The private keys do not match the public keys", "private", cause);
    }
  };

  private useKeySet(keySet: RSAKeySet) {
    this.publicKey = keySet.publicKey;
    this.verifyKey = keySet.verifyKey;
    this.privateCryptoKey = keySet.privateKey;
    this.signCryptoKey = keySet.signKey;
    this.privateKey = "";
    this.signKey = "";
  }

  private genKeySetPair = async (type: "decrypt" | "sign"): Promise<{ publicKey: string, privateKey: CryptoKey }> => {
    // the private key cannot be exported; WebCrypto always makes the RSA public key exportable
    const keyPair = await generateRSAKeyPair(type, false);
    return { publicKey: await exportKeyString(keyPair.publicKey), privateKey: keyPair.privateKey };
  };

  private getPrivateKey = async (type: "decrypt" | "sign"): Promise<CryptoKey> => {
    const cryptoKey = type === "decrypt" ? this.privateCryptoKey : this.signCryptoKey;
    if (cryptoKey) {
      return cryptoKey;
    }
    // String keys only come from the deprecated init(); remove this fallback in 3.0.0
    return await this.importPrivateKey(type === "decrypt" ? this.privateKey : this.signKey, type);
  };

  private genKeyPair = async (type: "decrypt" | "sign" = "decrypt"): Promise<RSAKeyPair> => {
    const keyPair = await generateRSAKeyPair(type, true);
    return { publicKey: await exportKeyString(keyPair.publicKey), privateKey: await exportKeyString(keyPair.privateKey) };
  };

  private importPrivateKey = async (privateKey: string, type: "sign" | "decrypt") =>
    await importRSAKey(privateKey, type, "private");

  private importPublicKey = async (publicKey: string, type: "encrypt" | "verify"): Promise<CryptoKey> =>
    await importRSAKey(publicKey, type, "public");

  /**
   * Encrypts a message using RSA-AES hybrid encryption, using the master AES key if set, otherwise generates a new AES key.
   * @param message - The plaintext message to encrypt
   * @param userId - The ID of the recipient user whose public key will be used
   * @param useMasterAESKey - If true, use the master AES key (if set)
   * @returns {Promise<IRSAEncryptedMessage>} Object containing the encrypted message components:
   *  - iv: Initialization vector for AES-GCM
   *  - encryptedMessage: The AES encrypted message
   *  - encryptedAESKey: The RSA encrypted AES key (undefined when the master AES key is used)
   *  - signature: Digital signature of the message
   * @throws {Error} If public key is not found for the user
   */
  public encryptMessage = async (message: string, userId: string, useMasterAESKey: boolean = false) => {
    const publicKeyRaw = this.publicKeys.get(userId);
    if (!publicKeyRaw) {
      throw new Error("Public key not found for user");
    }

    let aesKey: CryptoKey;
    let encryptedAESKey: ArrayBuffer | undefined;

    if (useMasterAESKey && this.encryptedMasterAESKey) {
      aesKey = await this.getDecryptedMasterAESKey();
      // No need to encrypt the AES key when using master key
      encryptedAESKey = undefined;
    } else {
      aesKey = await this.generateAESKey();
      // Export and encrypt the AES key with RSA
      const publicKey = await this.importPublicKey(publicKeyRaw, "encrypt");
      const aesKeyData = await getCrypto().subtle.exportKey("raw", aesKey);
      encryptedAESKey = await getCrypto().subtle.encrypt(RSA_OAEP, publicKey, aesKeyData);
    }

    const { iv, encryptedMessage, signature } = await this.encryptAndSign(aesKey, message);

    return {
      iv,
      encryptedMessage,
      encryptedAESKey,
      signature,
    } as IRSAEncryptedMessage;
  };

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
  public decryptMessage = async (encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey: boolean = false): Promise<string> => {
    const message = await this.decryptHybridMessage(encryptedData, useMasterAESKey);
    await this.requireVerifiedSignature(encryptedData.signature, message, sender);
    return message;
  };

  /**
   * Decrypts an encrypted message and returns verification status (does not throw on signature verification failure).
   * @param encryptedData - Object containing the encrypted message components
   * @param sender - The ID of the user who sent the message
   * @param useMasterAESKey - If true, use the master AES key (if set)
   * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
   */
  public async decryptMessageUnsafe(encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey: boolean = false): Promise<IDecryptionResult> {
    const message = await this.decryptHybridMessage(encryptedData, useMasterAESKey);
    return { message, verified: await this.isSignatureVerified(encryptedData.signature, message, sender) };
  }

  /**
   * Signs a message using RSA-PSS with the user's private signing key
   * @param message - The message string to sign
   * @returns Promise that resolves with the signature as an ArrayBuffer
   * @throws Error if signing fails
   */
  public signMessage = async (message: string): Promise<ArrayBuffer> => {
    const encoder = getTextEncoder();
    const data = encoder.encode(message);

    try {
      const privateKey = await this.getPrivateKey("sign");
      return await getCrypto().subtle.sign(RSA_PSS, privateKey, data);
    }
    catch (error) {
      throw cryptoOperationError("Failed to sign message", "sign", error);
    }
  };

  /**
   * Verifies a message signature using RSA-PSS with the sender's public verification key
   * @param signature - The signature to verify as an ArrayBuffer
   * @param message - The original message string that was signed
   * @param userId - The ID of the user who signed the message
   * @returns Promise that resolves with boolean indicating if signature is valid
   * @throws Error if verification fails or public key not found
   */
  public verifySignature = async (signature: ArrayBuffer, message: string, userId: string) => {
    const publicKeyRaw = this.verifyKeys.get(userId);
    if (!publicKeyRaw) {
      throw new Error("Public key not found for user");
    }

    try {
      const publicKey = await this.importPublicKey(publicKeyRaw, "verify");

      const encoder = getTextEncoder();
      const data = encoder.encode(message);

      const verified: boolean = await getCrypto().subtle.verify(RSA_PSS, publicKey, new Uint8Array(signature), data);

      return verified;
    }
    catch (error) {
      throw cryptoOperationError("Failed to verify signature", "verify", error);
    }
  };

  /**
   * Sets a user's public encryption key and optionally their verification key
   * @param userId - The ID of the user to set keys for
   * @param publicKey - The public encryption key string
   * @param verifyKey - Optional verification key string for backwards compatibility
   * @throws Error if userId or publicKey are invalid
   */
  public setPublicKey(userId: string, publicKey: string, verifyKey?: string) { // backwards compatible
    if (!userId || !publicKey) {
      throw new Error("Invalid arguments");
    }
    this.publicKeys.set(userId, publicKey);
    if (verifyKey) {
      this.verifyKeys.set(userId, verifyKey);
    }
  }

  /**
   * Sets a user's public verification key used for signature verification
   * @param userId - The ID of the user to set the verify key for
   * @param verifyKey - The verification key string
   * @throws Error if userId or verifyKey are invalid
   */
  public setVerifyKey(userId: string, verifyKey: string) {
    if (!userId || !verifyKey) {
      throw new Error("Invalid arguments");
    }
    this.verifyKeys.set(userId, verifyKey);
  }

  /**
   * Checks if a public encryption key exists for a user
   * @param userId - The ID of the user to check
   * @returns True if a public key exists for the user, false otherwise
   */
  public hasPublicKey(userId: string): boolean {
    return this.publicKeys.has(userId);
  }

  /**
   * Checks if a public verification key exists for a user
   * @param userId - The ID of the user to check
   * @returns True if a verification key exists for the user, false otherwise
   */
  public hasVerifyKey(userId: string): boolean {
    return this.verifyKeys.has(userId);
  }

  /**
   * Exports an encrypted message object to a string format
   * @param message - The encrypted message object to export
   * @returns An encoded string representation of the encrypted message
   */
  public exportEncryptedMessage(message: IRSAEncryptedMessage): string {
    return encodeJson({
      iv: bytesToBinaryString(message.iv),
      encryptedMessage: bufferToBase64(message.encryptedMessage),
      encryptedAESKey: message.encryptedAESKey ? bufferToBase64(message.encryptedAESKey) : undefined,
      signature: bufferToBase64(message.signature)
    });
  }

  /**
   * Imports an encoded string back into an encrypted message object
   * @param encoded - The encoded string to import
   * @returns The decoded IRSAEncryptedMessage object
   */
  public importEncryptedMessage(encoded: string): IRSAEncryptedMessage {
    const decoded = decodeJson(encoded);
    return {
      iv: binaryStringToBytes(decoded.iv),
      encryptedMessage: base64ToBuffer(decoded.encryptedMessage),
      encryptedAESKey: decoded.encryptedAESKey ? base64ToBuffer(decoded.encryptedAESKey) : undefined,
      signature: base64ToBuffer(decoded.signature)
    };
  }

  /**
   * Generates ECDH key pair for key exchange
   * @returns Promise that resolves with the public key in exportable format
   * @throws Error if key generation fails
   */
  public async generateECDHKeyPair(): Promise<ECDHPublicKey> {
    try {
      const keyPair: ECDHKeyPair = await getCrypto().subtle.generateKey(ECDH_P256, true, ["deriveBits", "deriveKey"]);

      this.ecdhPrivateKey = keyPair.privateKey;

      return { publicKey: await exportKeyString(keyPair.publicKey) };
    } catch (error) {
      throw cryptoOperationError("Failed to generate ECDH key pair", "encrypt", error);
    }
  }

  /**
   * Imports another user's ECDH public key for key exchange
   * @param userId - The ID of the user whose public key to import
   * @param publicKey - The base64 encoded ECDH public key
   * @throws Error if key import fails
   */
  public async setECDHPublicKey(userId: string, publicKey: string): Promise<void> {
    try {
      const cryptoKey = await getCrypto().subtle.importKey("jwk", decodeJson(publicKey), ECDH_P256, false, []);

      this.ecdhPublicKeys.set(userId, cryptoKey);
    } catch (error) {
      throw keyImportError("Failed to import ECDH public key", "public", error);
    }
  }

  /**
   * Derives a shared secret key using ECDH and stores it for the user
   * @param userId - The ID of the user to derive shared key with
   * @param salt - Optional salt for key derivation. If not provided, a random salt is generated
   * @returns The salt used for key derivation
   * @throws Error if key derivation fails or required keys are missing
   */
  public async deriveSharedKey(userId: string, salt?: Uint8Array): Promise<Uint8Array> {
    if (!this.ecdhPrivateKey) {
      throw new Error("ECDH private key not generated. Call generateECDHKeyPair() first.");
    }

    const otherPublicKey = this.ecdhPublicKeys.get(userId);
    if (!otherPublicKey) {
      throw new Error(`ECDH public key not found for user: ${userId}`);
    }

    try {
      // Generate salt if not provided
      const keySalt = salt || getCrypto().getRandomValues(new Uint8Array(16));

      // Derive shared secret using ECDH
      const sharedSecret = await getCrypto().subtle.deriveBits(
        {
          name: "ECDH",
          public: otherPublicKey,
        } as ECDHConfig,
        this.ecdhPrivateKey,
        256 // 256 bits
      );

      // Derive encryption key using PBKDF2
      const baseKey = await getCrypto().subtle.importKey(
        "raw",
        sharedSecret,
        "PBKDF2",
        false,
        ["deriveKey"]
      );

      const derivedKey = await getCrypto().subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: keySalt,
          iterations: 100000,
          hash: "SHA-256",
        } as DerivedKeyConfig,
        baseKey,
        AES_GCM_256,
        false,
        ["encrypt", "decrypt"]
      );

      this.sharedKeys.set(userId, derivedKey);
      return keySalt;
    } catch (error) {
      throw cryptoOperationError("Failed to derive shared key", "encrypt", error);
    }
  }

  /**
   * Encrypts a message using a derived shared key
   * @param message - The plaintext message to encrypt
   * @param userId - The ID of the user to encrypt for (must have shared key derived)
   * @returns Object containing the encrypted message components
   * @throws Error if shared key is not found or encryption fails
   */
  public async encryptWithSharedKey(message: string, userId: string): Promise<SharedKeyData> {
    const sharedKey = this.getSharedKey(userId);

    try {
      const { iv, encryptedMessage } = await aesGcmEncrypt(sharedKey, getTextEncoder().encode(message));
      const salt = getCrypto().getRandomValues(new Uint8Array(16)); // Salt for this encryption

      return {
        salt,
        encryptedMessage,
        iv,
      };
    } catch (error) {
      throw cryptoOperationError("Failed to encrypt with shared key", "encrypt", error);
    }
  }

  /**
   * Decrypts a message using a derived shared key
   * @param encryptedData - Object containing the encrypted message components
   * @param userId - The ID of the user who encrypted the message
   * @returns The decrypted message
   * @throws Error if shared key is not found or decryption fails
   */
  public async decryptWithSharedKey(encryptedData: SharedKeyData, userId: string): Promise<string> {
    const sharedKey = this.getSharedKey(userId);

    try {
      const { iv, encryptedMessage } = encryptedData;

      const decryptedMessage = await getCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        } as AESConfig,
        sharedKey,
        new Uint8Array(encryptedMessage)
      );

      return getTextDecoder().decode(decryptedMessage);
    } catch (error) {
      throw cryptoOperationError("Failed to decrypt with shared key", "decrypt", error);
    }
  }

  /**
   * Exports shared key encrypted message data to a string format
   * @param data - The shared key encrypted data object to export
   * @returns An encoded string representation of the encrypted data
   */
  public exportSharedKeyData(data: SharedKeyData): string {
    return encodeJson({
      salt: bytesToBinaryString(data.salt),
      encryptedMessage: bufferToBase64(data.encryptedMessage),
      iv: bytesToBinaryString(data.iv)
    });
  }

  /**
   * Imports an encoded string back into a shared key data object
   * @param encoded - The encoded string to import
   * @returns The decoded SharedKeyData object
   */
  public importSharedKeyData(encoded: string): SharedKeyData {
    const decoded = decodeJson(encoded);
    return {
      salt: binaryStringToBytes(decoded.salt),
      encryptedMessage: base64ToBuffer(decoded.encryptedMessage),
      iv: binaryStringToBytes(decoded.iv)
    };
  }

  /**
   * Checks if a shared key exists for a user
   * @param userId - The ID of the user to check
   * @returns True if a shared key exists for the user, false otherwise
   */
  public hasSharedKey(userId: string): boolean {
    return this.sharedKeys.has(userId);
  }

  /**
   * Checks if an ECDH public key exists for a user
   * @param userId - The ID of the user to check
   * @returns True if an ECDH public key exists for the user, false otherwise
   */
  public hasECDHPublicKey(userId: string): boolean {
    return this.ecdhPublicKeys.has(userId);
  }

  /**
   * Removes shared key for a user (useful for key rotation)
   * @param userId - The ID of the user whose shared key to remove
   */
  public removeSharedKey(userId: string): void {
    this.sharedKeys.delete(userId);
  }

  /**
   * Removes ECDH public key for a user
   * @param userId - The ID of the user whose ECDH public key to remove
   */
  public removeECDHPublicKey(userId: string): void {
    this.ecdhPublicKeys.delete(userId);
  }

  /**
   * Decrypts a message using a derived shared key and returns verification status (does not throw on signature verification failure).
   * Note: SharedKeyData does not include signatures, so this method always returns verified: true for consistency.
   * @param encryptedData - Object containing the encrypted message components
   * @param userId - The ID of the user who encrypted the message
   * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
   * @throws Error if shared key is not found or decryption fails
   */
  public async decryptWithSharedKeyUnsafe(encryptedData: SharedKeyData, userId: string): Promise<IDecryptionResult> {
    // SharedKeyData doesn't include signatures, so verification is always true
    return { message: await this.decryptWithSharedKey(encryptedData, userId), verified: true };
  }

  private requireMasterAESKey(): string {
    if (!this.encryptedMasterAESKey) {
      throw new Error("No master AES key set");
    }
    return this.encryptedMasterAESKey;
  }

  private getSharedKey(userId: string): CryptoKey {
    const sharedKey = this.sharedKeys.get(userId);
    if (!sharedKey) {
      throw new Error(`Shared key not found for user: ${userId}. Call deriveSharedKey() first.`);
    }
    return sharedKey;
  }

  // Encrypts an AES key for a user as an exported message, the form master AES keys are shared in
  private async encryptKeyForUser(aesKey: CryptoKey, userId: string): Promise<string> {
    const exported = await getCrypto().subtle.exportKey("jwk", aesKey);
    return this.exportEncryptedMessage(await this.encryptMessage(JSON.stringify(exported), userId));
  }

  // Decrypts an RSA-encrypted AES key with our private key
  private async unwrapAESKey(encryptedAESKey: ArrayBuffer): Promise<CryptoKey> {
    let privateKey: CryptoKey;
    try {
      privateKey = await this.getPrivateKey("decrypt");
    } catch (error) {
      throw new Error(`Failed to import private key: ${error}`);
    }

    let aesKeyData: ArrayBuffer;
    try {
      aesKeyData = await getCrypto().subtle.decrypt(RSA_OAEP, privateKey, new Uint8Array(encryptedAESKey));
    } catch (error) {
      throw cryptoOperationError("Failed to decrypt AES key", "decrypt", error);
    }

    try {
      return await getCrypto().subtle.importKey("raw", aesKeyData, "AES-GCM", true, ["decrypt"]);
    } catch (error) {
      throw keyImportError("Failed to import AES key", "private", error);
    }
  }

  // AES-GCM encrypts a message with a new IV and signs its plaintext
  private async encryptAndSign(aesKey: CryptoKey, message: string) {
    const { iv, encryptedMessage } = await aesGcmEncrypt(aesKey, getTextEncoder().encode(message));
    const signature = await this.signMessage(message);
    return { iv, encryptedMessage, signature };
  }

  // Decrypts with the master AES key or the RSA-encrypted one; the caller checks the signature
  private async decryptHybridMessage(encryptedData: IRSAEncryptedMessage, useMasterAESKey: boolean): Promise<string> {
    const { iv, encryptedMessage, encryptedAESKey } = encryptedData;
    let aesKey: CryptoKey;

    if (useMasterAESKey && this.encryptedMasterAESKey) {
      aesKey = await this.getDecryptedMasterAESKey();
    } else if (encryptedAESKey) {
      aesKey = await this.unwrapAESKey(encryptedAESKey);
    } else {
      throw new Error("No AES key available for decryption - either provide encryptedAESKey or use master AES key");
    }

    return getTextDecoder().decode(await aesGcmDecrypt(aesKey, iv, encryptedMessage, "Failed to decrypt message"));
  }

  // Decrypts a message encrypted with the master AES key; the caller checks the signature
  private async decryptMasterAESKeyMessage(encryptedData: IRSAEncryptedMessage): Promise<string> {
    const aesKey = await this.getDecryptedMasterAESKey();
    const { iv, encryptedMessage } = encryptedData;
    return getTextDecoder().decode(await aesGcmDecrypt(aesKey, iv, encryptedMessage, "Failed to decrypt with master AES key"));
  }

  // Throws a "verify" CryptoOperationError unless the signature is valid
  private async requireVerifiedSignature(signature: ArrayBuffer, message: string, signer: string): Promise<void> {
    try {
      if (!await this.verifySignature(signature, message, signer)) {
        throw new Error("Signature verification failed");
      }
    } catch (error) {
      throw cryptoOperationError("Failed to verify signature", "verify", error);
    }
  }

  // For the unsafe decrypt methods: any verification failure is reported as false
  private async isSignatureVerified(signature: ArrayBuffer, message: string, signer: string): Promise<boolean> {
    try {
      return await this.verifySignature(signature, message, signer);
    } catch (error) {
      return false;
    }
  }
}

export default RSAMessage;
