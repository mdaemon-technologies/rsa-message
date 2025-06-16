import { encode, decode } from "base64util";
import { 
  getCrypto, 
  getTextEncoder, 
  getTextDecoder, 
  bufferToBase64, 
  base64ToBuffer
} from "./util";
import {
  CryptoKeyOptions,
  RSAKeyPair,
  RSAConfig,
  KeyPairOutput,
  AESConfig,
  ECDHKeyPair,
  ECDHPublicKey,
  SharedKeyData,
  DerivedKeyConfig,
  ECDHConfig
} from "./crypto-types";
import { CryptoOperationError, KeyImportError } from "./error-types";

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

class RSAMessage {
  private privateKey: string;
  private publicKey: string;
  private verifyKey: string;
  private signKey: string;
  private publicKeys: Map<string, string> = new Map();
  private verifyKeys: Map<string, string> = new Map();
  private ecdhPrivateKey: CryptoKey | null = null;
  private ecdhPublicKeys: Map<string, CryptoKey> = new Map();
  private sharedKeys: Map<string, CryptoKey> = new Map();
  // Master AES key (encrypted, as base64 string)
  private encryptedMasterAESKey: string | null = null;  // Track who encrypted the master AES key for proper verification
  private masterAESKeyEncryptor: string | null = null;
  
  // Optionally cache the decrypted key in memory for a session (not persisted)
  private masterAESKeyCache: CryptoKey | null = null;

  /**
   * Generates a new AES master key, encrypts it with the current user's publicKey, and sets it as the master key.
   * @returns {Promise<string>} The encrypted master AES key (base64 string)
   */
  public async generateAndSetMasterAESKey(): Promise<string> {    // Generate AES key
    const aesKey = await this.generateAESKey();
    
    // Export as JWK
    const exported = await getCrypto().subtle.exportKey("jwk", aesKey);
    const exportedStr = JSON.stringify(exported);
    
    // Encrypt with our own publicKey
    const encrypted = await this.encryptMessage(exportedStr, "self");
    const exportedEncrypted = this.exportEncryptedMessage(encrypted);
    
    // Store the encrypted master key
    this.encryptedMasterAESKey = exportedEncrypted;
    this.masterAESKeyEncryptor = "self"; // We encrypted it ourselves
    this.masterAESKeyCache = null; // Clear cache
    return exportedEncrypted;
  }

  /**
   * Sets the encrypted master AES key (base64 string, encrypted with this user's publicKey)
   * @param {string} encryptedKey - The encrypted master AES key (base64 string)
   * @param {string} encryptor - The user ID who encrypted the key (defaults to "self")
   */  public setEncryptedMasterAESKey(encryptedKey: string, encryptor: string = "self") {
    this.encryptedMasterAESKey = encryptedKey;
    this.masterAESKeyEncryptor = encryptor;
    this.masterAESKeyCache = null; // Clear cache
  }

  /**
   * Decrypts and returns the master AES key as a CryptoKey. Always decrypts fresh (no persistent cache).
   * @returns {Promise<CryptoKey>} The decrypted AES-GCM key
   */
  public async getDecryptedMasterAESKey(): Promise<CryptoKey> {
    if (!this.encryptedMasterAESKey) throw new Error("No master AES key set");
    // Decrypt using the known encryptor for signature verification, but our own private key for decryption
    const encrypted = this.importEncryptedMessage(this.encryptedMasterAESKey);
    
    // Special handling for master AES key: we decrypt with our own private key but verify signature from the encryptor
    const { iv, encryptedMessage, encryptedAESKey, signature } = encrypted;
    
    if (!encryptedAESKey) {
      throw new Error("Master AES key must have been encrypted with RSA");
    }
    
    // Decrypt the AES key with our own private key
    let privateKey: CryptoKey;
    try {
      privateKey = await this.importPrivateKey(this.privateKey, "decrypt");
    } catch (error) {
      throw new Error(`Failed to import private key: ${error}`);
    }

    let aesKeyData: ArrayBuffer;
    try {
      aesKeyData = await getCrypto().subtle.decrypt(
        {
          name: "RSA-OAEP",
        } as RSAConfig,
        privateKey,
        new Uint8Array(encryptedAESKey)
      );
    } catch (error) {
      throw new CryptoOperationError(`Failed to decrypt AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }

    // Decrypt the message content with the AES key
    let aesKey: CryptoKey;
    try {
      aesKey = await getCrypto().subtle.importKey(
        "raw",
        aesKeyData,
        "AES-GCM",
        true,
        ["decrypt"]
      );
    } catch (error) {
      throw new KeyImportError(`Failed to import AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'private',
        error instanceof Error ? error : undefined
      );
    }

    let decryptedMessage: ArrayBuffer;
    try {
      decryptedMessage = await getCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        } as AESConfig,
        aesKey,
        new Uint8Array(encryptedMessage)
      );
    } catch (error) {
      throw new CryptoOperationError(`Failed to decrypt message: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }

    // Verify the signature using the encryptor's verify key
    try {
      const decoder = getTextDecoder();
      const message = decoder.decode(decryptedMessage);
      const verified = await this.verifySignature(signature, message, this.masterAESKeyEncryptor || "self");
      if (!verified) {
        throw new Error("Signature verification failed");
      }
      
      // Parse and return the AES key
      const jwk = JSON.parse(message);
      return await getCrypto().subtle.importKey(
        "jwk",
        jwk,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
      );
    } catch (error) {
      throw new CryptoOperationError(`Failed to verify signature: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'verify',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**   * Encrypts the current master AES key with another user's publicKey and exports it (base64 string).
   * @param {string} userId - The user to encrypt the key for
   * @returns {Promise<string>} The encrypted master AES key (base64 string)
   */
  public async exportMasterAESKeyForUser(userId: string): Promise<string> {
    if (!this.encryptedMasterAESKey) throw new Error("No master AES key set");
    
    // Decrypt our master key
    const aesKey = await this.getDecryptedMasterAESKey();
    const exported = await getCrypto().subtle.exportKey("jwk", aesKey);
    const exportedStr = JSON.stringify(exported);
    // Encrypt with the other user's publicKey
    const encrypted = await this.encryptMessage(exportedStr, userId);
    return this.exportEncryptedMessage(encrypted);
  }

  /**
   * Sets the master AES key from an encrypted key (base64 string, encrypted with this user's publicKey)
   * @param {string} encryptedKey - The encrypted master AES key (base64 string)
   * @param {string} encryptor - The user ID who encrypted the key (for proper signature verification)
   */
  public async setMasterAESKeyFromEncrypted(encryptedKey: string, encryptor: string = "self"): Promise<void> {
    this.encryptedMasterAESKey = encryptedKey;
    this.masterAESKeyEncryptor = encryptor;
    this.masterAESKeyCache = null;
    // Optionally, test decryption now to verify
    await this.getDecryptedMasterAESKey();
  }

  /**
   * Encrypts a message using the master AES key (must be set). No RSA is used. Output does not include encryptedAESKey.
   * @param message - The plaintext message to encrypt
   * @returns {Promise<IRSAEncryptedMessage>} Object containing the encrypted message, iv, and signature
   */
  public async encryptWithMasterAESKey(message: string): Promise<IRSAEncryptedMessage> {
    if (!this.encryptedMasterAESKey) throw new Error("No master AES key set");
    const aesKey = await this.getDecryptedMasterAESKey();
    const encoder = getTextEncoder();
    const data = encoder.encode(message);
    const iv = getCrypto().getRandomValues(new Uint8Array(12));
    const encryptedMessage = await getCrypto().subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      data
    );
    const signature = await this.signMessage(message);
    return {
      iv,
      encryptedMessage,
      signature
    };
  }

  /**
   * Decrypts a message using the master AES key (must be set). No RSA is used. Input should not include encryptedAESKey.
   * @param encryptedData - The encrypted message object (no encryptedAESKey)
   * @param sender - The ID of the user who sent the message (for signature verification)
   * @returns {Promise<string>} The decrypted message
   */
  public async decryptWithMasterAESKey(encryptedData: IRSAEncryptedMessage, sender: string): Promise<string> {
    if (!this.encryptedMasterAESKey) throw new Error("No master AES key set");
    const aesKey = await this.getDecryptedMasterAESKey();
    const { iv, encryptedMessage, signature } = encryptedData;
    let decryptedMessage: ArrayBuffer;
    try {
      decryptedMessage = await getCrypto().subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        new Uint8Array(encryptedMessage)
      );
    } catch (error) {
      throw new CryptoOperationError(`Failed to decrypt with master AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }
    try {
      const decoder = getTextDecoder();
      const message = decoder.decode(decryptedMessage);
      const verified = await this.verifySignature(signature, message, sender);
      if (!verified) {
        throw new Error("Signature verification failed");
      }
      return message;
    } catch (error) {
      throw new CryptoOperationError(`Failed to verify signature: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'verify',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Decrypts a message using the master AES key and returns verification status (does not throw on signature verification failure).
   * @param encryptedData - The encrypted message object (no encryptedAESKey)
   * @param sender - The ID of the user who sent the message (for signature verification)
   * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
   */
  public async decryptWithMasterAESKeyUnsafe(encryptedData: IRSAEncryptedMessage, sender: string): Promise<IDecryptionResult> {
    if (!this.encryptedMasterAESKey) throw new Error("No master AES key set");
    const aesKey = await this.getDecryptedMasterAESKey();
    const { iv, encryptedMessage, signature } = encryptedData;
    let decryptedMessage: ArrayBuffer;
    try {
      decryptedMessage = await getCrypto().subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        new Uint8Array(encryptedMessage)
      );
    } catch (error) {
      throw new CryptoOperationError(`Failed to decrypt with master AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }
    
    const decoder = getTextDecoder();
    const message = decoder.decode(decryptedMessage);
    
    // Attempt signature verification but don't throw on failure
    let verified = false;
    try {
      verified = await this.verifySignature(signature, message, sender);
    } catch (error) {
      // Signature verification failed, but we still return the message
      verified = false;
    }
    
    return { message, verified };
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

  get privatekey() {
    return this.privateKey;
  }

  get signkey() {
    return this.signKey;
  }


  public async generateAESKey() {
    return await getCrypto().subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"]
    );
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
   */
  public async init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string) : Promise<KeyPairOutput> {
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

  private genKeyPair = async (type: "decrypt" | "sign" = "decrypt"): Promise<RSAKeyPair> => {
    const usage = type === "decrypt" ? ["encrypt", "decrypt"] : ["sign", "verify"];
    const keyPair: RSAKeyPair = await getCrypto().subtle.generateKey(
      {
       name: type === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
       modulusLength: 2048,
       publicExponent: new Uint8Array([1, 0, 1]),
       hash: "SHA-256",
      },
      true,
      usage
    );
    
    const publicKeyRaw = await getCrypto().subtle.exportKey("jwk", keyPair.publicKey);
    const privateKeyRaw = await getCrypto().subtle.exportKey("jwk", keyPair.privateKey);
    return { publicKey: encode(JSON.stringify(publicKeyRaw)), privateKey: encode(JSON.stringify(privateKeyRaw)) };
  };

  private importPrivateKey = async (privateKey: string, type: "sign" | "decrypt") => {
    const options: CryptoKeyOptions = {
      name: type === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
      hash: "SHA-256",
    };

    if (type === "sign") {
      options.saltLength = 32;
    }
    
    try {
      const rsaPrivateKey = JSON.parse(decode(privateKey));
      return await getCrypto().subtle.importKey(
        "jwk",
        rsaPrivateKey,
        options,
        false,
        [type]
      );

    } catch (error) {
      throw new KeyImportError(`Failed to import private key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'private',
        error instanceof Error ? error : undefined
      );
    }
  };

  private importPublicKey = async (publicKey: string, type: "encrypt" | "verify"): Promise<CryptoKey> => {
    const options: CryptoKeyOptions = {
      name: "encrypt" === type ? "RSA-OAEP" : "RSA-PSS",
      hash: "SHA-256",
    };

    if (type === "verify") {
      options.saltLength = 32;
    }

    try {
      const rsaPublicKey = JSON.parse(decode(publicKey));
      return await getCrypto().subtle.importKey(
        "jwk",
        rsaPublicKey,
        options,
        false,
        [type]
      );

    } catch (error) {
      throw new KeyImportError(`Failed to import public key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'public',
        error instanceof Error ? error : undefined
      );
    }
  };

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
  public encryptMessage = async (message: string, userId: string, useMasterAESKey: boolean = false) => {
    const publicKeyRaw = this.publicKeys.get(userId);
    if (!publicKeyRaw) {
      throw new Error("Public key not found for user");
    }

    const encoder = getTextEncoder();
    const data = encoder.encode(message);

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
      encryptedAESKey = await getCrypto().subtle.encrypt(
        {
          name: "RSA-OAEP",
        } as RSAConfig,
        publicKey,
        aesKeyData
      );
    }

    const iv = getCrypto().getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
    const encryptedMessage = await getCrypto().subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      } as AESConfig,
      aesKey,
      data
    );

    const signature = await this.signMessage(message);

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
  public decryptMessage = async (encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey: boolean = false) => {
    const { iv, encryptedMessage, encryptedAESKey, signature } = encryptedData;
    let aesKey: CryptoKey;

    if (useMasterAESKey && this.encryptedMasterAESKey) {
      aesKey = await this.getDecryptedMasterAESKey();
    } else if (encryptedAESKey) {
      // Standard RSA-AES decryption
      let privateKey: CryptoKey;
      try {
        privateKey = await this.importPrivateKey(this.privateKey, "decrypt");
      }
      catch (error) {
        throw new Error(`Failed to import private key: ${error}`);
      }

      // Decrypt the AES key with RSA
      let aesKeyData: any = "";
      try {
        aesKeyData = await getCrypto().subtle.decrypt(
          {
            name: "RSA-OAEP",
          } as RSAConfig,
          privateKey,
          new Uint8Array(encryptedAESKey)
        );
      }
      catch (error) {
        throw new CryptoOperationError(`Failed to decrypt AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
          'decrypt',
          error instanceof Error ? error : undefined
        );
      }

      // Import the AES key
      try {
        aesKey = await getCrypto().subtle.importKey(
          "raw",
          aesKeyData,
          "AES-GCM",
          true,
          ["decrypt"]
        );
      }
      catch (error) {
        throw new KeyImportError(`Failed to import AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
          'private',
          error instanceof Error ? error : undefined
        );
      }
    } else {
      throw new Error("No AES key available for decryption - either provide encryptedAESKey or use master AES key");
    }

    // Decrypt the message with AES
    let decryptedMessage: any = "";
    try {
      decryptedMessage = await getCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        } as AESConfig,
        aesKey,
        new Uint8Array(encryptedMessage)
      );
    }
    catch (error) {
      throw new CryptoOperationError(`Failed to decrypt message: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }

    try {
      const decoder = getTextDecoder();
      const message = decoder.decode(decryptedMessage);

      const verified = await this.verifySignature(signature, message, sender);

      if (!verified) {
        throw new Error("Signature verification failed");
      }

      return message;    }
    catch (error) {
      throw new CryptoOperationError(`Failed to verify signature: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'verify',
        error instanceof Error ? error : undefined
      );
    }
  };

  /**
   * Decrypts an encrypted message and returns verification status (does not throw on signature verification failure).
   * @param encryptedData - Object containing the encrypted message components
   * @param sender - The ID of the user who sent the message
   * @param useMasterAESKey - If true, use the master AES key (if set)
   * @returns {Promise<IDecryptionResult>} Object containing the decrypted message and verification status
   */
  public async decryptMessageUnsafe(encryptedData: IRSAEncryptedMessage, sender: string, useMasterAESKey: boolean = false): Promise<IDecryptionResult> {
    const { iv, encryptedMessage, encryptedAESKey, signature } = encryptedData;
    let aesKey: CryptoKey;

    if (useMasterAESKey && this.encryptedMasterAESKey) {
      aesKey = await this.getDecryptedMasterAESKey();
    } else if (encryptedAESKey) {
      // Standard RSA-AES decryption
      let privateKey: CryptoKey;
      try {
        privateKey = await this.importPrivateKey(this.privateKey, "decrypt");
      }
      catch (error) {
        throw new Error(`Failed to import private key: ${error}`);
      }

      // Decrypt the AES key with RSA
      let aesKeyData: any = "";
      try {
        aesKeyData = await getCrypto().subtle.decrypt(
          {
            name: "RSA-OAEP",
          } as RSAConfig,
          privateKey,
          new Uint8Array(encryptedAESKey)
        );
      }
      catch (error) {
        throw new CryptoOperationError(`Failed to decrypt AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
          'decrypt',
          error instanceof Error ? error : undefined
        );
      }

      // Import the AES key
      try {
        aesKey = await getCrypto().subtle.importKey(
          "raw",
          aesKeyData,
          "AES-GCM",
          true,
          ["decrypt"]
        );
      }
      catch (error) {
        throw new KeyImportError(`Failed to import AES key: ${error instanceof Error ? error.message : 'Unknown error'}`,
          'private',
          error instanceof Error ? error : undefined
        );
      }
    } else {
      throw new Error("No AES key available for decryption - either provide encryptedAESKey or use master AES key");
    }

    // Decrypt the message with AES
    let decryptedMessage: any = "";
    try {
      decryptedMessage = await getCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        } as AESConfig,
        aesKey,
        new Uint8Array(encryptedMessage)
      );
    }
    catch (error) {
      throw new CryptoOperationError(`Failed to decrypt message: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }

    const decoder = getTextDecoder();
    const message = decoder.decode(decryptedMessage);

    // Attempt signature verification but don't throw on failure
    let verified = false;
    try {
      verified = await this.verifySignature(signature, message, sender);
    } catch (error) {
      // Signature verification failed, but we still return the message
      verified = false;
    }

    return { message, verified };
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
      const privateKey = await this.importPrivateKey(this.signKey, "sign");
      return await getCrypto().subtle.sign(
        {
          name: "RSA-PSS",
          saltLength: 32,
        } as RSAConfig,
        privateKey,
        data
      );
    }
    catch (error) {
      throw new CryptoOperationError(`Failed to sign message: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'sign',
        error instanceof Error ? error : undefined
      );
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
    
      const verified: boolean = await getCrypto().subtle.verify(
        {
          name: "RSA-PSS",
          saltLength: 32,
        } as RSAConfig,
        publicKey,
        new Uint8Array(signature),
        data
      );

      return verified;
    }
    catch (error) {
      throw new CryptoOperationError(`Failed to verify signature: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'verify',
        error instanceof Error ? error : undefined
      );
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
    return encode(JSON.stringify({
      iv: String.fromCharCode(...message.iv),
      encryptedMessage: bufferToBase64(message.encryptedMessage),
      encryptedAESKey: bufferToBase64(message.encryptedAESKey),
      signature: bufferToBase64(message.signature)
    }));
  }
  
  /**
   * Imports an encoded string back into an encrypted message object
   * @param encoded - The encoded string to import
   * @returns The decoded IRSAEncryptedMessage object
   */
  public importEncryptedMessage(encoded: string): IRSAEncryptedMessage {
    const decoded = JSON.parse(decode(encoded));
    return {
      iv: new Uint8Array([...decoded.iv].map(c => c.charCodeAt(0))),
      encryptedMessage: base64ToBuffer(decoded.encryptedMessage),
      encryptedAESKey: base64ToBuffer(decoded.encryptedAESKey),
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
      const keyPair: ECDHKeyPair = await getCrypto().subtle.generateKey(
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        true,
        ["deriveBits", "deriveKey"]
      );

      this.ecdhPrivateKey = keyPair.privateKey;
      
      const publicKeyRaw = await getCrypto().subtle.exportKey("jwk", keyPair.publicKey);
      return { publicKey: encode(JSON.stringify(publicKeyRaw)) };
    } catch (error) {
      throw new CryptoOperationError(`Failed to generate ECDH key pair: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'encrypt',
        error instanceof Error ? error : undefined
      );
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
      const publicKeyData = JSON.parse(decode(publicKey));
      const cryptoKey = await getCrypto().subtle.importKey(
        "jwk",
        publicKeyData,
        {
          name: "ECDH",
          namedCurve: "P-256",
        },
        false,
        []
      );
      
      this.ecdhPublicKeys.set(userId, cryptoKey);
    } catch (error) {
      throw new KeyImportError(`Failed to import ECDH public key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'public',
        error instanceof Error ? error : undefined
      );
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
        {
          name: "AES-GCM",
          length: 256,
        },
        false,
        ["encrypt", "decrypt"]
      );

      this.sharedKeys.set(userId, derivedKey);
      return keySalt;
    } catch (error) {
      throw new CryptoOperationError(`Failed to derive shared key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'encrypt',
        error instanceof Error ? error : undefined
      );
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
    const sharedKey = this.sharedKeys.get(userId);
    if (!sharedKey) {
      throw new Error(`Shared key not found for user: ${userId}. Call deriveSharedKey() first.`);
    }

    try {
      const encoder = getTextEncoder();
      const data = encoder.encode(message);
      
      const iv = getCrypto().getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
      const salt = getCrypto().getRandomValues(new Uint8Array(16)); // Salt for this encryption
      
      const encryptedMessage = await getCrypto().subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
        } as AESConfig,
        sharedKey,
        data
      );

      return {
        salt,
        encryptedMessage,
        iv,
      };
    } catch (error) {
      throw new CryptoOperationError(`Failed to encrypt with shared key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'encrypt',
        error instanceof Error ? error : undefined
      );
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
    const sharedKey = this.sharedKeys.get(userId);
    if (!sharedKey) {
      throw new Error(`Shared key not found for user: ${userId}. Call deriveSharedKey() first.`);
    }

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

      const decoder = getTextDecoder();
      return decoder.decode(decryptedMessage);
    } catch (error) {
      throw new CryptoOperationError(`Failed to decrypt with shared key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Exports shared key encrypted message data to a string format
   * @param data - The shared key encrypted data object to export
   * @returns An encoded string representation of the encrypted data
   */
  public exportSharedKeyData(data: SharedKeyData): string {
    return encode(JSON.stringify({
      salt: String.fromCharCode(...data.salt),
      encryptedMessage: bufferToBase64(data.encryptedMessage),
      iv: String.fromCharCode(...data.iv)
    }));
  }

  /**
   * Imports an encoded string back into a shared key data object
   * @param encoded - The encoded string to import
   * @returns The decoded SharedKeyData object
   */
  public importSharedKeyData(encoded: string): SharedKeyData {
    const decoded = JSON.parse(decode(encoded));
    return {
      salt: new Uint8Array([...decoded.salt].map(c => c.charCodeAt(0))),
      encryptedMessage: base64ToBuffer(decoded.encryptedMessage),
      iv: new Uint8Array([...decoded.iv].map(c => c.charCodeAt(0)))
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
    const sharedKey = this.sharedKeys.get(userId);
    if (!sharedKey) {
      throw new Error(`Shared key not found for user: ${userId}. Call deriveSharedKey() first.`);
    }

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

      const decoder = getTextDecoder();
      const message = decoder.decode(decryptedMessage);
      
      // SharedKeyData doesn't include signatures, so verification is always true
      return { message, verified: true };
    } catch (error) {
      throw new CryptoOperationError(`Failed to decrypt with shared key: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'decrypt',
        error instanceof Error ? error : undefined
      );
    }
  }
}

export default RSAMessage;