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
  AESConfig
} from "./crypto-types";
import { CryptoOperationError, KeyImportError } from "./error-types";

export interface IRSAEncryptedMessage {
  iv: Uint8Array;
  encryptedMessage: ArrayBuffer;
  encryptedAESKey: ArrayBuffer;
  signature: ArrayBuffer;
}

class RSAMessage {
  private privateKey: string;
  private publicKey: string;
  private verifyKey: string;
  private signKey: string;
  private publicKeys: Map<string, string> = new Map();
  private verifyKeys: Map<string, string> = new Map();

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

  private async generateAESKey() {
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
  public encryptMessage = async (message: string, userId: string) => {
    const publicKeyRaw = this.publicKeys.get(userId);
    if (!publicKeyRaw) {
      throw new Error("Public key not found for user");
    }
  
    const publicKey = await this.importPublicKey(publicKeyRaw, "encrypt");

    const encoder = getTextEncoder();
    const data = encoder.encode(message);
    
    // Encrypt the message with AES
    const aesKey = await this.generateAESKey();
    const iv = getCrypto().getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
    const encryptedMessage = await getCrypto().subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
      } as AESConfig,
      aesKey,
      data
    );
  
    // Export and encrypt the AES key with RSA
    const aesKeyData = await getCrypto().subtle.exportKey("raw", aesKey);
    const encryptedAESKey = await getCrypto().subtle.encrypt(
      {
        name: "RSA-OAEP",
      } as RSAConfig,
      publicKey,
      aesKeyData
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
   * Decrypts an encrypted message and verifies its signature
   * @param {IRSAEncryptedMessage} encryptedData - Object containing the encrypted message components:
   *  - iv: Initialization vector for AES-GCM
   *  - encryptedMessage: The AES encrypted message
   *  - encryptedAESKey: The RSA encrypted AES key
   *  - signature: Digital signature of the message
   * @param {string} sender - The ID of the user who sent the message
   * @returns {Promise<string>} The decrypted message
   * @throws {Error} If private key import fails
   * @throws {Error} If AES key decryption fails
   * @throws {Error} If AES key import fails
   * @throws {Error} If message decryption fails
   * @throws {Error} If signature verification fails
   */
  public decryptMessage = async (encryptedData: IRSAEncryptedMessage, sender: string) => {
    const { iv, encryptedMessage, encryptedAESKey, signature } = encryptedData;
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
    let aesKey: any = "";
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

      return message;
    }
    catch (error) {
      throw new CryptoOperationError(`Failed to verify signature: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'verify',
        error instanceof Error ? error : undefined
      );
    }
  };

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
  public setPublicKey(userId: string, publicKey: string, verifyKey?: string) { //backwards compatible
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
}

export default RSAMessage;