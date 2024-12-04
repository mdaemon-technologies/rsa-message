import { encode, decode, byteEncode } from "base64util";

const getCrypto = () => {
  if (typeof window !== 'undefined') {
    return window.crypto;
  }
  return require('crypto').webcrypto;
};

const getTextEncoder = () => {
  if (typeof window !== 'undefined') {
    return new window.TextEncoder();
  }
  return new (require('util').TextEncoder)();
};

const getTextDecoder = () => {
  if (typeof window !== 'undefined') {
    return new window.TextDecoder();
  }
  return new (require('util').TextDecoder)();
};

function bufferToBase64(buffer: ArrayBuffer): string {
  const byteView = new Uint8Array(buffer);
  let str = "";
  for (const charCode of byteView) {
    str += String.fromCharCode(charCode);
  }
  
  return byteEncode(str);
}

function base64ToBuffer(base64String: string): ArrayBuffer {
  const str = decode(base64String);
  const buffer = new ArrayBuffer(str.length);
  const byteView = new Uint8Array(buffer);
  for (let i = 0; i < str.length; i++) {
    byteView[i] = str.charCodeAt(i);
  }
  return buffer;
}

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

  public async init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string) {
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

  private genKeyPair = async (type: "decrypt" | "sign" = "decrypt") => {
    const usage = type === "decrypt" ? ["encrypt", "decrypt"] : ["sign", "verify"];
    const keyPair = await getCrypto().subtle.generateKey(
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
    const options: {  [key: string]: any } = {
      name: type === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
      hash: "SHA-256",
    };
    if (type === "sign") {
      options.saltLength = 32;
    }
    
    try {
      const rsaPrivateKey = JSON.parse(decode(privateKey));
      const key: CryptoKey = await getCrypto().subtle.importKey(
        "jwk",
        rsaPrivateKey,
        options,
        false,
        [type]
      );

      return key;
    } catch (error) {
      throw new Error(`Failed to import private key: ${error}`);
    }
  };

  private importPublicKey = async (publicKey: string, type: "encrypt" | "verify"): Promise<CryptoKey> => {
    const options: { [key: string]: any } = {
      name: "encrypt" === type ? "RSA-OAEP" : "RSA-PSS",
      hash: "SHA-256",
    };

    if (type === "verify") {
      options.saltLength = 32;
    }

    try {
      const rsaPublicKey = JSON.parse(decode(publicKey));
      const key: CryptoKey = await getCrypto().subtle.importKey(
        "jwk",
        rsaPublicKey,
        options,
        false,
        [type]
      );

      return key;
    } catch (error) {
      throw new Error(`Failed to import public key: ${error}`);
    }
  };

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
      },
      aesKey,
      data
    );
  
    // Export and encrypt the AES key with RSA
    const aesKeyData = await getCrypto().subtle.exportKey("raw", aesKey);
    const encryptedAESKey = await getCrypto().subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
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
  }

  public decryptMessage = async (encryptedData: IRSAEncryptedMessage, sender: string) => {
    const { iv, encryptedMessage, encryptedAESKey, signature } = encryptedData;
    let privateKey: any = "";

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
        },
        privateKey,
        new Uint8Array(encryptedAESKey)
      );
    }
    catch (error) {
      throw new Error(`Failed to decrypt AES key: ${error}`);
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
      throw new Error(`Failed to import AES key: ${error}`);
    }

    // Decrypt the message with AES
    let decryptedMessage: any = "";
    try {
      decryptedMessage = await getCrypto().subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
        },
        aesKey,
        new Uint8Array(encryptedMessage)
      );
    }
    catch (error) {
      throw new Error(`Failed to decrypt message: ${error}`);
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
      throw new Error(`Failed to verify signature: ${error}`);
    }
  };

  public signMessage = async (message: string): Promise<ArrayBuffer> => {
    const encoder = getTextEncoder();
    const data = encoder.encode(message);
    
    try {
      const privateKey = await this.importPrivateKey(this.signKey, "sign");
      const signature: ArrayBuffer = await getCrypto().subtle.sign(
        {
          name: "RSA-PSS",
          saltLength: 32,
        },
        privateKey,
        data
      );

      return signature;
    }
    catch (error) {
      throw new Error(`Failed to sign message: ${error}`);
    }
  };

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
        },
        publicKey,
        new Uint8Array(signature),
        data
      );

      return verified;
    }
    catch (error) {
      throw new Error(`Failed to verify signature: ${error}`);
    }
  }

  public setPublicKey(userId: string, publicKey: string, verifyKey?: string) { //backwards compatible
    if (!userId || !publicKey) {
      throw new Error("Invalid arguments");
    }
    this.publicKeys.set(userId, publicKey);
    if (verifyKey) {
      this.verifyKeys.set(userId, verifyKey);
    }
  }

  public setVerifyKey(userId: string, verifyKey: string) {
    if (!userId || !verifyKey) {
      throw new Error("Invalid arguments");
    }
    this.verifyKeys.set(userId, verifyKey);
  }

  public hasPublicKey(userId: string): boolean {
    return this.publicKeys.has(userId);
  }

  public hasVerifyKey(userId: string): boolean {
    return this.verifyKeys.has(userId);
  }

  public exportEncryptedMessage(message: IRSAEncryptedMessage): string {
    return encode(JSON.stringify({
      iv: String.fromCharCode(...message.iv),
      encryptedMessage: bufferToBase64(message.encryptedMessage),
      encryptedAESKey: bufferToBase64(message.encryptedAESKey),
      signature: bufferToBase64(message.signature)
    }));
  }
  
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