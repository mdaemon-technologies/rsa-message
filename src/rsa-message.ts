// Add at top of file
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

export interface IRSAEncryptedMessage {
  iv: Uint8Array;
  encryptedMessage: Uint8Array;
  encryptedAESKey: Uint8Array;
  signature: Uint8Array;
}

class RSAMessage {
  private privateKey: string;
  private publicKey: string;
  private publicKeys: Map<string, string> = new Map();

  constructor() {
    this.privateKey = "";
    this.publicKey = "";
  }

  get publickey() {
    return btoa(this.publicKey);
  }

  get privatekey() {
    return btoa(this.privateKey);
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

  public async init(publicKey?: string, privateKey?: string) {
    if (publicKey && privateKey) {
      this.publicKey = atob(publicKey);
      this.privateKey = atob(privateKey);
      return publicKey;
    }
    publicKey = await this.genKeyPair();
    return btoa(publicKey);
  }

  private genKeyPair = async () => {
    const keyPair = await getCrypto().subtle.generateKey(
      {
       name: "RSA-OAEP",
       modulusLength: 2048,
       publicExponent: new Uint8Array([1, 0, 1]),
       hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    
    const publicKeyRaw = await getCrypto().subtle.exportKey("spki", keyPair.publicKey);
    const privateKeyRaw = await getCrypto().subtle.exportKey("pkcs8", keyPair.privateKey);
    this.publicKey = String.fromCharCode(...Array.from(new Uint8Array(publicKeyRaw)));
    this.privateKey = String.fromCharCode(...Array.from(new Uint8Array(privateKeyRaw)));
    
    return this.publicKey;
  };

  private importPrivateKey = async (privateKey: string, type: "sign" | "decrypt") => {
    return await getCrypto().subtle.importKey(
      "pkcs8",
      new Uint8Array([...privateKey].map(c => c.charCodeAt(0))),
      {
        name: type === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
        hash: "SHA-256",
      },
      true,
      [type]
    );
  };

  public signMessage = async (message: string) => {
    const encoder = getTextEncoder();
    const data = encoder.encode(message);
    
    const rsaPrivateKey = await this.importPrivateKey(this.privateKey, "sign");

    return await getCrypto().subtle.sign(
      {
      name: "RSA-PSS",
      saltLength: 32,
      },
      rsaPrivateKey,
      data
    );
  };

  private importPublicKey = async (publicKey: string, type: "encrypt" | "verify") => {
    return await getCrypto().subtle.importKey(
      "spki",
      new Uint8Array([...publicKey].map(c => c.charCodeAt(0))),
      {
        name: "encrypt" === type ? "RSA-OAEP" : "RSA-PSS",
        hash: "SHA-256",
      },
      true,
      [type]
    );
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

  public verifySignature = async (signature: Uint8Array, message: string, userId: string) => {
    const publicKeyRaw = this.publicKeys.get(userId);
    if (!publicKeyRaw) {
      throw new Error("Public key not found for user");
    }

    const publicKey = await this.importPublicKey(publicKeyRaw, "verify");

    const encoder = getTextEncoder();
    const data = encoder.encode(message);
  
    return await getCrypto().subtle.verify(
      {
      name: "RSA-PSS",
      saltLength: 32,
      },
      publicKey,
      signature,
      data
    );
  }

  public decryptMessage = async (encryptedData: IRSAEncryptedMessage, userId: string) => {
    const publicKey = this.publicKeys.get(userId);
    if (!publicKey) {
      throw new Error("Public key not found for user");
    }

    const { iv, encryptedMessage, encryptedAESKey, signature } = encryptedData;
  
    const privateKey = await this.importPrivateKey(this.privateKey, "decrypt");
    

   // Decrypt the AES key with RSA
   const aesKeyData = await getCrypto().subtle.decrypt(
    {
     name: "RSA-OAEP",
    },
    privateKey,
    encryptedAESKey
   );
  
   // Import the AES key
   const aesKey = await getCrypto().subtle.importKey(
    "raw",
    aesKeyData,
    "AES-GCM",
    true,
    ["decrypt"]
   );
  
   // Decrypt the message with AES
   const decryptedMessage = await getCrypto().subtle.decrypt(
    {
     name: "AES-GCM",
     iv,
    },
    aesKey,
    encryptedMessage
   );

   
   const decoder = getTextDecoder();
   const message = decoder.decode(decryptedMessage);
   
   const verified = await this.verifySignature(signature, message, userId);
   if (!verified) {
    throw new Error("Signature verification failed");
   }

   return message;
  };

  public setPublicKey(userId: string, publicKey: string) {
    publicKey = atob(publicKey);
    this.publicKeys.set(userId, publicKey);
  }

  public exportEncryptedMessage(message: IRSAEncryptedMessage): string {
    return btoa(JSON.stringify({
      iv: String.fromCharCode(...message.iv),
      encryptedMessage: String.fromCharCode(...new Uint8Array(message.encryptedMessage)),
      encryptedAESKey: String.fromCharCode(...new Uint8Array(message.encryptedAESKey)),
      signature: String.fromCharCode(...new Uint8Array(message.signature))
    }));
  }
  
  public importEncryptedMessage(encoded: string): IRSAEncryptedMessage {
    const decoded = JSON.parse(atob(encoded));
    return {
      iv: new Uint8Array([...decoded.iv].map(c => c.charCodeAt(0))),
      encryptedMessage: new Uint8Array([...decoded.encryptedMessage].map(c => c.charCodeAt(0))),
      encryptedAESKey: new Uint8Array([...decoded.encryptedAESKey].map(c => c.charCodeAt(0))),
      signature: new Uint8Array([...decoded.signature].map(c => c.charCodeAt(0)))
    };
  }
}

export default RSAMessage;