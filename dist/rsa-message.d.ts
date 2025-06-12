interface IRSAEncryptedMessage {
    iv: Uint8Array;
    encryptedMessage: ArrayBuffer;
    encryptedAESKey?: ArrayBuffer;
    signature: ArrayBuffer;
}

interface ECDHPublicKey {
    publicKey: string;
}

interface SharedKeyData {
    salt: Uint8Array;
    encryptedMessage: ArrayBuffer;
    iv: Uint8Array;
}

export { IRSAEncryptedMessage, ECDHPublicKey, SharedKeyData };
export default class RSAMessage {
    constructor();
    get publickey(): string;
    get verifykey(): string;
    get privatekey(): string;
    get signkey(): string;
    init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string): Promise<{ publicKey: string; verifyKey: string }>;
    setPublicKey(userId: string, publicKey: string, verifyKey?: string): void;
    setVerifyKey(userId: string, verifyKey: string): void;
    hasPublicKey(userId: string): boolean;
    hasVerifyKey(userId: string): boolean;
    signMessage(message: string): Promise<ArrayBuffer>;
    encryptMessage(message: string, userId: string, useMasterKey?: boolean): Promise<IRSAEncryptedMessage>;
    verifySignature(signature: ArrayBuffer, message: string, userId: string): Promise<boolean>;
    decryptMessage(encryptedData: IRSAEncryptedMessage, userId: string, useMasterKey?: boolean): Promise<string>;
    exportEncryptedMessage(message: IRSAEncryptedMessage): string;
    importEncryptedMessage(encoded: string): IRSAEncryptedMessage;
    
    // Master AES Key Methods
    generateAndSetMasterAESKey(): Promise<string>;
    setEncryptedMasterAESKey(encryptedKey: string): void;
    getDecryptedMasterAESKey(): Promise<CryptoKey>;
    exportMasterAESKeyForUser(userId: string): Promise<string>;
    setMasterAESKeyFromEncrypted(encryptedKey: string, encryptor?: string): Promise<void>;
    encryptWithMasterAESKey(message: string): Promise<IRSAEncryptedMessage>;
    decryptWithMasterAESKey(encryptedData: IRSAEncryptedMessage, sender: string): Promise<string>;
    
    // ECDH Key Exchange Methods
    generateECDHKeyPair(): Promise<ECDHPublicKey>;
    setECDHPublicKey(userId: string, publicKey: string): Promise<void>;
    deriveSharedKey(userId: string, salt?: Uint8Array): Promise<Uint8Array>;
    encryptWithSharedKey(message: string, userId: string): Promise<SharedKeyData>;
    decryptWithSharedKey(encryptedData: SharedKeyData, userId: string): Promise<string>;
    exportSharedKeyData(data: SharedKeyData): string;
    importSharedKeyData(encoded: string): SharedKeyData;
    hasSharedKey(userId: string): boolean;
    hasECDHPublicKey(userId: string): boolean;
    removeSharedKey(userId: string): void;
    removeECDHPublicKey(userId: string): void;
}