interface IRSAEncryptedMessage {
    iv: Uint8Array;
    encryptedMessage: ArrayBuffer;
    encryptedAESKey: ArrayBuffer;
    signature: ArrayBuffer;
}
export { IRSAEncryptedMessage };
export default class RSAMessage {
    constructor();
    get publickey(): string;
    get verifykey(): string;
    get privatekey(): string;
    get signkey(): string;
    init(publicKey?: string, privateKey?: string, verifyKey?: string, signKey?: string): Promise<{ publicKey: string; verifyKey: string }>;
    setPublicKey(userId: string, publicKey: string, verifyKey: string): void;
    hasPublicKey(userId: string): boolean;
    signMessage(message: string): Promise<ArrayBuffer>;
    encryptMessage(message: string, userId: string): Promise<IRSAEncryptedMessage>;
    verifySignature(signature: ArrayBuffer, message: string, userId: string): Promise<boolean>;
    decryptMessage(encryptedData: IRSAEncryptedMessage, userId: string): Promise<string>;
    exportEncryptedMessage(message: IRSAEncryptedMessage): string;
    importEncryptedMessage(encoded: string): IRSAEncryptedMessage;
}