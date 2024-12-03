interface IRSAEncryptedMessage {
    iv: Uint8Array;
    encryptedMessage: Uint8Array;
    encryptedAESKey: Uint8Array;
    signature: Uint8Array;
}
export { IRSAEncryptedMessage };
export default class RSAMessage {
    constructor();
    get publickey(): string;
    get privatekey(): string;
    init(publicKey?: string, privateKey?: string): Promise<string>;
    setPublicKey(userId: string, publicKey: string): void;
    hasPublicKey(userId: string): boolean;
    signMessage(message: string): Promise<ArrayBuffer>;
    encryptMessage(message: string, userId: string): Promise<IRSAEncryptedMessage>;
    verifySignature(signature: Uint8Array, message: string, userId: string): Promise<boolean>;
    decryptMessage(encryptedData: IRSAEncryptedMessage, userId: string): Promise<string>;
    exportEncryptedMessage(message: IRSAEncryptedMessage): string;
    importEncryptedMessage(encoded: string): IRSAEncryptedMessage;
}