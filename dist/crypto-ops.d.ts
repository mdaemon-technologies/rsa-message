import { RSAKeyPurpose, RSAKeyUsage } from "./crypto-params";
export declare const generateRSAKeyPair: (purpose: RSAKeyPurpose, extractable: boolean) => Promise<CryptoKeyPair>;
export declare const exportKeyString: (key: CryptoKey) => Promise<string>;
export declare const importRSAKey: (key: string, usage: RSAKeyUsage, keyType: "public" | "private") => Promise<CryptoKey>;
export declare const aesGcmEncrypt: (key: CryptoKey, data: Uint8Array) => Promise<{
    iv: Uint8Array<ArrayBuffer>;
    encryptedMessage: ArrayBuffer;
}>;
export declare const aesGcmDecrypt: (key: CryptoKey, iv: Uint8Array, encryptedMessage: ArrayBuffer, failure: string) => Promise<ArrayBuffer>;
