import { CryptoKeyOptions, RSAConfig } from "./crypto-types";
export type RSAKeyPurpose = "decrypt" | "sign";
export type RSAKeyUsage = "encrypt" | "decrypt" | "sign" | "verify";
export declare const RSA_OAEP: RSAConfig;
export declare const RSA_PSS: RSAConfig;
export declare const AES_GCM_256: {
    readonly name: "AES-GCM";
    readonly length: 256;
};
export declare const AES_GCM_IV_BYTES = 12;
export declare const ECDH_P256: {
    readonly name: "ECDH";
    readonly namedCurve: "P-256";
};
export declare const rsaKeyGenParams: (purpose: RSAKeyPurpose) => RsaHashedKeyGenParams;
export declare const rsaKeyUsages: (purpose: RSAKeyPurpose) => KeyUsage[];
export declare const rsaImportParams: (usage: RSAKeyUsage) => CryptoKeyOptions;
