import { CryptoKeyOptions, RSAConfig } from "./crypto-types";

// Algorithm parameters shared by every operation; changing any of them breaks compatibility
// with keys and messages made by earlier versions

export type RSAKeyPurpose = "decrypt" | "sign";
export type RSAKeyUsage = "encrypt" | "decrypt" | "sign" | "verify";

export const RSA_OAEP = { name: "RSA-OAEP" } as RSAConfig;
export const RSA_PSS = { name: "RSA-PSS", saltLength: 32 } as RSAConfig;

export const AES_GCM_256 = { name: "AES-GCM", length: 256 } as const;
export const AES_GCM_IV_BYTES = 12;

export const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" } as const;

export const rsaKeyGenParams = (purpose: RSAKeyPurpose): RsaHashedKeyGenParams => ({
  name: purpose === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
});

export const rsaKeyUsages = (purpose: RSAKeyPurpose): KeyUsage[] =>
  purpose === "decrypt" ? ["encrypt", "decrypt"] : ["sign", "verify"];

export const rsaImportParams = (usage: RSAKeyUsage): CryptoKeyOptions => {
  const options: CryptoKeyOptions = {
    name: usage === "encrypt" || usage === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
    hash: "SHA-256",
  };
  if (usage === "sign" || usage === "verify") {
    options.saltLength = 32;
  }
  return options;
};
