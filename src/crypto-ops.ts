import { getCrypto, encodeJson, decodeJson } from "./util";
import { AESConfig } from "./crypto-types";
import { cryptoOperationError, keyImportError } from "./error-types";
import {
  AES_GCM_IV_BYTES,
  RSAKeyPurpose,
  RSAKeyUsage,
  rsaKeyGenParams,
  rsaKeyUsages,
  rsaImportParams
} from "./crypto-params";

export const generateRSAKeyPair = async (purpose: RSAKeyPurpose, extractable: boolean): Promise<CryptoKeyPair> =>
  await getCrypto().subtle.generateKey(rsaKeyGenParams(purpose), extractable, rsaKeyUsages(purpose)) as CryptoKeyPair;

// Exports a key as a base64 encoded JWK, the string format keys are shared in
export const exportKeyString = async (key: CryptoKey): Promise<string> =>
  encodeJson(await getCrypto().subtle.exportKey("jwk", key));

// Imports a non-extractable RSA key from a base64 encoded JWK
export const importRSAKey = async (key: string, usage: RSAKeyUsage, keyType: "public" | "private"): Promise<CryptoKey> => {
  const options = rsaImportParams(usage);
  try {
    return await getCrypto().subtle.importKey("jwk", decodeJson(key), options, false, [usage]);
  } catch (error) {
    throw keyImportError(`Failed to import ${keyType} key`, keyType, error);
  }
};

// Encrypts with a new random IV; errors are left to the caller
export const aesGcmEncrypt = async (key: CryptoKey, data: Uint8Array) => {
  const iv = getCrypto().getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const encryptedMessage = await getCrypto().subtle.encrypt({ name: "AES-GCM", iv } as AESConfig, key, data as BufferSource);
  return { iv, encryptedMessage };
};

// Decrypts, reporting a failure as a "decrypt" CryptoOperationError that starts with `failure`
export const aesGcmDecrypt = async (key: CryptoKey, iv: Uint8Array, encryptedMessage: ArrayBuffer, failure: string): Promise<ArrayBuffer> => {
  try {
    return await getCrypto().subtle.decrypt({ name: "AES-GCM", iv } as AESConfig, key, new Uint8Array(encryptedMessage));
  } catch (error) {
    throw cryptoOperationError(failure, "decrypt", error);
  }
};
