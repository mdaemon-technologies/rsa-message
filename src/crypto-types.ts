export interface CryptoKeyOptions {
  name: 'RSA-OAEP' | 'RSA-PSS' | 'AES-GCM';
  hash: 'SHA-256';
  saltLength?: number;
}

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface KeyPairOutput {
  publicKey: string;
  verifyKey: string;
}

export interface AESConfig {
  name: 'AES-GCM';
  iv: Uint8Array;
}

export interface RSAConfig {
  name: 'RSA-OAEP' | 'RSA-PSS';
  saltLength?: number;
}