export interface CryptoKeyOptions {
  name: 'RSA-OAEP' | 'RSA-PSS' | 'AES-GCM' | 'ECDH' | 'PBKDF2';
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

export interface ECDHKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface ECDHPublicKey {
  publicKey: string;
}

export interface SharedKeyData {
  salt: Uint8Array;
  encryptedMessage: ArrayBuffer;
  iv: Uint8Array;
}

export interface DerivedKeyConfig {
  name: 'PBKDF2';
  salt: Uint8Array;
  iterations: number;
  hash: 'SHA-256';
}

export interface ECDHConfig {
  name: 'ECDH';
  public: CryptoKey;
}