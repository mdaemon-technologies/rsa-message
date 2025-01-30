export class CryptoOperationError extends Error {
  constructor(
    message: string,
    public readonly operation: 'encrypt' | 'decrypt' | 'sign' | 'verify',
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'CryptoOperationError';
  }
}

export class KeyImportError extends Error {
  constructor(
    message: string,
    public readonly keyType: 'public' | 'private',
    public readonly originalError?: Error
  ) {
    super(message);
    this.name = 'KeyImportError';
  }
}