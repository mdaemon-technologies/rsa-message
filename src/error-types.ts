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

const describeError = (error: unknown): string => error instanceof Error ? error.message : 'Unknown error';

const asError = (error: unknown): Error | undefined => error instanceof Error ? error : undefined;

// Wraps a caught error as `${failure}: ${its message}`, keeping it as originalError
export const cryptoOperationError = (failure: string, operation: CryptoOperationError['operation'], error: unknown) =>
  new CryptoOperationError(`${failure}: ${describeError(error)}`, operation, asError(error));

export const keyImportError = (failure: string, keyType: KeyImportError['keyType'], error: unknown) =>
  new KeyImportError(`${failure}: ${describeError(error)}`, keyType, asError(error));
