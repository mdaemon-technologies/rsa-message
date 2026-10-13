export declare class CryptoOperationError extends Error {
    readonly operation: 'encrypt' | 'decrypt' | 'sign' | 'verify';
    readonly originalError?: Error | undefined;
    constructor(message: string, operation: 'encrypt' | 'decrypt' | 'sign' | 'verify', originalError?: Error | undefined);
}
export declare class KeyImportError extends Error {
    readonly keyType: 'public' | 'private';
    readonly originalError?: Error | undefined;
    constructor(message: string, keyType: 'public' | 'private', originalError?: Error | undefined);
}
export declare const cryptoOperationError: (failure: string, operation: CryptoOperationError["operation"], error: unknown) => CryptoOperationError;
export declare const keyImportError: (failure: string, keyType: KeyImportError["keyType"], error: unknown) => KeyImportError;
