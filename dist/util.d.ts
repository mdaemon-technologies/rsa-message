export declare const getCrypto: () => Crypto;
export declare const getTextEncoder: () => TextEncoder;
export declare const getTextDecoder: () => TextDecoder;
export declare const bufferToBase64: (buffer: ArrayBuffer) => string;
export declare const base64ToBuffer: (base64String: string) => ArrayBuffer;
export declare const shownDeprecations: Set<string>;
export declare const warnDeprecated: (code: string, message: string) => void;
