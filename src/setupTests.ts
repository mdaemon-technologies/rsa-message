import { webcrypto  } from 'crypto';
import { TextEncoder, TextDecoder } from 'util';
Object.defineProperty(globalThis, 'crypto', {
  value: webcrypto,
});
globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;