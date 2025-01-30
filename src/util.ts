import { encode, decode, byteEncode } from "base64util";

export const getCrypto = () => {
  if (typeof window !== 'undefined') {
    return window.crypto;
  }
  return require('crypto').webcrypto;
};

export const getTextEncoder = () => {
  if (typeof window !== 'undefined') {
    return new window.TextEncoder();
  }
  return new (require('util').TextEncoder)();
};

export const getTextDecoder = () => {
  if (typeof window !== 'undefined') {
    return new window.TextDecoder();
  }
  return new (require('util').TextDecoder)();
};

export const bufferToBase64 = (buffer: ArrayBuffer): string => {
  const byteView = new Uint8Array(buffer);
  let str = "";
  for (const charCode of byteView) {
    str += String.fromCharCode(charCode);
  }
  
  return byteEncode(str);
}

export const base64ToBuffer = (base64String: string): ArrayBuffer => {
  const str = decode(base64String);
  const buffer = new ArrayBuffer(str.length);
  const byteView = new Uint8Array(buffer);
  for (let i = 0; i < str.length; i++) {
    byteView[i] = str.charCodeAt(i);
  }
  return buffer;
}