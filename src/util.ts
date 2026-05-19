import { encode, decode, byteEncode } from "base64util";

export const getCrypto = () => {
  return globalThis.crypto;
};

export const getTextEncoder = () => {
  return new TextEncoder();
};

export const getTextDecoder = () => {
  return new TextDecoder();
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