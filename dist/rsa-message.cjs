'use strict';

/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
};

var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

/*globals atob, Buffer*/

// Modern browsers have atob and btoa defined
const atobBrowser = typeof atob == 'function' && atob;

// Node.js
function atobNode(data) { return Buffer.from(data, 'base64').toString('binary'); }

// Out custom implementation (polyfill)
var b64i;
const wsReg = /[\t\n\r\x20\x0C]+/g;
const chr = String.fromCharCode;
// if ( typeof chr.bind == 'function' ) chr = chr.bind(String);

/**
 * Decodes UTF8 or byte string
 *
 * @param {String} data
 */
function atobJS(data) {
    if (!data) return data;
    data = String(data).replace(wsReg, '');

    var o1, o2, o3, h1, h2, h3, h4, bits
    ,   l = data.length
    ,   i = 0
    ,   ac = 0
    ,   dec = ''
    ,   tmp_arr = []
    ;
    if(b64i == undefined) {
        b64i = {};
        for(var j = 0, bl = b64.length; j < bl; j++) b64i[b64.charAt(j)] = j;
    }

    do {
        // unpack four hexets into three octets using index points in b64
        h1 = b64i[data.charAt(i++)];
        h2 = b64i[data.charAt(i++)];
        h3 = b64i[data.charAt(i++)];
        h4 = b64i[data.charAt(i++)];

        bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

        o1 = bits >> 16 & 0xff;
        o2 = bits >> 8 & 0xff;
        o3 = bits & 0xff;

        if (h3 == 64) {
            tmp_arr[ac++] = chr(o1);
        }
        else if (h4 == 64) {
            tmp_arr[ac++] = chr(o1, o2);
        }
        else {
            tmp_arr[ac++] = chr(o1, o2, o3);
        }
    } while (i < l);

    dec = tmp_arr.join('');

    return dec.replace(/\0+$/, '');
}

const _atob = atobBrowser || typeof Buffer == 'function' && atobNode || atobJS;

/*globals btoa, Buffer*/

// Modern browsers have atob and btoa defined
const btoaBrowser = typeof btoa == 'function' && btoa;

// Node.js
function btoaNode(data) { return Buffer.from(data, 'binary').toString('base64'); }

// Out custom implementation (polyfill)

/**
 * Encodes UTF8 or byte string
 *
 * @param {String} data
 */
function btoaJS(data) {
    if (!data) return data;

    var o1, o2, o3, h1, h2, h3, h4, bits
    ,   i = 0
    ,   ac = 0
    ,   enc = ''
    ,   tmp_arr = []
    ;
    do {
        // pack three octets into four hexets
        o1 = data.charCodeAt(i++);
        o2 = data.charCodeAt(i++);
        o3 = data.charCodeAt(i++);

        bits = o1 << 16 | o2 << 8 | o3;

        h1 = bits >> 18 & 0x3f;
        h2 = bits >> 12 & 0x3f;
        h3 = bits >> 6 & 0x3f;
        h4 = bits & 0x3f;

        // use hexets to index into b64, and append result to encoded string
        tmp_arr[ac++] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
    } while (i < data.length);

    enc = tmp_arr.join('');

    var r = data.length % 3;

    return (r ? enc.slice(0, r - 3) : enc) + '==='.slice(r || 3);
}

const _btoa = btoaBrowser || typeof Buffer == 'function' && btoaNode || btoaJS;

/*globals unescape, escape, decodeURIComponent, encodeURI*/

/// Encode multi-byte into UTF-8 string
function utf8Encode(str) { return unescape( encodeURI( str ) ); }

/// Decode UTF-8 string to multi-byte string
function utf8Decode(str) { return decodeURIComponent( escape( str ) ); }

/**
*  Base64 string encoding and decoding utility.
*
*  play @ https://duzun.me/playground/encode#base64Encode=Test%20String%20
*
*  original of _btoa and _atob by: Tyler Akins (http://rumkin.com)
*
*
*  @license MIT
*  @version 2.2.0
*  @author Dumitru Uzun (DUzun.Me)
*/


// Decodes byte-string - 8bit per char - either btoa()'s return or byteUrlEncode()'s return
function byteDecode(data) {
    let ret = data;
    if(ret) {
        ret = _atob(String(ret)
            .replace(/_/g, '/')
            .replace(/-/g, '+'))
        ;
    }
    return ret;
}

// Encodes multi-byte string as utf8 (common in JS)
function mbEncode(data) {
    if(!data) return data;
    return _btoa(utf8Encode(data));
}

// Decodes to multi-byte string if utf8-encoded
function mbDecode(data, force_utf8) {
    let ret = byteDecode(data);
    if(ret) {
        if(force_utf8) {
            return utf8Decode(ret);
        }
        else {
            try {
                ret = utf8Decode(ret);
            } catch(err) {}
        }
    }
    return ret;
}

// Add String.prototype methods:
// bindProto(String.prototype);

const getCrypto = () => {
    if (typeof window !== 'undefined') {
        return window.crypto;
    }
    return require('crypto').webcrypto;
};
const getTextEncoder = () => {
    if (typeof window !== 'undefined') {
        return new window.TextEncoder();
    }
    return new (require('util').TextEncoder)();
};
const getTextDecoder = () => {
    if (typeof window !== 'undefined') {
        return new window.TextDecoder();
    }
    return new (require('util').TextDecoder)();
};
function bufferToBase64(buffer) {
    const byteView = new Uint8Array(buffer);
    let str = "";
    for (const charCode of byteView) {
        str += String.fromCharCode(charCode);
    }
    return _btoa(str);
}
function base64ToBuffer(base64String) {
    const str = mbDecode(base64String);
    const buffer = new ArrayBuffer(str.length);
    const byteView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
        byteView[i] = str.charCodeAt(i);
    }
    return buffer;
}
class RSAMessage {
    constructor() {
        this.publicKeys = new Map();
        this.genKeyPair = (...args_1) => __awaiter(this, [...args_1], void 0, function* (type = "decrypt") {
            const usage = type === "decrypt" ? ["encrypt", "decrypt"] : ["sign", "verify"];
            const keyPair = yield getCrypto().subtle.generateKey({
                name: type === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            }, true, usage);
            const publicKeyRaw = yield getCrypto().subtle.exportKey("jwk", keyPair.publicKey);
            const privateKeyRaw = yield getCrypto().subtle.exportKey("jwk", keyPair.privateKey);
            return { publicKey: mbEncode(JSON.stringify(publicKeyRaw)), privateKey: mbEncode(JSON.stringify(privateKeyRaw)) };
        });
        this.importPrivateKey = (privateKey, type) => __awaiter(this, void 0, void 0, function* () {
            const options = {
                name: type === "decrypt" ? "RSA-OAEP" : "RSA-PSS",
                hash: "SHA-256",
            };
            if (type === "sign") {
                options.saltLength = 32;
            }
            try {
                const rsaPrivateKey = JSON.parse(mbDecode(privateKey));
                const key = yield getCrypto().subtle.importKey("jwk", rsaPrivateKey, options, false, [type]);
                return key;
            }
            catch (error) {
                throw new Error(`Failed to import private key: ${error}`);
            }
        });
        this.importPublicKey = (publicKey, type) => __awaiter(this, void 0, void 0, function* () {
            const options = {
                name: "encrypt" === type ? "RSA-OAEP" : "RSA-PSS",
                hash: "SHA-256",
            };
            if (type === "verify") {
                options.saltLength = 32;
            }
            try {
                const rsaPublicKey = JSON.parse(mbDecode(publicKey));
                const key = yield getCrypto().subtle.importKey("jwk", rsaPublicKey, options, false, [type]);
                return key;
            }
            catch (error) {
                throw new Error(`Failed to import public key: ${error}`);
            }
        });
        this.encryptMessage = (message, userId) => __awaiter(this, void 0, void 0, function* () {
            const publicKeyRaw = this.publicKeys.get(userId);
            if (!publicKeyRaw) {
                throw new Error("Public key not found for user");
            }
            const publicKey = yield this.importPublicKey(publicKeyRaw.encrypt, "encrypt");
            const encoder = getTextEncoder();
            const data = encoder.encode(message);
            // Encrypt the message with AES
            const aesKey = yield this.generateAESKey();
            const iv = getCrypto().getRandomValues(new Uint8Array(12)); // 12-byte IV for AES-GCM
            const encryptedMessage = yield getCrypto().subtle.encrypt({
                name: "AES-GCM",
                iv,
            }, aesKey, data);
            // Export and encrypt the AES key with RSA
            const aesKeyData = yield getCrypto().subtle.exportKey("raw", aesKey);
            const encryptedAESKey = yield getCrypto().subtle.encrypt({
                name: "RSA-OAEP",
            }, publicKey, aesKeyData);
            const signature = yield this.signMessage(message);
            return {
                iv,
                encryptedMessage,
                encryptedAESKey,
                signature,
            };
        });
        this.decryptMessage = (encryptedData, sender) => __awaiter(this, void 0, void 0, function* () {
            const { iv, encryptedMessage, encryptedAESKey, signature } = encryptedData;
            let privateKey = "";
            try {
                privateKey = yield this.importPrivateKey(this.privateKey, "decrypt");
            }
            catch (error) {
                throw new Error(`Failed to import private key: ${error}`);
            }
            // Decrypt the AES key with RSA
            let aesKeyData = "";
            try {
                aesKeyData = yield getCrypto().subtle.decrypt({
                    name: "RSA-OAEP",
                }, privateKey, new Uint8Array(encryptedAESKey));
            }
            catch (error) {
                throw new Error(`Failed to decrypt AES key: ${error}`);
            }
            // Import the AES key
            let aesKey = "";
            try {
                aesKey = yield getCrypto().subtle.importKey("raw", aesKeyData, "AES-GCM", true, ["decrypt"]);
            }
            catch (error) {
                throw new Error(`Failed to import AES key: ${error}`);
            }
            // Decrypt the message with AES
            let decryptedMessage = "";
            try {
                decryptedMessage = yield getCrypto().subtle.decrypt({
                    name: "AES-GCM",
                    iv,
                }, aesKey, new Uint8Array(encryptedMessage));
            }
            catch (error) {
                throw new Error(`Failed to decrypt message: ${error}`);
            }
            try {
                const decoder = getTextDecoder();
                const message = decoder.decode(decryptedMessage);
                const verified = yield this.verifySignature(signature, message, sender);
                if (!verified) {
                    throw new Error("Signature verification failed");
                }
                return message;
            }
            catch (error) {
                throw new Error(`Failed to verify signature: ${error}`);
            }
        });
        this.signMessage = (message) => __awaiter(this, void 0, void 0, function* () {
            const encoder = getTextEncoder();
            const data = encoder.encode(message);
            try {
                const privateKey = yield this.importPrivateKey(this.signKey, "sign");
                const signature = yield getCrypto().subtle.sign({
                    name: "RSA-PSS",
                    saltLength: 32,
                }, privateKey, data);
                return signature;
            }
            catch (error) {
                throw new Error(`Failed to sign message: ${error}`);
            }
        });
        this.verifySignature = (signature, message, userId) => __awaiter(this, void 0, void 0, function* () {
            const publicKeyRaw = this.publicKeys.get(userId);
            if (!publicKeyRaw) {
                throw new Error("Public key not found for user");
            }
            try {
                const publicKey = yield this.importPublicKey(publicKeyRaw.verify, "verify");
                const encoder = getTextEncoder();
                const data = encoder.encode(message);
                const verified = yield getCrypto().subtle.verify({
                    name: "RSA-PSS",
                    saltLength: 32,
                }, publicKey, new Uint8Array(signature), data);
                return verified;
            }
            catch (error) {
                throw new Error(`Failed to verify signature: ${error}`);
            }
        });
        this.privateKey = "";
        this.publicKey = "";
        this.verifyKey = "";
        this.signKey = "";
    }
    get publickey() {
        return this.publicKey;
    }
    get verifykey() {
        return this.verifyKey;
    }
    get privatekey() {
        return this.privateKey;
    }
    get signkey() {
        return this.signKey;
    }
    generateAESKey() {
        return __awaiter(this, void 0, void 0, function* () {
            return yield getCrypto().subtle.generateKey({
                name: "AES-GCM",
                length: 256,
            }, true, ["encrypt", "decrypt"]);
        });
    }
    init(publicKey, privateKey, verifyKey, signKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (publicKey && privateKey && verifyKey && signKey) {
                this.publicKey = publicKey;
                this.privateKey = privateKey;
                this.verifyKey = verifyKey;
                this.signKey = signKey;
                return { publicKey: this.publicKey, verifyKey: this.verifyKey };
            }
            const encryptionKeys = yield this.genKeyPair();
            const signatureKeys = yield this.genKeyPair("sign");
            this.publicKey = encryptionKeys.publicKey;
            this.privateKey = encryptionKeys.privateKey;
            this.verifyKey = signatureKeys.publicKey;
            this.signKey = signatureKeys.privateKey;
            return { publicKey: encryptionKeys.publicKey, verifyKey: signatureKeys.publicKey };
        });
    }
    setPublicKey(userId, publicKey, verifyKey) {
        if (!userId || !publicKey || !verifyKey) {
            throw new Error("Invalid arguments");
        }
        this.publicKeys.set(userId, { encrypt: publicKey, verify: verifyKey });
    }
    hasPublicKey(userId) {
        return this.publicKeys.has(userId);
    }
    exportEncryptedMessage(message) {
        return mbEncode(JSON.stringify({
            iv: String.fromCharCode(...message.iv),
            encryptedMessage: bufferToBase64(message.encryptedMessage),
            encryptedAESKey: bufferToBase64(message.encryptedAESKey),
            signature: bufferToBase64(message.signature)
        }));
    }
    importEncryptedMessage(encoded) {
        const decoded = JSON.parse(mbDecode(encoded));
        return {
            iv: new Uint8Array([...decoded.iv].map(c => c.charCodeAt(0))),
            encryptedMessage: base64ToBuffer(decoded.encryptedMessage),
            encryptedAESKey: base64ToBuffer(decoded.encryptedAESKey),
            signature: base64ToBuffer(decoded.signature)
        };
    }
}

module.exports = RSAMessage;
