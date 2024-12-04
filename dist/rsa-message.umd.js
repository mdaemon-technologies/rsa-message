!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?module.exports=t():"function"==typeof define&&define.amd?define(t):(e="undefined"!=typeof globalThis?globalThis:e||self).RSAMessage=t()}(this,(function(){"use strict";function e(e,t,r,i){return new(r||(r=Promise))((function(n,o){function y(e){try{c(i.next(e))}catch(e){o(e)}}function s(e){try{c(i.throw(e))}catch(e){o(e)}}function c(e){var t;e.done?n(e.value):(t=e.value,t instanceof r?t:new r((function(e){e(t)}))).then(y,s)}c((i=i.apply(e,t||[])).next())}))}"function"==typeof SuppressedError&&SuppressedError;var t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";const r="function"==typeof atob&&atob;var i;const n=/[\t\n\r\x20\x0C]+/g,o=String.fromCharCode;const y=r||"function"==typeof Buffer&&function(e){return Buffer.from(e,"base64").toString("binary")}||function(e){if(!e)return e;var r,y,s,c,a,u,d=(e=String(e).replace(n,"")).length,h=0,p=0,l=[];if(null==i){i={};for(var f=0;f<65;f++)i[t.charAt(f)]=f}do{r=(u=i[e.charAt(h++)]<<18|i[e.charAt(h++)]<<12|(c=i[e.charAt(h++)])<<6|(a=i[e.charAt(h++)]))>>16&255,y=u>>8&255,s=255&u,l[p++]=64==c?o(r):64==a?o(r,y):o(r,y,s)}while(h<d);return l.join("").replace(/\0+$/,"")};const s="function"==typeof btoa&&btoa||"function"==typeof Buffer&&function(e){return Buffer.from(e,"binary").toString("base64")}||function(e){if(!e)return e;var r,i,n,o,y,s=0,c=0,a="",u=[];do{r=(y=e.charCodeAt(s++)<<16|e.charCodeAt(s++)<<8|e.charCodeAt(s++))>>18&63,i=y>>12&63,n=y>>6&63,o=63&y,u[c++]=t.charAt(r)+t.charAt(i)+t.charAt(n)+t.charAt(o)}while(s<e.length);a=u.join("");var d=e.length%3;return(d?a.slice(0,d-3):a)+"===".slice(d||3)};function c(e){return decodeURIComponent(escape(e))}
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
    */function a(e){return e?s(unescape(encodeURI(e))):e}function u(e,t){let r=function(e){let t=e;return t&&(t=y(String(t).replace(/_/g,"/").replace(/-/g,"+"))),t}(e);if(r){if(t)return c(r);try{r=c(r)}catch(e){}}return r}const d=()=>"undefined"!=typeof window?window.crypto:require("crypto").webcrypto,h=()=>"undefined"!=typeof window?new window.TextEncoder:new(require("util").TextEncoder);function p(e){const t=new Uint8Array(e);let r="";for(const e of t)r+=String.fromCharCode(e);return s(r)}function l(e){const t=u(e),r=new ArrayBuffer(t.length),i=new Uint8Array(r);for(let e=0;e<t.length;e++)i[e]=t.charCodeAt(e);return r}return class{constructor(){this.publicKeys=new Map,this.verifyKeys=new Map,this.genKeyPair=(...t)=>e(this,[...t],void 0,(function*(e="decrypt"){const t="decrypt"===e?["encrypt","decrypt"]:["sign","verify"],r=yield d().subtle.generateKey({name:"decrypt"===e?"RSA-OAEP":"RSA-PSS",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},!0,t),i=yield d().subtle.exportKey("jwk",r.publicKey),n=yield d().subtle.exportKey("jwk",r.privateKey);return{publicKey:a(JSON.stringify(i)),privateKey:a(JSON.stringify(n))}})),this.importPrivateKey=(t,r)=>e(this,void 0,void 0,(function*(){const e={name:"decrypt"===r?"RSA-OAEP":"RSA-PSS",hash:"SHA-256"};"sign"===r&&(e.saltLength=32);try{const i=JSON.parse(u(t));return yield d().subtle.importKey("jwk",i,e,!1,[r])}catch(e){throw new Error(`Failed to import private key: ${e}`)}})),this.importPublicKey=(t,r)=>e(this,void 0,void 0,(function*(){const e={name:"encrypt"===r?"RSA-OAEP":"RSA-PSS",hash:"SHA-256"};"verify"===r&&(e.saltLength=32);try{const i=JSON.parse(u(t));return yield d().subtle.importKey("jwk",i,e,!1,[r])}catch(e){throw new Error(`Failed to import public key: ${e}`)}})),this.encryptMessage=(t,r)=>e(this,void 0,void 0,(function*(){const e=this.publicKeys.get(r);if(!e)throw new Error("Public key not found for user");const i=yield this.importPublicKey(e,"encrypt"),n=h().encode(t),o=yield this.generateAESKey(),y=d().getRandomValues(new Uint8Array(12)),s=yield d().subtle.encrypt({name:"AES-GCM",iv:y},o,n),c=yield d().subtle.exportKey("raw",o);return{iv:y,encryptedMessage:s,encryptedAESKey:yield d().subtle.encrypt({name:"RSA-OAEP"},i,c),signature:yield this.signMessage(t)}})),this.decryptMessage=(t,r)=>e(this,void 0,void 0,(function*(){const{iv:e,encryptedMessage:i,encryptedAESKey:n,signature:o}=t;let y="";try{y=yield this.importPrivateKey(this.privateKey,"decrypt")}catch(e){throw new Error(`Failed to import private key: ${e}`)}let s="";try{s=yield d().subtle.decrypt({name:"RSA-OAEP"},y,new Uint8Array(n))}catch(e){throw new Error(`Failed to decrypt AES key: ${e}`)}let c="";try{c=yield d().subtle.importKey("raw",s,"AES-GCM",!0,["decrypt"])}catch(e){throw new Error(`Failed to import AES key: ${e}`)}let a="";try{a=yield d().subtle.decrypt({name:"AES-GCM",iv:e},c,new Uint8Array(i))}catch(e){throw new Error(`Failed to decrypt message: ${e}`)}try{const e=("undefined"!=typeof window?new window.TextDecoder:new(require("util").TextDecoder)).decode(a);if(!(yield this.verifySignature(o,e,r)))throw new Error("Signature verification failed");return e}catch(e){throw new Error(`Failed to verify signature: ${e}`)}})),this.signMessage=t=>e(this,void 0,void 0,(function*(){const e=h().encode(t);try{const t=yield this.importPrivateKey(this.signKey,"sign");return yield d().subtle.sign({name:"RSA-PSS",saltLength:32},t,e)}catch(e){throw new Error(`Failed to sign message: ${e}`)}})),this.verifySignature=(t,r,i)=>e(this,void 0,void 0,(function*(){const e=this.verifyKeys.get(i);if(!e)throw new Error("Public key not found for user");try{const i=yield this.importPublicKey(e,"verify"),n=h().encode(r);return yield d().subtle.verify({name:"RSA-PSS",saltLength:32},i,new Uint8Array(t),n)}catch(e){throw new Error(`Failed to verify signature: ${e}`)}})),this.privateKey="",this.publicKey="",this.verifyKey="",this.signKey=""}get publickey(){return this.publicKey}get verifykey(){return this.verifyKey}get privatekey(){return this.privateKey}get signkey(){return this.signKey}generateAESKey(){return e(this,void 0,void 0,(function*(){return yield d().subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt","decrypt"])}))}init(t,r,i,n){return e(this,void 0,void 0,(function*(){if(t&&r&&i&&n)return this.publicKey=t,this.privateKey=r,this.verifyKey=i,this.signKey=n,{publicKey:this.publicKey,verifyKey:this.verifyKey};const e=yield this.genKeyPair(),o=yield this.genKeyPair("sign");return this.publicKey=e.publicKey,this.privateKey=e.privateKey,this.verifyKey=o.publicKey,this.signKey=o.privateKey,{publicKey:e.publicKey,verifyKey:o.publicKey}}))}setPublicKey(e,t,r){if(!e||!t)throw new Error("Invalid arguments");this.publicKeys.set(e,t),r&&this.verifyKeys.set(e,r)}setVerifyKey(e,t){if(!e||!t)throw new Error("Invalid arguments");this.verifyKeys.set(e,t)}hasPublicKey(e){return this.publicKeys.has(e)}hasVerifyKey(e){return this.verifyKeys.has(e)}exportEncryptedMessage(e){return a(JSON.stringify({iv:String.fromCharCode(...e.iv),encryptedMessage:p(e.encryptedMessage),encryptedAESKey:p(e.encryptedAESKey),signature:p(e.signature)}))}importEncryptedMessage(e){const t=JSON.parse(u(e));return{iv:new Uint8Array([...t.iv].map((e=>e.charCodeAt(0)))),encryptedMessage:l(t.encryptedMessage),encryptedAESKey:l(t.encryptedAESKey),signature:l(t.signature)}}}}));
