"use strict";function e(e,r,t,i){return new(t||(t=Promise))((function(n,o){function s(e){try{c(i.next(e))}catch(e){o(e)}}function y(e){try{c(i.throw(e))}catch(e){o(e)}}function c(e){var r;e.done?n(e.value):(r=e.value,r instanceof t?r:new t((function(e){e(r)}))).then(s,y)}c((i=i.apply(e,r||[])).next())}))}"function"==typeof SuppressedError&&SuppressedError;var r="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";const t="function"==typeof atob&&atob;var i;const n=/[\t\n\r\x20\x0C]+/g,o=String.fromCharCode;const s=t||"function"==typeof Buffer&&function(e){return Buffer.from(e,"base64").toString("binary")}||function(e){if(!e)return e;var t,s,y,c,a,u,d=(e=String(e).replace(n,"")).length,h=0,p=0,f=[];if(null==i){i={};for(var l=0;l<65;l++)i[r.charAt(l)]=l}do{t=(u=i[e.charAt(h++)]<<18|i[e.charAt(h++)]<<12|(c=i[e.charAt(h++)])<<6|(a=i[e.charAt(h++)]))>>16&255,s=u>>8&255,y=255&u,f[p++]=64==c?o(t):64==a?o(t,s):o(t,s,y)}while(h<d);return f.join("").replace(/\0+$/,"")};const y="function"==typeof btoa&&btoa||"function"==typeof Buffer&&function(e){return Buffer.from(e,"binary").toString("base64")}||function(e){if(!e)return e;var t,i,n,o,s,y=0,c=0,a="",u=[];do{t=(s=e.charCodeAt(y++)<<16|e.charCodeAt(y++)<<8|e.charCodeAt(y++))>>18&63,i=s>>12&63,n=s>>6&63,o=63&s,u[c++]=r.charAt(t)+r.charAt(i)+r.charAt(n)+r.charAt(o)}while(y<e.length);a=u.join("");var d=e.length%3;return(d?a.slice(0,d-3):a)+"===".slice(d||3)};function c(e){return decodeURIComponent(escape(e))}
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
*/function a(e){return e?y(unescape(encodeURI(e))):e}function u(e,r){let t=function(e){let r=e;return r&&(r=s(String(r).replace(/_/g,"/").replace(/-/g,"+"))),r}(e);if(t){if(r)return c(t);try{t=c(t)}catch(e){}}return t}const d=()=>"undefined"!=typeof window?window.crypto:require("crypto").webcrypto,h=()=>"undefined"!=typeof window?new window.TextEncoder:new(require("util").TextEncoder),p=e=>{const r=new Uint8Array(e);let t="";for(const e of r)t+=String.fromCharCode(e);return y(t)},f=e=>{const r=u(e),t=new ArrayBuffer(r.length),i=new Uint8Array(t);for(let e=0;e<r.length;e++)i[e]=r.charCodeAt(e);return t};class l extends Error{constructor(e,r,t){super(e),this.operation=r,this.originalError=t,this.name="CryptoOperationError"}}class g extends Error{constructor(e,r,t){super(e),this.keyType=r,this.originalError=t,this.name="KeyImportError"}}module.exports=class{constructor(){this.publicKeys=new Map,this.verifyKeys=new Map,this.genKeyPair=(...r)=>e(this,[...r],void 0,(function*(e="decrypt"){const r="decrypt"===e?["encrypt","decrypt"]:["sign","verify"],t=yield d().subtle.generateKey({name:"decrypt"===e?"RSA-OAEP":"RSA-PSS",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},!0,r),i=yield d().subtle.exportKey("jwk",t.publicKey),n=yield d().subtle.exportKey("jwk",t.privateKey);return{publicKey:a(JSON.stringify(i)),privateKey:a(JSON.stringify(n))}})),this.importPrivateKey=(r,t)=>e(this,void 0,void 0,(function*(){const e={name:"decrypt"===t?"RSA-OAEP":"RSA-PSS",hash:"SHA-256"};"sign"===t&&(e.saltLength=32);try{const i=JSON.parse(u(r));return yield d().subtle.importKey("jwk",i,e,!1,[t])}catch(e){throw new g(`Failed to import private key: ${e instanceof Error?e.message:"Unknown error"}`,"private",e instanceof Error?e:void 0)}})),this.importPublicKey=(r,t)=>e(this,void 0,void 0,(function*(){const e={name:"encrypt"===t?"RSA-OAEP":"RSA-PSS",hash:"SHA-256"};"verify"===t&&(e.saltLength=32);try{const i=JSON.parse(u(r));return yield d().subtle.importKey("jwk",i,e,!1,[t])}catch(e){throw new g(`Failed to import public key: ${e instanceof Error?e.message:"Unknown error"}`,"public",e instanceof Error?e:void 0)}})),this.encryptMessage=(r,t)=>e(this,void 0,void 0,(function*(){const e=this.publicKeys.get(t);if(!e)throw new Error("Public key not found for user");const i=yield this.importPublicKey(e,"encrypt"),n=h().encode(r),o=yield this.generateAESKey(),s=d().getRandomValues(new Uint8Array(12)),y=yield d().subtle.encrypt({name:"AES-GCM",iv:s},o,n),c=yield d().subtle.exportKey("raw",o);return{iv:s,encryptedMessage:y,encryptedAESKey:yield d().subtle.encrypt({name:"RSA-OAEP"},i,c),signature:yield this.signMessage(r)}})),this.decryptMessage=(r,t)=>e(this,void 0,void 0,(function*(){const{iv:e,encryptedMessage:i,encryptedAESKey:n,signature:o}=r;let s;try{s=yield this.importPrivateKey(this.privateKey,"decrypt")}catch(e){throw new Error(`Failed to import private key: ${e}`)}let y="";try{y=yield d().subtle.decrypt({name:"RSA-OAEP"},s,new Uint8Array(n))}catch(e){throw new l(`Failed to decrypt AES key: ${e instanceof Error?e.message:"Unknown error"}`,"decrypt",e instanceof Error?e:void 0)}let c="";try{c=yield d().subtle.importKey("raw",y,"AES-GCM",!0,["decrypt"])}catch(e){throw new g(`Failed to import AES key: ${e instanceof Error?e.message:"Unknown error"}`,"private",e instanceof Error?e:void 0)}let a="";try{a=yield d().subtle.decrypt({name:"AES-GCM",iv:e},c,new Uint8Array(i))}catch(e){throw new l(`Failed to decrypt message: ${e instanceof Error?e.message:"Unknown error"}`,"decrypt",e instanceof Error?e:void 0)}try{const e=("undefined"!=typeof window?new window.TextDecoder:new(require("util").TextDecoder)).decode(a);if(!(yield this.verifySignature(o,e,t)))throw new Error("Signature verification failed");return e}catch(e){throw new l(`Failed to verify signature: ${e instanceof Error?e.message:"Unknown error"}`,"verify",e instanceof Error?e:void 0)}})),this.signMessage=r=>e(this,void 0,void 0,(function*(){const e=h().encode(r);try{const r=yield this.importPrivateKey(this.signKey,"sign");return yield d().subtle.sign({name:"RSA-PSS",saltLength:32},r,e)}catch(e){throw new l(`Failed to sign message: ${e instanceof Error?e.message:"Unknown error"}`,"sign",e instanceof Error?e:void 0)}})),this.verifySignature=(r,t,i)=>e(this,void 0,void 0,(function*(){const e=this.verifyKeys.get(i);if(!e)throw new Error("Public key not found for user");try{const i=yield this.importPublicKey(e,"verify"),n=h().encode(t);return yield d().subtle.verify({name:"RSA-PSS",saltLength:32},i,new Uint8Array(r),n)}catch(e){throw new l(`Failed to verify signature: ${e instanceof Error?e.message:"Unknown error"}`,"verify",e instanceof Error?e:void 0)}})),this.privateKey="",this.publicKey="",this.verifyKey="",this.signKey=""}get publickey(){return this.publicKey}get verifykey(){return this.verifyKey}get privatekey(){return this.privateKey}get signkey(){return this.signKey}generateAESKey(){return e(this,void 0,void 0,(function*(){return yield d().subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt","decrypt"])}))}init(r,t,i,n){return e(this,void 0,void 0,(function*(){if(r&&t&&i&&n)return this.publicKey=r,this.privateKey=t,this.verifyKey=i,this.signKey=n,{publicKey:this.publicKey,verifyKey:this.verifyKey};const e=yield this.genKeyPair(),o=yield this.genKeyPair("sign");return this.publicKey=e.publicKey,this.privateKey=e.privateKey,this.verifyKey=o.publicKey,this.signKey=o.privateKey,{publicKey:e.publicKey,verifyKey:o.publicKey}}))}setPublicKey(e,r,t){if(!e||!r)throw new Error("Invalid arguments");this.publicKeys.set(e,r),t&&this.verifyKeys.set(e,t)}setVerifyKey(e,r){if(!e||!r)throw new Error("Invalid arguments");this.verifyKeys.set(e,r)}hasPublicKey(e){return this.publicKeys.has(e)}hasVerifyKey(e){return this.verifyKeys.has(e)}exportEncryptedMessage(e){return a(JSON.stringify({iv:String.fromCharCode(...e.iv),encryptedMessage:p(e.encryptedMessage),encryptedAESKey:p(e.encryptedAESKey),signature:p(e.signature)}))}importEncryptedMessage(e){const r=JSON.parse(u(e));return{iv:new Uint8Array([...r.iv].map((e=>e.charCodeAt(0)))),encryptedMessage:f(r.encryptedMessage),encryptedAESKey:f(r.encryptedAESKey),signature:f(r.signature)}}};
