"use strict";function e(e,t,r,i){return new(r||(r=Promise))((function(n,o){function y(e){try{a(i.next(e))}catch(e){o(e)}}function s(e){try{a(i.throw(e))}catch(e){o(e)}}function a(e){var t;e.done?n(e.value):(t=e.value,t instanceof r?t:new r((function(e){e(t)}))).then(y,s)}a((i=i.apply(e,t||[])).next())}))}"function"==typeof SuppressedError&&SuppressedError;const t=()=>"undefined"!=typeof window?window.crypto:require("crypto").webcrypto,r=()=>"undefined"!=typeof window?new window.TextEncoder:new(require("util").TextEncoder);module.exports=class{constructor(){this.publicKeys=new Map,this.genKeyPair=()=>e(this,void 0,void 0,(function*(){const e=yield t().subtle.generateKey({name:"RSA-OAEP",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},!0,["encrypt","decrypt"]),r=yield t().subtle.exportKey("spki",e.publicKey),i=yield t().subtle.exportKey("pkcs8",e.privateKey);return this.publicKey=String.fromCharCode(...Array.from(new Uint8Array(r))),this.privateKey=String.fromCharCode(...Array.from(new Uint8Array(i))),this.publicKey})),this.importPrivateKey=(r,i)=>e(this,void 0,void 0,(function*(){return yield t().subtle.importKey("pkcs8",new Uint8Array([...r].map((e=>e.charCodeAt(0)))),{name:"decrypt"===i?"RSA-OAEP":"RSA-PSS",hash:"SHA-256"},!0,[i])})),this.signMessage=i=>e(this,void 0,void 0,(function*(){const e=r().encode(i),n=yield this.importPrivateKey(this.privateKey,"sign");return yield t().subtle.sign({name:"RSA-PSS",saltLength:32},n,e)})),this.importPublicKey=(r,i)=>e(this,void 0,void 0,(function*(){return yield t().subtle.importKey("spki",new Uint8Array([...r].map((e=>e.charCodeAt(0)))),{name:"encrypt"===i?"RSA-OAEP":"RSA-PSS",hash:"SHA-256"},!0,[i])})),this.encryptMessage=(i,n)=>e(this,void 0,void 0,(function*(){const e=this.publicKeys.get(n);if(!e)throw new Error("Public key not found for user");const o=yield this.importPublicKey(e,"encrypt"),y=r().encode(i),s=yield this.generateAESKey(),a=t().getRandomValues(new Uint8Array(12)),c=yield t().subtle.encrypt({name:"AES-GCM",iv:a},s,y),d=yield t().subtle.exportKey("raw",s);return{iv:a,encryptedMessage:c,encryptedAESKey:yield t().subtle.encrypt({name:"RSA-OAEP"},o,d),signature:yield this.signMessage(i)}})),this.verifySignature=(i,n,o)=>e(this,void 0,void 0,(function*(){const e=this.publicKeys.get(o);if(!e)throw new Error("Public key not found for user");const y=yield this.importPublicKey(e,"verify"),s=r().encode(n);return yield t().subtle.verify({name:"RSA-PSS",saltLength:32},y,i,s)})),this.decryptMessage=(r,i)=>e(this,void 0,void 0,(function*(){if(!this.publicKeys.get(i))throw new Error(`Public key not found for user ${i}`);const{iv:e,encryptedMessage:n,encryptedAESKey:o,signature:y}=r;let s="";try{s=yield this.importPrivateKey(this.privateKey,"decrypt")}catch(e){throw new Error(`Failed to import private key: ${e}`)}let a="";try{a=yield t().subtle.decrypt({name:"RSA-OAEP"},s,o)}catch(e){throw new Error(`Failed to decrypt AES key: ${e}`)}let c="";try{c=yield t().subtle.importKey("raw",a,"AES-GCM",!0,["decrypt"])}catch(e){throw new Error(`Failed to import AES key: ${e}`)}let d="";try{d=yield t().subtle.decrypt({name:"AES-GCM",iv:e},c,n)}catch(e){throw new Error(`Failed to decrypt message: ${e}`)}try{const e=("undefined"!=typeof window?new window.TextDecoder:new(require("util").TextDecoder)).decode(d);if(!(yield this.verifySignature(y,e,i)))throw new Error("Signature verification failed");return e}catch(e){throw new Error(`Failed to verify signature: ${e}`)}})),this.privateKey="",this.publicKey=""}get publickey(){return btoa(this.publicKey)}get privatekey(){return btoa(this.privateKey)}generateAESKey(){return e(this,void 0,void 0,(function*(){return yield t().subtle.generateKey({name:"AES-GCM",length:256},!0,["encrypt","decrypt"])}))}init(t,r){return e(this,void 0,void 0,(function*(){return t&&r?(this.publicKey=atob(t),this.privateKey=atob(r),t):(t=yield this.genKeyPair(),btoa(t))}))}setPublicKey(e,t){t=atob(t),this.publicKeys.set(e,t)}hasPublicKey(e){return this.publicKeys.has(e)}exportEncryptedMessage(e){return btoa(JSON.stringify({iv:String.fromCharCode(...e.iv),encryptedMessage:String.fromCharCode(...new Uint8Array(e.encryptedMessage)),encryptedAESKey:String.fromCharCode(...new Uint8Array(e.encryptedAESKey)),signature:String.fromCharCode(...new Uint8Array(e.signature))}))}importEncryptedMessage(e){const t=JSON.parse(atob(e));return{iv:new Uint8Array([...t.iv].map((e=>e.charCodeAt(0)))),encryptedMessage:new Uint8Array([...t.encryptedMessage].map((e=>e.charCodeAt(0)))),encryptedAESKey:new Uint8Array([...t.encryptedAESKey].map((e=>e.charCodeAt(0)))),signature:new Uint8Array([...t.signature].map((e=>e.charCodeAt(0))))}}};
