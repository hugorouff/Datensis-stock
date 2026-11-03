'use strict';
const {webcrypto}=require('node:crypto');const assert=require('node:assert/strict');
(async()=>{
const crypto=webcrypto;
// Le destinataire n'obtient que la cle publique de son invitation.
const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
const pkcs8=await crypto.subtle.exportKey('pkcs8',pair.privateKey);
// La cle privee reste chiffree a l'aide de la cle AES du coffre de l'administrateur.
const vaultKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
const iv=crypto.getRandomValues(new Uint8Array(12));
const protectedPrivate=await crypto.subtle.encrypt({name:'AES-GCM',iv},vaultKey,pkcs8);
const rawPrivate=await crypto.subtle.decrypt({name:'AES-GCM',iv},vaultKey,protectedPrivate);
const privateKey=await crypto.subtle.importKey('pkcs8',rawPrivate,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
const payload={entries:[{name:'Comptabilité',username:'demo',password:'fictif-seulement',folder:'Cabinet Exemple/Finance'}]};
const shareKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
const shareRaw=await crypto.subtle.exportKey('raw',shareKey);
const spki=await crypto.subtle.exportKey('spki',pair.publicKey);
const publicKey=await crypto.subtle.importKey('spki',spki,{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
const wrapped=await crypto.subtle.encrypt({name:'RSA-OAEP'},publicKey,shareRaw);
const nonce=crypto.getRandomValues(new Uint8Array(12));
const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},shareKey,new TextEncoder().encode(JSON.stringify(payload)));
assert(!Buffer.from(ciphertext).toString('utf8').includes('fictif-seulement'));
const recovered=await crypto.subtle.decrypt({name:'RSA-OAEP'},privateKey,wrapped);
const aes=await crypto.subtle.importKey('raw',recovered,{name:'AES-GCM'},false,['decrypt']);
const clear=JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce},aes,ciphertext)));
assert.deepEqual(clear,payload);
await assert.rejects(async()=>crypto.subtle.decrypt({name:'RSA-OAEP'},pair.publicKey,wrapped));
console.log('Crypto hybride RSA-OAEP + AES-GCM : aller-retour avec cle privee du coffre verifie.');
})().catch(e=>{console.error(e);process.exitCode=1;});
