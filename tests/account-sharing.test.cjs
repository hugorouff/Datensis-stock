'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const crypto=webcrypto;
const sharing=require('../public/assets/account-sharing.js');
async function encryptedPrivate(v,key){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(v)));
  return {v:1,iv:Buffer.from(iv).toString('base64'),data:Buffer.from(data).toString('base64')};
}
async function decryptPrivate(x,key){
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(x.iv,'base64')},key,Buffer.from(x.data,'base64'));
  return JSON.parse(new TextDecoder().decode(plain));
}
test('public key seals a credential; only matching private key opens',async()=>{
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const alice=await sharing.createIdentity(key,encryptedPrivate);
  const bob=await sharing.createIdentity(key,encryptedPrivate);
  const payload={entries:[{name:'Fiche de test',username:'user',password:'SECRET_TEST'}]};
  const sealed=await sharing.seal(payload,alice.publicKey);
  assert.equal(JSON.stringify(sealed).includes('SECRET_TEST'),false);
  const priv=await sharing.privateKey(alice.encryptedPrivateKey,key,decryptPrivate);
  assert.deepEqual(await sharing.open(sealed,priv),payload);
  const wrong=await sharing.privateKey(bob.encryptedPrivateKey,key,decryptPrivate);
  await assert.rejects(()=>sharing.open(sealed,wrong));
});
test('folder sharing uses only matching subtree and does not copy private metadata',()=>{
  const entries=[
    {id:'a',value:{type:'login',name:'Banque',folder:'Entreprise/Social',username:'soc',password:'A',url:'https://example.com',notes:'SECRET_INTERNE',totp:'PRIVATE_OTP'}},
    {id:'b',value:{type:'login',name:'Compta',folder:'Entreprise/Compta',password:'B'}},
    {id:'c',value:{type:'login',name:'Autre',folder:'EntrepriseX/Compta',password:'C'}},
    {id:'d',value:{type:'card',name:'CB',folder:'Entreprise/Social',password:'D'}},
  ];
  const bundle=sharing.snapshot(entries,'folder','Entreprise');
  assert.equal(bundle.entries.length,2);
  assert.equal(bundle.entries[0].relativeFolder,'Social');
  assert.equal(bundle.entries[1].relativeFolder,'Compta');
  assert.equal(JSON.stringify(bundle).includes('SECRET_INTERNE'),false);
  assert.equal(JSON.stringify(bundle).includes('PRIVATE_OTP'),false);
  assert.equal(JSON.stringify(bundle).includes('EntrepriseX'),false);
  const individual=sharing.snapshot(entries,'entry','a');
  assert.equal(individual.entries.length,1);
  assert.equal(individual.entries[0].relativeFolder,'');
});
test('API requires identity verification, explicit consent and private recipient data',()=>{
  const controller=fs.readFileSync(path.join(__dirname,'../src/Controller/AccountShareController.php'),'utf8');
  assert.match(controller,/getSharingEmailVerifiedAt\(\)/);
  assert.match(controller,/\['consent'\]/);
  assert.match(controller,/recipient_id=:uid/);
  assert.match(controller,/encrypted_bundle/);
  assert.match(controller,/revoked_at IS NULL/);
  const html=fs.readFileSync(path.join(__dirname,'../templates/vault/index.html.twig'),'utf8');
  assert.match(html,/data-view="shares"/);
  assert.match(html,/id="account-share-form"/);
});
