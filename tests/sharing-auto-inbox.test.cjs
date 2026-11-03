'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const {execFileSync}=require('node:child_process');
const server=fs.readFileSync('src/Controller/AccountShareController.php','utf8');
const ui=fs.readFileSync('public/assets/vault.js','utf8');
const twig=fs.readFileSync('templates/vault/index.html.twig','utf8');

test('Les demandes en préparation sont visibles sans exposer le secret ni autoriser acceptation',()=>{
  const listing=server.slice(server.indexOf('public function listing('),server.indexOf('public function create('));
  assert.match(listing,/s\.recipient_id=:uid AND s\.revoked_at IS NULL AND s\.declined_at IS NULL ORDER BY/);
  assert.doesNotMatch(listing,/AND s\.encrypted_bundle <>/);
  assert.match(listing,/'pendingEncryption'=>!\$ready/);
  assert.match(listing,/'encryptedBundle'=>\$ready && \$s\['accepted_at'\]!==null \? \$encrypted : null/);
  assert.match(ui,/if\(row\.pendingEncryption\)\{/);
  assert.match(ui,/En cours de préparation par l’expéditeur/);
  assert.match(ui,/\}else if\(!row\.accepted\)\{/);
  assert.match(server,/Le partage est encore en cours de preparation/);
});
test('Actualisation périodique et erreur explicite plutôt que faux « Aucune demande »',()=>{
  assert.match(ui,/function shareLoadError\(error\)/);
  assert.match(ui,/Demandes non chargées/);
  assert.match(ui,/ensureAccountSharing\(\)\.catch\(\(\)=>\{\}\)/);
  assert.match(ui,/setInterval\(\(\)=>\{[\s\S]*?ensureAccountSharing\(\)\.catch\(\(\)=>\{\}\);[\s\S]*?\},15000\);/);
  assert.match(twig,/id="account-share-refresh"/);
  assert.match(twig,/id="account-share-status"/);
  assert.match(twig,/v=20261030-share-auto2/);
});
test('Le chiffrement en attente peut encore être finalisé par le navigateur propriétaire',()=>{
  assert.match(ui,/row\.pendingEncryption && row\.recipientPublicKey/);
  assert.match(ui,/scheduleShareSync\(\)/);
  assert.match(ui,/shareCrypto\.seal\(entries,row\.recipientPublicKey\)/);
  assert.match(ui,/\/api\/shares\/'\+encodeURIComponent\(row\.id\)\+'\/content'/);
});
