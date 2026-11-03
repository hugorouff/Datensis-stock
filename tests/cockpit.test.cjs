'use strict';
// Teste les fonctions effectivement utilisees par le tableau de bord (pas une duplication).
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(__dirname + '/../public/assets/vault.js','utf8');
const from = source.indexOf('  function activeLogins(){');
const until = source.indexOf('  function cockpitItemButton(',from);
assert.ok(from > 0 && until > from, 'fonctions cockpit introuvables');
const yesterday = new Date(Date.now()-86400_000).toISOString().slice(0,10);
const tomorrow = new Date(Date.now()+86400_000).toISOString().slice(0,10);
const state={items:[
  {id:'one',value:{type:'login',name:'ERP client',client:'Dossier A',criticality:'critical',service2fa:'no',owner:'',password:'123456',nextRotation:yesterday}},
  {id:'two',value:{type:'login',name:'Messagerie',client:'Dossier A',owner:'Service comptable',password:'123456',nextRotation:tomorrow}},
  {id:'three',value:{type:'login',name:'Externe',client:'Dossier B',owner:'Service juridique',password:'K3a%S8m@p92?qX9y2!4',service2fa:'yes',nextRotation:''}},
  {id:'trash',value:{type:'login',name:'supprimé',password:'123456',deletedAt:'2025-01-01'}},
]};
const sandbox={state,Date,Map};
vm.createContext(sandbox);
vm.runInContext(source.slice(from,until)+'\nthis.cockpitAnalysis=cockpitAnalysis;',sandbox);
const result=sandbox.cockpitAnalysis();
assert.equal(result.logins.length,3,'la corbeille ne doit pas apparaitre');
assert.equal(result.clients.length,2,'deux dossiers');
assert.equal(result.upcoming.length,1,'une echeance proche');
assert.equal(result.upcoming[0].item.id,'two');
assert.equal(result.alerts.filter(x=>x.code==='duplicate').length,2);
assert.equal(result.alerts.filter(x=>x.code==='overdue').length,1);
assert.equal(result.alerts.filter(x=>x.code==='mfa').length,1);
assert.equal(result.alerts.filter(x=>x.code==='owner').length,1);
console.log('OK cockpit: dossiers, alertes, rotations, corbeille');
