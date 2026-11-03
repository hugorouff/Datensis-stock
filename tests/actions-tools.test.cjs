'use strict';
const assert=require('node:assert/strict');
const {analyze,tags,validDate}=require('../public/assets/actions-tools.js');
assert.deepEqual(tags('Finance, urgent, Finance,  , Contrats'),['Finance','urgent','Contrats']);
assert.ok(validDate('2026-10-28'));
assert.ok(!validDate('28/10/2026'));
const today=new Date('2026-10-28T10:30:00');
const entries=[
 {id:'a',value:{type:'login',name:'Portail impots',client:'Cabinet A',criticality:'critical',service2fa:'no',handover:'todo',tags:'Fiscal, Urgent',nextRotation:'2026-10-25',history:[{at:'2026-10-21T10:00:00Z',action:'Fiche creee'}]}},
 {id:'b',value:{type:'login',name:'Espace facturation',client:'Cabinet A',owner:'Gestion',criticality:'normal',service2fa:'yes',handover:'reviewed',tags:'Fiscal',reviewDue:'2026-11-01'}},
 {id:'c',value:{type:'login',name:'Supprime',deletedAt:'2026-09-01',criticality:'critical',tags:'test'}},
 {id:'d',value:{type:'note',name:'Note privee',tags:'test'}}
];
const a=analyze(entries,today);
assert.equal(a.total,2);assert.equal(a.late,1);assert.equal(a.unowned,1);
assert.equal(a.clients.length,1);assert.equal(a.clients[0].count,2);
assert.equal(a.tags.find(x=>x[0]==='Fiscal')[1].length,2);
assert.equal(a.events.length,1);assert.ok(a.queue.some(x=>x.item.id==='b'));
console.log('OK: Centre actions: retards, client, etiquettes, revue, corbeille, historique');
