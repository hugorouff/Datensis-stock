'use strict';
const fs=require('node:fs');const vm=require('node:vm');const assert=require('node:assert/strict');
const code=fs.readFileSync(__dirname+'/../public/assets/vault.js','utf8');
const pwStart=code.indexOf('  function activeLogins(){');
const pwEnd=code.indexOf('  function cockpitItemButton(',pwStart);
const auditStart=code.indexOf('  function securityAudit(){');
const auditEnd=code.indexOf('  function securityOpenItem(',auditStart);
assert.ok(pwStart>0&&pwEnd>pwStart&&auditStart>0&&auditEnd>auditStart);
const yesterday=new Date(Date.now()-86400000).toISOString().slice(0,10);
const state={items:[
{id:'a',value:{type:'login',name:'Banque',client:'Dossier A',owner:'Patricia',criticality:'critical',password:'123456',service2fa:'no',url:'http://banque.example',nextRotation:yesterday}},
{id:'b',value:{type:'login',name:'Portail A',client:'Dossier A',owner:'Patricia',criticality:'normal',password:'123456',url:'https://portail.example'}},
{id:'c',value:{type:'login',name:'Portail B',client:'Dossier B',owner:'Marie',criticality:'normal',password:'w5h*NoP-56fm!6oT$MX7',url:'https://portail.example'}},
{id:'d',value:{type:'login',name:'Trash',password:'123456',deletedAt:'2025-01-01',url:'https://secret.example'}}
]};
const ctx={state,Date,Map,Set,URL};vm.createContext(ctx);
vm.runInContext(code.slice(pwStart,pwEnd)+'\n'+code.slice(auditStart,auditEnd)+'\nthis.audit=securityAudit();',ctx);
assert.equal(ctx.audit.logins.length,3);
assert.equal(ctx.audit.domainMap.size,2);
assert.equal(ctx.audit.overdue.length,1);
assert.equal(ctx.audit.issues.filter(x=>x.label.includes('plusieurs')).length,2);
assert.equal(ctx.audit.issues.filter(x=>x.label.includes('HTTP')).length,1);
assert.equal(ctx.audit.owners.length,2);
assert.ok(ctx.audit.score < 100);
console.log('OK: Centre de securite - alertes, dates, domaines, responsable, corbeille, doublons');
