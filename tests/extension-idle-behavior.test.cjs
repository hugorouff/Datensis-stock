'use strict';
const assert=require('node:assert/strict');
const vm=require('node:vm');
const fs=require('node:fs');
const src=fs.readFileSync('chrome-extension/popup.js','utf8');
const start=src.indexOf('  const IDLE_OPTIONS = [0,1,3,5,10,15];');
const end=src.indexOf('  const b64 = ',start);
assert.ok(start>=0&&end>start);
let now=10000000,lockCount=0,notices=[];
const fakeState={key:'key-in-memory'};
const fakeDate={now:()=>now};
const ctx={state:fakeState,Date:fakeDate,$:()=>({textContent:''}),lock:()=>{lockCount++;fakeState.key=null;},message:(...args)=>notices.push(args),armInactivityWatchdog:()=>{},chrome:{alarms:{create:()=>Promise.resolve(),clear:()=>Promise.resolve()}},setTimeout:()=>1,clearTimeout:()=>{}};
vm.createContext(ctx);
vm.runInContext(src.slice(start,end),ctx);
// Le defaut utilisateur est desormais Jamais ; simuler explicitement le mode 5 minutes pour le test du minuteur.
vm.runInContext('idleMinutes=5',ctx);
// Last activity is set to now at boot. Browser inactivity 4m59s should not lock.
now+=299999;
assert.equal(vm.runInContext('checkInactivity()',ctx),false);
assert.equal(lockCount,0);
// Panel interaction extends session locally.
let stopped=false;
ctx.testEvent={cancelable:true,preventDefault(){},stopImmediatePropagation(){stopped=true;}};
vm.runInContext('recordActivity(testEvent)',ctx);
now+=300001;
assert.equal(vm.runInContext('checkInactivity()',ctx),true);
assert.equal(lockCount,1);
assert.match(notices.at(-1)[0],/inactivité/);
// Frozen timer scenario: first input event must lock, not refresh activity.
fakeState.key='new-session';vm.runInContext('lastActivityAt=Date.now()',ctx);
now+=300002;
let prevented=false,blocked=false;
ctx.testEvent={cancelable:true,preventDefault(){prevented=true;},stopImmediatePropagation(){blocked=true;}};
vm.runInContext('recordActivity(testEvent)',ctx);
assert.equal(lockCount,2);
assert.equal(prevented,true);
assert.equal(blocked,true);
console.log('OK: temporisation 5 min, prolongation par interaction, verrouillage au reveil apres suspension');

// L'option Jamais n'annule pas le verrouillage à la fermeture.
fakeState.key='still-unlocked';vm.runInContext('idleMinutes=0;lastActivityAt=Date.now()',ctx);now+=10000000;assert.equal(vm.runInContext('checkInactivity()',ctx),false);assert.equal(lockCount,2);
