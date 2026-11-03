'use strict';
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const {test}=require('node:test');
const root=require('node:path').join(__dirname,'..');
const popup=fs.readFileSync(root+'/chrome-extension/popup.js','utf8');
const site=fs.readFileSync(root+'/chrome-extension/site-assistant.js','utf8');
const manifest=JSON.parse(fs.readFileSync(root+'/chrome-extension/manifest.json','utf8'));
const block=popup.slice(popup.indexOf('  function matchHost(value){'),popup.indexOf('  function updateSiteSuggestions(){'));
function makeCase({origin='http://127.0.0.1:8000',key=true,users=1,server='http://127.0.0.1:8001'}={}){
  const sent=[];
  const tab={id:7,active:true,url:origin+'/login',windowId:14};
  const ctx={URL,TextEncoder,state:{key:key?'unlocked-key':null,origin:server,siteOrigin:null,
    items:Array.from({length:users},(_,i)=>({value:{type:'login',url:'http://127.0.0.1:8000/login',username:'person'+i,password:'secret'+i}}))},
    checkInactivity:()=>false,popupActive:()=>true,popupGeneration:1,
    chrome:{tabs:{get:async()=>tab,query:async()=>[tab],sendMessage:async(id,msg)=>{sent.push(msg);return {filled:true};}}}};
  vm.runInNewContext(block+';globalThis.testAuto=autoFillForSender;',ctx);
  return {ctx,sent,tab,run:(sender)=>ctx.testAuto(sender||{origin,tab})};
}
test('fills on exact site automatically when unlocked and one login corresponds',async()=>{
  const scenario=makeCase();assert.equal((await scenario.run()).filled,true);
  assert.equal(scenario.sent.length,1);
  assert.equal(scenario.sent[0].automatic,true);
  assert.equal(scenario.sent[0].password,'secret0');
  assert.equal(scenario.sent[0].origin,'http://127.0.0.1:8000');
});
test('never fills if locked, wrong origin, inactive tab, ambiguous accounts or own vault',async()=>{
  for(const variant of [{key:false},{users:2},{server:'http://127.0.0.1:8000'}]){
    const scenario=makeCase(variant);
    assert.equal((await scenario.run()).filled,false);assert.equal(scenario.sent.length,0);
  }
  const scenario=makeCase();
  assert.equal((await scenario.run({origin:'http://127.0.0.1:8001',tab:scenario.tab})).filled,false);
  scenario.tab.active=false;
  assert.equal((await scenario.run()).filled,false);
  assert.equal(scenario.sent.length,0);
});
test('site script requests automatic fill but never submits or persists password',()=>{
  assert.match(site,/datensis-stock-autofill-ready/);
  assert.match(site,/request\.automatic && \(pwd\.value/);
  assert.match(site,/datensis-stock-autofill-probe/);
  assert.match(site,/MutationObserver/);
  assert.doesNotMatch(site,/\.requestSubmit\(|\.submit\(/);
  assert.doesNotMatch(site,/localStorage|sessionStorage/);
  assert.doesNotMatch(popup,/chrome\.storage\.local\.set\(\{password/);
  assert.ok(manifest.permissions.includes('sidePanel'));
  assert.ok(manifest.host_permissions.includes('https://*/*'));
});
test('never is the default idle setting but closing the side panel still locks',()=>{
  const html=fs.readFileSync(root+'/chrome-extension/popup.html','utf8');
  const web=fs.readFileSync(root+'/public/assets/vault.js','utf8');
  assert.match(popup,/datensisStockLockMinutes:0/);
  assert.match(web,/getItem\('ml2c-lock-minutes'\)===null\?0:/);
  assert.match(html,/<option value="0" selected>Jamais/);
  assert.match(popup,/if\(msg\?\.type==='datensis-stock-panel-closed'\)lock\(\)/);
});
