'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {test}=require('node:test');
const path=require('node:path');
const root=path.join(__dirname,'..');
const popup=fs.readFileSync(path.join(root,'chrome-extension/popup.js'),'utf8');
const page=fs.readFileSync(path.join(root,'chrome-extension/site-assistant.js'),'utf8');
const web=fs.readFileSync(path.join(root,'templates/vault/index.html.twig'),'utf8');
const code=fs.readFileSync(path.join(root,'public/assets/vault.js'),'utf8');
const html=fs.readFileSync(path.join(root,'chrome-extension/popup.html'),'utf8');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'chrome-extension/manifest.json'),'utf8'));
test('URL matching ignores paths but isolates ports, scheme, and hostname',()=>{
  const block=popup.slice(popup.indexOf('  function matchHost(value){'),popup.indexOf('  const siteMatches='));
  const context={state:{siteOrigin:'http://127.0.0.1:8000'},URL};
  vm.runInNewContext(block+';globalThis.matches=matchHost;',context);
  const matches=url=>context.matches({type:'login',url});
  assert.equal(matches('http://127.0.0.1:8000/login'),true);
  assert.equal(matches('http://127.0.0.1:8000/'),true);
  assert.equal(matches('http://127.0.0.1:8000/any/subpage'),true);
  assert.equal(matches('http://127.0.0.1:8001/login'),false);
  assert.equal(matches('http://localhost:8000/login'),false);
  assert.equal(matches('https://127.0.0.1:8000/login'),false);
  assert.equal(context.matches({type:'note',url:'http://127.0.0.1:8000/'}),false);
});
test('web editor uses only simple fields; historical secrets and other encrypted metadata preserved',()=>{
  assert.ok(!web.includes('Suivi des accès professionnels'));
  assert.ok(!web.includes('item-totp'));
  assert.ok(!web.includes('item-criticality'));
  assert.ok(web.includes('id="item-url"'));
  assert.ok(web.includes('id="item-notes"'));
  assert.ok(code.includes('const value={...(existingValue||{})'));
  assert.ok(!code.includes("detailField(info,'Clé TOTP'"));
  assert.ok(!code.includes("$('item-criticality')"));
});
test('extension offers matching site suggestions, supports automatic filling, never auto-submits',()=>{
  assert.ok(manifest.content_scripts.some(v=>v.matches.includes('http://127.0.0.1/*')));
  assert.ok(manifest.content_scripts.some(v=>v.matches.includes('http://localhost/*')));
  assert.ok(html.includes('id="entry-url"'));
  assert.ok(html.includes('id="site-suggestions"'));
  assert.ok(html.includes('id="fill-site"'));
  assert.ok(popup.includes('chrome.tabs.sendMessage(tab.id'));
  assert.ok(popup.includes('autoFillForSender(sender)'));
  assert.ok(page.includes('datensis-stock-autofill-ready'));
  assert.ok(popup.includes("fill.onclick=e=>{e.stopPropagation();fillOnSite(item);};"));
  assert.ok(page.includes('request.origin !== location.origin'));
  assert.ok(page.includes('passwords.length !== 1'));
  assert.ok(!page.includes('.submit('));
  assert.ok(!page.includes('.requestSubmit('));
  assert.ok(!page.includes('localStorage'));
  assert.ok(!page.includes('sessionStorage'));
  assert.ok(!popup.includes('chrome.storage.local.set({password'));
});

test('content script fills the intended form only after explicit message and checks origin',async()=>{
  let listener=null;
  class Input{
    constructor(type,name){this.type=type;this.name=name;this.id=name;this.disabled=false;this.readOnly=false;this.autocomplete='';this._value='';this.changed=[];}
    get value(){return this._value;}
    set value(next){this._value=next;}
    getClientRects(){return [1];}
    dispatchEvent(evt){this.changed.push(evt.type);}
  }
  const username=new Input('text','username'),password=new Input('password','password');
  const form={querySelectorAll(sel){assert.equal(sel,'input');return [username,password];}};
  password.form=form;
  const doc={documentElement:{append(){}},getElementById(){return true;},querySelectorAll(sel){assert.equal(sel,'input[type="password"]');return [password];}};
  const ctx={document:doc,window:{},location:{origin:'http://127.0.0.1:8000',protocol:'http:'},
    chrome:{runtime:{onMessage:{addListener(fn){listener=fn;}}},storage:{local:{get:async()=>({ml2cVaultOrigin:'http://127.0.0.1:8001'})}}},
    HTMLInputElement:Input,Event:class{constructor(type){this.type=type;}},console};
  ctx.window.top=ctx.window;
  vm.runInNewContext(page,ctx);
  assert.ok(listener);
  let response;
  listener({type:'datensis-stock-fill',origin:'http://127.0.0.1:8001',username:'wrong',password:'secret'},null,v=>{response=v;});
  assert.equal(response.filled,false);
  assert.equal(password.value,'');
  listener({type:'datensis-stock-fill',origin:'http://127.0.0.1:8000',username:'mon.compte',password:'mon-secret'},null,v=>{response=v;});
  assert.equal(response.filled,true);
  assert.equal(username.value,'mon.compte');
  assert.equal(password.value,'mon-secret');
  assert.deepEqual(password.changed,['input','change']);
});
