'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const root=path.join(__dirname,'..');
const popup=fs.readFileSync(path.join(root,'chrome-extension/popup.js'),'utf8');
const site=fs.readFileSync(path.join(root,'chrome-extension/site-assistant.js'),'utf8');
const html=fs.readFileSync(path.join(root,'chrome-extension/popup.html'),'utf8');
const web=fs.readFileSync(path.join(root,'templates/vault/index.html.twig'),'utf8');
const js=fs.readFileSync(path.join(root,'public/assets/vault.js'),'utf8');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'chrome-extension/manifest.json'),'utf8'));
const context={state:{siteOrigin:'https://teams.microsoft.com'},URL};
const block=popup.slice(popup.indexOf('  function matchHost(value){'),popup.indexOf('  const siteMatches='));
vm.runInNewContext(block+';globalThis.matches=matchHost;',context);
const match=(siteOrigin,value)=>{context.state.siteOrigin=siteOrigin;return context.matches(value);};
const teams={type:'login',url:'https://teams.microsoft.com/v2/',loginUrls:'https://login.microsoftonline.com/\nhttps://login.live.com/'};
test('matches any HTTPS site from the active browser URL, not just localhost',()=>{
  assert.equal(match('https://teams.microsoft.com',teams),true);
  assert.equal(match('https://teams.microsoft.com', {...teams,url:'https://teams.microsoft.com/login?redirect=/chat'}),true);
  assert.equal(match('https://login.microsoftonline.com',teams),true);
  assert.equal(match('https://login.live.com',teams),true);
  assert.equal(match('https://teams.microsoft.com.evil.example',teams),false);
  assert.equal(match('https://office.com',teams),false);
  assert.equal(match('http://teams.microsoft.com',teams),false);
  assert.equal(match('https://login.microsoftonline.com', {type:'login',url:'https://teams.microsoft.com'}),false);
  assert.equal(match('http://127.0.0.1:8000',{type:'login',url:'http://127.0.0.1:8000/login'}),true);
  assert.equal(match('http://127.0.0.1:8001',{type:'login',url:'http://127.0.0.1:8000/login'}),false);
  assert.equal(match('https://teams.microsoft.com',{type:'login',url:'https://teams.microsoft.com',loginUrls:'javascript:alert(1)'}),true);
  assert.equal(match('javascript:alert(1)',{type:'login',url:'javascript:alert(1)'}),false);
});
test('optional SSO URLs editable in web and extension, encrypted in same entry',()=>{
  assert.match(html,/id="entry-loginUrls"/);
  assert.match(web,/id="item-loginUrls"/);
  assert.match(popup,/'url','loginUrls','cardHolder'/);
  assert.match(js,/'url','loginUrls','cardHolder'/);
  assert.match(popup,/await encrypt\(value,state.key\)/);
  assert.match(js,/await encrypt\(value,state.key\)/);
  assert.deepEqual(manifest.host_permissions.includes('https://*/*'),true);
  assert.match(JSON.stringify(manifest.host_permissions),/https:\/\/\*/);
  assert.match(popup,/chrome\.permissions\.request/);
  assert.match(popup,/chrome\.tabs\.sendMessage\(tab\.id/);
  assert.doesNotMatch(site,/\.requestSubmit\(|\.submit\(/);
});
test('Microsoft two-stage login fills email field but does not submit it',()=>{
  let receive;
  class Input{
    constructor(){this.type='email';this.name='loginfmt';this.id='i0116';this.autocomplete='username';this._value='';this.disabled=false;this.readOnly=false;}
    get value(){return this._value;}
    set value(v){this._value=v;}
    getClientRects(){return [1];}
    dispatchEvent(){}
  }
  const email=new Input();
  const document={documentElement:{},getElementById(){return true;},querySelectorAll(selector){return selector==='input[type="password"]'?[]:selector==='input'?[email]:[];}};
  const ctx={document,window:{},location:{protocol:'https:',origin:'https://login.microsoftonline.com'},
    chrome:{runtime:{onMessage:{addListener(fn){receive=fn;}}},storage:{local:{get:async()=>({ml2cVaultOrigin:'http://127.0.0.1:8001'})}}},
    HTMLInputElement:Input,Event:class{constructor(type){this.type=type;}},console};
  ctx.window.top=ctx.window;
  vm.runInNewContext(site,ctx);
  let result;
  receive({type:'datensis-stock-fill',origin:'https://login.microsoftonline.com',username:'member@example.org',password:'abc123'},null,r=>{result=r;});
  assert.equal(result.filled,true);
  assert.equal(result.onlyUsername,true);
  assert.equal(email.value,'member@example.org');
  receive({type:'datensis-stock-fill',origin:'https://teams.microsoft.com',username:'intruder',password:'abc123'},null,r=>{result=r;});
  assert.equal(result.filled,false);
  assert.equal(email.value,'member@example.org');
});
