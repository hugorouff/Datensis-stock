'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const root=path.join(__dirname,'..');
const page=fs.readFileSync(path.join(root,'chrome-extension/site-assistant.js'),'utf8');
const popup=fs.readFileSync(path.join(root,'chrome-extension/popup.js'),'utf8');
const html=fs.readFileSync(path.join(root,'chrome-extension/popup.html'),'utf8');
const manifest=JSON.parse(fs.readFileSync(path.join(root,'chrome-extension/manifest.json'),'utf8'));

test('server configurator and floating Mes identifiants removed',()=>{
  assert.doesNotMatch(html,/login-settings|origin-screen|save-server|id="server"/);
  assert.doesNotMatch(popup,/saveServer\(|\$\('login-settings'\)/);
  assert.doesNotMatch(page,/datensis-stock-launcher|Mes identifiants|createButton/);
});
test('extension can suggest saving on HTTPS sites and uses native Edge setting only after user clicks',()=>{
  assert.ok(manifest.content_scripts[0].matches.includes('https://*/*'));
  assert.ok(manifest.host_permissions.includes('https://*/*'));
  assert.ok(manifest.permissions.includes('privacy'));
  assert.match(popup, /\$\('disable-browser-save'\)\.onclick/);
  assert.match(popup, /passwordSavingEnabled\.set\(\{value:false,scope:'regular'\}\)/);
  assert.match(html,/id="browser-save-status"/);
  assert.doesNotMatch(page,/localStorage|sessionStorage|\.submit\(|\.requestSubmit\(/);
  assert.match(page,/event\.isTrusted/);
  assert.match(page,/draftApproved=true/);
  assert.match(page,/datensis-stock-take-save-draft/);
  assert.match(popup,/\$\('entry-url'\)\.value=result\.url/);
  assert.match(popup,/\$\('entry-password'\)\.value=result\.password/);
  assert.match(popup,/\$\('entry-username'\)\.value=result\.username/);
});
function scenario(known){
 let onMessage, inputListener, buttons=[],hosts=[],outbound=[],timers=[];
 class Input{
  constructor(type,name){this.type=type;this.name=name;this.id=name;this.autocomplete='';this.disabled=false;this.readOnly=false;this.value='';}
  getClientRects(){return [1];}
  closest(){return null;}
 }
 class Element{
  constructor(tag){this.tag=tag;this.events={};this.style={};this.children=[];this.id='';}
  append(...items){this.children.push(...items);}
  remove(){this.removed=true;}
  attachShadow(){this.shadow=new Element('shadow');return this.shadow;}
  addEventListener(name,fn){this.events[name]=fn;}
 }
 const user=new Input('text','username'),pwd=new Input('password','password');
 const form={querySelectorAll(){return [user,pwd]}};pwd.form=form;
 const document={
  documentElement:{append(e){hosts.push(e)}},
  getElementById(){return null},
  createElement(tag){const el=new Element(tag);if(tag==='button')buttons.push(el);return el},
  querySelectorAll(selector){return selector==='input[type="password"]'?[pwd]:[user,pwd]},
  addEventListener(name,fn){if(name==='input')inputListener=fn;}
 };
 const chrome={runtime:{onMessage:{addListener(fn){onMessage=fn}},sendMessage:async msg=>{outbound.push(msg);if(msg.type==='datensis-stock-check-credential')return {available:true,known};return {ok:true};}},storage:{local:{get:async()=>({ml2cVaultOrigin:'http://127.0.0.1:8001'})}}};
 const win={};win.top=win;
 const ctx={document,window:win,location:{protocol:'https:',origin:'https://app.example.com',hostname:'app.example.com',pathname:'/login'},chrome,HTMLInputElement:Input,Event:class{},console,setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){}};
 vm.runInNewContext(page,ctx);
 return {user,pwd,buttons,hosts,outbound,fire:()=>inputListener({isTrusted:true,target:pwd}),flush:async()=>{let t=timers.splice(0);for(const fn of t)await fn();for(let i=0;i<3;i++)await Promise.resolve();},getListener:()=>onMessage};
}
test('new login proposal requires real typing + explicit user click, then transfers to panel only',async()=>{
 const s=scenario(false);
 assert.equal(s.hosts.length,0);
 s.user.value='user@example.com';s.pwd.value='a-real-user-password';s.fire();await s.flush();
 // Request to panel checks only the username, never a password.
 assert.equal(s.outbound[0].type,'datensis-stock-check-credential');
 assert.equal(s.outbound[0].password,undefined);
 assert.equal(s.hosts.length,1);
 const yes=s.buttons.find(b=>b.textContent==='Enregistrer dans Datensis Stock');
 assert.ok(yes);
 await yes.events.click();
 const responses=[];
 s.getListener()({type:'datensis-stock-take-save-draft',origin:'https://app.example.com'},null,data=>responses.push(data));
 assert.equal(responses.length,1);
 assert.equal(responses[0].approved,true);
 assert.equal(responses[0].username,'user@example.com');
 assert.equal(responses[0].password,'a-real-user-password');
 assert.equal(responses[0].url,'https://app.example.com/login');
});
test('existing account must not receive new-save proposal when panel knows it',async()=>{
 const s=scenario(true);s.user.value='saved@example.com';s.pwd.value='somepass';s.fire();await s.flush();
 assert.equal(s.hosts.length,0);
});
