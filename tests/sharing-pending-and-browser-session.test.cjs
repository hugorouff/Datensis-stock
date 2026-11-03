'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const read=file=>fs.readFileSync(file,'utf8');

test('un compte non initialise est partageable sans envoi de secret en clair',()=>{
  const server=read('src/Controller/AccountShareController.php');
  const browser=read('public/assets/vault.js');
  const login=read('public/assets/login-unified.js');
  const recipientStart=server.indexOf("Route('/recipient'");
  const shareCreate=server.indexOf("Route('',name:'ds_shares_create'");
  assert.ok(recipientStart>=0&&shareCreate>recipientStart);
  const recipient=server.slice(recipientStart,shareCreate);
  assert.match(recipient,/pending.*getSharingPublicKey/);
  assert.doesNotMatch(recipient,/initialiser ses cl[eé]s de partage/);
  assert.match(server,/\$bundle=\$pending \? '\{\}'/);
  assert.doesNotMatch(server,/s\.encrypted_bundle <> :pending/);
  assert.match(server,/\$this->sealed\(json_decode\(\(string\) \$s\['encrypted_bundle'\],true\)\)===null/);
  assert.match(browser,/recipient\.publicKey\?await shareCrypto\.seal\(content,recipient\.publicKey\):null/);
  assert.match(browser,/pending:!recipient\.publicKey/);
  assert.match(browser,/row\.pendingEncryption && row\.recipientPublicKey/);
  assert.match(login,/loadScript\('\/assets\/account-sharing\.js\?v=/);
  assert.match(login,/loadScript\('\/assets\/recipient-search\.js\?v=/);
});

test('une ancienne session est fermee et les jetons renouveles avant connexion normale',async()=>{
  const script=read('public/assets/login-unified.js');
  const handlers={};
  const password={value:'password-for-new-account'};
  const csrf={value:'stale-token'};
  const err={hidden:true,textContent:''};
  const submit={disabled:false,textContent:'Connexion'};
  const form={action:'/login',elements:{_password:password,_csrf_token:csrf},querySelector(){return submit;},addEventListener(name,fn){handlers[name]=fn;}};
  const doc={hidden:false,contains(el){return el===err;},getElementById(id){return ({'login-form':form,'login-js-error':err})[id]||null;},addEventListener(){}};
  let navigated=null, priorSession=true,logoutCount=0, loginCount=0;
  const calls=[];
  const ctx={
    URL,URLSearchParams,FormData:class {constructor(f){assert.equal(f,form);assert.equal(csrf.value,'fresh-login-csrf');}},
    window:{addEventListener(){}},document:doc,
    location:{replace(path){navigated=path;},reload(){}},
    DOMParser:class {parseFromString(){return {querySelector(selector){return selector.includes('_csrf_token')?{value:'fresh-login-csrf'}:null;}};}},
    fetch:async(url,opts={})=>{
      calls.push([url,opts.method||'GET']);
      if(url==='/auth/session')return {ok:true,json:async()=>({authenticated:priorSession,logoutCsrf:'logout-valid'})};
      if(url==='/logout'){
        assert.equal(opts.method,'POST');
        assert.equal(opts.body.get('_csrf_token'),'logout-valid');
        priorSession=false;logoutCount++;
        return {ok:true,url:'http://127.0.0.1:8001/login'};
      }
      if(url==='/login'&&opts.method==='POST'){
        assert.equal(priorSession,false);
        loginCount++;
        return {ok:true,url:'http://127.0.0.1:8001/admin'};
      }
      if(url==='/login')return {ok:true,url:'http://127.0.0.1:8001/login',text:async()=>'<form id="login-form"></form>'};
      throw Error('Unexpected '+url);
    }
  };
  vm.runInNewContext(script,ctx);
  await handlers.submit({preventDefault(){}});
  assert.equal(logoutCount,1);assert.equal(loginCount,1);
  assert.equal(navigated,'/admin');assert.equal(password.value,'');
  assert.deepEqual(calls.map(x=>x[0]),['/auth/session','/logout','/login','/login']);
  assert.equal(err.hidden,true);
});
