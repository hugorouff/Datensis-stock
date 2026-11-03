'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('public/assets/login-unified.js','utf8');
const callbacks=new Map();
const input={value:'test-master-password'};
const error={hidden:true,textContent:''};
const submit={disabled:false,textContent:'Se connecter et déverrouiller'};
const form={
  action:'/login',hidden:false,elements:{_password:input},
  querySelector(){return submit;},
  addEventListener(type,callback){callbacks.set(type,callback);}
};
const oldHead={remove(){}};
const meta={content:'token',cloneNode(){return {content:'token'}}};
const head={querySelector(){return oldHead;},append(){}};
const body={innerHTML:'',append(script){
  loaded.push(script.src);
  // The browser loads these scripts one after the other, in the proper order.
  if(script.onload)script.onload();
}};
const loaded=[];
const nodes={'login-form':form,'login-js-error':error};
const doc={
  hidden:false,body,head,title:'Connexion',
  getElementById(id){return nodes[id]??null;},
  contains(node){return node===error;},
  addEventListener(){},
  createElement(tag){return {src:'',onload:null,onerror:null};}
};
const browser={
  document:doc,
  window:{addEventListener(){}},
  FormData:class{constructor(source){assert.equal(source,form);}},
  URL,URLSearchParams,
  location:{pathname:'/login'},
  history:{replaceState(_a,_b,path){assert.equal(path,'/vault');}},
  DOMParser:class{parseFromString(){return {title:'Coffre',body:{innerHTML:'vault html'},querySelector(){return meta;}};}},
  fetch:async (url,opts)=>{
    if(url==='/login')return {url:'http://127.0.0.1:8001/vault',ok:true};
    if(url==='/vault')return {url:'http://127.0.0.1:8001/vault',ok:true,text:async()=>'<main>coffre</main>'};
    throw new Error('unexpected '+url);
  }
};
browser.window.document=doc;
vm.runInNewContext(source,browser);
(async()=>{
  await callbacks.get('submit')({preventDefault(){}});
  assert.equal(browser.window.__vaultBootstrapPassword,'test-master-password');
  assert.equal(input.value,'');
  assert.equal(doc.title,'Coffre');
  assert.deepEqual(loaded,['/assets/actions-tools.js','/assets/vault-session-guard.js','/assets/vault.js']);
  assert.equal(error.hidden,true);
  console.log('OK: authentification du site et transmission transitoire de la clé au coffre');
})().catch(e=>{console.error(e);process.exitCode=1;});
