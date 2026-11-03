/* Datensis Stock - remplissage et proposition de sauvegarde sur les sites autorises.
 * Les champs du formulaire ne sont lus pour une proposition d'enregistrement
 * qu'apres une saisie de l'utilisateur. Le mot de passe est transmis au panneau
 * exclusivement apres clic sur « Enregistrer dans Datensis Stock ».
 * Aucun identifiant ou mot de passe n'est conserve dans chrome.storage.
 */
'use strict';
(() => {
  if (globalThis.__datensisStockSiteAssistant) return;
  globalThis.__datensisStockSiteAssistant = true;
  if (!['http:', 'https:'].includes(location.protocol) || window.top !== window) return;

  const setValue = (field, value) => {
    if (!field || typeof value !== 'string') return false;
    try {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;
      if (!setter) return false;
      setter.call(field,value);
      field.dispatchEvent(new Event('input',{bubbles:true}));
      field.dispatchEvent(new Event('change',{bubbles:true}));
      return true;
    } catch {return false;}
  };
  const editable = field => !!field && !field.disabled && !field.readOnly && field.getClientRects().length > 0;
  const usernameFields=()=>[...document.querySelectorAll('input')].filter(field=>
    editable(field) && ['text','email'].includes(field.type) &&
    /(?:username|email|login|identifier)/i.test([field.autocomplete,field.name,field.id].join(' ')) &&
    !/(?:search|captcha|code|otp|2fa)/i.test([field.name,field.id].join(' '))
  );
  let lastRequestedField=null;
  let requestPending=false;
  function requestAutofill(reset=false){
    if(reset)lastRequestedField=null;
    if(requestPending)return;
    const passwords=[...document.querySelectorAll('input[type="password"]')].filter(editable);
    if(passwords.length>1)return;
    const target=passwords[0]||(!passwords.length?usernameFields()[0]:null);
    if(!target || (target.value && passwords.length) || (target.value && !passwords.length) || lastRequestedField===target)return;
    requestPending=true;
    lastRequestedField=target;
    chrome.runtime.sendMessage({type:'datensis-stock-autofill-ready',origin:location.origin})
      .catch(()=>{})
      .finally(()=>{requestPending=false;});
  }
  let probeTimer=null;
  const scheduleProbe=()=>{
    if(probeTimer!==null)clearTimeout(probeTimer);
    probeTimer=setTimeout(()=>{probeTimer=null;requestAutofill();},250);
  };

  chrome.runtime.onMessage.addListener((request,_sender,sendResponse) => {
    if(request?.type==='datensis-stock-take-save-draft'){
    if(request.origin!==location.origin || !draftApproved || !draftInput){sendResponse({approved:false});return false;}
    const current=captureFields();
    if(!current || current.passwordInput!==draftInput.passwordInput || current.username!==draftInput.username || current.password!==draftInput.password){
      draftApproved=false;draftInput=null;sendResponse({approved:false});return false;
    }
    draftApproved=false;draftInput=null;dismissed=true;
    sendResponse({approved:true,origin:location.origin,url:current.url,username:current.username,password:current.password});
    return false;
    }
    if(request?.type==='datensis-stock-autofill-probe'){
      requestAutofill(true);
      sendResponse({ok:true});
      return false;
    }
    if (request?.type !== 'datensis-stock-fill') return false;
    if (request.origin !== location.origin || typeof request.password !== 'string' || !request.password) {
      sendResponse({filled:false,error:'Le site ouvert ne correspond pas à cet identifiant.'});return false;
    }
    const passwords = [...document.querySelectorAll('input[type="password"]')].filter(editable);
    if (!passwords.length) {
      // Ex. Microsoft : d'abord l'adresse e-mail, puis le mot de passe.
      const candidates=[...document.querySelectorAll('input')].filter(field=>
        editable(field) && ['text','email'].includes(field.type) &&
        /(?:username|email|login|identifier)/i.test([field.autocomplete,field.name,field.id].join(' ')) &&
        !/(?:search|captcha|code|otp|2fa)/i.test([field.name,field.id].join(' '))
      );
      if(candidates.length===1 && typeof request.username==='string' && request.username){
        if(request.automatic && candidates[0].value)return sendResponse({filled:false,reason:'already-filled'}),false;
        const ok=setValue(candidates[0],request.username);
        sendResponse({filled:ok,onlyUsername:ok});return false;
      }
      sendResponse({filled:false,error:'Aucun formulaire de connexion compatible. Ouvrez la page de connexion.'});return false;
    }
    // Ne pas remplir un formulaire de changement de mot de passe ou d'inscription.
    if (passwords.length !== 1 || /(?:new.password|confirm|repeat)/i.test(passwords[0].autocomplete||'')) {
      sendResponse({filled:false,error:'Plusieurs champs de mot de passe détectés : remplissage manuel nécessaire.'});return false;
    }
    const pwd = passwords[0];
    const form = pwd.form || pwd.closest('form') || document;
    const candidates = [...form.querySelectorAll('input')].filter(field =>
      field !== pwd && editable(field) && ['text','email','tel',''].includes(field.type) &&
      !/(?:search|captcha|code|otp|2fa)/i.test((field.name||'')+' '+(field.id||''))
    );
    const username = candidates.find(field=>/(?:user|email|login|identifiant)/i.test([field.autocomplete,field.name,field.id].join(' '))) || candidates[0];
    const hasUsername = typeof request.username === 'string' && request.username.length>0;
    // En mode automatique ne pas remplacer une saisie existante, meme partielle.
    if(request.automatic && (pwd.value || (hasUsername && username && username.value && username.value!==request.username))){
      sendResponse({filled:false,reason:'already-filled'});return false;
    }
    const ok = setValue(pwd,request.password);
    if (hasUsername && username) setValue(username,request.username);
    sendResponse({filled:ok});return false;
  });
  // Pages dynamiques (SPA, Microsoft SSO) : nouveau formulaire apres navigation.
  // Seules les apparitions de champs declenchent une demande ; pas de boucle DOM.
  if(typeof MutationObserver!=='undefined'){
    const observer=new MutationObserver(records=>{
      if(records.some(record=>[...record.addedNodes].some(node=>
        node.nodeType===1 && (node.matches?.('input') || node.querySelector?.('input'))
      )))scheduleProbe();
    });
    observer.observe(document.documentElement,{childList:true,subtree:true});
  }
  if(typeof setTimeout==='function')setTimeout(()=>requestAutofill(),200);
  // Pas de bouton flottant permanent sur les sites visites.
  // Proposition de sauvegarde seulement apres une SAISIE volontaire dans un
  // formulaire de connexion compatible. Jamais sur inscription/changement de MDP.
  let vaultOrigin='http://127.0.0.1:8001';
  let draftApproved=false, draftInput=null, dismissed=false;
  let captureTimer=null, saveHost=null;
  const captureFields=()=>{
    const passwords=[...document.querySelectorAll('input[type="password"]')].filter(editable);
    if(passwords.length!==1)return null;
    const pwd=passwords[0];
    if(/new-password|one-time-code/i.test(pwd.autocomplete||''))return null;
    const form=pwd.form || pwd.closest('form') || document;
    const fields=[...form.querySelectorAll('input')].filter(field=>field!==pwd && editable(field) && ['text','email','tel',''].includes(field.type) &&
      !/(?:search|captcha|otp|2fa|code)/i.test([field.name,field.id,field.autocomplete].join(' ')));
    const user=fields.find(field=>/(?:user|email|login|identifiant)/i.test([field.name,field.id,field.autocomplete].join(' '))) || (fields.length===1?fields[0]:null);
    if(!user || !user.value?.trim() || !pwd.value || pwd.value.length>4096 || user.value.length>320)return null;
    return {username:user.value.trim(),password:pwd.value,origin:location.origin,url:location.origin+location.pathname,passwordInput:pwd};
  };
  const clearPrompt=()=>{saveHost?.remove();saveHost=null;};
  function showSavePrompt(fields){
    if(saveHost || dismissed || location.origin===vaultOrigin || !document.documentElement)return;
    const host=document.createElement('div');host.id='datensis-stock-save-prompt';
    host.style.cssText='position:fixed;bottom:18px;right:18px;z-index:2147483646;max-width:min(350px,calc(100vw - 24px));pointer-events:none';
    const shadow=host.attachShadow({mode:'closed'});
    const card=document.createElement('div');
    card.style.cssText='pointer-events:auto;background:#fff;color:#16444a;border:1px solid #82c4a8;border-radius:13px;box-shadow:0 8px 32px #00222e50;padding:13px;font:13px/1.45 system-ui,-apple-system,Segoe UI,sans-serif';
    const title=document.createElement('strong');title.textContent='Enregistrer cet identifiant ?';title.style.cssText='display:block;margin-bottom:7px';
    const description=document.createElement('p');description.textContent='Ajouter ce compte à Datensis Stock pour '+location.hostname+' ?';description.style.cssText='margin:0 0 10px;color:#497077';
    const actions=document.createElement('div');actions.style.cssText='display:flex;gap:7px;flex-wrap:wrap';
    const yes=document.createElement('button');yes.type='button';yes.textContent='Enregistrer dans Datensis Stock';yes.style.cssText='cursor:pointer;border:0;border-radius:8px;padding:9px 10px;background:#00778b;color:white;font:600 12px system-ui';
    const no=document.createElement('button');no.type='button';no.textContent='Ignorer';no.style.cssText='cursor:pointer;border:1px solid #c4ded6;border-radius:8px;padding:9px 10px;background:white;color:#16444a;font:600 12px system-ui';
    yes.addEventListener('click',async()=>{
      // Le brouillon reste dans la memoire de CE document, jamais en stockage.
      const current=captureFields();
      if(!current || current.passwordInput!==fields.passwordInput){clearPrompt();return;}
      draftInput=current;draftApproved=true;clearPrompt();
      try{
        await chrome.runtime.sendMessage({type:'datensis-stock-open-for-site'});
        await chrome.runtime.sendMessage({type:'datensis-stock-capture-save-notify'});
      }catch{/* L'utilisateur peut ouvrir le panneau via l'icone de l'extension. */}
    });
    no.addEventListener('click',()=>{dismissed=true;clearPrompt();});
    actions.append(yes,no);card.append(title,description,actions);shadow.append(card);document.documentElement.append(host);saveHost=host;
  }
  async function checkNewCredential(){
    if(dismissed || location.origin===vaultOrigin || draftApproved)return;
    const fields=captureFields();
    if(!fields){clearPrompt();return;}
    let result=null;
    try{result=await chrome.runtime.sendMessage({type:'datensis-stock-check-credential',origin:fields.origin,username:fields.username});}catch{}
    const current=captureFields();
    if(!current || current.passwordInput!==fields.passwordInput || current.username!==fields.username || current.password!==fields.password)return;
    if(result?.known){clearPrompt();return;}
    showSavePrompt(fields);
  }
  if(typeof document.addEventListener==='function'){
    document.addEventListener('input',event=>{
      if(!event.isTrusted || !(event.target instanceof HTMLInputElement))return;
      if(captureTimer!==null)clearTimeout(captureTimer);
      captureTimer=setTimeout(checkNewCredential,450);
    },true);
  }
  chrome.storage.local.get({ml2cVaultOrigin:'http://127.0.0.1:8001'}).then(settings=>{
    if(typeof settings.ml2cVaultOrigin==='string')vaultOrigin=settings.ml2cVaultOrigin;
    if(location.origin===vaultOrigin)clearPrompt();
  }).catch(()=>{});
})();
