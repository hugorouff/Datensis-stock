/* Datensis Stock mini-coffre. Aucun secret, jeton ou cle persistant.
 * Les secrets ne vivent que dans la memoire du panneau lateral.
 * Le panneau garde seul les cles de chiffrement et autorise le remplissage automatique
 * sur les origines enregistrees, tant qu'il reste de-verrouille.
 */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const FALLBACK = 'http://127.0.0.1:8001';
  const enc = new TextEncoder(), dec = new TextDecoder(), ITERATIONS = 600000;
  const fields = ['username','password','url','loginUrls','cardHolder','cardNumber','expiry','cvv','firstName','lastName','email','phone','address','publicKey','privateKey','notes','folder'];
  const typeNames = {login:'Identifiant',note:'Note',card:'Carte',identity:'Identité',ssh:'Clé SSH'};
  const icons = {login:'◆',note:'▤',card:'▣',identity:'◎',ssh:'⌘'};
  const state = {origin:FALLBACK,token:null,expiresAt:0,key:null,items:[],sends:[],selected:null,editing:null,tab:'vault',showSecret:false,siteOnly:false,siteOrigin:null};
  let popupScreen = 'login';
  let popupGeneration=0;
  const popupActive=ticket=>ticket===popupGeneration;
  let detailsFromTrash = false;
  const IDLE_OPTIONS = [0,1,3,5,10,15];
  let idleMinutes = 0;
  let lastActivityAt = Date.now();
  const IDLE_ALARM='datensis-stock-idle-v1';
  let inactivityTimeout=null;
  // Le minuteur local donne une expiration precise tant que le panneau est actif.
  // L'alarme Chromium controle aussi l'expiration lorsqu'il est suspendu.
  function armInactivityWatchdog(){
    if(inactivityTimeout!==null){clearTimeout(inactivityTimeout);inactivityTimeout=null;}
    if(!state.key || idleMinutes===0){disarmInactivityWatchdog();updateIdleCountdown();return;}
    updateIdleCountdown();
    const deadline=lastActivityAt+idleMinutes*60000;
    const delay=Math.max(1,deadline-Date.now());
    inactivityTimeout=setTimeout(()=>{
      inactivityTimeout=null;
      if(!checkInactivity())armInactivityWatchdog();
    },delay);
    // Au minimum 30 secondes pour respecter la frequence autorisee des alarmes MV3.
    try{
      const request=chrome.alarms.create(IDLE_ALARM,{when:Math.max(Date.now()+30000,deadline)});
      if(request?.catch)request.catch(()=>{});
    }catch{ /* Le minuteur local reste actif si les alarmes ne sont pas disponibles. */ }
  }
  function disarmInactivityWatchdog(){
    if(inactivityTimeout!==null){clearTimeout(inactivityTimeout);inactivityTimeout=null;}
    try{
      const request=chrome.alarms.clear(IDLE_ALARM);
      if(request?.catch)request.catch(()=>{});
    }catch{}
  }
  // Aucun secret ni horodatage d'activite n'est conserve dans le stockage de l'extension.
  function updateIdleCountdown(){
    const node=$('idle-countdown');
    if(!node)return;
    if(!state.key){node.textContent='Le coffre est verrouillé.';return;}
    if(idleMinutes===0){node.textContent='Pas de verrouillage pour inactivité. Fermeture et expiration de session toujours actives.';return;}
    const remaining=Math.max(0,Math.ceil((lastActivityAt+idleMinutes*60000-Date.now())/1000));
    node.textContent='Verrouillage dans '+Math.floor(remaining/60)+':'+String(remaining%60).padStart(2,'0')+' sans activité.';
  }
  function checkInactivity() {
    if (!state.key || idleMinutes===0) return false;
    if (Date.now() - lastActivityAt < idleMinutes * 60000) return false;
    lock();
    message('Coffre verrouillé après '+idleMinutes+' minute(s) d’inactivité. Reconnectez-vous.',true);
    return true;
  }
  function recordActivity(event) {
    if (!state.key) return;
    if (checkInactivity()) {
      // Bloquer également l'action qui réveille un panneau suspendu (minuteur ralenti).
      if (event.cancelable) event.preventDefault();
      event.stopImmediatePropagation();
      return;
    }
    lastActivityAt=Date.now();
    armInactivityWatchdog();
  }

  const b64 = bytes => { const chunks=[];for(let i=0;i<bytes.length;i+=8192)chunks.push(String.fromCharCode(...bytes.slice(i,i+8192)));return btoa(chunks.join('')); };
  const unb64 = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
  const rand = n => crypto.getRandomValues(new Uint8Array(n));
  function message(text='',error=false){$('message').textContent=text;$('message').classList.toggle('error',error);}
  function normalizeOrigin(raw){
    let u;try{u=new URL(raw.trim());}catch{throw Error('Adresse du serveur invalide.');}
    if(u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw Error('Indiquez uniquement le domaine (sans chemin ni identifiants).');
    const local=['127.0.0.1','localhost'].includes(u.hostname);
    if(u.protocol!=='https:'&& !(local && u.protocol==='http:'))throw Error('HTTPS est obligatoire hors localhost.');
    return u.origin;
  }
  function screen(which){
    popupScreen=which;
    $('login-screen').hidden=which!=='login';
    $('unlocked-screen').hidden=which!=='unlocked';
    $('lock').hidden=which!=='unlocked';
    $('connection-label').textContent=which==='unlocked'?'Coffre ouvert · session temporaire':'Coffre verrouillé';
    message();
  }
  async function permissionFor(origin,ask=false){
    const u=new URL(origin);
    const pattern=u.protocol+'//'+u.hostname+'/*';
    // Ne pas redemander une permission deja incluse dans host_permissions.
    if(await chrome.permissions.contains({origins:[pattern]}))return true;
    if(!ask)return false;
    return chrome.permissions.request({origins:[pattern]});
  }
  async function fetchApi(path,method='GET',data=null,auth=true){
    if(auth&&(!state.token||Date.now()/1000>=state.expiresAt))throw Error('Session expirée : reconnectez-vous.');
    const options={method,cache:'no-store',credentials:'omit',headers:{Accept:'application/json'}};
    if(auth)options.headers.Authorization='Bearer '+state.token;
    if(method!=='GET'){options.headers['Content-Type']='application/json';options.body=JSON.stringify(data??{});}
    let response;
    try{response=await fetch(state.origin+'/api/extension'+path,options);}
    catch{throw Error('Connexion impossible : vérifiez la connexion à Datensis Stock et les permissions de l’extension.');}
    const contentType=(response.headers.get('content-type')||'').toLowerCase();
    let result=null;
    if(contentType.includes('json')){
      try{result=await response.json();}
      catch{result=null;}
    }
    if(!response.ok){
      if(response.status===401&&auth)lock(false);
      if(response.status===429){
        const retry=Number.parseInt(response.headers.get('retry-after')||String(result?.retryAfter||''),10);
        const delay=Number.isFinite(retry)&&retry>0?` Attendez environ ${Math.ceil(retry/60)} minute(s).`:'';
        throw Error((result?.error||'Trop de tentatives de connexion.')+delay);
      }
      // Ne jamais afficher le HTML du serveur (traces, jetons, chemins locaux).
      const error=typeof result?.error==='string'?result.error:`Erreur du serveur HTTP ${response.status}. Consultez les logs Symfony.`;
      const incident=typeof result?.incident==='string'?` (incident ${result.incident})`:'';
      throw Error(error+incident);
    }
    if(!result||typeof result!=='object')throw Error('Réponse JSON invalide du serveur : vérifiez la réponse de Datensis Stock.');
    return result;
  }
  async function deriveKey(password,salt,kdfVersion=2){
    if(kdfVersion===1){
      const material=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveKey']);
      return crypto.subtle.deriveKey({name:'PBKDF2',salt:unb64(salt),iterations:ITERATIONS,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    }
    if(kdfVersion!==2||!window.hashwasm?.argon2id)throw Error('Module Argon2id indisponible ou version de coffre inconnue.');
    const raw=await window.hashwasm.argon2id({password:enc.encode(password),salt:unb64(salt),parallelism:1,iterations:3,memorySize:65536,hashLength:32,outputType:'binary'});
    return crypto.subtle.importKey('raw',raw,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  async function encrypt(value,key){
    const iv=rand(12),data=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(value)));
    return {v:1,iv:b64(iv),data:b64(new Uint8Array(data))};
  }
  async function decrypt(payload,key){
    if(payload?.v!==1)throw Error('Version de chiffrement inconnue.');
    const value=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(payload.iv)},key,unb64(payload.data));
    return JSON.parse(dec.decode(value));
  }
  async function loadEncryptedState(vault,password,ticket){
    if(!popupActive(ticket))throw Error('Mini-coffre verrouillé.');
    let data=vault;
    const newVault=!data.initialized;
    const kdfVersion=newVault?2:(data.kdfVersion||1);
    const salt=newVault?b64(rand(16)):data.salt;
    const key=await deriveKey(password,salt,kdfVersion);
    if(!popupActive(ticket))throw Error('Mini-coffre verrouillé.');
    if(newVault){
      const check=await encrypt('vault-ready-v1',key);
      if(!popupActive(ticket))throw Error('Mini-coffre verrouillé.');
      await fetchApi('/initialize','POST',{salt,check,kdfVersion});
      data=await fetchApi('/state');
      if(!popupActive(ticket))throw Error('Mini-coffre verrouillé.');
    }else{
      let check;
      try{check=await decrypt(data.check,key);}catch{throw Error('Clé du coffre différente. Déverrouillez et convertissez une seule fois votre ancien coffre depuis le site.');}
      if(check!=='vault-ready-v1')throw Error('Mot de passe du coffre incorrect.');
    }
    const items=await Promise.all(data.entries.map(async item=>({id:item.id,updatedAt:item.updatedAt,value:await decrypt(item.payload,key)})));
    if(!popupActive(ticket))throw Error('Mini-coffre verrouillé.');
    state.key=key;state.items=items;state.selected=null;state.editing=null;
    lastActivityAt=Date.now();
    armInactivityWatchdog();
  }
  async function login(e){
    e.preventDefault();message();
    const password=$('login-password').value, email=$('login-email').value.trim();
    if(!email||!password)return message('Adresse et mot de passe requis.',true);
    const ticket=popupGeneration;
    const button=$('login-submit');button.disabled=true;
    try{
      if(!await permissionFor(state.origin,false))throw Error('Le serveur Datensis Stock n’est pas autorisé par Edge. Vérifiez les permissions de l’extension.');
      const result=await fetchApi('/session','POST',{email,password},false);
      if(!popupActive(ticket))throw Error('Mini-coffre verrouillé.');
      if(typeof result.token!=='string'||result.token.length!==43||
         !Number.isFinite(result.expiresAt)||!result.state||typeof result.state!=='object'){
        throw Error('Réponse de connexion incomplète. Vérifiez la version du serveur Datensis Stock.');
      }
      state.token=result.token;state.expiresAt=result.expiresAt;
      try{await loadEncryptedState(result.state,password,ticket);}catch(err){await revoke();throw err;}
      $('login-password').value='';
      try{await loadSends();}catch(err){console.warn('Chargement des Sends impossible :',err.message);}
      if(!popupActive(ticket))return;
      state.siteOnly=siteMatches().length>0;screen('unlocked');switchTab('vault');renderList();
      // Si la page etait deja ouverte avant le de-verrouillage du panneau.
      probeActiveSite().catch(()=>{});
      consumePendingCredentialDraft().catch(()=>{});
    }catch(err){message(err.message,true);}
    finally{button.disabled=false;$('login-password').value='';}
  }
  async function revoke(){
    if(!state.token)return;
    // Le jeton reste en memoire seulement, et expire de toute facon sous 10 minutes.
    try{await fetchApi('/logout','POST');}catch{}
    state.token=null;
  }
  function lock(doRevoke=true){
    disarmInactivityWatchdog();
    popupGeneration++;
    const token=state.token,origin=state.origin;
    state.token=null;state.expiresAt=0;state.key=null;state.items=[];state.sends=[];state.selected=null;state.editing=null;state.showSecret=false;state.siteOnly=false;
    $('search').value='';$('login-password').value='';$('generated').value='';$('item-list').replaceChildren();$('detail-fields').replaceChildren();
    $('editor-form').reset();$('send-form').reset();$('send-list').replaceChildren();
    $('send-entry').replaceChildren(new Option('Choisir un identifiant enregistré…',''));
    updateSendMode();
    $('send-result-link').value='';$('send-created').hidden=true;$('send-options').open=false;
    screen('login');
    updateIdleCountdown();
    if(doRevoke&&token){fetch(origin+'/api/extension/logout',{method:'POST',credentials:'omit',cache:'no-store',headers:{Authorization:'Bearer '+token}}).catch(()=>{});}
  }
  function switchTab(name){
    state.tab=name;
    document.querySelectorAll('[data-tab]').forEach(button=>{
      const active=button.dataset.tab===name;
      button.classList.toggle('active',active);button.setAttribute('aria-selected',String(active));
    });
    document.querySelectorAll('.panel').forEach(panel=>panel.hidden=panel.id!=='tab-'+name);
    message();
    if(name==='vault'&&state.key)renderList();
    if(name==='send'&&state.key){renderSendEntries();renderSends();}
    if(name==='settings')updateBrowserPasswordSetting().catch(()=>{});
  }
  // Un site est identifié par son origine depuis la barre d'adresse.
  // Les chemins sont ignorés ; les domaines de SSO sont ajoutés explicitement.
  // Jamais de correspondance approximative entre domaines, sous-domaines ou ports.
  function matchHost(value){
    if(!state.siteOrigin||value.type!=='login')return false;
    const urls=[value.url,...String(value.loginUrls||'').split(/[\n,;]/)];
    return urls.some(raw=>{
      if(typeof raw!=='string'||!raw.trim())return false;
      try{
        const u=new URL(raw.trim());
        const local=['localhost','127.0.0.1'].includes(u.hostname);
        return (u.protocol==='https:' || (local&&u.protocol==='http:')) && u.origin===state.siteOrigin;
      }catch{return false;}
    });
  }
  const siteMatches=()=>state.items.filter(x=>x.value.type==='login'&&!x.value.deletedAt&&matchHost(x.value));
  function originPattern(origin){const u=new URL(origin);return u.protocol+'//'+u.hostname+'/*';}
  async function enableAssistantForSite(origin,tab){
    const u=new URL(origin);
    if(!['https:','http:'].includes(u.protocol) || (u.protocol==='http:'&&!['localhost','127.0.0.1'].includes(u.hostname))){
      throw Error('Le remplissage est réservé aux sites HTTPS et aux sites locaux de développement.');
    }
    const pattern=originPattern(origin);
    if(!await chrome.permissions.contains({origins:[pattern]})){
      if(!await chrome.permissions.request({origins:[pattern]}))throw Error('Autorisation refusée pour ce site.');
    }
    // Enregistrer le script sur le site choisi, pas sur tous les sites ouverts.
    if(!['localhost','127.0.0.1'].includes(u.hostname)){
      const siteId='ds-site-'+Array.from(new TextEncoder().encode(origin)).map(v=>v.toString(16).padStart(2,'0')).join('').slice(0,120);
      if(!await chrome.scripting.getRegisteredContentScripts({ids:[siteId]}).then(items=>items.length>0)){
        await chrome.scripting.registerContentScripts([{id:siteId,matches:[pattern],js:['site-assistant.js'],runAt:'document_idle',allFrames:false,persistAcrossSessions:true}]);
      }
    }
    if(tab?.id && new URL(tab.url).origin===origin){
      await chrome.scripting.executeScript({target:{tabId:tab.id},files:['site-assistant.js']});
    }
  }
  async function currentSiteTab(){
    const tabs=await chrome.tabs.query({active:true,currentWindow:true});
    const tab=tabs.find(x=>{try{return ['http:','https:'].includes(new URL(x.url||'').protocol);}catch{return false;}});
    return tab||null;
  }
  // Pas de remplissage automatique : l'utilisateur choisit une fiche et clique.
  // Aucun secret ne passe dans le service worker, le stockage ou l'URL.
  async function fillOnSite(item){
    if(!state.key||checkInactivity())return;
    if(!item||!matchHost(item.value)||!item.value.password)return message('Ce mot de passe ne correspond pas au site actif.',true);
    try{
      const tab=await currentSiteTab();
      if(!tab||new URL(tab.url).origin!==state.siteOrigin)throw Error('Ouvrez la page du site concerné.');
      // Permission demandée uniquement à l'action de l'utilisateur, site par site.
      // Pour la correspondance par URL, aucune lecture du contenu du site n'est nécessaire.
      await enableAssistantForSite(state.siteOrigin,tab);
      const result=await chrome.tabs.sendMessage(tab.id,{type:'datensis-stock-fill',origin:state.siteOrigin,username:String(item.value.username||''),password:item.value.password});
      if(!result?.filled)throw Error(result?.error||'Aucun formulaire de connexion détecté. Ouvrez la page de connexion du site.');
      message(result.onlyUsername?'Identifiant rempli. Cliquez sur Suivant, puis de nouveau sur Remplir pour le mot de passe.':'Identifiant et mot de passe renseignés. Vérifiez puis validez la connexion.');
    }catch(err){message(err.message||'Ouvrez ou actualisez la page du site.',true);}
  }
  // Rafraichissement des fiches modifiees depuis le site web, en memoire seulement.
  // Une session API expiree ne change pas le reglage de verrouillage choisi :
  // le panneau garde ses fiches deja dechiffrees jusqu'a sa fermeture.
  let lastVaultSyncAt=0;
  async function refreshVaultCache(){
    if(!state.key || !state.token || Date.now()/1000>=state.expiresAt || Date.now()-lastVaultSyncAt<8000)return;
    const ticket=popupGeneration, key=state.key;
    lastVaultSyncAt=Date.now();
    try{
      const result=await fetchApi('/state');
      if(!popupActive(ticket) || state.key!==key || !Array.isArray(result.entries))return;
      const items=await Promise.all(result.entries.map(async item=>({
        id:item.id,updatedAt:item.updatedAt,value:await decrypt(item.payload,key)
      })));
      if(!popupActive(ticket) || state.key!==key)return;
      state.items=items;
      if(state.tab==='vault')renderList();
    }catch(err){console.warn('Synchronisation des fiches indisponible :',err.message);}
  }
  // Remplissage automatique sous controle du panneau, jamais du service worker.
  // Pas de stockage de cle ou mot de passe, et aucun envoi sans correspondance exacte.
  async function autoFillForSender(sender){
    if(!state.key || checkInactivity() || !sender?.tab?.id || !sender.tab.active) return {filled:false};
    const ticket=popupGeneration;
    try{
      const tab=await chrome.tabs.get(sender.tab.id);
      const activeTabs=await chrome.tabs.query({active:true,windowId:tab.windowId});
      if(!tab.active || activeTabs[0]?.id!==tab.id || tab.id!==sender.tab.id)return {filled:false};
      const current=new URL(tab.url||'');
      if(current.protocol!=='https:' && !(current.protocol==='http:' && ['localhost','127.0.0.1'].includes(current.hostname)))return {filled:false};
      if(sender.origin!==current.origin || current.origin===state.origin)return {filled:false};
      // Ne pas se fier a un onglet precedent ; la comparaison inclut le port.
      await refreshVaultCache();
      if(!popupActive(ticket) || !state.key)return {filled:false};
      state.siteOrigin=current.origin;
      const matches=siteMatches();
      if(matches.length!==1 || !matches[0].value.password)return {filled:false};
      if(!state.key || !popupActive(ticket) || checkInactivity())return {filled:false};
      const item=matches[0];
      return await chrome.tabs.sendMessage(tab.id,{
        type:'datensis-stock-fill',origin:current.origin,automatic:true,
        username:String(item.value.username||''),password:item.value.password
      });
    }catch{return {filled:false};}
  }
  async function probeActiveSite(){
    if(!state.key || checkInactivity())return;
    const tab=await currentSiteTab();
    if(!tab?.id)return;
    try{await chrome.tabs.sendMessage(tab.id,{type:'datensis-stock-autofill-probe'});}catch{}
  }
  // L'utilisateur a choisi de sauvegarder depuis le site. Le mot de passe
  // ne circule qu'entre le script de CET onglet et ce panneau de-verrouille.
  // Aucun stockage temporaire en clair ni envoi au service worker.
  let collectingDraft=false;
  async function consumePendingCredentialDraft(){
    if(collectingDraft || !state.key || checkInactivity())return;
    collectingDraft=true;
    try{
      const tab=await currentSiteTab();
      if(!tab?.id)return;
      const origin=new URL(tab.url).origin;
      if(origin===state.origin || (new URL(tab.url).protocol!=='https:' && !['localhost','127.0.0.1'].includes(new URL(tab.url).hostname)))return;
      const result=await chrome.tabs.sendMessage(tab.id,{type:'datensis-stock-take-save-draft',origin});
      if(!result?.approved || result.origin!==origin || typeof result.username!=='string' || typeof result.password!=='string' || !result.password)return;
      // Ne pas dupliquer une fiche de meme site + identifiant.
      state.siteOrigin=origin;
      await refreshVaultCache();
      const exists=siteMatches().some(item=>String(item.value.username||'').trim().toLowerCase()===result.username.trim().toLowerCase());
      if(exists){message('Cet identifiant existe déjà dans votre coffre. Utilisez Modifier pour le mettre à jour.');return;}
      switchTab('vault');
      openEditor();
      $('entry-type').value='login';
      editorFields();
      $('entry-name').value=new URL(origin).hostname.replace(/^www\./,'');
      $('entry-username').value=result.username;
      $('entry-password').value=result.password;
      $('entry-url').value=result.url;
      message('Nouvel identifiant détecté : vérifiez la fiche, puis cliquez sur « Enregistrer dans mon coffre ».');
    }catch{/* Aucun brouillon present ou le script du site n'est plus disponible. */}
    finally{collectingDraft=false;}
  }
  async function checkCredentialFromSender(message,sender){
    if(!state.key || checkInactivity() || !sender?.tab?.id || !sender.tab.active)return {available:false};
    try{
      const tab=await chrome.tabs.get(sender.tab.id);
      if(tab.id!==sender.tab.id || !tab.active || new URL(tab.url).origin!==sender.origin || sender.origin===state.origin)return {available:false};
      await refreshVaultCache();
      state.siteOrigin=sender.origin;
      const username=String(message.username||'').trim().toLowerCase();
      return {available:true,known:siteMatches().some(item=>String(item.value.username||'').trim().toLowerCase()===username)};
    }catch{return {available:false};}
  }
  function updateSiteSuggestions(){
    const box=$('site-suggestions');
    const matches=siteMatches();
    box.hidden=!state.siteOrigin;
    $('site-suggestions-title').textContent='Identifiants pour '+(state.siteOrigin||'ce site');
    $('site-suggestions-status').textContent=matches.length?matches.length+' identifiant(s) disponibles. Choisissez « Remplir » ou ouvrez une fiche.':'Aucun identifiant lié à ce site. Créez une fiche ou ajoutez cette adresse dans « Autre adresse de connexion ».';
    $('matched').textContent=state.siteOnly?'Tous les éléments':'Site actif';
    const permissionButton=$('site-permission');
    permissionButton.hidden=true;
    if(state.siteOrigin&&state.siteOrigin.startsWith('https://')){
      chrome.permissions.contains({origins:[originPattern(state.siteOrigin)]}).then(granted=>{if(state.key&&state.siteOrigin&&box.hidden===false)permissionButton.hidden=granted;}).catch(()=>{});
    }
  }
  function visibleItems(){
    const filter=$('filter').value,query=$('search').value.trim().toLocaleLowerCase('fr');
    return state.items.filter(item=>{
      const v=item.value,deleted=!!v.deletedAt;
      if(v.type==='folder')return false;
      if(filter==='trash'?!deleted:deleted)return false;
      if(filter==='favorite'&&!v.favorite)return false;
      if(filter!=='all'&&filter!=='favorite'&&filter!=='trash'&&v.type!==filter)return false;
      if(state.siteOnly&&!matchHost(v))return false;
      return !query||[v.name,v.username,v.notes].some(s=>String(s??'').toLocaleLowerCase('fr').includes(query));
    });
  }
  function renderList(){
    if(!state.key)return;
    const list=$('item-list');list.replaceChildren();
    updateSiteSuggestions();
    const entries=visibleItems();
    $('list-count').textContent=entries.length+' élément(s)'+(state.siteOnly?' pour le site ouvert':'');
    if(!entries.length){const p=document.createElement('p');p.className='empty';p.textContent='Aucun élément correspondant.';list.append(p);return;}
    for(const item of entries){
      const v=item.value,b=document.createElement('button');b.type='button';b.className='entry';
      const mark=document.createElement('span');mark.className='entry-mark';mark.textContent=icons[v.type]||'◆';
      const copy=document.createElement('span');copy.className='entry-copy';
      const name=document.createElement('strong');name.textContent=(v.favorite?'★ ':'')+(v.name||'Sans nom');
      const sub=document.createElement('small');sub.textContent=[v.username].filter(Boolean).join(' · ')||typeNames[v.type]||'Fiche';
      const chevron=document.createElement('span');chevron.className='entry-chevron';chevron.textContent='›';
      copy.append(name,sub);b.append(mark,copy);
      if(v.type==='login'&&matchHost(v)&&v.password){
        const fill=document.createElement('button');fill.type='button';fill.className='outline slim';fill.textContent='Remplir';
        fill.setAttribute('aria-label','Remplir '+(v.name||'identifiant')+' sur le site actif');
        fill.onclick=e=>{e.stopPropagation();fillOnSite(item);};
        // La ligne est un bouton ; eviter un bouton imbrique dans un bouton.
        const wrapper=document.createElement('div');wrapper.className='entry-with-action';wrapper.append(b,fill);
        b.append(chevron);b.addEventListener('click',()=>showItem(item.id));list.append(wrapper);
      }else{b.append(chevron);b.addEventListener('click',()=>showItem(item.id));list.append(b);} 
    }
  }
  function showArea(name){
    $('list-area').hidden=name!=='list';$('detail-area').hidden=name!=='detail';$('editor-area').hidden=name!=='editor';
    message();
  }
  function makeDetailField(label,value,secret=false,copyAllowed=true){
    if(value===undefined||value===null||value==='')return;
    const row=document.createElement('div');row.className='field-card';
    const key=document.createElement('small');key.textContent=label;
    const content=document.createElement('div');content.className='secret-row';
    const text=document.createElement('span');text.className='value';
    let shown=!secret;
    const reveal=()=>{text.textContent=shown?String(value):'••••••••••••';};
    reveal();content.append(text);
    const actions=document.createElement('div');actions.className='field-actions';
    if(secret){const b=document.createElement('button');b.type='button';b.textContent='Voir';b.setAttribute('aria-label','Afficher '+label);b.onclick=()=>{shown=!shown;reveal();b.textContent=shown?'Masquer':'Voir';};actions.append(b);}
    if(copyAllowed){const b=document.createElement('button');b.type='button';b.textContent='Copier';b.setAttribute('aria-label','Copier '+label);b.onclick=()=>copyText(String(value));actions.append(b);}
    content.append(actions);row.append(key,content);$('detail-fields').append(row);
  }
  function showItem(id){
    const item=state.items.find(x=>x.id===id);if(!item)return;
    state.selected=id;state.showSecret=false;detailsFromTrash=!!item.value.deletedAt;
    $('detail-name').textContent=item.value.name||'Sans nom';$('detail-type').textContent=typeNames[item.value.type]||item.value.type;
    $('detail-fields').replaceChildren();
    const v=item.value;
    if(v.type==='login'){
      makeDetailField('Identifiant',v.username,false,true);
      makeDetailField('Mot de passe',v.password,true,true);
      makeDetailField('Adresse du site',v.url,false,true);

    }else if(v.type==='note'){
      makeDetailField('Contenu de la note sécurisée',v.notes,false,true);
    }else if(v.type==='card'){
      makeDetailField('Titulaire',v.cardHolder,false,true);
      makeDetailField('Numéro de carte',v.cardNumber,true,true);
      makeDetailField('Expiration',v.expiry,false,false);
      makeDetailField('Code',v.cvv,true,true);
    }else if(v.type==='identity'){
      for(const [k,label] of [['firstName','Prénom'],['lastName','Nom'],['email','E-mail'],['phone','Téléphone'],['address','Adresse']])makeDetailField(label,v[k],false,true);
    }else if(v.type==='ssh'){
      makeDetailField('Clé publique',v.publicKey,false,true);
      makeDetailField('Clé privée',v.privateKey,true,true);
    }
    $('fill-site').hidden=!!v.deletedAt||v.type!=='login'||!matchHost(v)||!v.password;
    $('favorite').textContent=v.favorite?'★ Retirer le favori':'☆ Favori';
    $('trash').textContent=v.deletedAt?'Restaurer':'Corbeille';
    $('edit').hidden=!!v.deletedAt;
    $('share-entry').hidden=!!v.deletedAt||v.type!=='login'||typeof v.password!=='string'||!v.password;
    $('favorite').hidden=!!v.deletedAt;
    showArea('detail');
  }
  function knownFolders(){
    const folders=new Set();
    for(const item of state.items){
      if(item.value.deletedAt)continue;
      const p=String(item.value.type==='folder'?(item.value.path||item.value.folder||''):(item.value.folder||'')).trim();
      if(!p)continue;
      const parts=p.split('/');if(parts.length>4||parts.some(part=>!part||part.length>80))continue;
      for(let n=1;n<=parts.length;n++)folders.add(parts.slice(0,n).join('/'));
    }
    return [...folders].sort((a,b)=>a.localeCompare(b,'fr'));
  }
  function fillFolderSelect(select,values,placeholder){
    const old=select.value;select.replaceChildren(new Option(placeholder,''));
    for(const path of values)select.add(new Option('  '.repeat(path.split('/').length-1)+path,path));
    select.value=values.includes(old)?old:'';
  }
  function refreshFolders(){
    const paths=knownFolders();
    fillFolderSelect($('entry-folder'),paths,'Sans dossier');
    fillFolderSelect($('entry-folder-parent'),paths.filter(s=>s.split('/').length<4),'Nouvelle entreprise / société / cabinet');
  }
  $('entry-folder-new').onclick=()=>{$('entry-folder-create').hidden=!$('entry-folder-create').hidden;refreshFolders();};
  $('entry-folder-confirm').onclick=async()=>{
    const name=$('entry-folder-name').value.trim(),parent=$('entry-folder-parent').value;
    if(!name||name.length>80||/[\/\\\x00-\x1f]/.test(name)||name==='.'||name==='..')return message('Nom de dossier invalide.',true);
    const path=parent?parent+'/'+name:name;
    if(path.split('/').length>4||knownFolders().includes(path))return message('Dossier en double ou profondeur trop importante.',true);
    const ticket=popupGeneration;
    try{
      const payload=await encrypt({type:'folder',name,folder:path,path,favorite:false},state.key);
      const res=await fetchApi('/entries','POST',{payload});
      if(!popupActive(ticket)||!state.key)return;
      state.items.push({id:res.id,updatedAt:res.updatedAt,value:{type:'folder',name,folder:path,path,favorite:false}});
      refreshFolders();$('entry-folder').value=path;$('entry-folder-create').hidden=true;$('entry-folder-name').value='';message('Dossier créé.');
    }catch(err){message(err.message,true);}
  };
  function editorFields(){const type=$('entry-type').value;document.querySelectorAll('[data-fields]').forEach(root=>root.hidden=root.dataset.fields!==type);}
  function openEditor(id=null){
    state.editing=id;
    const item=state.items.find(x=>x.id===id);
    const v=item?.value||{};
    $('editor-title').textContent=id?'Modifier la fiche':'Nouvelle fiche';
    $('editor-form').reset();
    refreshFolders();$('entry-folder-create').hidden=true;
    $('entry-type').value=v.type||'login';
    $('entry-name').value=v.name||'';
    for(const field of fields){const element=$('entry-'+field);if(element)element.value=String(v[field]??'');}
    if(!id&&state.siteOrigin&&$('entry-type').value==='login')$('entry-url').value=state.siteOrigin+'/';
    $('entry-favorite').checked=!!v.favorite;
    editorFields();showArea('editor');
  }
  async function saveEditor(e){
    e.preventDefault();message();
    if(checkInactivity())return;
    const ticket=popupGeneration;
    const button=$('entry-save');button.disabled=true;
    try{
      const old=state.items.find(x=>x.id===state.editing);
      const type=$('entry-type').value;
      const value={...(old?.value||{}),type,name:$('entry-name').value.trim(),favorite:$('entry-favorite').checked};
      if(!value.name)throw Error('Donnez un nom à cette fiche.');
      for(const field of fields){const element=$('entry-'+field);if(element)value[field]=element.value;}
      if(type==='login'){
        const addresses=[value.url,...String(value.loginUrls||'').split(/[\n,;]/)].map(x=>String(x||'').trim()).filter(Boolean);
        if(addresses.length>11)throw Error('10 adresses de connexion supplémentaires maximum.');
        for(const raw of addresses){
          try{
            const u=new URL(raw);
            if(u.username||u.password||!['http:','https:'].includes(u.protocol))throw 0;
            if(u.protocol==='http:'&&!['localhost','127.0.0.1'].includes(u.hostname))throw 0;
          }catch{throw Error('Chaque adresse de connexion doit être une URL HTTPS (HTTP uniquement en local).');}
        }
      }
      // Preserver les champs supplementaires anciens (rotation, notes de suivi, historique...) sans les detruire.
      const payload=await encrypt(value,state.key);
      if(old){
        const response=await fetchApi('/entries/'+encodeURIComponent(old.id),'PUT',{payload});
        if(!popupActive(ticket)||checkInactivity()||!state.key)return;
        old.value=value;old.updatedAt=response.updatedAt;
        showItem(old.id);
      }else{
        const response=await fetchApi('/entries','POST',{payload});
        if(!popupActive(ticket)||checkInactivity()||!state.key)return;
        state.items.unshift({id:response.id,updatedAt:response.updatedAt,value});
        showItem(response.id);
      }
      message('Fiche enregistrée et chiffrée.');
    }catch(err){if(popupActive(ticket)&&state.key)message(err.message,true);}
    finally{button.disabled=false;}
  }
  async function updateSelected(modifier){
    if(checkInactivity())return;
    const ticket=popupGeneration;
    const item=state.items.find(x=>x.id===state.selected);if(!item)return;
    try{
      const value={...item.value};modifier(value);
      const payload=await encrypt(value,state.key);
      const result=await fetchApi('/entries/'+encodeURIComponent(item.id),'PUT',{payload});
      if(!popupActive(ticket)||checkInactivity()||!state.key)return;
      item.value=value;item.updatedAt=result.updatedAt;
      showItem(item.id);renderList();
    }catch(err){if(popupActive(ticket)&&state.key)message(err.message,true);}
  }
  function urlB64(bytes){return b64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');}
  async function loadSends(){
    const data=await fetchApi('/sends');
    const ticket=popupGeneration;
    const sends=await Promise.all(data.sends.map(async s=>({...s,owner:await decrypt(s.ownerPayload,state.key)})));
    if(!popupActive(ticket)||!state.key)return;
    state.sends=sends;
  }
  function sendUrl(s){return state.origin+'/s/'+s.owner.token+'#k='+s.owner.key;}
  function renderSends(){
    if(!state.key)return;
    const list=$('send-list');list.replaceChildren();
    if(!state.sends.length){const p=document.createElement('p');p.className='empty';p.textContent='Aucun Send créé. Utilisez + pour partager un texte.';list.append(p);return;}
    for(const s of state.sends){
      const row=document.createElement('div');row.className='send-row';
      const head=document.createElement('div');head.className='send-title';
      const name=document.createElement('strong');name.textContent=s.owner.name||'Sans nom';
      const stat=document.createElement('small');
      const used=s.maxViews!==null&&s.views>=s.maxViews;
      const expired=Date.parse(s.expiresAt)<=Date.now();
      stat.textContent=expired?'Expiré':s.disabled?'Désactivé':used?'Limite atteinte':'Actif';head.append(name,stat);
      const sub=document.createElement('small');sub.textContent='Expire : '+new Date(s.expiresAt).toLocaleString('fr-FR')+' · Lectures : '+s.views+(s.maxViews===null?'':' / '+s.maxViews);
      const actions=document.createElement('div');actions.className='send-actions';
      const copy=document.createElement('button');copy.className='outline';copy.type='button';copy.textContent='Copier le lien';copy.onclick=()=>copyText(sendUrl(s));actions.append(copy);
      if(!expired){const toggle=document.createElement('button');toggle.className='outline';toggle.type='button';toggle.textContent=s.disabled?'Activer':'Désactiver';toggle.onclick=async()=>{
        try{await fetchApi('/sends/'+encodeURIComponent(s.id),'PATCH',{disabled:!s.disabled});s.disabled=!s.disabled;renderSends();}catch(err){message(err.message,true);}
      };actions.append(toggle);}
      const remove=document.createElement('button');remove.className='danger-outline';remove.type='button';remove.textContent='Supprimer';remove.onclick=async()=>{
        if(!confirm('Supprimer définitivement ce partage ?'))return;
        try{await fetchApi('/sends/'+encodeURIComponent(s.id),'DELETE');state.sends=state.sends.filter(x=>x.id!==s.id);renderSends();}catch(err){message(err.message,true);}
      };actions.append(remove);
      row.append(head,sub,actions);list.append(row);
    }
  }
  function shareableLogins(){
    // Les fiches dans la corbeille, sans mot de passe ou non-login sont exclues.
    return state.items.filter(item=>item.value.type==='login'&&!item.value.deletedAt&&
      typeof item.value.password==='string'&&item.value.password.length>0)
      .sort((a,b)=>String(a.value.name||'').localeCompare(String(b.value.name||''),'fr'));
  }
  function renderSendEntries(preferredId=null){
    const select=$('send-entry');
    const previous=preferredId||select.value;
    select.replaceChildren(new Option('Choisir un identifiant enregistré…',''));
    const entries=shareableLogins();
    for(const item of entries){
      // Seulement le titre et l'identifiant : jamais de mot de passe dans le DOM.
      const title=String(item.value.name||'Sans nom');
      const username=String(item.value.username||'');
      select.add(new Option(title+(username?' — '+username:''),item.id));
    }
    if(entries.some(item=>item.id===previous))select.value=previous;
    updateSendPreview();
  }
  function updateSendPreview(){
    const item=shareableLogins().find(entry=>entry.id===$('send-entry').value);
    $('send-entry-preview').textContent=item?
      'Fiche : '+String(item.value.name||'Sans nom')+' · Identifiant : '+String(item.value.username||'non renseigné')+' · Mot de passe : ••••••••':
      (shareableLogins().length?'Sélectionnez la fiche dont vous souhaitez partager le mot de passe.':'Aucun mot de passe enregistré dans le coffre. Créez une fiche Identifiant ou choisissez « Un texte libre ».');
  }
  function updateSendMode(){
    const isLogin=$('send-mode-login').checked;
    $('send-login-area').hidden=!isLogin;
    $('send-text-area').hidden=isLogin;
    $('send-entry').disabled=!isLogin;
    $('send-text').disabled=isLogin;
    updateSendPreview();
  }
  function prepareSendFromEntry(id){
    if(checkInactivity()||!state.key)return;
    $('send-mode-login').checked=true;
    $('send-form').reset();
    $('send-mode-login').checked=true;
    updateSendMode();
    switchTab('send');
    renderSendEntries(id);
    $('send-entry').focus();
    message('Vérifiez la fiche sélectionnée, puis créez le lien de partage.');
  }
  function buildSendContent(){
    if($('send-mode-text').checked){
      const text=$('send-text').value;
      if(!text.trim())throw Error('Saisissez un texte à partager.');
      return {text,hidden:false,defaultName:'Partage du '+new Date().toLocaleString('fr-FR',{dateStyle:'short',timeStyle:'short'})};
    }
    const item=shareableLogins().find(entry=>entry.id===$('send-entry').value);
    if(!item)throw Error('Choisissez un mot de passe enregistré dans votre coffre.');
    const v=item.value;
    const title=String(v.name||'Sans nom');
    const lines=['Fiche : '+title];
    if(v.username)lines.push('Identifiant : '+String(v.username));
    lines.push('Mot de passe : '+v.password);
    const note=$('send-login-note').value.trim();
    if(note)lines.push('','Message : '+note);
    const text=lines.join('\n');
    if(text.length>20000)throw Error('Ce partage est trop volumineux.');
    return {text,hidden:true,defaultName:'Accès — '+title.slice(0,140),title};
  }
  async function createSend(e){
    e.preventDefault();message();
    if(checkInactivity())return;
    const ticket=popupGeneration;
    const button=$('send-create');button.disabled=true;
    try{
      const content=buildSendContent();
      const {text,hidden}=content;
      const name=$('send-name').value.trim()||content.defaultName;
      const rawLimit=$('send-max').value.trim(),pass=$('send-password').value;
      if(pass && pass.length<8)throw Error('Le mot de passe du partage doit avoir au moins 8 caractères.');
      if(rawLimit && (!Number.isInteger(Number(rawLimit))||Number(rawLimit)<1||Number(rawLimit)>1000))throw Error('Nombre de lectures invalide.');
      if(content.title&&!confirm('Partager le mot de passe de « '+content.title+' » ?\n\nLe destinataire pourra lire ce mot de passe avec le lien.'))return;
      const keyBytes=rand(32),sendKey=await crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['encrypt','decrypt']);
      const token=urlB64(rand(32)),key=urlB64(keyBytes);
      const payload=await encrypt({kind:'text',name,text,hidden},sendKey);
      if(!popupActive(ticket)||checkInactivity()||!state.key)return;
      const ownerPayload=await encrypt({token,key,name,notes:''},state.key);
      if(!popupActive(ticket)||checkInactivity()||!state.key)return;
      await fetchApi('/sends','POST',{
        token,kind:'text',expireHours:Number($('send-expiry').value),
        maxViews:rawLimit?Number(rawLimit):null,password:pass||null,payload,ownerPayload
      });
      if(!popupActive(ticket)||checkInactivity()||!state.key)return;
      // Toujours montrer le lien, même si le presse-papiers ou l'actualisation échoue.
      const link=state.origin+'/s/'+token+'#k='+key;
      $('send-result-link').value=link;
      $('send-created').hidden=false;
      $('send-form').reset();$('send-options').open=false;
      updateSendMode();
      $('send-copy').focus();
      const copied=await copyText(link);
      if(!popupActive(ticket)||checkInactivity()||!state.key)return;
      message(copied?'Send créé : lien copié.':'Send créé : copiez le lien avec le bouton ci-dessus.',!copied);
      try{await loadSends();if(popupActive(ticket)&&state.key)renderSends();}
      catch(err){if(popupActive(ticket)&&state.key)console.warn('Actualisation des Send impossible :',err.message);}
    }catch(err){if(popupActive(ticket)&&state.key)message(err.message,true);}
    finally{button.disabled=false;}
  }
  async function copyText(value){
    if(checkInactivity())return false;
    try{await navigator.clipboard.writeText(value);message('Copié. Le presse-papiers peut être lu par d’autres applications.');return true;}
    catch{message('Copie refusée par le navigateur : sélectionnez et copiez manuellement.',true);return false;}
  }
  function randomBelow(n){
    if(n<=0||n>256)throw Error('Choix invalide.');
    const ceiling=Math.floor(256/n)*n;
    while(true){const byte=rand(1)[0];if(byte<ceiling)return byte%n;}
  }
  const groups={upper:'ABCDEFGHJKLMNPQRSTUVWXYZ',lower:'abcdefghijkmnopqrstuvwxyz',digits:'23456789',symbols:'!@#$%&*?_+-='};
  function createPassword(){
    const selected=Object.keys(groups).filter(k=>$(k).checked);
    if(!selected.length){message('Sélectionnez au moins une catégorie.',true);return '';}
    const length=Math.max(12,Math.min(64,Number($('length').value)||24));
    const chars=selected.map(k=>groups[k][randomBelow(groups[k].length)]);
    const pool=selected.map(k=>groups[k]).join('');
    while(chars.length<length)chars.push(pool[randomBelow(pool.length)]);
    for(let i=chars.length-1;i>0;i--){const j=randomBelow(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
    return chars.join('');
  }
  async function activeSiteOrigin(){
    try{const tab=await currentSiteTab();return tab?new URL(tab.url).origin:null;}
    catch{return null;}
  }
  async function init(){
    const saved=await chrome.storage.local.get({ml2cVaultOrigin:FALLBACK,datensisStockLockMinutes:0});
    try{state.origin=normalizeOrigin(saved.ml2cVaultOrigin);}catch{state.origin=FALLBACK;}
    const preference=Number(saved.datensisStockLockMinutes);
    idleMinutes=IDLE_OPTIONS.includes(preference)?preference:0;
    $('idle-minutes').value=String(idleMinutes);
    $('advanced-server').value=state.origin;
    state.siteOrigin=await activeSiteOrigin();
    screen('login');
    if(!await permissionFor(state.origin,false))message('Serveur non autorisé. Vérifiez les permissions Edge pour cette extension.',true);
  }
  $('login-form').addEventListener('submit',login);
  $('lock').onclick=()=>lock();$('settings-lock').onclick=()=>lock();
  document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>switchTab(b.dataset.tab));
  $('search').oninput=renderList;$('filter').onchange=()=>{state.siteOnly=false;renderList();};
  $('matched').onclick=()=>{
    if(!state.siteOrigin)return message('Impossible de lire l’adresse de cet onglet.',true);
    state.siteOnly=!state.siteOnly;renderList();message(state.siteOnly?'Identifiants du site actif : '+state.siteOrigin:'Tous les éléments.');
  };
  $('add').onclick=()=>openEditor();
  $('detail-back').onclick=()=>{showArea('list');renderList();};
  $('editor-back').onclick=()=>{if(state.editing){showItem(state.editing);}else{showArea('list');renderList();}};
  $('entry-type').onchange=editorFields;
  $('entry-reveal').onclick=()=>{$('entry-password').type=$('entry-password').type==='password'?'text':'password';};
  $('entry-generate').onclick=()=>{$('entry-password').value=createPassword();message('Nouveau mot de passe dans la fiche. Enregistrez pour le conserver.');};
  $('editor-form').addEventListener('submit',saveEditor);
  $('edit').onclick=()=>openEditor(state.selected);
  $('share-entry').onclick=()=>prepareSendFromEntry(state.selected);
  $('fill-site').onclick=()=>fillOnSite(state.items.find(x=>x.id===state.selected));
  $('site-permission').onclick=async()=>{
    const origin=state.siteOrigin;if(!origin||!origin.startsWith('https://'))return;
    try{
      await enableAssistantForSite(origin,await currentSiteTab());
      message('Remplissage automatique activé pour ce site.');updateSiteSuggestions();
      await probeActiveSite();
    }catch(err){message(err.message,true);}
  };
  $('favorite').onclick=()=>updateSelected(v=>{v.favorite=!v.favorite;});
  $('trash').onclick=()=>updateSelected(v=>{if(v.deletedAt){delete v.deletedAt;}else{v.deletedAt=new Date().toISOString();}});
  $('send-form').addEventListener('submit',createSend);
  $('send-mode-login').onchange=updateSendMode;
  $('send-mode-text').onchange=updateSendMode;
  $('send-entry').onchange=updateSendPreview;
  $('send-copy').onclick=()=>{if($('send-result-link').value)copyText($('send-result-link').value);};
  $('send-new').onclick=()=>{$('send-result-link').value='';$('send-created').hidden=true;($('send-mode-login').checked?$('send-entry'):$('send-text')).focus();message();};
  $('send-refresh').onclick=async()=>{try{await loadSends();if(state.key)renderSends();}catch(err){message(err.message,true);}};
  async function updateBrowserPasswordSetting(){
    const node=$('browser-save-status'),button=$('disable-browser-save');
    if(!chrome.privacy?.services?.passwordSavingEnabled){
      node.textContent='Edge ne permet pas à cette extension de piloter ce réglage. Ouvrez les paramètres Edge > Mots de passe et désactivez « Proposer d’enregistrer les mots de passe ».';
      button.disabled=true;return;
    }
    try{
      const current=await chrome.privacy.services.passwordSavingEnabled.get({});
      if(current.value===false){
        node.textContent='La sauvegarde des mots de passe dans Edge est déjà désactivée.';
        button.disabled=true;
      }else if(!['controllable_by_this_extension','controlled_by_this_extension'].includes(current.levelOfControl)){
        node.textContent='Ce réglage est géré ailleurs. Désactivez « Proposer d’enregistrer les mots de passe » dans les paramètres Edge.';
        button.disabled=true;
      }else{
        node.textContent='Edge peut encore proposer de sauvegarder les mots de passe.';
        button.disabled=false;
      }
    }catch{node.textContent='Impossible de lire le réglage Edge. Utilisez les paramètres du navigateur.';button.disabled=true;}
  }
  $('save-advanced-server').onclick=async()=>{
    try{
      const origin=normalizeOrigin($('advanced-server').value);
      if(!await permissionFor(origin,true))throw Error('Permission refusée pour ce serveur.');
      if(origin!==state.origin){
        lock();state.origin=origin;
        await chrome.storage.local.set({ml2cVaultOrigin:origin});
        message('Serveur mis à jour. Reconnectez-vous pour ouvrir le coffre.');
      }else message('Cette adresse est déjà utilisée.');
    }catch(err){message(err.message,true);}
  };
  $('disable-browser-save').onclick=async()=>{
    const button=$('disable-browser-save');button.disabled=true;
    try{
      if(!chrome.privacy?.services?.passwordSavingEnabled)throw Error('Cette version d’Edge ne prend pas en charge cette option.');
      await chrome.privacy.services.passwordSavingEnabled.set({value:false,scope:'regular'});
      await updateBrowserPasswordSetting();
      message('Les propositions de sauvegarde d’Edge sont désactivées. Datensis Stock reste actif.');
    }catch(err){message('Impossible de modifier le réglage Edge : '+err.message,true);await updateBrowserPasswordSetting();}
  };
  $('idle-minutes').onchange=async()=>{
    const n=Number($('idle-minutes').value);
    if(!IDLE_OPTIONS.includes(n))return;
    idleMinutes=n;
    armInactivityWatchdog();
    try{await chrome.storage.local.set({datensisStockLockMinutes:n});message(n===0?'Inactivité désactivée. La fermeture verrouille toujours le coffre.':'Verrouillage automatique : '+n+' minute(s).');}
    catch{message('Préférence non enregistrée, mais appliquée à cette session.',true);}
    checkInactivity();
  };
  $('generate').onclick=()=>{$('generated').value=createPassword();};
  $('copy-generated').onclick=()=>{if($('generated').value)copyText($('generated').value);};
  $('length').oninput=()=>{$('length-output').textContent=$('length').value;$('generated').value=createPassword();};
  for(const key of Object.keys(groups))$(key).onchange=()=>{$('generated').value=createPassword();};
  $('open-website').onclick=async()=>{try{await chrome.tabs.create({url:state.origin+'/vault'});}catch(err){message(err.message,true);}};
  // Le panneau GLOBAL reste ouvert pendant la navigation dans le navigateur.
  // Un changement d onglet ne verrouille pas le coffre et ne doit pas
  // laisser le filtre « site actif » sur un domaine precedent.
  const refreshActiveSite = async () => {
    const origin=await activeSiteOrigin();
    if(state.siteOrigin!==origin){
      state.siteOrigin=origin;
      state.siteOnly=siteMatches().length>0;
      if(state.key && state.tab==='vault')renderList();
    }
    // Retenter apres navigation ou chargement d'un formulaire dynamique.
    if(state.key){await probeActiveSite();await consumePendingCredentialDraft();}
  };
  chrome.tabs.onActivated.addListener(() => {refreshActiveSite().catch(() => {});});
  chrome.tabs.onUpdated.addListener((_tabId,change,tab) => {
    if(tab.active && (change.url || change.status==='complete'))refreshActiveSite().catch(() => {});
  });
  chrome.runtime.onMessage.addListener((msg,sender,respond)=>{
    if(msg?.type==='datensis-stock-check-credential'){
      checkCredentialFromSender(msg,sender).then(result=>respond(result)).catch(()=>respond({available:false}));
      return true;
    }
    if(msg?.type==='datensis-stock-capture-save-notify'){
      consumePendingCredentialDraft().catch(()=>{});
      respond({ok:true});return false;
    }
    if(msg?.type==='datensis-stock-autofill-ready'){
      autoFillForSender(sender).then(result=>respond(result)).catch(()=>respond({filled:false}));
      return true;
    }
    if(msg?.type==='datensis-stock-panel-closed')lock();
    if(msg?.type==='datensis-stock-idle-check')checkInactivity();
  });
  window.addEventListener('pagehide',()=>lock());
  // Inactivite du panneau : changements d'onglet sans effet immediat, mais le
  // delai continue de courir tant que le panneau est ouvert.
  for(const type of ['pointerdown','keydown','input','wheel','touchstart']){
    document.addEventListener(type,recordActivity,{capture:true});
  }
  // Des evenements peuvent etre retardes lorsque Chromium suspend le panneau.
  document.addEventListener('visibilitychange',()=>{if(!document.hidden)checkInactivity();});
  window.addEventListener('focus',checkInactivity);
  window.addEventListener('focus',()=>consumePendingCredentialDraft().catch(()=>{}));
  // Controle supplementaire : tout evenement tardif est valide contre l'heure reelle.
  setInterval(()=>{checkInactivity();updateIdleCountdown();},1000);
  updateSendMode();
  $('generated').value=createPassword();
  init().catch(err=>message(err.message,true));
})();
