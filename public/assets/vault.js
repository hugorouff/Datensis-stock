/* ML2C Vault v2 - prototype non audite.
 * Mot de passe coffre -> cle AES locale, Send -> cle aleatoire dans fragment URL.
 */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const guard = window.ML2CVaultGuard;
  if (!guard) throw new Error('Protection de session ML2C manquante');
  const actionTools = window.ML2CActionTools;
  if (!actionTools) throw new Error('Module ML2C Action Tools manquant');
  const otpCsrf = document.querySelector('meta[name="twofa-csrf"]').content;
  let bootPassword = window.__vaultBootstrapPassword || null;
  delete window.__vaultBootstrapPassword;
  // Verification par e-mail conservee, mais ignoree quand le serveur la desactive.
  const otpEnabled = document.getElementById('app-shell').dataset.otpEnabled === '1';
  let otpRequired = false;
  const assertActive = ticket => {
    if (!guard.active(ticket)) throw new Error('La page a été quittée : le coffre reste verrouillé.');
  };
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const ITERATIONS = 600000;
  let argon2Loader = null;
  if(location.pathname==='/mini') document.body.classList.add('mini-mode');
  const state = {key:null, initial:null, items:[], sends:[], filter:'all', view:'vault', search:'',selectedId:null,editId:null,sendFilter:'all',folderSelected:'',lastActive:Date.now(),accountSharing:null,receivedItems:[]};
  const labels = {all:'Tous les éléments',favorite:'Favoris',login:'Identifiants',note:'Notes sécurisées',card:'Cartes bancaires',identity:'Identités',ssh:'Clés SSH',trash:'Corbeille'};
  const sublabels = {login:'Identifiant',note:'Note sécurisée',card:'Carte bancaire',identity:'Identité',ssh:'Clé SSH'};
  const fields = ['username','password','url','loginUrls','cardHolder','cardNumber','expiry','cvv','firstName','lastName','address','phone','email','publicKey','privateKey','folder','notes'];
  const escapeHtml = x => String(x ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const b64 = bytes => {const chunks=[];for(let i=0;i<bytes.length;i+=8192)chunks.push(String.fromCharCode(...bytes.subarray(i,i+8192)));return btoa(chunks.join(''));};
  const fromB64 = data => Uint8Array.from(atob(data.replace(/-/g,'+').replace(/_/g,'/') + '='.repeat((4-data.length%4)%4)), c=>c.charCodeAt(0));
  const urlB64 = bytes => b64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const rand = n => crypto.getRandomValues(new Uint8Array(n));
  const fmt = value => new Intl.DateTimeFormat('fr-FR',{dateStyle:'medium',timeStyle:'short'}).format(new Date(value));
  function toast(message) {const el=$('toast');el.textContent=message;el.hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>el.hidden=true,3800);}
  async function copyText(str) {try {await navigator.clipboard.writeText(str);toast('Copié dans le presse-papiers.');}catch {toast('Copie refusée : autorisez le presse-papiers ou utilisez HTTPS.');}}
  async function api(path,method='GET',body=null) {
    const opts={method,credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}};
    if(method!=='GET'){
      // Un onglet Edge peut conserver une ancienne page pendant qu'un autre
      // onglet change de compte. Toujours verifier l'identite avant d'ecrire.
      const check=await fetch('/api/vault/csrf',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
      let session;
      try{session=await check.json();}catch{throw Error('Session expirée : reconnectez-vous puis rechargez le coffre.');}
      if(!check.ok||!session?.csrfToken)throw Error(session?.error||'Session expirée : reconnectez-vous.');
      // Comparer des identifiants immuables, et non des e-mails qui peuvent changer.
      // En cas de page ancienne, ne pas contourner la protection : recharger.
      const expected=String($('app-shell').dataset.accountId||'').trim();
      const actual=String(session.accountId||'').trim();
      if(!expected||!actual||expected!==actual){
        throw Error('La session ne correspond plus à ce coffre. Rechargez la page et reconnectez-vous au bon compte avant de modifier.');
      }
      opts.headers['Content-Type']='application/json';
      opts.headers['X-CSRF-Token']=session.csrfToken;
      opts.body=JSON.stringify(body??{});
    }
    const r=await fetch(path,opts);let data;
    try{data=await r.json();}catch{throw Error('Réponse invalide du serveur. Vérifiez votre session.');}
    if(!r.ok)throw Error(data.error||'Erreur serveur.');return data;
  }
  async function vaultKey(passphrase,salt,kdfVersion=2) {
    if(kdfVersion===1){
      const base=await crypto.subtle.importKey('raw',encoder.encode(passphrase),{name:'PBKDF2'},false,['deriveKey']);
      return crypto.subtle.deriveKey({name:'PBKDF2',salt:fromB64(salt),iterations:ITERATIONS,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
    }
    if(kdfVersion!==2)throw Error('Version de dérivation du coffre inconnue : '+String(kdfVersion)+'.');
    await ensureArgon2();
    const raw=await window.hashwasm.argon2id({password:encoder.encode(passphrase),salt:fromB64(salt),parallelism:1,iterations:3,memorySize:65536,hashLength:32,outputType:'binary'});
    return crypto.subtle.importKey('raw',raw,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  async function ensureArgon2(){
    if(typeof window.hashwasm?.argon2id==='function')return;
    if(!argon2Loader){
      argon2Loader=new Promise((resolve,reject)=>{
        const existing=document.querySelector('script[src*="hash-wasm-argon2id-4.12.0.min.js"]');
        const source=new URL(existing?.src||'/assets/hash-wasm-argon2id-4.12.0.min.js',location.href);
        source.searchParams.set('retry','1');
        const script=document.createElement('script');
        script.src=source.href;
        script.onload=()=>typeof window.hashwasm?.argon2id==='function'
          ?resolve()
          :reject(new Error('Le script Argon2id est chargé, mais son module est introuvable.'));
        script.onerror=()=>reject(new Error('Impossible de charger Argon2id. Vérifiez le déploiement des assets et rechargez la page.'));
        document.head.append(script);
      });
    }
    await argon2Loader;
  }
  async function rawKey(bytes) {return crypto.subtle.importKey('raw',bytes,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}
  async function encrypt(value,key) {const iv=rand(12);const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,encoder.encode(JSON.stringify(value)));return {v:1,iv:b64(iv),data:b64(new Uint8Array(cipher))};}
  async function decrypt(payload,key) {if(payload?.v!==1)throw Error('Format inconnu.');const bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(payload.iv)},key,fromB64(payload.data));return JSON.parse(decoder.decode(bytes));}
  function lockError(message=''){$('lock-error').hidden=!message;$('lock-error').textContent=message;}
  async function loadVault(){
    state.initial=await api('/api/vault/state');
    const setup=!state.initial.initialized;
    $('lock-eyebrow').textContent=setup?'PREMIÈRE UTILISATION':'COFFRE VERROUILLÉ';
    $('lock-title').textContent=setup?'Initialiser le coffre':'Déverrouiller votre coffre';
    $('lock-description').textContent=setup?'Le coffre est initialise et ouvert automatiquement apres votre premiere connexion.':'Cette session a ete reverrouillee. Saisissez le mot de passe de connexion ; il ne reste pas enregistre apres fermeture ou rechargement.';
    $('confirm-wrap').hidden=!setup;
    $('vault-confirm').required=setup;
    $('unlock-button').textContent=setup?'Créer et ouvrir mon coffre':'Déverrouiller';
    $('unlock-button').disabled=false;
    $('unlock-otp-wrap').hidden=!otpRequired;
    $('unlock-otp').required=otpRequired;
  }
  async function verifyOtpUnlock(){
    if(!otpRequired)return;
    const code=$('unlock-otp').value.trim();
    if(!code)throw Error('Demandez puis saisissez le code reçu par e-mail.');
    const r=await fetch('/2fa/verify',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':otpCsrf},body:JSON.stringify({code}),cache:'no-store'});
    const body=await r.json();if(!r.ok)throw Error(body.error||'Code 2FA incorrect.');
    otpRequired=false;$('unlock-otp').value='';$('unlock-otp-wrap').hidden=true;
  }
  async function unlockWith(pass){
    const ticket = guard.ticket();
    assertActive(ticket);
    const init=!state.initial.initialized;
    if(pass.length<12)throw Error('Mot de passe principal de 12 caractères minimum.');
    const kdfVersion=init?2:(state.initial.kdfVersion||1);
    const salt=init?b64(rand(16)):state.initial.salt;
    let key=await vaultKey(pass,salt,kdfVersion);
    let migratedFromPbkdf2=false;
    assertActive(ticket); // Une derivation en cours ne doit jamais rouvrir un coffre masque.
    if(init){
      const check=await encrypt('vault-ready-v1',key);
      assertActive(ticket);
      await api('/api/vault/initialize','POST',{salt,check,kdfVersion});
      assertActive(ticket);
      await loadVault();
      assertActive(ticket);
    }else{
      if(await decrypt(state.initial.check,key)!=='vault-ready-v1')throw Error('Mot de passe incorrect.');
      if(kdfVersion===1){
        key=await rekeyVault(key,pass,false);
        assertActive(ticket);
        migratedFromPbkdf2=true;
      }
    }
    assertActive(ticket);
    const items=await Promise.all(state.initial.entries.map(async x=>({id:x.id,updatedAt:x.updatedAt,value:await decrypt(x.payload,key)})));
    assertActive(ticket);
    state.key=key;state.items=items;state.lastActive=Date.now();
    $('vault-passphrase').value='';$('vault-confirm').value='';$('lock-surface').hidden=true;$('app-unlocked').hidden=false;
    try{await loadSends();}catch(err){if(guard.active(ticket))toast('Coffre ouvert, mais chargement des Send impossible : '+err.message);}
    assertActive(ticket);
    navigateFromUrl();render();applyMiniIntent();toast(migratedFromPbkdf2?'Coffre déverrouillé et migré vers Argon2id.':'Coffre déverrouillé.');
    try { await ensureAccountSharing(ticket); }
    catch { /* L'interface affiche le detail et propose de reessayer. */ }
  }
  async function rekeyVault(oldKey,newPass,rotateSalt=true){
    const ticket=guard.ticket();
    assertActive(ticket);
    const salt=rotateSalt?b64(rand(16)):state.initial.salt,newKey=await vaultKey(newPass,salt);
    assertActive(ticket);
    const converted=await Promise.all(state.initial.entries.map(async x=>({id:x.id,payload:await encrypt(await decrypt(x.payload,oldKey),newKey)})));
    assertActive(ticket);
    const sendsData=await api('/api/sends');
    assertActive(ticket);
    const sends=await Promise.all(sendsData.sends.map(async x=>({id:x.id,ownerPayload:await encrypt(await decrypt(x.ownerPayload,oldKey),newKey)})));
    assertActive(ticket);
    const invitations=await Promise.all((state.initial.invitations||[]).map(async x=>({id:x.id,encryptedPrivateKey:await encrypt(await decrypt(x.encryptedPrivateKey,oldKey),newKey)})));
    const identity=await api('/api/shares/identity');
    const sharingPrivateKey=identity.encryptedPrivateKey?await encrypt(await decrypt(identity.encryptedPrivateKey,oldKey),newKey):null;
    const check=await encrypt('vault-ready-v1',newKey);
    assertActive(ticket);
    await api('/api/vault/rekey','POST',{salt,check,kdfVersion:2,entries:converted,sends,invitations,sharingPrivateKey});
    assertActive(ticket);
    state.initial=await api('/api/vault/state');
    assertActive(ticket);
    return newKey;
  }
  async function convertOldVault(oldPass,newPass){
    const ticket=guard.ticket();
    assertActive(ticket);
    const oldKey=await vaultKey(oldPass,state.initial.salt,state.initial.kdfVersion||1);
    assertActive(ticket);
    if(await decrypt(state.initial.check,oldKey)!=='vault-ready-v1')throw Error('Ancienne phrase secrète incorrecte.');
    await rekeyVault(oldKey,newPass);
    toast('Ancien coffre converti : le mot de passe de connexion devient la clé.');
  }
  $('unlock-form').addEventListener('submit',async e=>{
    e.preventDefault();lockError();
    const pass=$('vault-passphrase').value;
    if(!bootPassword && !state.initial.initialized && pass!==$('vault-confirm').value)return lockError('La confirmation ne correspond pas.');
    $('unlock-button').disabled=true;
    try{
      await verifyOtpUnlock();
      if(bootPassword){
        const newPass=bootPassword;
        await convertOldVault(pass,newPass);
        bootPassword=null;
        await unlockWith(newPass);
      }else await unlockWith(pass);
    }catch(err){lockError(err.name==='OperationError'?'Mot de passe incorrect ou données endommagées.':err.message);}
    finally{$('unlock-button').disabled=false;}
  });
  function serverLock(){
    if(!otpEnabled)return;
    // Beacon accepte un formulaire CSRF et survit mieux a pagehide, sans garantie absolue de livraison.
    const form=new URLSearchParams({_csrf_token:otpCsrf});
    if(navigator.sendBeacon && navigator.sendBeacon('/2fa/lock',form))return;
    fetch('/2fa/lock',{method:'POST',credentials:'same-origin',headers:{'X-CSRF-Token':otpCsrf},keepalive:true,cache:'no-store'}).catch(()=>{});
  }
  function lock(){
    // Toujours invalider : aussi lors du premier login et d'un dechiffrement en cours.
    guard.invalidate();
    bootPassword=null;
    delete window.__vaultBootstrapPassword;
    for(const d of ['item-dialog','send-dialog','folder-dialog'])if($(d).open)$(d).close();
    document.dispatchEvent(new Event('datensis:vault-locked'));
    state.key=null;state.items=[];state.sends=[];state.accountSharing=null;state.receivedItems=[];if(shareSyncTimer){clearTimeout(shareSyncTimer);shareSyncTimer=null;}state.folderSelected='';state.selectedId=null;state.editId=null;state.search='';
    // Ne pas conserver dans le DOM de lien d'invitation, de dépôt chiffre ni de secret admin.
    if($('admin-password'))$('admin-password').value='';
    if($('admin-invite-url'))$('admin-invite-url').value='';
    if($('admin-invite-result'))$('admin-invite-result').hidden=true;
    if($('admin-invite-list'))$('admin-invite-list').replaceChildren();
    if($('admin-panel'))$('admin-panel').hidden=true;
    if($('admin-auth-box'))$('admin-auth-box').hidden=false;
    $('item-form').reset();$('send-form').reset();$('send-result-link').value='';$('send-created').hidden=true;$('item-details').replaceChildren();$('items-list').replaceChildren();$('sends-list').replaceChildren();$('search-input').value='';$('generator-result').value='';
    $('app-unlocked').hidden=true;$('lock-surface').hidden=false;
    $('vault-passphrase').value='';$('vault-confirm').value='';lockError();
    otpRequired=otpEnabled;$('unlock-otp-wrap').hidden=!otpRequired;$('unlock-otp').required=otpRequired;
    serverLock();if(!document.hidden)$('vault-passphrase').focus();
  }
  $('lock-btn').onclick=lock;$('top-lock').onclick=lock;$('settings-lock').onclick=lock;
  function closeNav(){$('sidebar').classList.remove('open');$('sidebar-backdrop').classList.remove('visible');}
  $('menu-btn').onclick=()=>{$('sidebar').classList.add('open');$('sidebar-backdrop').classList.add('visible');};$('sidebar-backdrop').onclick=closeNav;
  const paths={admin:'/admin',shares:'/shares',vault:'/vault',passwords:'/passwords',cockpit:'/cockpit',actions:'/actions',send:'/send',security:'/security-center',generator:'/generator',transfer:'/transfer',settings:'/settings'};
  function navigateFromUrl(){const path=location.pathname;const name=Object.keys(paths).find(x=>paths[x]===path)||'vault';state.view=name;if(name==='passwords')state.filter='login';else if(name==='vault'&&new URLSearchParams(location.search).has('filter'))state.filter=new URLSearchParams(location.search).get('filter');showView();}
  function navigate(view,filter) {if(filter)state.filter=filter;if(view==='passwords')state.filter='login';state.view=view;const href=paths[view]+(view==='vault'&&filter?'?filter='+encodeURIComponent(filter):'');history.pushState({},'',href);showView();closeNav();}
  function showView(){const selected=state.view==='passwords'?'vault':state.view;document.querySelectorAll('[data-panel]').forEach(x=>x.hidden=x.dataset.panel!==selected);document.querySelectorAll('[data-view]').forEach(x=>x.classList.toggle('active',x.dataset.view===state.view));$('breadcrumb').textContent=({vault:'Mon coffre',passwords:'Mots de passe',shares:'Partages entre comptes',send:'Send',cockpit:'Cockpit cabinet',actions:'Centre d’actions',security:'Centre de sécurité',generator:'Générateur',transfer:'Importer / Exporter',settings:'Paramètres',admin:'Administration'})[state.view]||'Mon coffre';render();if(state.view==='shares'){ensureAccountSharing().catch(()=>{});}if(state.view==='admin'&&$('admin-auth-box'))loadAdmin().catch(e=>toast(e.message));}
  window.addEventListener('popstate',()=>{navigateFromUrl();});
  // Les liens /mini ouvrent le vrai coffre Symfony dans une petite fenetre.
  // Les secrets ne passent jamais dans le stockage de l'extension.
  function applyMiniIntent() {
    const params=new URLSearchParams(location.search);
    if(!document.body.classList.contains('mini-mode')) return;
    if(params.has('q')){
      state.search=params.get('q').slice(0,150);
      $('search-input').value=state.search;
      $('quick-search').value=state.search;
      state.filter='all';
      navigate('vault');
    }
    if(params.get('filter')==='login'){state.filter='login';navigate('passwords');}
    if(params.get('action')==='new'){
      state.filter='all';
      navigate('vault');
      openEditor(null);
    }
  }
  $('quick-new').onclick=()=>{state.filter='all';navigate('vault');openEditor(null);};
  $('quick-passwords').onclick=()=>{state.filter='login';navigate('vault','login');};
  $('quick-security').onclick=()=>navigate('security');

  $('quick-generate').onclick=()=>navigate('generator');
  $('quick-send').onclick=()=>navigate('send');
  $('quick-search').oninput=()=>{if(!state.key)return;state.search=$('quick-search').value;state.filter='all';$('search-input').value=state.search;navigate('vault');};

  document.querySelectorAll('[data-view]').forEach(el=>el.addEventListener('click',e=>{e.preventDefault();if(!state.key){toast('Déverrouillez le coffre.');return;}navigate(el.dataset.view);}));
  $('folder-filter').onchange=()=>{state.folderSelected=$('folder-filter').value;render();};
  $('vault-filter').onchange=()=>{if(!state.key)return;state.search='';$('search-input').value='';$('quick-search').value='';navigate('vault',$('vault-filter').value);};
  function relevantItems(){let items=[...state.items,...state.receivedItems].filter(x=>!['folder','shareTarget'].includes(x.value.type)&&(state.filter==='trash'?!!x.value.deletedAt:!x.value.deletedAt));const q=state.search.trim().toLowerCase();items=items.filter(x=>{const v=x.value;const category=['all','trash'].includes(state.filter)||(state.filter==='favorite'&&!!v.favorite)||v.type===state.filter||(state.filter.startsWith('folder:')&&v.folder===state.filter.slice(7)||(state.filter.startsWith('tag:')&&actionTools.tags(v.tags).includes(state.filter.slice(4))));return category&&(!state.folderSelected||v.folder===state.folderSelected||String(v.folder||'').startsWith(state.folderSelected+'/'))&&(!q||[v.name,v.username,v.url,v.folder,v.notes,v.email,v.client,v.owner,v.tags].some(s=>String(s||'').toLowerCase().includes(q)));});return items.sort($('sort-select').value==='name'?(a,b)=>(a.value.name||'').localeCompare(b.value.name||'','fr'):(a,b)=>b.updatedAt.localeCompare(a.updatedAt));}
  // Cockpit ML2C : calculs uniquement sur les données déjà déchiffrées en mémoire locale.
  // Indicateurs indicatifs, pas un scanner de fuites ni un audit de sécurité.
  function activeLogins(){return state.items.filter(i=>!i.value.deletedAt&&i.value.type==='login');}
  function passwordWeak(password){
    if(!password)return true;
    const length=[...password].length;
    const classes=[/[a-z]/.test(password),/[A-Z]/.test(password),/\d/.test(password),/[^\p{L}\p{N}]/u.test(password)].filter(Boolean).length;
    return length<12||(length<16&&classes<3)||/^(.)\1{5,}$/.test(password)||/^(password|admin|azerty|123456|qwerty)/i.test(password);
  }
  function cockpitAnalysis(){
    const logins=activeLogins(), now=new Date(); now.setHours(0,0,0,0);
    const end=new Date(now);end.setDate(end.getDate()+30);
    const counts=new Map();
    for(const i of logins){const p=i.value.password;if(p)counts.set(p,(counts.get(p)||0)+1);}
    const alerts=[],upcoming=[], clients=new Map();
    for(const item of logins){
      const v=item.value;
      const client=(v.client||'Sans dossier client').trim()||'Sans dossier client';
      const curr=clients.get(client)||{name:client,total:0,critical:0,actions:0};
      curr.total++; if(v.criticality==='critical')curr.critical++;
      let count=0;
      const add=(code,label,priority)=>{alerts.push({item,client,code,label,priority});count++;};
      if(v.password&&counts.get(v.password)>1)add('duplicate','Mot de passe réutilisé',1);
      if(passwordWeak(v.password))add('weak','Secret faible ou absent (estimation)',1);
      if(v.criticality==='critical'&&v.service2fa==='no')add('mfa','Accès critique sans 2FA déclarée',1);
      if(v.criticality==='critical'&&(!v.owner||!v.client))add('owner','Responsable ou dossier client manquant',2);
      if(v.nextRotation&&/^\d{4}-\d{2}-\d{2}$/.test(v.nextRotation)){
        const due=new Date(v.nextRotation+'T00:00:00');
        if(Number.isFinite(due.valueOf())){
          if(due<now)add('overdue','Rotation en retard',0);
          else if(due<=end){upcoming.push({item,client,date:v.nextRotation});}
        }
      }
      curr.actions+=count;clients.set(client,curr);
    }
    alerts.sort((a,b)=>a.priority-b.priority||a.client.localeCompare(b.client,'fr'));
    upcoming.sort((a,b)=>a.date.localeCompare(b.date));
    return {logins,alerts,upcoming,clients:[...clients.values()].sort((a,b)=>a.name.localeCompare(b.name,'fr'))};
  }
  function cockpitItemButton(item,label,cls=''){
    const button=document.createElement('button');button.type='button';button.className='cockpit-entry '+cls;
    button.textContent=label;
    button.onclick=()=>{state.selectedId=item.id;state.filter='all';navigate('vault');};
    return button;
  }
  function cockpitEmpty(message){const el=document.createElement('p');el.className='cockpit-empty';el.textContent=message;return el;}
  function renderCockpit(){
    const a=cockpitAnalysis();
    $('stat-total').textContent=a.logins.length;
    $('stat-clients').textContent=a.clients.filter(c=>c.name!=='Sans dossier client').length;
    $('stat-alerts').textContent=a.alerts.length;
    $('stat-due').textContent=a.upcoming.length;
    const root=$('cockpit-alerts');root.replaceChildren();
    if(!a.alerts.length)root.append(cockpitEmpty('Aucune alerte détectée dans les fiches renseignées. Les contrôles restent indicatifs.'));
    for(const warning of a.alerts.slice(0,40)){
      const row=document.createElement('div');row.className='cockpit-line';
      const txt=document.createElement('div');const headline=document.createElement('strong');headline.textContent=warning.label;
      const sub=document.createElement('small');sub.textContent=warning.client+' · '+warning.item.value.name;
      txt.append(headline,sub);row.append(txt,cockpitItemButton(warning.item,'Examiner',''));root.append(row);
    }
    if(a.alerts.length>40){const small=document.createElement('p');small.className='help-text';small.textContent='40 premières alertes affichées sur '+a.alerts.length+'.';root.append(small);}
    const clients=$('cockpit-clients');clients.replaceChildren();
    if(!a.clients.length)clients.append(cockpitEmpty('Aucun identifiant enregistré.'));
    for(const c of a.clients){const row=document.createElement('div');row.className='cockpit-line';
      const txt=document.createElement('div');const title=document.createElement('strong');title.textContent=c.name;
      const sub=document.createElement('small');sub.textContent=c.total+' accès · '+c.critical+' critique(s) · '+c.actions+' alerte(s)';txt.append(title,sub);row.append(txt);
      const b=document.createElement('button');b.type='button';b.className='cockpit-entry';b.textContent='Voir';b.onclick=()=>{state.filter='all';state.search=c.name==='Sans dossier client'?'':c.name;$('search-input').value=state.search;navigate('vault');};row.append(b);clients.append(row);}
    const rotations=$('cockpit-rotations');rotations.replaceChildren();
    if(!a.upcoming.length)rotations.append(cockpitEmpty('Aucune rotation prévue dans les 30 prochains jours.'));
    for(const r of a.upcoming){const row=document.createElement('div');row.className='cockpit-line';const txt=document.createElement('div');const title=document.createElement('strong');title.textContent=r.item.value.name;const sub=document.createElement('small');sub.textContent=r.client+' · '+r.date;txt.append(title,sub);row.append(txt,cockpitItemButton(r.item,'Ouvrir'));rotations.append(row);}
  }
  $('cockpit-export').onclick=()=>{
    if(!state.key)return;
    const entries=activeLogins().filter(x=>x.value.nextRotation);
    if(!entries.length){toast('Aucune échéance à exporter.');return;}
    if(!confirm('Le fichier CSV sera en clair sur votre ordinateur. Continuer ?'))return;
    const quote=s=>{let value=String(s??'');if(/^[=+\-@\t\r]/.test(value))value="'"+value;return '"'+value.replace(/"/g,'""')+'"';};
    const rows=[['Client','Accès','Responsable','Prochaine rotation','Criticité'].map(quote).join(';')];
    for(const item of entries){const v=item.value;rows.push([v.client,v.name,v.owner,v.nextRotation,v.criticality].map(quote).join(';'));}
    const blob=new Blob(['\ufeff'+rows.join('\r\n')],{type:'text/csv;charset=utf-8'});
    const url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download='ml2c-vault-rotations-'+new Date().toISOString().slice(0,10)+'.csv';anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1500);
    toast('Planning exporté : attention, fichier CSV non chiffré.');
  };
  // Centre de securite : les donnees ne quittent pas le navigateur debloque.
  function securityAudit(){
    const logins=activeLogins();
    const usage=new Map();
    for(const x of logins)if(x.value.password)usage.set(x.value.password,(usage.get(x.value.password)||0)+1);
    const domainMap=new Map(), issues=[], overdue=[], rotations=[];
    const today=new Date();today.setHours(0,0,0,0);
    const soon=new Date(today);soon.setDate(soon.getDate()+45);
    const add=(item,label,tone='coral')=>issues.push({item,label,tone});
    for(const item of logins){
      const v=item.value;
      if(passwordWeak(v.password))add(item,'Mot de passe manquant ou faible (estimation)');
      if(v.password && usage.get(v.password)>1)add(item,'Mot de passe utilise dans plusieurs fiches');
      if(v.url){
        try{
          const u=new URL(v.url);
          if(u.protocol==='http:'&& !['localhost','127.0.0.1'].includes(u.hostname))add(item,'Lien HTTP non chiffre');
          if(u.hostname){const name=u.hostname.toLowerCase();const list=domainMap.get(name)||[];list.push(item);domainMap.set(name,list);}
        }catch{add(item,'Adresse du site invalide');}
      }else add(item,'Adresse du site non renseignee','mint');
      if(v.criticality==='critical'&&v.service2fa!=='yes')add(item,'Acces critique : verification 2FA a effectuer');
      if(v.criticality==='critical'&&(!v.client||!v.owner))add(item,'Dossier client ou responsable manquant');
      if(v.nextRotation&&/^\d{4}-\d{2}-\d{2}$/.test(v.nextRotation)){
        const date=new Date(v.nextRotation+'T00:00:00');
        if(Number.isFinite(date.valueOf())){
          if(date<today){overdue.push(item);rotations.push({item,date:v.nextRotation,late:true});}
          else if(date<=soon)rotations.push({item,date:v.nextRotation,late:false});
        }
      }
    }
    rotations.sort((a,b)=>a.date.localeCompare(b.date));
    const owners=[...new Set(logins.map(x=>(x.value.owner||'').trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'fr'));
    const affected=new Set(issues.map(x=>x.item.id)).size;
    const score=logins.length?Math.max(0,Math.round(100*(1-affected/logins.length))):null;
    return {logins,issues,overdue,rotations,domainMap,owners,score};
  }
  function securityOpenItem(item){state.selectedId=item.id;state.filter='all';state.search='';$('search-input').value='';navigate('vault');}
  function securityLine(root,title,subtitle,buttonText,click,tone=''){
    const line=document.createElement('div');line.className='security-line';
    const copy=document.createElement('div');const head=document.createElement('strong');head.textContent=title;
    const sub=document.createElement('small');sub.textContent=subtitle;copy.append(head,sub);line.append(copy);
    if(buttonText){const b=document.createElement('button');b.type='button';b.textContent=buttonText;b.className='security-line-action '+tone;b.onclick=click;line.append(b);}
    root.append(line);
  }
  function renderSecurityCenter(){
    const audit=securityAudit();
    $('security-score').textContent=audit.score===null?'—':audit.score+' / 100';
    $('security-issues').textContent=new Set(audit.issues.map(x=>x.item.id)).size;
    $('security-overdue').textContent=audit.overdue.length;
    $('security-domains').textContent=audit.domainMap.size;
    const alerts=$('security-audit-list');alerts.replaceChildren();
    if(!audit.issues.length)alerts.append(cockpitEmpty('Aucun point a verifier selon les regles locales.'));
    for(const x of audit.issues.slice(0,40))securityLine(alerts,x.item.value.name,x.label,'Ouvrir',()=>securityOpenItem(x.item),x.tone);
    const turns=$('security-rotation-list');turns.replaceChildren();
    if(!audit.rotations.length)turns.append(cockpitEmpty('Aucune rotation en retard ou a 45 jours.'));
    for(const x of audit.rotations.slice(0,30))securityLine(turns,x.item.value.name,(x.late?'En retard : ':'Prevue : ')+x.date,'Planifier +90 j',()=>planRotation(x.item),x.late?'coral':'');
    const domains=$('security-domain-list');domains.replaceChildren();
    if(!audit.domainMap.size)domains.append(cockpitEmpty('Aucun domaine reference.'));
    for(const [name,items] of [...audit.domainMap.entries()].sort((a,b)=>b[1].length-a[1].length).slice(0,30)){
      securityLine(domains,name,items.length+' fiche(s) pour ce domaine','Voir',()=>securityOpenItem(items[0]));
    }
    const select=$('security-owner');const selected=select.value;
    select.replaceChildren();const opt=document.createElement('option');opt.value='';opt.textContent='Tous les responsables';select.append(opt);
    for(const owner of audit.owners){const option=document.createElement('option');option.value=owner;option.textContent=owner;select.append(option);}
    if(audit.owners.includes(selected))select.value=selected;
    const review=$('security-review-list');review.replaceChildren();
    const target=audit.logins.filter(x=>!select.value||x.value.owner===select.value);
    if(!target.length)review.append(cockpitEmpty('Aucun acces pour cette selection.'));
    for(const item of target.slice(0,30)){
      const label=item.value.handover==='reviewed'?'Revue effectuee':item.value.handover==='na'?'Non applicable':'A verifier';
      securityLine(review,item.value.name,(item.value.client||'Sans dossier client')+' · '+label,'Ouvrir',()=>securityOpenItem(item));
    }
  }
  async function planRotation(item){
    if(!confirm('Planifier une nouvelle echeance a J+90 ? Cela ne change PAS le mot de passe sur le service concerne.'))return;
    const due=new Date();due.setDate(due.getDate()+90);
    const nextRotation=due.getFullYear()+'-'+String(due.getMonth()+1).padStart(2,'0')+'-'+String(due.getDate()).padStart(2,'0');
    try{await saveValue(item.id,{...item.value,nextRotation});toast('Echeance enregistree ; mot de passe du service non modifie.');}catch(e){toast(e.message);}
  }
  $('security-owner').onchange=renderSecurityCenter;
  $('security-refresh').onclick=()=>{renderSecurityCenter();toast('Analyse locale actualisee.');};
  const presets={
    administration:{name:'Portail administratif',folder:'Administration',criticality:'high',service2fa:'unknown'},
    banque:{name:'Acces bancaire',folder:'Banque / Finance',criticality:'critical',service2fa:'unknown'},
    client:{name:'Portail client',folder:'Dossiers clients',criticality:'high',service2fa:'unknown'},
    hebergement:{name:'Administration technique',folder:'Informatique',criticality:'critical',service2fa:'unknown'},
  };
  document.querySelectorAll('[data-preset]').forEach(button=>button.onclick=()=>{
    const preset=presets[button.dataset.preset];if(!preset||!state.key)return;
    openEditor();
    $('item-name').value=preset.name;$('item-folder').value=preset.folder;
    $('item-password').value=passwordGen(24);toast('Modele pret : renseignez le site et le compte avant enregistrement.');
  });
  // Centre d'actions : aucune donnée en clair ne quitte le navigateur.
  const actionsState={filter:'all'};
  const actionItemButton=(item,label,fn)=>{const b=document.createElement('button');b.type='button';b.className='actions-button';b.textContent=label;b.onclick=fn||(()=>securityOpenItem(item));return b;};
  const actionsEmpty=(root,msg)=>{const p=document.createElement('p');p.className='actions-empty';p.textContent=msg;root.append(p);};
  function openActionsFilter(filter){actionsState.filter=filter;navigate('actions');}
  function renderActions(){
    if(!state.key)return;
    const a=actionTools.analyze(state.items);
    $('actions-total').textContent=a.total;
    $('actions-pending').textContent=a.queue.length;
    $('actions-late').textContent=a.late;
    $('actions-unowned').textContent=a.unowned;
    $('actions-filter').value=actionsState.filter;
    const queue=$('actions-queue');queue.replaceChildren();
    const active=a.queue.filter(x=>actionsState.filter==='all'||x.kind===actionsState.filter||x.problems.some(p=>p.kind===actionsState.filter));
    if(!active.length)actionsEmpty(queue,'Aucune fiche dans cette catégorie.');
    for(const x of active.slice(0,60)){
      const row=document.createElement('div');row.className='actions-row';
      const info=document.createElement('div');const head=document.createElement('strong');head.textContent=x.item.value.name||'Sans nom';
      const sub=document.createElement('small');sub.textContent=x.client+' · '+x.problems.map(p=>p.label).join(' · ');info.append(head,sub);row.append(info);
      row.append(actionItemButton(x.item,'Ouvrir'));
      if(x.item.value.handover!=='reviewed')row.append(actionItemButton(x.item,'Revue faite',async()=>{
        if(!confirm('Marquer la fiche comme revue ? Cela ne certifie pas la sécurité du compte tiers.'))return;
        try{await saveValue(x.item.id,{...x.item.value,handover:'reviewed',reviewedAt:new Date().toISOString()});toast('Revue enregistrée dans la fiche chiffrée.');}catch(e){toast(e.message);}
      }));queue.append(row);
    }
    const clients=$('actions-clients');clients.replaceChildren();
    if(!a.clients.length)actionsEmpty(clients,'Aucun dossier client.');
    for(const c of a.clients.slice(0,45)){
      const row=document.createElement('div');row.className='actions-row';const txt=document.createElement('div');const h=document.createElement('strong');h.textContent=c.name;const sub=document.createElement('small');sub.textContent=c.count+' accès · '+c.urgent+' à examiner';txt.append(h,sub);row.append(txt);
      row.append(actionItemButton(null,'Filtrer',()=>{state.search=c.name==='Sans dossier client'?'':c.name;state.filter='all';$('search-input').value=state.search;$('quick-search').value=state.search;navigate('vault');}));clients.append(row);
    }
    const tags=$('actions-tags');tags.replaceChildren();if(!a.tags.length)actionsEmpty(tags,'Aucune étiquette. Ajoutez-en dans une fiche.');
    for(const [tag,items] of a.tags){const b=document.createElement('button');b.type='button';b.className='actions-tag';b.textContent=tag+' · '+items.length;b.onclick=()=>{state.search='';$('search-input').value='';$('quick-search').value='';navigate('vault','tag:'+tag);};tags.append(b);}
    const activity=$('actions-activity');activity.replaceChildren();if(!a.events.length)actionsEmpty(activity,'Aucune modification enregistrée dans les fiches.');
    for(const e of a.events.slice(0,20)){const row=document.createElement('div');row.className='actions-row';const txt=document.createElement('div');const h=document.createElement('strong');h.textContent=e.item.value.name;const sub=document.createElement('small');sub.textContent=e.action+' · '+fmt(e.at);txt.append(h,sub);row.append(txt,actionItemButton(e.item,'Ouvrir'));activity.append(row);}
  }
  $('actions-filter').onchange=()=>{actionsState.filter=$('actions-filter').value;renderActions();};
  $('actions-new').onclick=()=>openEditor();
  // Les noms et arborescences sont dans les charges AES-GCM des entrees.
  // L'API ne connait pas les dossiers du coffre, sauf le dossier explicitement partage dans une invitation.
  function folderPaths(){
    const paths=new Set();
    for(const item of state.items){
      if(item.value.deletedAt)continue;
      const value=String(item.value.type==='folder'?(item.value.path||item.value.folder||''):(item.value.folder||'')).trim();
      if(!value)continue;
      const parts=value.split('/').map(x=>x.trim());
      if(parts.length>4||parts.some(p=>!p||p.length>80))continue;
      for(let n=1;n<=parts.length;n++)paths.add(parts.slice(0,n).join('/'));
    }
    return [...paths].sort((a,b)=>a.localeCompare(b,'fr'));
  }
  function updateSelectOptions(select,values,emptyText){
    if(!select)return;
    const previous=select.value;
    select.replaceChildren();
    const empty=document.createElement('option');empty.value='';empty.textContent=emptyText;select.append(empty);
    for(const value of values){const opt=document.createElement('option');opt.value=value;opt.textContent='  '.repeat(value.split('/').length-1)+value;select.append(opt);}
    select.value=values.includes(previous)?previous:'';
  }
  function renderFolders(){
    const paths=folderPaths();
    updateSelectOptions($('folder-filter'),paths,'Tous les dossiers');
    $('folder-filter').value=paths.includes(state.folderSelected)?state.folderSelected:'';
    updateSelectOptions($('item-folder'),paths,'Sans dossier');
    updateSelectOptions($('folder-parent'),paths.filter(v=>v.split('/').length<4),'Nouvelle entreprise / société / cabinet');
    if($('admin-invite-folder'))updateSelectOptions($('admin-invite-folder'),paths.filter(p=>!p.includes('/')),'Choisir une entreprise existante');
  }
  function openFolderDialog(){
    if(!state.key)return;
    renderFolders();$('folder-name').value='';$('folder-dialog').showModal();$('folder-name').focus();
  }
  $('new-folder').onclick=openFolderDialog;
  $('item-new-folder').onclick=openFolderDialog;
  $('folder-close').onclick=()=>$('folder-dialog').close();
  $('folder-cancel').onclick=()=>$('folder-dialog').close();
  $('folder-form').addEventListener('submit',async e=>{
    e.preventDefault();
    const name=$('folder-name').value.trim(),parent=$('folder-parent').value;
    if(!name||name.length>80||/[\/\\\x00-\x1f]/.test(name)||name==='.'||name==='..')return toast('Nom de dossier invalide.');
    const path=parent?parent+'/'+name:name;
    if(path.split('/').length>4)return toast('Quatre niveaux maximum, entreprise comprise.');
    if(folderPaths().includes(path))return toast('Ce dossier existe déjà.');
    try{
      await saveValue(null,{type:'folder',name,path,folder:path,favorite:false});
      renderFolders();$('item-folder').value=path;$('folder-dialog').close();
      toast('Dossier créé : '+path);
    }catch(err){toast(err.message);}
  });
  function render(){if(!state.key)return;renderActions();renderCockpit();renderSecurityCenter();renderFolders();renderAccountShares();document.querySelectorAll('[data-filter]').forEach(el=>el.classList.toggle('active',el.dataset.filter===state.filter));const current=relevantItems();$('vault-filter').value=['all','favorite','login','card','identity','note','trash'].includes(state.filter)?state.filter:'all';$('section-title').textContent='Mon coffre';$('results-count').textContent=current.length+' élément'+(current.length>1?'s':'');const list=$('items-list');list.replaceChildren();if(!current.length){const empty=document.createElement('div');empty.className='list-empty';empty.innerHTML='<div class="blank-icon">◇</div><h3>Aucun élément</h3><p>Créez votre premier élément ou sélectionnez un autre filtre.</p>';list.append(empty);$('item-details').innerHTML='<div class="detail-empty"><div class="blank-icon">▣</div><h3>Aucun élément sélectionné</h3><p>Vos détails apparaîtront ici.</p></div>';return;}if(!current.some(x=>x.id===state.selectedId))state.selectedId=current[0].id;for(const item of current){const v=item.value;const row=document.createElement('button');row.type='button';row.className='vault-entry '+(state.selectedId===item.id?'selected':'');row.innerHTML=`<span class="entry-mark ${escapeHtml(v.type||'login')}">${escapeHtml((v.name||'?').slice(0,1).toUpperCase())}</span><span class="entry-text"><strong>${escapeHtml(v.name||'Sans nom')}</strong><small>${escapeHtml(item.shared?('Partagé par '+item.source):(v.type==='login'?v.username||v.url||'Identifiant':sublabels[v.type]||'Élément'))}</small><small class="entry-folder-path" title="Dossier">${escapeHtml(v.folder||'Sans dossier')}</small></span>${v.favorite?'<span class="gold-star">★</span>':''}`;row.onclick=()=>{state.selectedId=item.id;render();};list.append(row);}renderDetail();}
  function detailField(root,label,value,{secret=false,copy=false,multi=false}={}){if(!value)return;const wrap=document.createElement('div');wrap.className='detail-field';const l=document.createElement('div');l.className='detail-label';l.textContent=label;const row=document.createElement('div');row.className='detail-value';const span=document.createElement(multi?'pre':'span');span.className='detail-value-text';span.textContent=secret?'••••••••••••':value;row.append(span);if(secret){const b=document.createElement('button');b.type='button';b.className='icon-mini';b.textContent='Voir';let show=false,hideTimer=null;b.onclick=()=>{show=!show;span.textContent=show?value:'••••••••••••';b.textContent=show?'Masquer':'Voir';if(hideTimer)clearTimeout(hideTimer);if(show)hideTimer=setTimeout(()=>{show=false;span.textContent='••••••••••••';b.textContent='Voir';},15000);};row.append(b);}if(copy){const b=document.createElement('button');b.type='button';b.className='icon-mini';b.textContent='Copier';b.onclick=()=>copyText(value);row.append(b);}wrap.append(l,row);root.append(wrap);}
  function renderDetail(){const box=$('item-details');box.replaceChildren();const item=[...state.items,...state.receivedItems].find(x=>x.id===state.selectedId);if(!item)return;if(item.shared){renderSharedDetail(item);return;}const v=item.value;const head=document.createElement('div');head.className='detail-header';head.innerHTML=`<span class="detail-bigmark">${escapeHtml((v.name||'?').slice(0,1).toUpperCase())}</span><div><h2>${escapeHtml(v.name)}</h2><p>${escapeHtml(sublabels[v.type]||'Élément')}</p><span class="detail-folder-tag">Dossier : ${escapeHtml(v.folder||'Sans dossier')}</span></div>`;box.append(head);const actions=document.createElement('div');actions.className='detail-actions';const edit=document.createElement('button');edit.type='button';edit.className='btn primary';edit.textContent=v.deletedAt?'Restaurer':'Modifier';edit.onclick=()=>v.deletedAt?restoreItem(item.id):openEditor(item.id);actions.append(edit);if(!v.deletedAt){const deleteButton=document.createElement('button');deleteButton.type='button';deleteButton.className='btn danger ds-delete-entry';deleteButton.textContent='Supprimer';deleteButton.title='Placer cette fiche dans la corbeille';deleteButton.onclick=()=>moveItemToTrash(item.id);actions.append(deleteButton);const duplicate=document.createElement('button');duplicate.className='btn outline';duplicate.textContent='Dupliquer';duplicate.onclick=()=>{openEditor(null);const original=v;for(const field of fields)$('item-'+field).value=original[field]||'';$('item-type').value=original.type;$('item-name').value=(original.name||'Accès')+' (copie)';$('item-favorite').checked=false;updateItemType();};actions.append(duplicate);const fav=document.createElement('button');fav.className='btn outline';fav.textContent=v.favorite?'★ Favori':'☆ Favori';fav.onclick=()=>toggleFavorite(item.id);actions.append(fav);if(v.type==='login'&&typeof v.password==='string'&&v.password.length){const share=document.createElement('button');share.type='button';share.className='btn outline';share.textContent='Partager avec Send';share.onclick=()=>openSendDialog(item.id);actions.append(share);const accountShare=document.createElement('button');accountShare.type='button';accountShare.className='btn outline';accountShare.textContent='Donner accès à un compte';accountShare.onclick=()=>grantFromEntry(item);actions.append(accountShare);}}else {const remove=document.createElement('button');remove.className='btn danger';remove.textContent='Supprimer définitivement';remove.onclick=()=>deleteForever(item.id);actions.append(remove);}box.append(actions);const info=document.createElement('div');info.className='detail-info';if(v.type==='login'){detailField(info,'Nom d’utilisateur',v.username,{copy:true});detailField(info,'Mot de passe',v.password,{secret:true,copy:true});detailField(info,'Adresse du site',v.url,{copy:true});detailField(info,'Autres adresses de connexion',v.loginUrls,{multi:true});}if(v.type==='card'){detailField(info,'Titulaire',v.cardHolder);detailField(info,'Numéro',v.cardNumber,{secret:true,copy:true});detailField(info,'Expiration',v.expiry);detailField(info,'Cryptogramme',v.cvv,{secret:true,copy:true});}if(v.type==='identity'){for(const [k,n] of [['firstName','Prénom'],['lastName','Nom'],['email','E-mail'],['phone','Téléphone'],['address','Adresse']])detailField(info,n,v[k],{copy:true});}if(v.type==='ssh'){detailField(info,'Clé publique',v.publicKey,{multi:true,copy:true});detailField(info,'Clé privée',v.privateKey,{multi:true,secret:true,copy:true});}detailField(info,'Dossier',v.folder);detailField(info,'Notes sécurisées',v.notes,{multi:true});detailField(info,'Dernière modification',fmt(item.updatedAt));if(Array.isArray(v.history)&&v.history.length){detailField(info,'Historique local de la fiche (non certifie)',v.history.slice(-5).reverse().map(x=>fmt(x.at)+' · '+x.action).join('\n'),{multi:true});}box.append(info);}
  async function saveValue(id,value){const itemBefore=id?state.items.find(x=>x.id===id):null;const prev=Array.isArray(itemBefore?.value?.history)?itemBefore.value.history:[];value.history=[...prev.slice(-14),{at:new Date().toISOString(),action:id?'Fiche mise a jour':'Fiche creee'}];const payload=await encrypt(value,state.key);if(id){const result=await api('/api/vault/entries/'+encodeURIComponent(id),'PUT',{payload});const item=state.items.find(x=>x.id===id);item.value=value;item.updatedAt=result.updatedAt;}else{const result=await api('/api/vault/entries','POST',{payload});state.items.push({id:result.id,updatedAt:result.updatedAt,value});state.selectedId=result.id;}render();scheduleShareSync();}
  async function toggleFavorite(id){const item=state.items.find(x=>x.id===id);if(!item)return;try{await saveValue(id,{...item.value,favorite:!item.value.favorite});}catch(e){toast(e.message);}}
  function updateItemType(){for(const type of ['login','card','identity','ssh'])$(type+'-fields').hidden=$('item-type').value!==type;}
  $('item-type').onchange=updateItemType;
  function openEditor(id=null){if(!state.key){toast('Déverrouillez votre coffre avant de modifier.');return;}renderFolders();const item=state.items.find(x=>x.id===id);if(id&&!item){toast('Cette fiche n’est plus disponible : actualisez le coffre.');return;}const v=item?.value||{type:'login',name:'',favorite:false};state.editId=id;$('item-form').reset();$('dialog-title').textContent=id?'Modifier '+(v.type==='login'?'un identifiant':'une fiche'):'Nouvel élément';$('item-form-error').hidden=true;$('item-form-error').textContent='';$('item-type').value=v.type||'login';$('item-name').value=v.name||'';for(const field of fields)$('item-'+field).value=v[field]??'';$('item-favorite').checked=!!v.favorite;$('delete-item').hidden=!id;$('item-password').type='password';$('toggle-password').textContent='Voir';updateItemType();$('item-dialog').showModal();$('item-name').focus();}
  $('new-item').onclick=()=>openEditor();$('cockpit-add').onclick=()=>{navigate('cockpit');openEditor();};$('close-dialog').onclick=()=>$('item-dialog').close();$('cancel-dialog').onclick=()=>$('item-dialog').close();$('item-dialog').addEventListener('close',()=>{state.editId=null;$('item-form').reset();});
  function itemFormError(message,focusId=null){
    const box=$('item-form-error');box.textContent=message;box.hidden=false;
    if(focusId && $(focusId))$(focusId).focus();
    toast(message);
  }
  function normalizeItemUrl(raw){
    const text=String(raw||'').trim();
    if(!text)return '';
    // Les anciennes fiches pouvaient contenir un domaine sans protocole.
    // Ne pas les rendre impossibles à modifier ; proposer HTTPS par défaut.
    const candidate=/^[a-z][a-z0-9+.-]*:\/\//i.test(text)?text:'https://'+text;
    const url=new URL(candidate);
    const local=['localhost','127.0.0.1','[::1]'].includes(url.hostname);
    if(url.username||url.password||!['http:','https:'].includes(url.protocol)||(!local&&url.protocol!=='https:'))throw Error('Adresse du site invalide : utilisez HTTPS (HTTP uniquement en local).');
    return candidate;
  }
  $('item-form').addEventListener('submit',async e=>{
    e.preventDefault();
    if(!state.key)return itemFormError('Déverrouillez votre coffre pour enregistrer.');
    const error=$('item-form-error');error.hidden=true;error.textContent='';
    const name=$('item-name').value.trim();
    if(!name)return itemFormError('Donnez un nom à la fiche.','item-name');
    const existing=state.editId?state.items.find(x=>x.id===state.editId):null;
    if(state.editId&&!existing)return itemFormError('Cette fiche n’est plus disponible. Actualisez votre coffre.');
    const existingValue=existing?.value;
    const value={...(existingValue||{}),type:$('item-type').value,name,favorite:$('item-favorite').checked};
    for(const field of fields)value[field]=$('item-'+field).value;
    // Contrôler uniquement les champs du type actuellement visible : les anciennes
    // valeurs masquées ne doivent pas interdire une mise à jour du mot de passe.
    if(value.type==='login'){
      try{
        value.url=normalizeItemUrl(value.url);
        const secondary=String(value.loginUrls||'').split(/[\n,;]/).map(x=>x.trim()).filter(Boolean);
        if(secondary.length>10)throw Error('10 adresses de connexion supplémentaires maximum.');
        value.loginUrls=secondary.map(normalizeItemUrl).join('\n');
      }catch(err){return itemFormError(err.message,'item-url');}
    }
    if(value.type==='identity' && value.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.email)){
      return itemFormError('L’adresse e-mail de cette identité est invalide.','item-email');
    }
    value.tags=actionTools.tags(value.tags).join(', ');
    $('save-item').disabled=true;
    try{
      await saveValue(state.editId,value);
      const wasEditing=!!state.editId;
      $('item-dialog').close();
      toast(wasEditing?'Fiche et mot de passe modifiés.':'Nouvelle fiche enregistrée.');
    }catch(err){itemFormError('Enregistrement impossible : '+err.message);}
    finally{$('save-item').disabled=false;}
  });
  async function moveItemToTrash(id){
    const item=state.items.find(x=>x.id===id);
    if(!item || item.value.deletedAt)return;
    if(!confirm('Supprimer « '+String(item.value.name||'cet identifiant')+' » ?\nLa fiche ira dans la corbeille et pourra être restaurée.'))return;
    try{
      await saveValue(id,{...item.value,deletedAt:new Date().toISOString()});
      if($('item-dialog').open)$('item-dialog').close();
      toast('Fiche supprimée. Vous pouvez la restaurer depuis le filtre Corbeille.');
    }catch(e){toast('Suppression impossible : '+e.message);}
  }
  $('delete-item').onclick=()=>moveItemToTrash(state.editId);
  async function restoreItem(id){try{const item=state.items.find(x=>x.id===id);const value={...item.value};delete value.deletedAt;await saveValue(id,value);toast('Élément restauré.');}catch(e){toast(e.message);}}
  async function deleteForever(id){if(!confirm('Supprimer définitivement cet élément ? Cette opération est irréversible.'))return;try{await api('/api/vault/entries/'+id,'DELETE');state.items=state.items.filter(x=>x.id!==id);state.selectedId=null;render();scheduleShareSync();toast('Élément définitivement supprimé.');}catch(e){toast(e.message);}}
  $('toggle-password').onclick=()=>{const el=$('item-password');el.type=el.type==='password'?'text':'password';$('toggle-password').textContent=el.type==='password'?'Voir':'Masquer';};
  function uniformIndex(max){const upper=Math.floor(256/max)*max;while(true){const v=rand(1)[0];if(v<upper)return v%max;}}
  const pick=s=>s[uniformIndex(s.length)];
  const WORDS='arbre avion accueil alliance amande animal argent artiste avenir ballon bateau beauté berceau biscuit bleu bonheur bougie branche brise bronze bureau cabane cadeau calme campagne canal carte cerise chance chanson chemin cheval ciel citron clair clavier colline couleur courage cuisine danse dauphin demain dessert diamant dimanche dragon dune école éclair étoile famille fenêtre fleur forêt fromage fruit fusée galaxie jardin jaune jeudi journal joueur juillet lampe liberté lumière lune maison matin mer mercredi miroir montagne musique nature navire neige nuage océan orange ours papier paradis parfum parole pastel pêche peinture pensée pierre planète plage plume poésie pomme printemps projet puzzle quartz radio raisin renard rivière robot rose route samedi sable saison secret soleil souris sourire sportif table tapis terre théâtre tigre tomate train trésor tulipe unique univers valise vélo vent verre violet voyage wagon xylophone yaourt zèbre zen'.split(' ');
  function passwordGen(length=24){const parts=[];if($('gen-upper').checked)parts.push('ABCDEFGHJKLMNPQRSTUVWXYZ');if($('gen-lower').checked)parts.push('abcdefghijkmnopqrstuvwxyz');if($('gen-digits').checked)parts.push('23456789');if($('gen-symbols').checked)parts.push('!@#$%&*?_+-=');if(!parts.length){toast('Sélectionnez au moins un jeu de caractères.');return '';}const alphabet=parts.join('');const out=parts.map(pick);while(out.length<length)out.push(pick(alphabet));for(let i=out.length-1;i>0;i--){let j=uniformIndex(i+1);[out[i],out[j]]=[out[j],out[i]];}return out.join('');}
  let phraseMode=false;
  function regen(){const value=phraseMode?Array.from({length:12},()=>pick(WORDS)).join('-'):passwordGen(Number($('gen-length').value));$('generator-result').value=value;}
  $('gen-length').oninput=()=>{$('gen-length-label').textContent=$('gen-length').value;regen();};
  for(const x of ['gen-upper','gen-lower','gen-digits','gen-symbols'])$(x).onchange=regen;
  $('gen-password-mode').onclick=()=>{phraseMode=false;$('gen-password-mode').classList.add('selected');$('gen-phrase-mode').classList.remove('selected');$('gen-length').disabled=false;regen();};
  $('gen-phrase-mode').onclick=()=>{phraseMode=true;$('gen-phrase-mode').classList.add('selected');$('gen-password-mode').classList.remove('selected');$('gen-length').disabled=true;regen();};
  $('regen-btn').onclick=regen;$('copy-generated').onclick=()=>copyText($('generator-result').value);
  $('generate-password').onclick=()=>{const pass=passwordGen(24);$('item-password').value=pass;$('item-password').type='text';$('toggle-password').textContent='Masquer';toast('Mot de passe généré.');};
  $('search-input').oninput=e=>{state.search=e.target.value;render();};$('sort-select').onchange=render;
  // Send: token opaque en chemin, cle AES-256 dans le fragment et jamais envoyee au serveur.
  async function loadSends(){const payload=await api('/api/sends');state.sends=await Promise.all(payload.sends.map(async s=>({...s,owner:await decrypt(s.ownerPayload,state.key)})));renderSends();}
  function sendLink(s){return location.origin+'/s/'+s.owner.token+'#k='+s.owner.key;}
  function renderSends(){const target=$('sends-list');target.replaceChildren();for(const send of state.sends.filter(x=>state.sendFilter==='all'||x.kind===state.sendFilter)){const expired=Date.parse(send.expiresAt)<=Date.now();const used=send.maxViews!==null&&send.views>=send.maxViews;const status=expired?'Expiré':send.disabled?'Désactivé':used?'Limite atteinte':'Actif';const row=document.createElement('div');row.className='table-row';row.innerHTML=`<div class="send-name"><span class="file-bubble">${send.kind==='file'?'▤':'☷'}</span><div><strong>${escapeHtml(send.owner.name||'Sans nom')}</strong><small>${send.kind==='file'?'Fichier':'Texte'}</small></div></div><span><span class="status-tag ${status==='Actif'?'status-active':'status-off'}">${status}</span></span><span class="date-cell">${escapeHtml(fmt(send.expiresAt))}</span><span>${send.views}${send.maxViews===null?'':' / '+send.maxViews}</span><span class="send-actions"></span>`;const actions=row.querySelector('.send-actions');const link=document.createElement('button');link.className='mini-action';link.textContent='Copier le lien';link.onclick=()=>copyText(sendLink(send));actions.append(link);if(!expired){const toggle=document.createElement('button');toggle.className='mini-action';toggle.textContent=send.disabled?'Activer':'Désactiver';toggle.onclick=async()=>{try{await api('/api/sends/'+send.id,'PATCH',{disabled:!send.disabled});send.disabled=!send.disabled;renderSends();toast('Statut mis à jour.');}catch(err){toast(err.message);}};actions.append(toggle);}const remove=document.createElement('button');remove.className='mini-action danger-link';remove.textContent='Supprimer';remove.onclick=async()=>{if(!confirm('Supprimer ce partage définitivement ?'))return;try{await api('/api/sends/'+send.id,'DELETE');state.sends=state.sends.filter(x=>x.id!==send.id);renderSends();}catch(err){toast(err.message);}};actions.append(remove);target.append(row);}if(!target.children.length){const el=document.createElement('div');el.className='list-empty';el.innerHTML='<div class="blank-icon">➤</div><h3>Aucun Send</h3><p>Créez un lien de partage sécurisé pour commencer.</p>';target.append(el);}}
  document.querySelectorAll('[data-send-filter]').forEach(b=>b.onclick=()=>{state.sendFilter=b.dataset.sendFilter;document.querySelectorAll('[data-send-filter]').forEach(x=>x.classList.toggle('selected',x===b));renderSends();});
  $('refresh-sends').onclick=()=>loadSends().then(()=>toast('Liste actualisée.')).catch(e=>toast(e.message));
  function shareableLogins(){
    return state.items.filter(item=>item.value.type==='login'&&!item.value.deletedAt&&
      typeof item.value.password==='string'&&item.value.password.length>0)
      .sort((a,b)=>String(a.value.name||'').localeCompare(String(b.value.name||''),'fr'));
  }
  function renderSendEntries(preferredId=null){
    const select=$('send-entry');
    const selected=preferredId||select.value;
    select.replaceChildren(new Option('Choisir un identifiant enregistré…',''));
    const entries=shareableLogins();
    for(const item of entries){
      const title=String(item.value.name||'Sans nom');
      const user=String(item.value.username||'');
      select.add(new Option(title+(user?' — '+user:''),item.id));
    }
    if(entries.some(item=>item.id===selected))select.value=selected;
    updateSendPreview();
  }
  function updateSendPreview(){
    const item=shareableLogins().find(entry=>entry.id===$('send-entry').value);
    $('send-entry-preview').textContent=item?
      'Fiche : '+String(item.value.name||'Sans nom')+' · Identifiant : '+String(item.value.username||'non renseigné')+' · Mot de passe : ••••••••':
      (shareableLogins().length?'Sélectionnez la fiche à partager.':'Aucun mot de passe disponible. Ajoutez une fiche Identifiant ou partagez un texte libre.');
  }
  function updateSendMode(){
    const mode=document.querySelector('input[name="send-mode"]:checked').value;
    $('send-login-wrap').hidden=mode!=='login';
    $('send-text-wrap').hidden=mode!=='text';
    $('send-file-wrap').hidden=mode!=='file';
    $('send-entry').disabled=mode!=='login';
    $('send-text').disabled=mode!=='text';
    $('send-file').disabled=mode!=='file';
    $('send-login-note').disabled=mode!=='login';
    $('send-hidden').disabled=mode!=='text';
    $('send-hidden').closest('label').hidden=mode!=='text';
    updateSendPreview();
  }
  function openSendDialog(entryId=null){
    if(!state.key)return;
    $('send-form').reset();
    $('send-form-error').hidden=true;$('send-form-error').textContent='';
    $('send-options').open=false;
    $('send-created').hidden=true;
    $('send-result-link').value='';
    $('send-submit').hidden=false;
    $('send-mode-login').checked=true;
    renderSendEntries(entryId);
    updateSendMode();
    $('send-dialog').showModal();
    $('send-entry').focus();
  }
  $('new-send').onclick=()=>openSendDialog();
  $('send-close').onclick=()=>$('send-dialog').close();
  $('send-cancel').onclick=()=>$('send-dialog').close();
  $('send-dialog').addEventListener('close',()=>{
    $('send-form').reset();$('send-result-link').value='';$('send-created').hidden=true;$('send-form-error').hidden=true;
  });
  for(const id of ['send-mode-login','send-mode-text','send-mode-file'])$(id).onchange=updateSendMode;
  $('send-entry').onchange=updateSendPreview;
  $('send-another').onclick=()=>{
    $('send-form').reset();$('send-options').open=false;
    $('send-result-link').value='';$('send-created').hidden=true;
    $('send-submit').hidden=false;
    renderSendEntries();updateSendMode();$('send-entry').focus();
  };
  $('send-copy').onclick=()=>{const link=$('send-result-link').value;if(link)copyText(link);};
  const fileToB64 = file => new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onload=()=>resolve(String(reader.result).split(',')[1]);
    reader.onerror=()=>reject(Error('Lecture du fichier impossible.'));
    reader.readAsDataURL(file);
  });
  function buildSendContent(){
    const mode=document.querySelector('input[name="send-mode"]:checked').value;
    if(mode==='text'){
      const text=$('send-text').value;
      if(!text.trim())throw Error('Saisissez un texte à partager.');
      return {kind:'text',text,hidden:$('send-hidden').checked,defaultName:'Partage du '+new Date().toLocaleString('fr-FR',{dateStyle:'short',timeStyle:'short'})};
    }
    if(mode==='login'){
      const item=shareableLogins().find(entry=>entry.id===$('send-entry').value);
      if(!item)throw Error('Choisissez un mot de passe enregistré dans le coffre.');
      const v=item.value,title=String(v.name||'Sans nom');
      const lines=['Fiche : '+title];
      if(v.username)lines.push('Identifiant : '+String(v.username));
      lines.push('Mot de passe : '+v.password);
      const note=$('send-login-note').value.trim();
      if(note)lines.push('','Message : '+note);
      const text=lines.join('\n');
      if(text.length>20000)throw Error('Le contenu à partager est trop long.');
      return {kind:'text',text,hidden:true,defaultName:'Accès — '+title.slice(0,140),title};
    }
    return {kind:'file',defaultName:'Fichier partagé'};
  }
  $('send-form').addEventListener('submit',async e=>{
    e.preventDefault();
    if(!state.key)return;
    const ticket=guard.ticket(),button=$('send-submit');
    const password=$('send-pass').value,maxStr=$('send-max').value.trim();
    $('send-form-error').hidden=true;
    if(password&&password.length<8){$('send-form-error').textContent='Le mot de passe d’accès au lien doit contenir 8 caractères minimum.';$('send-form-error').hidden=false;return;}
    if(maxStr&&(!Number.isInteger(Number(maxStr))||Number(maxStr)<1||Number(maxStr)>1000)){
      $('send-form-error').textContent='La limite de lectures doit être comprise entre 1 et 1000.';$('send-form-error').hidden=false;return;
    }
    button.disabled=true;
    try{
      const share=buildSendContent();
      const name=$('send-name').value.trim()||share.defaultName;
      let content;
      if(share.kind==='text'){
        if(share.title&&!confirm('Partager le mot de passe de « '+share.title+' » ?\n\nLa personne disposant du lien pourra lire ce mot de passe.'))return;
        content={kind:'text',name,text:share.text,hidden:share.hidden};
      }else{
        const file=$('send-file').files?.[0];
        if(!file)throw Error('Sélectionnez un fichier à partager.');
        if(file.size>2*1024*1024)throw Error('Fichier trop volumineux : 2 Mo maximum.');
        content={kind:'file',name,fileName:file.name,fileType:file.type||'application/octet-stream',bytes:await fileToB64(file)};
      }
      assertActive(ticket);
      const keyBytes=rand(32),key=await rawKey(keyBytes);
      const token=urlB64(rand(32)),keyB64=urlB64(keyBytes);
      const payload=await encrypt(content,key);
      assertActive(ticket);
      const ownerPayload=await encrypt({token,key:keyB64,name,notes:''},state.key);
      assertActive(ticket);
      await api('/api/sends','POST',{
        token,kind:share.kind,expireHours:Number($('send-expire').value),
        maxViews:maxStr?Number(maxStr):null,password:password||null,payload,ownerPayload
      });
      assertActive(ticket);
      const link=location.origin+'/s/'+token+'#k='+keyB64;
      $('send-result-link').value=link;
      $('send-created').hidden=false;
      $('send-submit').hidden=true;
      // Effacer du formulaire le texte, le mot de passe de protection et la piece jointe.
      $('send-text').value='';$('send-login-note').value='';$('send-pass').value='';$('send-file').value='';
      // Le lien reste disponible même si la copie ou l'actualisation de la liste échoue.
      try{await navigator.clipboard.writeText(link);if(guard.active(ticket))toast('Send créé : lien copié.');}
      catch{if(guard.active(ticket))toast('Send créé : utilisez le bouton « Copier le lien ».');}
      if(guard.active(ticket)&&state.key){
        try{await loadSends();}catch(err){if(guard.active(ticket))toast('Send créé. Actualisez la liste ultérieurement.');}
      }
    }catch(err){if(guard.active(ticket)&&state.key){$('send-form-error').textContent=err.message;$('send-form-error').hidden=false;toast(err.message);}}
    finally{button.disabled=false;}
  });
  async function adminStatus(){
    const r=await fetch('/api/admin/status',{credentials:'same-origin',cache:'no-store'});
    if(!r.ok)throw Error('Administration non disponible.');return (await r.json()).unlocked;
  }
  let adminBusy=false;
  async function loadAdmin(){
    if(!$('admin-auth-box')||!state.key||adminBusy)return;
    adminBusy=true;
    try{
      const unlocked=await adminStatus();
      $('admin-auth-box').hidden=unlocked;$('admin-panel').hidden=!unlocked;
      if(unlocked)await loadAdminInvitations();
    }finally{adminBusy=false;}
  }
  async function loadAdminInvitations(){
    const data=await api('/api/admin/invitations');
    const list=$('admin-invite-list');list.replaceChildren();
    if(!data.invitations.length){const msg=document.createElement('p');msg.textContent='Aucune invitation créée.';list.append(msg);return;}
    for(const inv of data.invitations){
      const box=document.createElement('div');box.className='ds-invite-card';
      const name=document.createElement('strong');name.textContent=inv.email;
      const details=document.createElement('p');details.textContent=inv.folder+' · expiration : '+fmt(inv.expiresAt);
      const status=document.createElement('small');status.textContent=inv.revoked?'Révoquée':inv.contribution?(inv.contribution.imported?'Importé dans le coffre':'Dépôt reçu'):inv.used?'Utilisée':new Date(inv.expiresAt)<new Date()?'Expirée':'En attente';
      box.append(name,details,status);
      if(inv.contribution&&!inv.contribution.imported){
        const importBtn=document.createElement('button');importBtn.className='btn primary';importBtn.type='button';importBtn.textContent='Déchiffrer et importer les identifiants';
        importBtn.onclick=async()=>{
          importBtn.disabled=true;
          try{await importContribution(inv);toast('Dépôt importé dans le coffre.');await loadAdminInvitations();}
          catch(err){toast(err.message);}finally{importBtn.disabled=false;}
        };box.append(importBtn);
      }
      if(!inv.revoked&&!inv.used&&new Date(inv.expiresAt)>=new Date()){
        const revoke=document.createElement('button');revoke.className='btn outline';revoke.type='button';revoke.textContent='Révoquer le lien';
        revoke.onclick=async()=>{if(!confirm('Révoquer définitivement ce lien ?'))return;try{await api('/api/admin/invitations/'+encodeURIComponent(inv.id)+'/revoke','POST',{});await loadAdminInvitations();}catch(err){toast(err.message);}};
        box.append(revoke);
      }
      list.append(box);
    }
  }
  async function importContribution(inv){
    if(!state.key)throw Error('Déverrouillez votre coffre.');
    const c=inv.contribution;
    const unlocked=await decrypt(inv.encryptedPrivateKey,state.key);
    if(!unlocked||typeof unlocked.pkcs8!=='string')throw Error('Clé de déchiffrement invalide.');
    const privateKey=await crypto.subtle.importKey('pkcs8',fromB64(unlocked.pkcs8),{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
    const encrypted=c.payload;
    const aesRaw=await crypto.subtle.decrypt({name:'RSA-OAEP'},privateKey,fromB64(encrypted.wrappedKey));
    const aes=await rawKey(new Uint8Array(aesRaw));
    const result=await decrypt({v:1,iv:encrypted.iv,data:encrypted.data},aes);
    if(!result||!Array.isArray(result.entries)||result.entries.length<1||result.entries.length>20)throw Error('Contenu du dépôt invalide.');
    // Le serveur n'a jamais les données en clair : le périmètre est vérifié au moment de l'import local.
    const root=inv.folder;
    for(const [index,entry] of result.entries.entries()){
      if(entry?.type!=='login'||typeof entry.name!=='string'||typeof entry.username!=='string'||typeof entry.password!=='string'||
          !entry.name||!entry.username||!entry.password||entry.password.length>1024||entry.name.length>120||
          typeof entry.folder!=='string'||!(entry.folder===root||entry.folder.startsWith(root+'/'))||
          entry.folder.split('/').length>4||entry.folder.split('/').some(s=>!s||s.length>80)||
          (entry.url&&(!/^https?:\/\//i.test(entry.url)||entry.url.length>1000)))throw Error('Identifiant reçu hors du dossier autorisé.');
      const marker=c.id+':'+index;
      if(state.items.some(x=>x.value.contributionId===marker))continue;
      const value={type:'login',name:entry.name,username:entry.username,password:entry.password,url:entry.url||'',folder:entry.folder,favorite:false,contributionId:marker};
      await saveValue(null,value);
    }
    await api('/api/admin/contributions/'+encodeURIComponent(c.id)+'/imported','POST',{});
  }
  if($('admin-auth-form')){
    $('admin-auth-form').addEventListener('submit',async e=>{
      e.preventDefault();const pass=$('admin-password').value;$('admin-password').value='';
      try{await api('/api/admin/unlock','POST',{password:pass});await loadAdmin();}catch(err){toast(err.message);}
    });
    $('admin-lock').onclick=async()=>{try{await api('/api/admin/lock','POST',{});await loadAdmin();}catch(err){toast(err.message);}};
    $('admin-invite-form').addEventListener('submit',async e=>{
      e.preventDefault();if(!state.key)return toast('Déverrouillez le coffre.');
      const button=$('admin-invite-form').querySelector('button[type=submit]');button.disabled=true;
      try{
        const folder=$('admin-invite-folder').value;
        if(!folder||folder.includes('/')||!folderPaths().includes(folder))throw Error('Choisissez une entreprise existante.');
        const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
        const publicKey=b64(new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey)));
        const pkcs8=b64(new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey)));
        const encryptedPrivateKey=await encrypt({pkcs8},state.key);
        const result=await api('/api/admin/invitations','POST',{
          email:$('admin-invite-email').value.trim(),folder,expiresHours:Number($('admin-invite-expiry').value),publicKey,encryptedPrivateKey});
        $('admin-invite-url').value=result.url;$('admin-invite-result').hidden=false;
        $('admin-invite-email').value='';toast('Lien créé, à transmettre uniquement au destinataire.');await loadAdminInvitations();
      }catch(err){toast(err.message);}finally{button.disabled=false;}
    });
    $('admin-copy-url').onclick=()=>copyText($('admin-invite-url').value);
  }

  async function exportVault(){const entries=await Promise.all(state.items.map(async item=>({payload:await encrypt(item.value,state.key)})));const data={format:'ml2c-vault-backup-v1',createdAt:new Date().toISOString(),salt:state.initial.salt,kdfVersion:state.initial.kdfVersion||1,check:state.initial.check,entries};const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='ml2c-vault-chiffre-'+new Date().toISOString().slice(0,10)+'.json';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Sauvegarde chiffrée exportée.');}
  $('export-vault').onclick=()=>exportVault().catch(e=>toast(e.message));
  function requestVaultPassword(){
    return new Promise(resolve=>{
      const dialog=document.createElement('dialog');
      const form=document.createElement('form');
      const label=document.createElement('label');
      const input=document.createElement('input');
      const cancel=document.createElement('button');
      const submit=document.createElement('button');
      let settled=false;
      const finish=value=>{if(settled)return;settled=true;if(dialog.open)dialog.close();dialog.remove();resolve(value);};
      label.textContent='Mot de passe du coffre au moment de cette sauvegarde';
      input.type='password';input.autocomplete='current-password';input.required=true;
      label.append(input);
      cancel.type='button';cancel.textContent='Annuler';cancel.addEventListener('click',()=>finish(null));
      submit.type='submit';submit.textContent='Continuer';
      form.append(label,cancel,submit);
      form.addEventListener('submit',event=>{event.preventDefault();finish(input.value);});
      dialog.addEventListener('cancel',event=>{event.preventDefault();finish(null);});
      dialog.append(form);document.body.append(dialog);dialog.showModal();input.focus();
    });
  }
  $('import-vault').onclick=async()=>{
    const file=$('import-file').files?.[0];
    if(!file)return toast('Choisissez une sauvegarde JSON.');
    if(file.size>5_000_000)return toast('Sauvegarde trop volumineuse.');
    try{
      const data=JSON.parse(await file.text()),backupVersion=data.kdfVersion??1;
      if(data.format!=='ml2c-vault-backup-v1'||![1,2].includes(backupVersion)||!Array.isArray(data.entries)||data.entries.length>500||typeof data.salt!=='string'||fromB64(data.salt).length!==16)throw Error('Sauvegarde incompatible ou trop volumineuse.');
      let backupKey=state.key;
      if(backupVersion!==(state.initial.kdfVersion||1)||data.salt!==state.initial.salt){
        const pass=await requestVaultPassword();
        if(pass===null)return;
        backupKey=await vaultKey(pass,data.salt,backupVersion);
      }
      if(await decrypt(data.check,backupKey)!=='vault-ready-v1')throw Error('Mot de passe de la sauvegarde incorrect.');
      if(!confirm('Importer '+data.entries.length+' éléments ? Les doublons seront conservés.'))return;
      let count=0;
      for(const entry of data.entries){
        const value=await decrypt(entry.payload,backupKey);
        if(!value||typeof value.name!=='string')throw Error('Entrée invalide.');
        const payload=await encrypt(value,state.key);
        const result=await api('/api/vault/entries','POST',{payload});
        state.items.push({id:result.id,updatedAt:result.updatedAt,value});count++;
      }
      render();toast(count+' éléments importés.');
    }catch(e){toast('Import : '+e.message);}
  };
  $('unlock-otp-send').onclick=async()=>{
    const button=$('unlock-otp-send');button.disabled=true;lockError();
    try{
      const r=await fetch('/2fa/send',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','X-CSRF-Token':otpCsrf},body:'{}'});
      const data=await r.json();if(!r.ok)throw Error(data.error||'Envoi du code impossible.');
      toast(data.message||'Code envoyé.');
    }catch(e){lockError(e.message);}finally{button.disabled=false;}
  };
  // Partage nominatif : l'adresse e-mail sert a retrouver un compte existant,
  // jamais a deriv er une cle cryptographique. Seul le destinataire possede sa cle privee.
  const shareCrypto=window.DatensisAccountSharing;
  let shareSyncTimer=null;
  let shareInitPromise=null;
  function shareStatus(message='',problem=false){
    const node=$('account-share-status');
    if(!node)return;
    node.hidden=!message;
    node.textContent=message;
    node.dataset.problem=problem?'1':'0';
    node.classList.toggle('error-alert',problem);
  }
  function shareLoadError(error){
    console.warn('Chargement des partages impossible :',error);
    shareStatus('Impossible de charger les partages : '+(error?.message||'erreur inconnue')+'. Réessayez avec « Actualiser les partages ».',true);
    // Ne jamais presenter une erreur de chargement comme « Aucune demande ».
    const incoming=$('account-share-incoming');
    if(incoming&&!state.accountSharing){
      incoming.replaceChildren(shareCard('Demandes non chargées','La liste n’a pas pu être récupérée. Utilisez « Actualiser les partages ».').card);
    }
  }
  async function ensureAccountSharing(ticket=guard.ticket()){
    if(!state.key)return;
    if(shareInitPromise)return shareInitPromise;
    if(state.accountSharing?.privateKey){
      try{await refreshAccountShares(ticket);}
      catch(error){if(guard.active(ticket))shareLoadError(error);throw error;}
      return;
    }
    shareStatus('Chargement des demandes reçues…');
    const attempt=initAccountSharing(ticket);
    shareInitPromise=attempt;
    try{await attempt;shareStatus('');}
    catch(error){if(guard.active(ticket))shareLoadError(error);throw error;}
    finally{if(shareInitPromise===attempt)shareInitPromise=null;}
  }
  function accountShareState(){
    return state.accountSharing || {identity:null,privateKey:null,outgoing:[],incoming:[],received:[]};
  }
  async function initAccountSharing(ticket){
    if(!shareCrypto)throw Error('Module de chiffrement des partages absent.');
    let identity=await api('/api/shares/identity');
    assertActive(ticket);
    if(!identity.publicKey){
      const keys=await shareCrypto.createIdentity(state.key,encrypt);
      assertActive(ticket);
      try {await api('/api/shares/identity','POST',keys);}
      catch(e){if(!/déjà|existe/i.test(e.message))throw e;}
      identity=await api('/api/shares/identity');
    }
    assertActive(ticket);
    if(!identity.encryptedPrivateKey)throw Error('Clé privée de partage manquante.');
    const privateKey=await shareCrypto.privateKey(identity.encryptedPrivateKey,state.key,decrypt);
    assertActive(ticket);
    state.accountSharing={identity,privateKey,outgoing:[],incoming:[],received:[]};
    await refreshAccountShares(ticket);
    assertActive(ticket);
    // Une nouvelle fiche ou un nouveau sous-dossier n'est synchronise que par le
    // navigateur du proprietaire, lorsque son coffre est deverrouille.
    await syncOutgoingShares(ticket);
  }
  function sharePath(scope,target){
    return scope==='folder'?target:(state.items.find(x=>x.id===target)?.value?.name||'Identifiant');
  }
  function shareTargetChoices(select,scope,preferred=''){
    const choices=scope==='folder'
      ? folderPaths()
      : state.items.filter(x=>x.value.type==='login'&&!x.value.deletedAt&&x.value.password).map(x=>({id:x.id,name:x.value.name||'Accès'}));
    select.replaceChildren();
    for(const item of choices){
      const opt=document.createElement('option');opt.value=scope==='folder'?item:item.id;
      opt.textContent=scope==='folder'?item:item.name;select.append(opt);
    }
    if(preferred&&[...select.options].some(x=>x.value===preferred))select.value=preferred;
  }
  function shareMapping(id){return state.items.find(x=>x.value.type==='shareTarget'&&x.value.shareId===id);}
  function buildReceivedItems(rows){
    const collection=[];
    for(const row of rows){
      if(!row.accepted||!row.decoded||!Array.isArray(row.decoded.entries))continue;
      const mapping=shareMapping(row.id);
      const root=String(mapping?.value.targetFolder||'');
      const entries=row.decoded.entries.slice(0,100);
      for(let i=0;i<entries.length;i++){
        const entry=entries[i];
        if(!entry||typeof entry.password!=='string'||typeof entry.name!=='string')continue;
        // Les sous-dossiers recus se calent sur le dossier choisi par le destinataire.
        // Aucune creation automatique de dossiers non demandes.
        const folder=String((mapping?.value.subfolderMappings||{})[String(entry.relativeFolder||'')]||root);
        collection.push({
          id:'shared:'+row.id+':'+i,
          updatedAt:row.updatedAt?.replace(' ','T')+'Z'||new Date().toISOString(),
          shared:true,source:row.ownerEmail,shareId:row.id,
          value:{type:'login',name:entry.name,username:String(entry.username||''),password:entry.password,
            url:String(entry.url||''),folder,originalSubfolder:String(entry.relativeFolder||'')},
        });
      }
    }
    return collection;
  }
  async function refreshAccountShares(ticket=guard.ticket()){
    const sharing=state.accountSharing;
    if(!sharing||!sharing.privateKey||!state.key)return;
    const data=await api('/api/shares');
    assertActive(ticket);
    const expectedAccount=String($('app-shell')?.dataset.accountEmail||'').toLowerCase();
    if(!data.accountEmail||!expectedAccount||String(data.accountEmail).toLowerCase()!==expectedAccount){
      throw Error('La session du navigateur a changé de compte. Déconnectez-vous et reconnectez-vous à votre compte.');
    }
    const outgoing=[];
    for(const row of data.outgoing||[]){
      let metadata;
      try {metadata=await decrypt(row.ownerMetadata,state.key);}
      catch {metadata={title:'Dossier inaccessible',scope:row.scope};}
      outgoing.push({...row,metadata});
    }
    const incoming=[];
    for(const row of data.incoming||[]){
      let decoded=null;
      if(row.accepted&&row.encryptedBundle){
        try{decoded=await shareCrypto.open(row.encryptedBundle,sharing.privateKey);}
        catch{decoded={entries:[]};}
      }
      incoming.push({...row,decoded});
    }
    assertActive(ticket);
    sharing.outgoing=outgoing;sharing.incoming=incoming;
    sharing.received=buildReceivedItems(incoming);
    state.receivedItems=sharing.received;
    shareStatus('');
    renderAccountShares();
    if(state.key)render();
    // Quand un nouveau destinataire s'est connecte et a genere sa cle publique,
    // activer automatiquement le partage en attente depuis le coffre emetteur.
    if(outgoing.some(row => row.pendingEncryption && row.recipientPublicKey && !row.revoked && !row.declined)){
      scheduleShareSync();
    }
  }
  function scheduleShareSync(){
    if(shareSyncTimer)clearTimeout(shareSyncTimer);
    shareSyncTimer=setTimeout(()=>{
      if(state.key&&state.accountSharing?.privateKey){
        syncOutgoingShares(guard.ticket()).catch(e=>console.warn('Partage non synchronise :',e.message));
      }
    },900);
  }
  async function syncOutgoingShares(ticket){
    const sharing=state.accountSharing;
    if(!state.key||!sharing)return;
    let changed=false;
    for(const row of sharing.outgoing){
      if(row.revoked||row.declined||!row.metadata||!row.recipientPublicKey)continue;
      const {scope,target}=row.metadata;
      try{
        const entries=shareCrypto.snapshot(state.items,scope,target);
        const encryptedBundle=await shareCrypto.seal(entries,row.recipientPublicKey);
        assertActive(ticket);
        await api('/api/shares/'+encodeURIComponent(row.id)+'/content','PUT',{encryptedBundle});
        changed=true;
      }catch(e){
        if(!guard.active(ticket))return;
        // Un dossier vide ne doit pas remettre a disposition une ancienne copie.
        if(/aucun mot de passe/i.test(e.message)){
          const empty=await shareCrypto.seal({v:1,scope,entries:[]},row.recipientPublicKey);
          assertActive(ticket);
          await api('/api/shares/'+encodeURIComponent(row.id)+'/content','PUT',{encryptedBundle:empty});
          changed=true;
        }else console.warn('Synchronisation partage',row.id,e.message);
      }
    }
    if(changed)await refreshAccountShares(ticket);
  }
  async function grantAccountShare(scope,target,email){
    
    if(!scope||!target)throw Error('Sélectionnez une fiche ou un dossier.');
    const recipient=await api('/api/shares/recipient','POST',{email});
    const content=shareCrypto.snapshot(state.items,scope,target);
    const ownerMetadata=await encrypt({scope,target,title:sharePath(scope,target)},state.key);
    // Aucun secret ne quitte le navigateur en clair. Si le compte n'a pas encore
    // de cle publique, seule une reference chiffree est enregistree en attente.
    const encryptedBundle=recipient.publicKey?await shareCrypto.seal(content,recipient.publicKey):null;
    const result=await api('/api/shares','POST',{scope,recipientEmail:recipient.email,ownerMetadata,encryptedBundle,pending:!recipient.publicKey});
    await refreshAccountShares();
    toast(result.pending
      ? 'Accès préparé : le destinataire doit se connecter une fois. Il sera chiffré automatiquement à votre prochaine connexion.'
      : 'Demande envoyée. Le destinataire doit accepter dans son compte.');
  }
  function shareCard(title,description){
    const card=document.createElement('article');card.className='ds-account-share-card';
    const h=document.createElement('strong');h.textContent=title;
    const p=document.createElement('p');p.textContent=description;
    card.append(h,p);
    const actions=document.createElement('div');actions.className='ds-account-share-actions';card.append(actions);
    return {card,actions};
  }
  function shareFolderSelect(selected=''){
    const select=document.createElement('select');select.setAttribute('aria-label','Dossier de votre coffre');
    for(const path of folderPaths()){
      const opt=document.createElement('option');opt.value=path;opt.textContent=path;select.append(opt);
    }
    if(selected&&[...select.options].some(x=>x.value===selected))select.value=selected;
    return select;
  }
  function shareButton(label,action,classes='btn outline'){
    const b=document.createElement('button');b.type='button';b.className=classes;b.textContent=label;
    b.onclick=async()=>{b.disabled=true;try{await action();}catch(e){toast(e.message);}finally{b.disabled=false;}};
    return b;
  }
  function renderAccountShares(){
    const sharing=state.accountSharing;
    if(!sharing||!state.key)return;
    const verify=$('share-verify-box');
    if(verify)verify.hidden=true;
    const outgoing=$('account-share-outgoing');const incoming=$('account-share-incoming');
    if(!outgoing||!incoming)return;
    // Les actualisations automatiques ne doivent pas decocher le consentement
    // ni effacer le dossier choisi pendant que le destinataire lit la demande.
    const inProgress=new Map();
    for(const node of incoming.querySelectorAll('[data-incoming-share-id]')){
      inProgress.set(node.dataset.incomingShareId,{
        consent:!!node.querySelector('input[type="checkbox"]')?.checked,
        folder:node.querySelector('.ds-account-share-actions select')?.value||'',
      });
    }
    outgoing.replaceChildren();incoming.replaceChildren();
    shareTargetChoices($('account-share-target'),$('account-share-scope').value,$('account-share-target').value);
    for(const row of sharing.outgoing){
      const status=row.revoked?'Révoqué':row.declined?'Refusé':row.pendingEncryption
        ? (row.recipientPublicKey?'Chiffrement en cours':'En attente de la première connexion du destinataire')
        :row.accepted?'Accepté':'En attente de consentement';
      const {card,actions}=shareCard(row.metadata?.title||'Accès',row.recipientEmail+' · '+status+' · '+(row.scope==='folder'?'Dossier':'Identifiant'));
      if(!row.revoked&&!row.declined)actions.append(shareButton('Révoquer',async()=>{
        if(!confirm('Révoquer cet accès ? Le destinataire pourrait avoir déjà copié le mot de passe.'))return;
        await api('/api/shares/'+row.id+'/revoke','POST',{});
        await refreshAccountShares();
      },'btn outline'));
      outgoing.append(card);
    }
    if(!sharing.outgoing.length)outgoing.append(shareCard('Aucun accès accordé','Sélectionnez un destinataire ci-dessus.').card);
    for(const row of sharing.incoming){
      const description=(row.scope==='folder'?'Dossier et identifiants associés':'Identifiant individuel');
      const {card,actions}=shareCard('Partage de '+row.ownerEmail,
        row.pendingEncryption ? description+' · En cours de préparation par l’expéditeur' : description);
      card.dataset.incomingShareId=row.id;
      const previousInput=inProgress.get(row.id);
      if(row.pendingEncryption){
        const info=document.createElement('p');
        info.textContent='La demande est enregistrée. Elle deviendra acceptable dès que l’expéditeur aura ouvert son coffre pour terminer le chiffrement.';
        card.insertBefore(info,actions);
        actions.append(shareButton('Vérifier maintenant',async()=>{
          await ensureAccountSharing();
          toast('Demandes vérifiées.');
        }));
      }else if(!row.accepted){
        const agreement=document.createElement('p');agreement.textContent='Accord de confidentialité : j’utilise ces accès uniquement pour la mission autorisée, je ne les transmets pas à un tiers sans l’accord du propriétaire et je comprends que cet accès peut être révoqué. Mon acceptation sera enregistrée avec sa date.';card.insertBefore(agreement,actions);
        const consent=document.createElement('label');consent.className='checkline';
        const checkbox=document.createElement('input');checkbox.type='checkbox';
        checkbox.checked=Boolean(previousInput?.consent);
        const span=document.createElement('span');span.textContent='Je confirme avoir lu et accepté l’accord de confidentialité ci-dessus.';
        consent.append(checkbox,span);card.insertBefore(consent,actions);
        const select=shareFolderSelect(previousInput?.folder||'');
        actions.append(select);
        actions.append(shareButton('Créer un dossier',async()=>openFolderDialog()));
        actions.append(shareButton('Accepter l’accès',async()=>{
          if(!checkbox.checked)throw Error('Vous devez accepter l’accord de confidentialité.');
          if(!select.value)throw Error('Créez ou sélectionnez un dossier de votre coffre.');
          
          await saveValue(null,{type:'shareTarget',name:'Accès reçu',shareId:row.id,targetFolder:select.value,subfolderMappings:{}});
          await api('/api/shares/'+row.id+'/accept','POST',{consent:true,consentVersion:'2026-10-29-v1'});
          await refreshAccountShares();
          toast('Accès accepté. Il apparaît dans Mon coffre.');
        },'btn primary'));
        actions.append(shareButton('Refuser',async()=>{
          await api('/api/shares/'+row.id+'/decline','POST',{});
          await refreshAccountShares();
        }));
      }else{
        const mapping=shareMapping(row.id);
        const select=shareFolderSelect(mapping?.value.targetFolder||'');
        actions.append(select);
        actions.append(shareButton('Changer le dossier',async()=>{
          if(!select.value)throw Error('Sélectionnez un dossier existant.');
          if(mapping)await saveValue(mapping.id,{...mapping.value,targetFolder:select.value});
          else await saveValue(null,{type:'shareTarget',name:'Accès reçu',shareId:row.id,targetFolder:select.value});
          await refreshAccountShares();
        }));
        actions.append(shareButton('Voir dans Mon coffre',async()=>{navigate('vault','login');}));
        const relativePaths=[...new Set((row.decoded?.entries||[]).map(e=>String(e.relativeFolder||'')).filter(Boolean))].sort();
        if(relativePaths.length){
          const heading=document.createElement('p');heading.textContent='Associer les sous-dossiers de l’expéditeur aux vôtres :';card.append(heading);
          for(const rel of relativePaths){
            const label=document.createElement('label');label.textContent=rel+' → ';
            const current=(mapping?.value.subfolderMappings||{})[rel]||mapping?.value.targetFolder||'';
            const chooser=shareFolderSelect(current);
            label.append(chooser);card.append(label);
            card.append(shareButton('Enregistrer ce sous-dossier',async()=>{
              if(!chooser.value)throw Error('Créez un sous-dossier de destination.');
              const previous=shareMapping(row.id);
              if(!previous)throw Error('Aucun dossier de destination enregistré.');
              const subfolderMappings={...(previous.value.subfolderMappings||{}),[rel]:chooser.value};
              await saveValue(previous.id,{...previous.value,subfolderMappings});
              await refreshAccountShares();
              toast('Sous-dossier associé à votre arborescence.');
            }));
          }
        }
        const detail=document.createElement('p');detail.textContent=(row.decoded?.entries?.length||0)+' identifiant(s) · Accès en lecture seule';
        card.append(detail);
      }
      incoming.append(card);
    }
    if(!sharing.incoming.length)incoming.append(shareCard('Aucune demande','Les nouveaux accès à votre adresse e-mail apparaîtront ici.').card);
  }
  $('account-share-refresh').onclick=async()=>{
    const button=$('account-share-refresh');button.disabled=true;
    try{await ensureAccountSharing();toast('Partages actualisés.');}
    catch{ /* L'erreur est deja visible dans le bloc de statut. */ }
    finally{button.disabled=false;}
  };
  $('account-share-scope').onchange=()=>shareTargetChoices($('account-share-target'),$('account-share-scope').value);
  $('account-share-form').addEventListener('submit',async e=>{
    e.preventDefault();const button=$('account-share-submit');button.disabled=true;
    try{await grantAccountShare($('account-share-scope').value,$('account-share-target').value,$('account-share-email').value.trim().toLowerCase());$('account-share-email').value='';document.dispatchEvent(new Event('datensis:recipient-clear'));}
    catch(err){toast(err.message);}finally{button.disabled=false;}
  });
  $('share-send-code').onclick=async()=>{try{const x=await api('/api/shares/verify-email/start','POST',{});$('share-verify-state').textContent=x.message||'Code envoyé.';}catch(e){toast(e.message);}};
  $('share-confirm-code').onclick=async()=>{try{await api('/api/shares/verify-email/confirm','POST',{code:$('share-code').value.trim()});$('share-code').value='';state.accountSharing.identity.verified=true;renderAccountShares();toast('Adresse e-mail vérifiée.');}catch(e){toast(e.message);}};
  function grantFromEntry(item){
    if(!item||item.shared)return;
    $('account-share-scope').value='entry';
    shareTargetChoices($('account-share-target'),'entry',item.id);
    navigate('shares');
    $('account-share-email').focus();
  }
  function renderSharedDetail(item){
    const box=$('item-details');box.replaceChildren();
    const v=item.value;
    const head=document.createElement('div');head.className='detail-header';
    const h=document.createElement('h2');h.textContent=v.name;
    const subtitle=document.createElement('p');subtitle.textContent='Accès reçu de '+item.source+' · Lecture seule';
    head.append(h,subtitle);box.append(head);
    const info=document.createElement('div');info.className='detail-info';
    detailField(info,'Identifiant',v.username,{copy:true});
    detailField(info,'Mot de passe',v.password,{secret:true,copy:true});
    detailField(info,'Site',v.url,{copy:true});
    detailField(info,'Dossier dans votre coffre',v.folder);
    if(v.originalSubfolder)detailField(info,'Sous-dossier chez l’expéditeur',v.originalSubfolder);
    box.append(info);
    const actions=document.createElement('div');actions.className='detail-actions';
    actions.append(shareButton('Gérer cet accès',async()=>navigate('shares')));
    box.append(actions);
  }

  const validLockMinutes=[0,1,3,5,10,15];
  let lockMinutes=localStorage.getItem('ml2c-lock-minutes')===null?0:Number(localStorage.getItem('ml2c-lock-minutes'));
  if(!validLockMinutes.includes(lockMinutes))lockMinutes=0;
  $('pref-lock-minutes').value=String(lockMinutes);
  $('pref-lock-minutes').onchange=()=>{const n=Number($('pref-lock-minutes').value);if(validLockMinutes.includes(n)){lockMinutes=n;localStorage.setItem('ml2c-lock-minutes',String(n));toast(n===0?'Verrouillage par inactivité désactivé (fermeture toujours protégée).':'Durée de verrouillage mise à jour.');}};
  document.addEventListener('keydown',event=>{
    if(!state.key||event.ctrlKey||event.metaKey)return;
    const target=event.target,editing=target instanceof HTMLElement&&(target.isContentEditable||['INPUT','TEXTAREA','SELECT'].includes(target.tagName));
    if(!editing&&event.key==='/'&&!event.altKey){event.preventDefault();navigate('vault');$('search-input').focus();}
    else if(!editing&&event.key.toLowerCase()==='n'&&!event.altKey){event.preventDefault();openEditor();}
    else if(event.altKey&&event.key==='1'){event.preventDefault();navigate('vault');}
    else if(event.altKey&&event.key==='2'){event.preventDefault();navigate('actions');}
  });
  for(const type of ['pointerdown','keydown','touchstart'])document.addEventListener(type,()=>{state.lastActive=Date.now();},{passive:true});
  setInterval(()=>{if(state.key&&lockMinutes>0&&Date.now()-state.lastActive>=lockMinutes*60000)lock();},10000);
  // Le destinataire n'a pas a recharger la page pour voir une demande chiffree.
  // La relance tente aussi de recuperer une initialisation qui avait echoue.
  setInterval(()=>{
    if(!state.key||document.hidden)return;
    ensureAccountSharing().catch(()=>{});
  },15000);
  // Changement d'onglet, de site ou fermeture : suppression immediate des references locales.
  document.addEventListener('visibilitychange',()=>{if(document.hidden)lock();});
  window.addEventListener('pagehide',()=>{guard.depart();lock();});
  // Retour depuis l'historique avec bfcache : ne jamais reutiliser une cle en memoire.
  window.addEventListener('pageshow',event=>{if(event.persisted){guard.restore();lock();}});
  regen();
  (async()=>{
    if(!window.isSecureContext||!crypto?.subtle){lockError('HTTPS ou localhost requis pour le chiffrement.');return;}
    const ticket=guard.ticket();
    try{
      await loadVault();
      if(!guard.active(ticket)){bootPassword=null;return;}
      if(bootPassword){
        const loginPassword=bootPassword;
        bootPassword=null;
        try{
          await unlockWith(loginPassword);
        }catch(err){
          if(!guard.active(ticket)){lockError('Page masquée : coffre verrouillé.');return;}
          if(state.initial?.initialized && (err.name==='OperationError'||err.message==='Mot de passe incorrect.')){
            // Une ancienne phrase secrete peut etre demandee une seule fois.
            bootPassword=loginPassword;
            $('lock-title').textContent='Convertir votre ancien coffre';
            $('lock-description').textContent='Entrez UNE fois votre ancienne phrase secrète pour chiffrer les éléments avec votre mot de passe principal de connexion.';
            $('confirm-wrap').hidden=true;
            $('vault-confirm').required=false;
            $('unlock-button').textContent='Convertir et ouvrir';
          }else{lockError(err.message);}
        }
      }
    }catch(err){if(guard.active(ticket))lockError('Chargement impossible : '+err.message);bootPassword=null;}
  })();
})();
