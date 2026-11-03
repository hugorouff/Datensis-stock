/* Single-password sign-in, no password in localStorage/sessionStorage/cookies. */
'use strict';
(() => {
  const form=document.getElementById('login-form');if(!form)return;
  const error=document.getElementById('login-js-error');
  let master=null, otpToken=null, loginGeneration=0;
  let pending=false;
  const isVisible = ticket => ticket===loginGeneration && !document.hidden;
  const cancelBootstrap=()=>{loginGeneration++;master=null;delete window.__vaultBootstrapPassword;};
  document.addEventListener('visibilitychange',()=>{if(document.hidden)cancelBootstrap();});
  window.addEventListener('pagehide',cancelBootstrap);
  // Une page de connexion revenue du cache d'historique doit etre revalidee.
  window.addEventListener('pageshow',event=>{if(event.persisted)location.reload();});
  async function openVault(ticket) {
    if(!isVisible(ticket))throw Error('Page masquée : reconnectez-vous pour ouvrir le coffre.');
    const response=await fetch('/vault',{credentials:'same-origin',cache:'no-store'});
    if(!response.ok||!new URL(response.url).pathname.startsWith('/vault'))throw Error('Connexion au coffre impossible.');
    const html=await response.text();
    if(!isVisible(ticket))throw Error('Page masquée : reconnectez-vous pour ouvrir le coffre.');
    const page=new DOMParser().parseFromString(html,'text/html');
    const csrf=page.querySelector('meta[name="vault-csrf"]');
    if(!csrf)throw Error('Jeton du coffre manquant.');
    for(const name of ['vault-csrf','twofa-csrf']){
      const node=page.querySelector(`meta[name="${name}"]`);
      if(node){document.head.querySelector(`meta[name="${name}"]`)?.remove();document.head.append(node.cloneNode(true));}
    }
    document.body.innerHTML=page.body.innerHTML;
    document.title=page.title;
    history.replaceState({},'', '/vault');
    // Cle uniquement transmise entre scripts de la MEME page, jamais persistee.
    window.__vaultBootstrapPassword=master;
    master=null;
    // L'interface du coffre requiert les outils locaux de suivi des actions.
    // Charger ces deux scripts dans l'ordre : l'initialisation de vault.js
    // ne doit pas etre lancee avant ML2CActionTools.
    const loadScript=(src,after)=>{
      const script=document.createElement('script');script.src=src;
      script.onload=()=>{if(isVisible(ticket))after?.();else delete window.__vaultBootstrapPassword;};
      script.onerror=()=>{delete window.__vaultBootstrapPassword;};
      document.body.append(script);
    };
    loadScript('/assets/account-sharing.js?v=20261029-sharefix1',()=>
      loadScript('/assets/actions-tools.js?v=20261029-sharefix1',()=>
        loadScript('/assets/vault-session-guard.js?v=20261029-sharefix1',()=>
          loadScript('/assets/vault.js?v=20261029-sharefix1',()=>
            loadScript('/assets/recipient-search.js?v=20261029-sharefix1')))));

  }
  async function sendCode(){
    const button=document.getElementById('login-otp-resend');button.disabled=true;error.hidden=true;
    try{
      const response=await fetch('/2fa/send',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','X-CSRF-Token':otpToken},body:'{}'});
      const data=await response.json();if(!response.ok)throw Error(data.error||'Envoi impossible.');
      document.getElementById('login-mail-status').textContent=data.message||'Code envoyé.';
    }catch(e){error.textContent=e.message;error.hidden=false;}finally{button.disabled=false;}
  }
  // Dans Edge normal, une page de connexion de l'historique peut garder une
  // ancienne session Symfony. Lors d'une NOUVELLE saisie volontaire, fermer
  // cette session et recuperer un jeton CSRF frais avant d'authentifier le compte.
  async function ensureFreshLogin() {
    const r=await fetch('/auth/session',{credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
    if(!r.ok)throw Error('Impossible de vérifier la session actuelle. Rechargez la page.');
    const status=await r.json();
    if(!status.authenticated)return;
    if(!status.logoutCsrf)throw Error('Impossible de fermer l’ancienne session.');
    const result=await fetch('/logout',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'follow',
      body:new URLSearchParams({'_csrf_token':status.logoutCsrf})});
    if(!result.ok||new URL(result.url).pathname!=='/login')throw Error('Ancienne session non fermée. Utilisez « Se déconnecter ».');
    const refreshed=await fetch('/login',{credentials:'same-origin',cache:'no-store'});
    if(!refreshed.ok||new URL(refreshed.url).pathname!=='/login')throw Error('Impossible de réinitialiser la connexion.');
    const page=new DOMParser().parseFromString(await refreshed.text(),'text/html');
    const token=page.querySelector('form#login-form input[name="_csrf_token"]')?.value;
    if(!token)throw Error('Jeton de connexion manquant, actualisez la page.');
    form.elements['_csrf_token'].value=token;
  }
  // Branche 2FA conservee pour une future reactivation.
  document.getElementById('login-otp-resend')?.addEventListener('click',sendCode);
  async function onLoggedIn(response,ticket) {
    if(!isVisible(ticket))throw Error('Page masquée : reconnectez-vous pour ouvrir le coffre.');
    const path=new URL(response.url).pathname;
    if(path==='/login')throw Error('Identifiants incorrects ou trop de tentatives.');
    if(!response.ok)throw Error('Connexion impossible (HTTP '+response.status+').');
    // Les administrateurs passent directement sur leur espace de gestion :
    // leur mot de passe ne doit jamais etre transmis au code de decryption du coffre.
    if(path==='/account/activate'){
      master=null;
      delete window.__vaultBootstrapPassword;
      location.replace('/account/activate');
      return;
    }
    if(path==='/admin'){
      master=null;
      delete window.__vaultBootstrapPassword;
      location.replace('/admin');
      return;
    }
    if(path==='/2fa'){
      const html=await response.text();
      const page=new DOMParser().parseFromString(html,'text/html');
      otpToken=page.querySelector('meta[name="twofa-csrf"]')?.content;
      if(!otpToken)throw Error('Jeton 2FA manquant.');
      form.hidden=true;
      const block=document.getElementById('login-twofactor');block.hidden=false;
      document.getElementById('login-otp').focus();
      await sendCode();
      return;
    }
    await openVault(ticket);
  }
  form.addEventListener('submit',async e=>{
    e.preventDefault();error.hidden=true;
    const ticket=loginGeneration;
    if(pending)return;
    pending=true;
    const submit=form.querySelector('button[type="submit"]');
    if(submit){submit.disabled=true;submit.textContent='Connexion en cours…';}
    master=form.elements['_password'].value;
    try{
      await ensureFreshLogin();
      const response=await fetch(form.action,{method:'POST',credentials:'same-origin',body:new FormData(form),redirect:'follow',cache:'no-store'});
      await onLoggedIn(response,ticket);
    }catch(e){
      master=null;
      delete window.__vaultBootstrapPassword;
      // Apres remplacement de la page, afficher l'erreur dans la page du coffre.
      const lockError=document.getElementById('lock-error');
      const target=document.contains(error)?error:lockError;
      if(target){target.textContent=e.message;target.hidden=false;}
    }finally{
      pending=false;
      form.elements['_password'].value='';
      if(submit){submit.disabled=false;submit.textContent='Se connecter';}
    }
  });
  document.getElementById('login-otp-form')?.addEventListener('submit',async e=>{
    e.preventDefault();error.hidden=true;
    try{
      const response=await fetch('/2fa/verify',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':otpToken},body:JSON.stringify({code:document.getElementById('login-otp').value.trim()}),cache:'no-store'});
      const data=await response.json();if(!response.ok)throw Error(data.error||'Code invalide.');
      // Une fois la 2FA validee, le serveur choisit la destination selon le role.
      const destination=await fetch('/',{credentials:'same-origin',cache:'no-store'});
      if(new URL(destination.url).pathname==='/admin'){
        master=null;
        delete window.__vaultBootstrapPassword;
        location.replace('/admin');
      }else{
        await openVault(loginGeneration);
      }
    }catch(e){error.textContent=e.message;error.hidden=false;}
  });
})();
