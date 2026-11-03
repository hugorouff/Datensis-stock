'use strict';
(() => {
  const el=id=>document.getElementById(id);
  if(!el('invite-consent'))return;
  const csrf=document.querySelector('meta[name="invite-csrf"]').content;
  const folder=document.querySelector('meta[name="invite-company"]').content;
  const pub=document.querySelector('meta[name="invite-public-key"]').content;
  const enc=new TextEncoder();
  const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
  const fromB64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  let verified=false;
  const showError=s=>{el('invite-error').textContent=s;el('invite-error').hidden=!s;};
  async function api(action,body){
    const r=await fetch(location.pathname+'/'+action,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,'Accept':'application/json'},body:JSON.stringify(body)});
    let data;try{data=await r.json();}catch{throw Error('Réponse invalide du serveur.');}
    if(!r.ok)throw Error(data.error||'Opération refusée.');return data;
  }
  el('invite-consent').onsubmit=async e=>{
    e.preventDefault();showError('');
    if(!el('invite-consent-check').checked)return showError('Consentement obligatoire.');
    try{await api('consent',{consent:true});el('invite-consent').hidden=true;el('invite-code-form').hidden=false;}
    catch(err){showError(err.message);}
  };
  el('invite-code-form').onsubmit=async e=>{
    e.preventDefault();showError('');
    try{await api('verify',{code:el('invite-code').value.trim()});verified=true;el('invite-code').value='';el('invite-code-form').hidden=true;el('invite-deposit').hidden=false;addRow();}
    catch(err){showError(err.message);}
  };
  const rows=el('invite-credentials');
  function addRow(){
    if(rows.children.length>=20)return showError('20 identifiants au maximum.');
    const fieldset=document.createElement('fieldset');fieldset.className='ds-invite-row';
    const legend=document.createElement('legend');legend.textContent='Identifiant '+(rows.children.length+1);fieldset.append(legend);
    for(const [field,label,type,max] of [['name','Nom du service','text',120],['username','Identifiant ou e-mail','text',200],['password','Mot de passe','password',1024],['url','Adresse du site (facultatif)','url',1000],['subfolder','Sous-dossier (facultatif)','text',200]]){
      const wrap=document.createElement('label');wrap.textContent=label;
      const input=document.createElement('input');input.type=type;input.dataset.field=field;input.maxLength=max;
      input.autocomplete='off';input.required=['name','username','password'].includes(field);
      input.placeholder=field==='subfolder'?'Ex. : Comptabilité / Banque':'';
      wrap.append(input);fieldset.append(wrap);
    }
    const remove=document.createElement('button');remove.className='btn outline';remove.type='button';remove.textContent='Retirer';remove.onclick=()=>fieldset.remove();fieldset.append(remove);rows.append(fieldset);
  }
  el('invite-add').onclick=addRow;
  function subpath(input){
    const path=input.trim();if(!path)return '';
    const segments=path.split('/').map(s=>s.trim());
    if(segments.length>3||segments.some(s=>!s||s.length>80||/[\\\x00-\x1f]/.test(s)||s==='.'||s==='..'))throw Error('Sous-dossier invalide (3 niveaux maximum).');
    return segments.join('/');
  }
  el('invite-deposit').onsubmit=async e=>{
    e.preventDefault();showError('');if(!verified)return showError('Vérification e-mail obligatoire.');
    const button=el('invite-submit');button.disabled=true;
    try{
      if(!window.isSecureContext||!crypto.subtle)throw Error('HTTPS ou localhost obligatoire pour le chiffrement.');
      const credentials=Array.from(rows.children).map(row=>{
        const val={};row.querySelectorAll('input').forEach(input=>val[input.dataset.field]=input.value.trim());
        if(!val.name||!val.username||!val.password)throw Error('Nom, identifiant et mot de passe obligatoires.');
        const suffix=subpath(val.subfolder);
        if(val.url&&!/^https?:\/\//i.test(val.url))throw Error('URL invalide.');
        return {type:'login',name:val.name,username:val.username,password:val.password,url:val.url,
          folder:folder+(suffix?'/'+suffix:''),favorite:false,notes:''};
      });
      if(!credentials.length)throw Error('Ajoutez au moins un identifiant.');
      const json=enc.encode(JSON.stringify({entries:credentials}));if(json.byteLength>50000)throw Error('Dépôt trop volumineux.');
      const aes=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
      const aesRaw=await crypto.subtle.exportKey('raw',aes);
      const rsa=await crypto.subtle.importKey('spki',fromB64(pub),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);
      const wrappedKey=await crypto.subtle.encrypt({name:'RSA-OAEP'},rsa,aesRaw);
      const iv=crypto.getRandomValues(new Uint8Array(12));
      const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},aes,json);
      await api('submit',{payload:{v:1,iv:b64(iv),data:b64(data),wrappedKey:b64(wrappedKey)}});
      rows.replaceChildren();el('invite-deposit').hidden=true;el('invite-done').hidden=false;
    }catch(err){showError(err.message);}finally{button.disabled=false;}
  };
})();
