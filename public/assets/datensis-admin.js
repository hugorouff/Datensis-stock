(()=>{'use strict';
const $=id=>document.getElementById(id);
let csrf=window.DS_ADMIN_CSRF;
const state={page:'overview',q:'',number:1,total:0,pageSize:25,users:[],active:null,busy:false};

// Recuperer le jeton et l'identite de l'administrateur reels a chaque ecriture.
// L'identifiant immuable evite les faux positifs dus a un email renomme ou une
// ancienne page en cache. Le serveur revalide ROLE_ADMIN, CSRF et acteur.
async function refreshAdminCsrf(){
 const r=await fetch('/api/admin/csrf',{method:'GET',credentials:'same-origin',cache:'no-store',redirect:'follow',headers:{'Accept':'application/json'}});
 if(r.redirected&&new URL(r.url).pathname==='/login')throw Error('Session expirée. Reconnectez-vous comme administrateur.');
 let body;try{body=await r.json();}catch{throw Error('Session administrateur invalide. Ouvrez à nouveau /admin.');}
 if(!r.ok)throw Error(body.error||'Accès administrateur refusé : reconnectez-vous.');
 if(typeof body.actorId!=='string'||!body.actorId||typeof body.actorEmail!=='string'||!body.actorEmail){
  throw Error('Impossible de vérifier le compte administrateur. Rechargez la page.');
 }
 if(typeof body.csrfToken!=='string'||!body.csrfToken)throw Error('Jeton de sécurité indisponible. Rechargez la page.');
 const previous=String(window.DS_ADMIN_ID||'');
 if(previous&&previous!==body.actorId){
  // Ne pas bloquer indéfiniment : si un autre ADMIN est connecté, demander
  // une confirmation explicite avant d'agir avec ce compte actuel.
  if(!window.confirm('La session active est maintenant « '+body.actorEmail+' ».\n\nConfirmer cette action avec ce compte administrateur ?')){
   throw Error('Action annulée. Aucune modification effectuée.');
  }
 }
 window.DS_ADMIN_ID=body.actorId;
 window.DS_ADMIN_EMAIL=body.actorEmail;
 const label=typeof document!=='undefined'?document.querySelector('.ds-admin-user'):null;
 if(label)label.textContent=body.actorEmail;
 csrf=body.csrfToken;
}
async function api(url, method='GET', data){
 const write=method!=='GET';
 // Les jetons CSRF sont attaches a la session. Renouvellement automatique avant
 // chaque ecriture (revocation, creation, edition, suppression).
 if(write)await refreshAdminCsrf();
 for(let attempt=0;attempt<2;attempt++){
  const r=await fetch(url,{method,credentials:'same-origin',cache:'no-store',redirect:'follow',headers:write?{'Content-Type':'application/json','Accept':'application/json','X-CSRF-Token':csrf,'X-Admin-Actor-Id':String(window.DS_ADMIN_ID||'')}:{'Accept':'application/json'},...(write?{body:JSON.stringify(data||{})}:{})});
  if(r.redirected&&new URL(r.url).pathname==='/login')throw Error('Session expirée. Reconnectez-vous et rechargez la page.');
  let json;try{json=await r.json();}catch{throw Error('Réponse serveur non JSON. Vérifiez que la session administrateur est active.');}
  // Cas exceptionnel : session regeneree entre la verification et le POST.
  // Reessayer une seule fois, uniquement pour une erreur CSRF explicite.
  if(write&&r.status===403&&json.code==='csrf_invalid'&&attempt===0){await refreshAdminCsrf();continue;}
  if(!r.ok)throw Error(json.error||`Erreur serveur (${r.status}).`);
  return json;
 }
 throw Error('Impossible de valider le jeton de sécurité. Rechargez la page.');
}
function elt(tag,content,cls){const e=document.createElement(tag);if(content!==undefined)e.textContent=String(content);if(cls)e.className=cls;return e;}
function note(message,bad=false){const el=$('admin-feedback');el.hidden=false;el.textContent=message;el.classList.toggle('error',bad);}
function clearNote(){$('admin-feedback').hidden=true;$('admin-feedback').textContent='';}
function showDialog(dialog){clearNote();dialog.showModal();}
function closeDialog(dialog){dialog.close();}
function formatDate(v){if(!v)return '—';const d=new Date(String(v).replace(' ','T')+(String(v).includes('Z')?'':'Z'));return Number.isFinite(d.getTime())?d.toLocaleString('fr-FR'):v;}
function changePage(name){state.page=name;document.querySelectorAll('[data-admin-page]').forEach(p=>{p.hidden=p.dataset.adminPage!==name;});document.querySelectorAll('[data-admin-tab]').forEach(t=>{const active=t.dataset.adminTab===name;t.classList.toggle('active',active);if(active)t.setAttribute('aria-current','page');else t.removeAttribute('aria-current');});clearNote();if(name==='users')loadUsers();if(name==='shares')loadShares();if(name==='audit')loadAudit();if(name==='invitations')loadInvitations();if(name==='overview')loadMetrics();}
async function loadMetrics(){try{const d=await api('/api/admin/metrics');for(const k of ['accounts','active','disabled','shares'])$('metric-'+k).textContent=d[k].toLocaleString('fr-FR');}catch(e){note(e.message,true);}}
function badge(label,style){return elt('span',label,'ds-admin-badge '+style);}
function userRow(u){const tr=elt('tr');let td=elt('td');td.append(elt('strong',u.email));if(u.mustChangePassword)td.append(elt('small','Mot de passe temporaire'));tr.append(td);
 td=elt('td');td.append(badge(u.admin?'Administrateur':'Utilisateur',u.admin?'role':'normal'));tr.append(td);
 td=elt('td');td.append(badge(u.disabled?'Suspendu':'Actif',u.disabled?'disabled':'active'));tr.append(td);
 td=elt('td');td.append(elt('span',u.vaultInitialized?'Initialisé':'À initialiser'));tr.append(td);
 td=elt('td');td.append(elt('span',formatDate(u.lastLoginAt)));tr.append(td);
 td=elt('td');td.className='ds-admin-action-cell';const edit=elt('button','Modifier','ds-admin-btn ds-admin-btn-outline ds-admin-btn-small');edit.type='button';edit.addEventListener('click',()=>openEdit(u));td.append(edit);
 const reset=elt('button','Accès provisoire','ds-admin-btn ds-admin-btn-outline ds-admin-btn-small');reset.type='button';reset.title='Uniquement si le coffre et les partages ne sont pas initialisés';reset.disabled=u.vaultInitialized||u.sharingEnabled||u.email===window.DS_ADMIN_EMAIL;reset.addEventListener('click',()=>resetAccount(u));td.append(reset);
 const remove=elt('button','Supprimer','ds-admin-btn ds-admin-btn-danger ds-admin-btn-small');remove.type='button';remove.disabled=u.email===window.DS_ADMIN_EMAIL;remove.addEventListener('click',()=>openDelete(u));td.append(remove);tr.append(td);return tr;}
async function loadUsers(){const n=state.number, q=state.q;try{const d=await api('/api/admin/users?'+new URLSearchParams({q,page:String(n)}));if(q!==state.q||n!==state.number)return;state.users=d.users;state.total=d.total;state.pageSize=d.pageSize;$('admin-users').replaceChildren(...d.users.map(userRow));if(!d.users.length){const tr=elt('tr'),td=elt('td','Aucun compte pour cette recherche.');td.colSpan=6;tr.append(td);$('admin-users').append(tr);}const from=d.total?(d.page-1)*d.pageSize+1:0,to=Math.min(d.total,d.page*d.pageSize);$('admin-users-count').textContent=`${d.total} compte(s), ${from}–${to} affiché(s)`;$('admin-page-label').textContent=`Page ${d.page} / ${Math.max(1,Math.ceil(d.total/d.pageSize))}`;$('admin-prev').disabled=state.number<=1;$('admin-next').disabled=state.number*d.pageSize>=d.total;}catch(e){note(e.message,true);}}
async function loadShares(){try{const d=await api('/api/admin/overview');const box=$('admin-shares');box.replaceChildren();if(!d.shares.length){box.append(elt('p','Aucun partage entre comptes.'));return;}for(const s of d.shares){const line=elt('article',undefined,'ds-admin-share');const body=elt('div');body.append(elt('strong',s.owner+' → '+s.recipient));body.append(elt('small',(s.scope==='folder'?'Dossier':'Identifiant')+' · '+(s.revoked?'Révoqué':s.accepted?'Accepté':'En attente')));line.append(body);if(!s.revoked){const btn=elt('button','Révoquer','ds-admin-btn ds-admin-btn-danger ds-admin-btn-small');btn.type='button';btn.addEventListener('click',async()=>{if(!confirm('Révoquer ce partage ? Le destinataire peut avoir déjà copié les données.'))return;await run(async()=>{await api('/api/admin/shares/'+encodeURIComponent(s.id)+'/revoke','POST');note('Partage révoqué.');await loadShares();});});line.append(btn);}box.append(line);}}catch(e){note(e.message,true);}}
async function loadInvitations(){try{const d=await api('/api/admin/invitations-overview');const box=$('admin-invitations');box.replaceChildren();if(!d.invitations.length){box.append(elt('p','Aucune invitation.'));return;}for(const i of d.invitations){const line=elt('article',undefined,'ds-admin-share'),body=elt('div');body.append(elt('strong',i.owner+' → '+i.recipient));body.append(elt('small','Dossier : '+i.folder+' · '+(i.revoked?'Révoquée':i.used?'Utilisée':'En attente')+' · Expiration : '+formatDate(i.expiresAt)));line.append(body);if(!i.revoked&&!i.used){const b=elt('button','Révoquer','ds-admin-btn ds-admin-btn-danger ds-admin-btn-small');b.addEventListener('click',async()=>{if(!confirm('Révoquer cette invitation ?'))return;await run(async()=>{await api('/api/admin/invitations/'+encodeURIComponent(i.id)+'/revoke','POST');note('Invitation révoquée.');await loadInvitations();});});line.append(b);}box.append(line);}}catch(e){note(e.message,true);}}
async function loadAudit(){try{const d=await api('/api/admin/audit'),body=$('admin-audit');body.replaceChildren();const labels={'user.created':'Création de compte','user.updated':'Modification de compte','user.deleted':'Suppression de compte','user.initial_password_reset':'Nouvel accès temporaire','share.revoked':'Révocation de partage','invitation.revoked':'Révocation d’invitation'};for(const item of d.events){const tr=elt('tr');for(const value of [formatDate(item.date),labels[item.action]||item.action,item.actor,item.subject])tr.append(elt('td',value));body.append(tr);}if(!d.events.length){const tr=elt('tr'),td=elt('td','Aucune action enregistrée.');td.colSpan=4;tr.append(td);body.append(tr);}}catch(e){note(e.message,true);}}
async function run(task){if(state.busy)return;state.busy=true;try{await task();}catch(e){note(e.message,true);}finally{state.busy=false;}}
function openEdit(u){state.active=u;$('admin-edit-caption').textContent=u.email;$('admin-edit-email').value=u.email;$('admin-edit-role').checked=u.admin;$('admin-edit-disabled').checked=u.disabled;showDialog($('admin-edit-dialog'));}
async function openDelete(u){state.active=u;$('admin-delete-confirm').value='';$('admin-delete-caption').textContent='Compte : '+u.email;$('admin-delete-preview').textContent='Chargement des éléments concernés…';showDialog($('admin-delete-dialog'));try{const d=await api('/api/admin/users/'+encodeURIComponent(u.id)+'/deletion-preview');if(state.active!==u)return;const labels={entries:'Identifiants et notes chiffrés',sends:'Liens Send',invitations:'Invitations',shares:'Partages reçus ou envoyés',sessions:'Sessions de l’extension'};const container=$('admin-delete-preview');container.replaceChildren();for(const [k,v] of Object.entries(d.counts)){const p=elt('p',labels[k]+': '+v);container.append(p);}}catch(e){$('admin-delete-preview').textContent=e.message;}}
function displayTemporary(email,password){$('admin-generated-email').value=email;$('admin-generated-password').value=password;showDialog($('admin-credential-dialog'));}
async function resetAccount(u){if(!confirm(`Créer un nouvel accès temporaire pour ${u.email} ? Seulement possible si aucun coffre ou partage chiffré n'est initialisé.`))return;await run(async()=>{const d=await api('/api/admin/users/'+encodeURIComponent(u.id)+'/reset-initial-password','POST');displayTemporary(d.email,d.temporaryPassword);await loadUsers();});}
document.querySelectorAll('[data-admin-tab]').forEach(b=>b.addEventListener('click',()=>changePage(b.dataset.adminTab)));
document.querySelectorAll('[data-open-page]').forEach(b=>b.addEventListener('click',()=>changePage(b.dataset.openPage)));
document.querySelectorAll('[data-close-dialog]').forEach(b=>b.addEventListener('click',()=>closeDialog(b.closest('dialog'))));
$('admin-create-open').addEventListener('click',()=>{$('admin-create-form').reset();showDialog($('admin-create-dialog'));});
$('admin-create-form').addEventListener('submit',async e=>{e.preventDefault();await run(async()=>{const d=await api('/api/admin/users','POST',{email:$('admin-create-email').value.trim(),admin:$('admin-create-role').checked});closeDialog($('admin-create-dialog'));displayTemporary(d.email,d.temporaryPassword);await loadUsers();await loadMetrics();});});
$('admin-edit-form').addEventListener('submit',async e=>{e.preventDefault();const u=state.active;if(!u)return;await run(async()=>{await api('/api/admin/users/'+encodeURIComponent(u.id),'PATCH',{email:$('admin-edit-email').value.trim(),admin:$('admin-edit-role').checked,disabled:$('admin-edit-disabled').checked});closeDialog($('admin-edit-dialog'));note('Compte modifié. Les sessions avec des droits modifiés seront réévaluées.');await loadUsers();await loadMetrics();});});
$('admin-delete-form').addEventListener('submit',async e=>{e.preventDefault();const u=state.active;if(!u)return;const email=$('admin-delete-confirm').value.trim().toLowerCase();if(email!==u.email.toLowerCase()){note('Recopiez exactement l’e-mail à supprimer.',true);return;}await run(async()=>{await api('/api/admin/users/'+encodeURIComponent(u.id),'DELETE',{confirmEmail:email});closeDialog($('admin-delete-dialog'));note('Compte et données associées supprimés.');await loadUsers();await loadMetrics();});});
$('admin-credential-dialog').addEventListener('close',()=>{$('admin-generated-password').value='';});
$('admin-credential-close').addEventListener('click',()=>{$('admin-generated-password').value='';closeDialog($('admin-credential-dialog'));});
$('admin-copy-password').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('admin-generated-password').value);$('admin-copy-password').textContent='Copié';setTimeout(()=>$('admin-copy-password').textContent='Copier',1200);}catch{note('Copie bloquée par le navigateur : sélectionnez la valeur pour la copier.',true);}});
let searchTimer;$('admin-user-search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.q=$('admin-user-search').value.trim();state.number=1;loadUsers();},230);});
$('admin-prev').addEventListener('click',()=>{if(state.number>1){state.number--;loadUsers();}});$('admin-next').addEventListener('click',()=>{if(state.number*state.pageSize<state.total){state.number++;loadUsers();}});
$('admin-shares-reload').addEventListener('click',loadShares);$('admin-audit-reload').addEventListener('click',loadAudit);$('admin-invites-reload').addEventListener('click',loadInvitations);
loadMetrics();
})();
