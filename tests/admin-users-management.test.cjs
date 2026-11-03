'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),vm=require('node:vm');
const root=path.join(__dirname,'..'),read=f=>fs.readFileSync(path.join(root,f),'utf8');
const api=read('src/Controller/AdminUserController.php'),account=read('src/Service/AdminAccountService.php'),auth=read('src/EventSubscriber/AccountPolicySubscriber.php'),checker=read('src/Security/ActiveUserChecker.php'),web=read('public/assets/datensis-admin.js'),login=read('public/assets/login-unified.js'),migration=read('migrations/Version20261029000300.php');
for(const route of ["/users'",'/users/{id}', '/users/{id}/deletion-preview','/users/{id}/reset-initial-password','/metrics','/audit','/invitations-overview'])assert(api.includes(route),`Missing route: ${route}`);
assert.match(api,/X-CSRF-Token/);assert.match(api,/random_bytes\(27\)/);assert.match(api,/requirePasswordChange\(\)/);assert.match(api,/is_bool\(\$data\['admin'\]/);
assert.match(api,/Impossible de suspendre votre propre compte/);assert.match(api,/Dernier administrateur actif/);assert.match(account,/DELETE FROM vault_share WHERE owner_id=:id OR recipient_id=:id/);assert.match(account,/DELETE FROM vault_contribution/);assert.match(account,/DELETE FROM vault_user WHERE id=:id AND email=:email/);assert.match(account,/canResetPassword\(User/);
assert.match(account,/getVaultSalt\(\)/);assert.match(account,/getSharingPrivateKey\(\)/);
assert.match(checker,/CustomUserMessageAccountStatusException/);assert.match(auth,/SELECT disabled_at, must_change_password, roles/);assert.match(auth,/setToken\(null\)/);
assert.match(migration,/vault_admin_audit/);assert.match(migration,/must_change_password/);
assert.match(web,/textContent=/);assert.doesNotMatch(web, /innerHTML\s*=/);assert.match(web,/confirmEmail/);
assert.match(login,/path==='\/account\/activate'/);
assert.match(read('config/packages/security.yaml'),/user_checker: App\\Security\\ActiveUserChecker/);
assert.match(read('templates/auth/login.html.twig'),/login-unified\.js.*\?v=/);
assert.match(read('public/assets/datensis-brand-layout.css'),/position:absolute!important/);
// Simule une premiere connexion avec un mot de passe temporaire :
// aucune ouverture de coffre, uniquement /account/activate.
(async()=>{
 const callbacks=new Map(), password={value:'temp-password'},error={textContent:'',hidden:true},submit={disabled:false,textContent:'Connexion'};
 const form={action:'/login',hidden:false,elements:{_password:password},querySelector(){return submit;},addEventListener(type,fn){callbacks.set(type,fn)}};
 const document={hidden:false,getElementById(id){return({'login-form':form,'login-js-error':error})[id]||null;},addEventListener(){},contains(n){return n===error;}};
 let redirected=null,vaultCalls=0;
 const ctx={window:{addEventListener(){}},document,FormData:class{},URL,location:{replace(url){redirected=url;}},fetch:async url=>{if(url==='/login')return{url:'http://127.0.0.1:8001/account/activate',ok:true,status:200};if(url==='/vault')vaultCalls++;throw Error('Unexpected URL '+url);}};
 vm.runInNewContext(login,ctx);await callbacks.get('submit')({preventDefault(){}});
 assert.equal(redirected,'/account/activate');assert.equal(vaultCalls,0);assert.equal(password.value,'');console.log('OK gestion utilisateurs et activation premiere connexion');
})().catch(e=>{console.error(e);process.exitCode=1;});
