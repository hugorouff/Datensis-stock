'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const js = read('public/assets/datensis-admin.js');
const php = read('src/Controller/AdminController.php');
const accounts = read('src/Controller/AdminUserController.php');
const twig = read('templates/admin/index.html.twig');
const vault = read('src/Controller/VaultController.php');
assert.match(php, /Route\('\/api\/admin\/csrf'/);
assert.match(php, /'actorId' => \$this->user\(\)->getId\(\)/);
assert.match(php, /'code' => 'actor_changed'/);
assert.match(accounts, /X-Admin-Actor-Id/);
assert.match(accounts, /'code' => 'csrf_invalid'/);
assert.match(vault, /private, no-store, max-age=0/);
assert.match(twig, /window\.DS_ADMIN_ID=/);
assert.match(twig, /datensis-admin\.js'\) \}\}\?v=20261030-4/);
assert.match(php, /UPDATE vault_share SET revoked_at=:now, encrypted_bundle=:empty/);
assert(js.includes("await api('/api/admin/shares/'+encodeURIComponent(s.id)+'/revoke','POST')"));
function setup(fetch,confirm = () => { throw Error('Unexpected confirmation'); }) {
  const source = js.slice(js.indexOf('const $=id=>'), js.indexOf('function elt('));
  const label = {textContent:'admin@example.com'};
  const context = {
    window: {DS_ADMIN_CSRF:'OLD', DS_ADMIN_EMAIL:'admin@example.com',DS_ADMIN_ID:'admin-123',confirm},
    document:{querySelector(sel){assert.equal(sel,'.ds-admin-user');return label;}},
    fetch,URL,Error,JSON,String
  };
  vm.runInNewContext(source+'\nthis.callApi=api;',context);
  return {api:context.callApi,window:context.window,label};
}
const ok = body => ({ok:true,status:200,redirected:false,json:async()=>body});
const denied = (body,status=403) => ({ok:false,status,redirected:false,json:async()=>body});
const actor = (token='FRESH',id='admin-123',email='admin@example.com') => ({csrfToken:token,actorId:id,actorEmail:email});
(async()=>{
  {
    const seen=[];
    const {api}=setup(async (url,options)=>{
      seen.push([url,options]);
      if(url==='/api/admin/csrf')return ok(actor());
      assert.equal(options.headers['X-CSRF-Token'],'FRESH');
      assert.equal(options.headers['X-Admin-Actor-Id'],'admin-123');
      return ok({ok:true});
    });
    assert.equal((await api('/api/admin/shares/test-id/revoke','POST')).ok,true);
    assert.equal(seen.length,2);
    assert.equal(seen[0][1].method,'GET');
    assert.equal(seen[1][1].method,'POST');
  }
  {
    let tokenN=0,writeN=0;
    const {api}=setup(async (url,options)=>{
      if(url==='/api/admin/csrf')return ok(actor('FRESH-'+(++tokenN)));
      writeN++;
      if(writeN===1)return denied({code:'csrf_invalid',error:'Jeton expiré'});
      assert.equal(options.headers['X-CSRF-Token'],'FRESH-2');
      return ok({ok:true});
    });
    assert.equal((await api('/api/admin/shares/test-id/revoke','POST')).ok,true);
    assert.equal(writeN,2);
    assert.equal(tokenN,2);
  }
  {
    // Un renommage d'email ne doit plus déclencher de blocage ou de confirmation.
    const {api,window,label}=setup(async (url,options)=>url==='/api/admin/csrf'?
      ok(actor('TOKEN','admin-123','renamed@example.com')):ok({ok:true}));
    assert.equal((await api('/api/admin/users/test-id','PATCH',{})).ok,true);
    assert.equal(window.DS_ADMIN_EMAIL,'renamed@example.com');
    assert.equal(label.textContent,'renamed@example.com');
  }
  {
    // Un autre administrateur réellement connecté : consentement explicite,
    // en-tête lié à la nouvelle session, sans blocage permanent.
    const requested=[];
    let confirms=0;
    const {api,window}=setup(async (url,options)=>{
      if(url==='/api/admin/csrf')return ok(actor('TOKEN','other-admin','other@example.com'));
      requested.push(options.headers['X-Admin-Actor-Id']);return ok({ok:true});
    },()=>{confirms++;return true;});
    await api('/api/admin/users/test-id','PATCH',{disabled:true});
    await api('/api/admin/users/test-id','PATCH',{disabled:false});
    assert.equal(confirms,1);
    assert.deepEqual(requested,['other-admin','other-admin']);
    assert.equal(window.DS_ADMIN_ID,'other-admin');
  }
  {
    // Refus de confirmation : aucune action destructive ne part.
    let writes=0;
    const {api}=setup(async url=>{
      if(url==='/api/admin/csrf')return ok(actor('TOKEN','other-admin','other@example.com'));
      writes++;return ok({ok:true});
    },()=>false);
    await assert.rejects(api('/api/admin/shares/test-id/revoke','POST'),/Action annulée/);
    assert.equal(writes,0);
  }
  {
    let writes=0;
    const {api}=setup(async url=>{
      if(url==='/api/admin/csrf')return denied({error:'Accès administrateur refusé'});
      writes++;return ok({ok:true});
    });
    await assert.rejects(api('/api/admin/shares/test-id/revoke','POST'),/Accès administrateur refusé/);
    assert.equal(writes,0);
  }
  {
    let writes=0;
    const {api}=setup(async url=>{
      if(url==='/api/admin/csrf')return ok(actor('TOKEN'));
      writes++;return denied({error:'Permissions insuffisantes',code:'access_denied'});
    });
    await assert.rejects(api('/api/admin/shares/test-id/revoke','POST'),/Permissions insuffisantes/);
    assert.equal(writes,1);
  }
  console.log('OK session admin: email modifie, changement acteur avec accord, CSRF regenere et droits conserves.');
})().catch(e=>{console.error(e);process.exitCode=1;});
