'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const js=fs.readFileSync('public/assets/vault.js','utf8');
const twig=fs.readFileSync('templates/vault/index.html.twig','utf8');
const base=fs.readFileSync('templates/base.html.twig','utf8');
const php=fs.readFileSync('src/Controller/VaultApiController.php','utf8');
const css=fs.readFileSync('public/assets/datensis-vault-responsive.css','utf8');

test('all-folders listing displays actual folder with escaped HTML',()=>{
  assert.match(js,/class="entry-folder-path"/);
  assert.match(js,/escapeHtml\(v\.folder\|\|'Sans dossier'\)/);
  assert.match(js,/detail-folder-tag/);
  assert.match(css,/\.entry-folder-path/);
  assert.match(css,/\.detail-folder-tag/);
});
test('delete action is displayed next to modify; trash remains available',()=>{
  const segment=js.slice(js.indexOf('  function renderDetail(){'),js.indexOf('  async function saveValue('));
  const editPos=segment.indexOf('actions.append(edit)');
  const deletePos=segment.indexOf('actions.append(deleteButton)');
  const duplicatePos=segment.indexOf('actions.append(duplicate)');
  assert(editPos>=0&&deletePos>editPos&&duplicatePos>deletePos);
  assert.match(segment,/deleteButton\.onclick=\(\)=>moveItemToTrash\(item\.id\)/);
  assert.match(twig,/<option value="trash">Corbeille<\/option>/);
});
test('write security compares immutable account ids even when email address changes',async()=>{
  assert.match(php,/'accountId' => \$this->currentUser\(\)->getId\(\)/);
  assert.match(twig,/data-account-id=/);
  const snippet=js.slice(js.indexOf('  async function api(path,method='),js.indexOf('  async function vaultKey('));
  const calls=[];
  const ctx={
    $:()=>({dataset:{accountId:'a111',accountEmail:'old@example.com'}}),
    fetch:async(url,opts)=>{calls.push({url,opts});return {ok:true,json:async()=>url==='/api/vault/csrf'?{csrfToken:'FRESH',accountId:'a111',accountEmail:'new@example.com'}:{ok:true}};},
    String,JSON,Error,
  };
  vm.runInNewContext(snippet+'\nthis.api=api;',ctx);
  await ctx.api('/api/vault/entries/foo','PUT',{payload:'encrypted'});
  assert.equal(calls.length,2);
  assert.equal(calls[1].opts.headers['X-CSRF-Token'],'FRESH');
  ctx.fetch=async(url)=>({ok:true,json:async()=>url==='/api/vault/csrf'?{csrfToken:'FRESH',accountId:'another-account'}:{ok:true}});
  await assert.rejects(ctx.api('/api/vault/entries/foo','PUT',{}),/session ne correspond plus/);
});
test('responsive layout has two-column toolbar and single-column vault on tablets',()=>{
  assert.match(css,/#view-vault \.vault-list-panel \.list-toolbar \{display:grid;grid-template-columns:repeat\(2,minmax\(0,1fr\)\)/);
  assert.match(css,/@media \(max-width:1080px\)/);
  assert.match(css,/@media \(max-width:700px\)/);
  assert.match(css,/@media \(max-width:400px\)/);
  assert.match(base,/assets\/datensis-vault-responsive\.css/);
  assert.match(twig,/vault\.js'\) }}\?v=20261103-argon2id2/);
});
