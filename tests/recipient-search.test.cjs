const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const read = filename => fs.readFileSync(path.join(__dirname, '..', filename), 'utf8');

test('search restricted to verified accounts; no secret sent; capped at 10', () => {
  const php = read('src/Controller/AccountShareController.php');
  assert.match(php, /Route\('\/recipients'/);
  assert.match(php, /getSharingEmailVerifiedAt\(\)/);
  assert.match(php, /sharing_email_verified_at IS NOT NULL/);
  assert.match(php, /sharing_public_key IS NOT NULL/);
  assert.match(php, /LIMIT 10/);
  assert.match(php, /ds_share_suggest/);
  assert.match(php, /str_replace\(\['!', '%', '_'\]/);
  assert.doesNotMatch(php.slice(php.indexOf("Route('/recipients'"), php.indexOf("Route('/recipient'")), /password_hash|sharing_private_key/);
});
test('interface has suggestions, debounce and uses textContent not HTML', () => {
  const html = read('templates/vault/index.html.twig');
  const js = read('public/assets/recipient-search.js');
  assert.match(html, /id="account-share-suggestions"/);
  assert.match(html, /assets\/recipient-search\.js/);
  assert.match(js, /setTimeout\(async \(\) =>/);
  assert.match(js, /350\)/);
  assert.match(js, /button\.textContent = email/);
  assert.doesNotMatch(js, /innerHTML/);
  assert.match(js, /datensis:vault-locked/);
});
