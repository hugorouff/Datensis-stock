/* Datensis Stock: partage chiffré entre comptes, aucune clé privée en clair côté serveur. */
'use strict';
(function (root) {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const b64 = bytes => {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let output = '';
    for (let i = 0; i < arr.length; i += 8192) output += String.fromCharCode(...arr.subarray(i, i + 8192));
    return btoa(output);
  };
  const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
  const subtle = () => root.crypto.subtle;
  async function createIdentity(vaultKey, encryptVault) {
    const pair = await subtle().generateKey({name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256'}, true, ['encrypt', 'decrypt']);
    const exported = await subtle().exportKey('jwk', pair.privateKey);
    const publicKey = b64(await subtle().exportKey('spki', pair.publicKey));
    const encryptedPrivateKey = await encryptVault(exported, vaultKey);
    return {publicKey, encryptedPrivateKey};
  }
  async function privateKey(encryptedPrivateKey, vaultKey, decryptVault) {
    const jwk = await decryptVault(encryptedPrivateKey, vaultKey);
    return subtle().importKey('jwk', jwk, {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['decrypt']);
  }
  async function seal(value, publicKey) {
    const key = root.crypto.getRandomValues(new Uint8Array(32));
    const iv = root.crypto.getRandomValues(new Uint8Array(12));
    const aead = await subtle().importKey('raw', key, 'AES-GCM', false, ['encrypt']);
    const rsa = await subtle().importKey('spki', bytes(publicKey), {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
    const data = await subtle().encrypt({name: 'AES-GCM', iv}, aead, encoder.encode(JSON.stringify(value)));
    const wrappedKey = await subtle().encrypt({name: 'RSA-OAEP'}, rsa, key);
    key.fill(0);
    return {v: 1, iv: b64(iv), data: b64(data), wrappedKey: b64(wrappedKey)};
  }
  async function open(bundle, rsaKey) {
    if (bundle?.v !== 1 || typeof bundle.wrappedKey !== 'string') throw Error('Partage chiffré invalide.');
    const key = new Uint8Array(await subtle().decrypt({name:'RSA-OAEP'}, rsaKey, bytes(bundle.wrappedKey)));
    try {
      const aead = await subtle().importKey('raw', key, 'AES-GCM', false, ['decrypt']);
      const plain = await subtle().decrypt({name: 'AES-GCM', iv: bytes(bundle.iv)}, aead, bytes(bundle.data));
      return JSON.parse(decoder.decode(plain));
    } finally { key.fill(0); }
  }
  function snapshot(items, scope, target) {
    const filtered = items.filter(x => !x.value.deletedAt && x.value.type === 'login' && typeof x.value.password === 'string'
      && (scope === 'entry' ? x.id === target : x.value.folder === target || (typeof x.value.folder === 'string' && x.value.folder.startsWith(target + '/'))));
    if (!filtered.length) throw Error('Ce partage ne contient aucun mot de passe.');
    if (filtered.length > 100) throw Error('Maximum 100 identifiants par partage.');
    const rows = filtered.map(x => ({
      name: String(x.value.name || 'Accès').slice(0,200),
      username: String(x.value.username || '').slice(0,300),
      password: x.value.password,
      url: String(x.value.url || '').slice(0,2048),
      // Chemin relatif pour que le destinataire choisisse lui-même son entreprise / dossier.
      relativeFolder: scope === 'folder' ? String(x.value.folder || '').slice(target.length).replace(/^\//,'') : '',
    }));
    const result = {v:1, scope, entries:rows};
    if (JSON.stringify(result).length > 110000) throw Error('Partage trop volumineux, sélectionnez un sous-dossier.');
    return result;
  }
  const api={createIdentity, privateKey, seal, open, snapshot};
  root.DatensisAccountSharing=api;
  if (typeof module !== 'undefined' && module.exports) module.exports=api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
