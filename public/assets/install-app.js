/* No credentials, secrets or cached pages in the install layer. */
'use strict';
(() => {
  let promptEvent;
  const buttons = () => document.querySelectorAll('[data-install-app]');
  const hint = text => document.querySelectorAll('[data-install-help]').forEach(el => el.textContent=text);
  const isStandalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  function refresh() {
    if(isStandalone()) {buttons().forEach(b=>b.hidden=true);hint('Application déjà installée.');return;}
    if(promptEvent) {buttons().forEach(b=>b.hidden=false);hint('');return;}
    buttons().forEach(b=>b.hidden=false);
    hint('Chrome/Edge : menu du navigateur > Installer cette application. Safari sur Mac : Fichier > Ajouter au Dock.');
  }
  window.addEventListener('beforeinstallprompt', e => {e.preventDefault();promptEvent=e;refresh();});
  window.addEventListener('appinstalled', () => {promptEvent=null;refresh();});
  document.addEventListener('click', async e => {
    const btn=e.target.closest('[data-install-app]');if(!btn)return;
    if(promptEvent) {const p=promptEvent;promptEvent=null;await p.prompt();await p.userChoice;refresh();return;}
    hint('Chrome/Edge : menu ⋯ > Installer Datensis Stock. Safari macOS : Fichier > Ajouter au Dock. Pour la popup dans la barre d’outils, installez l’extension séparément.');
  });
  // Network-only service worker: no passwords, tokens, pages, or responses are cached.
  if('serviceWorker' in navigator && location.protocol==='https:' || ('serviceWorker' in navigator && ['localhost','127.0.0.1'].includes(location.hostname))) {
    window.addEventListener('load',()=>navigator.serviceWorker.register('/sw.js',{scope:'/'}).catch(()=>{}));
  }
  refresh();
})();
