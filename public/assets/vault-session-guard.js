/* Invalidate pending unlocks whenever the vault is hidden or leaves this page.
 * No master password, AES key, token or other secret is stored here.
 */
'use strict';
(() => {
  let generation = 0;
  let leaving = false;
  window.ML2CVaultGuard = Object.freeze({
    ticket: () => generation,
    invalidate: () => ++generation,
    depart: () => { leaving = true; return ++generation; },
    restore: () => { leaving = false; return ++generation; },
    active: ticket => ticket === generation && !leaving && !document.hidden,
  });
})();
