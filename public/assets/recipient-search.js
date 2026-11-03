/* Recherche limitee aux comptes utilisateurs actifs, sans exposer de mots de passe. */
'use strict';
(() => {
  const input = document.getElementById('account-share-email');
  const list = document.getElementById('account-share-suggestions');
  const status = document.getElementById('account-share-search-status');
  if (!input || !list || !status) return;

  let timer = null;
  let controller = null;
  let generation = 0;
  let options = [];
  let selected = -1;

  const hide = () => {
    list.hidden = true;
    input.setAttribute('aria-expanded', 'false');
    input.removeAttribute('aria-activedescendant');
    options = [];
    selected = -1;
    list.replaceChildren();
  };
  function abort() {
    generation++;
    if (timer) clearTimeout(timer);
    timer = null;
    if (controller) controller.abort();
    controller = null;
  }
  function select(email) {
    input.value = email;
    abort();
    hide();
    status.textContent = 'Compte sélectionné : ' + email;
    input.focus();
  }
  function highlight(index) {
    if (!options.length) return;
    selected = (index + options.length) % options.length;
    options.forEach((button, i) => button.setAttribute('aria-selected', String(i === selected)));
    input.setAttribute('aria-activedescendant', options[selected].id);
  }
  function show(emails) {
    hide();
    if (!emails.length) { status.textContent = 'Aucun compte disponible pour cette recherche.'; return; }
    const fragment = document.createDocumentFragment();
    for (const [i, email] of emails.entries()) {
      if (typeof email !== 'string') continue;
      const button = document.createElement('button');
      button.id = 'ds-recipient-result-' + i;
      button.type = 'button';
      button.className = 'ds-recipient-option';
      button.setAttribute('role', 'option');
      button.setAttribute('aria-selected', 'false');
      button.textContent = email; // Jamais de HTML venant de l'API.
      button.addEventListener('mousedown', e => e.preventDefault());
      button.addEventListener('click', () => select(email));
      fragment.append(button);
      options.push(button);
    }
    list.append(fragment);
    list.hidden = !options.length;
    input.setAttribute('aria-expanded', String(options.length > 0));
    status.textContent = emails.length === 10
      ? '10 comptes affichés au maximum. Affinez la recherche si nécessaire.'
      : emails.length + ' compte(s) correspondant(s). Sélectionnez une adresse.';
  }
  input.addEventListener('input', () => {
    abort();
    hide();
    const query = input.value.trim().toLowerCase();
    if (query.length < 3) {
      status.textContent = 'Saisissez au moins 3 caractères pour rechercher un compte.';
      return;
    }
    if (query.length > 64) {
      status.textContent = 'Recherche trop longue.';
      return;
    }
    status.textContent = 'Recherche des comptes…';
    const current = generation;
    timer = setTimeout(async () => {
      controller = new AbortController();
      try {
        const response = await fetch('/api/shares/recipients?q=' + encodeURIComponent(query), {
          method: 'GET', credentials: 'same-origin', cache: 'no-store',
          headers: {'Accept': 'application/json'}, signal: controller.signal
        });
        const result = await response.json();
        if (current !== generation || input.value.trim().toLowerCase() !== query) return;
        if (!response.ok) throw Error(result.error || 'Recherche indisponible.');
        show(Array.isArray(result.results) ? result.results : []);
      } catch (error) {
        if (current !== generation || error.name === 'AbortError') return;
        hide();
        status.textContent = error.message || 'Recherche indisponible.';
      }
    }, 350);
  });
  input.addEventListener('keydown', event => {
    if (list.hidden || !options.length) return;
    if (event.key === 'ArrowDown') {event.preventDefault();highlight(selected + 1);}
    else if (event.key === 'ArrowUp') {event.preventDefault();highlight(selected - 1);}
    else if (event.key === 'Enter' && selected >= 0) {event.preventDefault();select(options[selected].textContent);}
    else if (event.key === 'Escape') {abort();hide();}
  });
  input.addEventListener('blur', () => {
    setTimeout(() => {if (!list.contains(document.activeElement)) hide();}, 150);
  });
  document.addEventListener('datensis:vault-locked', () => {abort();hide();input.value='';status.textContent='Saisissez au moins 3 caractères pour rechercher un compte.';});
  document.addEventListener('datensis:recipient-clear', () => {abort();hide();status.textContent='Saisissez au moins 3 caractères pour rechercher un compte.';});
})();
