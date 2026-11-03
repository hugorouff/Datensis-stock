/* Mandatory TOTP enrollment. All secret handling remains within this authenticated page. */
'use strict';
(() => {
  const $ = id => document.getElementById(id);
  if (!$('enroll-start-form')) return;
  const token = document.querySelector('meta[name="vault-csrf"]').content;
  const error = $('enroll-error');
  const showError = text => { error.textContent = text; error.hidden = !text; };
  async function post(path, data) {
    const res = await fetch(path, {method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:JSON.stringify(data)});
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || 'Une erreur est survenue.');
    return body;
  }
  $('enroll-start-form').addEventListener('submit', async event => {
    event.preventDefault(); showError('');
    const btn = event.submitter; if (btn) btn.disabled = true;
    try {
      const password = $('enroll-password').value;
      const data = await post('/2fa/setup', {password});
      $('enroll-password').value='';
      $('enroll-secret').textContent = data.secret;
      $('enroll-step-1').hidden=true; $('enroll-step-2').hidden=false;
      $('enroll-code').focus();
    } catch (err) {showError(err.message);} finally {if(btn) btn.disabled=false;}
  });
  $('enroll-confirm-form').addEventListener('submit', async event => {
    event.preventDefault(); showError('');
    const btn = event.submitter; if (btn) btn.disabled = true;
    try {
      const data = await post('/2fa/confirm', {code:$('enroll-code').value.trim()});
      $('enroll-code').value=''; $('enroll-secret').textContent='';
      $('enroll-recovery').textContent = data.recoveryCodes.join('\n');
      $('enroll-step-2').hidden=true; $('enroll-step-3').hidden=false;
    } catch (err) {showError(err.message);} finally {if(btn) btn.disabled=false;}
  });
  $('enroll-copy').addEventListener('click', async () => {
    try {await navigator.clipboard.writeText($('enroll-recovery').textContent);showError('Codes copiés. Conservez-les hors ligne puis effacez votre presse-papiers.');}
    catch {showError('Copie refusée. Sélectionnez manuellement les codes.');}
  });
  $('enroll-saved').addEventListener('change', () => {$('enroll-continue').disabled=!$('enroll-saved').checked;});
  $('enroll-continue').addEventListener('click', () => {
    if (!$('enroll-saved').checked) return;
    $('enroll-recovery').textContent='';
    location.replace('/vault');
  });
})();
