'use strict';
(() => {
  const form=document.getElementById('otp-page-form');if(!form)return;
  const token=document.querySelector('meta[name="twofa-csrf"]')?.content;
  const error=document.getElementById('otp-page-error');
  const status=document.getElementById('otp-send-status');
  async function post(path,body={}){
    const res=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'Content-Type':'application/json','X-CSRF-Token':token},body:JSON.stringify(body)});
    const data=await res.json();if(!res.ok)throw Error(data.error||'Une erreur est survenue.');return data;
  }
  async function send(){error.hidden=true;const btn=document.getElementById('otp-page-resend');btn.disabled=true;
    try{const data=await post('/2fa/send');status.textContent=data.message||'Un code a été envoyé.';}
    catch(e){error.textContent=e.message;error.hidden=false;status.textContent='Envoi non effectué.';}
    finally{btn.disabled=false;}
  }
  document.getElementById('otp-page-resend').addEventListener('click',send);
  form.addEventListener('submit',async e=>{
    e.preventDefault();error.hidden=true;
    try{await post('/2fa/verify',{code:document.getElementById('otp-page-code').value.trim()});location.replace('/');}
    catch(err){error.textContent=err.message;error.hidden=false;}
  });
  send();
})();
