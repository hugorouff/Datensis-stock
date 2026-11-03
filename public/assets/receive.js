'use strict';
(() => {
  const $=id=>document.getElementById(id);
  const token=location.pathname.split('/').pop();
  const keyString=new URLSearchParams(location.hash.slice(1)).get('k');
  const fromB64=data=>Uint8Array.from(atob(data.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-data.length%4)%4)),c=>c.charCodeAt(0));
  const message=text=>{$('recipient-status').textContent=text;};
  async function open(password='') {
    if(!keyString||!crypto.subtle){message('Lien incomplet ou navigateur incompatible.');return;}
    message('Ouverture sécurisée en cours…');
    try {
      const r=await fetch('/api/send-public/'+encodeURIComponent(token)+'/open',{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({password})});
      const result=await r.json();if(!r.ok){if(r.status===403){message('Un mot de passe est nécessaire pour ouvrir ce partage.');$('recipient-form').hidden=false;}else message(result.error||'Partage indisponible.');return;}
      const key=await crypto.subtle.importKey('raw',fromB64(keyString),{name:'AES-GCM'},false,['decrypt']);
      const env=result.payload;
      const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(env.iv)},key,fromB64(env.data));
      const data=JSON.parse(new TextDecoder().decode(plain));
      $('recipient-form').hidden=true;$('recipient-content').replaceChildren();
      const title=document.createElement('h2');title.textContent=data.name||'Partage sécurisé';$('recipient-content').append(title);
      if(data.kind==='text'){
        const text=document.createElement('div');text.className='received-text';text.textContent=data.text;
        if(data.hidden){text.hidden=true;const show=document.createElement('button');show.type='button';show.className='btn outline';show.textContent='Afficher le texte';show.onclick=()=>{text.hidden=!text.hidden;show.textContent=text.hidden?'Afficher le texte':'Masquer le texte';};$('recipient-content').append(show);}
        $('recipient-content').append(text);
        const copy=document.createElement('button');copy.type='button';copy.className='btn primary';copy.textContent='Copier le texte';copy.onclick=async()=>{try{await navigator.clipboard.writeText(data.text);message('Texte copié.');}catch{message('Copie refusée par le navigateur.');}};$('recipient-content').append(copy);
      } else if(data.kind==='file') {
        const binary=fromB64(data.bytes);const blob=new Blob([binary],{type:'application/octet-stream'});
        const button=document.createElement('button');button.type='button';button.className='btn primary';button.textContent='Télécharger '+(data.fileName||'fichier');button.onclick=()=>{const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=(data.fileName||'fichier').split(/[\\/]/).pop();document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500);};$('recipient-content').append(button);
      }else throw Error('Type de partage non reconnu.');
      $('recipient-content').hidden=false;message('Partage déchiffré dans votre navigateur.');
    }catch(e){message('Impossible de déchiffrer le contenu. Vérifiez le lien complet.');}
  }
  $('recipient-form').onsubmit=e=>{e.preventDefault();open($('recipient-password').value);};
  if(!window.isSecureContext){message('HTTPS ou localhost est nécessaire.');return;}
  open();
})();
