/* ML2C Vault - utilitaires purs pour le Centre d'actions. Aucune requête réseau. */
'use strict';
(function(root,factory){
  const tools=factory();
  if(typeof module==='object'&&module.exports)module.exports=tools;
  if(root)root.ML2CActionTools=tools;
})(typeof window!=='undefined'?window:null,function(){
  function tags(value){return [...new Set(String(value||'').split(',').map(x=>x.trim()).filter(Boolean).map(x=>x.slice(0,40)))].slice(0,12);}
  function validDate(value){return typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(new Date(value+'T00:00:00').getTime());}
  function analyze(items,now=new Date()){
    const day=new Date(now.getFullYear(),now.getMonth(),now.getDate());
    const cutoff=new Date(day);cutoff.setDate(cutoff.getDate()+30);
    const active=items.filter(i=>i&&i.value&&!i.value.deletedAt&&i.value.type==='login');
    const clientMap=new Map(),tagMap=new Map(),queue=[],events=[];
    for(const item of active){
      const v=item.value,client=String(v.client||'').trim()||'Sans dossier client';
      const entry=clientMap.get(client)||{name:client,count:0,urgent:0};entry.count++;
      const problems=[];
      const due=validDate(v.nextRotation)?new Date(v.nextRotation+'T00:00:00'):null;
      const review=validDate(v.reviewDue)?new Date(v.reviewDue+'T00:00:00'):null;
      if(due&&due<day)problems.push({kind:'late',label:'Rotation dépassée',priority:0});
      if(review&&review<day)problems.push({kind:'late',label:'Revue dépassée',priority:0});
      else if(review&&review<=cutoff)problems.push({kind:'review',label:'Revue prévue sous 30 jours',priority:2});
      if(v.criticality==='critical'&&v.service2fa!=='yes')problems.push({kind:'critical',label:'2FA critique à vérifier',priority:1});
      if(!String(v.owner||'').trim())problems.push({kind:'unowned',label:'Responsable non renseigné',priority:2});
      if(!String(v.client||'').trim())problems.push({kind:'review',label:'Dossier client absent',priority:3});
      if(v.handover!=='reviewed'&&v.handover!=='na')problems.push({kind:'review',label:'Passation à vérifier',priority:3});
      if(problems.length){entry.urgent++;const highest=problems.reduce((a,b)=>a.priority<=b.priority?a:b);queue.push({item,client,problems,kind:highest.kind,priority:highest.priority});}
      clientMap.set(client,entry);
      for(const tag of tags(v.tags)){const arr=tagMap.get(tag)||[];arr.push(item);tagMap.set(tag,arr);}
      if(Array.isArray(v.history))for(const event of v.history.slice(-3))if(event&&typeof event.at==='string'&&!Number.isNaN(Date.parse(event.at)))events.push({item,at:event.at,action:String(event.action||'Modification').slice(0,100)});
    }
    queue.sort((a,b)=>a.priority-b.priority||String(a.item.value.name||'').localeCompare(String(b.item.value.name||''),'fr'));
    events.sort((a,b)=>Date.parse(b.at)-Date.parse(a.at));
    return {total:active.length,queue,late:queue.filter(x=>x.problems.some(p=>p.kind==='late')).length,unowned:queue.filter(x=>x.problems.some(p=>p.kind==='unowned')).length,clients:[...clientMap.values()].sort((a,b)=>b.urgent-a.urgent||a.name.localeCompare(b.name,'fr')),tags:[...tagMap.entries()].sort((a,b)=>a[0].localeCompare(b[0],'fr')),events:events.slice(0,30)};
  }
  return {tags,validDate,analyze};
});
