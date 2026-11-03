/* Datensis Stock — panneau lateral natif Chrome / Edge.
 * Configuration globale (sans tabId) : meme panneau lors des changements d'onglet.
 * Aucun mot de passe, jeton ou cle ne transite par ce service worker.
 */
'use strict';

chrome.sidePanel.setPanelBehavior({openPanelOnActionClick:true})
  .catch(error => console.error('Impossible d activer le panneau lateral Datensis Stock :',error));

// Quand le navigateur signale la fermeture du panneau, invalider la session
// chiffree encore en memoire dans les vues eventuellement conservees en cache.
// Cette API est optionnelle sur certains navigateurs Chromium plus anciens.
if (chrome.sidePanel.onClosed) {
  chrome.sidePanel.onClosed.addListener(() => {
    chrome.runtime.sendMessage({type:'datensis-stock-panel-closed'}).catch(() => {});
  });
}

// Si le navigateur ralentit les timers de la page, l'alarme Chrome recontrole
// la date de derniere activite dans le panneau, sans avoir acces a la cle.
chrome.alarms.onAlarm.addListener(alarm=>{
  if(alarm.name!=='datensis-stock-idle-v1')return;
  chrome.runtime.sendMessage({type:'datensis-stock-idle-check'}).catch(()=>{});
});
