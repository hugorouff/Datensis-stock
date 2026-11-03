# Installer la vraie extension ML2C Vault

L’extension est une popup Manifest V3, pas une application PWA. Le site ne peut **ni activer le mode développeur, ni installer silencieusement l’extension**.

## Test local : Chrome / Edge

1. Démarrer Symfony sur `http://127.0.0.1:8001` (en production, HTTPS obligatoire).
2. Ouvrir `chrome://extensions` ou `edge://extensions`.
3. Activer **Mode développeur** et cliquer sur **Charger l’extension non empaquetée**.
4. Sélectionner le dossier `chrome-extension` contenant `manifest.json`.
5. Épingler l’icône ML2C Vault dans la barre d’outils.

## Installation facile pour les collaborateurs

- **Publication Chrome Web Store / Edge Add-ons** : distribution avec une page d’installation et mises à jour du navigateur. La publication nécessite validation.
- **Navigateurs administrés d’entreprise** : les politiques de navigateur permettent à un administrateur de distribuer une extension de façon automatique, avec un identifiant et un `update_url` fiables. Cette configuration doit être effectuée côté administration, pas depuis Symfony.
- **Safari** : nécessite un packaging et des procédures Apple dédiées. Ce ZIP ne fournit pas d’extension Safari.

## Limites du prototype

Le panneau de l’extension génère et copie un mot de passe hors ligne, et ouvre le site Symfony pour les fiches. L’extension **ne détient pas la clé du coffre** et ne réalise **pas d’autoremplissage**. Aucun mot de passe n’est stocké dans `chrome.storage`.
