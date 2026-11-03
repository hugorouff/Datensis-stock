# ML2C Vault – Extension mini-coffre Chrome et Edge

Cette extension ouvre une **vraie popup dans la barre d'outils**. La liste des mots de passe et leurs fiches s'affichent directement dans celle-ci, sans lancer le site Symfony.

## Mise a jour du projet Symfony existant

1. Copier `src/Controller/ExtensionApiController.php`, `config/packages/rate_limiter.yaml`, `config/packages/security.yaml`, `migrations/Version20261028000400.php` ainsi que le dossier `chrome-extension/` du ZIP de mise a jour dans le projet.
2. **Sauvegarder** `var/data.db` et `.env.local`, ne pas les remplacer.
3. Dans PowerShell, a la racine du projet :

```powershell
$env:DATABASE_URL = 'sqlite:///%kernel.project_dir%/var/data.db'
php bin/console cache:clear
php bin/console doctrine:migrations:migrate --no-interaction
php -S 127.0.0.1:8001 -t public public/router.php
```

La seule nouvelle table est `vault_extension_session`, pour des jetons de session temporaires. Les fiches et comptes existants restent dans les tables precedentes.

## Charger l'extension dans Edge/Chrome (developpement)

1. Ouvrir `edge://extensions` ou `chrome://extensions`.
2. Activer le mode developpeur.
3. Cliquer sur **Charger l'extension non empaquetee**.
4. Selectionner le dossier `chrome-extension` (il contient `manifest.json`).
5. Epingler ML2C Vault a la barre d'outils.
6. Cliquer sur son icone : la connexion apparait directement dans la petite popup.
7. Si besoin, cliquer sur **Configurer l'adresse du serveur**, saisir `http://127.0.0.1:8001`, autoriser le domaine et se connecter.

Pour actualiser une extension deja installee : ouvrir `edge://extensions` ou `chrome://extensions`, puis cliquer sur **Actualiser** sur la fiche ML2C Vault. Ne pas installer l'ancienne PWA.

## En production

- Remplacer le serveur par une adresse `https://` reelle dans les reglages de l'extension. La popup demande alors explicitement l'autorisation de contacter ce domaine (pas d'autorisation generale automatique).
- Configurer correctement le HTTPS et les proxies de Symfony avant de publier. La route de connexion extension refuse HTTP hors localhost.
- Publier l'extension sur Chrome Web Store et Edge Add-ons, ou la distribuer par politique d'entreprise pour eviter le mode developpeur aux collaborateurs.
- Realiser tests complets et audit de securite avant d'enregistrer de vrais secrets professionnels. La 2FA reste volontairement desactivee dans cette version de developpement.

## Fonctionnement et limites

La connexion dans la popup est **independante du cookie Symfony du site**. L'utilisateur saisit son e-mail et son mot de passe principal, ce qui authentifie et decrypte le coffre dans le meme ecran. Les nouveaux coffres utilisent Argon2id (3 passes, 64 Mio) pour deriver la cle et AES-GCM pour chiffrer les donnees. Les anciens coffres PBKDF2 restent accessibles dans la popup, mais doivent etre ouverts sur le site pour etre convertis vers Argon2id. La popup ne conserve ni mots de passe, ni cle de chiffrement, ni jeton d'authentification dans le stockage persistant. Elle perd sa session des sa fermeture.

Les fiches existantes chiffrees avec une ancienne phrase secrete differente doivent etre converties **une fois depuis le site** avant de fonctionner avec ce mot de passe.

Les notes et autres secrets s'affichent dans l'extension. Les Send de texte peuvent etre geres dans la popup. Les partages de fichiers, le remplissage automatique et le challenge 2FA dans l'extension sont des evolutions ulterieures. La 2FA reactivee bloque l'API extension par securite.
