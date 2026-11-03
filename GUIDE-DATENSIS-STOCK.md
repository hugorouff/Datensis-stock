# Datensis Stock — Site complet corrigé

Ce projet contient les pages Symfony, les APIs, le mini-coffre Chrome/Edge, les fichiers CSS/JS, les migrations et les tests.

## Connexion et déverrouillage sur le site

- Sur **/login**, le même mot de passe authentifie l’utilisateur Symfony et déchiffre le coffre dans le navigateur, sans deuxième saisie pour les coffres déjà associés à ce mot de passe.
- Le site ne stocke **pas** le mot de passe principal ou la clé AES dans localStorage, sessionStorage ou un cookie. La clé ne reste que dans la mémoire de la page ouverte.
- Après un verrouillage, rechargement ou changement d’onglet, le site redemande le mot de passe pour déchiffrer. La session Symfony peut encore être active, mais elle ne vaut pas déverrouillage.
- Si un ancien coffre a une **autre phrase secrète**, la première connexion peut demander l’ancienne phrase pour convertir le chiffrement. Ne supprimez pas vos données pour éviter cette étape.
- La connexion dans la **popup** et celle dans le **site** restent indépendantes. L’extension n’envoie ni mot de passe ni clé AES au site, et une connexion à l’extension n’ouvre pas silencieusement une session web.
- Les petits badges `new-chip` ont été retirés, mais leurs rubriques restent disponibles.

## Installer dans votre projet existant sur Windows

1. **Sauvegardez** le projet et la base de données (fichier SQLite ou PostgreSQL). Fermez les onglets du coffre.
2. Pour une installation existante, utilisez de préférence **Datensis-Stock-correctif-site-extension.zip** et son installateur PowerShell, qui conserve la configuration et la base. Pour une installation complète, copiez le contenu de l’archive dans `C:\Users\Hugo\Documents\bitwarden` (fusion des dossiers), **sans écraser** `.env.local`, `var/`, `vendor/` ni les autres fichiers contenant vos secrets.
3. Si les dépendances ne sont pas installées : `composer install`.
4. Vérifiez les migrations : `php bin/console doctrine:migrations:status`, puis `php bin/console doctrine:migrations:migrate --no-interaction` si une migration reste en attente (en particulier `Version20261028000400`, sessions de l’extension).
5. Effacez uniquement le cache applicatif : `php bin/console cache:clear`.
6. Ouvrez `http://127.0.0.1:8001/login` et connectez-vous. Le coffre doit s’ouvrir après dérivation de la clé. En cas de session déjà ouverte, déconnectez-vous normalement avant de tester la connexion en un clic.
7. Dans Edge/Chrome : `edge://extensions` ou `chrome://extensions` > mode développeur > actualiser l’extension chargée depuis le dossier `chrome-extension`.

**Important :** ne remplacez pas une base de données existante par une base vide ; ne modifiez pas les secrets actifs ni les paramètres de connexion. La migration des anciennes données n’est jamais automatique sans l’ancienne phrase secrète.

## Vérifications

Dans ce dossier, avec Node.js installé :

```powershell
node tests/integration-static.test.cjs
node tests/lifecycle-lock.test.cjs
node tests/datensis-login.test.cjs
node tests/login-flow.test.cjs
```

Ces tests vérifient la structure des fichiers et certains comportements JS. Ils ne remplacent pas un test de connexion réel avec Symfony, une base de données et un navigateur.
