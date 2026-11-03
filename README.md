# ML2C Vault — Projet Symfony complet

**Version de développement (28 octobre 2026)**. Application de coffre-fort avec identité ML2C Conseil, interface en bleu pétrole `#00778B`, corail `#E96148`, sauge `#82C4A8` et blanc `#FFFFFF`.

> **Prototype non audité : ne pas l'utiliser pour conserver de vrais identifiants professionnels en production.** Le chiffrement, l'authentification, la récupération des données, les partages et l'extension nécessitent encore une revue et des tests de sécurité de bout en bout.

## Inclus dans ce ZIP

- **Symfony 7.4 + Doctrine + Twig** : connexion, inscription, coffre et API pour les fiches.
- Coffre chiffré côté navigateur, avec déverrouillage après la connexion au moyen du mot de passe principal. Les anciens coffres peuvent nécessiter une conversion avec leur ancienne phrase secrète.
- Identifiants, notes, cartes, identités, clés SSH, favoris, dossiers, corbeille, générateur, import/export et **Send** (texte ou fichier).
- Cockpit cabinet et Centre de sécurité : analyse indicative locale des doublons, mots de passe faibles, accès critiques, échéances, dossiers et responsables.
- **2FA désactivée pour le développement** dans `config/services.yaml` (`app.vault_2fa_enabled: false`). Le code de vérification e-mail Brevo est conservé pour réactivation future.
- **Vraie extension Chrome/Edge** dans `chrome-extension/`, avec popup attachée à l'icône, générateur local et liens vers le coffre. Les fiches sont gérées dans le site Symfony, pas encore dans la popup. Pas d'autoremplissage, pas de popup Safari native, pas de publication sur les magasins d'extensions.
- Pas de bouton d'installation PWA dans le site : l'extension de barre d'outils est un module distinct.

## Installer sur un nouveau dossier (Windows, PowerShell)

Pré-requis : PHP 8.2 ou supérieur (extension `pdo_sqlite` activée), Composer, Node.js uniquement pour les tests JavaScript.

1. Décompresser l'archive dans un dossier de travail, par exemple `C:\Users\Hugo\Documents\bitwarden`.
2. Dans ce dossier, lancer :

```powershell
composer install
Copy-Item .env .env.local
```

3. Ouvrir `.env.local`, **remplacer `APP_SECRET` par un secret aléatoire privé**, et vérifier la connexion SQLite :

```dotenv
APP_ENV=dev
APP_DEBUG=1
DATABASE_URL="sqlite:///%kernel.project_dir%/var/data.db"
ALLOW_REGISTRATION=1
MAILER_DSN=null://null
```

4. Dans le **même** terminal, si Windows force encore une ancienne connexion PostgreSQL :

```powershell
$env:DATABASE_URL = 'sqlite:///%kernel.project_dir%/var/data.db'
php bin/console cache:clear
php bin/console doctrine:migrations:migrate --no-interaction
php -S 127.0.0.1:8001 -t public public/router.php
```

5. Ouvrir `http://127.0.0.1:8001/register` pour créer un compte, puis `/login`.

**Attention :** aucune base de données, aucun secret utilisateur, aucun répertoire `vendor/` ou `.env.local` n'est livré avec le ZIP. Ils sont générés localement.

## Mettre à jour un projet déjà utilisé

1. **Arrêter le serveur et sauvegarder** le dossier existant, en particulier `var/data.db`, `.env.local` et `composer.lock`.
2. Extraire les nouveaux fichiers à la racine du projet existant. Ne **pas** effacer `var/`, `vendor/`, `.env.local`, `composer.lock` ou les fichiers non inclus dans cette archive.
3. Installer les dépendances nécessaires avec Composer ; vérifier avant de lancer une migration que `DATABASE_URL` cible **la même base SQLite existante**.
4. Exécuter `php bin/console cache:clear` puis `php bin/console doctrine:migrations:migrate --no-interaction`.
5. Si le site demande de convertir un ancien coffre, disposer de l'ancienne phrase secrète et conserver une sauvegarde avant conversion.

## Installer l'extension Chrome / Edge

1. Démarrer le site Symfony.
2. Ouvrir `chrome://extensions` ou `edge://extensions`.
3. Activer le **mode développeur** ; cliquer sur **Charger l'extension non empaquetée**.
4. Sélectionner le dossier `chrome-extension/` contenant `manifest.json` et épingler l'extension.
5. Dans l'onglet Réglages de sa popup, conserver `http://127.0.0.1:8001` en local. En production, utiliser une URL HTTPS.

Cette procédure installe la **popup de barre d'outils**, pas une PWA. La publication dans les magasins d'extensions sera nécessaire pour permettre l'installation en un clic.

## Tests du code livrés

```powershell
php -d zend.assertions=1 -d assert.exception=1 tests/security-smoke.php
php -d zend.assertions=1 -d assert.exception=1 tests/email-otp.test.php
node tests/cockpit.test.cjs
node tests/security-center.test.cjs
```

Les tests ciblés et les contrôles de syntaxe ont passé dans l'environnement de préparation ; il reste à tester l'installation Windows, la migration avec vos données, le login et la popup dans votre navigateur.

## Documentation complémentaire

- `GUIDE-EXTENSION-POPUP.md` : vraie popup Chrome/Edge et différences avec une PWA.
- `GUIDE-MISE-A-JOUR-ML2C.md` : fonctions métier et palette.
- `GUIDE-BREVO.md` : préparation de la 2FA e-mail, actuellement désactivée.
- `SECURITY.md` : limites et précautions de sécurité.

## Nouveautés « Centre d’actions » (octobre 2026)

- Nouvelle URL `/actions` accessible depuis le site et la popup Chrome / Edge.
- Détection locale des revues en retard, accès sans responsable, accès critiques sans 2FA déclarée, passations à revoir et clients manquants.
- Liste de travail filtrable avec ouverture de fiche et validation *déclarative* d’une revue.
- Vue par dossier client, étiquettes de classement, dernier historique local consultable.
- Étiquettes et prochaine date de revue ajoutées dans le **contenu chiffré de chaque fiche** (aucune migration SQL).
- Duplication rapide d’une fiche (vérifier l’élément copié avant d’enregistrer) et recherche par étiquettes.
- Durée de verrouillage personnalisable sur l’appareil : 1/3/5/10/15 min, en plus du verrouillage au changement d’onglet.
- Raccourcis clavier `/`, `N`, `Alt+1`, `Alt+2`.
- Mise à jour de la popup : raccourci Centre d’actions.

**La publication d’une extension ou son installation forcée nécessite une action administrateur externe** ; consulter `GUIDE-EXTENSION-DEPLOIEMENT-ENTREPRISE.md`. Le mode développeur n’est pas activable depuis le site.

**Attention :** les analyses sont des aides manuelles ; les partages entre comptes sont nominatifs et en lecture seule, sans coffre commun ni rotation automatique des mots de passe externes. Le projet n’a pas fait l’objet d’un audit certifié.

## Extension mini-coffre dans la barre d'outils (version 1.0.0)

L'extension `chrome-extension/` n'est **pas** une PWA et ne se contente plus d'ouvrir le site.
En cliquant sur son icone Chrome/Edge, une popup permet maintenant :

- de se connecter avec l'adresse e-mail et le **mot de passe principal** ;
- de retrouver, chercher, filtrer et consulter les **identifiants, notes, cartes, identites et cles SSH** ;
- de reveler et copier le mot de passe, de modifier/ajouter une fiche, de la mettre en favori, de la mettre a la corbeille ou de la restaurer ;
- de generer un mot de passe localement ;
- de gerer les **Send de texte** (creer/copier le lien/activer/desactiver/supprimer) ;
- de filtrer les identifiants du domaine ouvert, via `activeTab` uniquement.

**Securite et limites :** les nouveaux coffres utilisent Argon2id (3 passes, 64 Mio) pour deriver la cle, puis AES-GCM localement. Les anciens coffres PBKDF2-SHA256 (600 000 iterations) restent lisibles; leur migration vers Argon2id est effectuee au prochain deverrouillage depuis le site, pas depuis l'extension. Le serveur ne voit que des enveloppes chiffrees. Les mots de passe de connexion sont haches avec Argon2id par Symfony; les anciens hashes sont verifies puis migres lors d'une connexion reussie. Le jeton de connexion (10 minutes maximum) est stocke sous forme de hash sur le serveur, uniquement en memoire dans la popup, jamais dans `chrome.storage.local`. L'extension se verrouille quand sa popup est fermee : il faudra donc **se reconnecter a chaque nouvelle ouverture**. Le presse-papiers est un canal externe non chiffre. Le remplissage automatique sur les pages visitees, la gestion Send de fichiers et l'activation 2FA depuis l'extension ne sont pas encore pris en charge. Si la 2FA est reactivee dans Symfony, l'API extension refuse l'authentification : ne pas la contourner.

La migration `Version20261103000100.php` ajoute `vault_kdf_version`; les coffres existants sont marques PBKDF2 et convertis par le navigateur lors de leur prochain deverrouillage sur le site.

**Mise a jour depuis ML2C Vault Plus** : sauvegarder `var/data.db` et `.env.local`, copier les fichiers du ZIP dans le projet et executer `php bin/console doctrine:migrations:migrate --no-interaction`. Ne jamais supprimer la base actuelle pour appliquer la mise a jour.

Voir `GUIDE-EXTENSION-MINI-COFFRE.md` pour les etapes d'installation et la configuration du serveur distant.

## Connexion = déverrouillage et verrouillage à la sortie (correctif 28/10/2026)

- En entrant ses identifiants sur `/login`, l'utilisateur authentifie son compte et déverrouille automatiquement son coffre **avec ce même mot de passe**, sans étape supplémentaire. Un coffre ancien chiffré avec une phrase différente peut demander une **conversion unique**.
- Dès que le navigateur masque l'onglet (`visibilitychange`), quitte ou recharge la page (`pagehide`), le coffre perd sa référence à la clé locale et supprime les listes déchiffrées de l'interface. Le retour via l'historique (`pageshow` et BFCache) reste verrouillé.
- Une opération de dérivation ou de déchiffrement commencée avant le changement d'onglet ne peut pas rouvrir le coffre : vérification d'un ticket de session après les opérations asynchrones.
- La navigation entre les rubriques internes (Coffre, Send, Cockpit, etc.) est gérée dans la **même page** et **ne verrouille pas** : elle ne quitte pas le coffre.
- Après un changement d'onglet, ressaisir le mot de passe principal sur l'écran verrouillé. Il n'est pas conservé dans un cookie ni dans `localStorage`/`sessionStorage`.
- L'extension a une session mémoire propre : la fermeture de sa popup verrouille l'extension indépendamment du site.
- Un verrouillage client **ne déconnecte pas forcément la session Symfony** : le serveur peut rester authentifié, mais les données locales déchiffrées sont supprimées. Cela ne garantit pas l'effacement physique des données dans la mémoire du navigateur.

Mise à jour : remplacer les fichiers du correctif, vider le cache Symfony puis recharger le navigateur / extension. **Aucune migration SQL.**
#   D a t e n s i s - s t o c k  
 