# Datensis Stock

**Gestionnaire de mots de passe auto-hébergé · Symfony 7.4 · Chrome / Edge**

Datensis Stock est une application de gestion d'identifiants développée avec Symfony. Elle associe un coffre accessible depuis le navigateur à une extension Chrome / Edge sous forme de mini-fenêtre, sans avoir à ouvrir systématiquement le site principal.

> [!WARNING]
> **Version de développement — projet non audité.** Ne pas utiliser en production pour conserver de vrais secrets professionnels avant une revue complète de sécurité, des tests de restauration et une validation du déploiement.

**Dépôt :** https://github.com/hugorouff/Datensis-stock.git

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation locale](#installation-locale)
- [Extension Chrome et Edge](#extension-chrome-et-edge)
- [Sécurité et limites](#sécurité-et-limites)
- [Mises à jour et migrations](#mises-à-jour-et-migrations)
- [Tests](#tests)
- [Documentation](#documentation)

## Fonctionnalités

| Module | Capacités décrites dans la version fournie |
| --- | --- |
| Coffre | Identifiants, notes, cartes, identités, clés SSH, favoris et dossiers |
| Gestion | Création, modification, corbeille, restauration, duplication et recherche |
| Outils | Générateur de mots de passe, import/export, Send de texte ou fichier via le site |
| Organisation | Étiquettes, responsables, échéances de revue et Centre d'actions (`/actions`) |
| Cabinet | Cockpit et Centre de sécurité avec indicateurs locaux et contrôles déclaratifs |
| Extension | Mini-coffre Chrome/Edge : connexion, consultation, édition, recherche, copie et générateur |

Les partages sont **nominatifs et en lecture seule** selon la documentation du projet. Il n'y a pas de coffre commun ni de rotation automatique des mots de passe des services externes.

### Interface

Palette utilisée par Datensis Stock : bleu pétrole `#00778B`, corail `#E96148`, sauge `#82C4A8` et blanc `#FFFFFF`.

## Prérequis

- PHP **8.2+**, avec `pdo_sqlite` ;
- Composer ;
- Git ;
- Node.js uniquement pour certains tests JavaScript ;
- navigateur Chrome ou Edge pour l'extension.

## Installation locale

### 1. Récupérer le projet

```powershell
git clone https://github.com/hugorouff/Datensis-stock.git
cd Datensis-stock
composer install
```

### 2. Configurer Symfony

Copier le fichier d'environnement local :

```powershell
Copy-Item .env .env.local
```

Adapter `.env.local` (ne pas publier ce fichier) :

```dotenv
APP_ENV=dev
APP_DEBUG=1
APP_SECRET=REMPLACER_PAR_UN_SECRET_ALEATOIRE
DATABASE_URL="sqlite:///%kernel.project_dir%/var/data.db"
ALLOW_REGISTRATION=1
MAILER_DSN=null://null
DEFAULT_URI=http://127.0.0.1:8001
```

> **Attention :** le guide technique associé signale que certaines versions de `config/packages/doctrine.yaml` imposent SQLite directement. Vérifier ce fichier : dans ce cas, modifier `DATABASE_URL` seul ne changera pas la base réellement utilisée.

### 3. Préparer SQLite

```powershell
php bin/console cache:clear
php bin/console doctrine:migrations:migrate --no-interaction
```

Avant de lancer une migration sur un projet déjà utilisé, **sauvegarder `var/data.db`** et vérifier la connexion réellement sélectionnée par Doctrine.

### 4. Lancer le serveur local

```powershell
php -S 127.0.0.1:8001 -t public public/router.php
```

Si `public/router.php` n'est pas présent dans la version du dépôt, utiliser le serveur Symfony CLI (`symfony server:start`) ou une configuration PHP adaptée.

Ouvrir `http://127.0.0.1:8001/register` pour créer un compte, puis `http://127.0.0.1:8001/login`.

## Extension Chrome et Edge

Le dossier `chrome-extension/` contient l'extension Manifest V3.

1. Démarrer l'application Symfony.
2. Ouvrir `chrome://extensions` ou `edge://extensions`.
3. Activer le **mode développeur** pour l'installation locale.
4. Cliquer sur **Charger l'extension non empaquetée**.
5. Sélectionner `chrome-extension/`, puis épingler l'extension.
6. Configurer l'adresse serveur dans la popup : `http://127.0.0.1:8001` en local, HTTPS pour un serveur distant.

La popup permet notamment de consulter et rechercher les fiches, copier ou révéler un mot de passe, ajouter/modifier une fiche, utiliser les favoris et générer des mots de passe. Le filtrage par domaine s'appuie sur l'autorisation `activeTab`.

**Limites documentées :** l'extension n'est pas publiée dans les boutiques ; l'installation sans mode développeur nécessite une distribution officielle ou administrée. La version décrite ne prend pas encore en charge le remplissage automatique sur les pages visitées, les Send de fichiers dans la popup ou la 2FA depuis l'extension. Pas de popup Safari native annoncée.

## Sécurité et limites

### Chiffrement et sessions

La documentation fournie décrit :

- Chiffrement local des fiches avec **AES-GCM** et dérivation de clé **Argon2id** pour les nouveaux coffres ;
- Prise en charge d'anciens coffres PBKDF2-SHA256 et migration lors du déverrouillage depuis le site ;
- Hachage des mots de passe de connexion côté Symfony ;
- Jeton d'extension à durée limitée, stocké en mémoire dans la popup ;
- Verrouillage de l'extension à la fermeture de la popup et verrouillage du coffre web au changement d'onglet ;
- **2FA désactivée en développement**, configuration conservée pour une réactivation future.

Ces caractéristiques sont **décrites dans les documents du projet, pas vérifiées par un audit indépendant**. Un verrouillage de l'interface n'équivaut pas à un effacement garanti de la mémoire du navigateur. Le presse-papiers reste un canal externe.

### SQLite et hébergement

SQLite convient au développement local, sous réserve de protéger les fichiers et les sauvegardes. Sur Scalingo, le système de fichiers des conteneurs est éphémère : **ne pas considérer `var/data.db` comme un stockage de production persistant**. Une stratégie de stockage durable et de restauration doit être définie avant une mise en production.

Ne jamais pousser vers GitHub les fichiers `.env.local`, `var/data.db`, les exports de coffres ou des secrets réels.

## Mises à jour et migrations

Pour un projet déjà utilisé :

1. Arrêter l'application et sauvegarder `var/data.db`, `.env.local` et la version du code.
2. Récupérer la nouvelle version du dépôt sans écraser les données locales.
3. Vérifier les paramètres Doctrine et les changements de migration.
4. Installer les dépendances : `composer install`.
5. Lancer `php bin/console doctrine:migrations:migrate --no-interaction` après vérification de la sauvegarde.
6. Tester la connexion, le déverrouillage, les fiches et l'extension.

La migration `Version20261103000100.php` est mentionnée dans la documentation fournie pour le suivi de `vault_kdf_version`. Les anciens coffres peuvent demander une conversion depuis le site. Le guide joint décrit séparément la **migration SQLite → PostgreSQL sur Scalingo** : elle est facultative pour le travail local et nécessite un outil d'import des données, pas seulement les migrations Doctrine.

## Tests

Si les fichiers correspondants existent dans le dépôt :

```powershell
php -d zend.assertions=1 -d assert.exception=1 tests/security-smoke.php
php -d zend.assertions=1 -d assert.exception=1 tests/email-otp.test.php
node tests/cockpit.test.cjs
node tests/security-center.test.cjs
```

Ces commandes sont issues du README fourni ; leur succès n'a pas été revérifié sur cette version du dépôt.

## Documentation

Documents mentionnés dans le projet (selon leur disponibilité dans le dépôt) :

- `SECURITY.md` : sécurité et limites ;
- `GUIDE-EXTENSION-MINI-COFFRE.md` : installation de la popup ;
- `GUIDE-EXTENSION-DEPLOIEMENT-ENTREPRISE.md` : distribution administrée ;
- `GUIDE-EXTENSION-POPUP.md` : fonctionnement de l'extension ;
- `GUIDE-BREVO.md` : préparation de la 2FA e-mail ;
- `GUIDE-MISE-A-JOUR-ML2C.md` : historique du projet ;
- **Guide de migration SQLite → PostgreSQL sur Scalingo** : procédure de bascule et sauvegarde.

---

**Datensis Stock** — Application Symfony auto-hébergée, actuellement en développement.
