# SÉCURITÉ — ML2C Vault Édition Cabinet

> Prototype non audité. **Ne pas confier de vrais secrets professionnels à ce code avant tests de sécurité indépendants, revue du chiffrement, du modèle de menace et de l'exploitation.**

### Chiffrement

- Coffre : clé AES-256-GCM dérivée dans le navigateur avec Argon2id (3 passes, 64 Mio, sel aléatoire de 16 octets). Les coffres existants en PBKDF2-SHA256 (600 000 itérations) sont convertis côté navigateur, au prochain déverrouillage sur le site, en rechiffrant les entrées, Sends et clés partagées. Le même mot de passe principal sert à l'authentification Symfony (hash Argon2id côté serveur) et à la dérivation **dans le navigateur** ; la clé AES n'est pas stockée sur le serveur. Les anciens hashes de connexion sont acceptés via `migrate_from: auto` puis remplacés par Argon2id lors d'une connexion réussie.
- Changement du mot de passe principal : **pas de parcours sûr de changement** implémenté. Modifier uniquement le hash serveur rendrait les anciens éléments illisibles.
- L'ancienne phrase secrète d'un coffre antérieur reste nécessaire pour rechiffrer les données anciennes : opération réalisée côté navigateur puis mise à jour atomique des enveloppes côté serveur. Conserver une sauvegarde de la base et tester sur copie avant la conversion.
- La compromission du serveur ou du JavaScript distribué peut compromettre le chiffrement côté client. Le code client doit être audité et protégé contre les injections.
- Les champs Cockpit (dossier client, responsable, criticité, procédures et échéances) restent dans la même enveloppe chiffrée que le mot de passe ; le serveur reçoit seulement le type, la taille, les identifiants et les métadonnées techniques nécessaires.

### 2FA et verrouillage

**Mise a jour Brevo :** la 2FA obligatoire utilise maintenant un OTP e-mail (6 chiffres / 5 min), non un code TOTP. Les phrases ci-dessous au sujet du TOTP decrivent l'ancien systeme et ne sont plus applicables. Limite globale par compte 3 e-mails et 5 essais / 15 min, dependant du stockage Symfony RateLimiter.


- **2FA obligatoire depuis cette mise à jour**, y compris pour les comptes existants. Le serveur refuse toutes les pages du coffre et API privées avant l’enrôlement puis la validation TOTP ; la page `/2fa` permet la configuration initiale. Les sessions précédentes ne doivent pas suffire à accéder au coffre.
- TOTP SHA-1/30 secondes/6 chiffres compatible RFC 6238, secret aléatoire 160 bits chiffré au repos à l'aide d'une clé dérivée de `APP_SECRET`, codes de récupération à usage unique conservés sous forme de hachages.
- Anti-rejeu TOTP sur le compteur consommé. Limitation applicative de tentatives **par session**, insuffisante contre les attaques distribuées ; renforcer avant toute production (par compte/IP, protection de l'endpoint OTP et journalisation sécurisée).
- Verrouillage immédiat en JavaScript au changement d'onglet / fermeture / inactivité (5 minutes) ; vérification OTP lors du déverrouillage de la page quand la 2FA est activée.
- Le signal de verrouillage serveur est transmis via `sendBeacon` si possible, avec requête `keepalive` de secours. **Aucune notification réseau n'est garantie à la fermeture brutale.** Pour un modèle strict de ré-authentification, ajouter un flux authentifié de verrouillage/jeton explicite et des règles de session serveur ; ce prototype ne garantit pas l'invalidation immédiate d'une session lors d'un crash.
- La clé mémoire et le mot de passe sont soumis aux limites du garbage collector du navigateur : suppression des références JS ≠ effacement RAM garanti.

### Application installable / extension Chrome-Edge

- PWA installable (Chrome/Edge, Safari Ajouter au Dock) avec service worker **réseau uniquement** : aucun contenu chiffré ou déchiffré n’est mis en cache offline. Ce n’est pas une extension de barre d’outils et ce n’est pas un contrôle de sécurité supplémentaire.
- Manifest V3, HTML/JS local, permission `storage` uniquement (adresse du serveur). Aucun accès aux autres onglets, pas de content script ni remplissage automatique.
- Le mini-coffre ouvre la **même application Symfony** dans une fenêtre, soumis aux mêmes cookies, à la connexion, à la 2FA et au verrouillage du site ; aucun secret du coffre n'est copié dans le stockage de l'extension.
- Les mots de passe générés dans le popup ne sont pas conservés par l'extension, mais la copie dans le presse-papiers est visible par d'autres logiciels capables de le lire. Effacer le presse-papiers manuellement si nécessaire.

### Cockpit

- Les contrôles sont heuristiques : réutilisation locale, qualité estimée, dates déclarées, 2FA du service **déclarée** par l'utilisateur. Ils ne vérifient ni compromission ni politiques de sécurité tierces.
- Le CSV de rotations est **délibérément non chiffré** : confirmation obligatoire avant téléchargement et protection contre l'injection de formules. Le document est à conserver sur un espace approuvé ou à supprimer.
- Aucune collecte de données clients depuis Datensis ; lier ultérieurement par API exige une analyse d'habilitations et de confidentialité.

### Send

- Clé aléatoire côté navigateur, transport dans le fragment de lien `#k=...` ; le serveur stocke la charge chiffrée et des métadonnées d'expiration/contrôle, mais pas cette clé de lien.
- Le lien complet donne accès au secret à toute personne qui le possède (en plus d'un éventuel mot de passe Send).
- HTTPS obligatoire pour toute exposition publique ; supprimer les Send expirés via la commande planifiée `php bin/console app:purge-expired-sends`.

### Pour une mise en production

HTTPS/HSTS, restriction des inscriptions, gestion de permissions par entreprise, anti-brute-force centralisé, séparation et rotation de clés, politique de sauvegarde chiffrée, tests de non-régression, audit cryptographique et de l'extension, CSP et tests d'intrusion restent indispensables.

Ne pas publier `var/data.db`, `.env.local`, les clés d'environnement, journaux sensibles ni les sauvegardes en clair. Le secret de développement du `.env` distribué doit être remplacé avant tout hébergement.

## API extension (mini-coffre)

Les routes `/api/extension/*` sont accessibles sans cookie, **mais n'autorisent pas les operations sans jeton Bearer temporaire**. La connexion exige e-mail + mot de passe, une limitation des tentatives et HTTPS hors localhost. Les jetons aleatoires sont haches (`sha256`) dans `vault_extension_session` et expirent au plus tard apres 10 minutes. Le jeton et la cle de coffre restent uniquement en memoire de la popup. La fermeture de celle-ci les fait disparaitre, meme si un jeton serveur non revoque peut rester valide jusqu'a son expiration.

Il n'existe **pas** de remplissage automatique, de lecture de cookies, ni d'injection de script dans les pages visitees. La permission `activeTab` est utilisee uniquement pour comparer le domaine de l'onglet actif avec les URL du coffre, localement. Le changement d'une option de securite du serveur doit etre accompagne de tests du parcours extension ; si la 2FA est activee, l'extension refuse de se connecter tant que son parcours de verification n'est pas implemente.

L'ensemble reste un prototype non audite. Les permissions, la synchronisation, le risque de fuite par presse-papiers et la recuperation de compte doivent etre examines avant la mise en production.

### Verrouillage sur changement de page (correctif)

Un garde d'epoch annule les déverrouillages asynchrones entamés avant la perte de visibilité. `visibilitychange`, `pagehide` et `pageshow` (BFCache) effacent les références au coffre déchiffré dans l'UI et les variables JavaScript principales. Le serveur Symfony reste potentiellement authentifié : c'est un **verrouillage du coffre**, pas une révocation fiable de session. Les chaînes et buffers libérés ne peuvent pas être effacés physiquement avec garantie en JavaScript. Le déverrouillage initial s'effectue au moment de la connexion ; un mot de passe redemandé reste nécessaire après un verrouillage de la page.
