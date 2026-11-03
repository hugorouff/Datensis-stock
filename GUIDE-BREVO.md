# ML2C Vault : mise a jour vers la 2FA e-mail Brevo

Ce correctif remplace le parcours TOTP par un code e-mail obligatoire a la connexion et au deverrouillage apres verrouillage de la page. Aucun compte ni coffre chiffre n'est modifie ; aucune migration de base de donnees n'est necessaire.

## Installation locale (Windows / PowerShell)

1. Sauvegarder **tout** le dossier `C:\Users\Hugo\Documents\bitwarden`, en particulier `var/data.db` et `.env.local`.
2. Extraire l'archive correctif dans `bitwarden` et accepter le remplacement des fichiers ; ne jamais supprimer `var`, `vendor`, `composer.lock` ou `.env.local`.
3. Installer les deux transports Symfony (la dependance `symfony/mailer` est installee automatiquement si necessaire) :

```powershell
cd C:\Users\Hugo\Documents\bitwarden
composer require symfony/brevo-mailer:^7.4 symfony/http-client:^7.4
```

4. Dans votre **`.env.local`** (jamais `.env` suivi par Git), ajouter / remplacer :

```dotenv
MAILER_DSN="brevo+api://VOTRE_CLE_API_BREVO@default"
MAILER_FROM="votre-adresse-verifiee@votre-domaine.fr"
```

La cle API v3 se cree dans **Brevo > SMTP et API > Cles API** (les libelles peuvent evoluer). Verifier l'identite de l'expediteur / le domaine d'envoi dans Brevo. Un compte Brevo et une adresse expediteur verifiee sont necessaires. **Ne pas envoyer la cle API dans le chat ni sur GitHub.** Si elle contient des caracteres speciaux URL, encoder le composant.

5. Verifier avec un vrai e-mail de test puis demarrer :

```powershell
$env:DATABASE_URL = 'sqlite:///%kernel.project_dir%/var/data.db'
php bin/console cache:clear
php bin/console mailer:test votre-adresse-de-test@exemple.fr
php -S 127.0.0.1:8001 -t public public/router.php
```

`mailer:test` teste uniquement l'envoi. Pour verifier la 2FA, ouvrez `/login`, connectez-vous, consultez le code recu, puis saisissez-le. Pas besoin de refaire les migrations (aucune nouvelle table).

## Securite

- Code generé avec `random_int`, 6 chiffres, duree 5 minutes, hachage cote serveur, usage unique.
- Limites : 3 demandes e-mail par compte et 5 **codes incorrects** par compte en 15 minutes (Symfony RateLimiter, stockage **par defaut non distribue**). Un nouveau code n'est pas envoye si un code valide a ete emis dans les 60 dernieres secondes.
- Le serveur refuse les pages et API privees avant validation du code, meme si un compte est deja connecte. L'ancien statut TOTP de la session n'est pas accepte.
- Le coffre peut etre deverrouille avec le mot de passe principal et le code e-mail apres verrouillage.
- La messagerie doit etre accessible **sans devoir ouvrir ML2C Vault** (sinon boucle de recuperation). La 2FA e-mail est moins robuste que TOTP/passkey face a la compromission de la messagerie.
- Erreur d'envoi Brevo : l'acces reste bloque. Ne JAMAIS remplacer `MAILER_DSN` par `null://null` en production.
- Pour une exploitation multi-serveurs, utiliser un cache partage pour RateLimiter et des sessions serveur correctement configurees. Une revue de securite est necessaire avant l'usage de vrais secrets d'entreprise.
