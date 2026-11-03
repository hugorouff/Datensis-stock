# ML2C Vault – Correctif barre d’outils et 2FA désactivée

## Installation SANS perte de données

1. **Sauvegarder intégralement** `C:\Users\Hugo\Documents\bitwarden`, et en particulier `var/data.db`, `.env.local` et `composer.lock`.
2. Décompresser `ml2c-vault-correctif-sans-2fa-toolbar.zip` dans ce dossier, et remplacer les fichiers indiqués. **Ne pas effacer** `var/`, `.env.local`, `vendor/` ni `composer.lock`.
3. Exécuter depuis PowerShell :

```powershell
cd C:\Users\Hugo\Documents\bitwarden
$env:DATABASE_URL = 'sqlite:///%kernel.project_dir%/var/data.db'
php bin/console cache:clear
php bin/console lint:twig templates
php bin/console debug:router
php -S 127.0.0.1:8001 -t public public/router.php
```

**Aucune nouvelle migration** pour ce correctif. Si le projet existant n'a pas encore appliqué ses anciennes migrations, les effectuer **après sauvegarde**, en vérifiant la connexion SQLite.

## 2FA en commentaire / en veille

Le code Brevo, l’envoi et la validation OTP sont conservés, mais la protection 2FA est **désactivée** à un unique endroit : `config/services.yaml` :

```yaml
# 2FA e-mail via Brevo est CONSERVEE mais desactivee temporairement.
# La reactiver plus tard en remplacant false par true puis cache:clear.
app.vault_2fa_enabled: false
```

Pour la remettre : `false` → `true`, configurer `MAILER_DSN=brevo+api://...@default` et `MAILER_FROM`, puis exécuter `php bin/console cache:clear` et tester dans une session privée. **Ne jamais activer la 2FA avec `null://null`** : aucun e-mail ne serait envoyé. Le mode sans 2FA est temporaire et non approprié à un déploiement professionnel avec des secrets réels.

## Barre d'outils en ligne

La page `/vault` possède une barre d’actions rapides (nouvel identifiant, mes accès, générateur, Send, recherche). `/mini` est conçu pour une petite fenêtre et utilise la session Symfony ordinaire et le même chiffrement dans le navigateur. Le déverrouillage du mini-coffre demande le mot de passe principal ; il ne réutilise pas une clé depuis un autre onglet.

## Extension Chrome et Edge

1. Dans le ZIP, extraire `chrome-extension/` dans un dossier fixe, par exemple `C:\Users\Hugo\Documents\ml2c-vault-extension`.
2. Chrome : `chrome://extensions` ; Edge : `edge://extensions`. Activer le mode développeur, puis **Charger l'extension non empaquetée** en sélectionnant ce dossier.
3. Épingler ML2C Vault depuis le menu Extensions. Cliquer sur son icône : onglets **Mes accès**, **Générateur** et **Réglages**.
4. Dans **Réglages**, conserver l’adresse `http://127.0.0.1:8001` pour le test local. Pour la production, spécifier l’URL **HTTPS** de votre serveur privé.
5. **Mes accès** ouvre un mini-coffre pour consulter, créer et modifier les fiches. Le générateur fonctionne dans la popup et copie le secret sans le sauvegarder.

**Ce n’est pas une extension Safari** et il n’y a pas encore de remplissage automatique sur les sites tiers. La popup ne lit jamais le contenu des onglets ni les secrets du coffre : ils restent dans la page Symfony déverrouillée. Pour une installation en un clic par les collaborateurs, publier et faire valider l’extension dans un magasin ; aucun site web ne peut installer silencieusement une extension dans Chrome ou Edge.

## Vérifications utiles

- `/login` : connexion directe sans redirection vers `/2fa`.
- `/2fa/send` ou `/2fa/verify` en POST : refus 403 quand 2FA coupée.
- `/mini?action=new` : après déverrouillage, formulaire de nouvel identifiant ouvert.
- Changement d’onglet : la clé de la page déverrouillée est effacée côté navigateur.
- `var/data.db` et les anciennes fiches sont inchangés.

**Sécurité :** prototype non audité, ne pas stocker de véritables mots de passe professionnels avant audit. La désactivation de 2FA diminue la protection de compte. Le presse-papiers reste accessible aux autres applications après copie.
