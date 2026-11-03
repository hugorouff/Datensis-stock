# ML2C Vault — Installation dans les navigateurs

## Le plus simple : installer comme application web

1. Démarrez Symfony (`php -S 127.0.0.1:8001 -t public public/router.php`).
2. Ouvrez `http://127.0.0.1:8001/login` dans Chrome ou Edge et cliquez **Installer ML2C Vault** si le navigateur le propose. Sinon utilisez le menu **Installer cette application**.
3. L'application apparaît avec une icône et dans une fenêtre dédiée. Elle n'est **pas** une extension de la barre d'outils et ne remplit pas les formulaires d'autres sites.
4. Safari sur macOS Sonoma 14 ou ultérieur : ouvrez le site dans Safari, puis **Fichier > Ajouter au Dock**. Cette méthode fournit une web app, **pas** une extension Safari.

## Vraie popup de barre d'outils pour Chrome ET Edge

Pour tester localement l'extension Manifest V3 (ce n'est pas une installation en 1 clic) :

- **Chrome** : `chrome://extensions` > Mode développeur > Charger l'extension non empaquetée > sélectionner le dossier `chrome-extension`.
- **Edge** : `edge://extensions` > Mode développeur > Charger l'extension non empaquetée > sélectionner le **même dossier** `chrome-extension`.
- Épinglez l'icône. Cliquez dessus depuis n'importe quel onglet pour ouvrir la popup et le mini-coffre.
- Le popup ne récupère aucun mot de passe, ne lit aucun onglet et n'effectue aucun auto-remplissage. Les données chiffrées restent dans le coffre Symfony.

Pour un véritable bouton **Ajouter à Chrome / Ajouter à Edge**, l'extension doit être publiée et validée par le Chrome Web Store ou Microsoft Edge Add-ons (ou distribuée par une politique d'entreprise). Une page web n'a pas le droit d'installer silencieusement une extension.

## Safari : étape distincte

Une vraie extension dans la barre Safari nécessite un conteneur application macOS/iOS, packaging via Xcode ou la procédure App Store Connect et distribution appropriée. Le dossier Manifest V3 ne s'installe **pas** automatiquement dans Safari. La web app *Ajouter au Dock* est la voie simple pour l'instant.

## Sécurité

L'app est en développement **local**. L'adresse `127.0.0.1` désigne l'ordinateur **qui exécute le navigateur**. Une extension sur un autre appareil ne peut pas accéder au serveur local de votre PC sans déploiement HTTPS accessible. Conservez la base SQLite actuelle, ne publiez pas les fichiers de secrets et n'utilisez pas de vrais identifiants d'entreprise dans ce prototype non audité.
