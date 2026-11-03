# ML2C Vault — la popup dans la barre d’outils (pas la PWA)

La PWA installée depuis « Installer ML2C Vault » est une application indépendante. Elle ne peut pas devenir une extension par simple réglage.

## Désinstaller la PWA si elle est déjà installée

- Chrome : `chrome://apps`, clic droit sur ML2C Vault > Supprimer de Chrome (selon la version, via les paramètres de l’application).
- Edge : `edge://apps`, ML2C Vault > Désinstaller.
- Cela ne supprime pas la base Symfony SQLite : ne touchez pas à `var/data.db`.

## Installer la vraie extension

1. Extrayez `ml2c-vault-extension-popup.zip` dans un dossier stable ; le dossier sélectionné doit contenir **manifest.json** directement.
2. Chrome : `chrome://extensions`, activer **Mode développeur**, puis **Charger l’extension non empaquetée**.
3. Edge : `edge://extensions`, activer **Mode développeur**, puis **Charger l’extension non empaquetée**.
4. Sélectionner **chrome-extension** et épingler ML2C Vault via l’icône en forme de puzzle.
5. Cliquez sur l’icône ML2C Vault dans la barre du navigateur : la **popup ancrée à l’icône** apparaît avec les onglets Mes accès, Générateur et Réglages.

IMPORTANT : l’onglet Générateur fonctionne entièrement dans cette popup. Les éléments du coffre sont gérés sur le site Symfony dans un onglet séparé et sécurisé ; l’extension ne déchiffre pas encore les secrets elle-même et ne remplit pas automatiquement les autres sites. Aucun secret du coffre n’est copié dans l’extension.

## Serveur

Démarrer Symfony : `php -S 127.0.0.1:8001 -t public public/router.php`. Dans la popup, sous Réglages, configurez `http://127.0.0.1:8001`. Pour un serveur distant, HTTPS est obligatoire.

## Distribution

Une installation « Ajouter à Chrome » ou « Obtenir sur Edge » sans le mode développeur nécessite la publication sur Chrome Web Store ou Edge Add-ons. L’équivalent Safari nécessite un packaging propre à Apple.

## Sécurité

Ceci reste un prototype non audité. La double authentification reste désactivée conformément au choix de développement. Ne l’utilisez pas pour des identifiants réels d’entreprise.
