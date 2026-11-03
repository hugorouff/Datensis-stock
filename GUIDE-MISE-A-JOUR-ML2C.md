# ML2C Vault - Identite visuelle et Centre de securite

Mise a jour du prototype Symfony existant. Ne pas utiliser comme coffre professionnel de production sans tests d'integration et audit cryptographique et applicatif.

## Fonctions ajoutees

- Palette ML2C : blanc `#FFFFFF`, corail `#E96148`, sauge `#82C4A8`, bleu petrole `#00778B` ; interface web, PWA et popup Chrome/Edge.
- Connexion et deverrouillage du coffre en une seule saisie du mot de passe principal lors du login normal (`login-unified.js` et `vault.js`). Aucun secret conserve en localStorage/sessionStorage.
- Ecran **Centre de securite** : indicateur **indicatif** de suivi, analyse des mots de passe faibles/reutilises, liens HTTP, 2FA manquante sur acces critiques, responsables manquants, domaines et rotations. Analyse effectuee dans le navigateur apres ouverture du coffre.
- Revue des acces par responsable et champ de passation dans les fiches chiffre dans leur payload.
- Planification des echeances a J+90 (ne change pas le secret du service externe).
- 4 modeles de creation de fiches pour le cabinet.
- Historique indicatif des modifications de fiche stocke dans le champ chiffre (non certifie et non infalsifiable).
- Affichage des secrets masque automatiquement apres 15 secondes.
- Raccourci vers le Centre de securite depuis la barre d'outils de la page et l'extension navigateur.

## Mettre a jour depuis la version precedente

1. Arreter le serveur PHP et faire une sauvegarde du dossier de projet, surtout `var/data.db` et `.env.local`.
2. Copier le contenu de `ml2c-vault-correctif-identite-securite.zip` a la racine `C:\Users\Hugo\Documents\bitwarden`, en remplacant seulement les fichiers correspondants.
3. Ne jamais supprimer `var/`, `vendor/`, `.env.local` ni `composer.lock`.
4. Executer `php bin/console cache:clear`, puis redemarrer avec `php -S 127.0.0.1:8001 -t public public/router.php`.
5. Aucun changement de schema SQL pour cette version : pas de nouvelle migration.
6. Ouvrir `http://127.0.0.1:8001/login` en navigation privee si deja connecte, sinon se deconnecter puis se reconnecter. Le coffre s'ouvre apres le login, sans nouvelle demande de mot de passe (sauf conversion d'un ancien coffre).

## Cas important : rechargement et verrouillage

Pour ne pas stocker le mot de passe principal ou une cle decryptante dans le stockage du navigateur, le coffre se verrouille apres rechargement de la page, changement d'onglet ou inactivite. Il faut alors ressaisir le meme mot de passe, sans reauthentification serveur automatique. Il est impossible de garantir un deverrouillage persistant sans un autre mecanisme de conservation des cles et un modele de menace adapte.

## Configuration securite

`app.vault_2fa_enabled: false` demeure dans `config/services.yaml` ; le mecanisme Brevo est conserve en code mais desactive. NE PAS utiliser sans 2FA en production. La reactivation demandera une verification complete du parcours.

## Extension Chrome / Edge

Remplacer l'ancien dossier de l'extension (ou charger le nouveau dossier de `ml2c-vault-extension-identite-securite.zip` en mode developpeur). L'extension necessite toujours une installation via magasin d'extensions pour une installation en un clic ; aucun remplissage automatique n'est implemente. Les secrets restent dans le mini-coffre Symfony.
