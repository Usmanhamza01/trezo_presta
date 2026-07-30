# Trezo Cloud — Trésorerie PME synchronisée (Supabase)

Même interface et mêmes fonctionnalités que Trezo Classique, mais : données synchronisées dans le cloud (accessibles depuis tous les appareils du client), sauvegarde automatique, et **vérification des licences côté serveur** — le secret de fabrication des clés n'est plus dans le code de l'application, il est désormais impossible de falsifier une clé ou une date d'expiration.

## Mise en route (une seule fois, ~20 minutes)

### 1. Créer le projet Supabase (gratuit)
- Allez sur https://supabase.com → « New project » (choisissez une région Europe, ex. West EU).
- Notez le mot de passe de base de données demandé (gardez-le précieusement).

### 2. Initialiser la base de données
- Menu gauche → **SQL Editor** → « New query ».
- Ouvrez le fichier `supabase-init.sql` fourni, copiez TOUT son contenu, collez, cliquez **Run**.
- Résultat attendu : « Success. No rows returned ». En cas d'erreur, copiez le message et demandez de l'aide.

### 3. Simplifier la connexion des clients (recommandé)
- Menu **Authentication → Sign In / Providers → Email** : désactivez « Confirm email ».
- Sans cela, chaque client devra cliquer un lien reçu par e-mail avant sa première connexion — source de blocage pour votre clientèle.

### 4. Relier l'application au projet
- Menu **Project Settings → API** (ou Data API) : copiez « Project URL » et la clé « anon public ».
- Ouvrez `config.js` (bloc-notes) et collez ces deux valeurs. La clé anon est conçue pour être publique : aucun risque.

### 5. Déployer
- Glissez-déposez CE dossier sur https://app.netlify.com/drop → vous obtenez l'adresse à donner à tous vos clients.
- (`supabase-init.sql` peut rester dans le dossier ou en être retiré, il ne contient pas le secret sous une forme exploitable côté client, mais par propreté retirez-le avant déploiement.)

## Parcours client

1. Ouvre votre lien → « Créer un compte » (e-mail + mot de passe).
2. Nom de l'entreprise + devise → clé de licence (ou essai 14 jours) → logo + produits.
3. Installe l'app sur son écran d'accueil. Il retrouve ses données sur n'importe quel appareil en se connectant avec son e-mail.

## Licences

- **Trezo Keygen reste votre outil, inchangé** : mêmes clés TRZO, même liaison au nom de l'entreprise, même date d'expiration.
- La validation se fait maintenant sur le serveur (fonction `check_key` du script SQL — c'est là que vit le secret).
- À l'expiration : écriture bloquée côté serveur + écran de renouvellement. Les données restent en sécurité.
- Un client = un compte = une entreprise (v1).

## Migration d'un client Trezo Classique vers le Cloud

Dans son app Classique : Réglages → « Télécharger une sauvegarde (.json) ». Dans Trezo Cloud, après activation : Réglages → « Importer une sauvegarde » → il retrouve tous ses flux, stocks, factures.

## Coûts et limites v1

- Supabase gratuit jusqu'à ~500 Mo / 50 000 utilisateurs actifs par mois (des dizaines de clients), puis ~25 $/mois.
- **Connexion Internet requise** pour utiliser l'app (le hors-ligne synchronisé est l'évolution prévue en phase 3).
- Un même compte ouvert sur deux appareils EN MÊME TEMPS : la dernière sauvegarde gagne ; l'app détecte le conflit et recharge automatiquement (indicateur « ✓ synchronisé » dans l'en-tête).
- Multi-utilisateurs par entreprise : le schéma de base y est prêt (table memberships), l'activation viendra en phase 2.

## IMPORTANT — Premier test

Ce portage a été vérifié par analyse statique mais pas exécuté contre un vrai projet Supabase. Avant toute vente : créez un compte test, activez avec une vraie clé, saisissez des flux, déconnectez-vous, reconnectez-vous depuis un autre appareil et vérifiez que tout est là. Au moindre message d'erreur, transmettez-le tel quel pour correction immédiate.

## v2.5 — Multi-utilisateurs
Exécutez migration-multi-utilisateurs.sql (une fois) dans Supabase pour activer la gestion des collaborateurs et des droits. L'administrateur invite via Réglages → Gestion des utilisateurs ; le collaborateur crée son compte puis entre le code d'invitation.

## v2.8 — Comptes collaborateurs créés par l'admin
Exécutez migration-comptes-collaborateurs.sql (une fois) dans Supabase. L'admin crée directement les comptes (nom, e-mail, mot de passe initial, rôle) dans Réglages → Gestion des utilisateurs ; l'invitation par code reste disponible. Prérequis : « Confirm email » désactivé dans Supabase → Authentication → Providers → Email.
