# AuditorIA — moteur réel

Remplace les données fictives (`baseAlerts`, `liveAnomalies`, `initCharts`) du frontend par de vraies
extractions IA + un moteur de règles déterministe.

## Déploiement

```bash
npm install -g wrangler
wrangler login

wrangler d1 create auditoria_db
# copier le database_id renvoyé dans wrangler.toml

wrangler r2 bucket create auditoria-documents

wrangler d1 execute auditoria_db --file=schema.sql

wrangler secret put ANTHROPIC_API_KEY
# coller ta clé API Anthropic

wrangler secret put RESEND_API_KEY
# (ou un autre fournisseur d'email — adapte sendResetEmail() dans index.js)
# Ajoute aussi dans wrangler.toml : [vars] APP_URL = "https://tondomaine.com", EMAIL_FROM = "no-reply@tondomaine.com"

wrangler deploy
```

## Isolation des données entre clients

C'est la garantie centrale du système : **aucune requête ne fait confiance à un identifiant envoyé par le
client.** `getUserId(request, env)` lit le cookie de session `httpOnly`, vérifie son hash en base
(`sessions`), et c'est ce `user_id`-là — jamais un autre — qui filtre chaque `SELECT`/`INSERT` sur
`documents`, `invoices`, `findings`, etc. Sans session valide, toute route de données renvoie 401.

Points qui en découlent, à ne pas casser en modifiant le code plus tard :
- Ne jamais réintroduire un `X-User-Id` ou un `user_id` lu depuis le body/query d'une requête publique.
- Les mots de passe sont hashés (PBKDF2 + sel), jamais stockés en clair, jamais renvoyés par l'API.
- Un changement de mot de passe invalide toutes les sessions existantes (`resetPassword` dans `auth.js`).
- Les tokens de réinitialisation sont à usage unique et expirent après 1h.

## Comptes (email + mot de passe, comme demandé)

- `POST /auth/signup` `{email, password}` → crée le compte et connecte directement (cookie de session posé)
- `POST /auth/login` `{email, password}`
- `POST /auth/logout`
- `POST /auth/forgot-password` `{email}` → envoie un lien si le compte existe (répond "ok" dans tous les cas,
  pour ne jamais révéler quels emails sont inscrits)
- `POST /auth/reset-password` `{token, new_password}`

Il te reste à créer les pages `login.html`, `signup.html`, `reset-password.html` côté frontend
(formulaires simples qui appellent ces routes) — dis-moi si tu veux que je les fasse à partir de ta
maquette actuelle.

Tu peux fusionner ce Worker avec ton Worker de paiement existant (`auditoria-pay`) :
mêmes bindings D1/R2, mêmes routes `/create-invoice` et `/status` à côté de celles-ci.

## Ce qui change côté frontend

1. **Authentification réelle requise en premier.** Toutes les routes lisent `X-User-Id` dans les
   en-têtes — aujourd'hui rien ne vérifie qu'un utilisateur est bien celui qu'il prétend être.
   Il faut brancher un vrai système de compte (email + mot de passe hashé, session/JWT) avant
   d'exposer ces routes publiquement, sinon n'importe qui peut lire les données de n'importe qui.

2. **`onUpload()`** doit envoyer le fichier à `/upload` (avec le `kind` du document), puis appeler
   `/extract/:id`, puis `/analyze`, puis rafraîchir via `/findings` — au lieu de choisir une alerte
   au hasard dans `liveAnomalies`.

3. **`renderAlerts()`** doit lire `GET /findings` au lieu du tableau `alerts` codé en dur.

4. **`initCharts()`** : trésorerie et flux doivent être calculés à partir de `bank_transactions`
   réellement stockées (somme des montants par mois), pas des tableaux `[900,980,1050,...]` fixes.
   C'est une prochaine étape (agrégation SQL simple par mois) une fois les relevés bancaires
   alimentés — dis-moi quand tu veux que je m'en occupe.

## Ce qui est réel dès maintenant

- Extraction : Claude lit chaque PDF/CSV et renvoie des champs factuels (montants, IBAN, dates,
  numéros de facture/BC), jamais un jugement — c'est le moteur de règles qui compare.
- Détection : 4 règles déterministes et vérifiables (`src/rules.js`) —
  écart facture/BC, doublon de paiement, échéance de contrat, sortie vers IBAN inconnu.
  Chaque alerte pointe vers les documents source (`related_document_ids`) pour audit.

## Frontend mis à jour (`app.html`)

`app.html` remplace ton `index.html` : mêmes styles et mise en page, mais :
- Connexion, inscription et mot de passe oublié appellent réellement `/auth/login`,
  `/auth/signup`, `/auth/forgot-password` (cookie de session `httpOnly`, jamais de mot de passe
  pré-rempli).
- `onUpload()` envoie le vrai fichier à `/upload` → `/extract/:id` → `/analyze`, puis rafraîchit
  les alertes et les statistiques. Il n'y a plus d'anomalie choisie au hasard.
- Un sélecteur de type de document (facture / bon de commande / contrat / relevé bancaire CSV)
  précède la zone de dépôt — plus de fichier envoyé par défaut comme "contrat" quel que soit son
  contenu réel.
- Les alertes affichées viennent de `GET /findings` ; si le moteur n'a rien détecté, le tableau
  de bord affiche "Aucune anomalie détectée" au lieu de données fictives.
- Les cartes de stats et les 3 graphiques (trésorerie, économies, flux) viennent de `GET /summary`,
  calculé en SQL à partir des vraies transactions et alertes — plus aucun chiffre codé en dur.
- `API_BASE` en haut du script (const) : laisse `""` si le Worker est sur le même domaine que le
  site, sinon mets l'URL complète du Worker déployé.
- Corrigé au passage : un bug préexistant dans `goToNowPayments()` (regex mal échappées)
  empêchait de construire correctement l'URL de retour après paiement.

Renomme `app.html` en `index.html` une fois vérifié, à la place de l'ancien.

## Définitions honnêtes des métriques (`src/summary.js`)

Pour ne jamais réafficher un chiffre inventé sous une étiquette qui suggère autre chose :
- **Trésorerie** = flux net cumulé depuis le premier relevé bancaire importé (somme de toutes
  les transactions). Ce n'est PAS un solde bancaire en direct tant qu'aucune connexion Open
  Banking n'est branchée — à clarifier auprès du client si le mot "trésorerie" doit rester tel quel.
- **Économies réalisées** = montant total des écarts facture/BC et doublons de paiement détectés
  (`invoice_po_mismatch`, `duplicate_payment`). C'est l'argent que l'audit a permis de repérer,
  pas une confirmation que la somme a été effectivement récupérée ou évitée.
- **Flux entrants/sortants** = sommes réelles du mois en cours sur `bank_transactions`.

## Paiements NOWPayments — fusionnés depuis ton Worker existant

Ton Worker `auditoria-pay` est maintenant intégré (`src/payments.js` + routes dans `src/index.js`) :
`/create-invoice`, `/ipn`, `/status`, `/subscription`. Il faut donc **déployer un seul Worker**
désormais (celui-ci), pas deux séparés — sinon les sessions/comptes et les paiements ne
partageraient pas la même base D1.

Secrets supplémentaires à configurer :
```bash
wrangler secret put NOWPAYMENTS_API_KEY
wrangler secret put IPN_SECRET
```
Et dans NOWPayments, configure l'URL d'IPN sur `https://tondomaine/ipn` (ou laisse le worker la
définir automatiquement via `ipn_callback_url`, déjà géré dans `createInvoice`).

### Faille corrigée : l'abonnement était activable sans payer

Deux problèmes dans le code d'origine permettaient de débloquer un abonnement complet
gratuitement :
1. Le statut d'abonnement (`getSub()`/`isPaidActive()`) était lu depuis `localStorage` — modifiable
   depuis la console du navigateur par n'importe quel client.
2. `activated.html` **activait l'abonnement même sans `order_id` dans l'URL, ou si la requête de
   vérification échouait** (`catch(e){activate(plan)}`) — il suffisait d'ouvrir cette page
   directement pour s'auto-activer.

Ce qui a changé :
- Le statut d'abonnement vit uniquement en D1 (table `subscriptions`), lu via `GET /subscription`.
  Le client ne peut plus rien modifier lui-même.
- `/ipn` vérifie la signature HMAC-SHA512 envoyée par NOWPayments (`x-nowpayments-sig`) avant
  d'activer quoi que ce soit — sans signature valide, la requête est rejetée.
- Chaque facture (`/create-invoice`) est créée pour un `user_id` authentifié et enregistrée dans
  la table `orders` ; `/ipn` ne peut activer que le compte lié à cette commande précise.
- `activated.html` ne fait plus qu'afficher le statut lu sur `/status` — il n'y a plus aucun
  chemin dans son code qui active un abonnement lui-même. Sans `order_id` valide et payé en base,
  il affiche une erreur, jamais une activation.
- La limite de 2 analyses gratuites est vérifiée dans `/upload` côté serveur
  (`consumeAnalysisCredit`), qui renvoie 402 une fois épuisée — plus un contournement possible
  en modifiant le navigateur.
- Sur la page publique, cliquer "S'abonner" sans compte ouvre désormais l'inscription d'abord (la
  facture doit être liée à un compte réel) ; une fois connecté, le paiement reprend automatiquement.

## Mode démo automatique (15 minutes)

Fini la demande de démo par email : dès l'inscription, le compte a un accès complet et illimité
pendant 15 minutes (calculées côté serveur depuis `users.created_at`, jamais depuis le navigateur).
`GET /subscription` renvoie `plan:"demo"` et `demo_ends_at` pendant cette fenêtre ; `/upload` ne
consomme aucun crédit gratuit tant que le mode démo est actif. Le bandeau du dashboard affiche un
vrai compte à rebours (mm:ss) et bascule automatiquement vers le plan gratuit (2 analyses) une fois
les 15 minutes écoulées. Les anciens boutons "Book a demo" ouvrent maintenant directement
l'inscription.

## Ce qui reste ouvert

- Import CSV bancaire multi-formats (chaque banque a son propre format d'export — aujourd'hui le
  CSV est envoyé tel quel à Claude pour extraction, ce qui marche mais reste à valider sur de
  vrais relevés)
- Connexion Open Banking (Bridge, Powens...) si tu veux une vraie trésorerie en direct plutôt que
  le flux cumulé décrit ci-dessus
- Seuils de règles configurables par utilisateur (aujourd'hui en dur : 3%, 5000€, 30 jours...)
- Pages `login.html` / `signup.html` autonomes si tu préfères des pages dédiées aux modales actuelles
