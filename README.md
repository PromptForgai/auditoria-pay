# AuditorIA — moteur réel

Un seul Worker Cloudflare (`auditoria-pay`) qui sert le site (`public/`), l'API (comptes, upload, extraction IA,
règles de détection, résumé) et les paiements NOWPayments, avec une base D1.

## Structure du projet

```
wrangler.toml      config (main = "index.js", assets = ./public, base D1)
index.js           routes HTTP
auth.js            comptes, sessions, mot de passe oublié
payments.js        NOWPayments, abonnement, quota d'essais gratuits
extraction.js      extraction Gemini (PDF/CSV → champs structurés)
rules.js           moteur de règles déterministe
summary.js         chiffres du dashboard
errors.js          HttpError (erreurs montrables au client)
ratelimit.js       limiteur de débit en D1
schema.sql         schéma complet (base neuve)
migration.sql      mise à jour d'une base déjà déployée
public/
  index.html       site + dashboard (bouton Support = chat tawk.to)
  activated.html   page de retour de paiement
```

Tous les fichiers `.js` sont à la racine, à côté de `wrangler.toml`. Les anciens `app.html` et `index-1.html` ne servent plus.

## Déploiement

Base **déjà déployée** (ton cas) :

```bash
wrangler d1 execute auditoria_db --remote --file=migration.sql   # une seule fois
wrangler deploy
```

Base **neuve** :

```bash
wrangler d1 create auditoria_db        # puis copier le database_id dans wrangler.toml
wrangler d1 execute auditoria_db --remote --file=schema.sql
wrangler secret put GEMINI_API_KEY     # gratuit, sans carte : aistudio.google.com → Get API key
wrangler secret put NOWPAYMENTS_API_KEY
wrangler secret put IPN_SECRET
# email de réinitialisation (optionnel) : BREVO_API_KEY + EMAIL_SENDER, ou RESEND_API_KEY + EMAIL_FROM
wrangler deploy
```

**`--remote` est indispensable** : sans lui, wrangler modifie une base locale de test et la vraie reste inchangée.
Il n'y a pas de bucket R2 à créer (les fichiers sont stockés en D1, voir plus bas).

## Isolation des données entre clients

Aucune requête ne fait confiance à un identifiant envoyé par le client. `getUserId()` lit le cookie de session
`httpOnly`, vérifie son hash en base, et c'est ce `user_id` qui filtre chaque `SELECT`/`INSERT`. Sans session valide,
toute route de données renvoie 401. À ne pas casser plus tard :
- ne jamais lire un `user_id` depuis le body, la query ou un en-tête d'une requête publique ;
- mots de passe en PBKDF2 + sel, jamais stockés ni renvoyés ; un changement de mot de passe ferme toutes les sessions ;
- jetons de réinitialisation à usage unique (consommés atomiquement), valables 1 h, un seul actif par compte.

## Routes

| Route | Rôle |
|---|---|
| `POST /auth/signup`, `/auth/login`, `/auth/logout` | comptes |
| `POST /auth/forgot-password`, `/auth/reset-password` | mot de passe oublié (répond « ok » que le compte existe ou non) |
| `POST /create-invoice`, `POST /ipn`, `GET /status`, `GET /subscription` | paiements et abonnement |
| `POST /upload` → `POST /extract/:id` → `POST /analyze` | dépôt, extraction IA, règles |
| `GET /findings`, `POST /findings/:id/status` | alertes ; `status` = `reviewed` ou `dismissed` |
| `GET /summary` | trésorerie, économies, flux |

## Règles de détection (`rules.js`)

- **Écart facture / bon de commande** : facture et BC reliés par le numéro de BC, seuil 3 %, mêmes devises uniquement.
- **Paiement en double** : même bénéficiaire, même montant, moins de 5 jours d'écart.
- **Contrat à échéance** : moins de 30 jours.
- **Sortie vers un IBAN inconnu** : sortie ≥ 5 000 € vers un IBAN qui ne figure ni sur une facture importée, ni dans
  `known_counterparties`, ni dans une transaction plus ancienne. Seule la **première** apparition d'un IBAN est signalée.
  Au premier import, tout gros virement vers un fournisseur sans facture correspondante sera donc signalé : c'est voulu,
  l'utilisateur les passe en « Ignorer » ou importe les factures.

Chaque constat a une empreinte (`findings.fingerprint`, index unique) : relancer `/analyze` ne crée jamais de doublon, et une
alerte ignorée ne revient pas.

## Métriques du dashboard (`summary.js`)

- **Trésorerie** = flux net cumulé depuis le premier relevé importé, pas un solde bancaire en direct.
- **Économies** = doublons de paiement + **surfacturations** facture/BC détectés (une facture inférieure au BC n'est pas
  une économie). Les alertes ignorées sont exclues. C'est de l'argent repéré, pas récupéré. « Économies (année) » cumule
  depuis le 1er janvier.
- **Flux entrants/sortants** = sommes réelles du mois en cours.

## Paiements NOWPayments

- Le statut d'abonnement vit uniquement en D1, lu via `GET /subscription`.
- `/ipn` vérifie la signature HMAC-SHA512, n'active que les statuts `finished` / `confirmed`, contrôle que le montant payé
  couvre le prix du plan, et est **idempotent** (un IPN rejoué ne prolonge rien). Un paiement partiel n'active rien.
- Un renouvellement du même plan avant expiration ajoute 30 jours à ce qui reste.
- Une panne passagère renvoie 500 à NOWPayments, qui réessaie ; seule une signature invalide renvoie 401.
- `success_url` est limité à ton domaine (`APP_URL`).
- Quota gratuit : **5 documents par compte** (tous types confondus, sans limite de durée), décomptés de façon atomique à
  l'upload **après** validation du fichier, et remboursés si l'extraction échoue. Il n'y a plus de mode démo chronométré :
  la valeur se voit sur les vrais documents du client, et le plafond fixe limite les appels Gemini par compte.
  Pour changer le nombre, modifie `FREE_LIMIT` dans `payments.js` **et** dans `public/index.html` (deux endroits).

## Support (chat en ligne tawk.to)

Le bouton **Support** (barre de navigation, pied de page, menu du dashboard) charge le chat au clic.
1. Crée un compte sur tawk.to, puis **Administration → Chat Widget → Direct Chat Link** : le lien ressemble à
   `https://tawk.to/chat/PROPERTY_ID/WIDGET_ID`.
2. Dans `public/index.html`, renseigne `TAWK_PROPERTY_ID` et `TAWK_WIDGET_ID` (en haut du script, section « Support »).
3. Tant que ces deux valeurs sont vides, « Support » ouvre simplement un email vers `SUPPORT_EMAIL`.

Le script tiers n'est chargé qu'au clic (pas à chaque visite), car la page affiche des données financières. Le site étant une
seule page, une fois le chat ouvert le script reste actif jusqu'au rechargement, y compris après connexion. Configure aussi
dans tawk.to un message hors-ligne qui collecte l'email du client. Aucune donnée du compte (email, documents) n'est transmise
automatiquement à tawk.to.

## Limites et sécurité

- **Taille de fichier : 1,4 Mo maximum.** D1 refuse une ligne de plus de 2 Mo et le base64 gonfle d'un tiers. Au-delà,
  il faut R2 (qui exige une carte bancaire ou PayPal chez Cloudflare).
- **Relevés : 1 000 lignes maximum par fichier**, et un fichier trop long est refusé avec un message clair (avant, il était
  tronqué en silence). Le même fichier ne peut pas être importé deux fois (SHA-256), ce qui évite de doubler les transactions.
- **Gemini gratuit** : limité en débit (une 429 devient un « service saturé, réessaie » et l'essai est remboursé) et les
  données du tier gratuit peuvent servir à améliorer les modèles de Google : à dire à tes clients.
- **Limitation de débit** : login (10 essais/15 min par email, 30 par IP), inscription (5/jour par IP), mot de passe oublié,
  reset, upload, analyse. Contrepartie connue : quelqu'un peut ralentir la connexion d'un email en le martelant.
- **Pas de vérification d'email** à l'inscription : la limite par IP (5 comptes/jour) freine les comptes jetables, sans les empêcher. Pire cas : 25 documents gratuits par jour et par connexion.
- Les erreurs internes (SQL, Gemini, config) sont écrites dans les logs du Worker (`[observability]` activé) et jamais
  renvoyées au navigateur.
- Le front échappe tout le texte issu de documents avant de l'afficher (un PDF piégé ne peut plus injecter de HTML).

## Pistes non faites

- R2 pour les gros fichiers ; vérification d'email ; bouton « faire confiance à cet IBAN » qui alimente
  `known_counterparties` ; cron quotidien pour les échéances de contrat ; règle `invoice_drift` (prévue dans le schéma,
  jamais implémentée).
