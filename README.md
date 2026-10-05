# AuditorIA — moteur réel

Un seul Worker Cloudflare (`auditoria-pay`) qui sert le site (`public/`), l'API (comptes, upload, extraction IA,
règles de détection, résumé) et les paiements NOWPayments, avec une base D1.

## Structure du projet

```
wrangler.toml      config (main = "index.js", assets = ./public, base D1)
index.js           routes HTTP
auth.js            comptes, sessions, mot de passe oublié
payments.js        NOWPayments, abonnement, quota d'essais gratuits
extraction.js      extraction via OpenRouter (PDF/CSV → champs structurés)
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
wrangler secret put OPENROUTER_API_KEY # openrouter.ai — accepte la carte, mais aussi la crypto (utile si ta banque ne propose que des cartes prépayées, refusées par Google/OpenAI en direct)
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
| `GET /contracts` | contrats réellement importés (page Contracts du dashboard) |
| `POST /auth/verify-email`, `POST /auth/resend-verification` | confirmation de l'email par code à 6 chiffres |
| `POST /kyc/submit`, `GET /kyc/status` | profil KYC : justificatif de domicile (soumission manuelle, revue humaine) |
| `POST /kyc/didit/start` | crée une session de vérification d'identité Didit, renvoie son URL |
| `POST /kyc/didit/webhook` | reçoit la décision de Didit (authentifié par signature, pas par session) |
| `GET /me` | email du compte connecté (menu du dashboard) |
| `POST /account/change-password` | changement de mot de passe (page Paramètres, session active requise) |
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
- **Changement d'IBAN fournisseur** : l'IBAN d'une facture diffère de celui de la facture précédente du même fournisseur
  (regroupement par nom, insensible à la casse/espaces). Signal classique de fraude au changement de coordonnées bancaires.
- **Facture en double** : même fournisseur, même numéro de facture sur deux documents distincts — détecté dès l'import,
  avant même qu'un paiement n'ait lieu. Différent du « paiement en double » ci-dessus (qui regarde les transactions bancaires).
- **Fractionnement de factures** (« structuring ») : au moins 2 factures du même fournisseur, le même jour, chacune sous
  5 000 € (`checkInvoiceSplitting`, seuil ajustable), dont la somme dépasse ce seuil — technique classique pour contourner
  un plafond d'approbation interne.
- **Montant inhabituel pour un bénéficiaire connu** : une sortie vers un IBAN *déjà vu* plus de 3× supérieure (seuil
  ajustable) à la moyenne historique de ce bénéficiaire (minimum 3 transactions antérieures). Complète la règle de l'IBAN
  inconnu, qui ne couvre pas le cas d'un bénéficiaire habituel dont le montant devient brusquement anormal. Limite connue :
  la moyenne inclut la transaction elle-même (pas de fenêtre l'excluant), ce qui amortit un peu le signal — accepté en
  échange d'une seule requête SQL, sans explosion du nombre de lectures.

Chaque constat a une empreinte (`findings.fingerprint`, index unique) : relancer `/analyze` ne crée jamais de doublon, et une
alerte ignorée ne revient pas.

Ce sont des règles **réellement distinctes**, pas des centaines de variantes d'un même contrôle : un outil d'audit sérieux
tourne généralement autour de ce même ordre de grandeur (15-30 contrôles distincts), pas des centaines.

## Email d'alerte

Après chaque `/analyze` qui crée au moins un nouveau constat, un email est envoyé à l'adresse du compte, dans sa langue
préférée (`users.lang`, `fr` ou `en`, mise à jour automatiquement par `POST /account/lang` à chaque changement de langue
dans l'interface). Il liste les anomalies **nouvellement créées par cette analyse précise** (pas le total des alertes
ouvertes), avec le même mécanisme d'envoi que la confirmation d'email et la réinitialisation de mot de passe (Brevo, sinon
Resend, sinon juste journalisé en développement). Sans clé email configurée, l'alerte n'est donc visible que dans les
logs du Worker, jamais perdue pour autant côté dashboard.

**Ce qui n'existe toujours pas** : SMS, notification push, ou email récapitulatif périodique (quotidien/hebdomadaire) pour
les alertes non critiques qu'un client n'aurait pas encore consultées.

## Métriques du dashboard (`summary.js`)

- **Trésorerie** = flux net cumulé depuis le premier relevé importé, pas un solde bancaire en direct.
- **Économies** = doublons de paiement + **surfacturations** facture/BC détectés (une facture inférieure au BC n'est pas
  une économie). Les alertes ignorées sont exclues. C'est de l'argent repéré, pas récupéré. « Économies (année) » cumule
  depuis le 1er janvier.
- **Flux entrants/sortants** = sommes réelles du mois en cours.

## Un seul point de dépôt, analyse automatique

Tout le dépôt de documents passe par la page **Import** du menu (nouvelle entrée dédiée) : l'ancienne
zone d'upload décorative du Dashboard et celle dupliquée sur la page Contracts ont été retirées. Le
Dashboard pointe maintenant vers cette page unique via un bouton, et Contracts n'affiche plus que les
vrais contrats importés. L'analyse (extraction + règles) démarrait déjà automatiquement après l'upload
avant ce changement ; ça n'a pas changé, c'était juste réparti sur deux écrans.

## Abonnement mensuel ou annuel

Les deux plans proposent maintenant un choix **mensuel (30 jours) ou annuel (360 jours)**, sur la page de
tarifs comme dans la fenêtre de paiement. Le tarif annuel vaut **10 fois le prix mensuel** (2 mois
offerts, ~17% de remise) — une hypothèse de départ, pas un chiffre qui t'a été demandé : change
`PLANS.starter.annual.price` et `PLANS.growth.annual.price` dans `payments.js` si tu veux un autre tarif.
Le cycle choisi est mémorisé sur la commande (`orders.cycle`) et c'est lui qui détermine la durée
créditée par `handleIpn`, jamais une valeur envoyée par le navigateur.

Le plafond de 50 documents de Starter continue de se renouveler **tous les 30 jours**, qu'il soit facturé
au mois ou à l'année (`plan_quota_reset_at`, recalculé à la lecture) : un Starter annuel n'a pas un seul
quota pour toute l'année, mais bien un quota qui repart à 0 toutes les 30 jours comme en mensuel.

## Confirmation d'email à l'inscription

Un code à 6 chiffres (valable 15 minutes, 8 tentatives maximum) est envoyé à l'inscription, via le même
mécanisme d'email que la réinitialisation de mot de passe (Brevo, sinon Resend, sinon juste journalisé en
développement — voir plus bas). Tant que l'email n'est pas confirmé, le compte reste utilisable (connexion,
consultation) mais **`POST /upload` est bloqué** (403 `email_not_verified`) : pas d'analyse de documents,
donc pas de coût OpenRouter ni de crédit consommé, sans confirmation préalable. Un bandeau dans le dashboard
permet d'entrer le code ou d'en redemander un.

## 1 compte par adresse IP

Un index unique en base (`idx_users_signup_ip`) empêche la création d'un deuxième compte depuis la même
IP, pour de bon (pas seulement "par jour"). **Point d'attention réel** : plusieurs personnes derrière la
même IP (bureau, Wi-Fi public, bien des connexions mobiles en dehors des US via le CGNAT, VPN) ne pourront
créer qu'un seul compte à elles toutes, et un VPN ou un Wi-Fi public déjà utilisé une fois par quelqu'un
d'autre peut bloquer un vrai client plus tard. C'est ce qui a été demandé, mais c'est plus strict que la
plupart des sites (qui se contentent d'une limite par jour, déjà en place par ailleurs : 5 inscriptions/jour
et par IP) — à surveiller si des clients légitimes se plaignent de ne pas pouvoir s'inscrire.

## Profil KYC

La page **Profil** du menu a deux sections indépendantes :

### Identité (automatisée, via Didit — gratuit)

Le bouton « Vérifier mon identité » crée une session Didit côté serveur (`POST /kyc/didit/start`) et
redirige le client vers l'interface hébergée par Didit, qui vérifie réellement le document (OCR),
la vivacité (liveness) et la correspondance du visage. Didit renvoie sa décision via webhook
(`POST /kyc/didit/webhook`), authentifié par signature HMAC-SHA256 (`X-Signature-V2`, vérifiée avec
une fenêtre de fraîcheur de 5 minutes, voir `kyc_didit.js`) — **jamais par cookie de session**, exactement
comme `/ipn` pour les paiements. `identity_status` (`not_started | pending | approved | rejected`) est mis à
jour automatiquement par ce webhook, jamais par le navigateur du client ni par la redirection de retour
(qui ne sert qu'à ramener le client sur la page, pas de preuve d'approbation).

Secrets à configurer :
```bash
wrangler secret put DIDIT_API_KEY
wrangler secret put DIDIT_WEBHOOK_SECRET
```
`DIDIT_WEBHOOK_SECRET` s'obtient en enregistrant la destination du webhook (une seule fois) :
```bash
curl -X POST https://verification.didit.me/v3/webhook/destinations/ \
  -H "x-api-key: TA_CLE_API_DIDIT" -H "Content-Type: application/json" \
  -d '{"label":"AuditorIA","url":"https://TON-DOMAINE/kyc/didit/webhook","webhook_version":"v3","subscribed_events":["status.updated"]}'
```
La réponse contient `secret_shared_key` : c'est la valeur à passer à `wrangler secret put DIDIT_WEBHOOK_SECRET`.

Le workflow utilisé (`DIDIT_WORKFLOW_ID` dans `kyc_didit.js`) est celui fourni par Didit, nommé « Free
KYC » : pièce d'identité + détection de vivacité passive + comparaison de visage + analyse d'IP, couvert
par les 500 vérifications gratuites par mois. Ce n'est pas un secret, il peut rester en dur dans le code.

### Justificatif de domicile (manuel, gratuit)

Resté tel quel : le client envoie un document (PDF, JPG, PNG), stocké en attente (`status = pending`), et
un humain doit l'examiner pour le faire passer à `approved` ou `rejected` directement en base (pas d'écran
d'administration) :
```sql
UPDATE kyc_profiles SET status = 'approved', reviewed_at = unixepoch() * 1000 WHERE user_id = '...';
```
La vérification de justificatif de domicile automatisée existe chez Didit (`PROOF_OF_ADDRESS`), mais n'est
pas incluse dans le pack gratuit (~0,20 $/vérification) — elle n'a donc pas été branchée, pour rester à 0 $.

**À savoir avant d'ouvrir ça à de vrais clients** : le justificatif de domicile reste stocké en base en
base64, protégé par les sessions et les requêtes préparées comme le reste de l'app, mais sans chiffrement
dédié. Une politique de rétention/suppression et, selon où sont tes clients, des obligations légales (RGPD
ou équivalent) restent à prévoir pour ces deux volets — Didit héberge et traite les données d'identité de
son côté selon sa propre politique, à vérifier sur docs.didit.me.

## Détection automatique du type de document

Le menu de dépôt propose « Détection automatique (recommandé) », réglage par défaut, en plus des quatre types
explicites. Elle permet un envoi groupé de fichiers de types différents sans avoir à les trier : qu'il s'agisse
d'un PDF ou d'un CSV, le document est d'abord soumis à un petit appel de classification (facture / bon de
commande / contrat / relevé), puis à l'extraction normale avec le schéma correspondant — un CSV n'est **pas**
présumé être un relevé bancaire du seul fait de son extension (un export de factures au format CSV, par
exemple, est classifié comme tel).

Chaque document en mode automatique consomme donc un appel de plus que ci-dessus (extraction classique), PDF
comme CSV. Le type détecté est enregistré sur le document (`documents.kind`) : il reste consultable et n'est
jamais redéterminé aux extractions suivantes.

## Service d'extraction (OpenRouter)

L'extraction et la classification des documents passent par **OpenRouter** (`extraction.js`), une passerelle
vers de nombreux modèles (OpenAI, Anthropic, Google...) avec un seul compte et un seul paiement — choisie
après que Google **et** OpenAI ont refusé la carte prépayée utilisée pour ce projet (les deux l'interdisent
explicitement en direct). OpenRouter, lui, accepte aussi la crypto et Alipay, en plus des cartes classiques.

- **Secret à configurer** : `wrangler secret put OPENROUTER_API_KEY` (clé générée sur openrouter.ai/keys).
  Il n'y a **pas de palier gratuit** sur OpenRouter : il faut créditer le compte au préalable (openrouter.ai/credits),
  même une petite somme suffit largement au vu du coût par document (voir plus bas).
- **Modèle utilisé** : `google/gemini-3.8-flash`, fixé dans `extraction.js` (`OPENROUTER_MODEL`). OpenRouter
  bascule automatiquement sur un autre fournisseur de ce même modèle (Google Vertex / Google AI Studio) si
  l'un des deux est en panne — un filet de sécurité contre les 429/503 qu'on n'avait pas avec Gemini en direct.
  Pour changer de modèle, parcours openrouter.ai/models et remplace cette seule constante.
- **Coût réel** : pour ce modèle, environ 0,003 à 0,005 $ par document (estimation grossière selon la longueur
  du fichier), deux fois plus en détection automatique (classification + extraction), PDF comme CSV. OpenRouter
  prend une petite commission au moment où tu achètes des crédits (pas de marge sur le prix du modèle lui-même).
- **Pas de sortie structurée stricte** : volontairement, par prudence — un paramètre spécifique à un modèle qui
  casse au moindre changement de modèle est exactement ce qui s'est produit lors d'un précédent changement de
  modèle Gemini. À la place, le schéma attendu est inclus en texte dans la consigne envoyée au modèle, avec
  `response_format: json_object` (juste "réponds en JSON valide", supporté par la quasi-totalité des modèles) et
  un nettoyage des éventuelles balises markdown avant de parser — moins strict, mais beaucoup plus portable.

## Plans payants : plafond mensuel

- **Starter (2 000 $/mois) : 50 documents par mois.** Au-delà, l'upload répond `402 plan_limit_reached` et le
  bandeau propose de passer à Growth (au lieu du message et du plan proposés quand c'est le quota gratuit qui est
  épuisé — les deux cas sont distincts, y compris dans le message affiché).
- **Growth (5 000 $/mois) : illimité.**
- Le "mois" est le **cycle de facturation de 30 jours**, pas le mois calendaire : le compteur repart à 0 à chaque
  paiement crédité (première activation ou renouvellement), qu'il coïncide ou non avec le 1er du mois.
- Comme pour le quota gratuit, le décompte est atomique (aucun dépassement possible par deux requêtes simultanées)
  et remboursé si l'extraction échoue ensuite.
- Pour changer la limite de Starter ou plafonner Growth, modifie `PLAN_LIMITS` dans `payments.js`. Un plan absent de
  cet objet est illimité.

## Abonnement : durée et expiration

Chaque activation ou renouvellement ajoute exactement **30 jours** (`PLAN_DURATION_MS`) à partir du paiement crédité
— ou à partir de la date d'expiration en cours si le renouvellement arrive avant qu'elle ne soit dépassée (les jours
restants ne sont jamais perdus). `GET /subscription` renvoie `expires_at` ; passé cette date, le plan repasse
automatiquement à `expired` puis à `free` dès la prochaine vérification, sans tâche planifiée nécessaire (le calcul
se fait à la lecture, pas par un job qui tournerait en arrière-plan).

## Paiements NOWPayments

- Le statut d'abonnement vit uniquement en D1, lu via `GET /subscription`.
- `/ipn` vérifie la signature HMAC-SHA512, n'active que les statuts `finished` / `confirmed`, contrôle que le montant payé
  couvre le prix du plan, et est **idempotent** (un IPN rejoué ne prolonge rien). Un paiement partiel n'active rien.
- Un renouvellement du même plan avant expiration ajoute 30 jours à ce qui reste.
- Une panne passagère renvoie 500 à NOWPayments, qui réessaie ; seule une signature invalide renvoie 401.
- `success_url` est limité à ton domaine (`APP_URL`).
- Quota gratuit : **5 documents par compte** (tous types confondus, sans limite de durée), décomptés de façon atomique à
  l'upload **après** validation du fichier, et remboursés si l'extraction échoue. Il n'y a plus de mode démo chronométré :
  la valeur se voit sur les vrais documents du client, et le plafond fixe limite les appels à l'IA par compte.
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
- **Service d'analyse (OpenRouter)** : une 429/503 du modèle devient « service saturé, réessaie » et l'essai est
  remboursé automatiquement. Le crédit OpenRouter est une vraie consommation payante (pas de palier gratuit) : surveille
  le solde sur openrouter.ai/settings/credits, surtout avec la détection automatique qui double le nombre d'appels par PDF.
- **Limitation de débit** : login (10 essais/15 min par email, 30 par IP), inscription (5/jour par IP), mot de passe oublié,
  reset, upload, analyse. Contrepartie connue : quelqu'un peut ralentir la connexion d'un email en le martelant.
- **Pas de vérification d'email** à l'inscription : la limite par IP (5 comptes/jour) freine les comptes jetables, sans les empêcher. Pire cas : 25 documents gratuits par jour et par connexion.
- Les erreurs internes (SQL, OpenRouter, config) sont écrites dans les logs du Worker (`[observability]` activé) et jamais
  renvoyées au navigateur.
- Le front échappe tout le texte issu de documents avant de l'afficher (un PDF piégé ne peut plus injecter de HTML).

## Pistes non faites

- R2 pour les gros fichiers ; vérification d'email ; bouton « faire confiance à cet IBAN » qui alimente
  `known_counterparties` ; cron quotidien pour les échéances de contrat ; règle `invoice_drift` (prévue dans le schéma,
  jamais implémentée).
- Adresse de support (`SUPPORT_EMAIL` dans `public/index.html`) : actuellement une adresse Gmail personnelle,
  à remplacer par une adresse sur le domaine du site pour un rendu plus professionnel.
