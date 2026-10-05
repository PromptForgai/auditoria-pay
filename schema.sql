-- AuditorIA — schéma D1 (moteur réel)
-- Nouvelle base :   wrangler d1 execute auditoria_db --remote --file=schema.sql
-- Base existante :  wrangler d1 execute auditoria_db --remote --file=migration.sql   (voir migration.sql)
-- Sans --remote, wrangler agit sur une base LOCALE de test, pas sur celle de Cloudflare.

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,              -- uuid
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,               -- 'invoice' | 'purchase_order' | 'contract' | 'bank_statement'
  content_base64 TEXT NOT NULL,     -- contenu brut du fichier, encodé en base64, stocké directement en D1
                                     -- (pas de R2 pour l'instant : R2 exige carte bancaire/PayPal, D1 non)
  filename TEXT,
  status TEXT NOT NULL DEFAULT 'uploaded', -- uploaded | extracting | extracted (un document dont l'extraction échoue est supprimé)
  uploaded_at INTEGER NOT NULL,
  extracted_at INTEGER,
  credit_used INTEGER NOT NULL DEFAULT 0,  -- 1 si cet envoi a consommé un essai gratuit (pour le rembourser en cas d'échec)
  content_hash TEXT                         -- SHA-256 du fichier : empêche d'importer deux fois le même document
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_hash ON documents(user_id, content_hash);

CREATE TABLE IF NOT EXISTS extractions (
  document_id TEXT PRIMARY KEY REFERENCES documents(id),
  kind TEXT NOT NULL,
  data_json TEXT NOT NULL,          -- JSON brut renvoyé par le modèle (champs ci-dessous, normalisés)
  confidence REAL,                  -- 0..1, auto-évalué par le modèle
  raw_text_excerpt TEXT             -- pour audit humain / debug
);

-- Vues normalisées, remplies à partir de extractions.data_json au moment de l'extraction
CREATE TABLE IF NOT EXISTS invoices (
  document_id TEXT PRIMARY KEY REFERENCES documents(id),
  user_id TEXT NOT NULL,
  invoice_number TEXT,
  supplier_name TEXT,
  supplier_iban TEXT,
  po_number TEXT,                   -- référence bon de commande, si mentionnée
  amount REAL NOT NULL,
  currency TEXT DEFAULT 'EUR',
  invoice_date TEXT,                -- ISO date
  due_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_invoices_po ON invoices(user_id, po_number);
CREATE INDEX IF NOT EXISTS idx_invoices_supplier ON invoices(user_id, supplier_name);

CREATE TABLE IF NOT EXISTS purchase_orders (
  document_id TEXT PRIMARY KEY REFERENCES documents(id),
  user_id TEXT NOT NULL,
  po_number TEXT NOT NULL,
  supplier_name TEXT,
  amount REAL NOT NULL,
  currency TEXT DEFAULT 'EUR',
  order_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_po_number ON purchase_orders(user_id, po_number);

CREATE TABLE IF NOT EXISTS contracts (
  document_id TEXT PRIMARY KEY REFERENCES documents(id),
  user_id TEXT NOT NULL,
  supplier_name TEXT,
  contract_ref TEXT,
  amount REAL,
  currency TEXT DEFAULT 'EUR',
  start_date TEXT,
  end_date TEXT,                    -- utilisé pour l'alerte "échéance proche"
  auto_renew INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bank_transactions (
  id TEXT PRIMARY KEY,
  document_id TEXT REFERENCES documents(id), -- relevé source
  user_id TEXT NOT NULL,
  tx_date TEXT NOT NULL,
  amount REAL NOT NULL,             -- négatif = sortie, positif = entrée
  counterparty_name TEXT,
  counterparty_iban TEXT,
  label TEXT
);
CREATE INDEX IF NOT EXISTS idx_tx_user_date ON bank_transactions(user_id, tx_date);

-- Comptes clients
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,     -- PBKDF2 (voir auth.js), jamais le mot de passe en clair
  password_salt TEXT NOT NULL,
  signup_ip TEXT,                  -- pour la règle "1 compte par IP" à l'inscription (voir index.js)
  email_verified INTEGER NOT NULL DEFAULT 0,
  lang TEXT NOT NULL DEFAULT 'fr', -- langue des emails automatiques (alertes, confirmation...) ; mise à jour via PATCH /account/lang
  created_at INTEGER NOT NULL
);

-- Code de confirmation d'email à l'inscription (un seul actif par compte, écrasé à chaque renvoi)
CREATE TABLE IF NOT EXISTS email_verification_codes (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
-- "1 compte par IP" (NULL autorisé plusieurs fois : ne concerne que les inscriptions avec IP connue)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_signup_ip ON users(signup_ip);

-- Sessions actives (on stocke un hash du token, jamais le token lui-même)
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Jetons de réinitialisation de mot de passe (à usage unique, courte durée de vie)
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- Commandes de paiement NOWPayments, liées à un compte réel (jamais un plan choisi côté client)
CREATE TABLE IF NOT EXISTS orders (
  order_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  plan TEXT NOT NULL,
  cycle TEXT NOT NULL DEFAULT 'monthly', -- 'monthly' (30 jours) | 'annual' (360 jours)
  invoice_id TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | paid
  created_at INTEGER NOT NULL,
  paid_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);

-- Statut d'abonnement réel — seule source de vérité, jamais le localStorage du navigateur
CREATE TABLE IF NOT EXISTS subscriptions (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  plan TEXT NOT NULL DEFAULT 'free',
  expires_at INTEGER,
  free_analyses_used INTEGER NOT NULL DEFAULT 0,
  plan_documents_used INTEGER NOT NULL DEFAULT 0, -- documents du cycle de 30 jours en cours (plan plafonné, ex. Starter)
  plan_cycle TEXT,                 -- 'monthly' | 'annual' : dernier cycle de facturation payé
  plan_quota_reset_at INTEGER,     -- dernière remise à 0 du quota de 30 jours (indépendant du cycle de facturation :
                                    -- un abonnement annuel voit quand même son quota de documents repartir tous les 30 jours)
  updated_at INTEGER NOT NULL
);

-- IBAN de confiance déclarés pour un compte (jamais remplie automatiquement depuis un relevé : voir rules.js).
-- Un IBAN est aussi considéré comme connu s'il figure sur une facture ou dans un relevé plus ancien.
CREATE TABLE IF NOT EXISTS known_counterparties (
  user_id TEXT NOT NULL,
  iban TEXT NOT NULL,
  name TEXT,
  first_seen TEXT,
  PRIMARY KEY (user_id, iban)
);

-- Alertes réelles générées par le moteur de règles (remplace les tableaux codés en dur du frontend)
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  type TEXT NOT NULL,                -- 'critical' | 'warning' | 'info'
  rule TEXT NOT NULL,                -- 'invoice_po_mismatch' | 'duplicate_payment' | 'contract_expiring' | 'unusual_outflow' | 'invoice_drift'
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  amount_impact REAL,                -- montant de l'écart détecté, si pertinent
  related_document_ids TEXT,         -- JSON array
  status TEXT NOT NULL DEFAULT 'open', -- open | reviewed | dismissed
  created_at INTEGER NOT NULL,
  fingerprint TEXT                   -- identifie le constat (règle + documents/transactions) : évite les doublons à chaque /analyze
);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id, status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(user_id, fingerprint);

-- Limiteur de débit (connexion, inscription, mot de passe oublié, envois...) — voir ratelimit.js
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

-- Profil KYC (identité + justificatifs) : soumission uniquement, pas de vérification automatisée.
-- Une ligne apparaît seulement une fois que le client a soumis le formulaire ; son absence = "non soumis".
CREATE TABLE IF NOT EXISTS kyc_profiles (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  first_name TEXT,
  last_name TEXT,
  address_line TEXT,
  city TEXT,
  postal_code TEXT,
  country TEXT,
  id_document_base64 TEXT,
  id_document_filename TEXT,
  proof_address_base64 TEXT,
  proof_address_filename TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected (justificatif de domicile, revu manuellement)
  submitted_at INTEGER NOT NULL,
  reviewed_at INTEGER,
  reviewer_note TEXT,
  -- Vérification d'identité automatisée (Didit) : distincte du "status" ci-dessus.
  identity_status TEXT NOT NULL DEFAULT 'not_started', -- not_started | pending | approved | rejected
  didit_session_id TEXT,
  didit_status TEXT,      -- dernier statut brut renvoyé par Didit (pour le débogage)
  identity_verified_at INTEGER
);

-- Anti-rejeu des webhooks Didit : un event_id déjà traité n'est jamais réappliqué.
CREATE TABLE IF NOT EXISTS didit_webhook_events (
  event_id TEXT PRIMARY KEY,
  received_at INTEGER NOT NULL
);
