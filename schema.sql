-- AuditorIA — schéma D1 (moteur réel)
-- wrangler d1 execute auditoria_db --file=schema.sql

CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,              -- uuid
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,               -- 'invoice' | 'purchase_order' | 'contract' | 'bank_statement'
  content_base64 TEXT NOT NULL,     -- contenu brut du fichier, encodé en base64, stocké directement en D1
                                     -- (pas de R2 pour l'instant : R2 exige carte bancaire/PayPal, D1 non)
  filename TEXT,
  status TEXT NOT NULL DEFAULT 'uploaded', -- uploaded | extracted | error
  uploaded_at INTEGER NOT NULL,
  extracted_at INTEGER
);

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
  created_at INTEGER NOT NULL
);

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
  updated_at INTEGER NOT NULL
);

-- Table des fournisseurs connus, construite au fil de l'eau (permet de détecter un IBAN "inconnu")
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
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_user ON findings(user_id, status, created_at);
