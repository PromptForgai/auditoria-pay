-- AuditorIA — migration n°3 : abonnements mensuel/annuel, vérification d'email, 1 compte par IP, profil KYC.
-- À exécuter UNE SEULE FOIS, en plus de migration.sql et migration-2.sql (déjà exécutés) :
--   wrangler d1 execute auditoria_db --remote --file=migration-3.sql
-- Si tu repars d'une base neuve, ignore ce fichier : schema.sql contient déjà tout ceci.

ALTER TABLE users ADD COLUMN signup_ip TEXT;
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
-- "1 compte par IP" : les comptes déjà existants ont signup_ip = NULL, et SQLite autorise plusieurs
-- NULL dans un index UNIQUE (ils ne se bloquent pas entre eux), donc cet index ne gêne pas les comptes
-- déjà créés — seules les inscriptions à partir de maintenant sont concernées.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_signup_ip ON users(signup_ip);

ALTER TABLE subscriptions ADD COLUMN plan_cycle TEXT;              -- 'monthly' | 'annual' (dernier cycle facturé)
ALTER TABLE subscriptions ADD COLUMN plan_quota_reset_at INTEGER;  -- dernière remise à 0 du quota mensuel du plan

ALTER TABLE orders ADD COLUMN cycle TEXT NOT NULL DEFAULT 'monthly';

CREATE TABLE IF NOT EXISTS email_verification_codes (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

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
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  submitted_at INTEGER NOT NULL,
  reviewed_at INTEGER,
  reviewer_note TEXT
);

-- Comptes déjà existants avant cette migration : comme s'ils avaient confirmé leur email
-- (on ne va pas bloquer des clients déjà actifs rétroactivement). Seuls les NOUVEAUX comptes
-- devront confirmer leur email à partir de maintenant.
UPDATE users SET email_verified = 1 WHERE email_verified = 0;
