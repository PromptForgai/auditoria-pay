-- AuditorIA — migration n°4 : vérification d'identité automatisée via Didit.
-- À exécuter UNE SEULE FOIS, en plus de migration.sql, migration-2.sql et migration-3.sql (déjà exécutés) :
--   wrangler d1 execute auditoria_db --remote --file=migration-4.sql
-- Si tu repars d'une base neuve, ignore ce fichier : schema.sql contient déjà tout ceci.

-- identity_status est distinct de "status" (qui reste le statut du justificatif de domicile, revu
-- manuellement) : une identité peut être approuvée par Didit alors que le justificatif de domicile
-- est encore en attente, et inversement.
ALTER TABLE kyc_profiles ADD COLUMN identity_status TEXT NOT NULL DEFAULT 'not_started';
ALTER TABLE kyc_profiles ADD COLUMN didit_session_id TEXT;
ALTER TABLE kyc_profiles ADD COLUMN didit_status TEXT;
ALTER TABLE kyc_profiles ADD COLUMN identity_verified_at INTEGER;

-- Anti-rejeu des webhooks Didit : un event_id déjà traité n'est jamais réappliqué.
CREATE TABLE IF NOT EXISTS didit_webhook_events (
  event_id TEXT PRIMARY KEY,
  received_at INTEGER NOT NULL
);
