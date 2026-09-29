-- AuditorIA — migration n°2 (plafond mensuel de documents pour le plan Starter).
-- À exécuter UNE SEULE FOIS, en plus de migration.sql (déjà exécuté) :
--   wrangler d1 execute auditoria_db --remote --file=migration-2.sql
-- Si tu repars d'une base neuve, ignore ce fichier : schema.sql contient déjà cette colonne.

ALTER TABLE subscriptions ADD COLUMN plan_documents_used INTEGER NOT NULL DEFAULT 0;
