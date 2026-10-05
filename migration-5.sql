-- AuditorIA — migration n°5 : langue préférée du client + alertes par email.
-- À exécuter UNE SEULE FOIS, en plus des migrations précédentes (déjà exécutées) :
--   wrangler d1 execute auditoria_db --remote --file=migration-5.sql
-- Si tu repars d'une base neuve, ignore ce fichier : schema.sql contient déjà cette colonne.

ALTER TABLE users ADD COLUMN lang TEXT NOT NULL DEFAULT 'fr';
