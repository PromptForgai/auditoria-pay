-- AuditorIA — migration n°7 : fichiers volumineux stockés sur R2 (au-delà de ~1,4 Mo).
-- À exécuter UNE SEULE FOIS, en plus des migrations précédentes (déjà exécutées) :
--   wrangler d1 execute auditoria_db --remote --file=migration-7.sql
-- Si tu repars d'une base neuve, ignore ce fichier : schema.sql contient déjà cette colonne.
--
-- IMPORTANT : avant de déployer le code qui accompagne cette migration, le bucket R2 doit exister
-- et wrangler.toml doit contenir son binding — voir le README, section "Fichiers volumineux (R2)".
-- Sans ça, cette migration seule ne casse rien (elle n'ajoute qu'une colonne), mais les fichiers de
-- plus de 1,4 Mo continueront d'être refusés tant que R2 n'est pas vraiment configuré.

ALTER TABLE documents ADD COLUMN r2_key TEXT;
