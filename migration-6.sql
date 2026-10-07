-- AuditorIA — migration n°6 : indice de manipulation à partir des métadonnées PDF.
-- À exécuter UNE SEULE FOIS, en plus des migrations précédentes (déjà exécutées) :
--   wrangler d1 execute auditoria_db --remote --file=migration-6.sql
-- Si tu repars d'une base neuve, ignore ce fichier : schema.sql contient déjà ces colonnes.

ALTER TABLE documents ADD COLUMN pdf_producer TEXT;
ALTER TABLE documents ADD COLUMN pdf_creator TEXT;
