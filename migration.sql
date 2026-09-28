-- AuditorIA — migration de la base D1 EXISTANTE vers le nouveau schéma.
-- À exécuter UNE SEULE FOIS (les ALTER TABLE ne sont pas rejouables) :
--   wrangler d1 execute auditoria_db --remote --file=migration.sql
-- Pour une base neuve, utilise schema.sql à la place.

-- 1. Nouvelles colonnes sur documents
ALTER TABLE documents ADD COLUMN credit_used INTEGER NOT NULL DEFAULT 0;
ALTER TABLE documents ADD COLUMN content_hash TEXT;
-- (les anciens documents ont content_hash NULL : SQLite autorise plusieurs NULL dans un index unique)
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_hash ON documents(user_id, content_hash);

-- 2. Empreinte des alertes + index unique anti-doublons
ALTER TABLE findings ADD COLUMN fingerprint TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(user_id, fingerprint);

-- 3. Limiteur de débit
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

-- 4. Nettoyage des données produites par l'ancien code.
-- Les anciennes alertes n'ont pas d'empreinte et contiennent les doublons empilés à chaque /analyze :
-- on les supprime, elles seront régénérées proprement au prochain /analyze (données dérivées, rien n'est perdu).
DELETE FROM findings;
-- L'ancien code remplissait cette table avec TOUS les IBAN des relevés importés, ce qui neutralisait
-- l'alerte "sortie inhabituelle". Elle est désormais réservée aux IBAN de confiance déclarés.
DELETE FROM known_counterparties;
