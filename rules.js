// rules.js — moteur de détection déterministe
// Chaque fonction lit des données déjà en base (D1) pour un user_id donné et renvoie
// une liste de "findings". Aucune génération de texte par IA ici : uniquement des comparaisons
// numériques/logiques, pour que chaque alerte affichée soit vérifiable.
//
// Chaque finding porte une "fingerprint" stable (règle + documents/transactions concernés).
// Un index UNIQUE (user_id, fingerprint) garantit qu'un même constat n'est créé qu'une fois,
// même si /analyze est appelé cent fois — et qu'une alerte ignorée par l'utilisateur ne revient pas.
//
// Nombre de requêtes D1 constant (et non proportionnel au nombre de lignes) : les jointures se font
// en SQL, et les insertions passent par db.batch().

import { looksLikeImageEditor } from './pdf_metadata.js';

const uuid = () => crypto.randomUUID();

function makeFinding(userId, f) {
  return {
    id: uuid(),
    user_id: userId,
    type: f.type,
    rule: f.rule,
    title: f.title,
    description: f.description,
    amount_impact: f.amount_impact ?? null,
    related_document_ids: JSON.stringify((f.docs || []).filter(Boolean)),
    status: 'open',
    created_at: Date.now(),
    fingerprint: f.fingerprint
  };
}

// 1. Écart facture vs bon de commande (une seule requête, jointure sur le numéro de BC)
export async function checkInvoicePoMismatch(db, userId, thresholdRatio = 0.03) {
  const { results } = await db.prepare(
    `SELECT i.document_id AS inv_doc, i.invoice_number, i.amount AS inv_amount, i.currency AS inv_cur,
            p.document_id AS po_doc, p.po_number, p.amount AS po_amount, p.currency AS po_cur
     FROM invoices i
     JOIN purchase_orders p ON p.user_id = i.user_id AND p.po_number = i.po_number
     WHERE i.user_id = ?`
  ).bind(userId).all();

  const findings = [];
  for (const r of results) {
    if (r.inv_cur !== r.po_cur) continue; // devises différentes : comparer les montants n'aurait aucun sens
    const diff = r.inv_amount - r.po_amount;
    const ratio = Math.abs(diff) / Math.max(Math.abs(r.po_amount), 1);
    if (ratio <= thresholdRatio) continue;
    findings.push(makeFinding(userId, {
      type: ratio > 0.1 ? 'critical' : 'warning',
      rule: 'invoice_po_mismatch',
      title: 'Écart de facturation',
      description: `Facture ${r.invoice_number || r.inv_doc} — écart de ${diff.toFixed(2)} ${r.inv_cur} vs bon de commande ${r.po_number}.`,
      amount_impact: diff,
      docs: [r.inv_doc, r.po_doc],
      fingerprint: `invoice_po_mismatch:${r.inv_doc}:${r.po_doc}`
    }));
  }
  return findings;
}

// 2. Paiements en double (même bénéficiaire, même montant, fenêtre de 5 jours).
// Regroupement en mémoire : une seule requête, au lieu d'une recherche linéaire par transaction.
export async function checkDuplicatePayments(db, userId, windowDays = 5) {
  const { results: txs } = await db.prepare(
    `SELECT id, document_id, tx_date, amount, counterparty_name, counterparty_iban
     FROM bank_transactions WHERE user_id = ? AND amount < 0 ORDER BY tx_date, id`
  ).bind(userId).all();

  const groups = new Map();
  for (const tx of txs) {
    const who = tx.counterparty_iban || (tx.counterparty_name ? `name:${tx.counterparty_name.trim().toLowerCase()}` : null);
    if (!who) continue;
    const key = `${who}|${Math.round(tx.amount * 100)}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(tx);
  }

  const findings = [];
  for (const list of groups.values()) {
    for (let i = 1; i < list.length; i++) {
      const prev = list[i - 1], tx = list[i];
      const gapMs = new Date(tx.tx_date) - new Date(prev.tx_date);
      if (!(gapMs <= windowDays * 86400000)) continue;
      findings.push(makeFinding(userId, {
        type: 'critical',
        rule: 'duplicate_payment',
        title: 'Paiement en double détecté',
        description: `Paiement de ${Math.abs(tx.amount).toFixed(2)} € vers ${tx.counterparty_name || tx.counterparty_iban} dupliqué (${prev.tx_date} et ${tx.tx_date}).`,
        amount_impact: tx.amount,
        docs: [tx.document_id, prev.document_id],
        fingerprint: `duplicate_payment:${prev.id}:${tx.id}`
      }));
    }
  }
  return findings;
}

// 3. Contrats arrivant à échéance (< 30 jours)
export async function checkContractsExpiring(db, userId, withinDays = 30) {
  const { results: contracts } = await db.prepare(
    `SELECT * FROM contracts WHERE user_id = ? AND end_date IS NOT NULL`
  ).bind(userId).all();

  const findings = [];
  const nowMs = Date.now();
  for (const c of contracts) {
    const end = new Date(c.end_date).getTime();
    if (Number.isNaN(end)) continue;
    const daysLeft = Math.ceil((end - nowMs) / 86400000);
    if (daysLeft < 0 || daysLeft > withinDays) continue;
    findings.push(makeFinding(userId, {
      type: daysLeft <= 7 ? 'critical' : 'warning',
      rule: 'contract_expiring',
      title: 'Contrat arrivant à échéance',
      description: `Fournisseur ${c.supplier_name || 'inconnu'} — échéance dans ${daysLeft} jour(s) (${c.end_date})${c.auto_renew ? ', reconduction tacite prévue' : ''}.`,
      amount_impact: c.amount || null,
      docs: [c.document_id],
      fingerprint: `contract_expiring:${c.document_id}`
    }));
  }
  return findings;
}

// 4. Sortie importante vers un IBAN inconnu.
// Un IBAN est "connu" s'il figure sur une facture importée, dans la liste de confiance
// (known_counterparties), ou si une transaction PLUS ANCIENNE vers ce même IBAN existe déjà :
// seule la première apparition d'un IBAN est signalée (les répétitions relèvent de la règle des doublons).
// IMPORTANT : on ne remplit plus known_counterparties depuis le relevé qu'on analyse — sinon
// tous les IBAN du relevé deviendraient "connus" avant même l'analyse et la règle ne se déclencherait jamais.
export async function checkUnusualOutflows(db, userId, unknownThreshold = 5000) {
  const { results: txs } = await db.prepare(
    `SELECT t.id, t.document_id, t.tx_date, t.amount, t.counterparty_iban
     FROM bank_transactions t
     WHERE t.user_id = ? AND t.amount <= ?
       AND t.counterparty_iban IS NOT NULL AND t.counterparty_iban != ''
       AND NOT EXISTS (SELECT 1 FROM invoices i WHERE i.user_id = t.user_id AND i.supplier_iban = t.counterparty_iban)
       AND NOT EXISTS (SELECT 1 FROM known_counterparties k WHERE k.user_id = t.user_id AND k.iban = t.counterparty_iban)
       AND NOT EXISTS (SELECT 1 FROM bank_transactions o
                       WHERE o.user_id = t.user_id AND o.counterparty_iban = t.counterparty_iban
                         AND (o.tx_date < t.tx_date OR (o.tx_date = t.tx_date AND o.id < t.id)))`
  ).bind(userId, -unknownThreshold).all();

  return txs.map(tx => makeFinding(userId, {
    type: 'critical',
    rule: 'unusual_outflow',
    title: 'Sortie inhabituelle',
    description: `${Math.abs(tx.amount).toFixed(2)} € vers un IBAN inconnu (${tx.counterparty_iban}) le ${tx.tx_date}.`,
    amount_impact: tx.amount,
    docs: [tx.document_id],
    fingerprint: `unusual_outflow:${tx.id}`
  }));
}

// 5. Changement d'IBAN d'un fournisseur entre deux factures — signal classique de fraude au
// changement de coordonnées bancaires (un fraudeur se fait passer pour un fournisseur connu et
// annonce un "nouvel IBAN"). LAG() compare chaque facture d'un fournisseur à la précédente du même
// fournisseur (regroupées par nom, insensible à la casse/espaces), dans l'ordre chronologique.
export async function checkSupplierIbanChange(db, userId) {
  const { results } = await db.prepare(
    `WITH ordered AS (
       SELECT document_id, invoice_number, supplier_name, supplier_iban, invoice_date,
              LAG(supplier_iban) OVER (PARTITION BY LOWER(TRIM(supplier_name)) ORDER BY invoice_date, document_id) AS prev_iban,
              LAG(document_id) OVER (PARTITION BY LOWER(TRIM(supplier_name)) ORDER BY invoice_date, document_id) AS prev_doc
       FROM invoices
       WHERE user_id = ? AND supplier_name IS NOT NULL AND supplier_iban IS NOT NULL AND supplier_iban != ''
     )
     SELECT * FROM ordered WHERE prev_iban IS NOT NULL AND prev_iban != supplier_iban`
  ).bind(userId).all();

  return results.map(r => makeFinding(userId, {
    type: 'critical',
    rule: 'supplier_iban_change',
    title: "Changement d'IBAN fournisseur",
    description: `${r.supplier_name} : nouvel IBAN (${r.supplier_iban}) sur la facture ${r.invoice_number || r.document_id}, différent de l'IBAN utilisé précédemment (${r.prev_iban}). Vérifie ce changement directement auprès du fournisseur avant tout paiement.`,
    docs: [r.document_id, r.prev_doc],
    fingerprint: `supplier_iban_change:${r.prev_doc}:${r.document_id}`
  }));
}

// 6. Factures en double : même fournisseur, même numéro de facture. Distinct du paiement en double
// (règle 2) : ici on détecte le doublon dès l'import des factures, avant même qu'un paiement n'ait
// lieu — ressaisie accidentelle ou double soumission par le fournisseur.
export async function checkDuplicateInvoiceNumbers(db, userId) {
  const { results } = await db.prepare(
    `SELECT a.document_id AS doc1, b.document_id AS doc2, a.invoice_number, a.supplier_name,
            a.amount AS amt1, b.amount AS amt2, a.currency
     FROM invoices a JOIN invoices b
       ON a.user_id = b.user_id AND LOWER(TRIM(a.supplier_name)) = LOWER(TRIM(b.supplier_name))
       AND a.invoice_number = b.invoice_number AND a.document_id < b.document_id
     WHERE a.user_id = ? AND a.invoice_number IS NOT NULL AND a.supplier_name IS NOT NULL AND a.supplier_name != ''`
  ).bind(userId).all();

  return results.map(r => makeFinding(userId, {
    type: 'warning',
    rule: 'duplicate_invoice_number',
    title: 'Facture en double',
    description: `Le numéro de facture ${r.invoice_number} apparaît deux fois pour ${r.supplier_name} (${r.amt1} et ${r.amt2} ${r.currency}).`,
    amount_impact: r.amt1 === r.amt2 ? r.amt1 : null,
    docs: [r.doc1, r.doc2],
    fingerprint: `duplicate_invoice_number:${r.doc1}:${r.doc2}`
  }));
}

// 7. Fractionnement de factures ("structuring") : plusieurs factures du même fournisseur, le même
// jour, chacune sous le seuil donné, mais dont la somme le dépasse — technique classique pour
// contourner un seuil d'approbation fixé par l'entreprise.
export async function checkInvoiceSplitting(db, userId, approvalThreshold = 5000) {
  const { results } = await db.prepare(
    `SELECT LOWER(TRIM(supplier_name)) AS supplier_key, supplier_name, invoice_date, currency,
            COUNT(*) AS cnt, SUM(amount) AS total, GROUP_CONCAT(document_id) AS docs
     FROM invoices
     WHERE user_id = ? AND supplier_name IS NOT NULL AND supplier_name != '' AND invoice_date IS NOT NULL AND amount < ?
     GROUP BY supplier_key, invoice_date, currency
     HAVING COUNT(*) >= 2 AND SUM(amount) >= ?`
  ).bind(userId, approvalThreshold, approvalThreshold).all();

  return results.map(r => {
    const docs = r.docs.split(',');
    return makeFinding(userId, {
      type: 'critical',
      rule: 'invoice_splitting',
      title: 'Fractionnement de factures suspecté',
      description: `${r.cnt} factures de ${r.supplier_name} le ${r.invoice_date}, chacune sous ${approvalThreshold} ${r.currency}, pour un total de ${r.total.toFixed(2)} ${r.currency}.`,
      amount_impact: r.total,
      docs,
      fingerprint: `invoice_splitting:${r.supplier_key}:${r.invoice_date}`
    });
  });
}

// 8. Sortie vers un bénéficiaire CONNU mais d'un montant très supérieur à son historique — complète
// la règle 4 (IBAN inconnu), qui ne couvre pas le cas d'un bénéficiaire habituel mais dont le montant
// payé devient brusquement anormal. Limite assumée : la moyenne inclut la transaction elle-même (pas
// de fenêtre excluant la ligne courante), ce qui amortit un peu le signal — en échange d'une seule
// requête, sans explosion du nombre de lectures. Au moins 3 transactions antérieures exigées pour
// qu'une moyenne ait un sens.
export async function checkOutlierTransactionAmount(db, userId, multiplier = 3) {
  const { results } = await db.prepare(
    `WITH stats AS (
       SELECT counterparty_iban, AVG(ABS(amount)) AS avg_amt, COUNT(*) AS cnt
       FROM bank_transactions
       WHERE user_id = ? AND amount < 0 AND counterparty_iban IS NOT NULL AND counterparty_iban != ''
       GROUP BY counterparty_iban
     )
     SELECT t.id, t.document_id, t.tx_date, t.amount, t.counterparty_iban, t.counterparty_name, s.avg_amt
     FROM bank_transactions t JOIN stats s ON s.counterparty_iban = t.counterparty_iban
     WHERE t.user_id = ? AND t.amount < 0 AND s.cnt >= 3 AND ABS(t.amount) > s.avg_amt * ?`
  ).bind(userId, userId, multiplier).all();

  return results.map(r => makeFinding(userId, {
    type: 'warning',
    rule: 'outlier_transaction_amount',
    title: 'Montant inhabituel pour ce bénéficiaire',
    description: `${Math.abs(r.amount).toFixed(2)} € vers ${r.counterparty_name || r.counterparty_iban} le ${r.tx_date}, contre une moyenne habituelle d'environ ${r.avg_amt.toFixed(2)} € pour ce bénéficiaire.`,
    amount_impact: r.amount,
    docs: [r.document_id],
    fingerprint: `outlier_transaction_amount:${r.id}`
  }));
}

// 9. Métadonnées PDF suspectes : une facture, un bon de commande ou un contrat dont les métadonnées
// /Producer ou /Creator mentionnent un logiciel d'édition d'image (Photoshop, GIMP...) plutôt qu'un
// logiciel de comptabilité, de bureautique, ou une imprimante PDF. Un indice de manipulation
// objectif (lu dans le fichier, pas une opinion de l'IA) — pas une preuve de fraude en soi : certains
// cabinets scannent/retouchent légitimement un document papier avec ce type d'outil. Le filtrage par
// motif se fait en JS plutôt qu'en SQL (D1 n'a pas d'extension REGEXP activée par défaut).
export async function checkSuspiciousPdfSoftware(db, userId) {
  const { results } = await db.prepare(
    `SELECT id, filename, kind, pdf_producer, pdf_creator
     FROM documents
     WHERE user_id = ? AND status = 'extracted' AND kind IN ('invoice', 'purchase_order', 'contract')
       AND (pdf_producer IS NOT NULL OR pdf_creator IS NOT NULL)`
  ).bind(userId).all();

  const findings = [];
  for (const doc of results) {
    const hit = looksLikeImageEditor(doc.pdf_producer) ? doc.pdf_producer
      : looksLikeImageEditor(doc.pdf_creator) ? doc.pdf_creator
      : null;
    if (!hit) continue;
    findings.push(makeFinding(userId, {
      type: 'warning',
      rule: 'suspicious_pdf_software',
      title: 'Métadonnées PDF à vérifier',
      description: `${doc.filename || 'Ce document'} a été produit ou retouché avec un logiciel d'édition d'image (${hit}) plutôt qu'un logiciel de comptabilité habituel. Ce n'est pas une preuve de falsification, mais mérite une vérification directe auprès de l'émetteur.`,
      docs: [doc.id],
      fingerprint: `suspicious_pdf_software:${doc.id}`
    }));
  }
  return findings;
}

// Insère les findings par lots. INSERT OR IGNORE + index unique (user_id, fingerprint) :
// un constat déjà présent (ouvert, revu ou ignoré) n'est jamais recréé.
// Renvoie uniquement les findings réellement créés.
export async function saveFindings(db, findings) {
  const created = [];
  const stmt = db.prepare(
    `INSERT OR IGNORE INTO findings
       (id, user_id, type, rule, title, description, amount_impact, related_document_ids, status, created_at, fingerprint)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  );
  for (let i = 0; i < findings.length; i += 50) {
    const chunk = findings.slice(i, i + 50);
    const results = await db.batch(chunk.map(f => stmt.bind(
      f.id, f.user_id, f.type, f.rule, f.title, f.description, f.amount_impact,
      f.related_document_ids, f.status, f.created_at, f.fingerprint
    )));
    results.forEach((r, j) => { if (r.meta.changes > 0) created.push(chunk[j]); });
  }
  return created;
}

// Point d'entrée : lance toutes les règles et insère les nouveaux constats
export async function runAllRules(db, userId) {
  const all = (await Promise.all([
    checkInvoicePoMismatch(db, userId),
    checkDuplicatePayments(db, userId),
    checkContractsExpiring(db, userId),
    checkUnusualOutflows(db, userId),
    checkSupplierIbanChange(db, userId),
    checkDuplicateInvoiceNumbers(db, userId),
    checkInvoiceSplitting(db, userId),
    checkOutlierTransactionAmount(db, userId),
    checkSuspiciousPdfSoftware(db, userId)
  ])).flat();
  return saveFindings(db, all);
}
