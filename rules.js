// rules.js — moteur de détection déterministe
// Chaque fonction lit des données déjà en base (D1) pour un user_id donné et renvoie
// une liste de "findings" à insérer. Aucune génération de texte par IA ici : uniquement
// des comparaisons numériques/logiques, pour que chaque alerte affichée soit vérifiable.

const uuid = () => crypto.randomUUID();
const now = () => Date.now();

// 1. Écart facture vs bon de commande
export async function checkInvoicePoMismatch(db, userId, thresholdRatio = 0.03) {
  const findings = [];
  const { results: invoices } = await db.prepare(
    `SELECT * FROM invoices WHERE user_id = ? AND po_number IS NOT NULL`
  ).bind(userId).all();

  for (const inv of invoices) {
    const po = await db.prepare(
      `SELECT * FROM purchase_orders WHERE user_id = ? AND po_number = ?`
    ).bind(userId, inv.po_number).first();

    if (!po) continue; // pas de BC correspondant trouvé, pas d'alerte fondée
    const diff = inv.amount - po.amount;
    const ratio = Math.abs(diff) / Math.max(po.amount, 1);
    if (ratio > thresholdRatio) {
      findings.push({
        id: uuid(),
        user_id: userId,
        type: ratio > 0.1 ? 'critical' : 'warning',
        rule: 'invoice_po_mismatch',
        title: 'Écart de facturation',
        description: `Facture ${inv.invoice_number || inv.document_id} — écart de ${diff.toFixed(2)} ${inv.currency} vs bon de commande ${po.po_number}.`,
        amount_impact: diff,
        related_document_ids: JSON.stringify([inv.document_id, po.document_id]),
        status: 'open',
        created_at: now()
      });
    }
  }
  return findings;
}

// 2. Paiements en double (même fournisseur, même montant, fenêtre de 5 jours)
export async function checkDuplicatePayments(db, userId, windowDays = 5) {
  const findings = [];
  const { results: txs } = await db.prepare(
    `SELECT * FROM bank_transactions WHERE user_id = ? AND amount < 0 ORDER BY tx_date`
  ).bind(userId).all();

  const seen = [];
  for (const tx of txs) {
    const dup = seen.find(other =>
      other.counterparty_iban && tx.counterparty_iban &&
      other.counterparty_iban === tx.counterparty_iban &&
      Math.abs(other.amount - tx.amount) < 0.01 &&
      Math.abs(new Date(tx.tx_date) - new Date(other.tx_date)) <= windowDays * 86400000 &&
      other.id !== tx.id
    );
    if (dup) {
      findings.push({
        id: uuid(),
        user_id: userId,
        type: 'critical',
        rule: 'duplicate_payment',
        title: 'Paiement en double détecté',
        description: `Paiement de ${Math.abs(tx.amount).toFixed(2)} € vers ${tx.counterparty_name || tx.counterparty_iban} dupliqué (${dup.tx_date} et ${tx.tx_date}).`,
        amount_impact: tx.amount,
        related_document_ids: JSON.stringify([tx.document_id, dup.document_id].filter(Boolean)),
        status: 'open',
        created_at: now()
      });
    }
    seen.push(tx);
  }
  return findings;
}

// 3. Contrats arrivant à échéance (< 30 jours)
export async function checkContractsExpiring(db, userId, withinDays = 30) {
  const findings = [];
  const { results: contracts } = await db.prepare(
    `SELECT * FROM contracts WHERE user_id = ? AND end_date IS NOT NULL`
  ).bind(userId).all();

  const nowMs = now();
  for (const c of contracts) {
    const end = new Date(c.end_date).getTime();
    const daysLeft = Math.ceil((end - nowMs) / 86400000);
    if (daysLeft >= 0 && daysLeft <= withinDays) {
      findings.push({
        id: uuid(),
        user_id: userId,
        type: daysLeft <= 7 ? 'critical' : 'warning',
        rule: 'contract_expiring',
        title: 'Contrat arrivant à échéance',
        description: `Fournisseur ${c.supplier_name || 'inconnu'} — échéance dans ${daysLeft} jour(s) (${c.end_date}).`,
        amount_impact: c.amount || null,
        related_document_ids: JSON.stringify([c.document_id]),
        status: 'open',
        created_at: now()
      });
    }
  }
  return findings;
}

// 4. Sortie inhabituelle vers un IBAN inconnu
export async function checkUnusualOutflows(db, userId, unknownThreshold = 5000) {
  const findings = [];
  const { results: txs } = await db.prepare(
    `SELECT * FROM bank_transactions WHERE user_id = ? AND amount < 0 AND tx_date >= date('now','-7 days')`
  ).bind(userId).all();

  for (const tx of txs) {
    if (!tx.counterparty_iban) continue;
    const known = await db.prepare(
      `SELECT 1 FROM known_counterparties WHERE user_id = ? AND iban = ?`
    ).bind(userId, tx.counterparty_iban).first();

    if (!known && Math.abs(tx.amount) >= unknownThreshold) {
      findings.push({
        id: uuid(),
        user_id: userId,
        type: 'critical',
        rule: 'unusual_outflow',
        title: 'Sortie inhabituelle',
        description: `${Math.abs(tx.amount).toFixed(2)} € vers un IBAN inconnu (${tx.counterparty_iban}).`,
        amount_impact: tx.amount,
        related_document_ids: JSON.stringify([tx.document_id].filter(Boolean)),
        status: 'open',
        created_at: now()
      });
    }
  }
  return findings;
}

// Point d'entrée : lance toutes les règles et insère les résultats en base
export async function runAllRules(db, userId) {
  const all = [
    ...(await checkInvoicePoMismatch(db, userId)),
    ...(await checkDuplicatePayments(db, userId)),
    ...(await checkContractsExpiring(db, userId)),
    ...(await checkUnusualOutflows(db, userId))
  ];

  for (const f of all) {
    await db.prepare(
      `INSERT INTO findings (id, user_id, type, rule, title, description, amount_impact, related_document_ids, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(f.id, f.user_id, f.type, f.rule, f.title, f.description, f.amount_impact, f.related_document_ids, f.status, f.created_at).run();
  }
  return all;
}
