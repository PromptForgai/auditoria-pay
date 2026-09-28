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
    checkUnusualOutflows(db, userId)
  ])).flat();
  return saveFindings(db, all);
}
