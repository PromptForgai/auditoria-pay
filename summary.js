// summary.js — remplace les tableaux figés du dashboard (initCharts) par de vrais calculs
// SQL sur bank_transactions et findings. Aucune valeur ici n'est inventée : tout est une somme
// ou un comptage sur des lignes réellement stockées.
//
// Hypothèse à connaître : "Trésorerie" est le flux net cumulé depuis le premier relevé bancaire
// importé (somme des transactions), pas un solde bancaire en direct — tant qu'aucune connexion
// bancaire live (Open Banking) n'est branchée, il n'existe pas d'autre source pour ce chiffre.
// "Économies réalisées" = montant total des écarts/doublons détectés par le moteur de règles
// (invoice_po_mismatch, duplicate_payment) : c'est l'argent que l'audit a permis de repérer,
// pas une confirmation que la somme a été effectivement récupérée.

// Clé de mois construite à partir de l'heure locale du Date (et non de toISOString, qui décale en UTC).
function monthKey(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`; } // "2026-09"
function monthLabel(d) {
  return d.toLocaleDateString('fr-FR', { month: 'short' }).replace('.', '');
}

function lastNMonths(n) {
  const months = [];
  const now = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    months.push({ key: monthKey(d), label: monthLabel(d) });
  }
  return months;
}

export async function getMonthlyTreasury(db, userId, months = 6) {
  const { results } = await db.prepare(
    `SELECT strftime('%Y-%m', tx_date) AS month, SUM(amount) AS total
     FROM bank_transactions WHERE user_id = ? GROUP BY month ORDER BY month`
  ).bind(userId).all();

  const byMonth = Object.fromEntries(results.map(r => [r.month, r.total]));
  const keys = lastNMonths(months);

  // Cumul : trésorerie = somme de tous les flux jusqu'à la fin de chaque mois, y compris avant la fenêtre affichée
  const { results: before } = await db.prepare(
    `SELECT SUM(amount) AS total FROM bank_transactions WHERE user_id = ? AND strftime('%Y-%m', tx_date) < ?`
  ).bind(userId, keys[0].key).all();
  let running = before[0]?.total || 0;

  const series = keys.map(k => {
    running += byMonth[k.key] || 0;
    return { label: k.label, value: Math.round(running) };
  });
  return series;
}

// Expression SQL commune : ce qui compte comme "économie repérée".
// - doublon de paiement : le montant du doublon ;
// - écart facture/BC : seulement la SURfacturation (une facture inférieure au BC n'est pas une économie) ;
// - les alertes ignorées par l'utilisateur (faux positifs) sont exclues.
const SAVINGS_SUM = `SUM(CASE WHEN rule = 'invoice_po_mismatch' THEN MAX(amount_impact, 0) ELSE ABS(amount_impact) END)`;
const SAVINGS_WHERE = `user_id = ? AND rule IN ('invoice_po_mismatch','duplicate_payment') AND amount_impact IS NOT NULL AND status != 'dismissed'`;

export async function getMonthlySavings(db, userId, months = 5) {
  const { results } = await db.prepare(
    `SELECT strftime('%Y-%m', created_at / 1000, 'unixepoch') AS month, ${SAVINGS_SUM} AS total
     FROM findings WHERE ${SAVINGS_WHERE}
     GROUP BY month ORDER BY month`
  ).bind(userId).all();

  const byMonth = Object.fromEntries(results.map(r => [r.month, r.total]));
  const keys = lastNMonths(months);
  return keys.map(k => ({ label: k.label, value: Math.round(byMonth[k.key] || 0) }));
}

// Cumul depuis le 1er janvier de l'année en cours (le champ s'appelait savings_ytd mais ne sommait que 2 mois).
export async function getSavingsYtd(db, userId) {
  const year = String(new Date().getFullYear());
  const row = await db.prepare(
    `SELECT ${SAVINGS_SUM} AS total FROM findings
     WHERE ${SAVINGS_WHERE} AND strftime('%Y', created_at / 1000, 'unixepoch') = ?`
  ).bind(userId, year).first();
  return Math.round(row?.total || 0);
}

export async function getWeeklyCashflow(db, userId, weeks = 4) {
  const { results } = await db.prepare(
    `SELECT tx_date, amount FROM bank_transactions
     WHERE user_id = ? AND tx_date >= date('now', ?)`
  ).bind(userId, `-${weeks * 7} days`).all();

  const buckets = Array.from({ length: weeks }, () => ({ in: 0, out: 0 }));
  const now = Date.now();
  for (const tx of results) {
    const ageDays = Math.floor((now - new Date(tx.tx_date).getTime()) / 86400000);
    const weekIdx = weeks - 1 - Math.max(0, Math.min(weeks - 1, Math.floor(ageDays / 7))); // borné : une date future ne doit pas sortir du tableau
    if (tx.amount >= 0) buckets[weekIdx].in += tx.amount;
    else buckets[weekIdx].out += Math.abs(tx.amount);
  }
  return {
    labels: buckets.map((_, i) => `S${i + 1}`),
    inflows: buckets.map(b => Math.round(b.in)),
    outflows: buckets.map(b => Math.round(b.out))
  };
}

function pctChange(current, previous) {
  if (!previous) return current ? 100 : 0;
  return Math.round(((current - previous) / Math.abs(previous)) * 1000) / 10;
}

export async function getStatCards(db, userId) {
  const treasury = await getMonthlyTreasury(db, userId, 2);
  const savingsYtd = await getSavingsYtd(db, userId);

  // lastNMonths(2) = [mois précédent, mois courant] — construit avec le 1er du mois, donc pas de bug
  // le 31 (setMonth(-1) un 31 débordait sur le mois en cours).
  const [lastMonthKey, thisMonthKey] = lastNMonths(2).map(m => m.key);

  const flowsThis = await db.prepare(
    `SELECT SUM(CASE WHEN amount >= 0 THEN amount ELSE 0 END) AS inflow,
            SUM(CASE WHEN amount < 0 THEN -amount ELSE 0 END) AS outflow
     FROM bank_transactions WHERE user_id = ? AND strftime('%Y-%m', tx_date) = ?`
  ).bind(userId, thisMonthKey).first();
  const flowsLast = await db.prepare(
    `SELECT SUM(CASE WHEN amount >= 0 THEN amount ELSE 0 END) AS inflow,
            SUM(CASE WHEN amount < 0 THEN -amount ELSE 0 END) AS outflow
     FROM bank_transactions WHERE user_id = ? AND strftime('%Y-%m', tx_date) = ?`
  ).bind(userId, lastMonthKey).first();

  return {
    treasury: { value: treasury[1]?.value || 0, change_pct: pctChange(treasury[1]?.value, treasury[0]?.value) },
    savings_ytd: { value: savingsYtd },
    inflows: { value: Math.round(flowsThis?.inflow || 0), change_pct: pctChange(flowsThis?.inflow, flowsLast?.inflow) },
    outflows: { value: Math.round(flowsThis?.outflow || 0), change_pct: pctChange(flowsThis?.outflow, flowsLast?.outflow) }
  };
}

export async function getFullSummary(db, userId) {
  const [monthly_treasury, monthly_savings, cashflow, stats] = await Promise.all([
    getMonthlyTreasury(db, userId, 6),
    getMonthlySavings(db, userId, 5),
    getWeeklyCashflow(db, userId, 4),
    getStatCards(db, userId)
  ]);
  return { monthly_treasury, monthly_savings, cashflow, stats };
}
