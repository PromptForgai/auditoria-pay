// payments.js — remplace la logique de confiance client (localStorage) par une vraie source
// de vérité serveur. Trois garanties centrales :
// 1. Une facture est toujours créée pour un user_id authentifié (jamais un plan "au choix du client").
// 2. /ipn n'active JAMAIS un abonnement sans vérifier la signature HMAC envoyée par NOWPayments —
//    sans ça, n'importe qui pourrait POST une fausse confirmation de paiement.
// 3. Le statut d'abonnement et le quota d'essais gratuits sont stockés en D1, jamais dans le navigateur.

import { HttpError } from './errors.js';

const NP_API = "https://api.nowpayments.io/v1";

// Prix par cycle de facturation. L'annuel vaut ici 10 fois le prix mensuel (2 mois offerts, ~17% de
// remise) — une pratique courante, mais purement une hypothèse de départ : change ces deux nombres
// (starter.annual.price et growth.annual.price) si tu veux un autre tarif annuel.
const PLANS = {
  starter: {
    monthly: { price: 2000, days: 30, name: "AuditorIA Starter — Monthly" },
    annual: { price: 20000, days: 360, name: "AuditorIA Starter — Annual" }
  },
  growth: {
    monthly: { price: 5000, days: 30, name: "AuditorIA Growth — Monthly" },
    annual: { price: 50000, days: 360, name: "AuditorIA Growth — Annual" }
  }
};

// Plafond de documents pour un plan payant, par tranche de 30 jours, quel que soit le cycle de
// facturation choisi (un client Starter annuel a quand même un quota qui se renouvelle tous les 30
// jours, pas une seule fois pour l'année — voir resetPlanQuotaIfDue ci-dessous). Un plan absent de cet
// objet (Growth) est illimité.
const PLAN_LIMITS = { starter: 50 };
const QUOTA_PERIOD_MS = 30 * 24 * 60 * 60 * 1000;

// Documents gratuits par compte (tous types confondus), sans limite de durée.
// Il en faut au moins 2 pour voir un écart facture/BC : 5 permettent un relevé + facture + BC + 2 contrats.
export const FREE_LIMIT = 5;

export async function createInvoice(db, userId, plan, cycle, successUrl, workerOrigin, apiKey, ipnSecret) {
  plan = (plan || "starter").toLowerCase();
  cycle = cycle === "annual" ? "annual" : "monthly"; // toute valeur inconnue retombe sur mensuel, jamais sur le tarif annuel
  if (!PLANS[plan]) throw new HttpError(400, "plan invalide");
  const tier = PLANS[plan][cycle];
  if (!apiKey) throw new Error("NOWPAYMENTS_API_KEY non configurée"); // erreur de config : journalisée, jamais montrée au client

  const orderId = `auditoria-${plan}-${cycle}-${crypto.randomUUID()}`;
  const payload = {
    price_amount: tier.price,
    price_currency: "usd",
    order_id: orderId,
    order_description: tier.name,
    success_url: successUrl.includes("?")
      ? `${successUrl}&order_id=${orderId}&plan=${plan}`
      : `${successUrl}?order_id=${orderId}&plan=${plan}`,
    is_fixed_rate: true,
    is_fee_paid_by_user: false
  };
  if (ipnSecret) payload.ipn_callback_url = `${workerOrigin}/ipn`;

  const res = await fetch(`${NP_API}/invoice`, {
    method: "POST",
    headers: { "x-api-key": apiKey, "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    console.error("Erreur NOWPayments:", res.status, JSON.stringify(data));
    throw new HttpError(502, "Le service de paiement est indisponible, réessaie dans un instant.");
  }

  // La commande est liée à user_id ici, côté serveur — le client ne peut jamais choisir
  // pour quel compte elle sera créditée. Le cycle vient aussi du serveur (le prix a été fixé selon lui) :
  // handleIpn le relit sur cette même ligne pour savoir combien de jours créditer, jamais depuis le client.
  await db.prepare(
    `INSERT INTO orders (order_id, user_id, plan, cycle, invoice_id, status, created_at) VALUES (?,?,?,?,?,?,?)`
  ).bind(orderId, userId, plan, cycle, data.id, "pending", Date.now()).run();

  return { order_id: orderId, invoice_url: data.invoice_url, invoice_id: data.id };
}

function sortKeys(obj) {
  if (Array.isArray(obj)) return obj.map(sortKeys);
  if (obj && typeof obj === "object") {
    return Object.keys(obj).sort().reduce((acc, k) => { acc[k] = sortKeys(obj[k]); return acc; }, {});
  }
  return obj;
}

// NOWPayments signe chaque IPN avec HMAC-SHA512 (clé = IPN_SECRET) sur le JSON dont les clés
// sont triées alphabétiquement, envoyé dans l'en-tête x-nowpayments-sig.
export async function verifyIpnSignature(rawBody, signatureHeader, ipnSecret) {
  if (!ipnSecret || !signatureHeader) return false;
  let parsed;
  try { parsed = JSON.parse(rawBody); } catch { return false; }
  const sorted = JSON.stringify(sortKeys(parsed));

  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(ipnSecret), { name: "HMAC", hash: "SHA-512" }, false, ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(sorted));
  const computed = [...new Uint8Array(sigBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");

  if (computed.length !== signatureHeader.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ signatureHeader.charCodeAt(i);
  return diff === 0;
}

export async function handleIpn(db, rawBody, signatureHeader, ipnSecret) {
  const verified = await verifyIpnSignature(rawBody, signatureHeader, ipnSecret);
  if (!verified) throw new HttpError(401, "signature IPN invalide");

  const body = JSON.parse(rawBody);
  const status = String(body.payment_status || body.status || "").toLowerCase();
  const orderId = body.order_id;

  // "partially_paid" n'active plus rien : un paiement partiel ne doit pas débloquer 30 jours complets.
  if (!["finished", "confirmed"].includes(status) || !orderId) return;

  const order = await db.prepare(`SELECT * FROM orders WHERE order_id = ?`).bind(orderId).first();
  if (!order) return; // commande inconnue : on n'active jamais un abonnement sans commande liée à un compte
  const planTiers = PLANS[order.plan];
  if (!planTiers) return;
  const cycle = order.cycle === "annual" ? "annual" : "monthly";
  const tier = planTiers[cycle];

  // Le montant doit correspondre au prix du cycle facturé (défense en profondeur, en plus de la signature).
  if (body.price_amount != null && Number(body.price_amount) < tier.price) {
    console.error("IPN ignoré : montant inférieur au prix du plan", orderId, body.price_amount);
    return;
  }
  if (body.actually_paid != null && body.pay_amount != null && Number(body.actually_paid) < Number(body.pay_amount)) {
    console.error("IPN ignoré : paiement incomplet", orderId, body.actually_paid, body.pay_amount);
    return;
  }

  // Idempotence atomique : NOWPayments renvoie plusieurs IPN par paiement (confirmed, puis finished)
  // et peut en rejouer. Seul le premier fait passer la commande à "paid" et crédite l'abonnement.
  const now = Date.now();
  const claim = await db.prepare(
    `UPDATE orders SET status = 'paid', paid_at = ? WHERE order_id = ? AND status != 'paid'`
  ).bind(now, orderId).run();
  if (!claim.meta.changes) return;

  // Renouvellement anticipé du même plan (et du même cycle) : la durée s'ajoute à ce qui reste, on ne
  // perd rien. Changer de plan ou de cycle repart d'aujourd'hui plutôt que de cumuler deux durées
  // différentes (30 jours restants de Starter + 360 jours de Growth n'aurait pas de sens).
  const existing = await db.prepare(`SELECT plan, plan_cycle, expires_at FROM subscriptions WHERE user_id = ?`).bind(order.user_id).first();
  const base = (existing && existing.plan === order.plan && existing.plan_cycle === cycle && existing.expires_at > now) ? existing.expires_at : now;
  const durationMs = tier.days * 24 * 60 * 60 * 1000;

  // plan_documents_used et plan_quota_reset_at repartent de 0 à chaque paiement crédité. Pour un
  // abonnement annuel, resetPlanQuotaIfDue (plus bas) les remettra ensuite à 0 tous les 30 jours
  // pendant la durée de l'abonnement : le plafond mensuel ne dépend pas de la fréquence de paiement.
  await db.prepare(
    `INSERT INTO subscriptions (user_id, plan, expires_at, free_analyses_used, plan_documents_used, plan_cycle, plan_quota_reset_at, updated_at)
     VALUES (?,?,?,0,0,?,?,?)
     ON CONFLICT(user_id) DO UPDATE SET plan = excluded.plan, expires_at = excluded.expires_at,
       plan_documents_used = 0, plan_cycle = excluded.plan_cycle, plan_quota_reset_at = excluded.plan_quota_reset_at,
       updated_at = excluded.updated_at`
  ).bind(order.user_id, order.plan, base + durationMs, cycle, now, now).run();
}

export async function getOrderStatus(db, orderId) {
  const order = await db.prepare(`SELECT * FROM orders WHERE order_id = ?`).bind(orderId).first();
  if (!order) return { status: "not_found" };
  return { order_id: orderId, status: order.status, plan: order.plan, paid: order.status === "paid" };
}

export async function getSubscription(db, userId) {
  let sub = await db.prepare(`SELECT * FROM subscriptions WHERE user_id = ?`).bind(userId).first();
  if (!sub) {
    const now = Date.now();
    await db.prepare(
      `INSERT OR IGNORE INTO subscriptions (user_id, plan, expires_at, free_analyses_used, plan_documents_used, updated_at) VALUES (?,?,?,?,?,?)`
    ).bind(userId, "free", null, 0, 0, now).run();
    sub = { user_id: userId, plan: "free", expires_at: null, free_analyses_used: 0, plan_documents_used: 0, plan_quota_reset_at: null };
  }

  const now = Date.now();
  const paidActive = sub.plan !== "free" && sub.expires_at && sub.expires_at > now;
  const paidExpired = sub.plan !== "free" && sub.expires_at && sub.expires_at <= now;

  // Le plafond de documents d'un plan payant se renouvelle tous les 30 jours, qu'il soit facturé au
  // mois ou à l'année (un abonnement annuel n'a pas un unique quota pour toute l'année). Calcul
  // paresseux : pas de tâche planifiée, on corrige simplement à la lecture si un cycle de 30 jours
  // s'est écoulé depuis la dernière remise à 0.
  if (paidActive && PLAN_LIMITS[sub.plan] != null) {
    const resetAt = sub.plan_quota_reset_at || 0;
    if (now - resetAt >= QUOTA_PERIOD_MS) {
      await db.prepare(
        `UPDATE subscriptions SET plan_documents_used = 0, plan_quota_reset_at = ? WHERE user_id = ?`
      ).bind(now, userId).run();
      sub.plan_documents_used = 0;
      sub.plan_quota_reset_at = now;
    }
  }

  const planLimit = paidActive ? (PLAN_LIMITS[sub.plan] ?? null) : null; // null = illimité (Growth) ou sans objet (gratuit/expiré)

  return {
    plan: paidActive ? sub.plan : (paidExpired ? "expired" : "free"),
    expired: paidExpired,
    expires_at: sub.expires_at,
    free_left: Math.max(0, FREE_LIMIT - (sub.free_analyses_used || 0)),
    active: paidActive,
    plan_limit: planLimit,
    plan_left: planLimit != null ? Math.max(0, planLimit - (sub.plan_documents_used || 0)) : null
  };
}

// Vraie porte d'entrée avant chaque analyse — remplace useFreeAnalysis() côté client,
// qui pouvait être contourné en modifiant le localStorage.
// Renvoie { allowed, creditType, reason } : creditType indique QUEL compteur a été décompté
// (0 = aucun/illimité, 1 = essai gratuit, 2 = quota mensuel d'un plan payant plafonné), pour pouvoir
// le rembourser précisément si l'analyse échoue ensuite. reason n'est présent que si allowed=false.
export async function consumeAnalysisCredit(db, userId) {
  const sub = await getSubscription(db, userId);

  if (sub.active) {
    if (sub.plan_limit == null) return { allowed: true, creditType: 0 }; // Growth (ou tout plan sans plafond) : illimité

    // Décompte atomique du quota mensuel du plan : la condition dans le WHERE empêche deux requêtes
    // simultanées de dépasser le plafond.
    const res = await db.prepare(
      `UPDATE subscriptions SET plan_documents_used = plan_documents_used + 1, updated_at = ?
       WHERE user_id = ? AND plan_documents_used < ?`
    ).bind(Date.now(), userId, sub.plan_limit).run();
    if (!res.meta.changes) return { allowed: false, creditType: 0, reason: 'plan_limit' };
    return { allowed: true, creditType: 2 };
  }

  if (sub.free_left <= 0) return { allowed: false, creditType: 0, reason: 'free_limit' };

  // Décompte atomique de l'essai gratuit : même principe.
  const res = await db.prepare(
    `UPDATE subscriptions SET free_analyses_used = free_analyses_used + 1, updated_at = ?
     WHERE user_id = ? AND free_analyses_used < ?`
  ).bind(Date.now(), userId, FREE_LIMIT).run();
  if (!res.meta.changes) return { allowed: false, creditType: 0, reason: 'free_limit' };
  return { allowed: true, creditType: 1 };
}

// Rend le crédit consommé (essai gratuit ou quota mensuel du plan) quand l'analyse a échoué côté
// serveur (fichier illisible, IA indisponible...). creditType vient de consumeAnalysisCredit ci-dessus.
export async function refundAnalysisCredit(db, userId, creditType) {
  if (creditType === 2) {
    await db.prepare(
      `UPDATE subscriptions SET plan_documents_used = MAX(plan_documents_used - 1, 0), updated_at = ? WHERE user_id = ?`
    ).bind(Date.now(), userId).run();
  } else if (creditType === 1) {
    await db.prepare(
      `UPDATE subscriptions SET free_analyses_used = MAX(free_analyses_used - 1, 0), updated_at = ? WHERE user_id = ?`
    ).bind(Date.now(), userId).run();
  }
}
