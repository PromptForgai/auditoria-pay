// payments.js — remplace la logique de confiance client (localStorage) par une vraie source
// de vérité serveur. Trois garanties centrales :
// 1. Une facture est toujours créée pour un user_id authentifié (jamais un plan "au choix du client").
// 2. /ipn n'active JAMAIS un abonnement sans vérifier la signature HMAC envoyée par NOWPayments —
//    sans ça, n'importe qui pourrait POST une fausse confirmation de paiement.
// 3. Le statut d'abonnement et le quota d'essais gratuits sont stockés en D1, jamais dans le navigateur.

const NP_API = "https://api.nowpayments.io/v1";

const PLANS = {
  starter: { price: 2000, name: "AuditorIA Starter — Monthly" },
  growth: { price: 5000, name: "AuditorIA Growth — Monthly" }
};

const PLAN_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours
export const FREE_LIMIT = 2;
export const DEMO_DURATION_MS = 15 * 60 * 1000; // 15 minutes, décomptées depuis la création du compte

export async function createInvoice(db, userId, plan, successUrl, workerOrigin, apiKey, ipnSecret) {
  plan = (plan || "starter").toLowerCase();
  if (!PLANS[plan]) throw new Error("plan invalide");
  if (!apiKey) throw new Error("NOWPAYMENTS_API_KEY non configurée");

  const orderId = `auditoria-${plan}-${crypto.randomUUID()}`;
  const payload = {
    price_amount: PLANS[plan].price,
    price_currency: "usd",
    order_id: orderId,
    order_description: PLANS[plan].name,
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
  if (!res.ok) throw new Error(data.message || data.error || "Erreur NOWPayments");

  // La commande est liée à user_id ici, côté serveur — le client ne peut jamais choisir
  // pour quel compte elle sera créditée.
  await db.prepare(
    `INSERT INTO orders (order_id, user_id, plan, invoice_id, status, created_at) VALUES (?,?,?,?,?,?)`
  ).bind(orderId, userId, plan, data.id, "pending", Date.now()).run();

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
  if (!verified) throw new Error("signature IPN invalide");

  const body = JSON.parse(rawBody);
  const status = (body.payment_status || body.status || "").toLowerCase();
  const orderId = body.order_id;
  const okStatuses = ["finished", "confirmed", "partially_paid"];
  if (!okStatuses.includes(status) || !orderId) return;

  const order = await db.prepare(`SELECT * FROM orders WHERE order_id = ?`).bind(orderId).first();
  if (!order) return; // commande inconnue : on n'active jamais un abonnement sans commande liée à un compte

  await db.prepare(`UPDATE orders SET status = 'paid', paid_at = ? WHERE order_id = ?`)
    .bind(Date.now(), orderId).run();

  const now = Date.now();
  await db.prepare(
    `INSERT INTO subscriptions (user_id, plan, expires_at, free_analyses_used, updated_at)
     VALUES (?,?,?,0,?)
     ON CONFLICT(user_id) DO UPDATE SET plan = excluded.plan, expires_at = excluded.expires_at, updated_at = excluded.updated_at`
  ).bind(order.user_id, order.plan, now + PLAN_DURATION_MS, now).run();
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
      `INSERT INTO subscriptions (user_id, plan, expires_at, free_analyses_used, updated_at) VALUES (?,?,?,?,?)`
    ).bind(userId, "free", null, 0, now).run();
    sub = { user_id: userId, plan: "free", expires_at: null, free_analyses_used: 0 };
  }

  const now = Date.now();
  const paidActive = sub.plan !== "free" && sub.expires_at && sub.expires_at > now;
  const paidExpired = sub.plan !== "free" && sub.expires_at && sub.expires_at <= now;

  // Mode démo : 15 minutes de crédit automatique décomptées depuis la création du compte,
  // calculées à partir de users.created_at — aucune valeur écrite ni lisible côté client.
  let demoActive = false, demoEndsAt = null;
  if (!paidActive) {
    const user = await db.prepare(`SELECT created_at FROM users WHERE id = ?`).bind(userId).first();
    if (user) {
      demoEndsAt = user.created_at + DEMO_DURATION_MS;
      demoActive = now < demoEndsAt;
    }
  }

  return {
    plan: paidActive ? sub.plan : (demoActive ? "demo" : (paidExpired ? "expired" : "free")),
    expired: paidExpired,
    expires_at: sub.expires_at,
    free_left: Math.max(0, FREE_LIMIT - (sub.free_analyses_used || 0)),
    active: paidActive || demoActive,
    demo_active: demoActive,
    demo_ends_at: demoActive ? demoEndsAt : null
  };
}

// Vraie porte d'entrée avant chaque analyse — remplace useFreeAnalysis() côté client,
// qui pouvait être contourné en modifiant le localStorage.
export async function consumeAnalysisCredit(db, userId) {
  const sub = await getSubscription(db, userId);
  if (sub.active) return true;
  if (sub.free_left <= 0) return false;
  await db.prepare(
    `UPDATE subscriptions SET free_analyses_used = free_analyses_used + 1, updated_at = ? WHERE user_id = ?`
  ).bind(Date.now(), userId).run();
  return true;
}
