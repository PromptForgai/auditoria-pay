/**
 * AuditorIA — Cloudflare Worker
 * NOWPayments invoice creation + IPN (automatic activation)
 *
 * Env vars (Cloudflare dashboard → Worker → Settings → Variables):
 *   NOWPAYMENTS_API_KEY  = your API key
 *   IPN_SECRET           = optional secret you set in NOWPayments IPN settings
 *
 * KV namespace binding (optional but recommended):
 *   SUBS  = KV namespace for storing paid orders
 */

const NP_API = "https://api.nowpayments.io/v1";

const PLANS = {
  starter: { price: 2000, name: "AuditorIA Starter — Monthly" },
  growth:  { price: 5000, name: "AuditorIA Growth — Monthly" },
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, "") || "/";

    // CORS
    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }

    try {
      if (path === "/create-invoice" && request.method === "POST") {
        return cors(await createInvoice(request, env));
      }
      if (path === "/ipn" && request.method === "POST") {
        return await handleIpn(request, env);
      }
      if (path === "/status" && request.method === "GET") {
        return cors(await getStatus(url, env));
      }
      return cors(json({ ok: true, service: "AuditorIA payments", endpoints: ["/create-invoice", "/ipn", "/status"] }));
    } catch (e) {
      return cors(json({ error: e.message || "Server error" }, 500));
    }
  },
};

async function createInvoice(request, env) {
  const body = await request.json().catch(() => ({}));
  const plan = (body.plan || "starter").toLowerCase();
  if (!PLANS[plan]) return json({ error: "Invalid plan" }, 400);

  const apiKey = env.NOWPAYMENTS_API_KEY;
  if (!apiKey) return json({ error: "NOWPAYMENTS_API_KEY not configured" }, 500);

  const orderId = `auditoria-${plan}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const successUrl = body.success_url || "https://YOUR_SITE/activated.html";
  const siteBase = body.site_base || "";

  const payload = {
    price_amount: PLANS[plan].price,
    price_currency: "usd",
    order_id: orderId,
    order_description: PLANS[plan].name,
    success_url: successUrl.includes("?")
      ? `${successUrl}&order_id=${orderId}&plan=${plan}`
      : `${successUrl}?order_id=${orderId}&plan=${plan}`,
    is_fixed_rate: true,
    is_fee_paid_by_user: false,
  };

  if (env.IPN_SECRET) {
    // IPN URL = this worker /ipn
    const workerOrigin = new URL(request.url).origin;
    payload.ipn_callback_url = `${workerOrigin}/ipn`;
  }

  const res = await fetch(`${NP_API}/invoice`, {
    method: "POST",
    headers: {
      "x-api-key": apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    return json({ error: data.message || data.error || "NOWPayments error", details: data }, res.status);
  }

  // Store pending order
  if (env.SUBS) {
    await env.SUBS.put(`order:${orderId}`, JSON.stringify({
      plan,
      status: "pending",
      created: Date.now(),
      invoice_id: data.id,
    }), { expirationTtl: 60 * 60 * 24 * 7 }); // 7 days
  }

  return json({
    order_id: orderId,
    invoice_url: data.invoice_url,
    invoice_id: data.id,
  });
}

async function handleIpn(request, env) {
  const raw = await request.text();
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return new Response("bad json", { status: 400 });
  }

  // Optional: verify signature if IPN_SECRET is set
  // NOWPayments sends x-nowpayments-sig header (HMAC SHA-512 of sorted JSON)
  const status = (body.payment_status || body.status || "").toLowerCase();
  const orderId = body.order_id;
  const paid = ["finished", "confirmed", "finished"].includes(status) || status === "finished";

  // Accept finished / confirmed
  const okStatuses = ["finished", "confirmed", "partially_paid"];
  const isPaid = okStatuses.includes(status);

  if (orderId && env.SUBS && isPaid) {
    const plan = (orderId.includes("growth") ? "growth" : "starter");
    await env.SUBS.put(`order:${orderId}`, JSON.stringify({
      plan,
      status: "paid",
      paid_at: Date.now(),
      payment_id: body.payment_id,
      payment_status: status,
    }), { expirationTtl: 60 * 60 * 24 * 40 }); // ~40 days
    await env.SUBS.put(`paid:${orderId}`, "1", { expirationTtl: 60 * 60 * 24 * 40 });
  }

  return new Response("OK", { status: 200 });
}

async function getStatus(url, env) {
  const orderId = url.searchParams.get("order_id");
  if (!orderId) return json({ error: "order_id required" }, 400);
  if (!env.SUBS) return json({ status: "unknown", note: "KV not configured" });

  const raw = await env.SUBS.get(`order:${orderId}`);
  if (!raw) return json({ status: "not_found" });
  const data = JSON.parse(raw);
  return json({
    order_id: orderId,
    status: data.status,
    plan: data.plan,
    paid: data.status === "paid",
  });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function cors(res) {
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  return new Response(res.body, { status: res.status, headers });
}
