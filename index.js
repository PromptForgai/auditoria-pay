// index.js — Worker principal du moteur réel AuditorIA
// À fusionner avec ton Worker existant auditoria-pay (mêmes bindings D1/R2, même domaine).
// Toutes les routes exigent un userId authentifié — adapte getUserId() à ton système de login.

import { extractDocument } from './extraction.js';
import { runAllRules } from './rules.js';
import { getFullSummary } from './summary.js';
import { createInvoice, handleIpn, getOrderStatus, getSubscription, consumeAnalysisCredit } from './payments.js';
import {
  signup, login, logout, requestPasswordReset, resetPassword,
  getUserIdFromSession, readSessionCookie, sessionCookieHeader, clearSessionCookieHeader
} from './auth.js';

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', ...extraHeaders }
  });
}

// Envoi d'email — branche un vrai fournisseur (Resend, Postmark...) avant la prod.
// Sans clé configurée, le lien est juste loggé (utile en dev, jamais suffisant en prod).
async function sendResetEmail(env, toEmail, token) {
  const resetUrl = `${env.APP_URL}/reset-password.html?token=${token}`;
  if (!env.RESEND_API_KEY) {
    console.log(`[dev] Lien de réinitialisation pour ${toEmail}: ${resetUrl}`);
    return;
  }
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.EMAIL_FROM,
      to: toEmail,
      subject: 'Réinitialisation de votre mot de passe AuditorIA',
      html: `<p>Cliquez sur ce lien pour choisir un nouveau mot de passe (valable 1 heure) :</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
    })
  });
}

// Vérifie la session réelle (cookie httpOnly) — remplace le X-User-Id de confiance.
// Chaque requête vers /upload, /extract, /analyze, /findings passe par ici :
// impossible de lire les données d'un autre utilisateur sans son cookie de session valide.
async function getUserId(request, env) {
  const token = readSessionCookie(request);
  const userId = await getUserIdFromSession(env.AUDITORIA_DB, token);
  if (!userId) throw new Error('unauthenticated');
  return userId;
}

async function normalizeAndStore(db, documentId, userId, kind, fields) {
  // Range les champs extraits dans la table normalisée correspondante.
  if (kind === 'invoice') {
    await db.prepare(
      `INSERT INTO invoices (document_id, user_id, invoice_number, supplier_name, supplier_iban, po_number, amount, currency, invoice_date, due_date)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(documentId, userId, fields.invoice_number, fields.supplier_name, fields.supplier_iban,
      fields.po_number, fields.amount, fields.currency || 'EUR', fields.invoice_date, fields.due_date).run();
  } else if (kind === 'purchase_order') {
    await db.prepare(
      `INSERT INTO purchase_orders (document_id, user_id, po_number, supplier_name, amount, currency, order_date)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(documentId, userId, fields.po_number, fields.supplier_name, fields.amount, fields.currency || 'EUR', fields.order_date).run();
  } else if (kind === 'contract') {
    await db.prepare(
      `INSERT INTO contracts (document_id, user_id, supplier_name, contract_ref, amount, currency, start_date, end_date, auto_renew)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).bind(documentId, userId, fields.supplier_name, fields.contract_ref, fields.amount, fields.currency || 'EUR',
      fields.start_date, fields.end_date, fields.auto_renew ? 1 : 0).run();
  } else if (kind === 'bank_statement') {
    for (const tx of fields.transactions || []) {
      await db.prepare(
        `INSERT INTO bank_transactions (id, document_id, user_id, tx_date, amount, counterparty_name, counterparty_iban, label)
         VALUES (?,?,?,?,?,?,?,?)`
      ).bind(crypto.randomUUID(), documentId, userId, tx.tx_date, tx.amount, tx.counterparty_name, tx.counterparty_iban, tx.label).run();

      // Alimente la liste des contreparties connues (sert à checkUnusualOutflows)
      if (tx.counterparty_iban) {
        await db.prepare(
          `INSERT OR IGNORE INTO known_counterparties (user_id, iban, name, first_seen) VALUES (?,?,?,?)`
        ).bind(userId, tx.counterparty_iban, tx.counterparty_name, tx.tx_date).run();
      }
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // --- Comptes ---

      // POST /auth/signup  {email, password}
      if (url.pathname === '/auth/signup' && request.method === 'POST') {
        const { email, password } = await request.json();
        const userId = await signup(env.AUDITORIA_DB, email, password);
        const token = await login(env.AUDITORIA_DB, email, password);
        return json({ user_id: userId }, 200, { 'Set-Cookie': sessionCookieHeader(token) });
      }

      // POST /auth/login  {email, password}
      if (url.pathname === '/auth/login' && request.method === 'POST') {
        const { email, password } = await request.json();
        const token = await login(env.AUDITORIA_DB, email, password);
        return json({ ok: true }, 200, { 'Set-Cookie': sessionCookieHeader(token) });
      }

      // POST /auth/logout
      if (url.pathname === '/auth/logout' && request.method === 'POST') {
        const token = readSessionCookie(request);
        await logout(env.AUDITORIA_DB, token);
        return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookieHeader() });
      }

      // POST /auth/forgot-password  {email}
      // Répond toujours "ok", que l'email existe ou non — ne révèle jamais quels comptes existent.
      if (url.pathname === '/auth/forgot-password' && request.method === 'POST') {
        const { email } = await request.json();
        await requestPasswordReset(env.AUDITORIA_DB, email, (to, token) => sendResetEmail(env, to, token));
        return json({ ok: true });
      }

      // POST /auth/reset-password  {token, new_password}
      if (url.pathname === '/auth/reset-password' && request.method === 'POST') {
        const { token, new_password } = await request.json();
        await resetPassword(env.AUDITORIA_DB, token, new_password);
        return json({ ok: true });
      }

      // --- Paiements (NOWPayments) ---

      // POST /create-invoice  {plan, success_url}  — protégé : la commande est liée au compte connecté
      if (url.pathname === '/create-invoice' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        const { plan, success_url } = await request.json();
        const workerOrigin = new URL(request.url).origin;
        const invoice = await createInvoice(
          env.AUDITORIA_DB, userId, plan,
          success_url || `${env.APP_URL}/activated.html`,
          workerOrigin, env.NOWPAYMENTS_API_KEY, env.IPN_SECRET
        );
        return json(invoice);
      }

      // POST /ipn — appelé par les serveurs NOWPayments, jamais par le navigateur du client.
      // Toute requête sans signature HMAC valide est rejetée : c'est ce qui empêche quiconque
      // de POST une fausse confirmation de paiement pour s'activer gratuitement.
      if (url.pathname === '/ipn' && request.method === 'POST') {
        const rawBody = await request.text();
        const sig = request.headers.get('x-nowpayments-sig');
        try {
          await handleIpn(env.AUDITORIA_DB, rawBody, sig, env.IPN_SECRET);
          return new Response('OK', { status: 200 });
        } catch (err) {
          return new Response(err.message, { status: 401 });
        }
      }

      // GET /status?order_id=...  — utilisé par activated.html pour savoir si la commande est payée.
      // order_id est un identifiant aléatoire non devinable, généré côté serveur : pas besoin de
      // session pour cette route de polling public, mais elle ne renvoie que le statut, jamais de données de compte.
      if (url.pathname === '/status' && request.method === 'GET') {
        const orderId = url.searchParams.get('order_id');
        if (!orderId) return json({ error: 'order_id requis' }, 400);
        return json(await getOrderStatus(env.AUDITORIA_DB, orderId));
      }

      // GET /subscription — seule source de vérité sur l'abonnement, jamais le localStorage du client.
      if (url.pathname === '/subscription' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        return json(await getSubscription(env.AUDITORIA_DB, userId));
      }

      // --- Documents & analyse (routes protégées) ---

      // POST /upload  — multipart/form-data: file, kind
      if (url.pathname === '/upload' && request.method === 'POST') {
        const userId = await getUserId(request, env);

        // Vérification réelle du quota AVANT tout traitement — c'est ici, pas dans le navigateur,
        // que la limite gratuite / l'abonnement actif est appliquée.
        const allowed = await consumeAnalysisCredit(env.AUDITORIA_DB, userId);
        if (!allowed) return json({ error: 'free_limit_reached' }, 402);
        const form = await request.formData();
        const file = form.get('file');
        const kind = form.get('kind'); // invoice | purchase_order | contract | bank_statement
        if (!file || !kind) return json({ error: 'file et kind requis' }, 400);

        const documentId = crypto.randomUUID();
        const r2Key = `${userId}/${documentId}-${file.name}`;
        await env.AUDITORIA_BUCKET.put(r2Key, await file.arrayBuffer());

        await env.AUDITORIA_DB.prepare(
          `INSERT INTO documents (id, user_id, kind, r2_key, filename, status, uploaded_at) VALUES (?,?,?,?,?,?,?)`
        ).bind(documentId, userId, kind, r2Key, file.name, 'uploaded', Date.now()).run();

        return json({ document_id: documentId, status: 'uploaded' });
      }

      // POST /extract/:id — lance l'extraction IA sur un document déjà uploadé
      if (url.pathname.startsWith('/extract/') && request.method === 'POST') {
        const userId = await getUserId(request, env);
        const documentId = url.pathname.split('/')[2];

        const doc = await env.AUDITORIA_DB.prepare(
          `SELECT * FROM documents WHERE id = ? AND user_id = ?`
        ).bind(documentId, userId).first();
        if (!doc) return json({ error: 'document introuvable' }, 404);

        const obj = await env.AUDITORIA_BUCKET.get(doc.r2_key);
        if (!obj) return json({ error: 'fichier introuvable dans R2' }, 404);

        const isPdf = doc.filename?.toLowerCase().endsWith('.pdf');
        const input = isPdf
          ? { pdfBase64: btoa(String.fromCharCode(...new Uint8Array(await obj.arrayBuffer()))) }
          : { text: await obj.text() }; // CSV/texte lu directement

        const fields = await extractDocument(doc.kind, input, env.GEMINI_API_KEY);

        await env.AUDITORIA_DB.prepare(
          `INSERT INTO extractions (document_id, kind, data_json) VALUES (?,?,?)`
        ).bind(documentId, doc.kind, JSON.stringify(fields)).run();

        await normalizeAndStore(env.AUDITORIA_DB, documentId, userId, doc.kind, fields);

        await env.AUDITORIA_DB.prepare(
          `UPDATE documents SET status = 'extracted', extracted_at = ? WHERE id = ?`
        ).bind(Date.now(), documentId).run();

        return json({ document_id: documentId, status: 'extracted', fields });
      }

      // POST /analyze — relance toutes les règles pour l'utilisateur (à appeler après chaque extraction,
      // ou en cron périodique pour les échéances de contrat)
      if (url.pathname === '/analyze' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        const findings = await runAllRules(env.AUDITORIA_DB, userId);
        return json({ findings_created: findings.length, findings });
      }

      // GET /findings — remplace le tableau baseAlerts codé en dur du frontend
      if (url.pathname === '/findings' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        const { results } = await env.AUDITORIA_DB.prepare(
          `SELECT * FROM findings WHERE user_id = ? AND status = 'open' ORDER BY created_at DESC LIMIT 50`
        ).bind(userId).all();
        return json({ findings: results });
      }

      // GET /summary — remplace les tableaux figés d'initCharts() : trésorerie, économies,
      // flux entrants/sortants calculés à partir des vraies transactions et alertes stockées.
      if (url.pathname === '/summary' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        const summary = await getFullSummary(env.AUDITORIA_DB, userId);
        return json(summary);
      }

      return json({ error: 'not found' }, 404);
    } catch (err) {
      if (err.message === 'unauthenticated') return json({ error: 'non authentifié' }, 401);
      return json({ error: err.message }, 500);
    }
  }
};
