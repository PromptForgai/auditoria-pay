// index.js — Worker principal AuditorIA : comptes, paiements NOWPayments, analyse de documents.
// Sert aussi le site (dossier public/) via [assets] dans wrangler.toml.
// Les routes de données exigent une session valide (cookie httpOnly) : voir getUserId().

import { extractDocument, classifyDocument } from './extraction.js';
import { runAllRules } from './rules.js';
import { getFullSummary } from './summary.js';
import { createInvoice, handleIpn, getOrderStatus, getSubscription, consumeAnalysisCredit, refundAnalysisCredit } from './payments.js';
import {
  signup, login, logout, requestPasswordReset, resetPassword, changePassword, createSession,
  getUserIdFromSession, readSessionCookie, sessionCookieHeader, clearSessionCookieHeader
} from './auth.js';
import { HttpError } from './errors.js';
import { hitRateLimit, clientIp, purgeRateLimits } from './ratelimit.js';
import { createDiditSession, verifyDiditWebhook, mapDiditStatus } from './kyc_didit.js';
import { extractPdfInfo } from './pdf_metadata.js';

const MINUTE = 60_000, HOUR = 3_600_000, DAY = 86_400_000;

// Limites d'upload. D1 refuse une ligne de plus de 2 Mo ; le base64 gonfle un fichier d'environ un tiers,
// donc 1,4 Mo de fichier ≈ 1,87 Mo stockés. Au-delà, il faudrait passer par R2.
// En dessous de ce seuil : stockage direct en D1 (rapide, inchangé). Au-delà : R2 (voir
// wrangler.toml et README, section "Fichiers volumineux"). 1,4 Mo ≈ juste sous ce qu'une ligne D1
// peut tenir une fois le fichier encodé en base64 (limite D1 de 2 Mo par ligne, encodage +33%).
const MAX_FILE_BYTES_D1 = 1_400_000;
// Plafond global. Au-delà de 10 Mo, le risque de dépasser les limites de taille de requête du modèle
// d'IA (non documentées précisément par OpenRouter) devient réel — à relever prudemment si besoin,
// pas un calcul exact comme pour le seuil D1 ci-dessus.
const MAX_FILE_BYTES = 10_000_000;
const ALLOWED_KINDS = ['invoice', 'purchase_order', 'contract', 'bank_statement'];
// 'auto' : le type réel est déterminé document par document à l'extraction (classifyDocument), pour
// accepter un envoi groupé de fichiers de types différents sans que le client ait à les trier.
const UPLOAD_KINDS = [...ALLOWED_KINDS, 'auto'];
const MAX_TRANSACTIONS = 1000;

// Pas d'en-tête CORS : le site et l'API sont servis par le même Worker (même origine).
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders
    }
  });
}

async function readJson(request) {
  let body;
  try { body = await request.json(); } catch { throw new HttpError(400, 'requête JSON invalide'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'requête JSON invalide');
  return body;
}

// Encode par blocs de 8ko : String.fromCharCode(...bigArray) plante sur les gros fichiers
// (dépassement de la pile d'appel avec l'opérateur spread sur un grand tableau).
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToText(base64) {
  return new TextDecoder().decode(Uint8Array.from(atob(base64), c => c.charCodeAt(0)));
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha256HexText(text) {
  return sha256Hex(new TextEncoder().encode(text).buffer);
}
function generateVerificationCode() {
  // 6 chiffres, dont le premier peut être 0 (padStart) : 1 000 000 combinaisons, code à usage limité
  // dans le temps (15 min) et en tentatives (voir EMAIL_CODE_MAX_ATTEMPTS), pas un secret cryptographique.
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, '0');
}
const EMAIL_CODE_DURATION_MS = 15 * 60 * 1000;
const EMAIL_CODE_MAX_ATTEMPTS = 8;

// Envoi de l'email de réinitialisation. Fournisseurs pris en charge, dans cet ordre :
//  1. Brevo (BREVO_API_KEY + EMAIL_SENDER, l'adresse expéditrice validée dans Brevo)
//  2. Resend (RESEND_API_KEY, EMAIL_FROM)
// Sans aucune clé, le lien est seulement écrit dans les logs du Worker : aucun email n'est envoyé.
// Le lien ouvre la page d'accueil, qui affiche le formulaire "nouveau mot de passe" (paramètre reset_token).
async function sendResetEmail(env, toEmail, token) {
  const resetUrl = `${env.APP_URL}/?reset_token=${token}`;
  const subject = 'Réinitialisation de votre mot de passe AuditorIA';
  const html = `<p>Cliquez sur ce lien pour choisir un nouveau mot de passe (valable 1 heure) :</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>`;
  await sendEmail(env, toEmail, subject, html, `[dev] Lien de réinitialisation pour ${toEmail}: ${resetUrl}`);
}

// Email de confirmation à l'inscription : un code à 6 chiffres, valable 15 minutes, entré dans l'appli
// (pas un lien à cliquer) pour rester dans le même onglet juste après l'inscription.
async function sendVerificationEmail(env, toEmail, code) {
  const subject = 'Confirmez votre adresse email — AuditorIA';
  const html = `<p>Voici votre code de confirmation (valable 15 minutes) :</p><p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p><p>Si vous n'êtes pas à l'origine de cette inscription, ignorez cet email.</p>`;
  await sendEmail(env, toEmail, subject, html, `[dev] Code de confirmation pour ${toEmail}: ${code}`);
}

// Email d'alerte envoyé après une analyse qui a trouvé de nouvelles anomalies (voir /analyze) — sans
// ça, un client qui ne revient pas sur le site ne découvrirait une anomalie que des semaines plus
// tard, par hasard. findings = les constats nouvellement créés par CETTE analyse (pas le total des
// alertes ouvertes), pour que l'email corresponde exactement à ce que le client vient de voir en toast.
async function sendAnomalyAlertEmail(env, toEmail, lang, findings) {
  const fr = lang !== 'en';
  const nb = findings.length;
  const nbCritical = findings.filter(f => f.type === 'critical').length;
  const subject = fr
    ? `${nb} anomalie${nb > 1 ? 's' : ''} détectée${nb > 1 ? 's' : ''}${nbCritical ? `, dont ${nbCritical} critique${nbCritical > 1 ? 's' : ''}` : ''} — AuditorIA`
    : `${nb} anomal${nb > 1 ? 'ies' : 'y'} detected${nbCritical ? `, ${nbCritical} critical` : ''} — AuditorIA`;
  // Titre et description viennent de documents importés par le client lui-même (donnée qu'il contrôle,
  // mais jamais interprétée comme du HTML) : échappement avant insertion, comme côté dashboard.
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const items = findings.slice(0, 10).map(f =>
    `<li><strong>${esc(f.title)}</strong>${f.type === 'critical' ? (fr ? ' (critique)' : ' (critical)') : ''} — ${esc(f.description)}</li>`
  ).join('');
  const more = nb > 10 ? `<p>${fr ? `… et ${nb - 10} de plus.` : `… and ${nb - 10} more.`}</p>` : '';
  const dashboardUrl = `${env.APP_URL}/?`; // page d'accueil : redemande une connexion si la session a expiré, par sécurité
  const html = fr
    ? `<p>${nb} nouvelle${nb > 1 ? 's' : ''} anomalie${nb > 1 ? 's' : ''} détectée${nb > 1 ? 's' : ''} sur tes documents :</p><ul>${items}</ul>${more}<p><a href="${dashboardUrl}">Voir le détail sur AuditorIA</a></p>`
    : `<p>${nb} new anomal${nb > 1 ? 'ies' : 'y'} detected on your documents:</p><ul>${items}</ul>${more}<p><a href="${dashboardUrl}">View details on AuditorIA</a></p>`;
  await sendEmail(env, toEmail, subject, html, `[dev] Alerte anomalies pour ${toEmail}: ${nb} (${nbCritical} critiques)`);
}

// Envoyeur générique (Brevo, sinon Resend, sinon simple log en développement) — factorisé pour que
// le lien de réinitialisation et le code de confirmation d'inscription partagent le même mécanisme.
async function sendEmail(env, toEmail, subject, html, devLogFallback) {
  if (env.BREVO_API_KEY && env.EMAIL_SENDER) {
    const res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'accept': 'application/json', 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json' },
      body: JSON.stringify({
        sender: { name: 'AuditorIA', email: env.EMAIL_SENDER },
        to: [{ email: toEmail }],
        subject,
        htmlContent: html
      })
    });
    if (!res.ok) console.error('Échec envoi email Brevo:', res.status, await res.text());
    return;
  }

  if (env.RESEND_API_KEY) {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: env.EMAIL_FROM || 'AuditorIA <onboarding@resend.dev>',
        to: toEmail,
        subject,
        html
      })
    });
    if (!res.ok) console.error('Échec envoi email Resend:', res.status, await res.text());
    return;
  }

  console.log(devLogFallback || `[dev] Email pour ${toEmail} — ${subject}`);
}

// Vérifie la session réelle (cookie httpOnly) — remplace le X-User-Id de confiance.
// Chaque requête vers /upload, /extract, /analyze, /findings passe par ici :
// impossible de lire les données d'un autre utilisateur sans son cookie de session valide.
async function getUserId(request, env) {
  const token = readSessionCookie(request);
  const userId = await getUserIdFromSession(env.AUDITORIA_DB, token);
  if (!userId) throw new HttpError(401, 'non authentifié');
  return userId;
}

// success_url vient du navigateur : on n'accepte que notre propre domaine (sinon la page de retour
// de NOWPayments pourrait renvoyer le client vers un site tiers).
function safeSuccessUrl(candidate, env) {
  const fallback = `${env.APP_URL}/activated.html`;
  if (typeof candidate !== 'string') return fallback;
  try {
    const u = new URL(candidate);
    if (u.origin !== new URL(env.APP_URL).origin) return fallback;
    return u.origin + u.pathname; // on jette la query/hash : createInvoice y ajoute order_id et plan
  } catch {
    return fallback;
  }
}

// --- Normalisation des champs extraits par le modèle ---
const str = v => (typeof v === 'string' && v.trim()) ? v.trim().slice(0, 300) : null;
const normIban = v => { const s = str(v); return s ? s.replace(/\s+/g, '').toUpperCase() : null; };
const normRef = v => { const s = str(v); return s ? s.toUpperCase() : null; };
const normDate = v => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}/.test(v.trim())) ? v.trim().slice(0, 10) : null;
const normCur = v => (typeof v === 'string' && /^[A-Za-z]{3}$/.test(v.trim())) ? v.trim().toUpperCase() : 'EUR';
const isNum = v => typeof v === 'number' && Number.isFinite(v);

// Valide et range les champs extraits : renvoie la LISTE des instructions SQL à exécuter.
// Elles partent toutes dans un seul db.batch() (transaction) : un document est importé en entier ou pas du tout,
// et le nombre de requêtes D1 ne dépend pas du nombre de transactions.
function buildStatements(db, documentId, userId, kind, fields) {
  if (!fields || typeof fields !== 'object') throw new HttpError(422, "Aucune donnée exploitable n'a pu être extraite.");

  if (kind === 'invoice') {
    if (!isNum(fields.amount)) throw new HttpError(422, 'Montant de la facture illisible : vérifie que le document est bien une facture.');
    return [db.prepare(
      `INSERT INTO invoices (document_id, user_id, invoice_number, supplier_name, supplier_iban, po_number, amount, currency, invoice_date, due_date)
       VALUES (?,?,?,?,?,?,?,?,?,?)`
    ).bind(documentId, userId, str(fields.invoice_number), str(fields.supplier_name), normIban(fields.supplier_iban),
      normRef(fields.po_number), fields.amount, normCur(fields.currency), normDate(fields.invoice_date), normDate(fields.due_date))];
  }

  if (kind === 'purchase_order') {
    if (!normRef(fields.po_number) || !isNum(fields.amount)) throw new HttpError(422, 'Numéro ou montant du bon de commande illisible.');
    return [db.prepare(
      `INSERT INTO purchase_orders (document_id, user_id, po_number, supplier_name, amount, currency, order_date)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(documentId, userId, normRef(fields.po_number), str(fields.supplier_name), fields.amount, normCur(fields.currency), normDate(fields.order_date))];
  }

  if (kind === 'contract') {
    return [db.prepare(
      `INSERT INTO contracts (document_id, user_id, supplier_name, contract_ref, amount, currency, start_date, end_date, auto_renew)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).bind(documentId, userId, str(fields.supplier_name), str(fields.contract_ref), isNum(fields.amount) ? fields.amount : null,
      normCur(fields.currency), normDate(fields.start_date), normDate(fields.end_date), fields.auto_renew ? 1 : 0)];
  }

  if (kind === 'bank_statement') {
    const txs = (Array.isArray(fields.transactions) ? fields.transactions : [])
      .map(tx => ({
        date: normDate(tx && tx.tx_date),
        amount: tx && tx.amount,
        name: str(tx && tx.counterparty_name),
        iban: normIban(tx && tx.counterparty_iban),
        label: str(tx && tx.label)
      }))
      .filter(tx => tx.date && isNum(tx.amount)); // une date non ISO casserait strftime et toutes les requêtes du dashboard

    if (!txs.length) throw new HttpError(422, 'Aucune transaction exploitable trouvée dans ce relevé.');
    if (txs.length > MAX_TRANSACTIONS) throw new HttpError(413, `Relevé trop volumineux (${MAX_TRANSACTIONS} lignes maximum par fichier) : découpe-le par période.`);

    // Insertions multi-lignes : 8 paramètres par ligne × 12 lignes = 96, sous la limite D1 de 100 paramètres par requête.
    const statements = [];
    for (let i = 0; i < txs.length; i += 12) {
      const chunk = txs.slice(i, i + 12);
      const placeholders = chunk.map(() => '(?,?,?,?,?,?,?,?)').join(',');
      const params = chunk.flatMap(tx => [crypto.randomUUID(), documentId, userId, tx.date, tx.amount, tx.name, tx.iban, tx.label]);
      statements.push(db.prepare(
        `INSERT INTO bank_transactions (id, document_id, user_id, tx_date, amount, counterparty_name, counterparty_iban, label) VALUES ${placeholders}`
      ).bind(...params));
    }
    return statements;
  }

  throw new HttpError(400, 'type de document inconnu');
}

// Supprime un document dont l'extraction a échoué et rend l'essai gratuit consommé à l'upload.
// La condition sur status garantit qu'on ne rembourse qu'une fois et qu'on ne touche jamais un document déjà extrait.
async function discardFailedDocument(db, doc, userId, env) {
  try {
    const del = await db.prepare(
      `DELETE FROM documents WHERE id = ? AND user_id = ? AND status = 'extracting'`
    ).bind(doc.id, userId).run();
    if (del.meta.changes && doc.credit_used) await refundAnalysisCredit(db, userId, doc.credit_used);
    // Évite un objet R2 orphelin (jamais nettoyé autrement) si ce document y était stocké.
    if (del.meta.changes && doc.r2_key && env.AUDITORIA_BUCKET) {
      await env.AUDITORIA_BUCKET.delete(doc.r2_key).catch(err => console.error('Échec suppression R2:', err));
    }
  } catch (err) {
    console.error('Échec du nettoyage après erreur d\'extraction:', err);
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const db = env.AUDITORIA_DB;
    const ip = clientIp(request);

    try {
      // --- Comptes ---

      // POST /auth/signup  {email, password}
      if (url.pathname === '/auth/signup' && request.method === 'POST') {
        // 5 inscriptions par IP et par jour : freine l'enchaînement de comptes jetables pour
        // relancer la démo de 15 min et les essais gratuits en boucle.
        if (await hitRateLimit(db, `signup:${ip}`, 5, DAY)) throw new HttpError(429, "Trop d'inscriptions depuis cette connexion. Réessaie demain.");
        ctx.waitUntil(purgeRateLimits(db));
        const { email, password } = await readJson(request);
        const userId = await signup(db, email, password, ip); // ip : voir "1 compte par IP" dans auth.js
        const token = await createSession(db, userId);

        // Code de confirmation d'email : envoyé en arrière-plan, ne bloque jamais la création du compte
        // (une panne d'envoi ne doit pas empêcher quelqu'un de s'inscrire).
        const code = generateVerificationCode();
        const codeHash = await sha256HexText(code);
        const now = Date.now();
        await db.prepare(
          `INSERT INTO email_verification_codes (user_id, code_hash, attempts, created_at, expires_at) VALUES (?,?,0,?,?)
           ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, attempts = 0, created_at = excluded.created_at, expires_at = excluded.expires_at`
        ).bind(userId, codeHash, now, now + EMAIL_CODE_DURATION_MS).run();
        ctx.waitUntil(sendVerificationEmail(env, email.trim().toLowerCase(), code));

        return json({ user_id: userId }, 200, { 'Set-Cookie': sessionCookieHeader(token) });
      }

      // POST /auth/login  {email, password}
      if (url.pathname === '/auth/login' && request.method === 'POST') {
        const { email, password } = await readJson(request);
        const emailKey = typeof email === 'string' ? email.trim().toLowerCase().slice(0, 254) : '';
        const tooMany =
          (await hitRateLimit(db, `login-ip:${ip}`, 30, 15 * MINUTE)) ||
          (await hitRateLimit(db, `login-email:${emailKey}`, 10, 15 * MINUTE));
        if (tooMany) throw new HttpError(429, 'Trop de tentatives. Réessaie dans quelques minutes.');
        const token = await login(db, email, password);
        return json({ ok: true }, 200, { 'Set-Cookie': sessionCookieHeader(token) });
      }

      // POST /auth/logout
      if (url.pathname === '/auth/logout' && request.method === 'POST') {
        const token = readSessionCookie(request);
        await logout(db, token);
        return json({ ok: true }, 200, { 'Set-Cookie': clearSessionCookieHeader() });
      }

      // POST /auth/forgot-password  {email}
      // Répond toujours "ok", que l'email existe ou non, et envoie l'email en arrière-plan :
      // ni le message ni le temps de réponse ne révèlent quels comptes existent.
      if (url.pathname === '/auth/forgot-password' && request.method === 'POST') {
        if (await hitRateLimit(db, `forgot-ip:${ip}`, 5, HOUR)) throw new HttpError(429, 'Trop de demandes. Réessaie plus tard.');
        const { email } = await readJson(request);
        const emailKey = typeof email === 'string' ? email.trim().toLowerCase().slice(0, 254) : '';
        // Limite par adresse (3/h) : au-delà, on répond "ok" sans rien envoyer (pas d'inondation de la boîte d'un tiers).
        if (!(await hitRateLimit(db, `forgot-email:${emailKey}`, 3, HOUR))) {
          const reset = await requestPasswordReset(db, email);
          if (reset) ctx.waitUntil(sendResetEmail(env, reset.email, reset.token));
        }
        return json({ ok: true });
      }

      // POST /auth/reset-password  {token, new_password}
      if (url.pathname === '/auth/reset-password' && request.method === 'POST') {
        if (await hitRateLimit(db, `reset-ip:${ip}`, 10, HOUR)) throw new HttpError(429, 'Trop de tentatives. Réessaie plus tard.');
        const { token, new_password } = await readJson(request);
        await resetPassword(db, token, new_password);
        return json({ ok: true });
      }

      // POST /auth/verify-email  {code}  — confirme l'email du compte connecté
      if (url.pathname === '/auth/verify-email' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `verify-email:${userId}`, 15, HOUR)) throw new HttpError(429, 'Trop de tentatives. Réessaie plus tard.');
        const { code } = await readJson(request);
        if (typeof code !== 'string' || !code) throw new HttpError(400, 'code requis');

        const row = await db.prepare(`SELECT * FROM email_verification_codes WHERE user_id = ?`).bind(userId).first();
        if (!row || row.expires_at < Date.now()) throw new HttpError(400, 'Code expiré ou introuvable. Demande-en un nouveau.');
        if (row.attempts >= EMAIL_CODE_MAX_ATTEMPTS) throw new HttpError(429, 'Trop de tentatives pour ce code. Demande-en un nouveau.');

        const codeHash = await sha256HexText(code.trim());
        if (codeHash !== row.code_hash) {
          await db.prepare(`UPDATE email_verification_codes SET attempts = attempts + 1 WHERE user_id = ?`).bind(userId).run();
          throw new HttpError(400, 'Code incorrect.');
        }

        await db.prepare(`UPDATE users SET email_verified = 1 WHERE id = ?`).bind(userId).run();
        await db.prepare(`DELETE FROM email_verification_codes WHERE user_id = ?`).bind(userId).run();
        return json({ ok: true });
      }

      // POST /auth/resend-verification — renvoie un nouveau code (remplace l'ancien)
      if (url.pathname === '/auth/resend-verification' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `resend-verify:${userId}`, 5, HOUR)) throw new HttpError(429, 'Trop de demandes. Réessaie plus tard.');
        const user = await db.prepare(`SELECT email, email_verified FROM users WHERE id = ?`).bind(userId).first();
        if (!user) throw new HttpError(401, 'non authentifié');
        if (user.email_verified) return json({ ok: true }); // déjà confirmé : rien à renvoyer

        const code = generateVerificationCode();
        const codeHash = await sha256HexText(code);
        const now = Date.now();
        await db.prepare(
          `INSERT INTO email_verification_codes (user_id, code_hash, attempts, created_at, expires_at) VALUES (?,?,0,?,?)
           ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, attempts = 0, created_at = excluded.created_at, expires_at = excluded.expires_at`
        ).bind(userId, codeHash, now, now + EMAIL_CODE_DURATION_MS).run();
        ctx.waitUntil(sendVerificationEmail(env, user.email, code));
        return json({ ok: true });
      }

      // --- Paiements (NOWPayments) ---

      // POST /create-invoice  {plan, cycle, success_url}  — protégé : la commande est liée au compte connecté.
      // Le prix vient de PLANS[plan][cycle] côté serveur (payments.js) : le client choisit, mais ne fixe pas le montant.
      if (url.pathname === '/create-invoice' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `invoice:${userId}`, 10, HOUR)) throw new HttpError(429, 'Trop de demandes de paiement. Réessaie plus tard.');
        const { plan, cycle, success_url } = await readJson(request);
        const invoice = await createInvoice(
          db, userId, plan, cycle,
          safeSuccessUrl(success_url, env),
          url.origin, env.NOWPAYMENTS_API_KEY, env.IPN_SECRET
        );
        return json(invoice);
      }

      // POST /ipn — appelé par les serveurs NOWPayments, jamais par le navigateur du client.
      // Toute requête sans signature HMAC valide est rejetée (401) : c'est ce qui empêche quiconque
      // de POST une fausse confirmation de paiement pour s'activer gratuitement.
      // Toute autre erreur (base indisponible...) renvoie 500 pour que NOWPayments RÉESSAIE l'envoi :
      // avant, une panne passagère répondait 401 et le paiement pouvait ne jamais être crédité.
      if (url.pathname === '/ipn' && request.method === 'POST') {
        const rawBody = await request.text();
        const sig = request.headers.get('x-nowpayments-sig');
        try {
          await handleIpn(db, rawBody, sig, env.IPN_SECRET);
          return new Response('OK', { status: 200 });
        } catch (err) {
          if (err instanceof HttpError) return new Response(err.message, { status: err.status });
          console.error('Erreur IPN:', err);
          return new Response('erreur interne', { status: 500 });
        }
      }

      // GET /status?order_id=...  — utilisé par activated.html pour savoir si la commande est payée.
      // order_id est un identifiant aléatoire non devinable, généré côté serveur : pas besoin de
      // session pour cette route de polling public, mais elle ne renvoie que le statut, jamais de données de compte.
      if (url.pathname === '/status' && request.method === 'GET') {
        const orderId = url.searchParams.get('order_id');
        if (!orderId) throw new HttpError(400, 'order_id requis');
        return json(await getOrderStatus(db, orderId));
      }

      // GET /subscription — seule source de vérité sur l'abonnement, jamais le localStorage du client.
      if (url.pathname === '/subscription' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        return json(await getSubscription(db, userId));
      }

      // POST /account/change-password  {current_password, new_password}
      // Distinct de /auth/reset-password : celle-ci exige une session active plutôt qu'un jeton reçu par email.
      if (url.pathname === '/account/change-password' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `changepw:${userId}`, 10, HOUR)) throw new HttpError(429, 'Trop de tentatives. Réessaie plus tard.');
        const token = readSessionCookie(request);
        const { current_password, new_password } = await readJson(request);
        await changePassword(db, userId, token, current_password, new_password);
        return json({ ok: true });
      }

      // GET /me — identité du compte connecté (menu du dashboard, bandeau de confirmation d'email).
      // Email, statut de vérification et langue préférée uniquement : jamais le hash du mot de passe
      // ni l'IP d'inscription.
      if (url.pathname === '/me' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        const user = await db.prepare(`SELECT email, email_verified, lang FROM users WHERE id = ?`).bind(userId).first();
        if (!user) throw new HttpError(401, 'non authentifié');
        return json({ email: user.email, email_verified: !!user.email_verified, lang: user.lang || 'fr' });
      }

      // POST /account/lang  {lang: 'fr'|'en'} — langue utilisée pour les emails automatiques
      // (alertes, confirmation, réinitialisation). Appelé silencieusement à chaque changement de
      // langue dans l'interface, tant que le client est connecté.
      if (url.pathname === '/account/lang' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        const { lang } = await readJson(request);
        if (lang !== 'fr' && lang !== 'en') throw new HttpError(400, 'langue invalide');
        await db.prepare(`UPDATE users SET lang = ? WHERE id = ?`).bind(lang, userId).run();
        return json({ ok: true });
      }

      // --- Documents & analyse (routes protégées) ---

      // POST /upload  — multipart/form-data: file, kind
      if (url.pathname === '/upload' && request.method === 'POST') {
        const userId = await getUserId(request, env);

        // Email non confirmé : l'analyse de documents (donc le coût Gemini et le crédit consommé) est
        // bloquée jusqu'à confirmation. Le reste du compte (connexion, consultation) reste accessible.
        const verifyRow = await db.prepare(`SELECT email_verified FROM users WHERE id = ?`).bind(userId).first();
        if (verifyRow && !verifyRow.email_verified) throw new HttpError(403, 'email_not_verified');

        if (await hitRateLimit(db, `upload:${userId}`, 60, HOUR)) throw new HttpError(429, "Trop d'envois en peu de temps. Réessaie plus tard.");

        // 1. Validation AVANT de toucher au quota : une requête invalide ne coûte plus un essai gratuit.
        const declared = Number(request.headers.get('content-length') || 0);
        if (declared > MAX_FILE_BYTES + 200_000) throw new HttpError(413, `Fichier trop volumineux (${(MAX_FILE_BYTES / 1e6).toFixed(0)} Mo maximum).`);

        let form;
        try { form = await request.formData(); } catch { throw new HttpError(400, 'envoi invalide'); }
        const file = form.get('file');
        const kind = form.get('kind'); // invoice | purchase_order | contract | bank_statement | auto
        if (!file || typeof file === 'string' || typeof kind !== 'string') throw new HttpError(400, 'file et kind requis');
        if (!UPLOAD_KINDS.includes(kind)) throw new HttpError(400, 'type de document inconnu');
        if (file.size === 0) throw new HttpError(400, 'fichier vide');
        if (file.size > MAX_FILE_BYTES) throw new HttpError(413, `Fichier trop volumineux (${(MAX_FILE_BYTES / 1e6).toFixed(0)} Mo maximum).`);

        const filename = String(file.name || 'document').slice(0, 200);
        const ext = (filename.split('.').pop() || '').toLowerCase();
        if (!['pdf', 'csv', 'txt'].includes(ext)) throw new HttpError(415, 'Formats acceptés : PDF, CSV.');
        // En détection automatique, le vrai type n'est pas encore connu : on ne peut pas encore vérifier
        // sa cohérence avec l'extension (fait à l'extraction, une fois le type déterminé).
        if (kind !== 'auto' && ext !== 'pdf' && kind !== 'bank_statement') throw new HttpError(415, 'Ce type de document doit être envoyé en PDF (le CSV est réservé aux relevés bancaires).');

        const buffer = await file.arrayBuffer();
        if (ext === 'pdf' && new TextDecoder().decode(new Uint8Array(buffer, 0, Math.min(5, buffer.byteLength))) !== '%PDF-') {
          throw new HttpError(400, "Ce fichier n'est pas un PDF valide.");
        }

        // 2. Anti-doublon : le même fichier ne peut pas être importé deux fois (sinon un relevé réimporté
        //    doublerait les transactions, fausserait la trésorerie et déclencherait de faux "paiements en double").
        const contentHash = await sha256Hex(buffer);
        const dup = await db.prepare(
          `SELECT id, status FROM documents WHERE user_id = ? AND content_hash = ?`
        ).bind(userId, contentHash).first();
        if (dup) {
          // envoi précédent interrompu avant l'extraction : on reprend ce document, sans nouveau décompte
          if (dup.status === 'uploaded') return json({ document_id: dup.id, status: 'uploaded' });
          throw new HttpError(409, 'Ce fichier a déjà été importé.');
        }

        // Métadonnées PDF (producteur/créateur) : best-effort, voir pdf_metadata.js. Un CSV n'a pas
        // ce concept, pdfInfo reste à {producer:null, creator:null} dans ce cas.
        const pdfInfo = ext === 'pdf' ? extractPdfInfo(buffer) : { producer: null, creator: null };

        // Au-delà du seuil D1, le fichier doit aller sur R2 : vérifié ICI, avant toute écriture, pour
        // ne jamais décompter un crédit sur un envoi qui ne pourra pas aboutir.
        const needsR2 = buffer.byteLength > MAX_FILE_BYTES_D1;
        if (needsR2 && !env.AUDITORIA_BUCKET) {
          throw new HttpError(413, `Fichier trop volumineux pour le moment (${(MAX_FILE_BYTES_D1 / 1e6).toFixed(1)} Mo maximum tant que le stockage étendu n'est pas activé).`);
        }

        const documentId = crypto.randomUUID();
        const r2Key = needsR2 ? `${userId}/${documentId}/${filename}` : null;

        // 3. Quota : décompté seulement maintenant, de façon atomique (voir payments.js) — après la
        // vérification R2 ci-dessus, pour ne jamais consommer un essai sur un envoi impossible à stocker.
        const credit = await consumeAnalysisCredit(db, userId);
        if (!credit.allowed) return json({ error: credit.reason === 'plan_limit' ? 'plan_limit_reached' : 'free_limit_reached' }, 402);

        if (needsR2) {
          try {
            await env.AUDITORIA_BUCKET.put(r2Key, buffer, { httpMetadata: { contentType: ext === 'pdf' ? 'application/pdf' : 'text/csv' } });
          } catch (err) {
            await refundAnalysisCredit(db, userId, credit.creditType);
            console.error('Échec écriture R2:', err);
            throw new HttpError(502, 'Le stockage du fichier a échoué, réessaie dans un instant.');
          }
        }

        try {
          await db.prepare(
            `INSERT INTO documents (id, user_id, kind, content_base64, filename, status, uploaded_at, credit_used, content_hash, pdf_producer, pdf_creator, r2_key)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
          ).bind(documentId, userId, kind, needsR2 ? '' : arrayBufferToBase64(buffer), filename, 'uploaded', Date.now(), credit.creditType, contentHash, pdfInfo.producer, pdfInfo.creator, r2Key).run();
        } catch (err) {
          if (credit.creditType) await refundAnalysisCredit(db, userId, credit.creditType);
          throw err;
        }

        return json({ document_id: documentId, status: 'uploaded' });
      }

      // POST /extract/:id — lance l'extraction IA sur un document déjà uploadé
      if (url.pathname.startsWith('/extract/') && request.method === 'POST') {
        const userId = await getUserId(request, env);
        const documentId = url.pathname.split('/')[2];

        const doc = await db.prepare(
          `SELECT * FROM documents WHERE id = ? AND user_id = ?`
        ).bind(documentId, userId).first();
        if (!doc) throw new HttpError(404, 'document introuvable');

        // Verrou atomique : un seul appel à la fois peut traiter ce document (double clic, deux onglets...).
        const claim = await db.prepare(
          `UPDATE documents SET status = 'extracting' WHERE id = ? AND user_id = ? AND status = 'uploaded'`
        ).bind(documentId, userId).run();
        if (!claim.meta.changes) throw new HttpError(409, 'document déjà traité ou en cours de traitement');

        try {
          const isPdf = doc.filename?.toLowerCase().endsWith('.pdf');
          // Fichier volumineux : relu depuis R2 et réencodé en base64 à la volée (seulement pour la
          // durée de cet appel, jamais stocké tel quel en D1). doc.r2_key absent = chemin D1 habituel.
          let contentBase64 = doc.content_base64;
          if (doc.r2_key) {
            const obj = await env.AUDITORIA_BUCKET.get(doc.r2_key);
            if (!obj) throw new Error(`Fichier introuvable sur R2 (clé ${doc.r2_key})`); // config/cohérence interne : jamais montré au client
            contentBase64 = arrayBufferToBase64(await obj.arrayBuffer());
          }
          const input = isPdf
            ? { pdfBase64: contentBase64 }
            : { text: base64ToText(contentBase64) }; // CSV/texte

          // Type déterminé automatiquement, que ce soit un PDF ou un CSV : un CSV peut aussi être un
          // export de factures ou de bons de commande, pas seulement un relevé bancaire — on ne
          // présume plus de son contenu à partir de son extension.
          let kind = doc.kind;
          if (kind === 'auto') {
            kind = await classifyDocument(input, env.OPENROUTER_API_KEY, env.APP_URL);
          }

          const fields = await extractDocument(kind, input, env.OPENROUTER_API_KEY, env.APP_URL);
          const statements = buildStatements(db, documentId, userId, kind, fields);

          // Tout ou rien : extraction brute + lignes normalisées + statut "extracted" (et type déterminé
          // si "auto") dans une seule transaction.
          await db.batch([
            db.prepare(`INSERT INTO extractions (document_id, kind, data_json) VALUES (?,?,?)`)
              .bind(documentId, kind, JSON.stringify(fields)),
            ...statements,
            db.prepare(`UPDATE documents SET status = 'extracted', extracted_at = ?, kind = ? WHERE id = ?`)
              .bind(Date.now(), kind, documentId)
          ]);
        } catch (err) {
          await discardFailedDocument(db, doc, userId, env); // le client peut réessayer sans avoir perdu un essai
          throw err;
        }

        return json({ document_id: documentId, status: 'extracted' });
      }

      // POST /analyze — relance toutes les règles pour l'utilisateur (à appeler après chaque extraction).
      // Idempotent : un constat déjà existant n'est jamais recréé (voir fingerprint dans rules.js).
      if (url.pathname === '/analyze' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `analyze:${userId}`, 60, HOUR)) throw new HttpError(429, "Trop d'analyses en peu de temps. Réessaie plus tard.");
        const findings = await runAllRules(db, userId);

        // Email d'alerte en arrière-plan (ne retarde jamais la réponse) : seulement s'il y a au moins
        // une nouveauté, pour ne jamais écrire "0 anomalie détectée" dans un email.
        if (findings.length > 0) {
          const user = await db.prepare(`SELECT email, lang FROM users WHERE id = ?`).bind(userId).first();
          if (user) ctx.waitUntil(sendAnomalyAlertEmail(env, user.email, user.lang || 'fr', findings));
        }

        return json({ findings_created: findings.length, findings });
      }

      // GET /findings — alertes ouvertes de l'utilisateur
      if (url.pathname === '/findings' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        const { results } = await db.prepare(
          `SELECT * FROM findings WHERE user_id = ? AND status = 'open' ORDER BY created_at DESC LIMIT 50`
        ).bind(userId).all();
        return json({ findings: results });
      }

      // POST /findings/:id/status  {status: 'reviewed' | 'dismissed' | 'open'}
      // Permet de traiter une alerte (faux positif, déjà réglée). Elle ne réapparaît plus après un /analyze,
      // et une alerte "dismissed" n'est plus comptée dans les économies du dashboard.
      const statusMatch = url.pathname.match(/^\/findings\/([0-9a-f-]{36})\/status$/);
      if (statusMatch && request.method === 'POST') {
        const userId = await getUserId(request, env);
        const { status } = await readJson(request);
        if (!['open', 'reviewed', 'dismissed'].includes(status)) throw new HttpError(400, 'statut invalide');
        const res = await db.prepare(`UPDATE findings SET status = ? WHERE id = ? AND user_id = ?`)
          .bind(status, statusMatch[1], userId).run();
        if (!res.meta.changes) throw new HttpError(404, 'alerte introuvable');
        return json({ ok: true });
      }

      // GET /contracts — contrats réellement importés par le client (page "Contracts" du dashboard).
      if (url.pathname === '/contracts' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        const { results } = await db.prepare(
          `SELECT document_id, supplier_name, contract_ref, amount, currency, start_date, end_date, auto_renew
           FROM contracts WHERE user_id = ? ORDER BY (end_date IS NULL), end_date ASC`
        ).bind(userId).all();
        return json({ contracts: results });
      }

      // GET /kyc/status — profil KYC du compte connecté (sans les fichiers : juste de quoi préremplir
      // le formulaire et afficher où en est la vérification). Absence de ligne = jamais soumis.
      if (url.pathname === '/kyc/status' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        const row = await db.prepare(
          `SELECT first_name, last_name, address_line, city, postal_code, country,
                  proof_address_filename, status, submitted_at, reviewer_note,
                  identity_status, didit_status, identity_verified_at
           FROM kyc_profiles WHERE user_id = ?`
        ).bind(userId).first();
        return json({ profile: row || null });
      }

      // POST /kyc/submit — multipart/form-data : first_name, last_name, address_line, city, postal_code,
      // country, proof_address (fichier). La pièce d'identité n'est plus demandée ici : elle est
      // vérifiée automatiquement via Didit (voir /kyc/didit/start et /kyc/didit/webhook plus bas).
      // Le justificatif de domicile, lui, reste reçu et stocké pour une revue manuelle (statut "pending") :
      // ceci ne fait que RECEVOIR le document, un humain doit l'examiner pour faire passer "status" à
      // "approved" ou "rejected" (pas d'écran d'administration fourni pour l'instant).
      if (url.pathname === '/kyc/submit' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `kyc:${userId}`, 5, DAY)) throw new HttpError(429, "Trop de soumissions. Réessaie demain.");

        let form;
        try { form = await request.formData(); } catch { throw new HttpError(400, 'envoi invalide'); }

        const field = (name, max) => {
          const v = form.get(name);
          if (typeof v !== 'string' || !v.trim()) throw new HttpError(400, `${name} requis`);
          return v.trim().slice(0, max);
        };
        const firstName = field('first_name', 100);
        const lastName = field('last_name', 100);
        const addressLine = field('address_line', 200);
        const city = field('city', 100);
        const postalCode = field('postal_code', 20);
        const country = field('country', 100);

        const KYC_ALLOWED_EXT = ['pdf', 'jpg', 'jpeg', 'png']; // souvent une photo, pas seulement un PDF
        const proofFile = form.get('proof_address');
        if (!proofFile || typeof proofFile === 'string') throw new HttpError(400, 'Justificatif de domicile requis');
        if (proofFile.size === 0) throw new HttpError(400, 'Justificatif de domicile : fichier vide');
        // Reste sur le seuil D1 simple (pas de R2 pour le KYC pour l'instant) : un justificatif de
        // domicile est presque toujours une photo ou un scan d'une page, largement sous 1,4 Mo.
        if (proofFile.size > MAX_FILE_BYTES_D1) throw new HttpError(413, `Justificatif de domicile trop volumineux (${(MAX_FILE_BYTES_D1 / 1e6).toFixed(1)} Mo maximum).`);
        const proofFilename = String(proofFile.name || 'proof_address').slice(0, 200);
        const proofExt = (proofFilename.split('.').pop() || '').toLowerCase();
        if (!KYC_ALLOWED_EXT.includes(proofExt)) throw new HttpError(415, 'Justificatif de domicile : formats acceptés PDF, JPG, PNG.');
        const proofAddr = { base64: arrayBufferToBase64(await proofFile.arrayBuffer()), filename: proofFilename };

        const now = Date.now();
        // Une nouvelle soumission remplace la précédente et repart en statut "pending" : un ancien refus
        // ou une ancienne approbation ne s'applique plus à un nouveau document. La vérification d'identité
        // (identity_status, didit_*) n'est jamais touchée ici : c'est un sujet distinct.
        await db.prepare(
          `INSERT INTO kyc_profiles
             (user_id, first_name, last_name, address_line, city, postal_code, country,
              proof_address_base64, proof_address_filename, status, submitted_at, reviewed_at, reviewer_note)
           VALUES (?,?,?,?,?,?,?,?,?,'pending',?,NULL,NULL)
           ON CONFLICT(user_id) DO UPDATE SET
             first_name = excluded.first_name, last_name = excluded.last_name, address_line = excluded.address_line,
             city = excluded.city, postal_code = excluded.postal_code, country = excluded.country,
             proof_address_base64 = excluded.proof_address_base64, proof_address_filename = excluded.proof_address_filename,
             status = 'pending', submitted_at = excluded.submitted_at, reviewed_at = NULL, reviewer_note = NULL`
        ).bind(
          userId, firstName, lastName, addressLine, city, postalCode, country,
          proofAddr.base64, proofAddr.filename, now
        ).run();

        return json({ ok: true, status: 'pending' });
      }

      // POST /kyc/didit/start — crée une session de vérification d'identité Didit et renvoie son URL.
      // Le navigateur est ensuite redirigé vers cette URL (window.location.href) : la vérification se
      // déroule entièrement chez Didit, notre clé API ne quitte jamais le serveur.
      if (url.pathname === '/kyc/didit/start' && request.method === 'POST') {
        const userId = await getUserId(request, env);
        if (await hitRateLimit(db, `didit-start:${userId}`, 10, DAY)) throw new HttpError(429, "Trop de tentatives. Réessaie demain.");

        const callbackUrl = `${env.APP_URL}/?didit_return=1`;
        const { url: sessionUrl, sessionId } = await createDiditSession(userId, callbackUrl, env.DIDIT_API_KEY);

        const now = Date.now();
        // S'assure qu'une ligne existe (le client a pu ne jamais encore soumis de justificatif de
        // domicile) sans toucher aux colonnes de ce dernier si la ligne existe déjà.
        await db.prepare(
          `INSERT INTO kyc_profiles (user_id, status, submitted_at, identity_status, didit_session_id)
           VALUES (?, 'pending', ?, 'pending', ?)
           ON CONFLICT(user_id) DO UPDATE SET identity_status = 'pending', didit_session_id = excluded.didit_session_id`
        ).bind(userId, now, sessionId).run();

        return json({ url: sessionUrl });
      }

      // POST /kyc/didit/webhook — appelé par les serveurs Didit, jamais par le navigateur du client.
      // Authentifié par signature HMAC (X-Signature-V2) + fraîcheur de l'horodatage, pas par cookie :
      // il n'y a pas de session ici, exactement comme pour /ipn (NOWPayments).
      if (url.pathname === '/kyc/didit/webhook' && request.method === 'POST') {
        const rawBody = await request.text();
        const sig = request.headers.get('x-signature-v2');
        const ts = request.headers.get('x-timestamp');
        const payload = await verifyDiditWebhook(rawBody, sig, ts, env.DIDIT_WEBHOOK_SECRET);
        if (!payload) return new Response('signature invalide ou expirée', { status: 401 });

        // Anti-rejeu : Didit peut renvoyer le même évènement plusieurs fois.
        try {
          await db.prepare(`INSERT INTO didit_webhook_events (event_id, received_at) VALUES (?, ?)`)
            .bind(payload.event_id, Date.now()).run();
        } catch (err) {
          if (/UNIQUE/i.test(String(err.message))) return new Response('ok (déjà traité)', { status: 200 });
          throw err;
        }

        const userId = payload.vendor_data; // notre propre user_id, transmis à la création de la session
        const identityStatus = mapDiditStatus(payload.status);
        if (userId) {
          await db.prepare(
            `UPDATE kyc_profiles SET identity_status = ?, didit_status = ?,
               identity_verified_at = CASE WHEN ? = 'approved' THEN ? ELSE identity_verified_at END
             WHERE user_id = ?`
          ).bind(identityStatus, payload.status, identityStatus, Date.now(), userId).run();
        }
        return new Response('ok', { status: 200 });
      }

      // GET /summary — trésorerie, économies, flux calculés à partir des vraies transactions et alertes stockées.
      if (url.pathname === '/summary' && request.method === 'GET') {
        const userId = await getUserId(request, env);
        return json(await getFullSummary(db, userId));
      }

      return json({ error: 'not found' }, 404);
    } catch (err) {
      // Erreurs "attendues" (validation, quota, session) : message montrable au client.
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      // Tout le reste (SQL, réseau, config) : détail dans les logs du Worker, message neutre côté client.
      console.error('Erreur non gérée:', request.method, url.pathname, err);
      return json({ error: 'erreur interne, réessaie dans un instant' }, 500);
    }
  }
};
