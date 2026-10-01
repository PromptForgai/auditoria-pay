// kyc_didit.js — vérification d'identité automatisée via Didit (gratuit : pièce d'identité, détection
// de vivacité, comparaison de visage, analyse d'IP — jusqu'à 500 vérifications/mois).
// Le justificatif de domicile reste géré à part (upload + revue manuelle, voir index.js /kyc/submit)
// car ce module-là n'est pas inclus dans le pack gratuit de Didit.

import { HttpError } from './errors.js';

const DIDIT_API = 'https://verification.didit.me/v3';

// Workflow "Free KYC" fourni par Didit : OCR + Liveness passive + Face Match + IP Analysis, couvert
// par le pack gratuit. Ce n'est pas un secret (contrairement à la clé API) : il peut rester en dur ici.
export const DIDIT_WORKFLOW_ID = 'e64456c5-29c5-4881-9dd8-720f2a04b76a';

// Crée une session de vérification côté serveur (jamais depuis le navigateur : la clé API n'y est
// jamais exposée). vendor_data = notre propre user_id, c'est lui que le webhook renverra pour savoir
// quel compte créditer du résultat.
export async function createDiditSession(userId, callbackUrl, apiKey) {
  if (!apiKey) throw new Error('DIDIT_API_KEY non configurée'); // erreur de config : journalisée, jamais montrée au client

  const res = await fetch(`${DIDIT_API}/session/`, {
    method: 'POST',
    headers: { 'x-api-key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ workflow_id: DIDIT_WORKFLOW_ID, vendor_data: userId, callback: callbackUrl })
  });

  if (!res.ok) {
    // 403 le plus souvent : clé API absente, invalide ou révoquée (le détail renvoyé par Didit ne
    // distingue pas ces cas). Le détail reste dans les logs, jamais montré au client.
    console.error('Échec création session Didit:', res.status, await res.text());
    throw new HttpError(502, "Le service de vérification d'identité est momentanément indisponible.");
  }
  const session = await res.json(); // { session_id, session_token, url, status, workflow_id, vendor_data }
  return { url: session.url, sessionId: session.session_id };
}

// --- Vérification de la signature des webhooks (X-Signature-V2) ---
// Canonicalisation exigée par Didit avant le HMAC : nombres décimaux entiers (1.0) -> entiers (1),
// puis tri récursif des clés, puis JSON.stringify. Sans ça, la signature ne correspond jamais.
function shortenFloats(v) {
  if (Array.isArray(v)) return v.map(shortenFloats);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, shortenFloats(x)]));
  if (typeof v === 'number' && !Number.isInteger(v) && v % 1 === 0) return Math.trunc(v);
  return v;
}
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    return Object.keys(v).sort().reduce((acc, k) => { acc[k] = sortKeys(v[k]); return acc; }, {});
  }
  return v;
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Vérifie fraîcheur (≤ 5 min) + signature HMAC-SHA256 d'un webhook Didit. rawBody doit être le texte
// BRUT de la requête (avant tout JSON.parse) : la canonicalisation part du contenu déjà parsé par
// Didit, donc on reparse ici nous-mêmes pour obtenir exactement la même forme.
export async function verifyDiditWebhook(rawBody, signatureHeader, timestampHeader, secret) {
  const ts = Number(timestampHeader);
  if (!ts || Math.abs(Date.now() / 1000 - ts) > 300) return null; // trop vieux/trop récent : rejet (anti-rejeu)
  if (!signatureHeader) return null;

  let parsed;
  try { parsed = JSON.parse(rawBody); } catch { return null; }

  const canonical = JSON.stringify(sortKeys(shortenFloats(parsed)));
  const expected = await hmacSha256Hex(secret, canonical);
  if (!timingSafeEqual(expected, signatureHeader)) return null;
  return parsed; // signature valide : on peut faire confiance au contenu
}

// Statuts Didit (chaînes exactes, sensibles à la casse) -> notre statut d'identité à 3 états.
// "Kyc Expired" (une identité déjà approuvée qui doit être revérifiée) repasse à "pending" plutôt que
// de rester "approved" : il faut une nouvelle session pour la confirmer à nouveau.
export function mapDiditStatus(status) {
  if (status === 'Approved') return 'approved';
  if (status === 'Declined') return 'rejected';
  return 'pending'; // Not Started | In Progress | Awaiting User | In Review | Resubmitted | Abandoned | Expired | Kyc Expired
}
