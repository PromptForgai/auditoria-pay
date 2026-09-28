// auth.js — comptes, sessions, mot de passe oublié
// Principe : on ne stocke jamais un mot de passe ni un token en clair.
// - Mot de passe : PBKDF2-SHA256 avec sel aléatoire par utilisateur (Web Crypto, dispo nativement dans Workers)
// - Session : token aléatoire renvoyé au client dans un cookie httpOnly ; seul son hash SHA-256 est stocké en base
// - Reset password : même principe de token à usage unique, courte durée de vie (1h)

import { HttpError } from './errors.js';

const PBKDF2_ITERATIONS = 100_000; // maximum accepté par Cloudflare Workers
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours
const RESET_TOKEN_DURATION_MS = 60 * 60 * 1000; // 1 heure
const MAX_EMAIL = 254;
const MAX_PASSWORD = 200; // évite qu'un mot de passe géant serve à saturer le CPU
const DUMMY_SALT = '00'.repeat(16);

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function randomToken(bytes = 32) {
  return toHex(crypto.getRandomValues(new Uint8Array(bytes)).buffer);
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toHex(digest);
}

async function hashPassword(password, saltHex) {
  const salt = saltHex ? Uint8Array.from(saltHex.match(/.{2}/g).map(b => parseInt(b, 16))) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return { hash: toHex(derived), salt: toHex(salt.buffer ?? salt) };
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  // comparaison en temps constant pour éviter les attaques par timing
  if (hash.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  return diff === 0;
}

function isValidEmail(email) {
  return email.length <= MAX_EMAIL && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function checkNewPassword(password) {
  if (typeof password !== 'string' || password.length < 10) throw new HttpError(400, 'mot de passe trop court (10 caractères minimum)');
  if (password.length > MAX_PASSWORD) throw new HttpError(400, `mot de passe trop long (${MAX_PASSWORD} caractères maximum)`);
}

export async function signup(db, email, password) {
  if (typeof email !== 'string' || typeof password !== 'string') throw new HttpError(400, 'email et mot de passe requis');
  email = email.trim().toLowerCase();
  if (!isValidEmail(email)) throw new HttpError(400, 'email invalide');
  checkNewPassword(password);

  const existing = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  if (existing) throw new HttpError(409, 'un compte existe déjà avec cet email');

  const { hash, salt } = await hashPassword(password);
  const userId = crypto.randomUUID();
  try {
    await db.prepare(
      `INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?,?,?,?,?)`
    ).bind(userId, email, hash, salt, Date.now()).run();
  } catch (err) {
    // deux inscriptions simultanées avec le même email : la contrainte UNIQUE tranche
    if (/UNIQUE/i.test(String(err.message))) throw new HttpError(409, 'un compte existe déjà avec cet email');
    throw err;
  }
  return userId;
}

export async function login(db, email, password) {
  const bad = () => new HttpError(401, 'email ou mot de passe incorrect');
  if (typeof email !== 'string' || typeof password !== 'string' || password.length > MAX_PASSWORD) throw bad();
  email = email.trim().toLowerCase();
  const user = await db.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  if (!user) {
    // Même coût CPU que pour un vrai compte : sans ça, la durée de la réponse révèle quels emails existent.
    await hashPassword(password, DUMMY_SALT);
    throw bad();
  }

  const ok = await verifyPassword(password, user.password_hash, user.password_salt);
  if (!ok) throw bad();

  return createSession(db, user.id);
}

export async function createSession(db, userId) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  await db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(now).run(); // ménage des sessions expirées
  await db.prepare(
    `INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)`
  ).bind(tokenHash, userId, now, now + SESSION_DURATION_MS).run();
  return token; // c'est CE token brut (jamais son hash) qu'on met dans le cookie
}

export async function getUserIdFromSession(db, token) {
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const session = await db.prepare(
    `SELECT * FROM sessions WHERE token_hash = ?`
  ).bind(tokenHash).first();
  if (!session || session.expires_at < Date.now()) return null;
  return session.user_id;
}

export async function logout(db, token) {
  if (!token) return;
  const tokenHash = await sha256Hex(token);
  await db.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(tokenHash).run();
}

// Crée un jeton de réinitialisation et le renvoie ({email, token}), ou null si le compte n'existe pas.
// La route HTTP répond "ok" dans les deux cas et envoie l'email en arrière-plan (waitUntil) :
// ni le message ni la durée de la réponse ne révèlent si le compte existe.
export async function requestPasswordReset(db, email) {
  if (typeof email !== 'string') return null;
  email = email.trim().toLowerCase();
  const user = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  if (!user) return null;

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  await db.prepare(`DELETE FROM password_reset_tokens WHERE expires_at < ?`).bind(now).run();
  // un seul lien valide à la fois : les précédents sont invalidés
  await db.prepare(`UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0`).bind(user.id).run();
  await db.prepare(
    `INSERT INTO password_reset_tokens (token_hash, user_id, created_at, expires_at, used) VALUES (?,?,?,?,0)`
  ).bind(tokenHash, user.id, now, now + RESET_TOKEN_DURATION_MS).run();

  return { email, token };
}

export async function resetPassword(db, token, newPassword) {
  checkNewPassword(newPassword);
  const invalid = () => new HttpError(400, 'lien de réinitialisation invalide ou expiré');
  if (typeof token !== 'string' || !token) throw invalid();

  const tokenHash = await sha256Hex(token);
  const reset = await db.prepare(
    `SELECT * FROM password_reset_tokens WHERE token_hash = ?`
  ).bind(tokenHash).first();
  if (!reset) throw invalid();

  // Le jeton est "consommé" d'abord, de façon atomique : deux requêtes simultanées avec le même
  // lien ne peuvent pas réussir toutes les deux.
  const claim = await db.prepare(
    `UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ? AND used = 0 AND expires_at > ?`
  ).bind(tokenHash, Date.now()).run();
  if (!claim.meta.changes) throw invalid();

  const { hash, salt } = await hashPassword(newPassword);
  await db.prepare(`UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?`)
    .bind(hash, salt, reset.user_id).run();

  // Invalide toutes les sessions existantes après un changement de mot de passe
  await db.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(reset.user_id).run();
}

// Lit le token de session depuis le cookie de la requête
export function readSessionCookie(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/auditoria_session=([a-f0-9]+)/);
  return match ? match[1] : null;
}

export function sessionCookieHeader(token, maxAgeSeconds = SESSION_DURATION_MS / 1000) {
  return `auditoria_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

export function clearSessionCookieHeader() {
  return `auditoria_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
