// auth.js — comptes, sessions, mot de passe oublié
// Principe : on ne stocke jamais un mot de passe ni un token en clair.
// - Mot de passe : PBKDF2-SHA256 avec sel aléatoire par utilisateur (Web Crypto, dispo nativement dans Workers)
// - Session : token aléatoire renvoyé au client dans un cookie httpOnly ; seul son hash SHA-256 est stocké en base
// - Reset password : même principe de token à usage unique, courte durée de vie (1h)

const PBKDF2_ITERATIONS = 100_000;
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours
const RESET_TOKEN_DURATION_MS = 60 * 60 * 1000; // 1 heure

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
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export async function signup(db, email, password) {
  email = email.trim().toLowerCase();
  if (!isValidEmail(email)) throw new Error('email invalide');
  if (!password || password.length < 10) throw new Error('mot de passe trop court (10 caractères minimum)');

  const existing = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  if (existing) throw new Error('un compte existe déjà avec cet email');

  const { hash, salt } = await hashPassword(password);
  const userId = crypto.randomUUID();
  await db.prepare(
    `INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?,?,?,?,?)`
  ).bind(userId, email, hash, salt, Date.now()).run();

  return userId;
}

export async function login(db, email, password) {
  email = email.trim().toLowerCase();
  const user = await db.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  // Message identique que l'email existe ou non : évite de révéler quels emails sont inscrits
  if (!user) throw new Error('email ou mot de passe incorrect');

  const ok = await verifyPassword(password, user.password_hash, user.password_salt);
  if (!ok) throw new Error('email ou mot de passe incorrect');

  return createSession(db, user.id);
}

export async function createSession(db, userId) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
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

export async function requestPasswordReset(db, email, sendEmail) {
  email = email.trim().toLowerCase();
  const user = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
  // On répond "ok" dans tous les cas côté route HTTP, qu'un compte existe ou non (voir index.js),
  // pour ne pas révéler quels emails sont inscrits. Ici on n'envoie l'email que s'il existe vraiment.
  if (!user) return;

  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = Date.now();
  await db.prepare(
    `INSERT INTO password_reset_tokens (token_hash, user_id, created_at, expires_at, used) VALUES (?,?,?,?,0)`
  ).bind(tokenHash, user.id, now, now + RESET_TOKEN_DURATION_MS).run();

  await sendEmail(email, token);
}

export async function resetPassword(db, token, newPassword) {
  if (!newPassword || newPassword.length < 10) throw new Error('mot de passe trop court (10 caractères minimum)');

  const tokenHash = await sha256Hex(token);
  const reset = await db.prepare(
    `SELECT * FROM password_reset_tokens WHERE token_hash = ?`
  ).bind(tokenHash).first();

  if (!reset || reset.used || reset.expires_at < Date.now()) {
    throw new Error('lien de réinitialisation invalide ou expiré');
  }

  const { hash, salt } = await hashPassword(newPassword);
  await db.prepare(`UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?`)
    .bind(hash, salt, reset.user_id).run();

  await db.prepare(`UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?`).bind(tokenHash).run();
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
