// ratelimit.js — limiteur de débit minimal en D1 (fenêtre fixe), sans dépendance externe.
// hitRateLimit() renvoie true quand la limite est DÉPASSÉE.

export async function hitRateLimit(db, key, max, windowMs) {
  const now = Date.now();
  const cutoff = now - windowMs;
  const row = await db.prepare(
    `INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN window_start <= ? THEN 1 ELSE count + 1 END,
       window_start = CASE WHEN window_start <= ? THEN ? ELSE window_start END
     RETURNING count`
  ).bind(key, now, cutoff, cutoff, now).first();
  return row.count > max;
}

export function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// Ménage occasionnel (appelé à l'inscription) : supprime les fenêtres vieilles de plus d'un jour.
export async function purgeRateLimits(db) {
  await db.prepare(`DELETE FROM rate_limits WHERE window_start < ?`).bind(Date.now() - 86400000).run();
}
