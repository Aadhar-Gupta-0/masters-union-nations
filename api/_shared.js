/** Helpers shared by the registration, delegate-card and check-in functions (the leading underscore keeps Vercel from exposing this file as a route). */
const crypto = require('crypto');

const reply = (res, status, data) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.status(status);
  return res.json(data);
};

/** POST + JSON + same-origin only. Returns the parsed body, or null after sending the error response. */
function guard(req, res) {
  if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); reply(res, 405, { error: 'Method not allowed.' }); return null; }
  const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') { reply(res, 415, { error: 'JSON body required.' }); return null; }
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (req.headers.origin) { try { if (new URL(req.headers.origin).host !== host) { reply(res, 403, { error: 'Cross-site requests not allowed.' }); return null; } } catch { reply(res, 403, { error: 'Invalid request origin.' }); return null; } }
  const declaredLength = Number(req.headers['content-length'] || 0);
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > 4000) {
    reply(res, 413, { error: 'Invalid or oversized request length.' }); return null;
  }
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    reply(res, 400, { error: 'A JSON object is required.' }); return null;
  }
  return req.body;
}

const clientIp = req => String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();

/** Best-effort in-memory limiter (each serverless instance keeps its own counts). */
const buckets = new Map();
const MAX_RATE_LIMIT_KEYS = 5000;
function limited(key, max, windowMs) {
  // A broken configuration must never accidentally disable limiting.
  if (!Number.isSafeInteger(max) || max < 1 ||
      !Number.isFinite(windowMs) || windowMs <= 0) return true;
  const now = Date.now();
  let b = buckets.get(key);
  if (!b && buckets.size >= MAX_RATE_LIMIT_KEYS) {
    for (const [k, v] of buckets) {
      if (now - v.t >= windowMs) buckets.delete(k);
    }
    // An unbounded stream of distinct keys can otherwise consume memory.
    // Refuse new principals if every existing slot is still active.
    if (buckets.size >= MAX_RATE_LIMIT_KEYS) return true;
  }
  if (!b || now - b.t >= windowMs) b = { n: 0, t: now };
  b.n++;
  buckets.set(key, b);
  return b.n > max;
}

const digest = s => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));

/** Calls the Google Apps Script web app. Throws on transport problems. */
async function sheet(payload) {
  const url = process.env.GOOGLE_SHEETS_WEBHOOK_URL, secret = process.env.GOOGLE_SHEETS_SECRET;
  if (!url || !secret) { const e = new Error('not configured'); e.code = 503; throw e; }
  const r = await fetch(url, { method: 'POST', redirect: 'follow', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ ...payload, secret }), signal: AbortSignal.timeout(12000) });
  const out = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error('sheet ' + r.status); e.code = 502; throw e; }
  return out;
}

const TOKEN_RE = /^[a-f0-9]{32}$/;
const ID_RE = /^MUN26-\d{4}$/;
const cleanText = (v, max) => typeof v === 'string' ? v.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max) : '';

module.exports = { reply, guard, clientIp, limited, safeEqual, sheet, TOKEN_RE, ID_RE, cleanText };
