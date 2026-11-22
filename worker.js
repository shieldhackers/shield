/* Shield scan service (Cloudflare Worker).
   Your website sends it a URL; it fetches that page ONCE (like a browser would) and
   returns headers, cookies and a form summary. It never sends attack payloads. */

const DEFAULT_ORIGIN = 'https://shieldhackers.github.io';
const KEEP = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options',
  'referrer-policy', 'permissions-policy', 'server', 'x-powered-by'];
const hits = new Map(); // best-effort rate limit per IP, per worker instance

function allowedOrigins(env) {
  return ((env && env.ALLOWED_ORIGIN) || DEFAULT_ORIGIN).split(',').map(s => s.trim());
}
function reply(obj, status, origin) {
  return new Response(status === 204 ? null : JSON.stringify(obj), { status, headers: {
    'Content-Type': 'application/json', 'Access-Control-Allow-Origin': origin || 'null',
    'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' } });
}
function blockedHost(h) {
  h = h.toLowerCase();
  return !h.includes('.') || h.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(h) ||
    /(^|\.)(localhost|local|internal|lan|home|corp|intranet)$/.test(h);
}
function validate(str) {
  let u;
  try { u = new URL(str); } catch (e) { throw new Error('That is not a valid URL.'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http and https URLs are allowed.');
  if (u.username || u.password) throw new Error('URLs with credentials are not allowed.');
  if (u.port && !['80', '443'].includes(u.port)) throw new Error('Only standard ports are allowed.');
  if (blockedHost(u.hostname)) throw new Error('Local and private addresses cannot be scanned.');
  return u;
}
async function fetchFollow(start) {
  let url = start;
  for (let hop = 0; hop < 4; hop++) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 8000);
    let res;
    try {
      res = await fetch(url.href, { redirect: 'manual', signal: ctl.signal,
        headers: { 'User-Agent': 'ShieldScanner/1.0 (passive header check)' } });
    } finally { clearTimeout(timer); }
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) { url = validate(new URL(loc, url).href); continue; }
    return { res, url };
  }
  throw new Error('Too many redirects.');
}
async function readLimited(res, max) {
  if (!/text\/html/i.test(res.headers.get('content-type') || '') || !res.body) return '';
  const reader = res.body.getReader(), dec = new TextDecoder();
  let text = '', size = 0;
  while (size < max) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length; text += dec.decode(value, { stream: true });
  }
  try { await reader.cancel(); } catch (e) { /* ignore */ }
  return text;
}
const attr = (tag, name) => { const m = tag.match(new RegExp('\\b' + name + '\\s*=\\s*["\']?([^"\'\\s>]*)', 'i')); return m ? m[1] : ''; };
function summarize(html, finalUrl) {
  const forms = [];
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    if (forms.length >= 10) break;
    forms.push({ method: (attr(m[1], 'method') || 'get').toLowerCase(), action: attr(m[1], 'action'),
      hasPassword: /type\s*=\s*["']?password/i.test(m[2]),
      hasCsrf: /name\s*=\s*["']?[^"'\s>]*(csrf|xsrf|authenticity_token|_token|nonce)/i.test(m[2]) });
  }
  const ext = [];
  for (const m of html.matchAll(/<(script|link)\b[^>]*>/gi)) {
    const tag = m[0], src = attr(tag, m[1].toLowerCase() === 'script' ? 'src' : 'href');
    if (!/^https?:\/\//i.test(src) || /integrity\s*=/i.test(tag)) continue;
    if (m[1].toLowerCase() === 'link' && !/rel\s*=\s*["']?stylesheet/i.test(tag)) continue;
    try { if (new URL(src).hostname !== finalUrl.hostname && ext.length < 8) ext.push(src); } catch (e) { /* ignore */ }
  }
  const mixed = finalUrl.protocol === 'https:' ? (html.match(/\bsrc\s*=\s*["']http:\/\//gi) || []).length : 0;
  return { forms, extScriptsNoSri: ext, mixed };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const ok = allowedOrigins(env).includes(origin);
    if (request.method === 'OPTIONS') return reply({}, ok ? 204 : 403, ok ? origin : '');
    if (!ok) return reply({ error: 'This service only works from the Shield website.' }, 403, '');
    if (request.method !== 'POST') return reply({ error: 'Use POST.' }, 405, origin);

    const ip = request.headers.get('cf-connecting-ip') || 'x', now = Date.now();
    const recent = (hits.get(ip) || []).filter(t => now - t < 60000);
    if (recent.length >= 10) return reply({ error: 'Too many scans. Wait a minute and try again.' }, 429, origin);
    recent.push(now); hits.set(ip, recent);

    let target;
    try {
      const raw = await request.text();
      if (raw.length > 2000) throw new Error('Request too large.');
      target = validate(String(JSON.parse(raw).url || '').trim());
    } catch (e) { return reply({ error: e instanceof SyntaxError ? 'Bad request.' : e.message }, 400, origin); }

    try {
      const { res, url } = await fetchFollow(target);
      const headers = {};
      KEEP.forEach(k => { const v = res.headers.get(k); if (v) headers[k] = v.slice(0, 300); });
      const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie().map(c => c.slice(0, 300)) : [];
      const html = await readLimited(res, 200000);
      return reply({ finalUrl: url.href, status: res.status, headers, cookies, ...summarize(html, url) }, 200, origin);
    } catch (e) {
      return reply({ error: e.name === 'AbortError' ? 'The site took too long to respond.' : (e.message.includes('redirect') || e.message.includes('allowed') || e.message.includes('Local') ? e.message : 'Could not reach that site (it may be down, or its HTTPS certificate is invalid).') }, 502, origin);
    }
  }
};
