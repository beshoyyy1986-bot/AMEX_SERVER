const express = require('express');
const cors = require('cors');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let HttpsProxyAgent;
let SocksProxyAgent;

const app = express();

// ============================================================
// SECURITY CONFIG — من Environment Variables فقط
// ============================================================
const ADMIN_PASS    = process.env.ADMIN_PASS;
const SESSION_SECRET = process.env.SESSION_SECRET || ADMIN_PASS;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://business.facebook.com,chrome-extension://*')
  .split(',').map(s => s.trim()).filter(Boolean);

if (!ADMIN_PASS) {
  console.warn('⚠️ SECURITY WARNING: set ADMIN_PASS in environment variables.');
}

// ============================================================
// API KEYS STORE — توليد + إدارة مفاتيح المستخدمين
// ============================================================
const DATA_DIR  = process.env.DATA_DIR || '/data';
fs.mkdirSync(DATA_DIR, { recursive: true });
const KEYS_FILE = path.join(DATA_DIR, 'api_keys.json');

function loadKeys() {
  try {
    if (fs.existsSync(KEYS_FILE)) return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  } catch (e) {}
  return [];
}

function saveKeys(list) {
  try { fs.writeFileSync(KEYS_FILE, JSON.stringify(list, null, 2), 'utf8'); } catch (e) {}
}

function generateKey() {
  return 'bsh_' + crypto.randomBytes(24).toString('hex');
}

// Structure: { id, key, label, createdAt, expiresAt|null, maxUsage|null, usageCount, enabled, lastUsed|null }
let apiKeys = loadKeys();

function findKey(rawKey) {
  if (!rawKey) return null;
  return apiKeys.find(k => k.key === rawKey) || null;
}

function isKeyValid(k) {
  if (!k || !k.enabled) return false;
  const now = Date.now();
  if (k.expiresAt && new Date(k.expiresAt).getTime() < now) return false;
  if (k.maxUsage !== null && k.maxUsage !== undefined && k.usageCount >= k.maxUsage) return false;
  return true;
}

function recordKeyUsage(k) {
  if (!k) return;
  k.usageCount = (k.usageCount || 0) + 1;
  k.lastUsed = new Date().toISOString();
  saveKeys(apiKeys);
}

// ============================================================
// PROXIES STORE
// ============================================================
const PROXIES_FILE = path.join(DATA_DIR, 'server_proxies.json');

function loadServerProxies() {
  try {
    if (fs.existsSync(PROXIES_FILE)) return JSON.parse(fs.readFileSync(PROXIES_FILE, 'utf8'));
  } catch (e) {}
  return [];
}
function saveServerProxies(list) {
  try { fs.writeFileSync(PROXIES_FILE, JSON.stringify(list), 'utf8'); } catch (e) {}
}

let serverProxies = loadServerProxies();
let rotationIndex = 0;

function getNextServerProxy() {
  const active = serverProxies.filter(p => p.enabled && p.lastStatus !== 'dead');
  if (!active.length) return null;
  const p = active[rotationIndex % active.length];
  rotationIndex++;
  return p;
}

// ============================================================
// CORS
// ============================================================
function isAllowedOrigin(origin, req) {
  if (!origin) return true; // null origin = same-origin or non-browser (curl, server)
  if (ALLOWED_ORIGINS.includes('*')) return true;
  // اسمح دايمًا لطلبات جاية من نفس دومين السيرفر (لوحة /admin بتنادي نفسها)
  if (req && req.headers.host && origin === `https://${req.headers.host}`) return true;
  return ALLOWED_ORIGINS.some(rule => {
    if (rule === '*') return true;
    if (rule.endsWith('://*')) return origin.startsWith(rule.slice(0, -1));
    return origin === rule;
  });
}
const corsStatic = {
  methods: ['GET', 'HEAD', 'POST', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-pass', 'x-api-key', 'x-requested-with', 'authorization'],
  optionsSuccessStatus: 204,
};
// per-request delegate عشان نقدر نستخدم req.headers.host (نفس الدومين) في القرار
function corsOptionsDelegate(req, callback) {
  const origin = req.headers.origin;
  const allowed = isAllowedOrigin(origin, req);
  callback(null, { ...corsStatic, origin: allowed });
}
app.use(cors(corsOptionsDelegate));
app.options('*', cors(corsOptionsDelegate));
app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', 1);

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// ============================================================
// RATE LIMITER
// ============================================================
const rateBuckets = new Map();
function rateLimit({ windowMs = 60_000, max = 60, keyPrefix = 'global' } = {}) {
  return (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const key = `${keyPrefix}:${ip}`;
    const now = Date.now();
    const bucket = rateBuckets.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > bucket.resetAt) { bucket.count = 0; bucket.resetAt = now + windowMs; }
    bucket.count++;
    rateBuckets.set(key, bucket);
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, max - bucket.count)));
    if (bucket.count > max) return res.status(429).json({ error: 'Too many requests' });
    next();
  };
}

// ============================================================
// PROXY PARSER
// ============================================================
function parseProxy(raw) {
  if (!raw || !raw.trim()) return null;
  raw = raw.trim();
  if (/^(https?|socks[45]):\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      return { protocol: u.protocol.replace(':', '').toLowerCase(), host: u.hostname,
               port: parseInt(u.port) || 1080,
               username: u.username ? decodeURIComponent(u.username) : null,
               password: u.password ? decodeURIComponent(u.password) : null, url: raw };
    } catch (e) { return null; }
  }
  const parts = raw.split(':');
  if (parts.length === 4 && !raw.includes('@')) return buildProxyObj('http', parts[0], parts[1], parts[2], parts[3]);
  if (raw.includes('@')) {
    const atIdx = raw.lastIndexOf('@');
    const creds = raw.substring(0, atIdx);
    const hostPart = raw.substring(atIdx + 1);
    const [credUser, ...credPass] = creds.split(':');
    const [host, port] = hostPart.split(':');
    return buildProxyObj('http', host, port, credUser, credPass.join(':'));
  }
  if (parts.length === 2) return buildProxyObj('http', parts[0], parts[1], null, null);
  return null;
}
function buildProxyObj(protocol, host, port, username, password) {
  const p = parseInt(port);
  if (!host || isNaN(p)) return null;
  let url = `${protocol}://`;
  if (username && password) url += `${encodeURIComponent(username)}:${encodeURIComponent(password)}@`;
  else if (username) url += `${encodeURIComponent(username)}@`;
  url += `${host}:${p}`;
  return { protocol, host, port: p, username: username || null, password: password || null, url };
}
function getProxyTypeLabel(p) {
  if (!p) return null;
  const pr = p.protocol.toUpperCase();
  if (pr === 'SOCKS4') return 'SOCKS4';
  if (pr === 'SOCKS5') return 'SOCKS5';
  if (pr === 'HTTPS') return 'HTTPS';
  return 'HTTP';
}
function proxyDisplayLabel(parsed) {
  if (!parsed) return 'unknown';
  return `${getProxyTypeLabel(parsed)}${parsed.username ? ' 🔐' : ''} ${parsed.host}:${parsed.port}`;
}

// ============================================================
// CHROME TLS + FETCH
// ============================================================
const CHROME_CIPHERS = [
  'TLS_AES_128_GCM_SHA256','TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-CHACHA20-POLY1305','ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-RSA-AES128-SHA','ECDHE-RSA-AES256-SHA',
  'AES128-GCM-SHA256','AES256-GCM-SHA384','AES128-SHA','AES256-SHA'
].join(':');

let defaultChromeAgent;
function createProxyAgent(proxyInfo) {
  if (!proxyInfo) return null;
  const { protocol, url } = proxyInfo;
  if (protocol === 'socks4' || protocol === 'socks5') return new SocksProxyAgent(url);
  return new HttpsProxyAgent(url);
}
function getChromeHeaders(cookies, extra = {}) {
  return {
    'sec-ch-ua': '"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="8"',
    'sec-ch-ua-mobile': '?0', 'sec-ch-ua-platform': '"Windows"',
    'x-fb-friendly-name': extra['x-fb-friendly-name'] || 'GraphQL',
    'x-fb-lsd': extra['x-fb-lsd'] || '',
    'content-type': 'application/x-www-form-urlencoded',
    'x-requested-with': 'XMLHttpRequest',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'accept': '*/*', 'origin': 'https://business.facebook.com',
    'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty',
    // ★ FIX: كان مثبّت على مسار وهمي /billing/payments/ — الأداة الشغالة بتبعت الـ origin بس
    'referer': 'https://business.facebook.com/',
    'accept-encoding': 'gzip, deflate, br', 'accept-language': 'en-US,en;q=0.9',
    'cookie': cookies, ...extra
  };
}

// ============================================================
// BRIGHT DATA
// ============================================================
const BRIGHT_DATA_KEY  = process.env.BRIGHT_DATA_KEY || '';
const BRIGHT_DATA_ZONE = process.env.BRIGHT_DATA_ZONE || 'web_unlocker1';
const USE_BRIGHT_DATA  = !!BRIGHT_DATA_KEY && process.env.USE_BRIGHT_DATA !== 'false';

async function brightDataFetch(url, options = {}) {
  const fetch = require('node-fetch');
  const payload = { zone: BRIGHT_DATA_ZONE, url, format: 'raw', method: options.method || 'GET' };
  if (options.headers) payload.headers = options.headers;
  if (options.body)    payload.body    = options.body;
  return fetch('https://api.brightdata.com/request', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${BRIGHT_DATA_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

async function chromeFetch(url, options = {}, proxyInfo = null) {
  const fetch = require('node-fetch');
  if (!proxyInfo && BRIGHT_DATA_KEY && USE_BRIGHT_DATA) {
    try { return await brightDataFetch(url, options); } catch (bdErr) {
      console.log('  ⚠️ BrightData failed, fallback direct:', bdErr.message);
    }
  }
  const agent = proxyInfo ? createProxyAgent(proxyInfo) : defaultChromeAgent;
  return fetch(url, { ...options, agent, compress: true });
}

// ============================================================
// CHECK PROXY
// ============================================================
async function checkProxyAlive(raw) {
  const parsed = parseProxy(raw);
  if (!parsed) return { ok: false, error: 'صيغة غير صحيحة', parsed: null };
  try {
    const fetch = require('node-fetch');
    const agent = createProxyAgent(parsed);
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 9000);
    const r = await fetch('https://www.facebook.com/robots.txt', {
      method: 'GET', agent, signal: ctrl.signal,
      headers: { 'user-agent': 'Mozilla/5.0 Chrome/120' }
    });
    clearTimeout(t);
    const ok = r.status >= 200 && r.status < 500;
    return { ok, parsed, error: ok ? null : `FB رد بـ ${r.status}`, statusCode: r.status };
  } catch (err) {
    let msg = err.message || 'فشل';
    if (err.name === 'AbortError') msg = 'timeout — بطيء أو غير متاح';
    else if (msg.includes('ECONNREFUSED')) msg = 'رفض الاتصال';
    else if (msg.includes('ENOTFOUND'))    msg = 'DNS error';
    else if (msg.includes('ETIMEDOUT'))    msg = 'timeout';
    else if (msg.includes('auth'))         msg = 'خطأ في الباسورد';
    return { ok: false, error: msg, parsed };
  }
}

// ============================================================
// AUTH HELPERS
// ============================================================
function constantTimeEqual(a, b) {
  a = String(a || ''); b = String(b || '');
  const ab = Buffer.from(a); const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function adminAuth(req, res, next) {
  const pass = req.headers['x-admin-pass'] || req.query.pass;
  if (!ADMIN_PASS || !constantTimeEqual(pass, ADMIN_PASS)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function apiAuth(req, res, next) {
  const rawKey = req.headers['x-api-key'] || req.body?.apiKey || req.query.apiKey;
  const k = findKey(rawKey);
  if (!k || !isKeyValid(k)) {
    return res.status(401).json({ error: 'مفتاح API غير صحيح أو منتهي الصلاحية' });
  }
  recordKeyUsage(k);
  req._apiKey = k;
  next();
}

// ============================================================
// ENDPOINT: CHECK PROXY
// ============================================================
app.post('/check-proxy', rateLimit({ max: 30, keyPrefix: 'check-proxy' }), apiAuth, async (req, res) => {
  const { proxy } = req.body;
  if (!proxy?.trim()) return res.json({ ok: false, error: 'لم تدخل بروكسي', type: null });
  const result = await checkProxyAlive(proxy);
  res.json({
    ok: result.ok, error: result.error || null,
    type: result.parsed ? getProxyTypeLabel(result.parsed) : null,
    host: result.parsed?.host, port: result.parsed?.port,
    hasAuth: !!(result.parsed?.username),
  });
});

// ============================================================
// ADMIN: PROXY ENDPOINTS
// ============================================================
app.get('/admin/proxies', rateLimit({ max: 60, keyPrefix: 'admin-api' }), adminAuth, (req, res) => {
  const safeList = serverProxies.map(p => ({
    id: p.id, label: p.label, enabled: p.enabled, addedAt: p.addedAt,
    lastCheck: p.lastCheck, lastStatus: p.lastStatus, failCount: p.failCount,
    type: p.type, hasAuth: p.hasAuth, host: p.host, port: p.port,
  }));
  res.json({ proxies: safeList, total: safeList.length, active: safeList.filter(p => p.enabled && p.lastStatus !== 'dead').length });
});

app.post('/admin/proxies', rateLimit({ max: 20, keyPrefix: 'admin-api' }), adminAuth, async (req, res) => {
  const { proxy } = req.body;
  if (!proxy?.trim()) return res.status(400).json({ error: 'proxy مطلوب' });
  const parsed = parseProxy(proxy.trim());
  if (!parsed) return res.status(400).json({ error: 'صيغة غير صحيحة' });
  const check = await checkProxyAlive(proxy.trim());
  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    raw: proxy.trim(), label: proxyDisplayLabel(parsed),
    host: parsed.host, port: parsed.port, type: getProxyTypeLabel(parsed),
    hasAuth: !!(parsed.username), enabled: true,
    addedAt: new Date().toISOString(), lastCheck: new Date().toISOString(),
    lastStatus: check.ok ? 'ok' : 'dead', failCount: check.ok ? 0 : 1,
  };
  serverProxies.push(entry);
  saveServerProxies(serverProxies);
  res.json({ ok: true, proxy: { ...entry, raw: undefined }, checkResult: { ok: check.ok, error: check.error } });
});

app.delete('/admin/proxies/:id', rateLimit({ max: 20, keyPrefix: 'admin-api' }), adminAuth, (req, res) => {
  const before = serverProxies.length;
  serverProxies = serverProxies.filter(p => p.id !== req.params.id);
  saveServerProxies(serverProxies);
  res.json({ ok: serverProxies.length < before });
});

app.patch('/admin/proxies/:id', rateLimit({ max: 20, keyPrefix: 'admin-api' }), adminAuth, (req, res) => {
  const p = serverProxies.find(p => p.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'not found' });
  if (req.body.enabled !== undefined) p.enabled = !!req.body.enabled;
  saveServerProxies(serverProxies);
  res.json({ ok: true, proxy: { ...p, raw: undefined } });
});

app.post('/admin/proxies/check-all', rateLimit({ max: 10, keyPrefix: 'admin-api' }), adminAuth, async (req, res) => {
  const results = [];
  for (const p of serverProxies) {
    const check = await checkProxyAlive(p.raw);
    p.lastCheck = new Date().toISOString();
    p.lastStatus = check.ok ? 'ok' : 'dead';
    p.failCount  = check.ok ? 0 : (p.failCount || 0) + 1;
    results.push({ id: p.id, label: p.label, ok: check.ok, error: check.error });
  }
  saveServerProxies(serverProxies);
  res.json({ results });
});

// ============================================================
// ADMIN: API KEYS ENDPOINTS
// ============================================================

// GET /admin/keys — قائمة الـ keys (بدون الـ key نفسه كامل)
app.get('/admin/keys', rateLimit({ max: 60, keyPrefix: 'admin-keys' }), adminAuth, (req, res) => {
  const now = Date.now();
  const safeList = apiKeys.map(k => {
    const expiresAt = k.expiresAt ? new Date(k.expiresAt).getTime() : null;
    const daysLeft = expiresAt ? Math.max(0, Math.ceil((expiresAt - now) / 86400000)) : null;
    return {
      id: k.id, label: k.label, keyPreview: k.key.slice(0, 12) + '…',
      enabled: k.enabled, createdAt: k.createdAt, expiresAt: k.expiresAt || null,
      maxUsage: k.maxUsage || null, usageCount: k.usageCount || 0, lastUsed: k.lastUsed || null,
      isExpired: expiresAt ? expiresAt < now : false,
      isExhausted: k.maxUsage ? (k.usageCount || 0) >= k.maxUsage : false,
      daysLeft,
    };
  });
  res.json({ keys: safeList, total: safeList.length, active: safeList.filter(k => k.enabled && !k.isExpired && !k.isExhausted).length });
});

// POST /admin/keys — توليد مفتاح جديد
app.post('/admin/keys', rateLimit({ max: 20, keyPrefix: 'admin-keys' }), adminAuth, (req, res) => {
  const { label = 'مفتاح جديد', expiresAt = null, durationDays = null, maxUsage = null } = req.body;
  const parsedDuration = durationDays !== null && durationDays !== undefined ? parseInt(durationDays) : null;
  const finalExpiresAt = expiresAt
    ? new Date(expiresAt).toISOString()
    : parsedDuration && parsedDuration > 0
      ? new Date(Date.now() + parsedDuration * 24 * 60 * 60 * 1000).toISOString()
      : null;

  const newKey = {
    id: 'k' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    key: generateKey(),
    label: String(label).slice(0, 80),
    enabled: true,
    createdAt: new Date().toISOString(),
    expiresAt: finalExpiresAt,
    maxUsage: maxUsage ? parseInt(maxUsage) : null,
    usageCount: 0,
    lastUsed: null,
  };
  apiKeys.push(newKey);
  saveKeys(apiKeys);
  res.json({ ok: true, key: newKey });
});

// GET /admin/keys/:id/reveal — كشف الـ key (محتاج admin pass)
app.get('/admin/keys/:id/reveal', rateLimit({ max: 10, keyPrefix: 'admin-keys' }), adminAuth, (req, res) => {
  const k = apiKeys.find(k => k.id === req.params.id);
  if (!k) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true, key: k.key, label: k.label });
});

// PATCH /admin/keys/:id — تحديث label / enabled / expiresAt / maxUsage
app.patch('/admin/keys/:id', rateLimit({ max: 20, keyPrefix: 'admin-keys' }), adminAuth, (req, res) => {
  const k = apiKeys.find(k => k.id === req.params.id);
  if (!k) return res.status(404).json({ error: 'not found' });
  if (req.body.label     !== undefined) k.label     = String(req.body.label).slice(0, 80);
  if (req.body.enabled   !== undefined) k.enabled   = !!req.body.enabled;
  if (req.body.expiresAt !== undefined) k.expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt).toISOString() : null;
  if (req.body.maxUsage  !== undefined) k.maxUsage  = req.body.maxUsage ? parseInt(req.body.maxUsage) : null;
  saveKeys(apiKeys);
  res.json({ ok: true });
});

// DELETE /admin/keys/:id
app.delete('/admin/keys/:id', rateLimit({ max: 20, keyPrefix: 'admin-keys' }), adminAuth, (req, res) => {
  const before = apiKeys.length;
  apiKeys = apiKeys.filter(k => k.id !== req.params.id);
  saveKeys(apiKeys);
  res.json({ ok: apiKeys.length < before });
});

// POST /admin/keys/:id/reset-usage
app.post('/admin/keys/:id/reset-usage', rateLimit({ max: 20, keyPrefix: 'admin-keys' }), adminAuth, (req, res) => {
  const k = apiKeys.find(k => k.id === req.params.id);
  if (!k) return res.status(404).json({ error: 'not found' });
  k.usageCount = 0;
  k.lastUsed   = null;
  saveKeys(apiKeys);
  res.json({ ok: true });
});

// ============================================================
// SESSION RESOLUTION — metaTokens engine (ported from metaTokens.js)
// ============================================================
// استراتيجيات استخراج متعددة بالترتيب من الأقوى للأضعف:
//   1. Multi-URL HTTP + redirect:follow (يتبع الـ redirect تلقائياً)
//   2. Script blocks deep parse
//   3. Cookie-only dtsg fallback

const SESSION_ORIGIN = 'https://business.facebook.com';

const SESSION_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'ar,en-US;q=0.7,en;q=0.3',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
  'Upgrade-Insecure-Requests': '1',
};

// ── Cookie helpers ──────────────────────────────────────────────────────────

function extractUserIdFromCookies(cookieStr) {
  const m = String(cookieStr || '').match(/(?:^|;\s*)c_user=([^;]+)/);
  return m ? m[1].trim() : '';
}

function extractDtsgFromCookies(cookieStr) {
  const s = String(cookieStr || '');
  for (const name of ['fb_dtsg', 'dtsg_ag', 'dtsg']) {
    const m = s.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
    if (m) { try { return decodeURIComponent(m[1].trim()); } catch { return m[1].trim(); } }
  }
  return '';
}

/** Extract business_id and ad_account_id from URL or bare ID string */
function parseBillingUrl(url) {
  let businessId = '';
  let adAccountId = '';
  if (!url) return { businessId, adAccountId };
  try {
    const u = new URL(url);
    businessId = u.searchParams.get('business_id') || '';
    // ★ FIX: أضفنا asset_id و payment_account_id (صفحات billing_hub/accounts/details)
    for (const p of ['act', 'act_id', 'ad_account_id', 'account_id', 'aaid', 'asset_id', 'payment_account_id']) {
      const v = u.searchParams.get(p);
      if (v) { adAccountId = v.replace(/^act_/i, ''); break; }
    }
    if (!adAccountId) {
      const pm = u.pathname.match(/act_(\d+)/);
      if (pm) adAccountId = pm[1];
    }
  } catch (_) {}
  if (!businessId) { const m = url.match(/[?&]business_id=(\d+)/); if (m) businessId = m[1]; }
  if (!adAccountId) { const m = url.match(/act_(\d+)/); if (m) adAccountId = m[1]; }
  if (!adAccountId) { const m = url.match(/[?&]account_id=(\d+)/); if (m) adAccountId = m[1]; }
  if (!adAccountId) { const m = url.match(/[?&]asset_id=(\d+)/); if (m) adAccountId = m[1]; }
  if (!adAccountId) { const m = url.match(/[?&]payment_account_id=(\d+)/); if (m) adAccountId = m[1]; }
  return { businessId, adAccountId };
}

// ── HTML parsers (metaTokens.js quality) ───────────────────────────────────

function _first(str, patterns, filter) {
  if (!str) return null;
  for (const p of patterns) {
    const m = str.match(p);
    if (m?.[1]) {
      const val = m[1].trim();
      if (!filter || filter(val)) return val;
    }
  }
  return null;
}

function parseDtsg(html) {
  if (!html) return '';
  const notEaa = (v) => v && !v.startsWith('EAA');
  return _first(html, [
    // Highest confidence — explicit DTSGInitialData structure
    /DTSGInitialData[^}]{0,300}"token"\s*:\s*"([^"]{8,100})"/,
    /"DTSGInitialData"[^}]{0,300}"token"\s*:\s*"([^"]{8,100})"/,
    // Direct dtsg object
    /"dtsg"\s*:\s*\{\s*"token"\s*:\s*"([^"]+)"/,
    // HTML form hidden input
    /name="fb_dtsg"\s+value="([^"]+)"/,
    /name="fb_dtsg"\s+value='([^']+)'/,
    // Relay store formats
    /"fb_dtsg"\s*,\s*"[^"]*"\s*,\s*"([^"]+)"/,
    /"s"\s*:\s*"fb_dtsg"\s*,\s*"v"\s*:\s*"([^"]+)"/,
    // Known prefixes
    /"token"\s*:\s*"(NAf[A-Za-z0-9_-]+)"/,
    /"token"\s*:\s*"(NACP[A-Za-z0-9_-]+)"/,
    /"token"\s*:\s*"(NAfw[A-Za-z0-9_-]+)"/,
    /"token"\s*:\s*"(NAcP[A-Za-z0-9_-]+)"/,
    /"token"\s*:\s*"(NAbb[A-Za-z0-9_-]+)"/,
    // Direct key
    /"fb_dtsg"\s*:\s*"([A-Za-z0-9_-]{8,})"/,
    // Global var
    /__DTSG\s*=\s*['"]([A-Za-z0-9_-]+)['"]/,
    // Broad fallback — last resort
    /"token"\s*:\s*"([A-Za-z0-9_-]{12,80})"/,
  ], notEaa) || '';
}

function parseLsd(html) {
  if (!html) return '';
  return _first(html, [
    /\["LSD",\[\d+\],\{"token":"([^"]+)"\}\]/,
    /\["LSD",\[\d+\],\{token:"([^"]+)"\}\]/,
    /"lsd"\s*:\s*"([^"]+)"/,
    /name="lsd"\s+value="([^"]+)"/,
    /"lsdToken"\s*:\s*"([^"]+)"/,
    /\["LSD",[^\]]*,"([A-Za-z0-9_-]{4,20})"\]/,
    /<meta\s+name="lsd"\s+content="([^"]+)"/,
  ]) || '';
}

function parseUserIdFromHtml(html) {
  if (!html) return '';
  return _first(html, [
    /"actorID"\s*:\s*"(\d{6,})"/,
    /"userID"\s*:\s*"(\d{6,})"/,
    /"USER_ID"\s*:\s*"(\d{6,})"/,
    /"viewer_actor_id"\s*:\s*"(\d{6,})"/,
    /"uid"\s*:\s*(\d{6,})/,
    /"uid"\s*:\s*"(\d{6,})"/,
  ]) || '';
}

/** Extract from all <script> blocks separately — catches split payloads */
function extractFromAllScripts(html) {
  if (!html) return { dtsg: '', lsd: '' };
  const blocks = html.match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
  const joined = blocks
    .map((s) => { const m = s.match(/<script[^>]*>([\s\S]*?)<\/script>/i); return m ? m[1] : ''; })
    .join('\n');
  return {
    dtsg: parseDtsg(joined) || parseDtsg(html),
    lsd:  parseLsd(joined)  || parseLsd(html),
  };
}

// ── Main session resolver ───────────────────────────────────────────────────

/**
 * Server-side session resolution — metaTokens quality.
 * Tries multiple URLs with redirect:follow + deep script extraction.
 * Fallback to cookie-embedded dtsg if HTTP fails.
 *
 * @param {string} cookies - Full cookie string (including httpOnly xs)
 * @param {string} pageUrl  - Actual URL the user has open (best signal)
 * @param {object|null} proxyInfo
 * @returns {{ dtsg, lsd, userId }}
 */
async function serverSideSession(cookies, pageUrl, proxyInfo = null) {
  const userId = extractUserIdFromCookies(cookies) || parseUserIdFromHtml('');
  if (!userId) throw new Error('لم يتم العثور على c_user في الكوكيز — يجب تسجيل الدخول أولاً');

  const bId = parseBillingUrl(pageUrl).businessId;

  // Priority URL list — /latest/ first (current FB schema), then legacy paths
  const urlsToTry = [
    pageUrl,
    bId ? `${SESSION_ORIGIN}/latest/billing_hub/?business_id=${bId}` : '',
    bId ? `${SESSION_ORIGIN}/latest/billing_hub/payment_accounts/?business_id=${bId}` : '',
    bId ? `${SESSION_ORIGIN}/latest/settings/?business_id=${bId}` : '',
    bId ? `${SESSION_ORIGIN}/billing_hub/payment_accounts/?business_id=${bId}` : '',
    `${SESSION_ORIGIN}/settings/billing/payment_methods/`,
    `${SESSION_ORIGIN}/billing_hub/`,
    bId ? `${SESSION_ORIGIN}/overview?business_id=${bId}` : '',
    `${SESSION_ORIGIN}/`,
    'https://www.facebook.com/',
    'https://www.facebook.com/adsmanager/manage/campaigns',
    'https://adsmanager.facebook.com/adsmanager/',
  ].filter(Boolean);

  let dtsg = '';
  let lsd  = '';

  for (const url of [...new Set(urlsToTry)]) {
    try {
      console.log(`[session] fetching: ${url.slice(0, 90)}`);
      // ★ FIX: كان مفيش timeout على أي fetch هنا — لو URL علّق كان بيستنى
      // على مهلة node-fetch الافتراضية، وده اللي كان بيطول الـ 41 ثانية
      const ctrl = new AbortController();
      const abortTimer = setTimeout(() => ctrl.abort(), 7000);
      let resp;
      try {
        resp = await chromeFetch(url, {
          method: 'GET',
          headers: { ...SESSION_HEADERS, 'Cookie': cookies, 'Referer': SESSION_ORIGIN },
          redirect: 'follow',   // ★ let node-fetch follow 302s automatically
          signal: ctrl.signal,
        }, proxyInfo);
      } finally {
        clearTimeout(abortTimer);
      }

      // Skip if landed on login / checkpoint
      const finalUrl = resp.url || url;
      if (/login|checkpoint|recover|disabled/i.test(finalUrl)) {
        console.log(`[session] auth wall at ${finalUrl.slice(0, 80)} — skipping`);
        continue;
      }

      const html = await resp.text();
      console.log(`[session] status=${resp.status} len=${html.length} finalUrl=${finalUrl.slice(0, 80)}`);

      if (resp.status < 200 || resp.status >= 400) continue;

      // Try full HTML first, then isolated script blocks
      const fromHtml = { dtsg: parseDtsg(html), lsd: parseLsd(html) };
      const fromScripts = (!fromHtml.dtsg || !fromHtml.lsd) ? extractFromAllScripts(html) : fromHtml;

      dtsg = dtsg || fromHtml.dtsg || fromScripts.dtsg;
      lsd  = lsd  || fromHtml.lsd  || fromScripts.lsd;

      if (dtsg && lsd) {
        console.log(`[session] ✅ dtsg=${dtsg.slice(0, 12)}… lsd=${lsd} userId=${userId}`);
        break;
      }
    } catch (err) {
      console.log(`[session] fetch error (${url.slice(0, 60)}): ${err.message}`);
    }
  }

  // ── Cookie-only dtsg fallback (weak — no lsd, but functional) ──
  if (!dtsg) {
    const cookieDtsg = extractDtsgFromCookies(cookies);
    if (cookieDtsg) {
      console.log(`[session] ⚠️ using cookie-embedded dtsg (no lsd) — strategy=cookie_dtsg`);
      dtsg = cookieDtsg;
    }
  }

  console.log(`[session] final: dtsg=${dtsg ? dtsg.slice(0, 12) + '…' : 'MISSING'} lsd=${lsd || 'MISSING'} userId=${userId}`);

  if (!dtsg) {
    throw new Error(
      'تعذّر استخراج fb_dtsg — تأكد من: (1) أنك فاتح صفحة business.facebook.com، ' +
      '(2) الكوكيز لم تنته، (3) الحساب غير موقوف أو موقوف مؤقتاً.'
    );
  }

  return { dtsg, lsd, userId };
}

// ============================================================
// FB GRAPHQL HELPER (server-side)
// ============================================================
async function fbGraphql(origin, params, cookies, lsd, proxyInfo = null) {
  const body = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) body.append(key, String(val));

  const headers = getChromeHeaders(cookies, {
    'x-fb-friendly-name': params.fb_api_req_friendly_name || 'GraphQL',
    'x-fb-lsd': lsd || '',
  });

  const resp = await chromeFetch(
    `${origin}/api/graphql/`,
    { method: 'POST', headers, body: body.toString() },
    proxyInfo
  );

  const text = await resp.text();
  const clean = text.replace(/^for\s*\(;;\s*\);?/, '');
  try {
    return JSON.parse(clean);
  } catch (e) {
    console.log(`[fbGraphql] parse error: ${text.slice(0, 200)}`);
    return { _raw: text.slice(0, 300), errors: [{ message: 'استجابة غير صالحة من Facebook' }] };
  }
}

// ============================================================
// FETCH CARDS ENDPOINT (NEW — fixes root causes 1-5)
// ============================================================
app.post('/fetch-cards', rateLimit({ max: 20, keyPrefix: 'fetch-cards' }), apiAuth, async (req, res) => {
  const { cookies, businessId, adAccountId, proxy: userProxy, pageUrl } = req.body;

  if (!cookies)    return res.status(400).json({ ok: false, error: 'الكوكيز مطلوبة' });
  if (!businessId) return res.status(400).json({ ok: false, error: 'business_id مطلوب' });

  // Resolve proxy
  let proxyInfo = null;
  let proxySource = 'none';
  if (userProxy?.trim()) {
    proxyInfo = parseProxy(userProxy.trim());
    proxySource = proxyInfo ? 'user' : 'none';
  } else {
    const sp = getNextServerProxy();
    if (sp) { proxyInfo = parseProxy(sp.raw); proxySource = `server:${sp.id}`; }
  }

  const proxyLabel = proxyInfo
    ? proxyDisplayLabel(proxyInfo)
    : (BRIGHT_DATA_KEY && USE_BRIGHT_DATA ? 'BrightData Web Unlocker' : 'بدون بروكسي');

  try {
    // Step 0: Resolve session server-side (fb_dtsg + lsd + userId)
    // ★ Use the actual page URL sent by the extension — best starting point
    const startUrl = pageUrl ||
      `${SESSION_ORIGIN}/latest/billing_hub/?business_id=${businessId}`;
    const session = await serverSideSession(cookies, startUrl, proxyInfo);

    const { dtsg: fb_dtsg, lsd, userId } = session;

    if (!fb_dtsg) {
      return res.json({ ok: false, error: 'تعذّر استخراج fb_dtsg — الكوكيز منتهية أو الحساب موقوف' });
    }

    // ★ FIX: كان فيه fallback خطير `adAccountId || businessId` — لو adAccountId
    // مش موجود كان بيبعت الـ business_id لفيسبوك على إنه ad/asset account ID،
    // وده اللي كان بيسبب field_exception (فيسبوك بيحاول يحل رقم من نوع غلط).
    // دلوقتي لو مفيش adAccountId نرجّع خطأ واضح بدل ما نبعت رقم غلط.
    let adId = adAccountId;
    if (!adId && pageUrl) {
      adId = parseBillingUrl(pageUrl).adAccountId;
    }
    if (!adId) {
      return res.json({ ok: false, error: 'تعذّر استخراج معرّف الحساب/الأصل (asset_id / account_id) من رابط الصفحة — افتح صفحة الفوترة الصحيحة وحاول تاني' });
    }

    // Step 1: Get billing payment account ID (doc_id 23945721255021756)
    console.log(`[fetch-cards] Step 1: get billing account ID — user=${userId} bm=${businessId} ad=${adId}`);
    const r1 = await fbGraphql(SESSION_ORIGIN, {
      av: userId, __user: userId, __bid: businessId, __aaid: adId,
      // ★ FIX: شلت __a:'1' و jazoest — مش موجودين في الأداة الشغالة (ccFromBm.js)
      // و jazoest كانت بصيغة غلط أصلاً (مش خوارزمية فيسبوك الحقيقية)
      fb_dtsg,
      lsd,
      fb_api_caller_class: 'RelayModern',
      fb_api_req_friendly_name: 'BillingHubPaymentMethodsViewQuery',
      variables: JSON.stringify({ businessID: businessId }),
      doc_id: '23945721255021756',
    }, cookies, lsd, proxyInfo);

    const payAccountId = r1?.data?.business?.billing_payment_account?.id;
    if (!payAccountId) {
      const errMsg = r1?.errors?.[0]?.message || r1?._raw || 'لم يتم العثور على حساب الفوترة';
      console.log(`[fetch-cards] Step 1 FAILED: ${errMsg}`);
      return res.json({ ok: false, error: `حساب الفوترة غير موجود: ${errMsg}` });
    }

    console.log(`[fetch-cards] Step 1 OK: payAccountId=${payAccountId}`);

    // Step 2: Get cards linked to payment account (doc_id 24585166657733775)
    console.log(`[fetch-cards] Step 2: get card list — payAccountId=${payAccountId}`);
    const r2 = await fbGraphql(SESSION_ORIGIN, {
      av: userId, __user: userId, __bid: businessId, __aaid: adId,
      fb_dtsg,
      lsd,
      fb_api_caller_class: 'RelayModern',
      fb_api_req_friendly_name: 'BillingHubPaymentMethodsBusinessSectionQuery',
      variables: JSON.stringify({
        paymentAccountID: payAccountId,
        billable_account_types: ['FB_ADS', 'WHATSAPP'],
        connected_asset_limit: 26,
        connected_asset_detail_limit: 5,
      }),
      doc_id: '24585166657733775',
    }, cookies, lsd, proxyInfo);

    const methods = r2?.data?.payment_account?.billing_payment_methods;
    if (!methods || methods.length === 0) {
      const errMsg = r2?.errors?.[0]?.message || 'لا توجد بطاقات مرتبطة بهذا الـ BM';
      console.log(`[fetch-cards] Step 2 FAILED: ${errMsg}`);
      return res.json({ ok: false, error: errMsg });
    }

    // ★ DEBUG: نطبع أول credential خام كامل — لو المشكلة استمرت في add-cards
    // هيبين لنا كل الحقول الحقيقية اللي فيسبوك بيرجعها بدل ما نخمن
    console.log(`[fetch-cards] raw credential[0]: ${JSON.stringify(methods[0]?.credential)}`);

    // Parse cards
    // ★ FIX: الكود الشغال (ccFromBm.js) بيستخدم credential_id بس — مفيش حقل
    // اسمه shared_biz_credential_id في الرد أصلاً، وده كان بيدي undefined
    // أو قيمة غلط في بعض الحالات
    const cards = methods
      .map(m => ({
        ...m.credential,
        sharedId: m.credential.credential_id,
        name: m.credential.card_association_name || '',
        last4: m.credential.last_four_digits || '',
      }))
      .filter(c => c.sharedId);

    if (!cards.length) {
      return res.json({ ok: false, error: 'لا توجد بطاقات مشتركة متاحة' });
    }

    console.log(`[fetch-cards] SUCCESS: ${cards.length} cards found`);

    // Return cards + resolved session (so /add-cards can reuse fb_dtsg/lsd)
    return res.json({
      ok: true,
      cards,
      session: {
        userId,
        businessId,
        adAccountId: adId,
        payAccountId,
        fb_dtsg,
        lsd,
        cookies,
      },
      proxyUsed: proxyLabel,
      proxySource,
    });

  } catch (err) {
    console.log(`[fetch-cards] ERROR: ${err.message}`);
    return res.json({ ok: false, error: err.message });
  }
});

// ============================================================
// ADD SHARED CARD
// ============================================================
// ── دالة حساب jazoest ──
function calcJazoest(s) {
  let n = 0;
  for (const c of s) n += c.charCodeAt(0);
  return String(n + 25000);
}

// ★ FIX: headers مطابقة تمامًا للكود الشغال (ccFromBm.js) — مستخدمة في addSharedCard
// بس، لأن فيسبوك بيطبّق فحوصات أشد على الـ mutations عن queries القراءة
const MINIMAL_FB_HEADERS = {
  'User-Agent':  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Accept':      'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'ar,en-US;q=0.7',
};

async function addSharedCard(params, proxyInfo = null) {
  const { user, ad, bm, token, sharedId, cookies, lsd, payAccountId } = params;
  const now  = Date.now();
  const uuid1 = Math.random().toString(36).slice(2, 11);
  const uuid2 = Math.random().toString(36).slice(2, 11);
  const extId = `upl_${now}_${uuid1}`, sessId = `upl_${now}_${uuid2}`;
  const wizardSess = `upl_wizard_${now}_${uuid2}`;
  const vars = {
    input: {
      // ★ REVERTED: كنت غيّرتها لـ payAccountId بناءً على نظرية مش متأكدة —
      // الكود الشغال (ccFromBm.js) بيستخدم adAccountId هنا، ولوج field_exception
      // الحقيقي أكد إن ده كان هو الغلط (بعتنا نوع ID غلط لفيسبوك)
      payment_legacy_account_id: ad, shared_biz_credential_id: sharedId,
      upl_logging_data: {
        context: 'billingaddpm', credential_id: sharedId,
        credential_type: 'CREDIT_CARD', entry_point: 'BILLING_HUB', external_flow_id: extId,
        target_name: 'BillingSaveSharedBizCardStateMutation', user_session_id: sessId,
        wizard_config_name: 'SELECT_PAYMENT_METHOD', wizard_name: 'ADD_PM_PUX_EP',
        wizard_session_id: wizardSess
      },
      actor_id: user, client_mutation_id: String(Date.now())
    },
    includeCreateNewFromOldFragment: false
  };
  const body = new URLSearchParams();

  body.append('av', user); body.append('__user', user);
  // ★ FIX: شلت __a:'1' و jazoest — نفس سبب التعديل في fbGraphql فوق
  body.append('__bid', bm); body.append('__aaid', ad);
  body.append('fb_dtsg', token);
  body.append('lsd', lsd || '');
  body.append('fb_api_caller_class', 'RelayModern');
  body.append('fb_api_req_friendly_name', 'BillingSaveSharedBizCardStateMutation');
  body.append('variables', JSON.stringify(vars));
  body.append('doc_id', '25126279877041501');

  const response = await chromeFetch(
    'https://business.facebook.com/api/graphql/',
    { method: 'POST', headers: {
        ...MINIMAL_FB_HEADERS,
        'Cookie': cookies,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'https://business.facebook.com',
        'X-FB-LSD': lsd || '',
        'X-FB-Friendly-Name': 'BillingSaveSharedBizCardStateMutation',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
      }, body: body.toString() },
    proxyInfo
  );
  const text = await response.text();
  console.log(`[addSharedCard] status=${response.status} len=${text.length} body=${text.slice(0, 300)}`);
  // ★ FIX: نفس الـ for(;;); stripping اللي في fbGraphql — كان ناقص هنا
  const clean = text.replace(/^for\s*\(;;\s*\);?/, '');
  let json;
  try { json = JSON.parse(clean); } catch (e) { throw new Error(`استجابة غير صالحة: ${text.slice(0, 200)}`); }
  if (json.errors) {
    const e = json.errors[0];
    console.log(`[addSharedCard] ERROR code=${e.code} severity=${e.severity} debug=${e.debug_link || 'none'}`);
    throw new Error(e.message || 'فشل غير معروف');
  }
  const cardResult = json.data?.xfb_billing_save_shared_biz_card ?? json.data?.billing_save_shared_biz_card;
  if (!cardResult) throw new Error('استجابة غير متوقعة: ' + text.slice(0, 200));
  return json;
}

// ============================================================
// ADD CARDS ENDPOINT (updated to accept server-resolved session)
// ============================================================
app.post('/add-cards', rateLimit({ max: 20, keyPrefix: 'add-cards' }), apiAuth, async (req, res) => {
  // The session object now comes from /fetch-cards with server-resolved values:
  // { userId, businessId, adAccountId, payAccountId, fb_dtsg, lsd, cookies }
  // OR the old format { user, ad, bm, token, cookies, lsd, ... } for backward compat
  const { session, cards, delaySec = 1, proxy: userProxy } = req.body;
  if (!session?.cookies) return res.status(400).json({ error: 'cookies مفقودة' });
  if (!cards?.length)    return res.json({ results: [], successCount: 0, total: 0, proxyUsed: null, proxySource: 'none' });

  // Normalize session: accept both new format (from /fetch-cards) and old format (from inject-main.js)
  const user     = session.userId   || session.user     || '';
  const ad       = session.adAccountId || session.ad      || '';
  const bm       = session.businessId  || session.bm      || '';
  const token    = session.fb_dtsg   || session.token   || '';
  const lsd      = session.lsd      || '';
  const cookies  = session.cookies  || '';
  // ★ FIX: بيجي من /fetch-cards (billing_payment_account.id) — ده اللي المفروض
  // يتبعت كـ payment_legacy_account_id مش adAccountId
  const payAccountId = session.payAccountId || session.payAccount || ad;

  let proxyInfo = null, proxySource = 'none';
  if (userProxy?.trim()) {
    proxyInfo   = parseProxy(userProxy.trim());
    proxySource = proxyInfo ? 'user' : 'none';
  } else {
    const sp = getNextServerProxy();
    if (sp) { proxyInfo = parseProxy(sp.raw); proxySource = `server:${sp.id}`; }
  }

  const proxyLabel = proxyInfo
    ? proxyDisplayLabel(proxyInfo)
    : (BRIGHT_DATA_KEY && USE_BRIGHT_DATA ? 'BrightData Web Unlocker' : 'بدون بروكسي');

  const results = [];
  for (let i = 0; i < cards.length; i++) {
    const card = cards[i];
    if (proxySource.startsWith('server') && !userProxy) {
      const sp = getNextServerProxy();
      if (sp) proxyInfo = parseProxy(sp.raw);
    }
    try {
      await addSharedCard({ user, ad, bm, token, sharedId: card.sharedId, cookies, lsd, payAccountId }, proxyInfo);
      results.push({ sharedId: card.sharedId, label: card.label, success: true });
    } catch (err) {
      results.push({ sharedId: card.sharedId, label: card.label, success: false, error: err.message });
      if (proxySource.startsWith('server:')) {
        const sid = proxySource.split(':')[1];
        const sp  = serverProxies.find(p => p.id === sid);
        if (sp) { sp.failCount = (sp.failCount || 0) + 1; if (sp.failCount >= 3) sp.lastStatus = 'dead'; saveServerProxies(serverProxies); }
      }
    }
    if (i < cards.length - 1 && delaySec > 0) await new Promise(r => setTimeout(r, delaySec * 1000));
  }
  res.json({ results, successCount: results.filter(r => r.success).length, total: cards.length, proxyUsed: proxyLabel, proxySource });
});

// ============================================================
// ADMIN DASHBOARD
// ============================================================
app.get('/admin', rateLimit({ max: 20, keyPrefix: 'admin' }), (req, res) => {
  const pass = req.query.pass;

  if (!pass || !ADMIN_PASS || !constantTimeEqual(pass, ADMIN_PASS)) {
    const warning = !ADMIN_PASS
      ? '<div style="color:#ffb15a;font-size:12px;text-align:center;margin-top:12px;">⚠️ لم يتم ضبط متغير البيئة ADMIN_PASS على Railway. أضف قيمة مثل: admin123</div>'
      : '<div style="color:#ff6060;font-size:12px;text-align:center;margin-top:12px;">❌ كلمة المرور غير صحيحة</div>';

    return res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login</title>
<style>
*{box-sizing:border-box} body{margin:0;font-family:'Segoe UI',sans-serif;background:#07090d;color:#eaeaea;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}
.box{width:min(420px,100%);background:#0d0d12;border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:28px;box-shadow:0 12px 30px rgba(0,0,0,.25)}
h1{margin:0 0 8px;font-size:26px;color:#7c6fff;text-align:center}
p{margin:0 0 20px;color:#a7a7b5;text-align:center;font-size:13px;line-height:1.7}
form{display:flex;flex-direction:column;gap:12px} input{width:100%;padding:12px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.08);background:#070710;color:#fff;font-size:14px;outline:none} input:focus{border-color:rgba(124,111,255,.6)}
button{padding:12px;border:none;border-radius:10px;background:#7c6fff;color:#fff;font-size:14px;font-weight:700;cursor:pointer}
</style>
</head>
<body>
<div class="box">
  <h1>🔐 Admin Login</h1>
  <p>أدخل كلمة مرور لوحة الإدارة لتشغيل لوحة التحكم.</p>
  <form method="get" action="/admin">
    <input type="password" name="pass" placeholder="كلمة المرور" required />
    <button type="submit">دخول</button>
  </form>
  ${warning}
</div>
</body>
</html>`);
  }

  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#07090d;color:#e0e0e0;font-family:'Segoe UI',sans-serif;padding:20px;min-height:100vh}
h1{color:#7c6fff;font-size:20px;margin-bottom:20px;letter-spacing:2px;display:flex;align-items:center;gap:8px}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:#0d0d12;border-radius:10px;padding:4px}
.tab{flex:1;padding:9px;text-align:center;border-radius:8px;cursor:pointer;font-size:12px;font-weight:700;color:#555;transition:all .2s;border:none;background:transparent}
.tab.active{background:#1a1a2e;color:#7c6fff;box-shadow:0 0 10px rgba(124,111,255,.15)}
.panel{display:none}.panel.active{display:block}
.card{background:#0d0d12;border:1px solid rgba(255,255,255,.06);border-radius:12px;padding:18px;margin-bottom:16px}
.card h2{font-size:11px;color:#555;letter-spacing:1px;margin-bottom:12px;text-transform:uppercase}
input,select{background:#070710;border:1px solid rgba(255,255,255,.08);border-radius:8px;color:#fff;padding:8px 12px;font-size:12px;outline:none}
input:focus,select:focus{border-color:rgba(124,111,255,.5)}
.row{display:flex;gap:8px;margin-bottom:8px}
.row input{flex:1}.row select{width:auto}
button{border:none;border-radius:8px;padding:8px 16px;font-size:12px;font-weight:700;cursor:pointer;transition:all .2s}
.btn-main{background:#7c6fff;color:#fff;width:100%;height:38px}
.btn-main:hover{background:#6a5de8}
.btn-sm{background:rgba(255,255,255,.06);color:#aaa;font-size:11px;padding:5px 10px}
.btn-danger{background:rgba(255,60,60,.1);color:#ff6060;border:1px solid rgba(255,60,60,.2)}
.btn-ok{background:rgba(124,111,255,.1);color:#7c6fff;border:1px solid rgba(124,111,255,.2)}
.btn-copy{background:rgba(0,200,120,.1);color:#00c878;border:1px solid rgba(0,200,120,.2)}
.stats{display:flex;gap:10px;margin-bottom:16px}
.stat{background:#0d0d12;border:1px solid rgba(255,255,255,.05);border-radius:8px;padding:10px 14px;flex:1;text-align:center}
.stat-num{font-size:22px;font-weight:700;color:#7c6fff}
.stat-label{font-size:10px;color:#444;margin-top:2px}
.list{display:flex;flex-direction:column;gap:6px}
.row-item{background:#070710;border:1px solid rgba(255,255,255,.05);border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:8px}
.row-item.dead,.row-item.expired,.row-item.exhausted{opacity:.5;border-color:rgba(255,60,60,.15)}
.row-item.ok{border-color:rgba(124,111,255,.2)}
.led{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.led.green{background:#00c878;box-shadow:0 0 5px #00c878}
.led.purple{background:#7c6fff;box-shadow:0 0 5px #7c6fff}
.led.red{background:#ff5050;box-shadow:0 0 5px #ff5050}
.led.gray{background:#333}
.item-body{flex:1;min-width:0}
.item-label{font-size:12px;color:#ccc;white-space:nowrap;overflow:hidden;overflow:text-overflow:ellipsis}
.item-meta{font-size:10px;color:#444;margin-top:2px}
.badge{font-size:9px;padding:2px 7px;border-radius:20px;font-weight:700;white-space:nowrap}
.badge-http{background:rgba(59,155,255,.12);color:#3b9eff}
.badge-socks{background:rgba(245,166,35,.12);color:#f5a623}
.badge-auth{background:rgba(0,200,120,.1);color:#00c878}
.badge-key{background:rgba(124,111,255,.12);color:#7c6fff}
.badge-exp{background:rgba(255,100,0,.1);color:#ff6400}
.badge-dead{background:rgba(255,60,60,.1);color:#ff5050}
.key-reveal{font-size:10px;font-family:monospace;background:#0a0a14;border:1px solid rgba(124,111,255,.2);border-radius:6px;padding:6px 10px;color:#7c6fff;word-break:break-all;margin-top:6px;display:none}
#msg{font-size:12px;color:#7c6fff;min-height:18px;margin-top:6px}
#msgK{font-size:12px;color:#00c878;min-height:18px;margin-top:6px}
.check-all-btn{background:rgba(124,111,255,.08);color:#7c6fff;border:1px solid rgba(124,111,255,.2);width:100%;height:36px;border-radius:8px;margin-bottom:10px}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:#0d0d12;border:1px solid rgba(124,111,255,.3);border-radius:14px;padding:20px;width:320px;max-width:90vw}
.modal h3{color:#7c6fff;font-size:14px;margin-bottom:12px}
.modal .key-box{font-family:monospace;font-size:11px;background:#070710;border:1px solid rgba(124,111,255,.3);border-radius:8px;padding:10px;color:#00c878;word-break:break-all;margin-bottom:12px}
.modal-btns{display:flex;gap:8px}
</style>
</head>
<body>
<h1>🔮 Admin Dashboard</h1>

<div class="tabs">
  <button class="tab active" onclick="switchTab('proxies')">🌐 بروكسيات</button>
  <button class="tab" onclick="switchTab('keys')">🔑 مفاتيح API</button>
</div>

<!-- ═══════════════ PROXIES PANEL ═══════════════ -->
<div id="panel-proxies" class="panel active">
  <div class="stats">
    <div class="stat"><div class="stat-num" id="pTotal">—</div><div class="stat-label">إجمالي</div></div>
    <div class="stat"><div class="stat-num" id="pActive" style="color:#00c878">—</div><div class="stat-label">نشط</div></div>
    <div class="stat"><div class="stat-num" id="pDead" style="color:#ff5050">—</div><div class="stat-label">ميت</div></div>
  </div>
  <div class="card">
    <h2>➕ إضافة بروكسي</h2>
    <input id="proxyInput" style="width:100%;margin-bottom:8px" placeholder="http://user:pass@host:port  أو  socks5://...  أو  host:port:user:pass"/>
    <button class="btn-main" onclick="addProxy()">إضافة + فحص فوري</button>
    <div id="msg"></div>
  </div>
  <div class="card">
    <h2>📋 بروكسيات السيرفر</h2>
    <button class="check-all-btn" onclick="checkAll()">🔄 فحص الكل</button>
    <div class="list" id="proxyList">جاري التحميل...</div>
  </div>
</div>

<!-- ═══════════════ KEYS PANEL ═══════════════ -->
<div id="panel-keys" class="panel">
  <div class="stats">
    <div class="stat"><div class="stat-num" id="kTotal">—</div><div class="stat-label">إجمالي</div></div>
    <div class="stat"><div class="stat-num" id="kActive" style="color:#7c6fff">—</div><div class="stat-label">نشط</div></div>
    <div class="stat"><div class="stat-num" id="kUsage" style="color:#00c878">—</div><div class="stat-label">استخدام اليوم</div></div>
  </div>
  <div class="card">
    <h2>➕ توليد مفتاح جديد</h2>
    <input id="keyLabel" style="width:100%;margin-bottom:8px" placeholder="اسم المفتاح (مثلاً: مستخدم 1)"/>
    <div class="row">
      <input id="keyDurationDays" type="number" placeholder="مدة الاشتراك بالأيام" style="flex:1" min="1"/>
      <input id="keyMax" type="number" placeholder="حد الاستخدام" style="width:130px" min="0"/>
    </div>
    <button class="btn-main" onclick="generateKey()">🔑 توليد مفتاح</button>
    <div id="msgK"></div>
  </div>
  <div class="card">
    <h2>📋 المفاتيح</h2>
    <div class="list" id="keyList">جاري التحميل...</div>
  </div>
</div>

<!-- ═══════════════ NEW KEY MODAL ═══════════════ -->
<div class="modal-overlay" id="keyModal">
  <div class="modal">
    <h3>✅ تم التوليد — احفظ المفتاح الآن</h3>
    <div class="key-box" id="modalKeyVal"></div>
    <div style="font-size:11px;color:#ff6400;margin-bottom:12px">⚠️ لن يُعرض مجدداً — انسخه الآن</div>
    <div class="modal-btns">
      <button class="btn-sm btn-copy" style="flex:1" onclick="copyModalKey()">📋 نسخ</button>
      <button class="btn-sm" style="flex:1" onclick="closeModal()">إغلاق</button>
    </div>
  </div>
</div>

<script>
const PASS = '${pass}';
let currentTab = 'proxies';
let modalKeyVal = '';

function switchTab(t) {
  currentTab = t;
  document.querySelectorAll('.tab').forEach((b,i)=>b.classList.toggle('active',['proxies','keys'][i]===t));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById('panel-'+t).classList.add('active');
  if (t==='proxies') loadProxies(); else loadKeys();
}

async function api(method, path, body) {
  try {
    const r = await fetch(path, {
      method, headers:{'Content-Type':'application/json','x-admin-pass':PASS},
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await r.text();
    try { return JSON.parse(text); } catch(e) { return { ok: false, error: 'استجابة غير صالحة: ' + text.slice(0,100) }; }
  } catch(e) {
    return { ok: false, error: 'خطأ في الاتصال: ' + e.message };
  }
}

// ════════════ PROXIES ════════════
async function loadProxies() {
  let data;
  try { data=await api('GET','/admin/proxies'); } catch(e){ document.getElementById('proxyList').innerHTML='<div style="color:#ff6060;font-size:12px;padding:8px">❌ فشل تحميل البروكسيات: '+e.message+'</div>'; return; }
  const list = data.proxies || [];
  document.getElementById('pTotal').textContent = list.length;
  document.getElementById('pActive').textContent = list.filter(p=>p.enabled&&p.lastStatus==='ok').length;
  document.getElementById('pDead').textContent  = list.filter(p=>p.lastStatus==='dead').length;
  const el = document.getElementById('proxyList');
  if (!list.length){el.innerHTML='<div style="color:#333;font-size:12px;padding:8px">لا توجد بروكسيات</div>';return;}
  el.innerHTML = list.map(p=>{
    const isOk=p.enabled&&p.lastStatus==='ok', isDead=p.lastStatus==='dead';
    const lc=isOk?'green':isDead?'red':'gray', rc=isOk?'ok':isDead?'dead':'';
    const tc=(p.type||'').includes('SOCKS')?'badge-socks':'badge-http';
    const chk=p.lastCheck?new Date(p.lastCheck).toLocaleTimeString('ar'):'—';
    return \`<div class="row-item \${rc}">
      <div class="led \${lc}"></div>
      <div class="item-body">
        <div class="item-label">\${p.label} \${p.hasAuth?'<span class="badge badge-auth">🔐</span>':''}</div>
        <div class="item-meta">آخر فحص: \${chk} | فشل: \${p.failCount||0}</div>
      </div>
      <span class="badge \${tc}">\${p.type||'HTTP'}</span>
      <button class="btn-sm btn-ok" onclick="recheckOne('\${p.id}')">فحص</button>
      <button class="btn-sm" onclick="toggleProxy('\${p.id}',\${!p.enabled})">\${p.enabled?'تعطيل':'تفعيل'}</button>
      <button class="btn-sm btn-danger" onclick="deleteProxy('\${p.id}')">حذف</button>
    </div>\`;
  }).join('');
}

async function addProxy(){
  const raw=document.getElementById('proxyInput').value.trim(); if(!raw)return;
  document.getElementById('msg').textContent='⏳ جاري الإضافة والفحص...';
  try {
    const d=await api('POST','/admin/proxies',{proxy:raw});
    if(d.ok){document.getElementById('msg').textContent=(d.checkResult&&d.checkResult.ok)?'✅ أضيف وشغال':'⚠️ أضيف لكن البروكسي لا يعمل';document.getElementById('proxyInput').value='';loadProxies();}
    else document.getElementById('msg').textContent='❌ '+(d.error||'خطأ');
  } catch(e){document.getElementById('msg').textContent='❌ خطأ: '+e.message;}
}
async function deleteProxy(id){if(!confirm('حذف؟'))return;try{await api('DELETE','/admin/proxies/'+id);}catch(e){}loadProxies();}
async function toggleProxy(id,e){try{await api('PATCH','/admin/proxies/'+id,{enabled:e});}catch(e){}loadProxies();}
async function recheckOne(id){document.getElementById('msg').textContent='⏳...';try{await api('POST','/admin/proxies/check-all');document.getElementById('msg').textContent='✅ تم';}catch(e){document.getElementById('msg').textContent='❌ خطأ: '+e.message;}loadProxies();}
async function checkAll(){document.getElementById('msg').textContent='⏳ جاري فحص الكل...';try{const d=await api('POST','/admin/proxies/check-all');const ok=(d.results||[]).filter(r=>r.ok).length;document.getElementById('msg').textContent=\`✅ \${ok}/\${(d.results||[]).length} شغالين\`;}catch(e){document.getElementById('msg').textContent='❌ خطأ: '+e.message;}loadProxies();}

// ════════════ KEYS ════════════
async function loadKeys(){
  let data;
  try { data=await api('GET','/admin/keys'); } catch(e){ document.getElementById('keyList').innerHTML='<div style="color:#ff6060;font-size:12px;padding:8px">❌ فشل تحميل المفاتيح: '+e.message+'</div>'; return; }
  const list=data.keys||[];
  document.getElementById('kTotal').textContent=list.length;
  document.getElementById('kActive').textContent=data.active||0;
  const total=(list.reduce((a,k)=>a+(k.usageCount||0),0));
  document.getElementById('kUsage').textContent=total;
  const el=document.getElementById('keyList');
  if(!list.length){el.innerHTML='<div style="color:#333;font-size:12px;padding:8px">لا توجد مفاتيح — ولّد مفتاحك الأول</div>';return;}
  el.innerHTML=list.map(k=>{
    const active=k.enabled&&!k.isExpired&&!k.isExhausted;
    const lc=active?'purple':k.isExpired||k.isExhausted?'red':'gray';
    const rc=active?'ok':k.isExpired||k.isExhausted?'expired':'';
    const daysLeft = k.daysLeft ?? null;
    const expBadge = k.isExpired
      ? '<span class="badge badge-dead">منتهي</span>'
      : k.expiresAt
        ? '<span class="badge badge-exp">⏰ ' + (daysLeft === 0 ? 'اليوم آخر يوم' : 'يبقى ' + daysLeft + ' يوم') + '</span>'
        : '<span class="badge badge-key">بدون انتهاء</span>';
    const exhaust=k.isExhausted?'<span class="badge badge-dead">الحد أُنهي</span>':'';
    const usage=k.maxUsage?k.usageCount+'/'+k.maxUsage:k.usageCount+' استخدام';
    const last=k.lastUsed?new Date(k.lastUsed).toLocaleString('ar'):'لم يُستخدم';
    return \`<div class="row-item \${rc}" id="ki-\${k.id}">
      <div class="led \${lc}"></div>
      <div class="item-body">
        <div class="item-label">\${k.label} <span class="badge badge-key">\${k.keyPreview}</span> \${expBadge} \${exhaust}</div>
        <div class="item-meta">استخدام: \${usage} | آخر استخدام: \${last}</div>
      </div>
      <button class="btn-sm btn-copy" onclick="revealKey('\${k.id}')">عرض</button>
      <button class="btn-sm btn-ok" onclick="resetUsage('\${k.id}')">صفّر</button>
      <button class="btn-sm" onclick="toggleKey('\${k.id}',\${!k.enabled})">\${k.enabled?'تعطيل':'تفعيل'}</button>
      <button class="btn-sm btn-danger" onclick="deleteKey('\${k.id}')">حذف</button>
    </div>\`;
  }).join('');
}

async function generateKey(){
  const label=document.getElementById('keyLabel').value.trim()||'مفتاح جديد';
  const durationDays = document.getElementById('keyDurationDays').value;
  const maxUsage=parseInt(document.getElementById('keyMax').value)||null;
  document.getElementById('msgK').style.color='#7c6fff';
  document.getElementById('msgK').textContent='⏳ جاري التوليد...';
  try {
    const d=await api('POST','/admin/keys',{label, durationDays: durationDays || null, maxUsage});
    if(d.ok && d.key && d.key.key){
      document.getElementById('msgK').style.color='#00c878';
      document.getElementById('msgK').textContent='✅ تم التوليد';
      document.getElementById('keyLabel').value='';
      document.getElementById('keyDurationDays').value='';
      document.getElementById('keyMax').value='';
      showModal(d.key.key);
      loadKeys();
    } else {
      document.getElementById('msgK').style.color='#ff6060';
      document.getElementById('msgK').textContent='❌ ' + (d.error || 'خطأ غير معروف');
    }
  } catch(e) {
    document.getElementById('msgK').style.color='#ff6060';
    document.getElementById('msgK').textContent='❌ خطأ: ' + e.message;
  }
}

async function revealKey(id){
  const d=await api('GET','/admin/keys/'+id+'/reveal');
  if(d.ok) showModal(d.key,d.label);
}

async function deleteKey(id){if(!confirm('حذف المفتاح؟'))return;await api('DELETE','/admin/keys/'+id);loadKeys();}
async function toggleKey(id,e){await api('PATCH','/admin/keys/'+id,{enabled:e});loadKeys();}
async function resetUsage(id){await api('POST','/admin/keys/'+id+'/reset-usage');loadKeys();}

function showModal(key, label=''){
  modalKeyVal=key;
  document.getElementById('modalKeyVal').textContent=key;
  document.getElementById('keyModal').classList.add('show');
}
function closeModal(){document.getElementById('keyModal').classList.remove('show');}
function copyModalKey(){navigator.clipboard.writeText(modalKeyVal);alert('✅ تم النسخ');}

// Init
loadProxies();
setInterval(()=>{ if(currentTab==='proxies') loadProxies(); else loadKeys(); }, 30000);
</script>
</body>
</html>`);
});

// ============================================================
// ROUTES
// ============================================================
app.get('/', (req, res) => res.json({
  status: 'ok', message: 'Beshoy BM Server v3',
  endpoints: ['GET /ping', 'POST /check-proxy (x-api-key)', 'POST /fetch-cards (x-api-key)', 'POST /add-cards (x-api-key)',
              'GET /admin?pass=... (admin)', 'GET /admin/proxies', 'POST /admin/proxies',
              'DELETE /admin/proxies/:id', 'PATCH /admin/proxies/:id',
              'POST /admin/proxies/check-all', 'GET /admin/keys', 'POST /admin/keys',
              'GET /admin/keys/:id/reveal', 'PATCH /admin/keys/:id',
              'DELETE /admin/keys/:id', 'POST /admin/keys/:id/reset-usage'],
  time: new Date().toISOString()
}));

app.get('/ping', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// 404 على أي راوت مش موجود — JSON مش HTML
app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Not found', path: req.originalUrl });
});

// error handler عام — يمنع Express من إرجاع صفحة HTML الافتراضية عند أي خطأ (زي CORS blocked)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && err.message);
  const status = err && err.status ? err.status : (err && err.message === 'CORS blocked' ? 403 : 500);
  res.status(status).json({ ok: false, error: err && err.message ? err.message : 'Server error' });
});

const PORT = process.env.PORT || 3000;

(async () => {
  try {
    const httpsM = await import('https-proxy-agent');
    const socksM = await import('socks-proxy-agent');
    HttpsProxyAgent = httpsM.HttpsProxyAgent;
    SocksProxyAgent = socksM.SocksProxyAgent;
    defaultChromeAgent = new https.Agent({
      ciphers: CHROME_CIPHERS, honorCipherOrder: false,
      minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', keepAlive: true,
    });
    app.listen(PORT, () => console.log(
      `\n✅ Server v3 on port ${PORT}\n` +
      `🔑 ADMIN_PASS: ${ADMIN_PASS ? 'set ✓' : '❌ NOT SET'}\n` +
      `🗝️  API Keys in store: ${apiKeys.length}\n`
    ));
  } catch (err) {
    console.error('Failed to start:', err);
    process.exit(1);
  }
})();
