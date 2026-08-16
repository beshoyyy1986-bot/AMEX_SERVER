const express = require('express');
const cors = require('cors');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

let HttpsProxyAgent;
let SocksProxyAgent;

const app = express();

// ── Explicit CORS — allow any origin (bookmarklet/extension runs on business.facebook.com) ──
const corsOptions = {
  origin: '*',
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-pass', 'x-requested-with', 'authorization'],
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// ── Keep-alive & ping ──
app.get('/ping', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// ============================================================
// ADMIN PASSWORD — غيّره من Environment Variable (ADMIN_PASS)
// ============================================================
const ADMIN_PASS = process.env.ADMIN_PASS || 'beshoy2024';

// ============================================================
// SERVER PROXY STORE — بروكسيات السيرفر (rotation)
// ============================================================
const PROXIES_FILE = path.join('/tmp', 'server_proxies.json');

function loadServerProxies() {
  try {
    if (fs.existsSync(PROXIES_FILE)) {
      return JSON.parse(fs.readFileSync(PROXIES_FILE, 'utf8'));
    }
  } catch (e) {}
  return [];
}

function saveServerProxies(list) {
  try { fs.writeFileSync(PROXIES_FILE, JSON.stringify(list), 'utf8'); } catch (e) {}
}

// كل بروكسي: { id, raw, label, enabled, addedAt, lastCheck, lastStatus, failCount, host, port, type, hasAuth }
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
// PROXY PARSER
// ============================================================
function parseProxy(raw) {
  if (!raw || typeof raw !== 'string' || !raw.trim()) return null;
  raw = raw.trim();

  // protocol://... (http, https, socks, socks4, socks5)
  if (/^(https?|socks[45]?):\/\//i.test(raw)) {
    try {
      const u = new URL(raw);
      const proto = u.protocol.replace(':', '').toLowerCase();
      const port = parseInt(u.port) || (proto.startsWith('socks') ? 1080 : 8080);
      return {
        protocol: proto,
        host: u.hostname,
        port: port,
        username: u.username ? decodeURIComponent(u.username) : null,
        password: u.password ? decodeURIComponent(u.password) : null,
        url: raw,
      };
    } catch (e) { return null; }
  }

  // host:port:user:pass
  const parts = raw.split(':');
  if (parts.length === 4 && !raw.includes('@')) {
    return buildProxyObj('http', parts[0], parts[1], parts[2], parts[3]);
  }

  // user:pass@host:port
  if (raw.includes('@')) {
    const atIdx = raw.lastIndexOf('@');
    const creds = raw.substring(0, atIdx);
    const hostPart = raw.substring(atIdx + 1);
    const [credUser, ...credPass] = creds.split(':');
    const [host, port] = hostPart.split(':');
    return buildProxyObj('http', host, port, credUser, credPass.join(':'));
  }

  // host:port
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
  const pr = (p.protocol || '').toUpperCase();
  if (pr.includes('SOCKS4')) return 'SOCKS4';
  if (pr.includes('SOCKS5')) return 'SOCKS5';
  if (pr.includes('SOCKS')) return 'SOCKS';
  if (pr === 'HTTPS') return 'HTTPS';
  return 'HTTP';
}

function proxyDisplayLabel(parsed) {
  if (!parsed) return 'unknown';
  const type = getProxyTypeLabel(parsed);
  const auth = parsed.username ? '🔐' : '';
  return `${type}${auth} ${parsed.host}:${parsed.port}`;
}

// ============================================================
// CHROME TLS + FETCH
// ============================================================
const CHROME_CIPHERS = [
  'TLS_AES_128_GCM_SHA256','TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-CHACHA20-POLY1305','ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-RSA-AES128-SHA','ECDHE-RSA-AES256-SHA','AES128-GCM-SHA256',
  'AES256-GCM-SHA384','AES128-SHA','AES256-SHA'
].join(':');

function createProxyAgent(proxyInfo) {
  if (!proxyInfo) return null;
  const { protocol, url } = proxyInfo;
  if (protocol && protocol.toLowerCase().startsWith('socks')) {
    return new SocksProxyAgent(url);
  }
  return new HttpsProxyAgent(url);
}

let defaultChromeAgent;

function getChromeHeaders(cookies, extra = {}) {
  const lsdMatch = (cookies || '').match(/lsd=([^;]+)/);
  const lsdVal = lsdMatch?.[1] || extra['x-fb-lsd'] || 'q9vNxXN6fvGqQxpxVlG7Ap';
  return {
    'sec-ch-ua': '"Google Chrome";v="120", "Chromium";v="120", "Not?A_Brand";v="8"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'x-fb-friendly-name': extra['x-fb-friendly-name'] || 'GraphQL',
    'x-fb-lsd': lsdVal,
    'content-type': 'application/x-www-form-urlencoded',
    'x-requested-with': 'XMLHttpRequest',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'accept': '*/*',
    'origin': 'https://business.facebook.com',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
    'referer': 'https://business.facebook.com/billing/payments/',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'en-US,en;q=0.9',
    'cookie': cookies || '',
    ...extra
  };
}

async function chromeFetch(url, options = {}, proxyInfo = null) {
  const fetch = require('node-fetch');
  const agent = proxyInfo ? createProxyAgent(proxyInfo) : defaultChromeAgent;
  return fetch(url, { ...options, agent, compress: true });
}

// ============================================================
// CHECK PROXY
// ============================================================
async function checkProxyAlive(raw) {
  const parsed = parseProxy(raw);
  if (!parsed) return { ok: false, error: 'صيغة غير صحيحة', parsed: null };

  let t;
  try {
    const fetch = require('node-fetch');
    const agent = createProxyAgent(parsed);
    const ctrl = new AbortController();
    t = setTimeout(() => ctrl.abort(), 9000);
    const r = await fetch('https://www.facebook.com/robots.txt', {
      method: 'GET', agent, signal: ctrl.signal,
      headers: { 'user-agent': 'Mozilla/5.0 Chrome/120' }
    });
    clearTimeout(t);
    const ok = r.status >= 200 && r.status < 500;
    return { ok, parsed, error: ok ? null : `FB رد بـ ${r.status}`, statusCode: r.status };
  } catch (err) {
    if (t) clearTimeout(t);
    let msg = err.message || 'فشل';
    if (err.name === 'AbortError') msg = 'timeout — بطيء أو غير متاح';
    else if (msg.includes('ECONNREFUSED')) msg = 'رفض الاتصال';
    else if (msg.includes('ENOTFOUND')) msg = 'DNS error';
    else if (msg.includes('ETIMEDOUT')) msg = 'timeout';
    else if (msg.includes('auth')) msg = 'خطأ في الباسورد';
    return { ok: false, error: msg, parsed };
  }
}

// ============================================================
// ADMIN AUTH MIDDLEWARE
// ============================================================
function adminAuth(req, res, next) {
  const pass = req.headers['x-admin-pass'] || req.query.pass;
  if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ============================================================
// PUBLIC: CHECK PROXY
// ============================================================
app.post('/check-proxy', async (req, res) => {
  const { proxy } = req.body;
  if (!proxy || !proxy.trim()) return res.json({ ok: false, error: 'لم تدخل بروكسي', type: null });
  const result = await checkProxyAlive(proxy);
  res.json({
    ok: result.ok,
    error: result.error || null,
    type: result.parsed ? getProxyTypeLabel(result.parsed) : null,
    host: result.parsed?.host,
    port: result.parsed?.port,
    hasAuth: !!(result.parsed?.username),
  });
});

// ============================================================
// ADMIN: PROXIES MANAGEMENT
// ============================================================
app.get('/admin/proxies', adminAuth, (req, res) => {
  const safeList = serverProxies.map(p => ({
    id: p.id,
    label: p.label,
    enabled: p.enabled,
    addedAt: p.addedAt,
    lastCheck: p.lastCheck,
    lastStatus: p.lastStatus,
    failCount: p.failCount,
    type: p.type,
    hasAuth: p.hasAuth,
    host: p.host,
    port: p.port,
  }));
  res.json({ proxies: safeList, total: safeList.length, active: safeList.filter(p => p.enabled && p.lastStatus !== 'dead').length });
});

app.post('/admin/proxies', adminAuth, async (req, res) => {
  const { proxy } = req.body;
  if (!proxy || !proxy.trim()) return res.status(400).json({ error: 'proxy مطلوب' });

  const parsed = parseProxy(proxy.trim());
  if (!parsed) return res.status(400).json({ error: 'صيغة غير صحيحة' });

  const check = await checkProxyAlive(proxy.trim());

  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    raw: proxy.trim(),
    label: proxyDisplayLabel(parsed),
    host: parsed.host,
    port: parsed.port,
    type: getProxyTypeLabel(parsed),
    hasAuth: !!(parsed.username),
    enabled: true,
    addedAt: new Date().toISOString(),
    lastCheck: new Date().toISOString(),
    lastStatus: check.ok ? 'ok' : 'dead',
    failCount: check.ok ? 0 : 1,
  };

  serverProxies.push(entry);
  saveServerProxies(serverProxies);

  res.json({ ok: true, proxy: { ...entry, raw: undefined }, checkResult: { ok: check.ok, error: check.error } });
});

app.delete('/admin/proxies/:id', adminAuth, (req, res) => {
  const before = serverProxies.length;
  serverProxies = serverProxies.filter(p => p.id !== req.params.id);
  saveServerProxies(serverProxies);
  res.json({ ok: serverProxies.length < before });
});

app.patch('/admin/proxies/:id', adminAuth, (req, res) => {
  const p = serverProxies.find(p => p.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'not found' });
  if (req.body.enabled !== undefined) p.enabled = !!req.body.enabled;
  saveServerProxies(serverProxies);
  res.json({ ok: true, proxy: { ...p, raw: undefined } });
});

app.post('/admin/proxies/check-all', adminAuth, async (req, res) => {
  const results = [];
  for (const p of serverProxies) {
    const check = await checkProxyAlive(p.raw);
    p.lastCheck = new Date().toISOString();
    p.lastStatus = check.ok ? 'ok' : 'dead';
    if (!check.ok) p.failCount = (p.failCount || 0) + 1;
    else p.failCount = 0;
    results.push({ id: p.id, label: p.label, ok: check.ok, error: check.error });
  }
  saveServerProxies(serverProxies);
  res.json({ results });
});

// ============================================================
// ADD SHARED CARD
// ============================================================
async function addSharedCard(params, proxyInfo = null) {
  const { user, ad, bm, token, dyn, csr, hs, hsi, hsdp, hblp, sjsp,
          spin_r, spin_b, spin_t, comet_req, sharedId, cookies } = params;

  const now = Date.now();
  const uuid1 = Math.random().toString(36).slice(2, 10);
  const uuid2 = Math.random().toString(36).slice(2, 10);
  const extId = `upl_${now}_${uuid1}`;
  const sessId = `upl_${now}_${uuid2}`;
  const wizardSess = `upl_wizard_${now}_${uuid2}`;
  const mutationId = String(Math.floor(Math.random() * 100));

  const vars = {
    input: {
      payment_legacy_account_id: ad, shared_biz_credential_id: sharedId,
      upl_logging_data: {
        billing_notification_id: "", context: "billingaddpm", credential_id: sharedId,
        credential_type: "INLINE_BM", entry_point: "BILLING_HUB", external_flow_id: extId,
        target_name: "BillingSaveSharedBizCardStateMutation", user_session_id: sessId,
        wizard_config_name: "SELECT_PAYMENT_METHOD", wizard_name: "ADD_PM_PUX_EP",
        wizard_screen_name: "wizard_landing_state_display", wizard_session_id: wizardSess
      },
      actor_id: user, client_mutation_id: mutationId
    },
    includeCreateNewFromOldFragment: false
  };

  const body = new URLSearchParams();
  const ai = (k, v) => { if (v) body.append(k, v); };
  body.append('av', user); body.append('__aaid', ad); body.append('__bid', bm);
  body.append('__user', user); body.append('__a', '1'); body.append('fb_dtsg', token);
  body.append('jazoest', '25805'); body.append('lsd', 'q9vNxXN6fvGqQxpxVlG7Ap');
  body.append('__spin_r', spin_r || ''); body.append('__spin_b', spin_b || '');
  body.append('__spin_t', String(now)); body.append('__jssesw', '1');
  body.append('__comet_req', comet_req || '15');
  ai('__dyn', dyn); ai('__csr', csr); ai('__hs', hs); ai('__hsi', hsi);
  ai('__hsdp', hsdp); ai('__hblp', hblp); ai('__sjsp', sjsp);
  body.append('fb_api_caller_class', 'RelayModern');
  body.append('fb_api_req_friendly_name', 'BillingSaveSharedBizCardStateMutation');
  body.append('server_timestamps', 'true');
  body.append('variables', JSON.stringify(vars));
  body.append('doc_id', '25126279877041501');

  const lsdMatch = (cookies || '').match(/lsd=([^;]+)/);
  const response = await chromeFetch(
    'https://business.facebook.com/api/graphql/?_callFlowletID=0&_triggerFlowletID=2596',
    { method: 'POST', headers: getChromeHeaders(cookies || '', {
      'x-fb-friendly-name': 'BillingSaveSharedBizCardStateMutation',
      'x-fb-lsd': lsdMatch?.[1] || 'q9vNxXN6fvGqQxpxVlG7Ap'
    }), body: body.toString() },
    proxyInfo
  );

  const text = await response.text();
  let json;
  try {
    // Facebook responses are prefixed with "for (;;);" to prevent JSON hijacking
    const cleanText = text.replace(/^for \(;;\);/, '');
    json = JSON.parse(cleanText);
  } catch (e) {
    throw new Error(`استجابة غير صالحة من FB: ${text.slice(0, 150)}`);
  }

  if (json.errors) throw new Error(json.errors[0]?.message || 'فشل إضافة البطاقة من فيسبوك');
  if (!json.data?.billing_save_shared_biz_card) throw new Error(`استجابة غير متوقعة من FB`);
  return json;
}

// ============================================================
// ADD CARDS ENDPOINT
// ============================================================
app.post('/add-cards', async (req, res) => {
  const { session, cards, delaySec = 1, proxy: userProxy } = req.body;

  if (!session?.cookies) return res.status(400).json({ error: 'cookies مفقودة' });
  if (!cards?.length) return res.json({ results: [], successCount: 0, total: 0, proxyUsed: null, proxySource: 'none' });

  let baseProxyInfo = null;
  let isUserProxy = false;

  if (userProxy && typeof userProxy === 'string' && userProxy.trim()) {
    baseProxyInfo = parseProxy(userProxy.trim());
    isUserProxy = !!baseProxyInfo;
  }

  const results = [];

  for (let i = 0; i < cards.length; i++) {
    const card = cards[i];
    let cardProxyInfo = null;
    let cardProxyObj = null;
    let cardProxySource = 'none';

    if (isUserProxy) {
      cardProxyInfo = baseProxyInfo;
      cardProxySource = 'user';
    } else {
      const sp = getNextServerProxy();
      if (sp) {
        cardProxyInfo = parseProxy(sp.raw);
        cardProxyObj = sp;
        cardProxySource = `server:${sp.id}`;
      }
    }

    const cardProxyLabel = cardProxyInfo ? proxyDisplayLabel(cardProxyInfo) : 'بدون بروكسي';

    try {
      await addSharedCard({ ...session, sharedId: card.sharedId }, cardProxyInfo);
      results.push({ sharedId: card.sharedId, label: card.label, success: true, proxyUsed: cardProxyLabel, proxySource: cardProxySource });
      console.log(`  ✅ ${card.label} (${cardProxyLabel})`);
    } catch (err) {
      results.push({ sharedId: card.sharedId, label: card.label, success: false, error: err.message, proxyUsed: cardProxyLabel, proxySource: cardProxySource });
      console.log(`  ❌ ${card.label} — ${err.message}`);
      if (cardProxyObj) {
        cardProxyObj.failCount = (cardProxyObj.failCount || 0) + 1;
        if (cardProxyObj.failCount >= 3) cardProxyObj.lastStatus = 'dead';
        saveServerProxies(serverProxies);
      }
    }

    if (i < cards.length - 1 && delaySec > 0) await new Promise(r => setTimeout(r, delaySec * 1000));
  }

  const successCount = results.filter(r => r.success).length;
  const lastResult = results[results.length - 1] || {};
  res.json({
    results,
    successCount,
    total: cards.length,
    proxyUsed: lastResult.proxyUsed || 'بدون بروكسي',
    proxySource: lastResult.proxySource || 'none'
  });
});

// ============================================================
// ADMIN DASHBOARD & BASE ROUTES
// ============================================================
app.get('/admin', adminAuth, (req, res) => {
  const pass = req.query.pass;
  res.send(`<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Proxy Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0a0a;color:#e0e0e0;font-family:'Segoe UI',sans-serif;padding:20px;min-height:100vh}
h1{color:#00ffc8;font-size:20px;margin-bottom:20px;letter-spacing:2px}
.card{background:#111;border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:18px;margin-bottom:16px}
.card h2{font-size:13px;color:#888;letter-spacing:1px;margin-bottom:12px;text-transform:uppercase}
input{background:#0d0d0d;border:1px solid rgba(255,255,255,0.1);border-radius:8px;color:#fff;padding:9px 12px;font-size:13px;width:100%;outline:none;margin-bottom:8px}
input:focus{border-color:rgba(0,255,200,0.4)}
button{border:none;border-radius:8px;padding:8px 18px;font-size:12px;font-weight:700;cursor:pointer;transition:all .2s}
.btn-main{background:#00ffc8;color:#000;width:100%;height:38px}
.btn-main:hover{background:#00e6b5}
.btn-sm{background:rgba(255,255,255,0.08);color:#ccc;font-size:11px;padding:5px 12px}
.btn-danger{background:rgba(255,50,50,0.15);color:#ff6060;border:1px solid rgba(255,50,50,0.2)}
.btn-check{background:rgba(0,255,200,0.1);color:#00ffc8;border:1px solid rgba(0,255,200,0.2)}
.proxy-list{display:flex;flex-direction:column;gap:8px}
.proxy-row{background:#0d0d0d;border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:10px}
.proxy-row.dead{border-color:rgba(255,50,50,0.2);opacity:.6}
.proxy-row.ok{border-color:rgba(0,255,200,0.15)}
.led{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.led.green{background:#00ffc8;box-shadow:0 0 6px #00ffc8}
.led.red{background:#ff5050;box-shadow:0 0 6px #ff5050}
.led.gray{background:#555}
.proxy-label{flex:1;font-size:12px;color:#ccc}
.proxy-meta{font-size:10px;color:#555;margin-top:2px}
.badge{font-size:10px;padding:2px 8px;border-radius:20px;font-weight:700}
.badge-http{background:rgba(59,155,255,0.15);color:#3b9eff}
.badge-socks{background:rgba(245,166,35,0.15);color:#f5a623}
.badge-auth{background:rgba(0,255,200,0.1);color:#00ffc8}
.stats{display:flex;gap:10px;margin-bottom:16px}
.stat{background:#111;border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:10px 14px;flex:1;text-align:center}
.stat-num{font-size:22px;font-weight:700;color:#00ffc8}
.stat-label{font-size:10px;color:#555;margin-top:2px}
#msg{font-size:12px;color:#00ffc8;min-height:18px;margin-top:6px}
.check-all-btn{background:rgba(0,255,200,0.08);color:#00ffc8;border:1px solid rgba(0,255,200,0.2);width:100%;height:36px;border-radius:8px;margin-bottom:12px}
</style>
</head>
<body>
<h1>💳 Proxy Dashboard</h1>

<div class="stats">
  <div class="stat"><div class="stat-num" id="totalCount">—</div><div class="stat-label">إجمالي</div></div>
  <div class="stat"><div class="stat-num" id="activeCount" style="color:#00ffc8">—</div><div class="stat-label">نشط</div></div>
  <div class="stat"><div class="stat-num" id="deadCount" style="color:#ff5050">—</div><div class="stat-label">ميت</div></div>
</div>

<div class="card">
  <h2>➕ إضافة بروكسي جديد</h2>
  <input id="proxyInput" placeholder="http://user:pass@host:port  أو  host:port:user:pass  أو  socks5://..." />
  <button class="btn-main" onclick="addProxy()">إضافة + فحص فوري</button>
  <div id="msg"></div>
</div>

<div class="card">
  <h2>📋 بروكسيات السيرفر</h2>
  <button class="check-all-btn" onclick="checkAll()">🔄 فحص الكل الآن</button>
  <div class="proxy-list" id="proxyList">جاري التحميل...</div>
</div>

<script>
const PASS = '${pass}';
const API = '';

async function api(method, path, body) {
  const r = await fetch(API + path, {
    method, headers: {'Content-Type':'application/json','x-admin-pass':PASS},
    body: body ? JSON.stringify(body) : undefined
  });
  return r.json();
}

async function loadProxies() {
  const data = await api('GET', '/admin/proxies');
  const list = data.proxies || [];
  document.getElementById('totalCount').textContent = list.length;
  document.getElementById('activeCount').textContent = list.filter(p => p.enabled && p.lastStatus === 'ok').length;
  document.getElementById('deadCount').textContent = list.filter(p => p.lastStatus === 'dead').length;

  const el = document.getElementById('proxyList');
  if (!list.length) { el.innerHTML = '<div style="color:#555;font-size:12px;padding:8px">لا توجد بروكسيات</div>'; return; }

  el.innerHTML = list.map(p => {
    const isOk = p.enabled && p.lastStatus === 'ok';
    const isDead = p.lastStatus === 'dead';
    const ledClass = isOk ? 'green' : isDead ? 'red' : 'gray';
    const rowClass = isOk ? 'ok' : isDead ? 'dead' : '';
    const typeClass = (p.type||'').includes('SOCKS') ? 'badge-socks' : 'badge-http';
    const checked = p.lastCheck ? new Date(p.lastCheck).toLocaleTimeString('ar') : '—';
    return \`<div class="proxy-row \${rowClass}">
      <div class="led \${ledClass}"></div>
      <div style="flex:1">
        <div class="proxy-label">\${p.label} \${p.hasAuth ? '<span class="badge badge-auth">🔐 Auth</span>' : ''}</div>
        <div class="proxy-meta">آخر فحص: \${checked} | فشل: \${p.failCount||0}</div>
      </div>
      <span class="badge \${typeClass}">\${p.type||'HTTP'}</span>
      <button class="btn-sm btn-check" onclick="recheckProxy('\${p.id}')">فحص</button>
      <button class="btn-sm" onclick="toggleProxy('\${p.id}', \${!p.enabled})">\${p.enabled ? 'تعطيل' : 'تفعيل'}</button>
      <button class="btn-sm btn-danger" onclick="deleteProxy('\${p.id}')">حذف</button>
    </div>\`;
  }).join('');
}

async function addProxy() {
  const raw = document.getElementById('proxyInput').value.trim();
  if (!raw) return;
  document.getElementById('msg').textContent = '⏳ جاري الإضافة والفحص...';
  const data = await api('POST', '/admin/proxies', { proxy: raw });
  if (data.ok) {
    document.getElementById('msg').textContent = data.checkResult.ok ? '✅ أضيف وهو شغال' : '⚠️ أضيف لكن البروكسي لا يعمل حالياً';
    document.getElementById('proxyInput').value = '';
    loadProxies();
  } else {
    document.getElementById('msg').textContent = '❌ ' + (data.error || 'خطأ');
  }
}

async function deleteProxy(id) {
  if (!confirm('حذف؟')) return;
  await api('DELETE', '/admin/proxies/' + id);
  loadProxies();
}

async function toggleProxy(id, enabled) {
  await api('PATCH', '/admin/proxies/' + id, { enabled });
  loadProxies();
}

async function recheckProxy(id) {
  document.getElementById('msg').textContent = '⏳ جاري الفحص...';
  await api('POST', '/admin/proxies/check-all');
  document.getElementById('msg').textContent = '✅ تم الفحص';
  loadProxies();
}

async function checkAll() {
  document.getElementById('msg').textContent = '⏳ جاري فحص الكل...';
  const data = await api('POST', '/admin/proxies/check-all');
  const ok = (data.results||[]).filter(r=>r.ok).length;
  document.getElementById('msg').textContent = \`✅ انتهى: \${ok}/\${(data.results||[]).length} شغالين\`;
  loadProxies();
}

loadProxies();
setInterval(loadProxies, 30000);
</script>
</body>
</html>`);
});

app.get('/', (req, res) => res.json({
  status: 'ok', message: 'TOOL_AMEX server',
  endpoints: ['GET /', 'GET /ping', 'POST /check-proxy', 'POST /add-cards',
              'GET /admin?pass=...', 'GET /admin/proxies', 'POST /admin/proxies',
              'DELETE /admin/proxies/:id', 'PATCH /admin/proxies/:id',
              'POST /admin/proxies/check-all'],
  time: new Date().toISOString()
}));

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
    app.listen(PORT, () => console.log(`\n✅ Server on port ${PORT}\n🔑 Admin: /admin?pass=${ADMIN_PASS}\n`));
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
})();
