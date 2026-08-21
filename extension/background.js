// ═══════════════════════════════════════════════
//  BACKGROUND SERVICE WORKER
//  — يعمل خارج صفحة FB تماماً → لا قيود CSP
// ═══════════════════════════════════════════════

const DEFAULT_SERVER = 'https://3000-6a8836a626efe92ac86e3a51-191f73d386a798a0b228f164.imported.base44-preview.app';

// ── Get FULL cookie string (including httpOnly ones like `xs`) ──
// FIX v2.1: نستخدم URL بدل domain لأن xs مسجّل على www.facebook.com
// والـ host_permissions القديمة ما كانتش بتشمل www → xs كان مفقود
async function getFullCookieString() {
  try {
    const [c1, c2, c3] = await Promise.all([
      chrome.cookies.getAll({ url: 'https://www.facebook.com' }),
      chrome.cookies.getAll({ url: 'https://business.facebook.com' }),
      chrome.cookies.getAll({ url: 'https://facebook.com' }),
    ]);

    // Deduplicate by name (أول ظهور يكسب)
    const seen = new Set();
    const all = [...c1, ...c2, ...c3].filter(c => {
      if (seen.has(c.name)) return false;
      seen.add(c.name);
      return true;
    });

    const str = all.map(c => `${c.name}=${c.value}`).join('; ');
    const hasXs = /\bxs=/.test(str);
    console.log(`[BG] cookies collected: ${all.length} | len: ${str.length} | xs: ${hasXs}`);
    return str;
  } catch (err) {
    console.error('[BG] getFullCookieString error:', err);
    return '';
  }
}

// ── Main message handler ──────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── SERVER_FETCH: يُرحَّل من content.js لأنه يُحجب بسبب CSP ──
  if (msg.type === 'SERVER_FETCH') {
    chrome.storage.local.get(['serverUrl', 'apiKey'], async ({ serverUrl, apiKey }) => {
      const base = (serverUrl || DEFAULT_SERVER).replace(/\/$/, '');
      try {
        const storedKey = apiKey || '';
        const overrideHeaders = msg.headers || {};
        const opts = {
          method: msg.method || 'POST',
          headers: { 'Content-Type': 'application/json', ...overrideHeaders, 'x-api-key': storedKey || overrideHeaders['x-api-key'] || '' },
        };
        if (msg.body !== undefined) {
          const payload = { ...msg.body };
          // Swap in the full (httpOnly-inclusive) cookie string
          if (payload.session) {
            const fullCookies = await getFullCookieString();
            payload.session = { ...payload.session, cookies: fullCookies };
          }
          opts.body = JSON.stringify(payload);
        }

        const res = await fetch(base + msg.path, opts);
        let data;
        try { data = await res.json(); } catch { data = { _text: await res.text() }; }
        sendResponse({ ok: res.ok, status: res.status, data });
      } catch (err) {
        sendResponse({ ok: false, error: err.message, data: null });
      }
    });
    return true; // keep async channel open
  }

  // ── DIRECT_FETCH: طلبات لمصادر خارجية أخرى ──
  if (msg.type === 'DIRECT_FETCH') {
    (async () => {
      try {
        const res = await fetch(msg.url, {
          method: msg.method || 'GET',
          headers: msg.headers || {},
          body: msg.body || undefined,
        });
        let data;
        try { data = await res.json(); } catch { data = { _text: await res.text() }; }
        sendResponse({ ok: res.ok, status: res.status, data });
      } catch (err) {
        sendResponse({ ok: false, error: err.message, data: null });
      }
    })();
    return true;
  }

  return false;
});
