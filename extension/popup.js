// ═══════════════════════════════════════════
//  POPUP.JS — Activation + Settings & Launch
// ═══════════════════════════════════════════

let currentTab = null;
let isOnFB = false;
let activeServerUrl = '';
let activeApiKey = '';

// ── DOM refs: activation screen ───────────
const setupView      = document.getElementById('setupView');
const setupServerUrl = document.getElementById('setupServerUrl');
const setupApiKey    = document.getElementById('setupApiKey');
const setupMsg       = document.getElementById('setupMsg');
const btnActivate    = document.getElementById('btnActivate');

// ── DOM refs: main tool view ──────────────
const mainView     = document.getElementById('mainView');
const statusBar    = document.getElementById('statusBar');
const statusTxt    = document.getElementById('statusTxt');
const proxyInput   = document.getElementById('proxyInput');
const delayInput   = document.getElementById('delayInput');
const pxLed        = document.getElementById('pxLed');
const pxInfoTxt    = document.getElementById('pxInfoTxt');
const pxTypeBadge  = document.getElementById('pxTypeBadge');
const btnCheck     = document.getElementById('btnCheck');
const btnSave      = document.getElementById('btnSave');
const btnLaunch    = document.getElementById('btnLaunch');
const footerArea   = document.getElementById('footerArea');
const notFb        = document.getElementById('notFb');
const btnReset     = document.getElementById('btnReset');

// ── Helpers ───────────────────────────────
function setStatus(msg, state = '') {
  statusBar.className = 'status-bar ' + state;
  statusTxt.textContent = msg;
}

function setSetupMsg(msg, state = '') {
  setupMsg.className = 'act-msg ' + state;
  setupMsg.textContent = msg;
}

function setProxyLed(state, info = '', type = '') {
  pxLed.className = 'px-led ' + state;
  pxInfoTxt.textContent = info || (
    state === 'ok'       ? 'بروكسي شخصي • متصل ✓' :
    state === 'fail'     ? 'البروكسي لا يعمل' :
    state === 'checking' ? '⏳ جاري الفحص...' :
    proxyInput.value.trim()
      ? 'بروكسي مُدخل — غير محقق بعد'
      : 'فارغ → السيرفر يستخدم بروكسياته تلقائياً'
  );
  if (type) {
    pxTypeBadge.style.display = '';
    pxTypeBadge.textContent = type;
  } else {
    pxTypeBadge.style.display = 'none';
  }
}

async function serverFetch(path, body) {
  const base = activeServerUrl.replace(/\/$/, '');
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': activeApiKey },
    body: JSON.stringify(body || {}),
  });
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

// ── View switching ────────────────────────
function showSetupView() {
  setupView.style.display = '';
  mainView.style.display = 'none';
  btnReset.style.display = 'none';
}

function showMainView() {
  setupView.style.display = 'none';
  mainView.style.display = '';
  btnReset.style.display = '';
}

// ── Activation flow ────────────────────────
async function activate() {
  const serverUrl = setupServerUrl.value.trim().replace(/\/$/, '');
  const apiKey    = setupApiKey.value.trim();

  if (!serverUrl) { setSetupMsg('❌ اكتب عنوان السيرفر', 'err'); return; }
  if (!apiKey)    { setSetupMsg('❌ اكتب كود التفعيل', 'err'); return; }

  btnActivate.disabled = true;
  setSetupMsg('⏳ جاري التحقق من السيرفر...', 'chk');

  // 1) Check server reachability
  try {
    const res = await fetch(serverUrl + '/ping', { method: 'GET' });
    const d = await res.json();
    if (!d.ok) throw new Error('bad-response');
  } catch (e) {
    setSetupMsg('❌ تعذر الوصول للسيرفر — تحقق من الرابط', 'err');
    btnActivate.disabled = false;
    return;
  }

  // 2) Validate the API key against the protected endpoint
  setSetupMsg('⏳ جاري التحقق من كود التفعيل...', 'chk');
  try {
    const res = await fetch(serverUrl + '/check-proxy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({}),
    });
    if (res.status === 401) {
      setSetupMsg('❌ كود التفعيل غير صحيح', 'err');
      btnActivate.disabled = false;
      return;
    }
  } catch (e) {
    setSetupMsg('❌ خطأ أثناء التحقق: ' + e.message, 'err');
    btnActivate.disabled = false;
    return;
  }

  // 3) Success — persist and lock the fields away
  await chrome.storage.local.set({
    serverUrl, apiKey, activated: true,
  });
  activeServerUrl = serverUrl;
  activeApiKey = apiKey;

  setSetupMsg('✅ تم التفعيل بنجاح', 'ok');
  setTimeout(async () => {
    showMainView();
    await loadSettings();
    await checkTab();
    setStatus('✅ متصل • ' + serverUrl.replace('https://', ''), 'ok');
  }, 500);

  btnActivate.disabled = false;
}

// ── Reset activation (re-enter server/key) ─
async function resetActivation() {
  const ok = window.confirm('هل تريد إعادة ضبط بيانات الاتصال؟ سيُطلب منك إدخالها من جديد.');
  if (!ok) return;
  await chrome.storage.local.remove(['serverUrl', 'apiKey', 'activated']);
  activeServerUrl = '';
  activeApiKey = '';
  setupServerUrl.value = '';
  setupApiKey.value = '';
  setSetupMsg('', '');
  showSetupView();
}

// ── Load settings (proxy/delay only — no url/key shown) ─
async function loadSettings() {
  const data = await chrome.storage.local.get(['proxy', 'delay', 'proxyStatus', 'proxyType']);
  proxyInput.value  = data.proxy || '';
  delayInput.value  = data.delay ?? 1;

  if (data.proxy) {
    setProxyLed(data.proxyStatus || '', '', data.proxyType || '');
  } else {
    setProxyLed('', 'فارغ → السيرفر يستخدم بروكسياته تلقائياً');
  }
}

// ── Check active tab ──────────────────────
async function checkTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;
  isOnFB = !!tab?.url?.includes('business.facebook.com');

  if (isOnFB) {
    footerArea.style.display = '';
    notFb.style.display = 'none';
    btnLaunch.disabled = false;
    btnLaunch.textContent = '▶ Launch Tool على Facebook';
  } else {
    footerArea.style.display = 'none';
    notFb.style.display = '';
  }
}

// ── Ping server (status bar only, no fields) ─
async function pingServer() {
  setStatus('⏳ جاري الاتصال بالسيرفر...', 'chk');
  try {
    const res = await fetch(activeServerUrl + '/ping', { method: 'GET' });
    const d = await res.json();
    if (d.ok) setStatus('✅ متصل • ' + activeServerUrl.replace('https://', ''), 'ok');
    else       setStatus('⚠️ السيرفر رد بخطأ', 'err');
  } catch (e) {
    setStatus('❌ لا يوجد اتصال بالسيرفر', 'err');
  }
}

// ── Check proxy ───────────────────────────
async function checkProxy() {
  const px = proxyInput.value.trim();
  if (!px) {
    setProxyLed('', 'فارغ → السيرفر يستخدم بروكسياته تلقائياً');
    return;
  }
  setProxyLed('checking', '⏳ جاري الفحص...');
  btnCheck.textContent = '⏳';
  btnCheck.disabled = true;

  try {
    const { data: d } = await serverFetch('/check-proxy', { proxy: px });
    if (d.ok) {
      const type  = d.type || 'HTTP';
      const label = `✓ شغال — ${type}${d.hasAuth ? ' 🔐' : ''}  ${d.host}:${d.port}`;
      setProxyLed('ok', label, type);
      await chrome.storage.local.set({ proxyStatus: 'ok', proxyType: type });
    } else {
      setProxyLed('fail', '❌ ' + (d.error || 'لا يعمل'));
      await chrome.storage.local.set({ proxyStatus: 'fail', proxyType: '' });
    }
  } catch (e) {
    setProxyLed('fail', '❌ خطأ في الاتصال: ' + e.message);
    await chrome.storage.local.set({ proxyStatus: 'fail', proxyType: '' });
  }

  btnCheck.textContent = '🔍';
  btnCheck.disabled = false;
}

// ── Save settings (proxy/delay only) ──────
async function saveSettings() {
  const proxy = proxyInput.value.trim();
  const delay = parseInt(delayInput.value) || 0;

  await chrome.storage.local.set({ proxy, delay });

  btnSave.textContent = '✅ تم الحفظ';
  setTimeout(() => { btnSave.textContent = '💾 حفظ الإعدادات'; }, 1500);
}

// ── Launch tool in Facebook page ──────────
async function launchTool() {
  if (!currentTab?.id) return;
  btnLaunch.disabled = true;
  btnLaunch.textContent = '⏳ جاري الفتح...';

  try {
    await saveSettings();
    await chrome.tabs.sendMessage(currentTab.id, { type: 'TOGGLE_TOOL' });
    window.close();
  } catch (e) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        files: ['content.js'],
      });
      await new Promise(r => setTimeout(r, 300));
      await chrome.tabs.sendMessage(currentTab.id, { type: 'TOGGLE_TOOL' });
      window.close();
    } catch (e2) {
      btnLaunch.textContent = '❌ خطأ — أعد تحميل الصفحة';
      btnLaunch.disabled = false;
    }
  }
}

// ── Event listeners ───────────────────────
btnActivate.addEventListener('click', activate);
btnReset.addEventListener('click', resetActivation);
btnCheck.addEventListener('click', checkProxy);
btnSave.addEventListener('click', saveSettings);
btnLaunch.addEventListener('click', launchTool);

setupApiKey.addEventListener('keydown', (e) => { if (e.key === 'Enter') activate(); });

// ── Init ──────────────────────────────────
(async () => {
  const data = await chrome.storage.local.get(['serverUrl', 'apiKey', 'activated']);

  if (data.activated && data.serverUrl && data.apiKey) {
    activeServerUrl = data.serverUrl;
    activeApiKey = data.apiKey;
    showMainView();
    await loadSettings();
    await checkTab();
    await pingServer();
  } else {
    showSetupView();
  }
})();
