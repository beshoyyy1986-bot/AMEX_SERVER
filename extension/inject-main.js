// Runs in the page's MAIN world (declared in manifest.json with "world":"MAIN").
// This bypasses Facebook's CSP because it's injected by the browser extension
// mechanism itself, not appended as a <script> element into the page DOM.
(function () {
  window.addEventListener('message', function (e) {
    if (e.source !== window) return;
    if (!e.data || e.data.__bshReq !== true) return;
    const id = e.data.id;
    const P = {};
    try {
      const R = window.require;
      try { const d = R('DTSGInitialData') || R('DTSGInitData'); P.tok = d && (d.token || d['token']) || ''; } catch (e) {}
      try { const lsdMod = R('LSD'); P.lsd = lsdMod && (lsdMod.token || lsdMod.LSD) || ''; } catch (e) {}
      try { const u = R('CurrentUserInitialData'); P.usr = String(u.USER_ID || ''); P.ad = String(u.ACCOUNT_ID || ''); } catch (e) {}
      try { const rv = R('ServerJS'); P.sr = rv.revision || ''; P.sb = rv.pkg_cohort || ''; } catch (e) {}
      try { P.creq = R('CometSSRPrerender')?.comet_req || '15'; } catch (e) {}
      try { P.dyn = R('__dynamicPageContext')?.dyn || ''; } catch (e) {}
      try { const ci = R('CometSSRPrerender') || {}; P.csr = ci.csr || ''; } catch (e) {}
      try { const h = R('WebSpeedTestResult') || R('BootloaderConfig') || {}; P.hs = h.hs || ''; P.hsi = h.hsi || ''; P.hsdp = h.hsdp || ''; P.hblp = h.hblp || ''; P.sjsp = h.sjsp || ''; } catch (e) {}
      try { const bd = R('BusinessAppMeta') || R('CurrentBusiness') || {}; P.bm = String(bd.businessID || bd.id || ''); } catch (e) {}
    } catch (e) {}
    try {
      const w = window.__additionalData && window.__additionalData[0] && window.__additionalData[0].data;
      if (w) { P.tok = P.tok || w.token; P.usr = P.usr || String(w.userID || ''); }
    } catch (e) {}
    if (!P.tok) {
      try {
        for (const sc of document.scripts) {
          const m = (sc.textContent || '').match(/"token"\s*:\s*"([A-Za-z0-9_\-]{20,})"/);
          if (m) { P.tok = m[1]; break; }
        }
      } catch (e) {}
    }
    if (!P.lsd) {
      try {
        const meta = document.querySelector('meta[name="lsd"]');
        if (meta) P.lsd = meta.getAttribute('content') || '';
      } catch (e) {}
      if (!P.lsd) {
        try {
          for (const sc of document.scripts) {
            const m = (sc.textContent || '').match(/"lsd"\s*:\s*"([A-Za-z0-9_\-]{20,})"/);
            if (m) { P.lsd = m[1]; break; }
          }
        } catch (e) {}
      }
    }
    try {
      const u = new URL(location.href);
      P.bm = P.bm || u.searchParams.get('business_id') || location.pathname.match(/\/(\d{10,})/)?.[1] || '';
      P.ad = P.ad || u.searchParams.get('account_id') || '';
    } catch (e) {}
    P.spin_t = String(Math.floor(Date.now() / 1000));
    P.cookies = document.cookie;
    console.log('[BSH SESSION]', { tok: P.tok?.slice(0,10)+'...', lsd: P.lsd, usr: P.usr, bm: P.bm, ad: P.ad });
    window.postMessage({ __bsh: id, payload: P }, '*');
  });
})();
