/* Interactive preview of the first-boot wizard: the page the firmware serves
 * (main/gen_index_html_gz.py through tools/ui_build.cjs) against the mock
 * gateway of tools/test_first_boot_ui.cjs, with synthetic data only. The BOOT
 * button is pressed by itself, and a small preview-only script walks the
 * first steps so the page opens directly on the choice of functions. Nothing
 * reaches a real gateway.
 *
 *   NODE_PATH=<playwright> node tools/preview_first_boot.cjs [--port 8767] [--shots <dir>]
 *
 * Cases (?case=...): wol (only Wake-on-LAN, no Tailscale; default), skip
 * (continue without Tailscale), tailnet (with a key), ethernet (cable, no
 * Tailscale), manual (whole wizard by hand). --shots saves desktop and phone
 * screenshots of the wol case and exits. */
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const { mockGateway, html } = require('./test_first_boot_ui.cjs');

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const port = +opt('--port', 8767);
const shots = opt('--shots', '');

const PREVIEW = `
<style>
  #pv-bar { position: fixed; left: 0; right: 0; bottom: 0; z-index: 2000; display: flex; flex-wrap: wrap; gap: 6px 12px; align-items: center;
    padding: 6px 12px; font: 12px/1.4 system-ui, sans-serif; background: #111827; color: #e5e7eb; border-top: 1px solid #374151; }
  #pv-bar a { color: #6ee7b7; } #pv-bar a[aria-current] { color: #fff; font-weight: 600; text-decoration: none; }
  #firstBoot { padding-bottom: 5.5rem; }
  #pv-cover { position: fixed; inset: 0; z-index: 1500; display: grid; place-items: center; background: var(--bg-page); color: var(--fg-muted); font: 14px system-ui, sans-serif; }
</style>
<div id="pv-cover" data-no-i18n>Opening the choice of functions with synthetic data…</div>
<div id="pv-bar" data-no-i18n><b>Preview, synthetic data</b>
  <a href="?case=wol">Only Wake-on-LAN, no Tailscale</a><a href="?case=skip">Without Tailscale</a>
  <a href="?case=tailnet">With a Tailscale key</a><a href="?case=ethernet">Ethernet, no Tailscale</a><a href="?case=manual">Whole wizard</a></div>
<script>
(function () {
  var c = new URLSearchParams(location.search).get('case') || 'wol';
  document.querySelectorAll('#pv-bar a').forEach(function (a) { if (a.getAttribute('href') === '?case=' + c) a.setAttribute('aria-current', 'page'); });
  function $(id) { return document.getElementById(id); }
  function shown(id) { var e = $(id); return !!e && e.offsetParent !== null; }
  function until(f) { return new Promise(function (ok) { (function t() { if (f()) ok(); else setTimeout(t, 60); })(); }); }
  function set(id, v) { var e = $(id); e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); }
  if (c === 'manual') { $('pv-cover').remove(); return; }
  (async function () {
    await until(function () { return shown('fb-pw'); });
    set('fb-pw', 'Preview-Admin-Passphrase-1'); set('fb-pw2', 'Preview-Admin-Passphrase-1'); $('fb-next').click();
    await until(function () { return shown('fb-test') || shown('fb-eth-box'); });
    if (c === 'ethernet') document.querySelector('input[name="fb-up"][value="ethernet"]').click();
    else { set('fb-ssid', 'HomeNetwork'); set('fb-wpw', 'synthetic-wifi-pass'); $('fb-test').click(); await until(function () { return $('fb-tested-ip').value; }); }
    await until(function () { return !$('fb-next').disabled; }); $('fb-next').click();
    await until(function () { return shown('fb-wol-only'); });
    if (c === 'wol') $('fb-wol-only').click();
    else if (c === 'tailnet') { set('fb-key', 'synthetic-preview-auth-key-0123'); $('fb-next').click(); }
    else $('fb-skip-tailnet').click();
    await until(function () { return shown('fb-roles-title'); });
    $('pv-cover').remove();
  })();
})();
</script>
`;
const page = html.replace('</body>', () => PREVIEW + '</body>');

let g = mockGateway();
/* The mock answers Playwright routes; this adapts a plain HTTP request. */
function route(req, body, res) {
  return {
    request: () => ({ url: () => 'http://esp32.test' + req.url, postData: () => body || null, headers: () => req.headers }),
    fulfill: ({ status = 200, contentType = 'text/plain', body: out = '' }) => {
      res.writeHead(status, { 'Content-Type': contentType, 'Cache-Control': 'no-store' }); res.end(out);
    },
  };
}
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', async () => {
    const url = new URL(req.url, 'http://esp32.test');
    if (url.pathname === '/') {
      g = mockGateway();                         /* every page load starts a fresh setup */
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(page); return;
    }
    try {
      await g.handle(route(req, Buffer.concat(chunks).toString('utf8'), res));
      if (url.pathname === '/api/setup/begin') setTimeout(g.press, 400);   /* the BOOT button, pressed for you */
    } catch (e) { res.writeHead(500); res.end(String(e && e.message)); }
  });
});

server.listen(port, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${port}/`;
  if (!shots) { console.log(`First-boot preview (synthetic data): ${base}?case=wol`); return; }
  const { chromium } = require('playwright');
  fs.mkdirSync(shots, { recursive: true });
  const browser = await chromium.launch({ channel: process.env.TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    /* The view on arrival, then the summary with both sections opened. */
    for (const [w, h, name] of [[1440, 900, 'desktop'], [390, 844, 'mobile'], [320, 640, 'mobile-320']]) {
      const ctx = await browser.newContext({ viewport: { width: w, height: h }, isMobile: w < 768, hasTouch: w < 768, locale: 'en-US', colorScheme: 'dark' });
      const p = await ctx.newPage();
      await p.goto(base + '?case=wol');
      await p.waitForSelector('#pv-cover', { state: 'detached' });
      await p.waitForTimeout(300);
      await p.screenshot({ path: path.join(shots, `first-boot-choices-wol-${name}.png`) });
      await p.evaluate(() => {
        document.querySelectorAll('#fb-net, #fb-extras').forEach(d => { d.open = true; });
        document.getElementById('fb-picked').scrollIntoView({ block: 'start' });
      });
      await p.waitForTimeout(150);
      await p.screenshot({ path: path.join(shots, `first-boot-choices-wol-${name}-summary.png`) });
      await ctx.close();
    }
  } finally { await browser.close(); server.close(); }
  console.log('Screenshots in ' + shots);
});
