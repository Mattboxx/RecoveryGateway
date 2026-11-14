/* Network → Gateway Wi-Fi in the real Web UI (ui_fixture.cjs data, Chromium):
 * the open network chosen at first boot can be set and undone here too.
 * - an open AP shows the warning and the switch on, with no password field;
 * - closing it needs a password, then sends open:false with that password;
 * - opening a protected AP sends open:true and no password;
 * - other AP edits never send "open", so they never change the security mode.
 * Synthetic data only; no device.
 * Run: NODE_PATH=<playwright> node tools/test_network_ap_ui.cjs */
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { install, data } = require('./ui_fixture.cjs');

function network(ap) {
  const n = JSON.parse(JSON.stringify(data['/api/network']));
  Object.assign(n.ap, { ssid: 'ESP32-Tailnet-1A2B' }, ap);
  return n;
}

async function open(browser, ap) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'en-US' });
  await context.addInitScript(() => { try { localStorage.setItem('ui-advanced', '1'); } catch (e) {} });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const posts = await install(page, { '/api/network': network(ap) });
  await page.goto('http://esp32.test/#network');
  await page.click('.subnav[data-page="network"] [data-sub="wifi"]');
  await page.waitForFunction(() => document.getElementById('net-ap-ssid').value === 'ESP32-Tailnet-1A2B');
  const sent = () => posts.filter(p => p.path === '/api/network').map(p => JSON.parse(p.body).ap);
  return { context, page, errors, sent };
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.TEST_BROWSER_CHANNEL || 'chrome' });
  try {
    /* Open since setup: visible state, closing needs a password. */
    {
      const f = await open(browser, { open: true });
      assert.equal(await f.page.isVisible('#net-ap-open'), true, 'open network warning');
      assert.equal(await f.page.isChecked('#net-ap-open-sw'), true);
      assert.equal(await f.page.isDisabled('#net-ap-pw'), true, 'no password while open');
      await f.page.uncheck('#net-ap-open-sw', { force: true });
      assert.equal(await f.page.isDisabled('#net-ap-pw'), false);
      assert.equal(await f.page.getAttribute('#net-ap-pw', 'placeholder'), 'Required');
      await f.page.click('#net-ap-save');
      await f.page.waitForTimeout(200);
      assert.deepEqual(f.sent(), [], 'not sent without a password');
      await f.page.fill('#net-ap-pw', 'new-iot-password');
      await f.page.click('#net-ap-save');
      await f.page.waitForFunction(() => true);
      await f.page.waitForTimeout(300);
      const ap = f.sent().pop();
      assert.equal(ap.open, false); assert.equal(ap.password, 'new-iot-password');
      assert.deepEqual(f.errors, []);
      await f.context.close();
    }
    /* Protected: open it on purpose; other edits leave the mode alone. */
    {
      const f = await open(browser, { open: false });
      assert.equal(await f.page.isVisible('#net-ap-open'), false);
      assert.equal(await f.page.isChecked('#net-ap-open-sw'), false);
      await f.page.fill('#net-ap-ssid', 'Gateway-IoT');
      await f.page.click('#net-ap-save');
      await f.page.waitForTimeout(300);
      let ap = f.sent().pop();
      assert.equal(ap.ssid, 'Gateway-IoT'); assert.equal('open' in ap, false, 'other AP edits do not send the security mode');
      await f.page.fill('#net-ap-pw', 'typed-before-open');
      await f.page.check('#net-ap-open-sw', { force: true });
      assert.equal(await f.page.inputValue('#net-ap-pw'), '', 'a typed password is dropped when opening');
      await f.page.click('#net-ap-save');
      await f.page.waitForTimeout(300);
      ap = f.sent().pop();
      assert.equal(ap.open, true); assert.equal('password' in ap, false, 'an open network sends no password');
      assert.deepEqual(f.errors, []);
      await f.context.close();
    }
  } finally { await browser.close(); }
  console.log('PASS: Network page opens and closes the gateway Wi-Fi like first boot: warning and switch, password required to close, mode sent only when changed (synthetic, Chromium)');
})().catch(e => { console.error(e); process.exit(1); });
