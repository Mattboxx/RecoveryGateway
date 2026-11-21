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
  return { context, page, errors, sent, posts };
}

async function restore(browser, response, restartOk = true) {
  const f = await open(browser, { open: true });
  const sent = [];
  for (const path of ['/api/network', '/api/system/secrets', '/api/system/restart']) {
    await f.page.route('http://esp32.test' + path, route => {
      if (route.request().method() !== 'POST') return route.fallback();
      sent.push({ path, body: route.request().postDataJSON() });
      if (path === '/api/system/restart' && !restartOk) {
        return route.fulfill({ status: 503, json: { ok: false } });
      }
      return route.fulfill({ json: path === '/api/network' ? response : { ok: true } });
    });
  }
  const result = !response.ok ? 'Restore failed' : restartOk ? 'Restored — rebooting' : 'Settings restored';
  const finished = f.page.getByText(result, { exact: true }).waitFor();
  await f.page.evaluate(async () => {
    const passphrase = 'synthetic-backup-passphrase';
    const secrets = await encryptSecretsBundle({ ap_password: 'synthetic-gateway-password' }, passphrase);
    _runConfigRestore({ network: { ap: { ssid: 'GatewayExample', open: false } }, secrets_encrypted: secrets }, true, passphrase);
  });
  await finished;
  await f.page.waitForFunction(() => !document.getElementById('sys-config-restore').disabled);

  assert.deepEqual(sent, [
    { path: '/api/network', body: { ap: { ssid: 'GatewayExample' } } },
    ...(response.ok ? [
      { path: '/api/system/secrets', body: { ap_password: 'synthetic-gateway-password' } },
      { path: '/api/system/restart', body: {} }
    ] : []),
  ]);
  if (response.ok && !restartOk) {
    assert.equal(await f.page.locator('#pendingRebootBanner').evaluate(e => e.classList.contains('visible')), true);
  }
  assert.deepEqual(f.errors, []);
  await f.context.close();
}

async function backup(browser, status, body, succeeds) {
  const f = await open(browser, { open: true });
  await f.page.route('http://esp32.test/api/dhcp/reservations', route =>
    route.fulfill({ status, json: body }));
  let downloads = 0;
  let secretsRequests = 0;
  f.page.on('request', r => { if (new URL(r.url()).pathname === '/api/system/secrets') secretsRequests++; });
  f.page.on('download', () => downloads++);
  const done = succeeds ? f.page.waitForEvent('download')
    : f.page.getByText('Backup failed', { exact: true }).waitFor();
  await f.page.evaluate(() => _runConfigBackup(false, ''));
  const result = await done;
  await f.page.waitForFunction(() => !document.getElementById('sys-config-backup').disabled);
  assert.equal(downloads, Number(succeeds));
  if (succeeds) {
    const stream = await result.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const portable = JSON.parse(Buffer.concat(chunks).toString());
    assert.deepEqual(portable.dhcp_reservations, []);
    assert.equal(portable.format,'tsr-backup-v1');
    for (const key of ['cellular','data_limit','saved_tcp','telegram','email','secrets_encrypted']) assert(!(key in portable));
    await f.page.evaluate(() => document.getElementById('sys-config-backup').click());
    assert.equal(await f.page.locator('#backup-include-secrets').isChecked(),false);
  }
  assert.equal(secretsRequests,0);
  assert.deepEqual(f.errors, []);
  await f.context.close();
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
    await restore(browser, { ok: true });
    await restore(browser, { ok: false });
    await restore(browser, { ok: true }, false);
    await backup(browser, 503, { reservations: [] }, false);
    await backup(browser, 200, { error: 'unavailable' }, false);
    await backup(browser, 200, {}, false);
    await backup(browser, 200, { reservations: [] }, true);
    {
      const f = await open(browser, { open: false });
      await f.page.click('.subnav[data-page="network"] [data-sub="internet"]');
      const savedNetwork = f.posts.filter(p => p.path === '/api/network');
      assert.equal(savedNetwork.length, 0);
      await f.page.locator('.net-del').click();
      await f.page.click('#net-sta-save');
      await f.page.getByText('Remove the Wi-Fi uplink?', { exact: true }).waitFor();
      await f.page.click('#modal-cancel');
      assert.equal(f.posts.filter(p => p.path === '/api/network').length, 0);
      await f.page.click('#net-sta-save');
      const posted = f.page.waitForRequest(r => r.method() === 'POST' && new URL(r.url()).pathname === '/api/network');
      await f.page.click('#modal-confirm');
      assert.deepEqual((await posted).postDataJSON(), { networks: [] });
      assert.deepEqual(f.errors, []);
      await f.context.close();
    }
  } finally { await browser.close(); }
  console.log('PASS: Network page opens and closes the gateway Wi-Fi like first boot: warning and switch, password required to close, mode sent only when changed (synthetic, Chromium)');
})().catch(e => { console.error(e); process.exit(1); });
