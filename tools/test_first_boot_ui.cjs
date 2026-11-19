/* First-boot setup wizard in the real embedded Web UI against a mock gateway
 * that implements the setup API with Node's own X25519/AES-256-GCM: full
 * flow (BOOT-button pairing, password, scan, Wi-Fi test, tailnet, features,
 * finish), Ethernet-only and SIM-only setups, setup-code pairing with a wrong
 * code, "another device is pairing", no secret in any request body, the
 * browser's language and time zone, and layout at phone/tablet/desktop widths
 * in every shipped language (no page overflow, clipped controls, tiny targets
 * or script errors). Synthetic data only; no device.
 * Run: NODE_PATH=<playwright> node tools/test_first_boot_ui.cjs [shots] */
const { chromium } = require('playwright');
const crypto = require('node:crypto');
const path = require('node:path');
const assert = require('node:assert/strict');
const { builtHtml, serveAsset } = require('./ui_build.cjs');

const html = builtHtml();
const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI = Buffer.from('302a300506032b656e032100', 'hex');
const LABEL = Buffer.from('mattboxx-tailnet-gateway-setup-v1');
const SECRETS = { admin: 'Blue-Lantern-42-river', wifi: 'home-wifi-passphrase-9', key: 'synthetic-headscale-preauth-0123456789' };
const shots = process.argv[2];
/* Every shipped language (main/i18n/languages.json) plus English. */
const LOCALES = ['en-US'].concat(Object.keys(require('../main/i18n/languages.json')).map(c => ({ it: 'it-IT', es: 'es-ES', zh: 'zh-CN', fr: 'fr-FR', de: 'de-DE' })[c] || c));

function mockGateway(opts = {}) {
  const g = { sid: '', key: null, state: 'none', seq: 0, wifi: 'idle', polls: 0, bodies: [], finish: null, busy: !!opts.busy, codeFails: 0 };
  g.press = () => { if (g.state === 'pending') g.state = 'claimed'; };
  g.handle = async (route) => {
    const req = route.request(), url = new URL(req.url()), body = req.postData() || '';
    if (body) g.bodies.push(body);
    const send = (status, obj) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(obj) });
    const sidHeader = req.headers()['x-setup-session'] || '';
    if (url.pathname.startsWith('/i18n/') && await serveAsset(route, url.pathname)) return;
    switch (url.pathname) {
      case '/': return route.fulfill({ contentType: 'text/html', body: html });
      case '/api/auth/status': return send(200, { setup_mode: true, password_set: false, auth_enabled: true, auth_required: false, authenticated: false, device_name: 'RecoveryGateway' });
      case '/api/setup/state': {
        const mine = sidHeader && sidHeader === g.sid;
        const out = { setup: true, setup_ssid: 'RecoveryGateway-Setup-1A2B', default_ap_ssid: 'ESP32-Tailnet-1A2B', version: 'synthetic', lan_name: 'esp32-tailnet-1a2b',
          session: mine ? g.state : 'none', other_pairing: false, code_locked: false, finished: !!g.finish, uplinks: ['wifi', 'ethernet', 'cellular'] };
        if (mine && g.state === 'claimed') {
          if (g.wifi === 'testing' && ++g.polls >= 2) g.wifi = 'ok';
          out.wifi = { state: g.wifi };
          if (g.wifi === 'ok') Object.assign(out.wifi, { ip: '192.168.1.77', prefix: 24 });
        }
        return send(200, out);
      }
      case '/api/setup/begin': {
        if (g.busy) return send(409, { error: 'busy', detail: 'another device is pairing' });
        const { client_pub } = JSON.parse(body);
        assert.match(client_pub, /^[0-9a-f]{64}$/);
        const devPriv = crypto.randomBytes(32);
        const devKey = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, devPriv]), format: 'der', type: 'pkcs8' });
        const devPub = crypto.createPublicKey(devKey).export({ format: 'der', type: 'spki' }).subarray(12);
        const cpub = Buffer.from(client_pub, 'hex');
        const shared = crypto.diffieHellman({ privateKey: devKey, publicKey: crypto.createPublicKey({ key: Buffer.concat([SPKI, cpub]), format: 'der', type: 'spki' }) });
        g.key = crypto.createHash('sha256').update(Buffer.concat([LABEL, shared, devPub, cpub])).digest();
        g.sid = crypto.randomBytes(16).toString('hex'); g.state = 'pending'; g.seq = 0;
        return send(200, { sid: g.sid, device_pub: devPub.toString('hex'), expires_s: 120, button: true });
      }
      case '/api/setup/claim': {
        const { sid, code } = JSON.parse(body);
        if (sid !== g.sid) return send(404, { error: 'session' });
        if (code !== '12345678') { g.codeFails++; return send(403, { error: 'bad_code', detail: String(5 - g.codeFails) }); }
        g.state = 'claimed'; return send(200, { claimed: true });
      }
      case '/api/setup/apply': {
        const m = JSON.parse(body);
        if (m.sid !== g.sid) return send(404, { error: 'session' });
        if (g.state !== 'claimed') return send(403, { error: 'not_paired' });
        if (!(m.seq > g.seq)) return send(409, { error: 'replay' });
        const aad = Buffer.concat([Buffer.from(m.sid, 'hex'), Buffer.from([m.seq >>> 24 & 255, m.seq >>> 16 & 255, m.seq >>> 8 & 255, m.seq & 255])]);
        const d = crypto.createDecipheriv('aes-256-gcm', g.key, Buffer.from(m.iv, 'hex'));
        d.setAAD(aad); d.setAuthTag(Buffer.from(m.tag, 'hex'));
        let cmd;
        try { cmd = JSON.parse(Buffer.concat([d.update(Buffer.from(m.ct, 'hex')), d.final()]).toString('utf8')); }
        catch (e) { return send(403, { error: 'seal' }); }
        g.seq = m.seq;
        if (cmd.action === 'wifi_test') { g.wifi = 'testing'; g.polls = 0; g.tested = cmd.wifi; return send(200, { wifi: 'testing' }); }
        if (cmd.action === 'finish') { g.finish = cmd; return send(200, { ok: true, restart_in_s: 3, tailnet: !!cmd.tailnet.auth_key, lan_name: cmd.lan_name || 'esp32-tailnet-1a2b', uplink: cmd.uplink.type }); }
        return send(400, { error: 'action' });
      }
      case '/api/network/scan': return send(200, { status: 'scanning' });
      case '/api/network/scan/result': return send(200, { status: 'ready', age_ms: 10, networks: [
        { ssid: 'HomeNetwork', rssi: -48, channel: 6, auth: 'WPA2_PSK' }, { ssid: 'HomeNetwork', rssi: -71, channel: 11, auth: 'WPA2_PSK' },
        { ssid: 'Neighbour-Guest-Network-With-A-Very-Long-Name', rssi: -83, channel: 1, auth: 'OPEN' }, { ssid: '', rssi: -60, channel: 3, auth: 'WPA2_PSK' }] });
      default: return send(403, { error: 'setup' });   /* everything else is closed during setup */
    }
  };
  return g;
}

async function layout(page, touch) {
  return page.evaluate((touch) => {
    const vw = window.innerWidth, out = { overflow: document.documentElement.scrollWidth - vw, behind: document.documentElement.scrollHeight - window.innerHeight, clipped: [], small: [], tiny: [] };
    const card = document.querySelector('#firstBoot');
    card.querySelectorAll('button, input, select, summary').forEach(el => {
      const b = el.getBoundingClientRect(), s = getComputedStyle(el);
      if (!b.width || !b.height || s.visibility === 'hidden' || el.closest('[hidden]')) return;
      const name = (el.id || el.textContent || el.tagName).trim().slice(0, 24);
      if (b.right > vw + 1 || b.left < -1) out.clipped.push(name);
      if (touch && b.height < 36 && el.type !== 'checkbox' && el.type !== 'radio') out.small.push(name + ':' + Math.round(b.height));
    });
    card.querySelectorAll('p, li, label, .form-hint, button, small, dt, dd').forEach(el => {
      const b = el.getBoundingClientRect();
      if (!b.width || el.closest('[hidden]') || !el.textContent.trim()) return;
      const f = parseFloat(getComputedStyle(el).fontSize); if (f < 11 && !el.closest('.fb-steps')) out.tiny.push(el.textContent.trim().slice(0, 18) + ':' + f);
    });
    return out;
  }, touch);
}

/* Pairs a fresh page and sets the admin password: the wizard is on step 2. */
async function paired(context) {
  const page = await context.newPage(); const g = mockGateway(); await page.route('http://esp32.test/**', g.handle);
  await page.goto('http://esp32.test/'); await page.waitForFunction(() => document.getElementById('fb-pair-status').textContent.includes('BOOT'));
  g.press(); await page.waitForSelector('#fb-pw', { state: 'visible' });
  await page.fill('#fb-pw', SECRETS.admin); await page.fill('#fb-pw2', SECRETS.admin); await page.click('#fb-next');
  await page.waitForSelector('input[name="fb-up"][value="ethernet"]', { state: 'visible' });
  return { page, g };
}

/* Ethernet without Wi-Fi, and a SIM as the only uplink: the right fields,
 * safe defaults and what is sent. */
async function uplinkFlows(context) {
  let { page, g } = await paired(context);
  await page.check('input[name="fb-up"][value="ethernet"]');
  assert.equal(await page.isVisible('#fb-ssid'), false, 'Ethernet: Wi-Fi fields hidden');
  assert.equal(await page.isVisible('#fb-wifi-backup-row'), true);
  await page.click('#fb-eth-box summary');
  await page.fill('#fb-eth-cs', '11');
  assert.equal(await page.isEnabled('#fb-next'), false, 'a pin used twice is refused');
  await page.fill('#fb-eth-cs', '10');
  assert.equal(await page.isVisible('#fb-lan'), true, '.local name on Ethernet too');
  await page.fill('#fb-lan', 'nas-gateway');
  await page.click('#fb-next');                          /* no Wi-Fi test question without Wi-Fi */
  await page.waitForSelector('#fb-ts-later', { state: 'visible' });
  await page.check('#fb-ts-later');
  await page.click('#fb-next');                          /* tailnet later is fine on Ethernet */
  await page.waitForSelector('#fb-apname', { state: 'visible' });
  await page.click('#fb-appw-gen');
  assert.equal(await page.isVisible('#fb-share-lan-row'), false, 'home-network route needs a Wi-Fi test: offered later on Ethernet');
  await page.check('#fb-roles input[value="subnet-router"]');
  assert.equal(await page.isChecked('#fb-share-lan'), false);
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  assert.ok((await page.textContent('#fb-summary')).includes('Ethernet cable'));
  assert.ok((await page.textContent('#fb-summary')).includes('http://nas-gateway.local/'), 'chosen .local name in the summary');
  await page.click('#fb-next'); await page.waitForSelector('#fb-done', { state: 'visible' });
  assert.deepEqual(g.finish.uplink, { type: 'ethernet', ethernet: { sclk: 12, mosi: 11, miso: 13, cs: 10, intr: 14, rst: 9, transport: 'pins' } });
  assert.deepEqual(g.finish.wifi, { ssid: '', password: '' }); assert.equal(g.finish.share_lan, false);
  assert.equal(g.finish.lan_name, 'nas-gateway');
  assert.ok((await page.textContent('#fb-done-open')).includes('http://nas-gateway.local/'));
  await page.close();

  ({ page, g } = await paired(context));
  await page.check('input[name="fb-up"][value="cellular"]');
  assert.equal(await page.isVisible('#fb-apn'), true);
  assert.equal(await page.isVisible('#fb-lan'), false, 'no .local name without a home network');
  await page.fill('#fb-apn', 'internet'); await page.fill('#fb-simpin', '12');
  assert.equal(await page.isEnabled('#fb-next'), false, 'short SIM PIN refused');
  await page.fill('#fb-simpin', '1234');
  assert.equal(await page.isEnabled('#fb-next'), false, 'mobile data needs consent');
  await page.check('#fb-data-ack');
  await page.click('#fb-next'); await page.waitForSelector('#fb-ts-later', { state: 'visible' });
  await page.check('#fb-ts-later');
  assert.equal(await page.isEnabled('#fb-next'), true, 'SIM only: local administration works through the AP');
  await page.click('#fb-next'); await page.waitForSelector('#fb-apname', { state: 'visible' });
  await page.click('#fb-appw-gen');
  await page.locator('details:has(#fb-exit-row) > summary').click();
  assert.equal(await page.isVisible('#fb-exit-row'), true, 'exit node is an explicit opt-in on mobile data');
  assert.equal(await page.isChecked('#fb-exit'), false);
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  const sum = await page.textContent('#fb-summary');
  assert.ok(sum.includes('.local/') && !sum.includes('1234'), 'local address shown; PIN never shown');
  await page.click('#fb-next'); await page.waitForSelector('#fb-done', { state: 'visible' });
  assert.deepEqual(g.finish.uplink, { type: 'cellular', cellular: { tx: 17, rx: 18, pwrkey: -1, transport: 'pins', apn: 'internet', pin: '1234', roaming: false, data_ack: true } });
  assert.equal(g.finish.exit_node, false); assert.equal(g.finish.lan_name, '');
  assert.ok((await page.textContent('#fb-done-open')).includes('.local/'));
  assert.match(await page.textContent('#fb-done-reconnect'), /access point/i);
  for (const b of g.bodies) assert.ok(!b.includes('"1234"') && !b.includes(SECRETS.key), 'SIM PIN and key only sealed');
  await page.close();

  /* Ethernet through the USB port: no wiring, a clear summary, transport sent. */
  ({ page, g } = await paired(context));
  await page.check('input[name="fb-up"][value="ethernet"]');
  assert.equal(await page.isChecked('input[name="fb-eth-conn"][value="spi"]'), true, 'pins stay the default');
  assert.equal(await page.isVisible('#fb-eth-usb-power'), false, 'pins: no USB power warning');
  await page.check('input[name="fb-eth-conn"][value="usb"]');
  assert.equal(await page.isVisible('#fb-eth-wiring'), false, 'USB: no wiring to fill in');
  assert.equal(await page.isVisible('#fb-eth-usb-power'), true, 'USB: power warning shown');
  const ethPower = await page.textContent('#fb-eth-usb-power');
  assert.match(ethPower, /does not supply 5 V/); assert.match(ethPower, /16 receive buffers instead of 24/); assert.doesNotMatch(ethPower, /2 A in bursts/);
  const guide = '#fb-eth-usb-power a.usb-guide-link';
  assert.equal(await page.getAttribute(guide, 'href'), 'https://mattboxx.github.io/esp32-tailnet-gateway/usb-devices/', 'a non-pre-release keeps the website guide');
  await page.evaluate(() => window.setUsbGuideLinks('3.0.25-beta.8'));
  assert.equal(await page.getAttribute(guide, 'href'), 'https://github.com/Mattboxx/esp32-tailnet-gateway/blob/v3.0.25-beta.8/docs/USB-DEVICES.md', 'a pre-release links to the guide of its own tag');
  await page.evaluate(() => { window.setUsbGuideLinks('3.0.26'); window.setUsbGuideLinks('1.0.0-beta"><x'); window.setUsbGuideLinks(undefined); });
  assert.match(await page.getAttribute(guide, 'href'), /blob\/v3\.0\.25-beta\.8\//, 'stable or malformed versions change nothing');
  await page.evaluate(() => { const c = document.getElementById('fb-eth-cs'); c.value = '11'; c.dispatchEvent(new Event('input')); });   /* hidden pins: not checked or sent */
  assert.equal(await page.isEnabled('#fb-next'), true);
  await page.click('#fb-next'); await page.waitForSelector('#fb-ts-later', { state: 'visible' });
  await page.check('#fb-ts-later'); await page.click('#fb-next');
  await page.waitForSelector('#fb-apname', { state: 'visible' }); await page.click('#fb-appw-gen');
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  assert.match(await page.textContent('#fb-summary'), /Ethernet connectionUSB port/);
  await page.click('#fb-next'); await page.waitForSelector('#fb-done', { state: 'visible' });
  assert.deepEqual(g.finish.uplink, { type: 'ethernet', ethernet: { transport: 'usb' } });
  await page.close();

  /* A USB modem or stick: the APN may stay empty; switching back restores the rules. */
  ({ page, g } = await paired(context));
  await page.check('input[name="fb-up"][value="cellular"]');
  await page.check('input[name="fb-cell-conn"][value="usb"]');
  assert.equal(await page.isVisible('#fb-cell-wiring'), false);
  assert.equal(await page.isVisible('#fb-apn-usb-hint'), true); assert.equal(await page.isVisible('#fb-apn-hint'), false);
  assert.equal(await page.isVisible('#fb-cell-usb-power'), true, 'USB modem: power warning shown');
  assert.match(await page.textContent('#fb-cell-usb-power'), /up to 2 A in bursts/);
  await page.check('#fb-data-ack');
  assert.equal(await page.isEnabled('#fb-next'), true, 'over USB the APN is optional');
  await page.check('input[name="fb-cell-conn"][value="uart"]');
  assert.equal(await page.isEnabled('#fb-next'), false, 'wired modem: the APN is required again');
  assert.equal(await page.isVisible('#fb-cell-wiring'), true);
  assert.equal(await page.isVisible('#fb-cell-usb-power'), false, 'wired modem: no USB power warning');
  await page.check('input[name="fb-cell-conn"][value="usb"]');
  await page.fill('#fb-apn', 'bad apn!');
  assert.equal(await page.isEnabled('#fb-next'), false, 'a given APN is still checked');
  await page.fill('#fb-apn', '');
  await page.click('#fb-next'); await page.waitForSelector('#fb-ts-later', { state: 'visible' });
  await page.check('#fb-ts-later'); await page.click('#fb-next');
  await page.waitForSelector('#fb-apname', { state: 'visible' }); await page.click('#fb-appw-gen');
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  const usbSum = await page.textContent('#fb-summary');
  assert.match(usbSum, /Modem connectionUSB port/); assert.match(usbSum, /APNfrom the modem/);
  await page.click('#fb-next'); await page.waitForSelector('#fb-done', { state: 'visible' });
  assert.deepEqual(g.finish.uplink, { type: 'cellular', cellular: { transport: 'usb', apn: '', pin: '', roaming: false, data_ack: true } });
  await page.close();
}

/* Step 4 opens on the title of the choices, at the top of the view on every width. */
async function choicesStart(page) {
  await page.waitForFunction(() => document.activeElement && document.activeElement.id === 'fb-roles-title');
  const r = await page.evaluate(() => { const o = document.getElementById('firstBoot'); return { top: document.getElementById('fb-roles-title').getBoundingClientRect().top, end: o.scrollTop + o.clientHeight >= o.scrollHeight - 1 }; });
  assert.ok(r.top >= 0 && (r.top < 40 || r.end), 'step 4 starts from the title of the choices, not from a field below: ' + r.top);
}

/* Step 4 without Tailscale: presets undone by unticking (but not what another
 * choice or the user still wants), no section opened and no page jump on a
 * click, the live and final summaries, and the default restored when a key
 * is entered after all. Sent roles keep the firmware's order. */
async function choicesFlow(context) {
  const { page, g } = await paired(context);
  await page.check('input[name="fb-up"][value="ethernet"]');
  await page.click('#fb-next'); await page.waitForSelector('#fb-ts-later', { state: 'visible' });
  await page.check('#fb-ts-later'); await page.click('#fb-next');
  await choicesStart(page);
  await page.click('#fb-appw-gen');
  const tick = v => page.evaluate(v => { const o = document.getElementById('firstBoot'), y = o.scrollTop; document.querySelector(v.startsWith('#') ? v : `#fb-roles input[value="${v}"]`).click(); return o.scrollTop - y; }, v);
  const on = () => page.evaluate(() => [...document.querySelectorAll('#fb-net input, #fb-extras input, #fb-ap-always')].filter(i => i.checked).map(i => i.id));
  const shown = id => page.isVisible(id);
  const sum = async () => (await page.innerText('#fb-picked')).replace(/\s+/g, ' ');
  assert.match(await sum(), /Nothing selected/);
  assert.ok(await page.isVisible('#fb-ts-off') && !(await page.isVisible('#fb-ts-on')), 'says that Tailscale was skipped');
  assert.deepEqual(await on(), [], 'without Tailscale every network option and extra starts off');
  assert.ok(await shown('#fb-ap-off-t') && !(await shown('#fb-ap-on-t')), 'recovery-only: the box is the emergency Wi-Fi');
  for (const v of ['monitoring', 'wol', 'iot-ap']) assert.equal(await tick(v), 0, 'a choice does not move the page');
  assert.equal(await page.evaluate(() => document.getElementById('fb-net').open || document.getElementById('fb-extras').open), false, 'a choice opens no section');
  assert.deepEqual(await on(), ['fb-share-ap', 'fb-ap-always', 'fb-x-history', 'fb-x-trends', 'fb-x-snapshots', 'fb-x-names']);
  assert.ok(await shown('#fb-ap-on-t') && !(await shown('#fb-ap-off-t')), 'always on: the box is the IoT access point, not an emergency Wi-Fi');
  assert.equal((await page.textContent('#fb-ap-on-t')).trim(), 'Access point for IoT devices');
  assert.equal(await page.textContent('#fb-net-n'), '✓ 2'); assert.equal(await page.textContent('#fb-extras-n'), '✓ 4', 'closed sections count what is on');
  let s = await sum();
  assert.match(s, /Wake a NAS or PC No Tailscale needed Turned on now Keep an event history After the restart Save the device/);
  assert.match(s, /Wi-Fi for IoT devices Tailscale optional Turned on now Share the gateway's own Wi-Fi network \(waits for Tailscale\), Keep the gateway's own Wi-Fi always on, Tailnet names for devices on the gateway's Wi-Fi \(waits for Tailscale\)/);
  assert.ok(await page.isVisible('#fb-ap-on'), 'IoT: the emergency Wi-Fi is always on');
  await tick('monitoring');
  assert.deepEqual(await on(), ['fb-share-ap', 'fb-ap-always', 'fb-x-history', 'fb-x-names'], 'unticking keeps what another choice still wants');
  await tick('#fb-x-history'); await tick('wol');
  assert.deepEqual(await on(), ['fb-share-ap', 'fb-ap-always', 'fb-x-names'], 'an option changed by hand stays as the user left it');
  await tick('iot-ap');
  assert.deepEqual(await on(), [], 'unticking every choice undoes its presets');
  assert.equal(await page.textContent('#fb-net-n'), '', 'no count when nothing is on');
  assert.ok(await page.isVisible('#fb-ap-off'));
  await tick('subnet-router'); await tick('wol');
  s = await sum();
  assert.match(s, /Reach this network from your Tailnet Waits for Tailscale .*On Ethernet or SIM/);
  assert.deepEqual(await on(), ['fb-x-history'], 'no home-network route at setup on Ethernet');
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  assert.match(await page.textContent('#fb-summary'), /Waits for TailscaleReach this network from your Tailnet/);
  await page.click('#fb-back'); await tick('subnet-router');
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  assert.doesNotMatch(await page.textContent('#fb-summary'), /Waits for Tailscale/, 'Wake-on-LAN alone waits for nothing');
  await page.click('#fb-back'); await page.click('#fb-back');
  await page.check('#fb-ts-now'); await page.fill('#fb-key', SECRETS.key); await page.click('#fb-next'); await choicesStart(page);
  assert.equal(await page.isChecked('#fb-share-ap'), true, 'a key entered after skipping restores the default');
  assert.ok(await page.isVisible('#fb-ts-on'));
  await tick('lan-tailnet');
  assert.match(await sum(), /Let a LAN device use one Tailnet service Needs Tailscale .*Also turned on Share the gateway's own Wi-Fi network$/);
  /* A language chosen on this step redraws the summary, names included. */
  await page.selectOption('#fb-lang', 'it');
  await page.waitForFunction(() => /Le tue scelte[\s\S]*Accendi un NAS o un PC[\s\S]*Dopo il riavvio/.test(document.getElementById('fb-picked').innerText));
  await page.selectOption('#fb-lang', 'en');
  await page.waitForFunction(() => /Your choices[\s\S]*Wake a NAS or PC[\s\S]*After the restart/.test(document.getElementById('fb-picked').innerText));
  /* An open gateway Wi-Fi only on explicit request, then without a password. */
  assert.equal(await page.isChecked('#fb-ap-open'), false);
  await page.check('#fb-ap-open');
  assert.equal(await page.isVisible('#fb-appw'), false, 'no password field for an open network');
  await page.fill('#fb-apname', 'IoT-Open');
  await page.click('#fb-next'); await page.waitForSelector('#fb-summary dt');
  assert.match(await page.textContent('#fb-summary'), /IoT-Open · when the local LAN is unavailable · open, no password/);
  await page.click('#fb-next'); await page.waitForSelector('#fb-done', { state: 'visible' });
  assert.equal(g.finish.ap_open, true); assert.equal(g.finish.ap_password, '', 'a password typed before is not sent for an open network');
  assert.deepEqual(g.finish.roles, ['lan-tailnet', 'wol'], 'roles in the order the firmware always received');
  assert.deepEqual(g.finish.extras, { history: true, trends: false, snapshots: false, tailnet_names: false });
  assert.equal(g.finish.share_ap, true); assert.equal(g.finish.ap_recovery_only, true);
  await page.close();
}

/* Tailscale is an explicit choice: none at first, a key only with "Yes",
 * and "Not now" discards a key typed before. Wake-on-LAN alone works locally. */
async function standaloneRecoveryFlow(context) {
  const { page, g } = await paired(context);
  await page.check('input[name="fb-up"][value="ethernet"]');
  await page.click('#fb-next');
  await page.waitForSelector('#fb-ts-later', { state: 'visible' });
  assert.equal(await page.isEnabled('#fb-next'), false, 'Tailscale now or later must be chosen');
  assert.equal(await page.isVisible('#fb-key'), false, 'no key field before choosing to connect');
  await page.check('#fb-ts-now');
  assert.equal(await page.isEnabled('#fb-next'), false, 'connecting now needs a key');
  await page.fill('#fb-key', SECRETS.key);
  assert.equal(await page.isEnabled('#fb-next'), true);
  await page.check('#fb-ts-later');
  assert.equal(await page.isVisible('#fb-key'), false);
  await page.click('#fb-next');
  await choicesStart(page);
  assert.equal(await page.inputValue('#fb-key'), '', 'Not now clears a key typed before');
  await page.fill('#fb-appw', 'emergency-wifi-pass');
  assert.deepEqual(await page.locator('#fb-roles input:checked').evaluateAll(roles => roles.map(role => role.value)), []);
  assert.equal(await page.locator('#fb-roles input').first().getAttribute('value'), 'wol', 'Wake-on-LAN is the first choice');
  await page.check('#fb-roles input[value="wol"]');
  assert.equal(await page.isChecked('#fb-x-history'), true);
  assert.match(await page.textContent('#fb-picked'), /Wake a NAS or PC/);
  assert.ok(!(await page.isChecked('#fb-share-ap')));
  assert.ok(await page.isVisible('#fb-roles input[value="home-assistant"]'));
  await page.click('#fb-next');
  assert.match(await page.textContent('#fb-summary'), /TailnetDisabled/);
  await page.click('#fb-next');
  await page.waitForSelector('#fb-done-wol', { state: 'visible' });
  assert.deepEqual(g.finish.roles, ['wol']);
  assert.equal(g.finish.tailnet.auth_key, '', 'The optional local setup never submits the previous key');
  assert.equal(g.finish.share_ap || g.finish.share_lan || g.finish.exit_node, false);
  assert.doesNotMatch(await page.textContent('#fb-done-open'), /tailnet by its name/);
  await page.close();
}

async function flow(browser, [width, height, locale], failures, full) {
  const touch = width < 768;
  const context = await browser.newContext({ viewport: { width, height }, hasTouch: touch, isMobile: touch, locale, timezoneId: 'Europe/Rome' });
  const page = await context.newPage();
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  if (shots) await context.route('**/*', route => route.abort('blockedbyclient'));
  const g = mockGateway(); await page.route('http://esp32.test/**', g.handle);
  const where = `${width}x${height} ${locale}`;
  const check = async (step) => {
    const r = await layout(page, touch);
    if (r.overflow > 0) failures.push(`${where} step ${step}: page scrolls horizontally by ${r.overflow}px`);
    if (r.behind > 1) failures.push(`${where} step ${step}: the page behind the wizard scrolls by ${r.behind}px`);
    if (r.clipped.length) failures.push(`${where} step ${step}: clipped ${r.clipped.slice(0, 5).join(', ')}`);
    if (r.small.length) failures.push(`${where} step ${step}: touch targets <36px ${r.small.slice(0, 5).join(', ')}`);
    if (r.tiny.length) failures.push(`${where} step ${step}: text <11px ${r.tiny.slice(0, 4).join(', ')}`);
    if (shots) {
      const filename = path.join(shots, `first-boot-${locale}-${width}x${height}-step${step}.png`);
      if (step === 5) await page.locator('#fbForm').screenshot({ path: filename, animations: 'disabled' });
      else await page.screenshot({ path: filename, fullPage: true });
    }
  };
  try {
    await page.goto('http://esp32.test/');
    await page.waitForSelector('#firstBoot', { state: 'visible' });
    await page.waitForFunction(() => document.getElementById('fb-pair-status').textContent.includes('BOOT'));
    assert.equal(await page.isVisible('#authSetup'), false);
    /* The wizard follows the browser language like the dashboard. */
    const want = locale.split('-')[0];
    await page.waitForFunction(w => document.documentElement.lang.split('-')[0] === w && !document.documentElement.classList.contains('i18n-wait'), want);
    const title = (await page.textContent('#fb-title')).trim();
    if (want === 'en') assert.equal(title, 'Welcome to RecoveryGateway');
    else assert.notEqual(title, 'Welcome to RecoveryGateway', 'wizard title translated');
    assert.equal(await page.getAttribute('#firstBoot', 'lang'), null);
    assert.equal(await page.inputValue('#fb-lang'), want, 'language picker shows the language in use');
    assert.equal(await page.isEnabled('#fb-next'), false);
    await check(0);
    g.press();
    await page.waitForSelector('#fb-pw', { state: 'visible' });
    await page.fill('#fb-pw', 'short'); await page.fill('#fb-pw2', 'short');
    assert.equal(await page.isEnabled('#fb-next'), false, 'weak password refused');
    await page.fill('#fb-pw', SECRETS.admin); await page.fill('#fb-pw2', SECRETS.admin + 'x');
    assert.equal(await page.isEnabled('#fb-next'), false, 'mismatch refused');
    await page.fill('#fb-pw2', SECRETS.admin);
    if (locale.startsWith('en')) assert.equal((await page.textContent('#fb-next')).trim(), 'Set password & continue');
    await page.check('#fb-show'); assert.equal(await page.getAttribute('#fb-pw', 'type'), 'text'); await page.uncheck('#fb-show');
    await check(1);
    await page.click('#fb-next');
    await page.waitForSelector('#fb-nets button');
    const names = await page.$$eval('#fb-nets button span', s => s.map(x => x.textContent));
    assert.deepEqual(names.filter(n => n === 'HomeNetwork').length, 1, 'duplicate SSIDs merged');
    assert.ok(!names.includes(''), 'hidden SSIDs omitted');
    await page.click('#fb-nets button:has-text("HomeNetwork")');
    assert.equal(await page.inputValue('#fb-ssid'), 'HomeNetwork');
    await page.fill('#fb-wpw', SECRETS.wifi);
    assert.equal(await page.isEnabled('#fb-next'), false, 'connection test required before Next');
    await page.click('#fb-test');
    await page.waitForFunction(() => document.getElementById('fb-tested-ip').value === '192.168.1.77', null, { timeout: 15000 });
    assert.equal(await page.isVisible('#fb-copy-ip'), true);
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
      document.execCommand = command => {
        if (command !== 'copy') return false;
        const field = document.activeElement;
        window.lastCopiedIp = field.value.slice(field.selectionStart, field.selectionEnd);
        return true;
      };
    });
    await page.click('#fb-copy-ip');
    await page.waitForFunction(() => window.lastCopiedIp === '192.168.1.77');
    await page.fill('#fb-wpw', SECRETS.wifi + 'x');
    assert.equal(await page.isEnabled('#fb-next'), false, 'changed password invalidates the connection test');
    assert.equal(await page.isVisible('#fb-copy-ip'), false);
    await page.fill('#fb-wpw', SECRETS.wifi);
    await page.click('#fb-test');
    await page.waitForFunction(() => document.getElementById('fb-tested-ip').value === '192.168.1.77', null, { timeout: 15000 });
    assert.deepEqual(g.tested, { ssid: 'HomeNetwork', password: SECRETS.wifi });
    assert.equal(await page.inputValue('#fb-lan'), 'esp32-tailnet-1a2b', 'the board name is suggested for .local');
    await page.fill('#fb-lan', 'Bad_Name');
    assert.equal(await page.inputValue('#fb-lan'), 'bad_name', 'typed lowercase');
    assert.equal(await page.isEnabled('#fb-next'), false, 'an invalid .local name is refused');
    await page.fill('#fb-lan', 'esp32-tailnet-1a2b');
    await check(2);
    await page.click('#fb-next');
    await page.waitForSelector('#fb-ts-now', { state: 'visible' });
    assert.equal(await page.isEnabled('#fb-next'), false, 'Tailscale now or later must be chosen');
    await page.check('#fb-ts-now');
    await page.fill('#fb-key', 'tskey');
    assert.equal(await page.isEnabled('#fb-next'), false, 'short key refused');
    await page.fill('#fb-key', SECRETS.key);
    await page.check('input[name="fb-ctl"][value="hs"]');
    assert.equal(await page.isEnabled('#fb-next'), false, 'Headscale needs a URL');
    await page.fill('#fb-server', 'https://headscale.example.com');
    await page.fill('#fb-host', 'Bad_Name');
    assert.equal(await page.isEnabled('#fb-next'), false, 'invalid hostname refused');
    await page.fill('#fb-host', 'home-gateway');
    await check(3);
    await page.click('#fb-next');
    await page.waitForSelector('#fb-apname', { state: 'visible' });
    await choicesStart(page);
    assert.equal(await page.inputValue('#fb-apname'), 'ESP32-Tailnet-1A2B');
    assert.equal(await page.inputValue('#fb-appw'), '', 'no gateway Wi-Fi password is chosen for the user');
    assert.equal(await page.isEnabled('#fb-next'), false, 'the gateway Wi-Fi password is required');
    await page.click('#fb-appw-gen');
    const apPw = await page.inputValue('#fb-appw');
    assert.match(apPw, /^[A-Za-z0-9]{5}-[A-Za-z0-9]{5}-[A-Za-z0-9]{4}$/);
    await page.fill('#fb-appw', SECRETS.admin);
    assert.equal(await page.isEnabled('#fb-next'), false, 'AP password must differ from admin');
    await page.click('#fb-appw-gen');
    await page.check('#fb-roles input[value="subnet-router"]');
    assert.equal(await page.isChecked('#fb-share-lan'), true, 'Connect a network selects the subnet route');
    await page.check('#fb-roles input[value="wol"]');
    assert.equal(await page.isChecked('#fb-x-history'), true, 'Wake or recover keeps the event history');
    assert.equal(await page.isChecked('#fb-x-trends'), false, 'extras stay off unless chosen');
    await page.check('#fb-roles input[value="monitoring"]');
    assert.equal(await page.isChecked('#fb-x-trends') && await page.isChecked('#fb-x-snapshots'), true, 'Monitor and get alerts selects trends and settings copies');
    assert.equal(await page.isChecked('#fb-x-names'), false, 'tailnet names only for the IoT role or by hand');
    await page.check('#fb-roles input[value="advanced"]');
    assert.equal(await page.evaluate(() => document.getElementById('fb-net').open || document.getElementById('fb-extras').open), false, 'a choice opens no section');
    await check(4);
    await page.click('#fb-next');
    await page.waitForSelector('#fb-summary dt');
    const summaryText = await page.textContent('#fb-summary');
    assert.ok(summaryText.includes('HomeNetwork') && summaryText.includes('Europe/Rome'), 'Wi-Fi and the browser time zone in the summary');
    assert.ok(summaryText.includes('http://192.168.1.77/') && summaryText.includes('http://esp32-tailnet-1a2b.local/'), 'address after the restart in the summary');
    for (const s of [...Object.values(SECRETS), await page.inputValue('#fb-appw')]) assert.ok(!summaryText.includes(s), 'secret in summary');
    await check(5);
    await page.click('#fb-next');
    await page.waitForSelector('#fb-done', { state: 'visible' });
    assert.ok(g.finish, 'finish sent');
    assert.equal(g.finish.admin_password, SECRETS.admin);
    assert.deepEqual(g.finish.wifi, { ssid: 'HomeNetwork', password: SECRETS.wifi });
    assert.deepEqual(g.finish.uplink, { type: 'wifi' }); assert.equal(g.finish.tz, 'CET-1CEST,M3.5.0,M10.5.0/3');
    assert.deepEqual(g.finish.tailnet, { auth_key: SECRETS.key, login_server: 'https://headscale.example.com', hostname: 'home-gateway' });
    assert.equal(g.finish.share_lan, true); assert.equal(g.finish.exit_node, false); assert.equal(g.finish.ap_recovery_only, true);
    assert.equal(g.finish.ap_ssid, 'ESP32-Tailnet-1A2B');
    assert.equal(g.finish.lan_name, '', 'the suggested name is the board default: nothing to save');
    assert.equal(g.finish.ap_open, false, 'the gateway Wi-Fi has a password unless the user removes it');
    assert.deepEqual(g.finish.roles, ['subnet-router', 'wol', 'monitoring', 'advanced']);
    assert.deepEqual(g.finish.extras, { history: true, trends: true, snapshots: true, tailnet_names: false });
    const [xh, xt] = await page.evaluate(() => [I18N.t('Event history'), I18N.t('Trends')]);
    assert.ok(summaryText.includes(xh) && summaryText.includes(xt), 'extras in the summary, in the page language'); assert.equal(g.finish.advanced_ui, true); assert.ok(g.finish.ap_password.length >= 8 && g.finish.ap_password !== SECRETS.admin);
    assert.ok((await page.textContent('#fb-done-open')).includes('http://192.168.1.77/'));
    assert.equal(await page.getAttribute('#fb-done-open a[href="http://192.168.1.77/"]', 'href'), 'http://192.168.1.77/', 'tested address is a link');
    assert.equal(await page.getAttribute('#fb-done-open a[href="http://esp32-tailnet-1a2b.local/"]', 'href'), 'http://esp32-tailnet-1a2b.local/', 'per-board .local link');
    assert.equal(await page.isVisible('#fb-done-name'), true); assert.equal(await page.textContent('#fb-done-host'), 'esp32-tailnet-1a2b.local');
    assert.equal(await page.inputValue('#fb-pw'), '', 'secrets cleared from the form');
    for (const b of g.bodies) for (const s of [...Object.values(SECRETS), g.finish.ap_password])
      assert.ok(!b.includes(s), 'secret sent in clear');
    await check(5);
    if (errors.length) failures.push(`${where}: script errors ${[...new Set(errors)].slice(0, 3).join(' | ')}`);
    if (!full) return;
    await uplinkFlows(context);
    await standaloneRecoveryFlow(context);
    await choicesFlow(context);
    // Setup-code pairing with one wrong code, on a fresh page.
    const p2 = await context.newPage(); const g2 = mockGateway(); await p2.route('http://esp32.test/**', g2.handle);
    await p2.goto('http://esp32.test/'); await p2.waitForSelector('#firstBoot', { state: 'visible' });
    await p2.waitForFunction(() => document.getElementById('fb-pair-status').textContent.includes('BOOT'));
    await p2.click('.fb-details summary'); await p2.fill('#fb-code', '1111 2222'); await p2.click('#fb-code-btn');
    await p2.waitForFunction(() => /Attempts left: 4/.test(document.getElementById('fb-error').textContent));
    await p2.fill('#fb-code', '1234 5678'); await p2.click('#fb-code-btn');
    await p2.waitForSelector('#fb-pw', { state: 'visible' });
    // Gateway restarted during pairing (real board: console opened): the page says
    // so instead of "expired", the code is refused cleanly, and Try again recovers.
    const p4 = await context.newPage(); const g4 = mockGateway(); await p4.route('http://esp32.test/**', g4.handle);
    await p4.goto('http://esp32.test/'); await p4.waitForFunction(() => document.getElementById('fb-pair-status').textContent.includes('BOOT'));
    g4.sid = 'restarted';
    await p4.waitForFunction(() => /pairing was reset/.test(document.getElementById('fb-pair-status').textContent));
    assert.ok(await p4.isVisible('#fb-retry'));
    await p4.click('#fb-retry'); await p4.waitForFunction(() => document.getElementById('fb-pair-status').textContent.includes('BOOT'));
    g4.press(); await p4.waitForSelector('#fb-pw', { state: 'visible' });
    // Another device already pairing: clear message and a retry button.
    const p3 = await context.newPage(); const g3 = mockGateway({ busy: true }); await p3.route('http://esp32.test/**', g3.handle);
    await p3.goto('http://esp32.test/'); await p3.waitForSelector('#fb-retry', { state: 'visible' });
    assert.ok((await p3.textContent('#fb-pair-status')).includes('Another device'));
    g3.busy = false; await p3.click('#fb-retry');
    await p3.waitForFunction(() => document.getElementById('fb-pair-status').textContent.includes('BOOT'));
  } catch (e) {
    failures.push(`${where}: ${process.env.FB_VERBOSE ? e.stack : e.message.split('\n').slice(0, 6).join(' ')}`);
  } finally { await context.close(); }
}

module.exports = { mockGateway, html, SECRETS };
if (require.main === module) (async () => {
  const browser = await chromium.launch({ channel: process.env.TEST_BROWSER_CHANNEL || 'chrome' });
  const failures = [];
  const runs = [[390, 844, 'en-US', true], [1440, 900, 'en-US', true]].concat(
    LOCALES.flatMap(l => [[320, 640, l], [768, 1024, l], [1920, 1080, l]]))
    .filter(r => !process.env.FB_LOCALE || r[2] === process.env.FB_LOCALE);
  try {
    for (const r of runs) await flow(browser, r, failures, r[3]);
  } finally { await browser.close(); }
  if (failures.length) { console.log(failures.join('\n')); console.log('FAIL ' + failures.length); process.exit(1); }
  console.log(`PASS: first-boot wizard end to end (${runs.length} viewport/language runs): pairing by button and code, busy pairing, password/Wi-Fi/tailnet/AP validation, sealed requests with no secret in clear, layout`);
})();
