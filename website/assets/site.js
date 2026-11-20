// Navigation, support choices, theme toggle, copy buttons and client-side search.
// No network requests: the search index ships as search-index.js.
(function () {
  var doc = document.documentElement;

  var supportDialog = document.getElementById('support-dialog'), supportOpener = null;
  if (supportDialog && typeof supportDialog.showModal === 'function') {
    document.querySelectorAll('[data-support-open]').forEach(function (link) {
      link.addEventListener('click', function (e) {
        // Keep the direct provider link usable if native dialogs are unavailable.
        e.preventDefault();
        if (panel && !panel.hidden) closeSearch();
        supportOpener = link;
        if (!supportDialog.open) supportDialog.showModal();
      });
    });
    supportDialog.querySelector('.support-close').addEventListener('click', function () { supportDialog.close(); });
    supportDialog.addEventListener('click', function (e) {
      var r = supportDialog.getBoundingClientRect();
      if (e.target === supportDialog && (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom)) supportDialog.close();
    });
    supportDialog.addEventListener('close', function () {
      if (supportOpener) supportOpener.focus();
    });
  }

  // Web installer: after a finished install, once its dialog closes, show the
  // next step and a quiet tip line (the line at most once a month per browser).
  // ESP Web Tools 10.4.0 has no completion event; its dialog element keeps the
  // install progress in _installState, read here without changing it.
  var done = document.getElementById('flasher-done');
  if (done && 'MutationObserver' in window) {
    var showDone = function () {
      var tip = done.querySelector('.flasher-tip'), now = Date.now(), last = 0;
      try { last = Number(localStorage.getItem('rg-tip-shown')) || 0; } catch (e) { last = 0; }
      if (tip) tip.hidden = now - last < 30 * 24 * 3600 * 1000;
      if (tip && !tip.hidden) { try { localStorage.setItem('rg-tip-shown', String(now)); } catch (e) { /* private mode */ } }
      done.hidden = false;
      done.scrollIntoView({ block: 'nearest' });
    };
    done.querySelector('.flasher-done-close').addEventListener('click', function () { done.hidden = true; });
    var watchDialog = function (dialog) {
      var finished = false;
      var timer = setInterval(function () {
        var state = dialog._installState;
        if (state && state.state === 'finished') finished = true;
      }, 500);
      dialog.addEventListener('closed', function () { clearInterval(timer); if (finished) showDone(); }, { once: true });
    };
    new MutationObserver(function (changes) {
      changes.forEach(function (change) {
        change.addedNodes.forEach(function (node) { if (node.nodeName === 'EWT-INSTALL-DIALOG') watchDialog(node); });
      });
    }).observe(document.body, { childList: true });
  }

  var menu = document.querySelector('.menu'), nav = document.getElementById('site-nav');
  if (menu && nav) {
    var openedAt = 0;
    var setMenu = function (open) {
      nav.classList.toggle('open', open);
      menu.setAttribute('aria-expanded', open ? 'true' : 'false');
      openedAt = window.scrollY;
    };
    menu.addEventListener('click', function () { setMenu(!nav.classList.contains('open')); });
    // The open menu must not stay over the page: close it when the page
    // scrolls, on a tap outside the header or with Escape.
    window.addEventListener('scroll', function () {
      if (nav.classList.contains('open') && Math.abs(window.scrollY - openedAt) > 40) setMenu(false);
    }, { passive: true });
    document.addEventListener('click', function (e) {
      if (nav.classList.contains('open') && !e.target.closest('.top')) setMenu(false);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && nav.classList.contains('open')) { setMenu(false); menu.focus(); }
    });
  }

  var theme = document.querySelector('.theme');
  if (theme) theme.addEventListener('click', function () {
    var current = doc.getAttribute('data-theme') ||
      (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    var next = current === 'light' ? 'dark' : 'light';
    doc.setAttribute('data-theme', next);
    try { localStorage.setItem('theme', next); } catch (e) { /* optional */ }
  });

  document.querySelectorAll('pre > code').forEach(function (code) {
    var button = document.createElement('button');
    button.type = 'button'; button.className = 'copy'; button.textContent = 'Copy';
    button.addEventListener('click', function () {
      var done = function (ok) { button.textContent = ok ? 'Copied' : 'Select and copy'; setTimeout(function () { button.textContent = 'Copy'; }, 1800); };
      if (navigator.clipboard) navigator.clipboard.writeText(code.innerText).then(function () { done(true); }, function () { done(false); });
      else done(false);
    });
    code.parentNode.appendChild(button);
  });

  var panel = document.querySelector('.search-panel'), input = document.getElementById('search-input'),
      results = document.getElementById('search-results'), opener = document.querySelector('.search-open');
  var root = (document.querySelector('.brand') || {}).getAttribute ? document.querySelector('.brand').getAttribute('href') : './';
  function openSearch() { panel.hidden = false; input.focus(); }
  function closeSearch() { panel.hidden = true; if (opener) opener.focus(); }
  function escapeHtml(s) { return s.replace(/[&<>"]/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]; }); }
  function search(q) {
    var words = q.toLowerCase().split(/\s+/).filter(Boolean), index = window.SEARCH_INDEX || [];
    if (!words.length) { results.innerHTML = ''; return; }
    var hits = index.map(function (p) {
      var t = p.t.toLowerCase(), d = p.d.toLowerCase(), x = p.x.toLowerCase(), score = 0;
      for (var i = 0; i < words.length; i++) {
        var w = words[i], s = (t.indexOf(w) >= 0 ? 8 : 0) + (d.indexOf(w) >= 0 ? 4 : 0) + (x.indexOf(w) >= 0 ? 1 : 0);
        if (!s) return null; score += s;
      }
      return {p: p, s: score};
    }).filter(Boolean).sort(function (a, b) { return b.s - a.s; }).slice(0, 8);
    results.innerHTML = hits.length ? hits.map(function (h) {
      return '<li><a href="' + root + h.p.u + '">' + escapeHtml(h.p.t) + '</a><small>' + escapeHtml(h.p.d) + '</small></li>';
    }).join('') : '<li>No results. Try a different word.</li>';
  }
  if (panel && input) {
    if (opener) opener.addEventListener('click', openSearch);
    panel.querySelector('.search-close').addEventListener('click', closeSearch);
    input.addEventListener('input', function () { search(input.value); });
    document.addEventListener('keydown', function (e) {
      if (supportDialog && supportDialog.open) return;
      if (e.key === 'Escape' && !panel.hidden) closeSearch();
      if (e.key === '/' && panel.hidden && !/input|textarea/i.test((e.target || {}).tagName || '')) { e.preventDefault(); openSearch(); }
    });
  }
})();
/* Interactive hardware diagram: choosing a part shows its details below.
 * Without JavaScript every detail stays visible as a list. */
(function () {
  var fig = document.getElementById('hw-diagram');
  if (!fig) return;
  var parts = fig.querySelectorAll('.hw-part');
  var details = document.querySelectorAll('.hw-detail');
  if (!parts.length || !details.length) return;
  document.documentElement.classList.add('hw-js');
  function select(key, focusDetail) {
    for (var i = 0; i < parts.length; i++) {
      var on = parts[i].getAttribute('data-part') === key;
      parts[i].classList.toggle('is-active', on);
      parts[i].setAttribute('aria-pressed', on ? 'true' : 'false');
    }
    for (var j = 0; j < details.length; j++) {
      details[j].classList.toggle('is-active', details[j].getAttribute('data-part') === key);
    }
    if (focusDetail && window.matchMedia('(max-width: 700px)').matches) {
      var d = document.getElementById('hw-d-' + key);
      if (d) d.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }
  for (var i = 0; i < parts.length; i++) {
    parts[i].addEventListener('click', function () { select(this.getAttribute('data-part'), true); });
    parts[i].addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(this.getAttribute('data-part'), true); }
    });
  }
  select(details[0].getAttribute('data-part'), false);
})();
