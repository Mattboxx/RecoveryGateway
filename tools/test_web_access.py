"""Web administration access scope and session binding (actual code).

web_access.h (pure) and the real session store of main/web_ui.c (struct,
lookup, slot choice, creation) compiled against a scripted HTTP request:
- sessions are bound to the client address that logged in: the same cookie
  from another IPv4 or IPv6 address is refused, the session stays valid for
  its own client (a copied cookie cannot log the owner out either), an
  unknown client address creates no session;
- admin scope "anywhere" allows every gateway address; "tailnet and AP"
  allows the tailnet address, the AP address while the AP runs, loopback
  and Tailscale IPv6, refuses the LAN address and other IPv6, and allows
  everything while the tailnet is down (no lock-out);
- IPv4-mapped addresses round-trip.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
web = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')


def function(signature):
    start = web.index(signature)
    return web[start:web.index('\n}\n', start) + 3]


store = web[web.index('typedef struct {\n    char     token[WEB_UI_SESSION_TOKEN_LEN * 2 + 1];'):web.index('static web_session_t s_sessions[WEB_UI_SESSION_MAX] = {0};')]
store += 'static web_session_t s_sessions[WEB_UI_SESSION_MAX] = {0};\n'
store += 'static uint64_t s_session_activity_order;\nstatic uint32_t s_session_timeout_s = 1800;\n'
code = store + function('static int session_find_for_req(httpd_req_t *req)') + function('static int session_pick_new_slot(void)') \
    + function('static const char *session_create(httpd_req_t *req)')

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "web_access.h"
#include "upstream_validation.h"
#define ESP_OK 0
#define WEB_UI_SESSION_TOKEN_LEN 32
#define WEB_UI_SESSION_MAX 4
typedef struct {const char *cookie; web_addr_t peer; bool peer_known;} httpd_req_t;
static httpd_req_t *g_req;
static int httpd_req_to_sockfd(httpd_req_t *r) {g_req = r; return 7;}
static size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *k) {(void)k; return r->cookie ? strlen(r->cookie) : 0;}
static int httpd_req_get_hdr_value_str(httpd_req_t *r, const char *k, char *out, size_t n) {(void)k; snprintf(out, n, "%s", r->cookie); return ESP_OK;}
static int64_t esp_timer_get_time(void) {return 1000000;}
static void esp_fill_random(void *b, size_t n) {static uint8_t x = 1; for (size_t i = 0; i < n; i++) ((uint8_t *)b)[i] = x++;}
static void hex_encode(const uint8_t *src, size_t len, char *out) {for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02x", src[i]); out[len * 2] = 0;}
static bool socket_addr(int fd, bool peer, web_addr_t *out) {(void)fd; (void)peer; if (!g_req->peer_known) return false; *out = g_req->peer; return true;}
@@CODE@@
static uint32_t ip(int a, int b, int c, int d) {uint8_t x[4] = {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d}; uint32_t v; memcpy(&v, x, 4); return v;}
int main(void)
{
    /* sessions bound to the client address */
    httpd_req_t login = {.peer = web_addr_v4(ip(192, 168, 1, 50)), .peer_known = true};
    const char *t = session_create(&login);
    assert(t && strlen(t) == 64);
    char cookie[128];
    snprintf(cookie, sizeof cookie, "theme=dark; ts_session=%s", t);
    httpd_req_t same = {.cookie = cookie, .peer = web_addr_v4(ip(192, 168, 1, 50)), .peer_known = true};
    httpd_req_t other = {.cookie = cookie, .peer = web_addr_v4(ip(192, 168, 1, 51)), .peer_known = true};
    httpd_req_t v6 = {.cookie = cookie, .peer_known = true};
    v6.peer.b[0] = 0xfe; v6.peer.b[1] = 0x80; v6.peer.b[15] = 0x32;
    httpd_req_t unknown = {.cookie = cookie, .peer_known = false};
    int slot = session_find_for_req(&same);
    assert(slot >= 0);
    assert(session_find_for_req(&other) == -1 && session_find_for_req(&v6) == -1 && session_find_for_req(&unknown) == -1);
    assert(session_find_for_req(&same) == slot);              /* still valid for its own client */
    httpd_req_t no_addr = {.peer_known = false};
    assert(session_create(&no_addr) == NULL);
    /* an IPv6 client's session */
    httpd_req_t v6login = v6; v6login.cookie = NULL;
    const char *t6 = session_create(&v6login);
    char cookie6[128]; snprintf(cookie6, sizeof cookie6, "ts_session=%s", t6);
    httpd_req_t v6same = v6; v6same.cookie = cookie6;
    httpd_req_t v6other = v6; v6other.cookie = cookie6; v6other.peer.b[15] = 0x33;
    assert(session_find_for_req(&v6same) >= 0 && session_find_for_req(&v6other) == -1);

    /* admin scope */
    uint32_t lan = ip(192, 168, 1, 246), ap = ip(192, 168, 4, 1), ts = ip(100, 80, 107, 31);
    web_addr_t a_lan = web_addr_v4(lan), a_ap = web_addr_v4(ap), a_ts = web_addr_v4(ts), a_lo = web_addr_v4(ip(127, 0, 0, 1));
    uint32_t back; assert(web_addr_is_v4(&a_lan, &back) && back == lan);
    for (int s = 0; s < 2; s++) assert(web_admin_allowed(WEB_ADMIN_ANYWHERE, s ? &a_lan : &a_ap, ap, ts, true));
    assert(!web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_lan, ap, ts, true));
    assert(web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_ap, ap, ts, true));
    assert(web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_ts, ap, ts, true));
    assert(web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_lo, ap, ts, true));
    assert(!web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_ap, 0, ts, true));      /* AP off */
    assert(!web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_ts, ap, 0, true));      /* no tailnet address yet */
    assert(web_admin_allowed(WEB_ADMIN_TAILNET_AP, &a_lan, ap, ts, false));    /* tailnet down: LAN keeps access */
    web_addr_t ula = {{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}};
    web_addr_t lo6 = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    web_addr_t ll6 = {{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}};
    assert(web_admin_allowed(WEB_ADMIN_TAILNET_AP, &ula, ap, ts, true));
    assert(web_admin_allowed(WEB_ADMIN_TAILNET_AP, &lo6, ap, ts, true));
    assert(!web_admin_allowed(WEB_ADMIN_TAILNET_AP, &ll6, ap, ts, true));
    assert(!web_addr_is_v4(&ll6, NULL));
    puts("web access ok");
    return 0;
}
'''


def run(source):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 't.c').write_text(PROGRAM.replace('@@CODE@@', source), encoding='utf-8')
        exe = tmp / ('t.exe' if os.name == 'nt' else 't')
        flags = ['-fsanitize=address,undefined'] if os.environ.get('WEB_SANITIZE') == '1' else []
        build = subprocess.run(['gcc', '-std=gnu11', '-O1', '-Wall', '-Wno-unused-function', *flags, '-I', str(ROOT / 'main'),
                                str(tmp / 't.c'), '-o', str(exe)], capture_output=True, text=True)
        if build.returncode:
            return build
        return subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)


ok = run(code)
assert ok.returncode == 0 and 'web access ok' in ok.stdout, (ok.returncode, ok.stdout, ok.stderr[-2000:])
# Before 3.0.25-beta.10 a session matched on the cookie alone.
old = 'return peer_known && web_addr_same(&peer, &s_sessions[i].peer) ? i : -1;'
assert old in code
assert run(code.replace(old, 'return i;')).returncode != 0, 'cookie-only sessions must fail'
print('web access: sessions bound to the login address (IPv4/IPv6), admin limited to tailnet/AP with no lock-out while the tailnet is down')
