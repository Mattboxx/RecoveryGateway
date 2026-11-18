"""Leave the tailnet (actual microlink.c, ml_coord.c and web_ui.c code).

The "Leave tailnet" button logs this gateway out of the control server as
`tailscale logout` does (a RegisterRequest for the same node key with an
expiry in the past, never an auth key), then forgets the auth key and the
identity, turns Tailscale off and restarts. Checked:
- microlink_logout(): nothing to do for a node never registered; ESP_OK only
  when the control server accepted it, ESP_FAIL on its refusal, a timeout
  when it never answered (also when the command cannot be queued);
- the RegisterRequest of a logout carries Expiry 1970-01-01T00:02:03Z and no
  auth key even when one is saved; a renewal never rides on it;
- the answer: only an explicit Error refuses the logout, and nothing else in
  it is acted on;
- the coordination task opens a fresh connection for it and then stays idle
  (a forced reconnect does not register the node again);
- the web endpoint reports what the server answered and forgets locally in
  every case (key erased, Tailscale off, identity reset).
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
MAIN = (ML / 'src/microlink.c').read_text(encoding='utf-8').replace('\r\n', '\n')
COORD = (ML / 'src/ml_coord.c').read_text(encoding='utf-8').replace('\r\n', '\n')
WEB = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(src, sig):
    start = src.index(sig)
    return src[start:src.index('\n}\n', start) + 3]


def block(src, head):
    """The braced block of the statement that starts at head."""
    a = src.index(head)
    depth, k = 0, src.index('{', a)
    while True:
        depth += {'{': 1, '}': -1}.get(src[k], 0)
        if depth == 0:
            return src[a:k + 1]
        k += 1


logout = function(MAIN, 'esp_err_t microlink_logout(microlink_t *ml, uint32_t timeout_ms) {')
req = block(COORD, '    if (ml->logout_requested) {\n        /* Logout, as the reference client')
resp = block(COORD, '    if (ml->logout_requested) {\n        /* The server answered the logout;')
server = function(WEB, 'static const char *tailscale_leave_server(esp_err_t lo)')

# Wiring of the coordination task and the endpoint.
assert '    if (ml->renewing && !ml->logout_requested) {' in COORD
loop = COORD[COORD.index('            case ML_CMD_LOGOUT:'):]
loop = loop[:loop.index('break;')]
assert 'ml->logout_requested = true;' in loop and 'ml->force_register = true;' in loop and 'state = COORD_TCP_CONNECT;' in loop
assert 'if (!ml->logout_requested) state = COORD_RECONNECTING;' in COORD
reg = COORD[COORD.index('                int reg = do_register(ml, &noise);'):]
reg = reg[:reg.index('                if (reg < 0) {')]
for s in ('ml->logout_ok = reg >= 0;', 'state = COORD_IDLE;', 'xEventGroupSetBits(ml->events, ML_EVT_LOGOUT_DONE);', 'ml_policy_reset();'):
    assert s in reg, s
handler = function(WEB, 'static esp_err_t tailscale_leave_handler(httpd_req_t *req)')
assert handler.index('require_password_session(req)') < handler.index('microlink_logout(ml, 10000)')
assert handler.index('microlink_logout(ml, 10000)') < handler.index('nvs_param_erase("ts_authkey")') \
    < handler.index('nvs_param_set_int("ts_enabled", 0)') < handler.index('microlink_factory_reset()')
assert 'reg_uri(server, &uri_tailscale_leave);' in WEB

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_TIMEOUT 0x107
#define ESP_LOGW(...) ((void)0)
#define TAG "t"
#define pdTRUE 1
#define pdFALSE 0
#define pdMS_TO_TICKS(x) (x)
#define ML_EVT_LOGOUT_DONE (1u << 10)
typedef unsigned EventBits_t;
typedef enum { ML_CMD_LOGOUT = 4 } ml_coord_cmd_t;
typedef struct { int depth, full; ml_coord_cmd_t last; } queue_t;
typedef struct { unsigned bits; } events_t;
typedef struct {
    queue_t *coord_cmd_queue; events_t *events; bool registered_this_boot;
    volatile bool logout_requested, logout_ok;
} microlink_t;
static bool nvs_registered;
static bool ml_identity_registered(microlink_t *ml) { (void)ml; return nvs_registered; }
/* The coordination task, simulated: it answers a queued logout. */
static int server_answer;   /* 0 none, 1 accepted, 2 refused */
static microlink_t *coord_ml;
static int xQueueSend(queue_t *q, ml_coord_cmd_t *c, int w) { (void)w; if (q->full) return 0; q->depth++; q->last = *c; return pdTRUE; }
static void xEventGroupClearBits(events_t *e, unsigned b) { e->bits &= ~b; }
static EventBits_t xEventGroupWaitBits(events_t *e, unsigned b, int clear, int all, int t) {
    (void)all; (void)t;
    if (server_answer) { coord_ml->logout_ok = server_answer == 1; e->bits |= ML_EVT_LOGOUT_DONE; }
    EventBits_t r = e->bits & b; if (clear) e->bits &= ~b; return r; }
@@LOGOUT@@
static void request(microlink_t *ml, cJSON *root, bool have_key_in) {
    bool have_key = have_key_in;
@@REQ@@
    cJSON_AddBoolToObject(root, "_have_key", have_key);
}
static int answer(microlink_t *ml, cJSON *resp_json) {
@@RESP@@
    cJSON_Delete(resp_json);
    return 99;   /* not a logout: the normal interpretation follows */
}
@@SERVER@@
int main(void) {
    queue_t q = {0}; events_t ev = {0};
    microlink_t ml = { .coord_cmd_queue = &q, .events = &ev }; coord_ml = &ml;
    assert(microlink_logout(NULL, 10) == ESP_ERR_INVALID_ARG);
    /* never registered: nothing to log out, nothing queued */
    assert(microlink_logout(&ml, 10) == ESP_ERR_INVALID_STATE && q.depth == 0);
    nvs_registered = true;
    server_answer = 1; assert(microlink_logout(&ml, 10) == ESP_OK && q.depth == 1 && q.last == ML_CMD_LOGOUT);
    server_answer = 2; assert(microlink_logout(&ml, 10) == ESP_FAIL);
    server_answer = 0; assert(microlink_logout(&ml, 10) == ESP_ERR_TIMEOUT);
    q.full = 1; server_answer = 1; assert(microlink_logout(&ml, 10) == ESP_ERR_TIMEOUT); q.full = 0;
    nvs_registered = false; ml.registered_this_boot = true; assert(microlink_logout(&ml, 10) == ESP_OK);

    /* RegisterRequest of a logout: expiry in the past, no key */
    cJSON *r = cJSON_CreateObject();
    ml.logout_requested = true; request(&ml, r, true);
    assert(!strcmp(cJSON_GetObjectItem(r, "Expiry")->valuestring, "1970-01-01T00:02:03Z"));
    assert(cJSON_IsFalse(cJSON_GetObjectItem(r, "_have_key")));
    cJSON_Delete(r);
    r = cJSON_CreateObject(); ml.logout_requested = false; request(&ml, r, true);
    assert(!cJSON_GetObjectItem(r, "Expiry") && cJSON_IsTrue(cJSON_GetObjectItem(r, "_have_key")));
    cJSON_Delete(r);

    /* the answer */
    ml.logout_requested = true;
    assert(answer(&ml, cJSON_Parse("{}")) == 0);
    assert(answer(&ml, cJSON_Parse("{\"NodeKeyExpired\":true,\"MachineAuthorized\":false}")) == 0);
    assert(answer(&ml, cJSON_Parse("{\"Error\":\"\"}")) == 0);
    assert(answer(&ml, cJSON_Parse("{\"Error\":\"node not found\"}")) == -1);
    ml.logout_requested = false;
    assert(answer(&ml, cJSON_Parse("{\"Error\":\"x\"}")) == 99);

    /* what the page is told */
    assert(!strcmp(tailscale_leave_server(ESP_OK), "logged_out"));
    assert(!strcmp(tailscale_leave_server(ESP_FAIL), "refused"));
    assert(!strcmp(tailscale_leave_server(ESP_ERR_INVALID_STATE), "not_registered"));
    assert(!strcmp(tailscale_leave_server(ESP_ERR_TIMEOUT), "unreachable"));
    puts("PASS: actual logout: expiry in the past without a key, answer judged only by Error, bounded wait, refusal/timeout/never-registered reported");
    return 0;
}
'''
dep = os.environ.get('CJSON_SOURCE')
cj = [dep, '-I', str(Path(dep).parent)] if dep else \
    subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcjson'], text=True).split()
with tempfile.TemporaryDirectory(prefix='tailnet-leave-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@LOGOUT@@', logout).replace('@@REQ@@', req).replace('@@RESP@@', resp)
                 .replace('@@SERVER@@', server), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), *cj, '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('tailnet leave: logout, then the key and identity are forgotten')
