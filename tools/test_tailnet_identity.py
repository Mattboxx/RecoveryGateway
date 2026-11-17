"""Node key expiry, renewal, Tailnet Lock and registration state (actual code).

- history.c key_expiry_warning(): no warning without a set clock, beyond 14
  days or after expiry; once a day inside 14 days; last-day text.
- microlink.c renewal: after the control server reported the node key
  expired, the next start with an auth key makes a new node key (machine and
  DISCO keys stay), keeps the old one for OldNodeKey until the server accepts
  the renewal, resumes an unaccepted renewal, needs an auth key, and keeps
  the old identity if saving fails (NVS stubbed, write failures injected).
- index.html renderTsRegistration() (run in Node with a stub DOM): the
  notice per registration state, the auth-key link, expiry date and the
  14-day hint, map/tunnel counts, the Tailnet Lock sign command.
- ml_coord.c wiring: OldNodeKey while renewing, NodeKeyExpired recorded,
  reconnects after a registration skip the RegisterRequest until a map
  exchange fails, TKAInfo sets Tailnet Lock.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
BLAKE = next(ML.glob('components/wireguard_lwip/src/crypto/refc/blake2s.c'))
HIST = (ROOT / 'main/history.c').read_text(encoding='utf-8').replace('\r\n', '\n')
MAIN = (ML / 'src/microlink.c').read_text(encoding='utf-8').replace('\r\n', '\n')
COORD = (ML / 'src/ml_coord.c').read_text(encoding='utf-8').replace('\r\n', '\n')
HTML = (ROOT / 'main/index.html').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(src, signature):
    start = src.index(signature)
    return src[start:src.index('\n}\n', start) + 3]


def compile_run(program, name, extra=()):
    with tempfile.TemporaryDirectory(prefix='tailnet-identity-') as tmp:
        c = Path(tmp) / (name + '.c')
        c.write_text(program, encoding='utf-8')
        exe = Path(tmp) / (name + ('.exe' if os.name == 'nt' else ''))
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', *[a for a in extra if not a.endswith('.c')]]
        if os.environ.get('POLICY_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), *[a for a in extra if a.endswith('.c')], '-o', str(exe)],
                       check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        print(out.stdout.strip())
        if out.returncode:
            raise SystemExit(out.stderr[-2000:])


# --- structural wiring -------------------------------------------------------
reg = COORD[COORD.index('static int do_register('):COORD.index('State: FETCH_PEERS')]
assert 'if (ml->renewing) {' in reg and '"OldNodeKey"' in reg
assert 'ml->reg_auth.registered = !ml->renewing && ml_identity_registered(ml);' in reg
assert 'ml_identity_mark_expired(ml);' in reg and 'ml->reg_state = ML_REG_STATE_KEY_EXPIRED;' in reg
assert reg.index('ml->registered_this_boot = true;') > reg.index('ml_reg_auth_result(')
assert 'state = ml->registered_this_boot && !ml->force_register ? COORD_FETCH_PEERS : COORD_REGISTER;' in COORD
assert COORD.count('ml->force_register = true;') == 2
apply_map = function(COORD, 'static bool apply_peer_map(')
assert apply_map.index('"TKAInfo"') < apply_map.index('ml_policy_apply(map)') and 'ml->tailnet_lock=on;' in apply_map
init = MAIN[MAIN.index('microlink_t *microlink_init('):]
assert init.index('ml->config.auth_key = ml->nvs_auth_key;') < init.index('ml_identity_renew_if_expired(ml);') < init.index('/* Create queues */')

# --- key expiry warning (history.c) -------------------------------------------
warn = function(HIST, 'static bool key_expiry_warning(')
compile_run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define KEY_EXPIRY_WARN_DAYS 14
''' + warn + r'''
int main(void){
    char t[161];int64_t last=-1,now=1800000000;
    assert(!key_expiry_warning(0,now,&last,t,sizeof t));                       /* never expires */
    assert(!key_expiry_warning(now+86400*10,1000,&last,t,sizeof t));           /* clock not set */
    assert(!key_expiry_warning(now+86400*15,now,&last,t,sizeof t));            /* > 14 days */
    assert(key_expiry_warning(now+86400*10+5,now,&last,t,sizeof t)&&strstr(t,"expires in 10 days"));
    assert(!key_expiry_warning(now+86400*10+5,now+3600,&last,t,sizeof t));     /* once a day */
    assert(key_expiry_warning(now+86400*10+5,now+86400,&last,t,sizeof t)&&strstr(t,"in 9 days"));
    last=-1;assert(key_expiry_warning(now+600,now,&last,t,sizeof t)&&strstr(t,"within a day"));
    assert(!key_expiry_warning(now-1,now,&last,t,sizeof t));                   /* expired: the refusal reports it */
    assert(strlen(t)<=160);
    puts("PASS: actual key expiry warning: once a day within 14 days, none without clock/after expiry/never-expiring");
    return 0;
}
''', 'warn')

# --- renewal (microlink.c) ------------------------------------------------------
renew = ''.join(function(MAIN, sig) for sig in (
    'static esp_err_t save_keypair(', 'void ml_identity_mark_expired(',
    'static void ml_identity_renew_if_expired(', 'void ml_identity_mark_registered('))
compile_run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "ml_reg_auth.h"
typedef int esp_err_t;typedef int nvs_handle_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NVS_NOT_FOUND 0x1102
#define NVS_READWRITE 1
#define NVS_READONLY 0
#define NVS_NAMESPACE "microlink"
#define NVS_KEY_WG_PRI "wg_private"
#define NVS_KEY_WG_PUB "wg_public"
#define NVS_KEY_REG_MARKER "reg_marker"
#define NVS_KEY_NK_EXPIRED "nk_expired"
#define NVS_KEY_NK_OLD "nk_old"
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
static const char *TAG="t";
static const char *esp_err_to_name(esp_err_t e){(void)e;return "err";}
/* NVS stub: a few named blobs/u8, failure injection on writes. */
typedef struct {char key[16];uint8_t data[64];size_t len;bool used;} slot_t;
static slot_t nv[16];static int fail_writes,commits;
static slot_t *find(const char *k){for(int i=0;i<16;i++)if(nv[i].used&&!strcmp(nv[i].key,k))return &nv[i];return NULL;}
static esp_err_t nvs_open(const char *ns,int mode,nvs_handle_t *h){(void)ns;(void)mode;*h=1;return ESP_OK;}
static void nvs_close(nvs_handle_t h){(void)h;}
static esp_err_t nvs_get_blob(nvs_handle_t h,const char *k,void *out,size_t *len){(void)h;slot_t *s=find(k);if(!s)return ESP_ERR_NVS_NOT_FOUND;if(*len<s->len)return ESP_FAIL;memcpy(out,s->data,s->len);*len=s->len;return ESP_OK;}
static esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *v,size_t len){(void)h;if(fail_writes)return ESP_FAIL;slot_t *s=find(k);
    if(!s)for(int i=0;i<16&&!s;i++)if(!nv[i].used){s=&nv[i];s->used=true;strcpy(s->key,k);}memcpy(s->data,v,len);s->len=len;return ESP_OK;}
static esp_err_t nvs_get_u8(nvs_handle_t h,const char *k,uint8_t *v){size_t l=1;return nvs_get_blob(h,k,v,&l);}
static esp_err_t nvs_set_u8(nvs_handle_t h,const char *k,uint8_t v){return nvs_set_blob(h,k,&v,1);}
static esp_err_t nvs_erase_key(nvs_handle_t h,const char *k){(void)h;if(fail_writes)return ESP_FAIL;slot_t *s=find(k);if(!s)return ESP_ERR_NVS_NOT_FOUND;s->used=false;return ESP_OK;}
static esp_err_t nvs_commit(nvs_handle_t h){(void)h;commits++;return fail_writes?ESP_FAIL:ESP_OK;}
static uint8_t gen=0x40;
static void generate_keypair(uint8_t *pri,uint8_t *pub){memset(pri,gen,32);memset(pub,(uint8_t)(gen+1),32);gen+=2;}
typedef struct {const char *auth_key;} cfg_t;
typedef struct {cfg_t config;bool identity_persistent,renewing;uint8_t wg_private_key[32],wg_public_key[32],old_node_key[32];} microlink_t;
@@CODE@@
static void boot(microlink_t *m,const char *key){m->config.auth_key=key;m->renewing=false;m->identity_persistent=true;
    memset(m->wg_private_key,1,32);memset(m->wg_public_key,2,32);
    slot_t *p=find(NVS_KEY_WG_PUB);if(p)memcpy(m->wg_public_key,p->data,32);slot_t *q=find(NVS_KEY_WG_PRI);if(q)memcpy(m->wg_private_key,q->data,32);}
int main(void){
    microlink_t m;memset(&m,0,sizeof m);
    /* No expiry recorded: nothing changes. */
    boot(&m,"synthetic-key");ml_identity_renew_if_expired(&m);assert(!m.renewing&&m.wg_public_key[0]==2);
    /* Expired, no auth key: kept, waits for a key. */
    ml_identity_mark_expired(&m);assert(find(NVS_KEY_NK_EXPIRED));
    boot(&m,"");ml_identity_renew_if_expired(&m);assert(!m.renewing&&m.wg_public_key[0]==2&&find(NVS_KEY_NK_EXPIRED));
    /* Saving fails: the old identity stays, the expiry stays recorded. */
    fail_writes=1;boot(&m,"synthetic-key");ml_identity_renew_if_expired(&m);fail_writes=0;
    assert(!m.renewing&&m.wg_public_key[0]==2);
    /* With an auth key: new node key, old one kept for OldNodeKey, flag cleared. */
    uint8_t g=gen;boot(&m,"synthetic-key");ml_identity_renew_if_expired(&m);
    assert(m.renewing&&m.old_node_key[0]==2&&m.wg_public_key[0]==g+1&&m.wg_private_key[0]==g);
    assert(!find(NVS_KEY_NK_EXPIRED)&&find(NVS_KEY_NK_OLD)&&find(NVS_KEY_WG_PUB)->data[0]==g+1);
    /* Not accepted before a restart: the renewal resumes with the same keys. */
    boot(&m,"synthetic-key");ml_identity_renew_if_expired(&m);
    assert(m.renewing&&m.old_node_key[0]==2&&m.wg_public_key[0]==g+1&&gen==g+2);
    /* Accepted: record written, renewal state cleared for good. */
    ml_identity_mark_registered(&m);assert(!m.renewing&&!find(NVS_KEY_NK_OLD)&&find(NVS_KEY_REG_MARKER));
    boot(&m,"synthetic-key");ml_identity_renew_if_expired(&m);assert(!m.renewing&&m.wg_public_key[0]==g+1);
    puts("PASS: actual node key renewal: needs an auth key, new node key with OldNodeKey kept until accepted, resumes after restart, save failure keeps the identity");
    return 0;
}
'''.replace('@@CODE@@', renew), 'renew', ['-Wno-misleading-indentation', '-Wno-unused-variable', '-I', str(ML / 'src'), '-I', str(BLAKE.parent), str(ML / 'src/ml_reg_auth.c'), str(BLAKE)])

# --- UI (index.html) in Node --------------------------------------------------------
start = HTML.index('    var TS_REG_TEXT = {')
end = HTML.index('\n    }\n', HTML.index('function renderTsRegistration(r)')) + 7
ui = HTML[start:end]
ids = ['ts-reg-notice', 'ts-reg-notice-text', 'ts-reg-notice-key', 'ts-key-expiry-row', 'ts-key-expiry', 'ts-key-expiry-hint',
       'ts-tunnels-row', 'ts-tunnels-row2', 'ts-map-peers', 'ts-tunnels', 'ts-lock-notice', 'ts-lock-cmd', 'ts-auth-key']
for i in ids:
    assert f'id="{i}"' in HTML, i
NODE = r'''
const els = {};
for (const id of IDS) els[id] = {style: {display: 'none'}, textContent: '', onclick: null, focus(){this.focused=true;}, scrollIntoView(){}};
const document = {getElementById: id => els[id] || null};
@@UI@@
const shown = id => els[id].style.display !== 'none';
const check = (c, m) => { if (!c) { console.error('FAIL ' + m); process.exit(1); } };
const states = ['key_retry','need_new_key','need_key','approval','key_expired','refused'];
for (const s of states) {
  renderTsRegistration({reg_state: s});
  check(shown('ts-reg-notice') && els['ts-reg-notice-text'].textContent === TS_REG_TEXT[s], 'notice ' + s);
  check(shown('ts-reg-notice-key') === !['approval','key_retry'].includes(s), 'key link ' + s);
}
renderTsRegistration({reg_state: 'need_new_key'});
els['ts-reg-notice-key'].onclick({preventDefault(){}});
check(els['ts-auth-key'].focused, 'link focuses the auth key field');
renderTsRegistration({reg_state: 'ok', key_expiry: 0, map_peers: 18, tunnels_active: 3, tunnel_slots: 20, tailnet_lock: false});
check(!shown('ts-reg-notice') && !shown('ts-key-expiry-row') && !shown('ts-lock-notice'), 'ok state quiet');
check(els['ts-map-peers'].textContent === '18' && els['ts-tunnels'].textContent === '3 / 20' && shown('ts-tunnels-row'), 'counts');
const now = Date.now() / 1000;
renderTsRegistration({reg_state: 'ok', key_expiry: Math.floor(now + 30 * 86400)});
check(shown('ts-key-expiry-row') && !shown('ts-key-expiry-hint') && /\d{4}-\d{2}-\d{2}/.test(els['ts-key-expiry'].textContent), 'expiry far');
renderTsRegistration({reg_state: 'ok', key_expiry: Math.floor(now + 5 * 86400)});
check(shown('ts-key-expiry-hint'), 'expiry soon hint');
renderTsRegistration({reg_state: 'ok', tailnet_lock: true, node_key: 'nodekey:abcd'});
check(shown('ts-lock-notice') && els['ts-lock-cmd'].textContent === 'tailscale lock sign nodekey:abcd', 'lock command');
renderTsRegistration({});
check(!shown('ts-reg-notice') && !shown('ts-tunnels-row'), 'older firmware fields absent');
console.log('PASS: actual Tailscale page registration notice, auth-key link, expiry/hint, counts, Tailnet Lock command (Node, stub DOM)');
'''
with tempfile.TemporaryDirectory(prefix='tailnet-identity-ui-') as tmp:
    js = Path(tmp) / 'ui.js'
    js.write_text('const IDS = ' + json.dumps(ids) + ';\n' + NODE.replace('@@UI@@', ui), encoding='utf-8')
    out = subprocess.run(['node', str(js)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:])
print('tailnet identity: expiry warned, renewal keeps the device, clear registration state in the UI')
