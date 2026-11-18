"""Tailnet access on restrictive networks and odd inputs (actual code).

- ml_coord.c ctrl_transport_failed(): Tailscale's control server over TLS on
  443 after two failed connections on port 80 (blocked port, transparent
  proxy breaking the upgrade), back after two more failures; a custom login
  server keeps its address; the default branch of do_tcp_connect follows it.
- clock_from_control(): the clock is set from MapResponse.ControlTime while
  unset (NTP blocked left the policy pending: key expiry needs a clock);
  never overrides a set clock, accepts only valid UTC RFC 3339.
- first_ipv4(): the own and peer address is the first IPv4 of Addresses,
  not item 0 (IPv6-first or IPv6-only nodes left it empty).
- web_ui.c save_trimmed_str_if_present() / tailscale_manager.c
  trim_in_place(): a pasted auth key with spaces or a line break is saved
  and used without them ("invalid key" otherwise).
- Wiring: DERP moves to the next node of its region after a failure and
  dials the DERPMap address when DNS fails; the first map of a session is
  marked complete; refusals needing user action retry every 5 minutes.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
COORD = (ML / 'src/ml_coord.c').read_text(encoding='utf-8').replace('\r\n', '\n')
DERP = (ML / 'src/ml_derp.c').read_text(encoding='utf-8').replace('\r\n', '\n')
WEB = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8').replace('\r\n', '\n')
MGR = (ROOT / 'main/tailscale_manager.c').read_text(encoding='utf-8').replace('\r\n', '\n')
HTML = (ROOT / 'main/index.html').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(src, signature):
    start = src.index(signature)
    return src[start:src.index('\n}\n', start) + 3]


# --- wiring ------------------------------------------------------------------
tcp = function(COORD, 'static int do_tcp_connect(')
assert 'ml->ctrl_saas_tls ? "443" : "80"' in tcp and 'ml->use_tls = ml->ctrl_saas_tls;' in tcp
assert COORD.count('ctrl_transport_failed(ml);') == 3
assert 'ml->ctrl_transport_failures = 0;   /* this transport works: keep it */' in COORD
assert 'clock_from_control(map);' in function(COORD, 'static bool apply_peer_map(')
assert COORD.count('ml_policy_expect_full_map();') == 2 and 'if (!omit_peers) ml_policy_expect_full_map();' in COORD
assert COORD.count('first_ipv4(cJSON_GetObjectItem(') == 4 and 'cJSON_GetArrayItem(addresses, 0)->valuestring' not in COORD
assert 'backoff_ms = 300000;' in COORD
assert 'if (err != ESP_OK) ml->derp_node_pick++;' in function(DERP, 'esp_err_t ml_derp_connect(')
once = DERP[DERP.index('static esp_err_t derp_connect_once(microlink_t *ml) {'):]
assert 'ml->derp_node_pick % usable' in once and 'ml_getaddrinfo(derp_node->ipv4, port_str, &hints, &res)' in once
assert WEB.count('save_trimmed_str_if_present(s, "auth_key", "ts_authkey");') == 1
assert WEB.count('save_trimmed_str_if_present(root, "auth_key", "ts_authkey");') == 1
assert 'save_str_if_present(s, "auth_key"' not in WEB and 'save_str_if_present(root, "auth_key"' not in WEB
assert 's_active_auth_key = trim_in_place(nvs_str_or_empty("ts_authkey"));' in MGR
assert "document.getElementById('ts-auth-key').value.trim()" in HTML
# Approval granted later arrives in the map (reconnects do not register).
amap = function(COORD, 'static bool apply_peer_map(')
assert 'if (cJSON_IsTrue(ma) && ml->reg_state==ML_REG_STATE_APPROVAL) ml->reg_state=ML_REG_STATE_OK;' in amap
# A registered identity starts without a saved auth key; host/login trimmed.
conn = function(MGR, 'static esp_err_t tailscale_connect_locked(')
assert '!s_active_auth_key[0] ||' not in conn and 'No auth key saved: connecting with the registered identity' in conn
assert 's_active_login_server = trim_in_place(nvs_str_or_empty("ts_login"));' in MGR
assert 'save_trimmed_str_if_present(s, "login_server", "ts_login");' in WEB

assert 'answer_ping_request(ml, noise);' in COORD and 'note_ping_request(ml,' in amap and 'apply_display_messages(ml,' in amap
assert 'if (ctrl_is_tailscale(ml)) {' in tcp
# Node.Expired in the map forces a real registration (reconnects skip it
# since beta.17) and records the expiry for the renewal.
assert 'ml->force_register = true;   /* the server answers NodeKeyExpired */' in COORD
assert 'ml->force_register = true;   /* not straight to the map */' in COORD
assert COORD.count('saas_refresh_key(ml);') == 1
noise = function(COORD, 'static int do_noise_handshake(')
assert 'else if (ml->ctrl_noise_pubkey_valid) {' in noise
C_CODE = (function(COORD, 'static bool ctrl_is_tailscale(const microlink_t *ml)\n{') + function(COORD, 'static void ctrl_transport_failed(')
          + function(COORD, 'static void note_ping_request(') + function(COORD, 'static void apply_display_messages(')
          + function(COORD, 'int microlink_get_display_messages(') + function(COORD, 'static uint32_t first_ipv4(const cJSON *addresses) {')
          + function(COORD, 'static void saas_refresh_key(')
          + function(COORD, 'static void clock_from_control(') + function(WEB, 'static void save_trimmed_str_if_present(')
          + function(MGR, 'static char *trim_in_place('))
PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"
#define ESP_LOGW(...) ((void)0)
static const char *TAG = "t";
#include <strings.h>
#define ML_CTRL_HOST "controlplane.tailscale.com"
#define MICROLINK_MAX_DISPLAY_MESSAGES 4
typedef struct {char id[48];char title[96];char text[320];char severity[8];bool impacts_connectivity;} microlink_display_message_t;
typedef struct {char ctrl_host[64];char ctrl_host_parsed[64];char ctrl_port_str[8];bool ctrl_saas_tls;uint8_t ctrl_transport_failures;
    uint64_t ctrl_saas_key_ms;bool use_tls;char ctrl_host_hdr[96];bool ctrl_noise_pubkey_valid;
    microlink_display_message_t display_msgs[MICROLINK_MAX_DISPLAY_MESSAGES];uint8_t display_msg_count;char ping_path[200];char ping_last[200];} microlink_t;
static uint64_t fake_ms=1;static uint64_t ml_get_time_ms(void){return fake_ms;}
static int fetches,fetch_ok;static bool fetch_tls;static char fetch_host[64],fetch_port[8],fetch_hdr[96];
struct microlink_s;static int fetch_server_pubkey(void *m,const char *host,const char *port);
#define strlcpy test_strlcpy   /* glibc >= 2.38 declares strlcpy under gnu11 */
static size_t strlcpy(char *d,const char *s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
#define timeval test_timeval   /* host headers may define their own */
struct timeval {time_t tv_sec;long tv_usec;};
static time_t fake_now, set_to;static int sets;
#define time(x) (fake_now)
static int settimeofday(const struct timeval *tv, const void *tz){(void)tz;set_to=tv->tv_sec;sets++;fake_now=tv->tv_sec;return 0;}
static char saved[200];
static void nvs_save_str(const char *k,const char *v){(void)k;snprintf(saved,sizeof saved,"%s",v);}
static int fetch_server_pubkey(void *mv,const char *host,const char *port){microlink_t *m=mv;fetches++;fetch_tls=m->use_tls;snprintf(fetch_host,sizeof fetch_host,"%s",host);snprintf(fetch_port,sizeof fetch_port,"%s",port);snprintf(fetch_hdr,sizeof fetch_hdr,"%s",m->ctrl_host_hdr);return fetch_ok?0:-1;}
@@CODE@@
static uint32_t ip(const char *json){cJSON *a=cJSON_Parse(json);uint32_t r=first_ipv4(a);cJSON_Delete(a);return r;}
static void ct(const char *text){cJSON *m=cJSON_CreateObject();cJSON_AddStringToObject(m,"ControlTime",text);clock_from_control(m);cJSON_Delete(m);}
int main(void){
    (void)TAG;
    /* Transport fallback (Tailscale default server only). */
    microlink_t ml;memset(&ml,0,sizeof ml);
    ctrl_transport_failed(&ml);assert(!ml.ctrl_saas_tls);
    ctrl_transport_failed(&ml);assert(ml.ctrl_saas_tls&&ml.ctrl_transport_failures==0);
    ctrl_transport_failed(&ml);ctrl_transport_failed(&ml);assert(!ml.ctrl_saas_tls);     /* back to 80 */
    strcpy(ml.ctrl_host,"https://headscale.example");strcpy(ml.ctrl_host_parsed,"headscale.example");strcpy(ml.ctrl_port_str,"443");
    for(int i=0;i<6;i++)ctrl_transport_failed(&ml);assert(!ml.ctrl_saas_tls);          /* custom server untouched */
    strcpy(ml.ctrl_host,"https://controlplane.tailscale.com/");strcpy(ml.ctrl_host_parsed,"controlplane.tailscale.com");
    assert(ctrl_is_tailscale(&ml));ctrl_transport_failed(&ml);ctrl_transport_failed(&ml);assert(ml.ctrl_saas_tls);   /* typed by hand: same fallback */
    strcpy(ml.ctrl_port_str,"8443");assert(!ctrl_is_tailscale(&ml));                  /* explicit port kept */
    /* Tailscale key refresh after a Noise failure: HTTPS only, every 10 min, custom servers untouched. */
    ml.ctrl_host[0]=0;ml.use_tls=false;strcpy(ml.ctrl_host_hdr,"keep-me");fake_ms=5000;fetch_ok=1;
    saas_refresh_key(&ml);assert(fetches==1&&fetch_tls&&!strcmp(fetch_host,"controlplane.tailscale.com")&&!strcmp(fetch_port,"443"));
    assert(!strcmp(fetch_hdr,"controlplane.tailscale.com")&&!ml.use_tls&&!strcmp(ml.ctrl_host_hdr,"keep-me"));   /* restored */
    fake_ms=5000+599999;saas_refresh_key(&ml);assert(fetches==1);
    fake_ms=5000+600000;saas_refresh_key(&ml);assert(fetches==2);
    strcpy(ml.ctrl_host,"https://hs.example");fake_ms+=700000;saas_refresh_key(&ml);assert(fetches==2);
    /* PingRequest: liveness over Noise recorded once per URL; others not. */
    cJSON *pr=cJSON_Parse("{\"URL\":\"https://controlplane.tailscale.com/machine/ping/abc\",\"URLIsNoise\":true}");
    note_ping_request(&ml,pr);assert(!strcmp(ml.ping_path,"/machine/ping/abc"));
    strcpy(ml.ping_last,ml.ping_path);ml.ping_path[0]=0;note_ping_request(&ml,pr);assert(!ml.ping_path[0]);cJSON_Delete(pr);   /* duplicate */
    pr=cJSON_Parse("{\"URL\":\"https://x/y\",\"URLIsNoise\":true,\"Types\":\"disco\",\"IP\":\"100.64.0.2\"}");note_ping_request(&ml,pr);assert(!ml.ping_path[0]);cJSON_Delete(pr);
    pr=cJSON_Parse("{\"URL\":\"https://log.example/z\"}");note_ping_request(&ml,pr);assert(!ml.ping_path[0]);cJSON_Delete(pr);   /* plain TLS: not here */
    note_ping_request(&ml,NULL);
    /* DisplayMessages patch semantics, bounded. */
    cJSON *dm=cJSON_Parse("{\"a\":{\"Title\":\"Key expiring\",\"Text\":\"Renew soon\",\"Severity\":\"medium\"},\"b\":{\"Title\":\"B\",\"ImpactsConnectivity\":true}}");
    apply_display_messages(&ml,dm);cJSON_Delete(dm);assert(ml.display_msg_count==2&&!strcmp(ml.display_msgs[0].title,"Key expiring")&&ml.display_msgs[1].impacts_connectivity);
    dm=cJSON_Parse("{\"a\":null,\"c\":{\"Title\":\"C\"},\"d\":{\"Title\":\"D\"},\"e\":{\"Title\":\"E\"},\"f\":{\"Title\":\"F\"}}");
    apply_display_messages(&ml,dm);cJSON_Delete(dm);assert(ml.display_msg_count==4&&!strcmp(ml.display_msgs[0].id,"b"));   /* a deleted, f over the bound */
    microlink_display_message_t out[4];assert(microlink_get_display_messages(&ml,out,4)==4&&microlink_get_display_messages(&ml,out,2)==2);
    dm=cJSON_Parse("{\"*\":null,\"g\":{\"Title\":\"G\"}}");apply_display_messages(&ml,dm);cJSON_Delete(dm);
    assert(ml.display_msg_count==1&&!strcmp(ml.display_msgs[0].id,"g"));
    char longtext[1000];memset(longtext,'x',999);longtext[999]=0;cJSON *big=cJSON_CreateObject(),*one=cJSON_AddObjectToObject(big,"g");
    cJSON_AddStringToObject(one,"Text",longtext);apply_display_messages(&ml,big);cJSON_Delete(big);assert(strlen(ml.display_msgs[0].text)==319);
    /* Clock from the control server. */
    fake_now=0;ct("2026-11-18T09:30:15.123456789Z");assert(sets==1&&set_to==1794994215);
    ct("2027-01-01T00:00:00Z");assert(sets==1);                                        /* clock already set */
    fake_now=0;ct("2028-03-01T00:00:00Z");assert(sets==2&&set_to==1835481600);         /* after a leap day */
    fake_now=0;ct("2024-02-29T12:00:00Z");assert(sets==3&&set_to==1709208000);sets=2;  /* on a leap day */
    fake_now=0;ct("2026-11-18T09:30:15+01:00");ct("garbage");ct("2026-13-01T00:00:00Z");ct("2019-01-01T00:00:00Z");
    assert(sets==2);                                                                   /* non-UTC/invalid ignored */
    cJSON *m=cJSON_CreateObject();cJSON_AddNumberToObject(m,"ControlTime",5);clock_from_control(m);cJSON_Delete(m);assert(sets==2);
    /* First IPv4 of Addresses. */
    assert(ip("[\"100.64.1.2/32\",\"fd7a:115c:a1e0::2/128\"]")==0x64400102);
    assert(ip("[\"fd7a:115c:a1e0::2/128\",\"100.64.1.3/32\"]")==0x64400103);          /* IPv6 first */
    assert(ip("[\"fd7a:115c:a1e0::2/128\"]")==0&&ip("[]")==0&&ip("[null,5]")==0&&ip("[\"300.1.1.1/32\"]")==0);
    assert(first_ipv4(NULL)==0);
    /* Auth key trimming. */
    cJSON *o=cJSON_Parse("{\"auth_key\":\"  tskey-x \\r\\n\"}");save_trimmed_str_if_present(o,"auth_key","k");assert(!strcmp(saved,"tskey-x"));cJSON_Delete(o);
    o=cJSON_Parse("{\"auth_key\":\"\\t\\n\"}");save_trimmed_str_if_present(o,"auth_key","k");assert(!strcmp(saved,""));cJSON_Delete(o);
    strcpy(saved,"unchanged");o=cJSON_Parse("{\"auth_key\":5}");save_trimmed_str_if_present(o,"auth_key","k");assert(!strcmp(saved,"unchanged"));cJSON_Delete(o);
    char k1[]=" \tabc-def\r\n",k2[]="abc",k3[]="   ";
    assert(!strcmp(trim_in_place(k1),"abc-def")&&!strcmp(trim_in_place(k2),"abc")&&!strcmp(trim_in_place(k3),"")&&trim_in_place(NULL)==NULL);
    puts("PASS: actual control key refresh over HTTPS only (rate limited), TLS-443 fallback for Tailscale control (also when typed by hand; custom servers untouched), liveness PingRequest recorded once, DisplayMessages patch/bound/truncation, clock from ControlTime only while unset and only valid UTC, first IPv4 of Addresses, auth key trimmed on save and load");
    return 0;
}
'''
dep = os.environ.get('CJSON_SOURCE')
cj = [dep, '-I', str(Path(dep).parent)] if dep else \
    subprocess.check_output(['pkg-config', '--cflags', '--libs', 'libcjson'], text=True).split()
with tempfile.TemporaryDirectory(prefix='tailnet-access-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@CODE@@', C_CODE), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-misleading-indentation']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), *cj, '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:])
print('tailnet access: restrictive networks and pasted keys no longer block access')
