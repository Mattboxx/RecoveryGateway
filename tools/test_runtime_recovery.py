"""Actual-C AP scheduler, Microlink startup rollback and bounded retry tests.

No device access. RUNTIME_SANITIZE=1 enables ASan/UBSan on CI.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(name, program):
    with tempfile.TemporaryDirectory(prefix='runtime-recovery-') as directory:
        path = Path(directory)
        source = path / 'test.c'
        source.write_text(program, encoding='utf-8')
        binary = path / ('test.exe' if os.name == 'nt' else 'test')
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-variable', '-Wno-unused-function']
        if os.environ.get('RUNTIME_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(source), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
        print('PASS:', name, flush=True)


headers = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <stdlib.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define pdPASS 1
#define pdTRUE 1
#define pdFALSE 0
#define portMAX_DELAY 0xffffffffu
#define pdMS_TO_TICKS(x) (x)
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
static int locks;
#define taskENTER_CRITICAL(x) do {(void)(x);assert(!locks);locks++;}while(0)
#define taskEXIT_CRITICAL(x) do {(void)(x);assert(locks==1);locks--;}while(0)
'''
ap_source = re.sub(r'^#include.*\n', '', (ROOT / 'main/ap_policy.c').read_text(), flags=re.M)
ap_fixture = r'''
typedef uint8_t StackType_t;
typedef unsigned TickType_t;
typedef int StaticTask_t;
typedef void *TaskHandle_t;
static int64_t clock_us;
static unsigned allocations, mode_calls, mode_failures, notifications;
static bool last_target, request_during_apply;
static void (*spawned)(void *), (*shutdown_callback)(void);
static jmp_buf blocked;
static int64_t esp_timer_get_time(void) {return clock_us;}
static int esp_register_shutdown_handler(void (*cb)(void)){shutdown_callback=cb;return ESP_OK;}
static TaskHandle_t xTaskCreateStatic(void(*fn)(void*),const char*n,unsigned stack,
    void*a,int priority,StackType_t *buffer,StaticTask_t *tcb) {
    (void)n;(void)a;assert(!locks && stack==8192 && priority==5 && buffer && tcb);
    assert(((uintptr_t)buffer&15)==0);allocations++;spawned=fn;return tcb;
}
static void xTaskNotifyGive(TaskHandle_t task){assert(task && !locks);notifications++;}
static unsigned ulTaskNotifyTake(int clear,unsigned ticks);
'''
ap_tests = r'''
static bool apply(bool target) {
    assert(!locks);mode_calls++;last_target=target;
    if(request_during_apply){request_during_apply=false;ap_policy_request(!target);}
    if(mode_failures){mode_failures--;return false;}return true;
}
static unsigned ulTaskNotifyTake(int clear,unsigned ticks) {
    assert(clear && !locks);
    if(ticks==portMAX_DELAY && (!s_pending || s_shutdown))longjmp(blocked,1);
    if(ticks!=portMAX_DELAY)clock_us+=(int64_t)ticks*1000;
    return 0;
}
static void execute(void) {
    assert(spawned);
    if(!setjmp(blocked))spawned(NULL);
    assert(!locks);
}
int main(void) {
    assert(ap_policy_init(NULL)==ESP_ERR_INVALID_ARG);
    assert(ap_policy_init(apply)==ESP_OK);
    assert(allocations==1 && ap_policy_init(apply)==ESP_OK && allocations==1);
    ap_policy_request(false);
    for(unsigned i=0;i<1000;i++)ap_policy_request(false);
    assert(allocations==1 && s_pending);
    execute();assert(!last_target && mode_calls==1 && clock_us==1500000);
    ap_policy_request(true);execute();assert(last_target && mode_calls==2);
    mode_failures=1;ap_policy_request(false);int64_t before_time=clock_us;execute();
    assert(!s_pending && !last_target && clock_us==before_time+2500000);
    /* A new request arriving during apply must survive the older completion. */
    request_during_apply=true;mode_failures=1;ap_policy_request(true);execute();
    assert(!last_target && !s_pending);
    /* Replace an already queued transition before the worker gets CPU time. */
    ap_policy_request(true);ap_policy_request(false);execute();assert(!last_target);
    /* Recovery-only fallback: a lost uplink waits 60 s; disconnect events
     * repeated by STA retries never postpone it; a reconnect cancels it. */
    ap_policy_request(false);execute();unsigned calls=mode_calls;int64_t lost=clock_us;
    ap_policy_request_after(true,60000);
    for(int i=0;i<11;i++){clock_us+=5000000;ap_policy_request_after(true,60000);} /* retries every 5 s */
    clock_us=lost;execute();assert(last_target&&mode_calls==calls+1&&clock_us==lost+60000000);
    ap_policy_request(false);execute();calls=mode_calls;
    ap_policy_request_after(true,60000);clock_us+=30000000;ap_policy_request(false); /* back within the minute */
    execute();assert(!last_target&&mode_calls==calls+1); /* AP never turned on */
    ap_policy_request(true);unsigned before=mode_calls;
    shutdown_callback();ap_policy_request(true);execute();
    assert(ap_policy_is_shutdown() && mode_calls==before && !s_pending && allocations==1);
    puts("AP recovery: one reserved stack, 1000 coalesced requests without allocation, grace/retry timing, 60 s WiFi-loss fallback not postponed by retries and cancelled by reconnect, latest-generation races and shutdown suppression");
}
'''
run('AP recovery remains allocation-free under runtime fragmentation', headers + ap_fixture + ap_source + ap_tests)

ml = (ROOT / 'external/microlink/components/microlink/src/microlink.c').read_text()
start = ml.split('    /* Create tasks */', 1)[1].split('\nesp_err_t microlink_stop', 1)[0]
ml_fixture = r'''
typedef int BaseType_t;
typedef struct {int events,coord_cmd_queue,tasks_alive;bool stop_incomplete;void *config_httpd;
    void *wg_mgr_task,*net_io_task,*derp_tx_task,*derp_rx_task,*coord_task;} microlink_t;
#define ML_TASK_WG_MGR_STACK 8192
#define ML_TASK_NET_IO_STACK 6144
#define ML_TASK_DERP_TX_STACK 10240
#define ML_TASK_COORD_STACK 12288
#define ML_TASK_WG_MGR_PRIO 18
#define ML_TASK_NET_IO_PRIO 18
#define ML_TASK_DERP_TX_PRIO 5
#define ML_TASK_COORD_PRIO 5
#define ML_TASK_WG_MGR_CORE 1
#define ML_TASK_NET_IO_CORE 0
#define ML_TASK_DERP_TX_CORE 0
#define ML_TASK_COORD_CORE 1
#define ML_EVT_WIFI_CONNECTED 1
#define ML_EVT_TASKS_READY 512
#define ML_CMD_CONNECT 1
typedef int ml_coord_cmd_t;
static void ml_wg_mgr_task(void *a){(void)a;}
static void ml_net_io_task(void *a){(void)a;}
static void ml_derp_tx_task(void *a){(void)a;}
static void ml_derp_rx_task(void *a){(void)a;}
static void ml_coord_task(void *a){(void)a;}
static int calls,fail_at,stops;static bool ready,incomplete;
static const char *expected[]={"ml_coord","ml_derp_tx","ml_derp_rx","ml_wg_mgr","ml_net_io"};
static int xTaskCreatePinnedToCore(void(*fn)(void*),const char*n,unsigned s,void*a,int p,void**h,int c) {
    (void)fn;(void)s;(void)a;(void)p;(void)c;
    assert(!ready && !strcmp(n,expected[calls]));int index=calls++;
    if(index==fail_at)return 0;
    *h=(void*)(uintptr_t)(index+1);return pdPASS;
}
static void xEventGroupSetBits(int e,int bits){(void)e;assert(calls==5 && (bits&ML_EVT_TASKS_READY));ready=true;}
static void xQueueSend(int q,const void*c,unsigned t){(void)q;(void)c;(void)t;assert(ready);}
static void ml_config_httpd_start(void*h,microlink_t*m){(void)h;(void)m;assert(ready);}
static void microlink_stop(microlink_t*m){stops++;m->tasks_alive=0;m->stop_incomplete=incomplete;
    m->wg_mgr_task=m->net_io_task=m->derp_tx_task=m->derp_rx_task=m->coord_task=NULL;}
'''
ml_tests = r'''
int main(void) {
    for(int failure=-1;failure<5;failure++) {
        calls=stops=0;ready=false;fail_at=failure;microlink_t node={0};
        int result=test_start(&node);
        if(failure<0){assert(result==ESP_OK && ready && node.tasks_alive==5 && !stops);}
        else {assert(result==ESP_ERR_NO_MEM && !ready && node.tasks_alive==0 && stops==1);}
    }
    calls=stops=0;ready=false;fail_at=2;incomplete=true;microlink_t node={0};
    assert(test_start(&node)==ESP_ERR_INVALID_STATE && !ready);
    puts("Microlink startup: descending stack sizes, ready barrier and rollback at all five allocation points; incomplete cleanup is not retryable");
}
'''
run('Microlink startup allocation rollback and registration barrier', headers + ml_fixture + 'static int test_start(microlink_t *ml) {\n' + start + ml_tests)

manager = (ROOT / 'main/tailscale_manager.c').read_text()
start = manager.index('static void tailscale_start_attempts(void)')
retry = manager[start:manager.index('\n}\n', start) + 3]
retry_fixture = r'''
static portMUX_TYPE s_connect_lock;
static bool s_start_retrying;static unsigned attempts,delayed,shortages;static int terminal;
static int tailscale_connect(void){assert(!locks);return attempts++<shortages?ESP_ERR_NO_MEM:terminal;}
static void vTaskDelay(unsigned ms){assert(!locks);delayed+=ms;}
static void tailscale_finish_start(int result){assert(!locks&&(result==terminal||result==ESP_ERR_NO_MEM));s_start_retrying=false;}
'''
retry_tests = r'''
int main(void){
    shortages=3;terminal=ESP_OK;tailscale_start_attempts();assert(attempts==4 && delayed==14000 && !s_start_retrying);
    attempts=delayed=0;shortages=10;tailscale_start_attempts();assert(attempts==5 && delayed==30000 && !s_start_retrying);
    attempts=delayed=shortages=0;terminal=ESP_ERR_INVALID_ARG;tailscale_start_attempts();assert(attempts==1 && !delayed);
    attempts=0;terminal=ESP_ERR_INVALID_STATE;tailscale_start_attempts();assert(attempts==1 && !delayed);
    puts("Tailscale startup: bounded transient retries, success recovery, no auth/config/incomplete-cleanup retries or reboot loop");
}
'''
run('Tailscale transient retry limits', headers + retry_fixture + retry + retry_tests)

for name in ('ml_coord.c', 'ml_wg_mgr.c'):
    source = (ROOT / 'external/microlink/components/microlink/src' / name).read_text()
    entry = source.split('void ' + name[:-2] + '_task(void *arg)', 1)[1]
    assert entry.index('ML_EVT_TASKS_READY') < entry.index('ESP_LOGI'), name
    assert 'ml_task_exiting(ml);' in entry.split('ESP_LOGI', 1)[0], name
assert 'ml->stun_public_ip == 0 || ml->stun_public_port == 0' in (ROOT / 'external/microlink/components/microlink/src/ml_coord.c').read_text()
assert 's_snapshot = heap_caps_malloc(cnt + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)' in (ROOT / 'main/log_capture.c').read_text()
print('PASS: coordinator/WG entry gates, missing STUN baseline and external-RAM boot-log snapshot guards')

coord = (ROOT / 'external/microlink/components/microlink/src/ml_coord.c').read_text()
nat = 'if (ml->stun_public_ip == 0 || ml->stun_public_port == 0)' + coord.split(
    'if (ml->stun_public_ip == 0 || ml->stun_public_port == 0)', 1)[1].split('                        parsed = true;', 1)[0]
nat_fixture = r'''
typedef struct {uint32_t stun_public_ip,stun_fallback_ip;uint16_t stun_public_port,stun_secondary_port;
    unsigned stun_retry_count;bool stun_nat_checked,nat_mapping_varies;} nat_t;
#define ML_STUN_FALLBACK_PORT 19302
static void ml_stun_send_probe_to(nat_t*m,uint32_t ip,unsigned port){(void)m;(void)ip;(void)port;}
'''
nat_tests = r'''
int main(void){
    nat_t n={.stun_public_ip=0xc0000201};
    sample(&n,0xc0000201,51820);assert(n.stun_public_port==51820 && !n.stun_nat_checked && !n.nat_mapping_varies);
    sample(&n,0xc0000201,51820);assert(n.stun_nat_checked && !n.nat_mapping_varies);
    n=(nat_t){0};sample(&n,0xc0000201,51820);sample(&n,0xc0000201,51821);
    assert(n.stun_nat_checked && n.nat_mapping_varies);
}
'''
run('Actual STUN comparison rejects zero baseline but retains valid equal/different-port detection',
    headers + nat_fixture + 'static void sample(nat_t *ml,uint32_t pub_ip,uint16_t pub_port){' + nat + '}\n' + nat_tests)

internal = (ROOT / 'external/microlink/components/microlink/include/microlink_internal.h').read_text()
allocate = 'static inline void *ml_psram_malloc' + internal.split('static inline void *ml_psram_malloc', 1)[1].split('static inline void *ml_psram_calloc', 1)[0]
allocator = 'static void *cjson_psram_malloc' + ml.split('static void *cjson_psram_malloc', 1)[1].split('/* ============================================================================', 1)[0]
json_fixture = r'''
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
typedef struct {void *(*malloc_fn)(size_t);void (*free_fn)(void*);} cJSON_Hooks;
static cJSON_Hooks installed;static unsigned hook_changes,external_attempts;static bool external_ok=true;
static void *heap_caps_malloc(size_t n,int caps){assert(caps==3 && !locks);external_attempts++;return external_ok?malloc(n):NULL;}
static void cJSON_InitHooks(cJSON_Hooks *h){assert(locks==1);installed=*h;hook_changes++;}
'''
json_tests = r'''
int main(void){
    microlink_json_memory_init();microlink_json_memory_init();assert(hook_changes==1);
    void *p=installed.malloc_fn(24);assert(p && external_attempts==1);installed.free_fn(p);
    external_ok=false;p=installed.malloc_fn(24);assert(p && external_attempts==2);installed.free_fn(p);
}
'''
run('One-time JSON allocator initialization, external allocation and internal fallback', headers + json_fixture + allocate + allocator + json_tests)
boot = (ROOT / 'main/main.c').read_text()
assert boot.index('microlink_json_memory_init();') < boot.index('ota_remote_init();') < boot.index('web_ui_init();')

wg_backend = (ROOT / 'external/microlink/components/microlink/components/wireguard_lwip/src/wireguardif.c').read_text()
endpoint = 'static void update_peer_addr' + wg_backend.split('static void update_peer_addr', 1)[1].split('/* Count contiguous', 1)[0]
endpoint += wg_backend[wg_backend.index('bool wireguardif_endpoint_usable('):wg_backend.index('static void mark_link_up(')]
endpoint_fixture = r'''
typedef uint32_t ip_addr_t;
typedef uint32_t ip4_addr_t;
typedef uint16_t u16_t;
struct netif {ip4_addr_t ip; ip4_addr_t peer_route;};
struct wireguard_peer {ip_addr_t ip,connect_ip;u16_t port,connect_port;uint32_t last_direct_rx;bool valid;};
#define WIREGUARD_MAX_PEERS 2
struct wireguard_device {struct wireguard_peer peers[WIREGUARD_MAX_PEERS];};
#define LWIP_IPV6 0
#define PP_NTOHL(a) (a)
#define IP_IS_V4(ip) ((ip)!=NULL)
#define ip_2_ip4(ip) (ip)
#define ip4_addr_get_u32(ip) (*(ip))
#define netif_ip4_addr(netif) (&(netif)->ip)
#define ip4_addr_cmp(a,b) (*(a)==*(b))
#define ip_addr_cmp(a,b) (*(a)==*(b))
#define IPADDR_BROADCAST UINT32_MAX
static unsigned checks;
static bool wireguardif_has_host_route(struct netif *n,const ip4_addr_t *ip){checks++;return n->peer_route==*ip;}
bool wireguardif_endpoint_usable(struct netif *, const ip_addr_t *);
static uint32_t now;
static uint32_t wireguard_sys_now(void){return now;}
static bool ip_addr_isany(const ip_addr_t *ip){return *ip==0;}
static void ip_addr_set_any(bool ipv6,ip_addr_t *ip){(void)ipv6;*ip=0;}
#define WG_DEBUG(...) ((void)0)
'''
endpoint_tests = r'''
int main(void){
    struct netif n={.ip=0x64400001,.peer_route=0x64400002};
    ip_addr_t direct=0xc0000201,relay=0;struct wireguard_peer p={.ip=direct,.port=41641};
    now=1000;update_peer_addr(&p,&relay,0,false);assert(p.ip==0 && p.port==0);
    now=2000;update_peer_addr(&p,&direct,41642,false);assert(p.ip==direct && p.port==41642 && p.last_direct_rx==2000);
    now=2100;update_peer_addr(&p,&relay,0,true);assert(!p.ip && !p.port);
    now=2200;update_peer_addr(&p,&direct,41642,true);
    now=31999;update_peer_addr(&p,&relay,0,false);assert(p.ip==direct && p.port==41642);
    now=32200;update_peer_addr(&p,&relay,0,false);assert(!p.ip && !p.port && p.last_direct_rx==2200);
    now=40000;update_peer_addr(&p,&direct,41643,false);assert(p.ip==direct && p.port==41643);
    now=0xfffffff0;update_peer_addr(&p,&direct,41644,false);
    now=100;update_peer_addr(&p,&relay,0,false);assert(p.ip==direct && p.port==41644);
    now=30000;update_peer_addr(&p,&relay,0,false);assert(!p.ip && !p.port);
    ip_addr_t cgnat=0x64400003,mask=UINT32_MAX;
    assert(!wireguardif_endpoint_usable(&n,&n.ip));
    assert(!wireguardif_endpoint_usable(&n,&n.peer_route));
    assert(wireguardif_endpoint_usable(&n,&cgnat));
    update_peer_addr(&p,&cgnat,41641,false); assert(p.ip==cgnat);
    unsigned before=checks;
    for (int i=0;i<1000;i++) update_peer_addr(&p,&cgnat,41641,false);
    assert(checks==before);
    update_peer_addr(&p,&n.peer_route,41641,false); assert(p.ip==cgnat);
    struct wireguard_device device={.peers={p}};
    device.peers[0].valid=true;
    device.peers[0].connect_ip=cgnat;
    device.peers[0].connect_port=41641;
    retire_endpoint_for_host_route(&device,&cgnat,&mask);
    assert(!device.peers[0].ip && !device.peers[0].connect_ip && !device.peers[0].port);
}
'''.replace('update_peer_addr(&p,','update_peer_addr(&n, &p,')
run('Actual authenticated endpoint selection: relay recovery, healthy direct retention, upgrade and clock wrap',
    headers + endpoint_fixture + endpoint + endpoint_tests)
assert 'update_peer_addr(device->netif, peer, addr, port, pbuf->tot_len > 0);' in wg_backend
assert 'uint32_t age = wireguard_sys_now() - kwp->last_direct_rx;' in (
    ROOT / 'external/microlink/components/microlink/src/ml_wg_mgr.c').read_text()

web = (ROOT / 'main/web_ui.c').read_text()
if os.environ.get('SESSION_BASELINE_REF'):
    web = subprocess.check_output(['git', 'show', os.environ['SESSION_BASELINE_REF'] + ':main/web_ui.c'], cwd=ROOT).decode()
sessions = 'static int session_pick_new_slot' + web.split('static int session_pick_new_slot', 1)[1].split('/* Remaining seconds', 1)[0]
auth = 'static bool request_authenticated' + web.split('static bool request_authenticated', 1)[1].split('/* Read the operator-defined', 1)[0]
clear = 'static void session_clear_all' + web.split('static void session_clear_all', 1)[1].split('/* Locate the slot', 1)[0]
session_fixture = r'''
#define WEB_UI_SESSION_MAX 4
#define WEB_UI_SESSION_TOKEN_LEN 32
typedef struct {uint8_t b[16];} web_addr_t;
typedef struct {char token[65];uint64_t expires_us,last_used_order;web_addr_t peer;} web_session_t;
static web_session_t s_sessions[4];static uint64_t s_session_activity_order,clock_us=100000;
static uint32_t s_session_timeout_s;static bool s_web_auth_enabled=true,password_set=true;
typedef struct {int slot;char token[65];} httpd_req_t;
static int httpd_req_to_sockfd(httpd_req_t *r){(void)r;return 3;}
static bool socket_addr(int fd,bool peer,web_addr_t *out){(void)fd;(void)peer;memset(out,1,sizeof *out);return true;}
static int64_t esp_timer_get_time(void){return clock_us;}
static void esp_fill_random(void *p,size_t n){static unsigned value;memset(p,++value,n);}
static void hex_encode(const uint8_t *p,size_t n,char *out){(void)n;memset(out,'a'+p[0]%26,64);out[64]=0;}
static bool is_web_password_set(void){return password_set;}
static int session_find_for_req(httpd_req_t *req){int i=req->slot;return i>=0&&i<4&&s_sessions[i].token[0]&&
    clock_us<s_sessions[i].expires_us&&!strcmp(req->token,s_sessions[i].token)?i:-1;}
'''
session_tests = r'''
int main(void){
    for(int i=0;i<4;i++){session_create(NULL);assert(s_sessions[i].expires_us==UINT64_MAX);}
    httpd_req_t req={.slot=0};strcpy(req.token,s_sessions[0].token);
    assert(request_authenticated(&req));assert(session_pick_new_slot()==1);
    session_create(NULL);assert(!strcmp(req.token,s_sessions[0].token));assert(session_pick_new_slot()==2);
    for(int n=0;n<10000;n++){int expected=(n+2)%4;assert(session_pick_new_slot()==expected);session_create(NULL);}
    s_sessions[3].expires_us=clock_us;assert(session_pick_new_slot()==3);
    session_clear_slot(2);assert(!s_sessions[2].token[0]&&!s_sessions[2].last_used_order);
    assert(session_pick_new_slot()==2);session_create(NULL);
    req.slot=2;strcpy(req.token,s_sessions[2].token);s_session_timeout_s=60;
    assert(request_authenticated(&req));assert(s_sessions[2].expires_us==clock_us+60000000);
    uint64_t order=s_sessions[2].last_used_order;req.token[0]='!';
    assert(!request_authenticated(&req)&&s_sessions[2].last_used_order==order);
    req.token[0]=s_sessions[2].token[0];
    clock_us+=50000000;assert(request_authenticated(&req));
    clock_us+=11000000;assert(request_authenticated(&req)); /* past the login's original deadline */
    order=s_sessions[2].last_used_order;
    s_session_timeout_s=120;session_extend_all_alive();
    assert(s_sessions[2].last_used_order==order&&s_sessions[2].expires_us==clock_us+120000000);
    s_session_timeout_s=15;session_extend_all_alive();
    clock_us+=15000000;assert(!request_authenticated(&req));
    int replacement=session_pick_new_slot();session_create(NULL);
    s_session_timeout_s=0;session_extend_all_alive();assert(s_sessions[replacement].expires_us==UINT64_MAX);
    session_clear_all();
    for(int i=0;i<4;i++)assert(!s_sessions[i].token[0]&&!s_sessions[i].expires_us&&!s_sessions[i].last_used_order);
    puts("Session eviction: no-timeout LRU, active-session preservation, 10000 creations, expired/cleared slots and timed-window changes");
}
'''
run('Actual Web UI session eviction with disabled timeout', headers + session_fixture + sessions + auth + clear + session_tests)

ops = (ROOT / 'main/homelab_ops.c').read_text()
retry_start = ops.index('void homelab_ops_retry_worker(void)')
retry = ops[retry_start:ops.index('\n}\n', retry_start) + 3]
ops_fixture = r'''
#define LOCK() taskENTER_CRITICAL(&ops_lock)
#define UNLOCK() taskEXIT_CRITICAL(&ops_lock)
static int ops_lock;
static int64_t now;
static bool initialized,starting,task,health,saved,fail_worker;
static struct {struct {bool monitoring;} settings;} store;
static unsigned attempts;
static int64_t esp_timer_get_time(void){return now;}
static bool health_monitor_enabled(void){assert(!locks);return health;}
static bool saved_tcp_schedule_enabled(void){assert(!locks);return saved;}
static esp_err_t ensure_worker(void){assert(!locks);attempts++;task=!fail_worker;return task?ESP_OK:ESP_ERR_NO_MEM;}
'''
ops_tests = r'''
int main(void){
    store.settings.monitoring=true;
    homelab_ops_retry_worker();assert(!attempts);
    initialized=true;starting=true;
    homelab_ops_retry_worker();assert(!attempts);
    starting=false;
    for(unsigned mode=0;mode<3;mode++){
        store.settings.monitoring=mode==0;health=mode==1;saved=mode==2;
        fail_worker=true;homelab_ops_retry_worker();assert(attempts==2*mode+1&&!task);
        now+=29999999;homelab_ops_retry_worker();assert(attempts==2*mode+1);
        now++;fail_worker=false;homelab_ops_retry_worker();assert(attempts==2*mode+2&&task);
        now+=30000000;homelab_ops_retry_worker();assert(attempts==2*mode+2);
        task=false;
    }
    store.settings.monitoring=health=saved=false;homelab_ops_retry_worker();assert(attempts==6);
}
'''
run('Shared operations worker retries each configured scheduler after allocation failure',
    headers + ops_fixture + retry + ops_tests)

direct_start = ml.index('bool ml_open_direct_udp(')
direct_start = ml[direct_start:ml.index('\n}\n', direct_start) + 3]
net_io = (ROOT / 'external/microlink/components/microlink/src/ml_net_io.c').read_text()
start = net_io.index('static int direct_udp_fd(')
direct_retry = net_io[start:net_io.index('\n}\n', start) + 3]
direct_fixture = r'''
#include <stdatomic.h>
#define CONFIG_ML_ZERO_COPY_WG 1
#define AF_INET 2
#define SOCK_DGRAM 2
#define IPPROTO_UDP 17
#define IPPROTO_IP 0
#define IP_TOS 1
#define F_GETFL 1
#define F_SETFL 2
#define O_NONBLOCK 4
#define INADDR_ANY 0
typedef unsigned socklen_t;
struct sockaddr {int unused;};
struct sockaddr_in {int sin_family;uint16_t sin_port;struct {uint32_t s_addr;} sin_addr;};
#define htons(x) (x)
#define ntohs(x) (x)
typedef struct {_Atomic int disco_sock4;_Atomic uint16_t disco_local_port;struct {void *pcb;} zc;} microlink_t;
static int64_t now;
static unsigned calls,closes,fail,bind_fail;
static microlink_t instance={.disco_sock4=-1};
static int64_t esp_timer_get_time(void){return now;}
static int ml_socket(int domain,int type,int proto){
 assert(domain==AF_INET&&type==SOCK_DGRAM&&proto==IPPROTO_UDP);calls++;return fail==1?-1:10;
}
static int ml_bind(int fd,struct sockaddr *addr,socklen_t size){
 const struct sockaddr_in *a=(const void *)addr;
 assert(fd==10&&size==sizeof *a&&a->sin_family==AF_INET);
 return fail==2||(bind_fail&&a->sin_port==51820)?-1:0;
}
static int setsockopt(int fd,int level,int op,const void *value,socklen_t size){
 assert(fd==10&&level==IPPROTO_IP&&op==IP_TOS&&size==sizeof(int)&&*(const int *)value==0xb8);return 0;
}
static int ml_fcntl(int fd,int cmd,int arg){
 assert(fd==10&&instance.disco_sock4<0);
 if(cmd==F_SETFL){assert(arg==O_NONBLOCK);return fail==3?-1:0;}
 assert(cmd==F_GETFL&&!arg);return 0;
}
static int getsockname(int fd,struct sockaddr *addr,socklen_t *size){
 assert(fd==10&&*size==sizeof(struct sockaddr_in));
 struct sockaddr_in *a=(void *)addr;
 if(!a->sin_port)a->sin_port=49153;
 return fail==4?-1:0;
}
static int ml_close_sock(int fd){assert(fd==10);closes++;return 0;}
'''
direct_tests = r'''
int main(void){
    for(fail=1;fail<=4;fail++){
        assert(!ml_open_direct_udp(&instance)&&instance.disco_sock4==-1&&!instance.disco_local_port);
        assert(closes==fail-1);
    }
    int64_t retry_at=5000000;fail=1;
    now=4999999;assert(direct_udp_fd(&instance,&retry_at)==-1&&calls==4);
    now++;assert(direct_udp_fd(&instance,&retry_at)==-1&&calls==5);
    now+=4999999;fail=0;bind_fail=1;
    assert(direct_udp_fd(&instance,&retry_at)==-1&&calls==5);
    now++;assert(direct_udp_fd(&instance,&retry_at)==10&&instance.disco_local_port==49153&&calls==6);
    assert(direct_udp_fd(&instance,&retry_at)==10&&calls==6);
    instance.disco_sock4=-1;instance.zc.pcb=&instance;
    now+=5000000;assert(direct_udp_fd(&instance,&retry_at)==-1&&calls==6);
}
'''
run('Direct UDP retries after socket pressure without replacing a live descriptor or raw PCB',
    headers + direct_fixture + direct_start + direct_retry + direct_tests)

start = manager.index('void tailscale_retry_peer_dns(')
peer_dns_retry = manager[start:manager.index('\n}\n', start) + 3]
peer_dns_fixture = r'''
typedef struct {uint16_t port;} microlink_t;
static microlink_t instance,*s_microlink;
static bool serving,running,locked,lock_busy,fail;
static unsigned starts,announcements;
static int64_t now;
static int64_t esp_timer_get_time(void){return now;}
static bool tailscale_exit_server_active(void){return serving;}
static bool peer_dns_is_running(void){return running;}
static bool tailscale_lifecycle_try_acquire(void){assert(!locked);return !lock_busy&&(locked=true);}
static void tailscale_lifecycle_release(void){assert(locked);locked=false;}
static void peer_dns_start(void){assert(locked&&!running);starts++;running=!fail;}
static uint16_t tailscale_peerapi_port(void){return 41181;}
static void microlink_set_peer_api_port(microlink_t *ml,uint16_t port){
    assert(locked&&running&&ml==&instance);ml->port=port;announcements++;
}
'''
peer_dns_tests = r'''
int main(void){
    s_microlink=&instance;tailscale_retry_peer_dns();assert(!starts);
    serving=true;s_microlink=NULL;tailscale_retry_peer_dns();assert(!starts&&!locked);
    s_microlink=&instance;lock_busy=true;tailscale_retry_peer_dns();assert(!starts&&!locked);
    lock_busy=false;fail=true;tailscale_retry_peer_dns();assert(starts==1&&!announcements&&!locked);
    now=29999999;fail=false;tailscale_retry_peer_dns();assert(starts==1&&!announcements);
    now++;tailscale_retry_peer_dns();assert(starts==2&&running&&announcements==1&&instance.port==41181&&!locked);
    now+=30000000;tailscale_retry_peer_dns();assert(starts==2&&announcements==1);
}
'''
run('Exit-node DNS listener retries without replacing the active tunnel', headers + peer_dns_fixture + peer_dns_retry + peer_dns_tests)
