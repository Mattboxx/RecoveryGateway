"""WireGuard sends on the TCPIP thread and kept direct endpoints (actual
ml_wg_mgr.c; port of upstream MicroLink 0.1.39).

1. This build runs lwIP without core locking, so a raw-API udp_sendto is only
   safe on the TCPIP thread. The wg_mgr task sent handshakes, handshake
   responses, cookies and the keepalive after a handshake itself, racing the
   TCPIP thread on the ARP table (an upstream router rebooted in
   free_etharp_q). wg_udp_sendto_tcpip() sends directly on the TCPIP thread
   and otherwise posts a private copy there; failures free everything.
2. A direct endpoint kept because direct data was still flowing is re-checked
   on every tick: once no direct packet has arrived for 30 s and a session is
   up, the peer goes back to the relay (before, has_direct_path was false and
   the check never ran again, so a quiet peer kept a dead endpoint).
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'external/microlink/components/microlink/src/ml_wg_mgr.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(sig):
    start = SRC.index(sig)
    return SRC[start:SRC.index('\n}\n', start) + 3]


send = 'struct wg_udp_send_msg { struct pbuf *p; ip_addr_t dst; u16_t port; };\n' + function('static void wg_udp_send_on_tcpip_cb(void *arg)') + function('static err_t wg_udp_sendto_tcpip(')
assert SRC.count('wg_udp_sendto_tcpip(p, &dst, dest_port)') == 2
assert 'struct wg_udp_send_msg { struct pbuf *p; ip_addr_t dst; u16_t port; };' in SRC
assert 's_tcpip_task = xTaskGetCurrentTaskHandle();' in function('static esp_err_t wg_tcpip_exec_wrap(void *ctx)')

# The kept-endpoint block of disco_periodic_probes, run as a function.
a = SRC.index('        struct wireguard_peer *kwp = NULL;')
b = SRC.index('        if (trust_expired || kept_endpoint) {', a)
depth, k = 0, SRC.index('{', b)
while True:
    if SRC[k] == '{':
        depth += 1
    elif SRC[k] == '}':
        depth -= 1
        if depth == 0:
            break
    k += 1
block = SRC[a:k + 1]

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int err_t;typedef unsigned short u16_t;typedef unsigned char u8_t;
#define ERR_OK 0
#define ERR_MEM -1
#define ERR_CONN -11
#define TAG "t"
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ML_DISCO_TRUST_DURATION_MS 60000
#define WIREGUARD_MAX_PEERS 20
typedef void *TaskHandle_t;
typedef struct { uint32_t addr; } ip_addr_t;
#define ip_addr_isany(a) ((a)->addr == 0)
struct pbuf { void *payload; u16_t tot_len; int ref; };
struct udp_pcb { int x; };
static struct udp_pcb pcb_storage;
static TaskHandle_t current, tcpip = (TaskHandle_t)0x7c;
static TaskHandle_t xTaskGetCurrentTaskHandle(void){return current;}
/* udp_sendto records the thread and the bytes it was given */
static int sends; static TaskHandle_t send_thread; static char sent[64];
static err_t udp_sendto(struct udp_pcb *pcb,struct pbuf *p,const ip_addr_t *dst,u16_t port){
    (void)pcb;(void)dst;(void)port;assert(p->ref==1);sends++;send_thread=current;memcpy(sent,p->payload,p->tot_len);return ERR_OK;}
static int live_pbufs,alloc_fail,post_fail;
static struct pbuf *ml_spiram_pbuf_new(u16_t len){if(alloc_fail)return NULL;struct pbuf *p=malloc(sizeof *p);p->payload=malloc(len);p->tot_len=len;p->ref=1;live_pbufs++;return p;}
static void pbuf_free(struct pbuf *p){free(p->payload);free(p);live_pbufs--;}
static void pbuf_copy_partial(struct pbuf *p,void *d,u16_t n,u16_t o){memcpy(d,(char*)p->payload+o,n);}
static void (*queued_fn)(void*);static void *queued_arg;
static err_t tcpip_callback(void (*fn)(void*),void *arg){if(post_fail)return ERR_MEM;queued_fn=fn;queued_arg=arg;return ERR_OK;}
static TaskHandle_t s_tcpip_task;
static struct udp_pcb *s_wg_output_pcb=&pcb_storage;
@@SEND@@
/* kept-endpoint block */
struct wireguard_peer { ip_addr_t ip; u16_t port; uint32_t last_direct_rx, last_rx; };
struct wireguard_device { struct wireguard_peer peers[WIREGUARD_MAX_PEERS]; };
struct netif { void *state; };
typedef struct { bool has_direct_path; uint64_t trust_until_ms; int wg_peer_index; char hostname[16]; } ml_peer_t;
typedef struct { void *wg_netif; } microlink_t;
static uint32_t wg_now; static uint32_t wireguard_sys_now(void){return wg_now;}
static int session, reverts, pings;
static err_t wireguardif_peer_is_up(struct netif *n,u8_t i,void *a,void *b){(void)n;(void)i;(void)a;(void)b;return session?ERR_OK:ERR_CONN;}
static void wireguardif_connect_derp(struct netif *n,u8_t i){struct wireguard_device *d=n->state;d->peers[i].ip.addr=0;d->peers[i].port=0;reverts++;}
static bool ml_at_socket_is_ready(void){return false;}
static void disco_send_ping_to_peer(microlink_t *ml,int i,bool f){(void)ml;(void)i;(void)f;pings++;}
static void tick(microlink_t *ml, ml_peer_t *p, uint64_t now, bool peer_allowed){
    int i=0;
@@BLOCK@@
}
int main(void){
    /* 1. on the TCPIP thread: sent directly, caller keeps its pbuf */
    struct pbuf *p=ml_spiram_pbuf_new(5);memcpy(p->payload,"hello",5);ip_addr_t dst={1};
    s_tcpip_task=tcpip;current=tcpip;assert(wg_udp_sendto_tcpip(p,&dst,41641)==ERR_OK&&sends==1&&send_thread==tcpip&&!queued_fn);
    /* not learned yet (before the netif came up): direct, as before */
    s_tcpip_task=NULL;current=(TaskHandle_t)0x55;assert(wg_udp_sendto_tcpip(p,&dst,41641)==ERR_OK&&sends==2);
    /* wg_mgr task: nothing sent here; a private copy is posted to TCPIP */
    s_tcpip_task=tcpip;current=(TaskHandle_t)0x55;
    assert(wg_udp_sendto_tcpip(p,&dst,41641)==ERR_OK&&sends==2&&queued_fn&&live_pbufs==2);
    memcpy(p->payload,"XXXXX",5);                       /* the caller reuses/frees its buffer */
    current=tcpip;queued_fn(queued_arg);queued_fn=NULL;
    assert(sends==3&&send_thread==tcpip&&!memcmp(sent,"hello",5)&&live_pbufs==1);
    /* post refused / no memory: error, nothing leaked */
    current=(TaskHandle_t)0x55;post_fail=1;assert(wg_udp_sendto_tcpip(p,&dst,41641)!=ERR_OK&&live_pbufs==1);post_fail=0;
    alloc_fail=1;assert(wg_udp_sendto_tcpip(p,&dst,41641)==ERR_MEM&&live_pbufs==1);alloc_fail=0;
    pbuf_free(p);assert(live_pbufs==0);

    /* 2. kept endpoint */
    static struct wireguard_device dev;struct netif nif={&dev};microlink_t ml={&nif};
    ml_peer_t peer={.has_direct_path=true,.trust_until_ms=1000,.wg_peer_index=3,.hostname="nas"};
    struct wireguard_peer *wp=&dev.peers[3];wp->ip.addr=0x0a000002;wp->port=41641;session=1;
    wg_now=100000;wp->last_direct_rx=wg_now-5000;          /* direct data 5 s ago */
    tick(&ml,&peer,2000,true);                               /* trust expired, data flowing: kept, one ping */
    assert(!peer.has_direct_path&&wp->port==41641&&pings==1&&reverts==0);
    wg_now+=20000;tick(&ml,&peer,3000,true);                 /* kept, still < 30 s: nothing */
    assert(wp->port==41641&&pings==1&&reverts==0);
    wg_now+=10000;tick(&ml,&peer,4000,true);                 /* 35 s without direct data: back to relay */
    assert(reverts==1&&wp->port==0&&pings==1);
    tick(&ml,&peer,5000,true);assert(reverts==1);            /* nothing kept any more */
    /* a kept endpoint without a session is left to the relay fallback (no ping storm) */
    wp->ip.addr=0x0a000002;wp->port=41641;session=0;wg_now+=60000;
    tick(&ml,&peer,6000,true);assert(reverts==1&&pings==1);
    /* not allowed peers: untouched */
    session=1;tick(&ml,&peer,7000,false);assert(reverts==1);
    puts("PASS: actual WireGuard sends reach lwIP only on the TCPIP thread (copy posted otherwise, no leaks); kept direct endpoints are re-checked and dropped after 30 s without direct traffic");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wg-tcpip-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@SEND@@', send).replace('@@BLOCK@@', block), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('wg tcpip send: upstream 0.1.39 fixes on the actual code')
