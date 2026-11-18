"""lwIP raw API calls of MicroLink's UDP helpers on the TCPIP thread (actual
ml_udp.c and ml_zerocopy.c).

This lwIP runs without core locking: raw API calls (udp_new, udp_bind,
udp_recv, udp_remove, udp_sendto) are safe only on the TCPIP thread.
microlink_udp_create/close/send called them from the caller's task; they now
go through a synchronous tcpip_api_call(). Checked with stubs that fail any
raw call made outside the (simulated) TCPIP thread:
- create binds on the WG netif, VPN IP and port, registers the receive
  callback, and frees everything when the bind or the call fails;
- close removes the callback and PCB before the RX task is stopped;
- send queues the datagram on the TCPIP thread and frees the pbuf;
- zero-copy send takes a TX slot only when its callback was queued (a
  failed tcpip_callback used to leak the slot until the pool ran dry), and
  shutdown never waits for a callback that was not queued.
Host stubs only: no lwIP, task timing or device behavior is claimed.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
UDP = (ML / 'src/ml_udp.c').read_text(encoding='utf-8').replace('\r\n', '\n')
ZC = (ML / 'src/ml_zerocopy.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(src, sig):
    start = src.index(sig)
    return src[start:src.index('\n}\n', start) + 3]


sock_type = UDP[UDP.index('typedef struct {\n    uint32_t src_ip;'):UDP.index('};\n', UDP.index('struct microlink_udp_socket {')) + 3]
calls = UDP[UDP.index('/* lwIP raw API calls run on the TCPIP thread'):UDP.index('microlink_udp_socket_t *microlink_udp_create(')]
api = (function(UDP, 'static void ip_to_lwip(') + calls + function(UDP, 'microlink_udp_socket_t *microlink_udp_create(')
       + function(UDP, 'void microlink_udp_close(') + function(UDP, 'esp_err_t microlink_udp_send('))
for raw in ('udp_new()', 'udp_bind(', 'udp_remove(', 'udp_sendto('):
    outside = api.replace(calls, '')
    assert raw not in outside, raw + ' called outside the TCPIP thread'
zc_ctx = ZC[ZC.index('typedef struct {\n    microlink_t *ml;'):ZC.index('} zc_setup_ctx_t;\n') + len('} zc_setup_ctx_t;\n')]
zc = zc_ctx + function(ZC, 'esp_err_t ml_zerocopy_send(') + function(ZC, 'void ml_zerocopy_deinit(')

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t; typedef int err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_TIMEOUT 0x107
#define ERR_OK 0
#define ERR_MEM -1
#define ERR_USE -8
#define ERR_CLSD -15
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define TAG "t"
#define pdMS_TO_TICKS(x) (x)
#define pdPASS 1
#define portTICK_PERIOD_MS 1
#define configMAX_PRIORITIES 25
#define UDP_RX_QUEUE_SIZE 4
#define UDP_MAX_PKT_SIZE 1400
#define ML_STATE_CONNECTED 3
#define ML_MAX_PACKET_SIZE 1500
#define ML_ZC_TX_POOL_SIZE 24
#define IPADDR_TYPE_V4 0
#define portMAX_DELAY 0xffffffffu
typedef void *SemaphoreHandle_t; typedef void *TaskHandle_t;
struct netif { int id; };
typedef struct { uint32_t addr; } ip4_addr_t;
typedef struct { union { ip4_addr_t ip4; } u_addr; int type; } ip_addr_t;
#define IP4_ADDR(a,b,c,d,e) ((a)->addr = ((uint32_t)(b)<<24)|((uint32_t)(c)<<16)|((uint32_t)(d)<<8)|(uint32_t)(e))
#define IP_SET_TYPE_VAL(ip, t) ((ip).type = (t))
#define ip_2_ip4(ip) (&(ip)->u_addr.ip4)
#define ip4_addr_set_u32(a, v) ((a)->addr = (v))
static uint32_t htonl(uint32_t v){return v;}
struct pbuf { void *payload; size_t len; };
struct udp_pcb { uint16_t local_port; void *recv_arg; void (*recv)(void); };
typedef struct { int active; uint32_t vpn_ip; } ml_peer_t;
typedef struct { struct udp_pcb *pcb; uint8_t data[ML_MAX_PACKET_SIZE]; size_t len; ip_addr_t dest; uint16_t port; } ml_zc_tx_ctx_t;
typedef struct {
    int state; void *wg_netif; uint32_t vpn_ip; int peer_count; ml_peer_t peers[2];
    struct { struct udp_pcb *pcb; ml_zc_tx_ctx_t tx_pool[ML_ZC_TX_POOL_SIZE]; volatile uint8_t tx_head, tx_tail; uint16_t local_port; } zc;
} microlink_t;
typedef struct microlink_udp_socket microlink_udp_socket_t;
typedef void (*microlink_udp_rx_cb_t)(microlink_udp_socket_t *, uint32_t, uint16_t, const uint8_t *, size_t, void *);
/* The TCPIP thread, simulated: raw calls must happen inside it. */
static int in_tcpip, api_calls, api_fail, raw_calls;
struct tcpip_api_call_data { int unused; };
typedef err_t (*tcpip_api_call_fn)(struct tcpip_api_call_data *);
static err_t tcpip_api_call(tcpip_api_call_fn fn, struct tcpip_api_call_data *c){
    api_calls++; if (api_fail) return ERR_MEM; in_tcpip = 1; err_t e = fn(c); in_tcpip = 0; return e; }
#define RAW() (assert(in_tcpip), raw_calls++)
static struct udp_pcb pcbs[4]; static int pcb_n, bind_fail, removed, sent, sendto_rc;
static struct netif *bound_netif; static uint32_t bound_ip; static uint16_t bound_port; static void *recv_arg; static int recv_set;
static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *a, uint16_t port){(void)arg;(void)pcb;(void)p;(void)a;(void)port;}
typedef void (*udp_recv_fn)(void *, struct udp_pcb *, struct pbuf *, const ip_addr_t *, uint16_t);
static struct udp_pcb *udp_new(void){RAW();struct udp_pcb *p=&pcbs[pcb_n++];memset(p,0,sizeof *p);return p;}
static void udp_bind_netif(struct udp_pcb *p, struct netif *n){RAW();(void)p;bound_netif=n;}
static err_t udp_bind(struct udp_pcb *p, const ip_addr_t *ip, uint16_t port){RAW();if(bind_fail)return ERR_USE;
    bound_ip=ip->u_addr.ip4.addr;bound_port=port;p->local_port=port?port:49152;return ERR_OK;}
static void udp_recv(struct udp_pcb *p, udp_recv_fn fn, void *arg){RAW();(void)p;recv_set=fn!=NULL;recv_arg=arg;}
static void udp_remove(struct udp_pcb *p){RAW();(void)p;removed++;}
static err_t udp_sendto(struct udp_pcb *p, struct pbuf *b, const ip_addr_t *ip, uint16_t port){RAW();(void)p;
    assert(b->len==5&&!memcmp(b->payload,"hello",5)&&ip->u_addr.ip4.addr==0x64400002u&&port==9000);sent++;return sendto_rc;}
static int pbufs;
static struct pbuf *pbuf_alloc(int layer, size_t len, int type){(void)layer;(void)type;struct pbuf *p=malloc(sizeof *p);p->payload=malloc(len);p->len=len;pbufs++;return p;}
static void pbuf_free(struct pbuf *p){free(p->payload);free(p);pbufs--;}
#define PBUF_TRANSPORT 0
#define PBUF_RAM 0
static int sems;
static SemaphoreHandle_t xSemaphoreCreateCounting(int a,int b){(void)a;(void)b;sems++;return &sems;}
static SemaphoreHandle_t xSemaphoreCreateBinary(void){sems++;return &sems;}
static void vSemaphoreDelete(SemaphoreHandle_t s){(void)s;sems--;}
static int gives, takes;
static int xSemaphoreGive(SemaphoreHandle_t s){(void)s;gives++;return 1;}
static int xSemaphoreTake(SemaphoreHandle_t s, uint32_t t){(void)s;(void)t;takes++;return 1;}
static void udp_rx_task(void *a){(void)a;}
static int xTaskCreatePinnedToCore(void (*f)(void *), const char *n, int st, void *a, int pr, TaskHandle_t *h, int core){
    (void)f;(void)n;(void)st;(void)a;(void)pr;(void)core;*h=NULL;return 0;}
static void vTaskDelay(int t){(void)t;}
static uint32_t xTaskGetTickCount(void){return 100000;}
static int cmm, handshakes;
static void ml_wg_mgr_send_cmm(microlink_t *ml, uint32_t ip){(void)ml;(void)ip;cmm++;}
static void ml_wg_mgr_trigger_handshake(microlink_t *ml, uint32_t ip){(void)ml;(void)ip;handshakes++;}
static void microlink_ip_to_str(uint32_t ip, char *b){snprintf(b,16,"%u",(unsigned)ip);}
@@SOCK@@
@@API@@
/* zero-copy */
static int cb_fail, cb_queued;
static void zc_send_in_tcpip(void *arg){(void)arg;}
static void zc_pcb_remove_in_tcpip(void *arg){(void)arg;}
static err_t tcpip_callback(void (*fn)(void *), void *ctx){(void)fn;(void)ctx;if(cb_fail)return ERR_MEM;cb_queued++;return ERR_OK;}
@@ZC@@
int main(void){
    static microlink_t ml; struct netif wg={1};
    ml.state=ML_STATE_CONNECTED;ml.wg_netif=&wg;ml.vpn_ip=0x64400001u;
    /* create: everything on the TCPIP thread, bound to WG netif + VPN IP + port */
    microlink_udp_socket_t *s=microlink_udp_create(&ml,9000);
    assert(s&&s->pcb==&pcbs[0]&&bound_netif==&wg&&bound_ip==0x64400001u&&bound_port==9000&&recv_set&&recv_arg==s);
    assert(s->local_port==9000&&api_calls==1&&raw_calls==4);
    /* send: queued on the TCPIP thread, pbuf freed */
    assert(microlink_udp_send(s,0x64400002u,9000,"hello",5)==ESP_OK&&sent==1&&pbufs==0&&api_calls==2);
    sendto_rc=ERR_MEM;assert(microlink_udp_send(s,0x64400002u,9000,"hello",5)==ESP_FAIL&&pbufs==0&&handshakes==1);sendto_rc=ERR_OK;
    assert(microlink_udp_send(s,0x64400002u,9000,"x",0)==ESP_ERR_INVALID_ARG&&api_calls==3);
    /* close: callback and PCB gone on the TCPIP thread, then the rest */
    microlink_udp_close(s);assert(!recv_set&&removed==1&&api_calls==4&&sems==0);
    /* a failed bind or an unreachable TCPIP thread leaves nothing behind */
    bind_fail=1;assert(!microlink_udp_create(&ml,9000)&&removed==2&&sems==0);bind_fail=0;
    api_fail=1;assert(!microlink_udp_create(&ml,9000)&&sems==0);api_fail=0;
    ml.state=0;assert(!microlink_udp_create(&ml,9000));ml.state=ML_STATE_CONNECTED;
    puts("PASS: actual UDP helpers: create/send/close make every lwIP raw call on the TCPIP thread; failures free everything");

    /* zero-copy: a send that could not be queued keeps no slot */
    struct udp_pcb zpcb={0};ml.zc.pcb=&zpcb;uint8_t pkt[64]={1};
    cb_fail=1;
    for(int i=0;i<100;i++)assert(ml_zerocopy_send(&ml,pkt,sizeof pkt,0x01020304u,41641)==ESP_ERR_NO_MEM);
    assert(ml.zc.tx_head==0&&cb_queued==0);
    cb_fail=0;
    for(int i=0;i<ML_ZC_TX_POOL_SIZE-1;i++)assert(ml_zerocopy_send(&ml,pkt,sizeof pkt,0x01020304u,41641)==ESP_OK);
    assert(ml_zerocopy_send(&ml,pkt,sizeof pkt,0x01020304u,41641)==ESP_ERR_NO_MEM&&cb_queued==ML_ZC_TX_POOL_SIZE-1);  /* full: consumer has not run */
    assert(ml.zc.tx_pool[0].port==41641&&ml.zc.tx_pool[0].len==64&&ml.zc.tx_pool[0].pcb==&zpcb);
    ml.zc.tx_tail=5;assert(ml_zerocopy_send(&ml,pkt,sizeof pkt,0x01020304u,41641)==ESP_OK);   /* consumer freed slots */
    assert(ml_zerocopy_send(&ml,pkt,ML_MAX_PACKET_SIZE+1,1,1)==ESP_ERR_INVALID_ARG);
    /* shutdown: never waits for a callback that was not queued */
    takes=0;cb_fail=1;ml_zerocopy_deinit(&ml);assert(takes==0&&sems==0);
    cb_fail=0;ml_zerocopy_deinit(&ml);assert(takes==1&&sems==0);
    puts("PASS: actual zero-copy send/shutdown: a failed TCPIP callback keeps no TX slot, the pool cannot run dry, shutdown cannot hang");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='ml-udp-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@SOCK@@', sock_type).replace('@@API@@', api).replace('@@ZC@@', zc), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('MicroLink UDP helpers: lwIP raw calls on the TCPIP thread')
