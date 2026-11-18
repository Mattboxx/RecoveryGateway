"""Relay to peers homed on another DERP region (actual ml_derp.c).

A DERP relay delivers only to clients connected to it: a packet for a peer
homed on another region is dropped, and a disco packet is answered with
PeerGone "not here". The gateway kept one connection, to its home region, so
traffic it started toward such a peer (LAN to tailnet, exit node, wake-on-LAN)
with no direct path was lost until the peer itself reached out. Now the
peer is noted as away and its packets go over one auxiliary connection to its
home region, opened on demand and closed when idle, as the reference client
does. This drives the actual away table, routing decision, open/close and
maintenance, and the frame dispatch (PeerGone reasons, relay PING answered
through the writer queue) with stubbed sockets and TLS.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'external/microlink/components/microlink/src/ml_derp.c').read_text(encoding='utf-8').replace('\r\n', '\n')
HDR = (ROOT / 'external/microlink/components/microlink/include/microlink_internal.h').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(sig):
    start = SRC.index(sig)
    return SRC[start:SRC.index('\n}\n', start) + 3]


aux = SRC[SRC.index('#if ML_DERP_AUX\n\n#define DERP_AWAY_SLOTS'):SRC.index('#endif /* ML_DERP_AUX */')]
aux = aux[len('#if ML_DERP_AUX\n'):]
dispatch = function('static void dispatch_derp_frame(')
defines = SRC[SRC.index('#define DERP_FRAME_SERVER_KEY'):SRC.index('#if ML_DERP_AUX\nstatic void derp_away_note(')]

# Wiring that a unit test cannot run (tasks, sockets): checked on the source.
tx = function('void ml_derp_tx_task(void *arg) {')
assert 'c = derp_conn_for(ml, item.dest_pubkey);' in tx and 'ret = derp_send_packet(c, item.dest_pubkey, item.data, item.len);' in tx
assert tx.index('if (ret < 0 && c != &ml->derp) {') < tx.index('xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);\n                } else {')
assert 'derp_aux_maintain(ml, loop_start);' in tx
rx = function('void ml_derp_rx_task(void *arg) {')
assert 'conns[1] = &ml->derp_aux;' in rx and 'int ret = poll_derp_read(ml, c);' in rx
assert rx.index('c->rx_parked = false;') < rx.index('if (!c->connected || c->sockfd < 0) {')
assert 'if (!k) xEventGroupSetBits(ml->events, ML_EVT_DERP_RECONNECT);' in rx
assert 'derp_wait_readable_any(ml, DERP_RX_IDLE_WAIT_US)' in rx
op = SRC[SRC.index('unsigned region, bool home)\n{'):]
op = op[:op.index('\n}\n') + 3]
assert 'uint8_t preferred = home ? 0x01 : 0x00;' in op and 'if (home) xEventGroupSetBits(ml->events, ML_EVT_DERP_CONNECTED);' in op
assert "atoi((char *)resp_buf + 9) != 101" in op
disc = function('void ml_derp_disconnect(microlink_t *ml) {')
assert 'derp_conn_close(&ml->derp_aux);' in disc
assert '#if defined(CONFIG_ML_DERP_AUX) && CONFIG_ML_DERP_AUX' in HDR

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define TAG "t"
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ML_MAX_PEERS 20
#define ML_DERP_PORT 443
#define ML_DERP_STALE_MS 90000
#define pdMS_TO_TICKS(x) (x)
#define pdTRUE 1
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
static int crit;
#define taskENTER_CRITICAL(m) (assert(!crit), crit = 1, (void)(m))
#define taskEXIT_CRITICAL(m) (assert(crit), crit = 0, (void)(m))
static void vTaskDelay(int t){(void)t;}
static uint64_t fake_ms = 1000000;
static uint64_t ml_get_time_ms(void){return fake_ms;}
static void *ml_psram_malloc(size_t n){return malloc(n);}
typedef struct {int sockfd;bool connected;volatile bool rx_parked;uint64_t last_recv_ms;} ml_derp_conn_t;
typedef struct {char hostname[64];bool stun_only;uint16_t derp_port;} ml_derp_node_t;
typedef struct {uint16_t region_id;int node_count;ml_derp_node_t nodes[4];} ml_derp_region_t;
typedef struct {uint8_t public_key[32];uint16_t derp_region;} ml_peer_t;
typedef struct {uint8_t *data;size_t len;uint8_t frame_type;uint8_t dest_pubkey[32];} ml_derp_tx_item_t;
typedef struct {ml_derp_tx_item_t items[8];int n;int front;} queue_t;
typedef struct {
    ml_derp_conn_t derp, derp_aux;
    volatile uint16_t derp_aux_region; volatile uint32_t derp_aux_used_s; volatile uint32_t derp_aux_opens;
    ml_peer_t peers[ML_MAX_PEERS]; int peer_count;
    uint16_t derp_home_region; int derp_region_count; ml_derp_region_t derp_regions[4];
    queue_t *derp_tx_queue;
} microlink_t;
static int xQueueSendToFront(queue_t *q, ml_derp_tx_item_t *it, int w){(void)w;if(q->n>=8)return 0;q->items[q->n++]=*it;q->front++;return pdTRUE;}
/* Stubbed relay connections: record what was dialled and closed. */
static int opens, closes, open_fail;static char opened_host[64];static unsigned opened_region;static bool opened_home;
static esp_err_t derp_open(microlink_t *ml, ml_derp_conn_t *c, const char *host, int port, const ml_derp_node_t *n, unsigned region, bool home){
    (void)ml;(void)n;assert(port==443);assert(!c->connected);opens++;snprintf(opened_host,sizeof opened_host,"%s",host);opened_region=region;opened_home=home;
    if(open_fail)return ESP_FAIL;c->sockfd=9;c->connected=true;c->last_recv_ms=fake_ms;return ESP_OK;}
static void derp_conn_close(ml_derp_conn_t *c){assert(c->rx_parked);closes++;c->connected=false;c->sockfd=-1;}
static int routed;static uint8_t routed_from[32];
static void route_derp_packet(microlink_t *ml,uint8_t *d,size_t l,const uint8_t *src){(void)ml;(void)l;routed++;memcpy(routed_from,src,32);free(d);}
@@DEFINES@@
#define ML_DERP_AUX 1
@@AUX@@
@@DISPATCH@@
static void key(uint8_t *k,int id){memset(k,0,32);k[0]=(uint8_t)id;k[31]=0x5a;}
static void gone(microlink_t *ml,ml_derp_conn_t *c,int id,int reason){
    uint8_t *p=malloc(33);key(p,id);p[32]=(uint8_t)reason;dispatch_derp_frame(ml,c,0x08,(uint8_t[32]){0},p,reason<0?32:33);}
int main(void){
    static microlink_t ml;static queue_t q;memset(&ml,0,sizeof ml);ml.derp_tx_queue=&q;
    ml.derp.sockfd=5;ml.derp.connected=true;ml.derp_aux.sockfd=-1;ml.derp_aux.rx_parked=true;ml.derp_home_region=1;
    ml.derp_region_count=4;
    const char *hosts[4][2]={{"derp1a","derp1b"},{"derp2a","derp2b"},{"derp3a",""},{"derp4a","derp4b"}};
    for(int r=0;r<4;r++){ml.derp_regions[r].region_id=(uint16_t)(r+1);ml.derp_regions[r].node_count=2;
        for(int n=0;n<2;n++)snprintf(ml.derp_regions[r].nodes[n].hostname,64,"%s",hosts[r][n]);}
    ml.derp_regions[1].nodes[0].stun_only=false;
    /* peers: 1 home region 1, 2 region 2, 3 region 3, 4 region 4, 5 unknown region */
    int regions[6]={0,1,2,3,4,0};
    for(int i=1;i<=5;i++){key(ml.peers[i-1].public_key,i);ml.peers[i-1].derp_region=(uint16_t)regions[i];}
    ml.peer_count=5;
    uint8_t k1[32],k2[32],k3[32],k4[32],k5[32],k9[32];key(k1,1);key(k2,2);key(k3,3);key(k4,4);key(k5,5);key(k9,9);

    /* Nothing reported: every packet takes the home relay, no table work. */
    assert(derp_conn_for(&ml,k2)==&ml.derp&&opens==0&&!s_away_any);

    /* "Disconnected" and aux-relay reports do not route anywhere else. */
    gone(&ml,&ml.derp,2,0);gone(&ml,&ml.derp,2,-1);assert(!s_away_any);
    gone(&ml,&ml.derp_aux,2,1);assert(!s_away_any);

    /* Home relay: peer 2 not here -> its home region (2) over the auxiliary relay. */
    gone(&ml,&ml.derp,2,1);assert(s_away_any);
    ml_derp_conn_t *c=derp_conn_for(&ml,k2);
    assert(c==&ml.derp_aux&&opens==1&&!strcmp(opened_host,"derp2a")&&opened_region==2&&!opened_home);
    assert(ml.derp_aux_region==2&&ml.derp_aux_opens==1);
    fake_ms+=500;assert(derp_conn_for(&ml,k2)==&ml.derp_aux&&opens==1);          /* reused */
    assert(derp_conn_for(&ml,k1)==&ml.derp);                                    /* peer on our region */
    gone(&ml,&ml.derp,1,1);assert(derp_conn_for(&ml,k1)==&ml.derp);             /* away but homed with us */
    gone(&ml,&ml.derp,5,1);assert(derp_conn_for(&ml,k5)==&ml.derp);             /* region unknown */
    assert(derp_conn_for(&ml,k9)==&ml.derp);                                    /* not in the peer table */

    /* Another region while the relay is busy: no thrashing, old path. */
    gone(&ml,&ml.derp,3,1);fake_ms+=2000;
    assert(derp_conn_for(&ml,k3)==&ml.derp&&opens==1&&ml.derp_aux_region==2);
    /* Idle 10 s: it moves to region 3 (old session closed after the reader parked). */
    fake_ms+=11000;ml.derp_aux.rx_parked=true;
    assert(derp_conn_for(&ml,k3)==&ml.derp_aux&&closes==1&&opens==2&&opened_region==3&&ml.derp_aux_region==3);

    /* Receiving on the auxiliary relay keeps it in use; on the home relay it does not. */
    uint32_t before=ml.derp_aux_used_s;fake_ms+=5000;
    uint8_t *pk=malloc(40);memset(pk,1,40);dispatch_derp_frame(&ml,&ml.derp,0x05,k1,pk,40);
    assert(ml.derp_aux_used_s==before&&routed==1&&!memcmp(routed_from,k1,32));
    pk=malloc(40);dispatch_derp_frame(&ml,&ml.derp_aux,0x05,k3,pk,40);
    assert(ml.derp_aux_used_s==(uint32_t)(fake_ms/1000)&&routed==2);

    /* Maintenance: busy -> kept; idle 60 s -> closed. */
    derp_aux_maintain(&ml,fake_ms);assert(closes==1&&ml.derp_aux.connected);
    fake_ms+=61000;derp_aux_maintain(&ml,fake_ms);assert(closes==2&&ml.derp_aux.sockfd<0&&ml.derp_aux_region==0);
    derp_aux_maintain(&ml,fake_ms);assert(closes==2);                           /* nothing open */
    /* Broken by the reader / silent / became home: closed. */
    assert(derp_conn_for(&ml,k3)==&ml.derp_aux&&opens==3);
    ml.derp_aux.connected=false;derp_aux_maintain(&ml,fake_ms);assert(closes==3);
    assert(derp_conn_for(&ml,k3)==&ml.derp_aux&&opens==4);
    ml.derp_aux.last_recv_ms=fake_ms-91000;derp_aux_maintain(&ml,fake_ms);assert(closes==4);
    assert(derp_conn_for(&ml,k3)==&ml.derp_aux&&opens==5);
    ml.derp_home_region=3;derp_aux_maintain(&ml,fake_ms);assert(closes==5);
    assert(derp_conn_for(&ml,k3)==&ml.derp&&opens==5);                          /* now our own region */
    ml.derp_home_region=1;
    /* A broken session found by the writer is replaced at once. */
    assert(derp_conn_for(&ml,k3)==&ml.derp_aux&&opens==6);
    ml.derp_aux.connected=false;assert(derp_conn_for(&ml,k3)==&ml.derp_aux&&closes==6&&opens==7);

    /* Failed connect: old path, no retry for 30 s, then the next node. */
    gone(&ml,&ml.derp,4,1);fake_ms+=61000;derp_aux_maintain(&ml,fake_ms);int cl=closes;
    open_fail=1;assert(derp_conn_for(&ml,k4)==&ml.derp&&opens==8&&!strcmp(opened_host,"derp4a"));
    assert(ml.derp_aux.sockfd<0&&closes==cl);
    fake_ms+=10000;assert(derp_conn_for(&ml,k4)==&ml.derp&&opens==8);          /* backing off */
    fake_ms+=21000;assert(derp_conn_for(&ml,k4)==&ml.derp&&opens==9&&!strcmp(opened_host,"derp4b"));
    open_fail=0;fake_ms+=31000;assert(derp_conn_for(&ml,k4)==&ml.derp_aux&&opens==10&&!strcmp(opened_host,"derp4a"));

    /* Away notes expire: after 5 min the home relay is tried again. */
    fake_ms+=301000;assert(derp_conn_for(&ml,k4)==&ml.derp);
    /* The table is bounded: 12 reports keep the 8 newest. */
    for(int i=20;i<32;i++){uint8_t kk[32];key(kk,i);fake_ms+=1;derp_away_note(kk,fake_ms);}
    int live=0;for(int i=0;i<DERP_AWAY_SLOTS;i++)live+=s_away[i].until_ms>fake_ms;assert(live==8);
    uint8_t old[32],newest[32];key(old,20);key(newest,31);assert(!derp_away(old,fake_ms)&&derp_away(newest,fake_ms));

    /* Relay PING: answered through the writer queue (front), home relay only, bounded. */
    uint8_t *ping=malloc(8);memcpy(ping,"12345678",8);dispatch_derp_frame(&ml,&ml.derp,0x12,k1,ping,8);
    assert(q.n==1&&q.items[0].frame_type==0x13&&q.items[0].len==8&&!memcmp(q.items[0].data,"12345678",8));
    ping=malloc(8);dispatch_derp_frame(&ml,&ml.derp_aux,0x12,k1,ping,8);assert(q.n==1);
    ping=malloc(65);memset(ping,0,65);dispatch_derp_frame(&ml,&ml.derp,0x12,k1,ping,65);assert(q.n==1);
    free(q.items[0].data);

    /* The pure decision. */
    assert(derp_route_pick(0,1,false,0,0,0,0)==DERP_ROUTE_HOME);
    assert(derp_route_pick(1,1,false,0,0,0,0)==DERP_ROUTE_HOME);
    assert(derp_route_pick(2,1,false,0,UINT64_MAX,0,UINT64_MAX)==DERP_ROUTE_OPEN);
    assert(derp_route_pick(2,1,true,2,0,0,0)==DERP_ROUTE_AUX);
    assert(derp_route_pick(2,1,true,3,9999,0,0)==DERP_ROUTE_HOME);
    assert(derp_route_pick(2,1,true,3,10000,0,0)==DERP_ROUTE_OPEN);
    assert(derp_route_pick(2,1,false,0,0,2,29999)==DERP_ROUTE_HOME);
    assert(derp_route_pick(2,1,false,0,0,2,30000)==DERP_ROUTE_OPEN);
    assert(derp_route_pick(2,1,false,0,0,3,0)==DERP_ROUTE_OPEN);
    assert(!crit);
    puts("PASS: actual relay routing: peers the home relay does not know reach their own region over one on-demand connection; bounded, no thrash, backoff, idle close");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='derp-aux-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@DEFINES@@', defines).replace('@@AUX@@', aux).replace('@@DISPATCH@@', dispatch),
                 encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-misleading-indentation']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('derp aux: cross-region peers reachable through their home relay')
