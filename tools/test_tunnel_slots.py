"""Tailnets larger than the WireGuard slot table (actual MicroLink code).

3.0.24 refused a whole map above 16 peers (policy and mailbox tables) and,
below that, gave tunnel slots in map order: a tailnet of 18 devices, most of
them stale, blocked every tunnel. Now the map, policy and mailbox are sized
by the tailnet and the slots go to the peers that need them.

Compiles the real peer_activity_ms()/tunnel_slot_to_give() from ml_wg_mgr.c:
- slots in use (recent traffic) are never given away, nor the priority peer;
- an offline peer (by the map) gives its slot before an idle one, the
  longest-quiet first; idle means quiet for ML_WG_IDLE_EVICT_MS exactly;
- an offline newcomer takes no slot.
Compiles the real mailbox (ml_peer_sync.c): 600 peers recorded (grown past
the old 16), every entry readable through ml_peer_sync_entry(), latest
metadata kept, allocation failure refused without losing the table.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
MANAGER = (ML / 'src/ml_wg_mgr.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(signature):
    start = MANAGER.index(signature)
    return MANAGER[start:MANAGER.index('\n}\n', start) + 3]


idle = MANAGER[MANAGER.index('#define ML_WG_IDLE_EVICT_MS'):].split('\n', 1)[0] + '\n'
SLOTS = idle + function('static uint64_t peer_activity_ms(') + function('static int tunnel_slot_to_give(')

SLOT_TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ML_MAX_PEERS 16
typedef struct {bool has_online,online;char hostname[8];} ml_peer_update_t;
typedef struct {bool active,online;uint32_t vpn_ip;uint64_t peer_added_ms,last_send_ms,last_pong_recv_ms,last_init_handshake_ms;} ml_peer_t;
typedef struct {ml_peer_t peers[ML_MAX_PEERS];struct {uint32_t priority_peer_ip;} config;} microlink_t;
static uint64_t now_ms;
static uint64_t ml_get_time_ms(void){return now_ms;}
@@SLOTS@@
int main(void){
    microlink_t ml;memset(&ml,0,sizeof ml);
    ml_peer_update_t online={.has_online=true,.online=true},offline={.has_online=true,.online=false},unknown={0};
    now_ms=1000000;
    for(int i=0;i<ML_MAX_PEERS;i++){ml.peers[i].active=true;ml.peers[i].online=true;ml.peers[i].vpn_ip=100+i;ml.peers[i].peer_added_ms=now_ms-1000;}
    assert(tunnel_slot_to_give(&ml,&online)==-1);                 /* all in use */
    /* Idle exactly at the threshold; any recent activity source keeps it. */
    ml.peers[3].peer_added_ms=now_ms-ML_WG_IDLE_EVICT_MS+1;assert(tunnel_slot_to_give(&ml,&online)==-1);
    ml.peers[3].peer_added_ms=now_ms-ML_WG_IDLE_EVICT_MS;assert(tunnel_slot_to_give(&ml,&online)==3);
    ml.peers[3].last_send_ms=now_ms-5;assert(tunnel_slot_to_give(&ml,&online)==-1);
    ml.peers[3].last_send_ms=0;ml.peers[3].last_pong_recv_ms=now_ms-5;assert(tunnel_slot_to_give(&ml,&online)==-1);
    ml.peers[3].last_pong_recv_ms=0;ml.peers[3].last_init_handshake_ms=now_ms-5;assert(tunnel_slot_to_give(&ml,&online)==-1);
    ml.peers[3].last_init_handshake_ms=0;
    /* Offline before idle, and among offline the longest quiet. */
    ml.peers[9].online=false;ml.peers[9].peer_added_ms=now_ms-2000;
    ml.peers[12].online=false;ml.peers[12].peer_added_ms=now_ms-9000;
    assert(tunnel_slot_to_give(&ml,&online)==12);
    assert(tunnel_slot_to_give(&ml,&unknown)==12);                /* no Online field: treated as needed */
    /* An offline newcomer takes nothing. */
    assert(tunnel_slot_to_give(&ml,&offline)==-1);
    /* The priority peer never gives its slot. */
    ml.config.priority_peer_ip=ml.peers[12].vpn_ip;assert(tunnel_slot_to_give(&ml,&online)==9);
    ml.peers[9].online=true;ml.peers[9].peer_added_ms=now_ms;assert(tunnel_slot_to_give(&ml,&online)==3);
    /* Inactive slots are not candidates (they are free slots, handled before). */
    ml.peers[3].active=false;assert(tunnel_slot_to_give(&ml,&online)==-1);
    puts("PASS: actual tunnel slot choice: in-use and priority peers kept, offline before idle, longest quiet first, offline newcomer waits");
    return 0;
}
'''

SYNC_TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ML_PEER_SYNC_HOST_TEST 1
typedef struct {
    enum {ML_PEER_ADD,ML_PEER_REMOVE,ML_PEER_UPDATE_ENDPOINT} action;
    uint8_t public_key[32];uint64_t node_id;bool has_node_id,has_online,online,has_endpoints,has_derp_region;
    int endpoint_count;struct {uint32_t ip;uint16_t port;bool is_ipv6;} endpoints[8];uint16_t derp_region;
} ml_peer_update_t;
static bool fail_alloc;
void *peer_sync_test_alloc(size_t n){return fail_alloc?NULL:malloc(n);}
/* Policy authority stub: every peer authorized with key = its ID. */
static void key_of(uint64_t id,uint8_t key[32]){memset(key,0,32);memcpy(key,&id,sizeof id);key[31]=1;}
int ml_policy_peer_key(uint64_t id,uint8_t key[32]){key_of(id,key);return 1;}
int ml_policy_peer_status(const uint8_t key[32]){(void)key;return 1;}
#include "ml_peer_sync.c"
int main(void){
    ml_peer_update_t u;
    for(uint64_t id=1;id<=600;id++){
        memset(&u,0,sizeof u);u.action=ML_PEER_ADD;u.has_node_id=true;u.node_id=id;key_of(id,u.public_key);
        u.has_online=true;u.online=id%3!=0;
        assert(ml_peer_sync_record(&u));
    }
    assert(sync_cap>=600);
    unsigned used_n=0,online_n=0;bool used;
    for(int i=0;ml_peer_sync_entry(i,&u,&used);i++)if(used){used_n++;online_n+=u.online;}
    assert(used_n==600&&online_n==400);
    /* Latest metadata wins for a peer beyond the old 16 entries. */
    memset(&u,0,sizeof u);u.action=ML_PEER_UPDATE_ENDPOINT;u.has_node_id=true;u.node_id=577;u.has_online=true;u.online=true;
    assert(ml_peer_sync_record(&u));
    ml_peer_update_t r={.action=ML_PEER_ADD,.has_node_id=true,.node_id=577};
    assert(ml_peer_sync_resolve(&r)&&r.online&&r.action==ML_PEER_ADD);
    /* Growth failure: refused, existing entries intact. */
    int cap=sync_cap;fail_alloc=true;
    for(uint64_t id=601;id<=(uint64_t)cap+1;id++){
        memset(&u,0,sizeof u);u.action=ML_PEER_ADD;u.has_node_id=true;u.node_id=id;key_of(id,u.public_key);
        bool ok=ml_peer_sync_record(&u);if(!ok){assert(id==(uint64_t)cap+1);}
    }
    fail_alloc=false;memset(&r,0,sizeof r);r.action=ML_PEER_ADD;r.has_node_id=true;r.node_id=3;
    assert(ml_peer_sync_resolve(&r)&&!r.online);                 /* id%3==0 was recorded offline */
    assert(!ml_peer_sync_entry(-1,&u,&used)&&!ml_peer_sync_entry(cap,&u,&used));
    puts("PASS: actual mailbox grows with the tailnet (600 peers), every entry readable, latest metadata kept, growth failure refused without loss");
    free(sync_entries);
    return 0;
}
'''


def run(program, name, extra=()):
    with tempfile.TemporaryDirectory(prefix='tunnel-slots-') as tmp:
        c = Path(tmp) / (name + '.c')
        c.write_text(program, encoding='utf-8')
        exe = Path(tmp) / (name + ('.exe' if os.name == 'nt' else ''))
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-pthread', *extra]
        if os.environ.get('POLICY_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        print(out.stdout.strip())
        if out.returncode:
            print(out.stderr.strip()[-2000:])
            raise subprocess.CalledProcessError(out.returncode, str(exe))


run(SLOT_TEST.replace('@@SLOTS@@', SLOTS), 'slots')
dep = os.environ.get('CJSON_SOURCE')   # only for the cJSON.h declarations in ml_policy.h
cjson = ['-I', str(Path(dep).parent)] if dep else \
    subprocess.check_output(['pkg-config', '--cflags', 'libcjson'], text=True).split()
run(SYNC_TEST, 'sync', ['-I', str(ML / 'src'), '-I', str(ML / 'include'), *cjson])
# Mutant: map order instead of "offline first" must fail the slot test.
mutant = SLOTS.replace('(offline && !best_offline) || ', '')
assert mutant != SLOTS
try:
    run(SLOT_TEST.replace('@@SLOTS@@', mutant), 'mutant')
except subprocess.CalledProcessError:
    pass
else:
    raise SystemExit('offline-first mutant survived')
print('tunnel slots: maps of any size; slots to the peers that need them')
