"""WireGuard allowed IPs per peer beyond the two inline ones (actual
wireguardif.c code).

Through 3.0.25-beta.16 a peer had two allowed IPs: its own address and ONE
more. A second advertised subnet, or a subnet next to an exit route, failed
to attach (logged only) and was unreachable. Extra allowed IPs now live in a
device table in PSRAM, allocated at the first need.

Compiles the real peer_allowed_count/peer_allowed/peer_add_ip/
mask_prefix_len/peer_lookup_by_allowed_ip with lwIP types stubbed:
- own /32 + exit 0/0 + 5 subnets on one peer: all attached, no duplicates;
- 2 inline + 30 extra per peer, the 33rd refused; other peers unaffected;
- longest-prefix choice across inline and extra entries of different peers;
- allocation failure: refused, inline entries keep working;
- a removed slot's extras are gone (count reset), a reused slot starts empty.
A mutant that ignores the extra table must fail.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WG = (ROOT / 'external/microlink/components/microlink/components/wireguard_lwip/src/wireguardif.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(signature):
    start = WG.index(signature)
    return WG[start:WG.index('\n}\n', start) + 3]


CODE = ''.join(function(sig) for sig in (
    'static int mask_prefix_len(',
    'static int peer_allowed_count(',
    'static struct wireguard_allowed_ip *peer_allowed(',
    'static struct wireguard_peer *peer_lookup_by_allowed_ip(',
    'static void retire_endpoint_for_host_route(',
    'static bool peer_add_ip(',
))

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define WIREGUARD_MAX_PEERS 4
#define WIREGUARD_MAX_SRC_IPS 2
#define WIREGUARD_EXTRA_SRC_IPS 30
#define LWIP_IPV4 1
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
typedef struct {uint32_t addr;uint8_t type;} ip_addr_t;
#define ip_addr_cmp(a,b) ((a)->addr==(b)->addr&&(a)->type==(b)->type)
#define IP_ADDR_NETCMP_COMPAT(s,i,m) (((s)->addr & (m)->addr)==((i)->addr & (m)->addr))
#define IPADDR_BROADCAST 0xffffffffu
#define IP_IS_V4(a) ((a)->type == 4)
#define ip_addr_set_any(v6, a) (*(a) = (ip_addr_t){.type = (v6) ? 6 : 4})
#define ip_2_ip4(a) (a)
#define ip4_addr_get_u32(a) ((a)->addr)
#define lwip_ntohl(x) (x)          /* host order throughout the test */
struct wireguard_allowed_ip {bool valid;ip_addr_t ip,mask;};
struct wireguard_keypair {bool valid;};
struct wireguard_peer {
    bool valid;
    struct wireguard_allowed_ip allowed_source_ips[WIREGUARD_MAX_SRC_IPS];
    struct wireguard_keypair curr_keypair,prev_keypair;
    ip_addr_t connect_ip,ip;
    uint16_t connect_port,port;
    uint32_t last_direct_rx;
};
struct wireguard_device {struct wireguard_peer peers[WIREGUARD_MAX_PEERS];
    struct wireguard_allowed_ip (*extra_ips)[WIREGUARD_EXTRA_SRC_IPS];uint8_t extra_count[WIREGUARD_MAX_PEERS];};
static int alloc_fail;
static void *heap_caps_calloc(size_t n,size_t s,int caps){(void)caps;return alloc_fail?NULL:calloc(n,s);}
#define calloc(n,s) (alloc_fail?NULL:(calloc)(n,s))
@@CODE@@
#undef calloc
static ip_addr_t A(uint32_t a){return (ip_addr_t){.addr=a,.type=4};}
static uint32_t M(int bits){return bits?0xffffffffu<<(32-bits):0;}
static bool add(struct wireguard_device *d,int slot,uint32_t net,int bits){return peer_add_ip(d,slot,A(net),A(M(bits)));}
static int owner(struct wireguard_device *d,uint32_t ip){ip_addr_t a=A(ip);struct wireguard_peer *p=peer_lookup_by_allowed_ip(d,&a);return p?(int)(p-d->peers):-1;}
int main(void){
    static struct wireguard_device d;
    for(int i=0;i<WIREGUARD_MAX_PEERS;i++)d.peers[i].valid=true;
    /* Allocation failure: inline entries still attach, extras refused. */
    alloc_fail=1;
    assert(add(&d,0,0x64400001,32)&&add(&d,0,0,0)&&!add(&d,0,0xC0A80100,24));
    assert(owner(&d,0x08080808)==0&&owner(&d,0xC0A80105)==0);   /* only the exit route covers it */
    alloc_fail=0;
    /* Own /32 + exit + 5 subnets on one peer: all attached. */
    for(int s=0;s<5;s++)assert(add(&d,0,0xC0A80000u|(uint32_t)(s<<8),24));
    assert(add(&d,0,0xC0A80100,24)&&d.extra_count[0]==5);       /* duplicate not added twice */
    assert(peer_allowed_count(&d,0)==7);
    /* Peer 1: own /32 + a more specific subnet than peer 0's /24. */
    assert(add(&d,1,0x64400002,32)&&add(&d,1,0xC0A80300,28)&&add(&d,1,0xAC100000,16));
    assert(owner(&d,0xC0A80305)==1);   /* /28 (peer 1, inline) beats /24 (peer 0, extra) */
    assert(owner(&d,0xC0A80325)==0);   /* outside the /28: peer 0's extra /24 */
    assert(owner(&d,0xAC10FF01)==1);   /* peer 1 extra entry */
    assert(owner(&d,0x64400001)==0&&owner(&d,0x64400002)==1&&owner(&d,0x01020304)==0);
    /* Capacity: 2 inline + 30 extra, the 33rd refused, peer 2 unaffected. */
    assert(add(&d,2,0x64400003,32));
    for(int s=0;s<31;s++)assert(add(&d,2,0x0A000000u|(uint32_t)(s<<16),16));
    assert(d.extra_count[2]==30&&!add(&d,2,0x0B000000,8));
    assert(owner(&d,0x0A1D0001)==2&&add(&d,3,0x64400004,32));
    /* Removal clears the slot's extras (as wireguardif_remove_peer does). */
    d.extra_count[0]=0;memset(d.extra_ips[0],0,sizeof d.extra_ips[0]);
    memset(&d.peers[0],0,sizeof d.peers[0]);
    assert(owner(&d,0xC0A80105)==-1&&owner(&d,0xC0A80325)==-1&&owner(&d,0xC0A80305)==1);
    d.peers[0].valid=true;assert(peer_allowed_count(&d,0)==2&&add(&d,0,0x64400009,32)&&owner(&d,0x64400009)==0);
    free(d.extra_ips);
    puts("PASS: actual WG allowed IPs: own /32 + exit + 5 subnets on one peer, 32 per peer, LPM across inline/extra entries of different peers, OOM keeps inline, removal clears extras");
    return 0;
}
'''


def run(code, name):
    with tempfile.TemporaryDirectory(prefix='wg-allowed-') as tmp:
        c = Path(tmp) / (name + '.c')
        c.write_text(PROGRAM.replace('@@CODE@@', code), encoding='utf-8')
        exe = Path(tmp) / (name + ('.exe' if os.name == 'nt' else ''))
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
        if os.environ.get('POLICY_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        print(out.stdout.strip())
        return out.returncode


assert run(CODE, 'allowed') == 0
mutant = CODE.replace('n += __atomic_load_n(&device->extra_count[x], __ATOMIC_ACQUIRE);', '(void)x;')
assert mutant != CODE
assert run(mutant, 'mutant') != 0, 'a lookup that ignores the extra table must fail'
print('wg allowed ips: every advertised route reachable, not only the first')
