"""Run the custom DHCP OFFER/ACK option encoder without the removed SDK flag."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'components/dhcpserver/dhcpserver.c').read_text(encoding='utf-8')
header = (root / 'components/dhcpserver/include/dhcpserver/dhcpserver.h').read_text(encoding='utf-8')


def function(text, start):
    offset = text.index(start)
    return text[offset:text.index('\n}', offset) + 2]


fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t u8_t;
typedef uint32_t u32_t;
typedef uint8_t dhcps_offer_t;
typedef struct { u32_t addr; } ip4_addr_t;
typedef struct { ip4_addr_t gw; } ip_info_t;
enum { OFFER_ROUTER = 1, OFFER_DNS = 2 };
enum { DNS_TYPE_MAIN, DNS_TYPE_BACKUP };
typedef struct {
    ip4_addr_t server_address, dhcps_mask, dns_server[2];
    dhcps_offer_t dhcps_dns, dhcps_offer;
    unsigned dhcps_lease_time;
    void *dhcps_netif;
    const char *dhcps_captiveportal_uri;
} dhcps_t;
#define DHCPS_LEASE_UNIT 60
#define LWIP_ASSERT(message, condition) assert(condition)
#define ip4_addr1(ip) (((const u8_t *)&(ip)->addr)[0])
#define ip4_addr2(ip) (((const u8_t *)&(ip)->addr)[1])
#define ip4_addr3(ip) (((const u8_t *)&(ip)->addr)[2])
#define ip4_addr4(ip) (((const u8_t *)&(ip)->addr)[3])
#define ip4_addr_isany_val(ip) (!(ip).addr)
static void get_ip_info(void *netif, ip_info_t *out) { (void)netif; *out = (ip_info_t){0}; }
'''

tests = r'''
static ip4_addr_t address(const u8_t octets[4]) {
    ip4_addr_t value;
    memcpy(&value.addr, octets, 4);
    return value;
}

static void check(bool enabled, const u8_t primary[4], const u8_t backup[4],
                  const u8_t *expected, size_t count) {
    dhcps_t state = {
        .server_address = address((const u8_t[]){192, 0, 2, 1}),
        .dhcps_mask = address((const u8_t[]){255, 255, 255, 0}),
        .dns_server = {address(primary), address(backup)},
        .dhcps_dns = enabled ? OFFER_DNS : 0,
        .dhcps_lease_time = 10,
    };
    u8_t options[256] = {0};
    const u8_t *end = add_offer_options(&state, options);
    size_t dns_options = 0;
    for (const u8_t *p = options; p < end;) {
        assert(end - p >= 2);
        const u8_t type = *p++;
        const u8_t size = *p++;
        assert(end - p >= size);
        if (type == DHCP_OPTION_DNS_SERVER) {
            assert(size == count);
            assert(memcmp(p, expected, count) == 0);
            dns_options++;
        }
        p += size;
    }
    assert(dns_options == 1);
}

int main(void) {
    const u8_t none[] = {0, 0, 0, 0};
    const u8_t ap[] = {192, 0, 2, 1};
    const u8_t primary[] = {192, 0, 2, 53};
    const u8_t backup[] = {198, 51, 100, 53};
    const u8_t both[] = {192, 0, 2, 53, 198, 51, 100, 53};
    check(false, primary, backup, ap, sizeof ap);
    check(true, none, none, ap, sizeof ap);
    check(true, primary, none, primary, sizeof primary);
    check(true, none, backup, backup, sizeof backup);
    check(true, primary, backup, both, sizeof both);
}
'''

options = re.findall(r'^#define DHCP_OPTION_[^\n]+', source, re.MULTILINE)
implementation = [
    function(header, 'static inline bool dhcps_router_enabled'),
    function(header, 'static inline bool dhcps_dns_enabled'),
    function(source, 'static inline u8_t* dhcps_option_ip'),
    function(source, 'static u8_t *add_offer_options'),
]
with tempfile.TemporaryDirectory(prefix='dhcps-dns-') as temp:
    path = Path(temp)
    test = path / 'test.c'
    test.write_text('\n'.join([fixture, *options, *implementation, tests]), encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    subprocess.run([os.environ.get('CC', 'gcc'), '-std=c11', '-Wall', '-Wextra',
                    '-Werror', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print('PASS custom DHCP DNS option: recovery fallback and configured primary/backup')

snapshot_type = 'typedef struct {\n    dhcp_lease_info_t *leases;'
snapshot = snapshot_type + source.split(snapshot_type, 1)[1].split('\n#endif // ESP_DHCPS', 1)[0]
lease_fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "dhcps_ext.h"
struct dhcps_pool {uint8_t mac[6]; struct {uint32_t addr;} ip; uint32_t lease_timer; char hostname[32];};
typedef struct list_node {struct list_node *pnext; void *pnode;} list_node;
typedef struct {list_node *plist;} dhcps_t;
static dhcps_t *g_dhcps_instance;
static struct dhcps_pool pool;
static int calls;
static bool owned, stop_before, stop_after, fail_schedule;
#define ERR_OK 0
#define LWIP_ASSERT_CORE_LOCKED() assert(owned)
static void stop_server(void) {
    LWIP_ASSERT_CORE_LOCKED();
    g_dhcps_instance=NULL;
    memset(&pool,0x7a,sizeof pool);
}
static int tcpip_callback_wait(void (*copy)(void *), void *arg){
    assert(!owned);
    calls++;
    if(fail_schedule)return -1;
    owned=true;
    if(stop_before)stop_server();
    copy(arg);
    if(stop_after)stop_server();
    owned=false;
    return ERR_OK;
}
@@SNAPSHOT@@
int main(void){
    static const uint32_t address=0xc0000201;
    list_node second={.pnode=&pool}, first={.pnext=&second,.pnode=&pool};
    dhcps_t server={.plist=&first};
    pool.ip.addr=address; pool.mac[5]=17; pool.lease_timer=300;
    memset(pool.hostname,'a',sizeof pool.hostname);
    dhcp_lease_info_t out[2]={0};
    g_dhcps_instance=&server;
    assert(!dhcps_get_active_leases(NULL,2) && !dhcps_get_active_leases(out,0) && !calls);
    fail_schedule=true;
    assert(dhcps_get_active_leases(out,2)==-1 && calls==1 && !out[0].ip);
    fail_schedule=false;
    assert(dhcps_get_active_leases(out,2)==2 && calls==2 && out[1].ip==address);
    memset(&out[1],0,sizeof out[1]);
    stop_after=true; /* Teardown after copying cannot affect the HTTP-side data. */
    assert(dhcps_get_active_leases(out,1)==1 && calls==3 && !out[1].ip);
    assert(!owned && !g_dhcps_instance && out[0].ip==address && out[0].mac[5]==17);
    assert(out[0].lease_timer==300 && out[0].hostname[30]=='a' && !out[0].hostname[31]);
    g_dhcps_instance=&server;
    stop_after=false;stop_before=true;
    assert(!dhcps_get_active_leases(out,2) && calls==4 && out[0].ip==address);
}
'''
with tempfile.TemporaryDirectory(prefix='dhcps-leases-') as temp:
    path = Path(temp)
    test = path / 'test.c'
    test.write_text(lease_fixture.replace('@@SNAPSHOT@@', snapshot), encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    subprocess.run([os.environ.get('CC', 'gcc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I', str(root / 'components/dhcpserver/include'), str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print('PASS DHCP snapshot: owner context, teardown before/after copy, truncation and scheduling failure')

runtime_fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define RECOVERYGATEWAY_LWIP_OWNED_TIMEOUTS 1
#define DHCP_COARSE_TIMER_MSECS 1000
#define MAX_STATION_NUM 16
#define DHCPS_SERVER_PORT 67
#define DHCPS_DEBUG 0
#define ESP_LOGI(...) do {} while (0)
#define LWIP_ASSERT_CORE_LOCKED() assert(core)
#define IP4_ADDR(out,a,b,c,d) ((out)->addr=0xffffffffu)
#define ip4_addr_isany_val(ip) (!(ip).addr)
#define DHCP_CHECK_SUBNET_MASK_IP(mask) do {if (!(mask)) return ERR_ARG;} while (0)
#define DHCP_CHECK_IP_MATCH_SUBNET_MASK(mask, ip) ((void)(mask), (void)(ip))
#define htonl(value) (value)
enum {ERR_OK=0, ERR_MEM=-1, ERR_ARG=-2, ERR_USE=-3};
typedef int err_t;
typedef uint8_t u8_t;
typedef struct {uint32_t addr;} ip4_addr_t;
typedef struct {
    void (*handler)(void *);
    void *arg;
    bool pending;
} lwip_owned_timeout_t;
struct netif {ip4_addr_t ip_addr;};
struct udp_pcb {struct netif *netif; void *arg;};
struct dhcps_pool {unsigned lease_timer;};
typedef struct list_node {struct list_node *pnext; void *pnode;} list_node;
enum {DHCPS_HANDLE_CREATED, DHCPS_HANDLE_STARTED, DHCPS_HANDLE_STOPPED};
typedef struct {
    struct netif *dhcps_netif;
    struct udp_pcb *dhcps_pcb;
    ip4_addr_t dhcps_mask, server_address, broadcast_dhcps, client_address_plus;
    struct {ip4_addr_t start_ip;} dhcps_poll;
    list_node *plist;
    int state;
    lwip_owned_timeout_t lease_timeout;
} dhcps_t;
static dhcps_t *g_dhcps_instance;
static bool core=true, allocation_fails, bind_fails;
static unsigned pcbs, timers, deleted, binds;
static void dhcps_tmr(void *arg);
static void dhcps_release_runtime(dhcps_t *server);
static void handle_dhcp(void) {abort();}
static struct udp_pcb *udp_new(void) {
    if (allocation_fails) return NULL;
    struct udp_pcb *pcb=calloc(1,sizeof *pcb);
    assert(pcb); pcbs++;
    return pcb;
}
static void udp_bind_netif(struct udp_pcb *pcb, struct netif *netif) {pcb->netif=netif;}
static err_t udp_bind(struct udp_pcb *pcb, const ip4_addr_t *addr, unsigned port) {
    assert(addr==&pcb->netif->ip_addr && port==DHCPS_SERVER_PORT);
    binds++;
    return bind_fails ? ERR_USE : ERR_OK;
}
static void udp_recv(struct udp_pcb *pcb, void (*fn)(void), void *arg) {assert(fn==handle_dhcp);pcb->arg=arg;}
static void udp_remove(struct udp_pcb *pcb) {assert(core && pcbs);pcbs--;free(pcb);}
static void dhcps_poll_set(dhcps_t *server, uint32_t addr) {server->dhcps_poll.start_ip.addr=addr+1;}
static void lwip_owned_timeout_schedule(lwip_owned_timeout_t *timer, uint32_t delay,
    void (*handler)(void *), void *arg, const char *name) {
    assert(core && !timer->pending && delay==1000 && handler==dhcps_tmr && name);
    *timer=(lwip_owned_timeout_t){handler,arg,true};
    timers++;
}
static void lwip_owned_timeout_cancel(lwip_owned_timeout_t *timer) {
    assert(core);
    if (timer->pending) {timer->pending=false; timers--;}
}
static void fire(dhcps_t *server) {
    lwip_owned_timeout_t *timer=&server->lease_timeout;
    assert(timer->pending && timer->arg==server);
    timer->pending=false;timers--;
    timer->handler(timer->arg);
}
static void mem_free(dhcps_t *server) {
    assert(!server->lease_timeout.pending && !server->dhcps_pcb && !server->plist && g_dhcps_instance!=server);
    deleted++;free(server);
}
static void kill_oldest_dhcps_pool(dhcps_t *server) {(void)server;abort();}
@@RUNTIME@@
static dhcps_t *new_server(void) {
    dhcps_t *server=calloc(1,sizeof *server);
    assert(server);server->dhcps_mask.addr=0xffffff00u;
    return server;
}
static void add_lease(dhcps_t *server, unsigned lease_timer) {
    list_node *node=calloc(1,sizeof *node);
    struct dhcps_pool *pool=calloc(1,sizeof *pool);
    assert(node && pool);pool->lease_timer=lease_timer;
    node->pnode=pool;node->pnext=server->plist;server->plist=node;
}
int main(void) {
    dhcps_t *first=new_server(), *second=new_server();
    struct netif a={{0xc0000201}}, b={{0xc6336401}};
    assert(__wrap_dhcps_start(first,&a,(ip4_addr_t){0})==ERR_ARG && !pcbs);
    allocation_fails=true;
    assert(__wrap_dhcps_start(first,&a,a.ip_addr)==ERR_MEM && !pcbs && !timers);
    allocation_fails=false;bind_fails=true;
    assert(__wrap_dhcps_start(first,&a,a.ip_addr)==ERR_USE && !pcbs && !timers && !g_dhcps_instance);
    bind_fails=false;
    assert(__wrap_dhcps_start(first,&a,a.ip_addr)==ERR_OK && pcbs==1 && timers==1);
    add_lease(first,1);
    assert(__wrap_dhcps_start(first,&a,a.ip_addr)==ERR_OK && binds==2 && first->plist);
    assert(__wrap_dhcps_start(second,&b,b.ip_addr)==ERR_OK && pcbs==2 && timers==2);
    fire(first);
    assert(!first->plist && timers==2 && second->lease_timeout.pending);
    assert(__wrap_dhcps_stop(first,&a)==ERR_OK && pcbs==1 && timers==1 && g_dhcps_instance==second);
    assert(__wrap_dhcps_start(first,&a,a.ip_addr)==ERR_OK && timers==2);
    add_lease(first,60);
    __wrap_dhcps_delete(first);
    assert(deleted==1 && !g_dhcps_instance && pcbs==1 && timers==1);
    fire(second);
    __wrap_dhcps_delete(second);
    assert(deleted==2 && !pcbs && !timers);
}
'''
runtime = '\n'.join(function(source, begin) for begin in (
    'static void dhcps_schedule_lease_timer(', 'void __wrap_dhcps_delete(',
    'static void node_remove_from_list(', 'err_t __wrap_dhcps_start(',
    'static void dhcps_release_runtime(dhcps_t *dhcps)\n{', 'err_t __wrap_dhcps_stop(',
    'static void dhcps_tmr(void *arg)\n{'))
with tempfile.TemporaryDirectory(prefix='dhcps-lifecycle-') as temp:
    path = Path(temp)
    test = path / 'test.c'
    test.write_text(runtime_fixture.replace('@@RUNTIME@@', runtime), encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    subprocess.run([os.environ.get('CC', 'gcc'), '-std=c11', '-Wall', '-Wextra',
                    '-Werror', str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)
print('PASS DHCP lifecycle: allocation/bind faults, timer expiry, independent stop/restart/delete')
