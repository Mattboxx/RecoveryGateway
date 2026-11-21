"""Compile the actual routing hook/diagnostic functions with synthetic netifs.

No board changes or private network data. ROUTE_SANITIZE=1 enables ASan/UBSan.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/lwip_route_hook.c').read_text(encoding='utf-8')
helpers = source.split('/* Tailscale CGNAT: 100.64.0.0/10 */', 1)[1].split('static bool s_wg_udp_pinned', 1)[0]
hook_start = 'static struct netif *route_src_hook(const ip4_addr_t *src, const ip4_addr_t *dest);'
hook = hook_start + source.split(hook_start, 1)[1].split('/* ---------------------------------------------------------------------', 1)[0]
diagnostic = 'static void name_netif' + source.split('static void name_netif', 1)[1].split('/* ---------------------------------------------------------------------', 1)[0]
napt_start = 'static err_t napt_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp, struct netif *outp);'
napt = napt_start + source.split(napt_start, 1)[1]
# Release definitions of the test-only counters (empty macros).
perf_hooks = (ROOT / 'main/perf_hooks.h').read_text(encoding='utf-8').replace('#pragma once', '')
fixture = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
typedef struct { uint32_t addr; } ip4_addr_t;
typedef ip4_addr_t ip_addr_t;
typedef unsigned char u8_t;
#define DNS_MAX_SERVERS 2
#define IP_IS_V4(a) ((a) != non_ipv4_dns)
static const ip_addr_t *non_ipv4_dns;
#define ip_2_ip4(a) (a)
#define ip_addr_isany(a) ((a)->addr == 0)
#define ip_addr_isany_val(a) ((a).addr == 0)
#define ip4_addr_netcmp(a,b,m) (((a)->addr & (m)->addr) == ((b)->addr & (m)->addr))
static ip_addr_t dns_servers[DNS_MAX_SERVERS];
static const ip_addr_t *dns_getserver(u8_t i) { return &dns_servers[i]; }
static int dns_sets;
static void dns_setserver(u8_t i, const ip_addr_t *a) { dns_servers[i] = a ? *a : (ip_addr_t){0}; dns_sets++; }
static struct dhcp { ip_addr_t server_ip_addr; } dhcp_state;
#define netif_dhcp_data(n) (&dhcp_state)
static uint32_t known_peer_nbo;
struct netif;
static bool microlink_wg_has_peer_ip(struct netif *wg, uint32_t ip);
struct netif { struct netif *next; char name[2]; uint8_t num, napt, flags; bool up, link; ip4_addr_t ip, mask, gw; };
#define NETIF_FLAG_ETHARP 0x08
#define IPADDR4_INIT(v) {v}
static struct netif *netif_list, *netif_default;
#define netif_ip4_addr(n) (&(n)->ip)
#define netif_ip4_netmask(n) (&(n)->mask)
#define netif_ip4_gw(n) (&(n)->gw)
#define ip4_addr_get_u32(a) ((a)->addr)
#define ip4_addr_isany_val(a) ((a).addr == 0)
#define ip4_addr_cmp(a,b) ((a)->addr == (b)->addr)
#define netif_is_up(n) ((n)->up)
#define netif_is_link_up(n) ((n)->link)
static uint32_t swap32(uint32_t x) { return ((x&255)<<24)|((x&0xff00)<<8)|((x>>8)&0xff00)|(x>>24); }
#define lwip_ntohl swap32
#define lwip_htonl swap32
#define lwip_ntohs(x) ((uint16_t)(((x)>>8)|((x)<<8)))
#define ESP_LOGW(...) ((void)0)
#define ESP_OK 0
#define ERR_OK 0
static int tcpip_callback_wait(void (*callback)(void *), void *arg) {
    callback(arg); return ERR_OK;
}
#define TAILSCALE_ACCEPTED_ROUTES_MAX 32
typedef struct { uint32_t network; uint8_t prefix_len; } tailscale_accepted_route_t;
static tailscale_accepted_route_t tailscale_accepted_routes[TAILSCALE_ACCEPTED_ROUTES_MAX];
static int tailscale_accepted_routes_count;
static uint32_t tailscale_exit_node_ip;
static int32_t tailscale_lan_bypass, tailscale_accept_routes;
static _Thread_local int core_depth;
static atomic_int lock_count;
typedef pthread_mutex_t portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(mux) do { assert(core_depth==0); assert(pthread_mutex_lock(mux)==0); core_depth=1; atomic_fetch_add(&lock_count,1); } while(0)
#define portEXIT_CRITICAL(mux) do { assert(core_depth==1); core_depth=0; assert(pthread_mutex_unlock(mux)==0); } while(0)
static bool should_log_route_hook(void) { assert(core_depth==0); return false; }
static struct netif *__real_ip4_route_src_hook(const ip4_addr_t *src, const ip4_addr_t *dst) { (void)src; (void)dst; return NULL; }
typedef struct microlink_s { int unused; } microlink_t;
static bool microlink_wg_has_peer_ip(struct netif *wg, uint32_t ip) { return wg && known_peer_nbo && ip == known_peer_nbo; }
typedef struct { char hostname[64]; uint32_t vpn_ip; int subnet_route_count; tailscale_accepted_route_t subnet_routes[32]; } microlink_peer_info_t;
static microlink_t *tailscale_get_microlink(void) { return NULL; }
static int microlink_get_peer_count(microlink_t *ml) { (void)ml; return 0; }
static int microlink_get_peer_info(microlink_t *ml, int i, microlink_peer_info_t *pi) { (void)ml; (void)i; (void)pi; return -1; }
typedef int err_t;
struct pbuf { uint16_t len; void *payload; };
struct ip_hdr { ip4_addr_t src, dest; uint8_t proto; };
#define IPH_PROTO(h) ((h)->proto)
#define IPH_HL(h) 5
static bool exit_server_active;
static int32_t tailscale_snat_subnet_routes;
static bool tailscale_exit_server_active(void) { return exit_server_active; }
static struct netif *selected_eth;
static struct netif *eth_uplink_selected_lwip(void) { return selected_eth; }
static struct netif *selected_ppp;
static struct netif *cell_uplink_selected_lwip(void) { return selected_ppp; }
static struct netif *cell_netif;
static struct netif *cell_uplink_lwip(void) { return cell_netif; }
static uint32_t binding;
static bool tailnet_forward_is_routed_target(uint32_t uplink, int proto, uint32_t ip, uint16_t port) {
    return binding && uplink==binding && (proto==6 || proto==17) && ip==known_peer_nbo && port==22;
}
static int napt_calls;
static bool napt_enabled_at_call;
static err_t __real_ip_napt_forward(struct pbuf *p, struct ip_hdr *h, struct netif *inp, struct netif *outp) {
    (void)p; (void)h; (void)outp;
    napt_calls++; napt_enabled_at_call=inp && inp->napt;
    return ERR_OK;
}
'''
tests = r'''
static struct netif sta, ap, wg, eth;
static void reset(void) {
    sta=(struct netif){.name={'s','t'},.num=1,.up=true,.link=true,.ip={swap32(0xc0a80114)},.mask={swap32(0xffffff00)}};
    ap=(struct netif){.name={'a','p'},.num=2,.up=true,.link=true,.ip={swap32(0xc0a80401)},.mask={swap32(0xffffff00)}};
    wg=(struct netif){.name={'w','g'},.up=true,.link=true,.ip={swap32(0x6450463c)},.mask={swap32(0xffc00000)}};
    sta.next=&ap; ap.next=&wg; netif_list=&sta; netif_default=NULL;
    selected_eth=NULL; selected_ppp=NULL; cell_netif=NULL; binding=0;
    tailscale_exit_node_ip=0; tailscale_lan_bypass=0; tailscale_accept_routes=0;
    publish_accepted_routes(NULL,0);
    memset(dns_servers,0,sizeof dns_servers); memset(&dhcp_state,0,sizeof dhcp_state); known_peer_nbo=0;
}
static void expect(uint32_t src, uint32_t dst, struct netif *want) {
    ip4_addr_t s={swap32(src)}, d={swap32(dst)};
    struct netif *got=__wrap_ip4_route_src_hook(&s,&d);
    if(got!=want) { fprintf(stderr,"hook mismatch %08x -> %08x: %.2s\n",src,dst,got?got->name:"--"); abort(); }
    char label[16], reason[160], expected[16];
    route_explain(src,dst,label,sizeof label,reason,sizeof reason);
    name_netif(want,expected,sizeof expected);
    if(strcmp(label,expected)) { fprintf(stderr,"route mismatch %08x -> %08x: %s != %s\n",src,dst,label,expected); abort(); }
    assert(reason[0]); assert(core_depth==0);
}
static atomic_bool producer_done;
static void *route_producer(void *arg) {
    (void)arg;
    tailscale_accepted_route_t rows[32];
    for(int gen=0;gen<20000;gen++) {
        for(int i=0;i<32;i++) rows[i]=(tailscale_accepted_route_t){0x0a000000u+(uint32_t)gen*64u+(uint32_t)i,32};
        publish_accepted_routes(rows,32);
    }
    atomic_store(&producer_done,true); return NULL;
}
int main(void) {
    reset();
    /* CGNAT local egress needs NAT too; only actual WG TCP skips it. */
    struct ip_hdr header={.dest={swap32(0x6450463d)},.proto=6};
    napt_calls=0; exit_server_active=true;
    assert(__wrap_ip_napt_forward(NULL,&header,&wg,&sta)==ERR_OK);
    assert(napt_calls==1 && napt_enabled_at_call && wg.napt==0);
    exit_server_active=false; tailscale_snat_subnet_routes=1;
    __wrap_ip_napt_forward(NULL,&header,&wg,&sta);
    assert(napt_calls==2 && napt_enabled_at_call && wg.napt==0);
    tailscale_snat_subnet_routes=0;
    __wrap_ip_napt_forward(NULL,&header,&wg,&sta);
    assert(napt_calls==3 && !napt_enabled_at_call);
    __wrap_ip_napt_forward(NULL,&header,&ap,&wg); assert(napt_calls==3);
    ap.napt=1; __wrap_ip_napt_forward(NULL,&header,&ap,&sta);
    assert(napt_calls==4 && napt_enabled_at_call && ap.napt==1);
    header.proto=17; __wrap_ip_napt_forward(NULL,&header,&ap,&wg);
    assert(napt_calls==5 && napt_enabled_at_call);
    reset();
    eth=sta; eth.name[0]='e'; eth.name[1]='n'; eth.ip.addr=swap32(0xc0a80115);
    sta.next=&eth; selected_eth=&eth; binding=eth.ip.addr;
    known_peer_nbo=swap32(0x6450463d);
    expect(0x6450463d,0xc0a80102,&eth);
    eth.link=false;
    ip4_addr_t peer={known_peer_nbo}, client={swap32(0xc0a80102)};
    assert(__wrap_ip4_route_src_hook(&peer,&client)==NULL);
    eth.link=true;
    uint8_t ports[24]={0}; struct pbuf packet={sizeof ports,ports};
    for (unsigned proto=6; proto<=17; proto+=11) {
        header=(struct ip_hdr){.dest={known_peer_nbo},.proto=proto};
        ports[21]=123; ports[23]=22;
        napt_calls=0;
        __wrap_ip_napt_forward(&packet,&header,&eth,&wg);
        assert(napt_calls==1 && napt_enabled_at_call && !eth.napt);
        binding=sta.ip.addr; napt_enabled_at_call=false;
        __wrap_ip_napt_forward(&packet,&header,&sta,&wg);
        assert(!napt_enabled_at_call && !sta.napt);
        selected_eth=NULL;
        __wrap_ip_napt_forward(&packet,&header,&sta,&wg);
        assert(napt_enabled_at_call && !sta.napt);
        selected_eth=&eth; binding=eth.ip.addr;
        header=(struct ip_hdr){.src={known_peer_nbo},.proto=proto};
        ports[21]=22; ports[23]=123;
        __wrap_ip_napt_forward(&packet,&header,&wg,&eth);
        assert(napt_enabled_at_call && !wg.napt);
        __wrap_ip_napt_forward(&packet,&header,&wg,&sta);
        assert(!napt_enabled_at_call);
    }
    struct netif ppp={.name={'p','p'},.up=true,.link=true,.ip={swap32(0x64401014)},.mask={swap32(0xffffffff)}};
    selected_ppp=&ppp;
    tailscale_exit_node_ip=known_peer_nbo;
    tailscale_lan_bypass=1;
    expect(0,0x08080808,&ppp);                  /* control traffic stays outside the exit tunnel */
    expect(0xc0a80402,0x08080808,&wg);        /* AP clients still use the exit tunnel */
    expect(0,0x0a000001,&eth);                 /* local bypass stays on the physical LAN */
    tailscale_exit_node_ip=0;
    exit_server_active=true;
    header=(struct ip_hdr){.dest={swap32(0x08080808)},.proto=6};
    __wrap_ip_napt_forward(&packet,&header,&wg,&ppp);
    assert(napt_enabled_at_call && !wg.napt);
    exit_server_active=false;
    tailscale_snat_subnet_routes=1;
    __wrap_ip_napt_forward(&packet,&header,&wg,&ppp);
    assert(!napt_enabled_at_call);             /* PPP is not a local subnet listener */
    __wrap_ip_napt_forward(&packet,&header,&wg,&eth);
    assert(napt_enabled_at_call && !wg.napt);
    tailscale_snat_subnet_routes=0;
    reset();
    reset();
    /* New 0.1.30 CGNAT exceptions work without exit-node/LAN-bypass mode. */
    sta.ip.addr=swap32(0x64600114); sta.mask.addr=swap32(0xffc00000);
    expect(0,0x6450463d,&sta);
    known_peer_nbo=swap32(0x6450463d); expect(0,0x6450463d,&wg);
    known_peer_nbo=0; sta.mask.addr=swap32(0xffffff00);
    dns_servers[0].addr=swap32(0x64710202); expect(0,0x64710202,&sta);
    known_peer_nbo=dns_servers[0].addr; expect(0,0x64710202,&wg);
    known_peer_nbo=0; dhcp_state.server_ip_addr.addr=swap32(0x64720202);
    expect(0,0x64720202,&sta);
    sta.link=false; expect(0,0x64720202,&wg); expect(0,0x64710202,&wg);
    reset(); ap.ip.addr=swap32(0x64400401); expect(0,0x64400402,&ap);
    known_peer_nbo=swap32(0x64400402); expect(0,0x64400402,&wg);
    reset();
    sta.ip.addr=swap32(0x64600114); /* CGNAT uplink before wg in list */
    assert(find_wg_netif()==&wg);
    wg.ip.addr=0; assert(find_wg_netif()==NULL); /* boot/reconnect: never STA */
    expect(0xc0a80402,0x6450463d,NULL);
    wg.ip.addr=swap32(0x0a010101); assert(find_wg_netif()==&wg); /* identity is name */
    expect(0xc0a80402,0x6450463d,&wg);
    reset(); tailscale_exit_node_ip=0x6450463d; tailscale_lan_bypass=1;
    expect(0xc0a80402,0xc0a80164,&sta);
    expect(0x6450463d,0xc0a80402,&ap);
    expect(0xc0a80402,0x0a0a0101,&sta);
    expect(0,0xcb007107,&sta); /* local public control-plane socket */
    expect(0xc0a80402,0xcb007107,&wg); /* forwarded public exit traffic */
    assert(__wrap_ip4_route_src_hook(NULL,&(ip4_addr_t){swap32(0xcb007107)})==&sta);
    ap.link=false; expect(0x6450463d,0xc0a80402,&sta);
    ap.link=true; ap.up=false; expect(0x6450463d,0xc0a80402,&sta);
    ap.up=true; sta.link=false; expect(0xc0a80402,0xc0a80164,NULL);
    sta.link=true; sta.up=false; expect(0xc0a80402,0xc0a80164,NULL);
    sta.up=true; sta.ip.addr=swap32(0x64600114); sta.mask.addr=swap32(0xff000000);
    expect(0xc0a80402,0x64800164,&sta); /* CGNAT uplink is valid LAN bypass */
    for(int up=0;up<2;up++) for(int link=0;link<2;link++) {
        sta.up=up; sta.link=link;
        expect(0xc0a80402,0x64800164,up&&link?&sta:&wg);
    }
    /* 3.0.29: a USB stick network on the home LAN prefix (192.168.1.0/24 on
     * both sides). Home devices go to the LAN uplink; the stick's own
     * address, gateway, DHCP server and (while it carries the Internet
     * uplink) resolvers stay on the stick. Listed first, as lwIP adds new
     * netifs at the head of the list. */
    reset();
    struct netif stick={.name={'e','n'},.num=3,.up=true,.link=true,.ip={swap32(0xc0a801a7)},.mask={swap32(0xffffff00)},.gw={swap32(0xc0a80101)}};
    stick.next=&sta; netif_list=&stick; cell_netif=&stick;
    sta.gw.addr=swap32(0xc0a801fe);
    expect(0,0xc0a8013f,&sta);                   /* this PC on the home LAN */
    expect(0,0xc0a801fe,&sta);                   /* the home router */
    expect(0x6450463d,0xc0a8013f,&sta);          /* forwarded from the tailnet */
    expect(0xc0a80402,0xc0a8013f,&sta);          /* forwarded from an AP client */
    expect(0,0xc0a801a7,&stick);                 /* the stick's own address */
    expect(0xc0a801a7,0xc0a8013f,&stick);        /* bound to the stick's address */
    /* Wi-Fi carries the Internet uplink: .1 is the home router (and often its
     * DNS), even though it is also the stick's gateway and DHCP server. */
    dhcp_state.server_ip_addr.addr=swap32(0xc0a80101);
    dns_servers[0].addr=swap32(0xc0a80101);
    expect(0,0xc0a80101,&sta);
    selected_ppp=&stick;                         /* the stick carries it */
    expect(0,0xc0a80101,&stick);                 /* its gateway, DHCP server and resolver */
    dns_servers[0].addr=swap32(0xc0a801fe); dhcp_state.server_ip_addr.addr=swap32(0xc0a80102);
    expect(0,0xc0a801fe,&sta);                   /* board A: the home router's resolver (.254, from the
                                                    Wi-Fi lease) stays on the LAN while the stick carries
                                                    the Internet uplink */
    expect(0,0xc0a80102,&stick);                 /* its DHCP server */
    expect(0,0xc0a80104,&sta);                   /* anything else in the prefix: home LAN */
    expect(0,0xc0a8013f,&sta);                   /* home devices still on the LAN */
    expect(0,0xc0a80114,&sta);                   /* the LAN uplink's own address */
    selected_ppp=NULL; memset(dns_servers,0,sizeof dns_servers); memset(&dhcp_state,0,sizeof dhcp_state);
    expect(0,0x08080808,NULL);                   /* Internet: unchanged (lwIP default route) */
    assert(__wrap_ip4_route_src_hook(NULL,&(ip4_addr_t){swap32(0xc0a80402)})==NULL);   /* AP clients: unchanged */
    { ip4_addr_t d={swap32(0xc0a8013f)};
      sta.link=false; assert(__wrap_ip4_route_src_hook(NULL,&d)==NULL);   /* Wi-Fi down: the stick's prefix */
      sta.link=true; stick.up=false; assert(__wrap_ip4_route_src_hook(NULL,&d)==NULL);
      stick.up=true; cell_netif=NULL; assert(__wrap_ip4_route_src_hook(NULL,&d)==NULL);   /* no address yet */
      cell_netif=&stick; stick.ip.addr=swap32(0x0a000002);                              /* no overlap */
      assert(__wrap_ip4_route_src_hook(NULL,&d)==NULL);
      stick.ip.addr=swap32(0xc0a801a7); stick.mask.addr=0;
      assert(__wrap_ip4_route_src_hook(NULL,&d)==NULL);                                /* no prefix */
      stick.mask.addr=swap32(0xffff0000); sta.mask.addr=swap32(0xffffff00);           /* wider stick prefix */
      assert(__wrap_ip4_route_src_hook(NULL,&d)==&sta);
      ip4_addr_t other={swap32(0xc0a8023f)};
      assert(__wrap_ip4_route_src_hook(NULL,&other)==NULL);                            /* outside the LAN prefix */
    }
    eth=sta; eth.name[0]='e'; eth.name[1]='t'; eth.ip.addr=swap32(0xc0a80115); eth.next=NULL;
    sta.next=&eth; selected_eth=&eth; stick.mask.addr=swap32(0xffffff00);
    expect(0,0xc0a8013f,&eth);                   /* a selected Ethernet LAN uplink wins */
    /* 3.0.29: with the stick as the Internet uplink, a LAN resolver (the home
     * router .254 from the Wi-Fi lease, as on board A) follows the stick's
     * gateway, and comes back when the LAN uplink carries the traffic again. */
    reset();
    stick=(struct netif){.name={'e','n'},.num=3,.flags=NETIF_FLAG_ETHARP,.up=true,.link=true,.ip={swap32(0xc0a801a7)},.mask={swap32(0xffffff00)},.gw={swap32(0xc0a80101)}};
    dns_servers[0].addr=swap32(0xc0a801fe); dns_sets=0;
    cell_dns_follow(NULL,&sta); assert(dns_servers[0].addr==swap32(0xc0a801fe) && dns_sets==0);   /* LAN in use: untouched */
    cell_dns_follow(&stick,&sta); assert(dns_servers[0].addr==swap32(0xc0a80101) && dns_sets==1);  /* follows the stick */
    cell_dns_follow(&stick,&sta); assert(dns_sets==1);                                             /* stable: no rewrite */
    dns_servers[0].addr=swap32(0xc0a801fd);                                                        /* a renewal supplies a different DNS */
    cell_dns_follow(&stick,&sta); assert(dns_servers[0].addr==swap32(0xc0a80101) && dns_sets==2);
    cell_dns_follow(NULL,&sta); assert(dns_servers[0].addr==swap32(0xc0a801fd) && dns_sets==3);    /* newest lease restored */
    cell_dns_follow(NULL,&sta); assert(dns_sets==3);
    dns_servers[0].addr=swap32(0x01010101);                                                        /* user's public resolver */
    cell_dns_follow(&stick,&sta); assert(dns_servers[0].addr==swap32(0x01010101) && dns_sets==3);
    dns_servers[0].addr=swap32(0xc0a801fe); sta.link=false;                                        /* Wi-Fi down: failover */
    cell_dns_follow(&stick,NULL); assert(dns_servers[0].addr==swap32(0xc0a80101));
    sta.link=true; dns_servers[0].addr=swap32(0x08080808);                                         /* changed meanwhile */
    cell_dns_follow(NULL,&sta); assert(dns_servers[0].addr==swap32(0x08080808));                   /* not overwritten */
    dns_servers[0].addr=0; cell_dns_follow(&stick,&sta); assert(dns_servers[0].addr==swap32(0xc0a80101));   /* none yet */
    cell_dns_follow(NULL,&sta); assert(dns_servers[0].addr==0);                                                   /* empty slot restored */
    dns_servers[0].addr=1; non_ipv4_dns=&dns_servers[0]; dns_sets=0;
    cell_dns_follow(&stick,&sta); assert(dns_servers[0].addr==1 && dns_sets==0);           /* IPv6 untouched */
    non_ipv4_dns=NULL;
    dns_servers[0].addr=swap32(0xc0a801fd);
    cell_dns_follow(&stick,&sta);
    stick.gw.addr=swap32(0xc0a80201);
    cell_dns_follow(&stick,&sta); assert(dns_servers[0].addr==stick.gw.addr);             /* replacement modem */
    cell_dns_follow(NULL,&sta); assert(dns_servers[0].addr==swap32(0xc0a801fd));
    struct netif ppp2={.name={'p','p'},.up=true,.link=true,.ip={swap32(0x0a400001)},.mask={swap32(0xffffffff)},.gw={swap32(0x0a404040)}};
    dns_servers[0].addr=swap32(0xc0a801fe); dns_sets=0;
    cell_dns_follow(&ppp2,&sta); assert(dns_servers[0].addr==swap32(0xc0a801fe) && dns_sets==0);  /* PPP: left alone */
    cell_dns_follow(NULL,&sta);
    reset(); tailscale_accept_routes=1;
    tailscale_accepted_route_t routes[32], snapshot[32];
    for(int i=0;i<32;i++) routes[i]=(tailscale_accepted_route_t){0x0a000000u+(i<<16),16};
    publish_accepted_routes(routes,32);
    int before=lock_count;
    assert(tailscale_accepted_routes_snapshot(snapshot,32)==32);
    assert(lock_count==before+1 && !memcmp(routes,snapshot,sizeof routes));
    assert(tailscale_accepted_routes_snapshot(snapshot,1)==1);
    assert(tailscale_accepted_routes_snapshot(NULL,32)==0);
    assert(tailscale_accepted_routes_snapshot(snapshot,0)==0);
    publish_accepted_routes(NULL,33); assert(tailscale_accepted_routes_count==32);
    publish_accepted_routes(NULL,1); assert(tailscale_accepted_routes_count==32);
    for(int i=0;i<32;i++) expect(0xc0a80402,0x0a000001u+(i<<16),&wg);
    expect(0xc0a80114,0x0a000001,NULL); /* own IP does not accept peer routes */
    expect(0,0x0a000001,NULL);
    routes[0]=(tailscale_accepted_route_t){0x0a000001,32}; publish_accepted_routes(routes,1);
    expect(0xc0a80402,0x0a000001,&wg); expect(0xc0a80402,0x0a000002,NULL);
    for(int prefix=0;prefix<=255;prefix++) {
        routes[0]=(tailscale_accepted_route_t){0x0a000001,(uint8_t)prefix}; publish_accepted_routes(routes,1);
        expect(0xc0a80402,0x0a000001,prefix>=1&&prefix<=32?&wg:NULL);
    }
    publish_accepted_routes(NULL,0); expect(0xc0a80402,0x0a000001,NULL);
    assert(ip_is_rfc1918(0x0a000000) && ip_is_rfc1918(0xac100000) && ip_is_rfc1918(0xac1fffff) && ip_is_rfc1918(0xc0a8ffff));
    assert(!ip_is_rfc1918(0xac200000) && !ip_is_rfc1918(0x64400000) && !ip_is_rfc1918(0xc0a90000));
    assert(__wrap_ip4_route_src_hook(NULL,NULL)==NULL);
    for(int i=0;i<32;i++) routes[i]=(tailscale_accepted_route_t){0x0a000000u+(uint32_t)i,32};
    publish_accepted_routes(routes,32);
    pthread_t producer; assert(!pthread_create(&producer,NULL,route_producer,NULL));
    int reads=0;
    while(!atomic_load(&producer_done) || reads<5000) {
        assert(tailscale_accepted_routes_snapshot(snapshot,32)==32);
        uint32_t base=snapshot[0].network; assert((base&63)==0);
        for(int i=0;i<32;i++) assert(snapshot[i].network==base+(uint32_t)i && snapshot[i].prefix_len==32);
        tailscale_accepted_route_t matched;
        if(accepted_route_lookup(0x0a000007,&matched)) assert(matched.network==0x0a000007 && matched.prefix_len==32);
        reads++;
    }
    assert(!pthread_join(producer,NULL));
    puts("PASS: real hook/diagnostic parity, Ethernet/Wi-Fi Service Gateway, CGNAT identity, exit routing, every prefix width and concurrent route publication");
}
'''
with tempfile.TemporaryDirectory(prefix='route-hook-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(fixture + perf_hooks + helpers + hook + diagnostic + napt + tests, encoding='utf-8')
    flags = ['-std=c11', '-pthread', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable']
    if os.environ.get('ROUTE_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'test.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'


startup = 'typedef struct {\n    atomic_bool pending;' + source.split(
    'typedef struct {\n    atomic_bool pending;', 1)[1].split('static void route_supervisor_task(', 1)[0]
startup += source[source.index('static void route_supervisor_task('):].split('    while (1) {', 1)[0]
startup += '    assert(msg && msg->ctx == &request);\n}\n'
startup += ''.join(map(function, ('static bool start_route_supervisor(', 'static void retry_route_supervisor(',
                                   'void lwip_route_hook_init(', 'bool lwip_route_hook_supervisor_running(',
                                   'bool lwip_route_hook_supervisor_degraded(')))
microlink = (ROOT / 'external/microlink/components/microlink/src/ml_wg_mgr.c').read_text(encoding='utf-8')
pin_start = microlink.index('esp_err_t microlink_pin_wg_output_netif_core(')
microlink_pin = microlink[pin_start:microlink.index('\n}', pin_start) + 2] + '\n'
coordinator = (ROOT / 'external/microlink/components/microlink/src/ml_coord.c').read_text(encoding='utf-8')
bind_start = coordinator.index('void ml_bind_sock_to_upstream(')
microlink_pin += coordinator[bind_start:coordinator.index('\n}', bind_start) + 2] + '\n'

startup_fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {void (*callback)(void *); const char *name; bool skip_unhandled_events;} esp_timer_create_args_t;
typedef esp_timer_create_args_t *esp_timer_handle_t;
struct tcpip_callback_msg {void (*callback)(void *); void *ctx;};
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 0x103
#define ERR_OK 0
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define MALLOC_CAP_SPIRAM 1
#define pdPASS 1
#define pdMS_TO_TICKS(ms) (ms)
bool lwip_route_hook_supervisor_running(void);
static esp_timer_create_args_t timer;
static struct tcpip_callback_msg fixture_msg, *queued;
static int mode, msg_calls, delays, task_calls, timer_deleted;
static bool timer_active, can_spawn;
static void (*worker)(void *);
static bool core, leased, reject_mailbox, tailnet_on=true, upstream_present=true, upstream_changed;
static uint32_t generation=1, tailscale_exit_node_ip;
static bool tailscale_accept_routes=true, s_wg_udp_pinned;
static int64_t now_us;
static int pins, publications, published_count;
struct netif {bool up;uint8_t ifindex;};
static struct netif sta={true,1}, wg={true,2}, eth={true,3};
static struct netif *netif_default=&sta, *preferred, *last_pin;
typedef int esp_err_t;
typedef struct {uint8_t upstream_ifindex;} microlink_t;
static microlink_t active;
struct udp_pcb {int unused;};
static struct udp_pcb pcb, *s_wg_output_pcb=&pcb;
#define LWIP_ASSERT_CORE_LOCKED() assert(core)
struct ifreq {char ifr_name[6];};
#define SOL_SOCKET 1
#define SO_BINDTODEVICE 2
static unsigned socket_binds;
static int netifapi_netif_index_to_name(uint8_t index,char *name){
    assert(!core && !leased && index==eth.ifindex);
    if(!upstream_present)return -1;
    if(upstream_changed)__atomic_store_n(&active.upstream_ifindex,sta.ifindex,__ATOMIC_RELEASE);
    strcpy(name,"en2");return ERR_OK;
}
static int ml_setsockopt(int fd,int level,int option,const struct ifreq *ifr,size_t size){
    assert(fd==7 && level==SOL_SOCKET && option==SO_BINDTODEVICE && size==sizeof *ifr && !strcmp(ifr->ifr_name,"en2"));
    socket_binds++;return 0;
}
#define TAILSCALE_ACCEPTED_ROUTES_MAX 32
typedef struct {uint32_t network; uint8_t prefix_len;} tailscale_accepted_route_t;
typedef struct {int subnet_route_count; tailscale_accepted_route_t subnet_routes[1];} microlink_peer_info_t;
static bool tailscale_lifecycle_try_acquire(void){if(leased)return false;leased=true;return true;}
static void tailscale_lifecycle_release(void){assert(leased);leased=false;}
static uint32_t tailscale_lifecycle_generation(void){assert(leased);return generation;}
static microlink_t *tailscale_get_microlink(void){assert(leased);return tailnet_on ? &active : NULL;}
static int microlink_get_peer_count(microlink_t *ml){assert(ml==&active && leased && !core);return 1;}
static int microlink_get_peer_info(microlink_t *ml,int i,microlink_peer_info_t *p){
    assert(ml==&active && i==0 && leased && !core);
    *p=(microlink_peer_info_t){.subnet_route_count=1,.subnet_routes={{0xc0000200,24}}};return ESP_OK;
}
static struct netif *find_sta_netif(void){assert(core && leased);return &sta;}
static struct netif *find_wg_netif(void){assert(core && leased);return &wg;}
static struct netif *eth_uplink_lwip_select(struct netif *n){assert(n==&sta && core);return preferred;}
static struct netif *cell_uplink_lwip_select(struct netif *n){assert(n && core);return NULL;}
static void cell_dns_follow(struct netif *n,struct netif *lan){assert(!n && lan && core);}
static bool netif_is_up(struct netif *n){assert(core);return n->up;}
static void netif_set_default(struct netif *n){
    assert(core && leased);
    if(n==&wg)assert(last_pin==&sta || last_pin==&eth);
    netif_default=n;
}
static uint8_t netif_get_index(struct netif *n){assert(core && n);return n->ifindex;}
static void udp_bind_netif(struct udp_pcb *p, struct netif *n){
    assert(core && leased && p==&pcb);
    last_pin=n;pins++;
}
static void publish_accepted_routes(const tailscale_accepted_route_t *routes,int count){
    assert(core && leased && (count==0 || (count==1 && routes[0].prefix_len==24)));
    publications++;published_count=count;
}
static int64_t esp_timer_get_time(void){return now_us;}
static int tcpip_callbackmsg_trycallback(struct tcpip_callback_msg *msg){
    assert(!queued && !leased && !core && msg==&fixture_msg);
    if(reject_mailbox)return -1;
    queued=msg;return ERR_OK;
}
static void run_queued(void){
    assert(queued);
    struct tcpip_callback_msg *msg=queued;queued=NULL;
    core=true;msg->callback(msg->ctx);core=false;
}
static struct tcpip_callback_msg *tcpip_callbackmsg_new(void (*callback)(void *),void *ctx){
    assert(ctx && !lwip_route_hook_supervisor_running());
    if(++msg_calls<7)return NULL;
    fixture_msg=(struct tcpip_callback_msg){callback,ctx};
    return &fixture_msg;
}
static void vTaskDelay(unsigned ms){
    const unsigned expected[]={2000,4000,8000,16000,30000,30000};
    assert(!lwip_route_hook_supervisor_running() && delays<6 && ms==expected[delays++]);
}
static int xTaskCreateWithCaps(void (*entry)(void *),const char *name,int stack,void *arg,int priority,void *out,int caps){
    assert(entry && !strcmp(name,"exit_route") && stack==5120 && !arg && priority==5 && !out && caps==MALLOC_CAP_SPIRAM);
    assert(!worker && !lwip_route_hook_supervisor_running());
    task_calls++;
    if(!can_spawn)return -1;
    worker=entry;return pdPASS;
}
static int esp_timer_create(const esp_timer_create_args_t *args,esp_timer_handle_t *out){
    assert(args->callback && args->name && args->skip_unhandled_events);
    if(mode==2)return -1;
    timer=*args;*out=&timer;return ESP_OK;
}
static int esp_timer_start_periodic(esp_timer_handle_t handle,uint64_t delay){
    assert(handle==&timer && delay==5000000 && !timer_active);
    if(mode==3)return -1;
    timer_active=true;return ESP_OK;
}
static void esp_timer_stop(esp_timer_handle_t handle){assert(handle==&timer && timer_active);timer_active=false;}
static void esp_timer_delete(esp_timer_handle_t handle){assert(handle==&timer && !timer_active);timer_deleted++;}
@@MICROLINK@@
@@STARTUP@@
int main(int argc,char **argv){
    assert(argc==2);
    mode=atoi(argv[1]);can_spawn=mode==0;
    assert(!lwip_route_hook_supervisor_running());
    lwip_route_hook_init();lwip_route_hook_init();
    assert(task_calls==1);
    if(mode>=2){
        assert(!s_supervisor_retry && !timer_active && timer_deleted==(mode==3));
        assert(!worker && !lwip_route_hook_supervisor_running());
        return 0;
    }
    if(mode==1){
        assert(!worker && timer_active && s_supervisor_retry);
        timer.callback(NULL);
        assert(task_calls==2 && timer_active && !worker && !lwip_route_hook_supervisor_running());
        can_spawn=true;timer.callback(NULL);
        assert(task_calls==3 && !timer_active && !s_supervisor_retry && timer_deleted==1);
        lwip_route_hook_init();assert(task_calls==3);
    } else {
        assert(!timer_active && !s_supervisor_retry);
    }
    assert(worker && !lwip_route_hook_supervisor_running());
    worker(NULL);
    assert(lwip_route_hook_supervisor_running() && msg_calls==7 && delays==6);
    supervisor_request_t *request=fixture_msg.ctx;
    reject_mailbox=true;route_supervisor_poll(request,&fixture_msg);
    assert(!leased && !queued && !request->pending && lwip_route_hook_supervisor_degraded());
    reject_mailbox=false;route_supervisor_poll(request,&fixture_msg);
    assert(!leased && queued && request->pending);
    now_us+=ROUTE_REQUEST_MAX_US+1;route_supervisor_poll(request,&fixture_msg);
    assert(queued && request->pending && lwip_route_hook_supervisor_degraded());
    run_queued();assert(!request->pending && !publications && !leased);
    route_supervisor_poll(request,&fixture_msg);
    generation++;run_queued();assert(!publications && !request->pending);
    route_supervisor_poll(request,&fixture_msg);
    leased=true;run_queued();assert(leased && !publications);leased=false;
    tailscale_exit_node_ip=0x64400001;s_wg_output_pcb=NULL;
    route_supervisor_poll(request,&fixture_msg);run_queued();
    assert(!pins && netif_default==&sta && lwip_route_hook_supervisor_degraded());
    s_wg_output_pcb=&pcb;preferred=&eth;
    route_supervisor_poll(request,&fixture_msg);run_queued();
    assert(pins==1 && netif_default==&wg && last_pin==&eth && !lwip_route_hook_supervisor_degraded());
    assert(s_supervisor_keepalive==tailscale_exit_node_ip && published_count==1 && active.upstream_ifindex==eth.ifindex);
    ml_bind_sock_to_upstream(&active,7);
    assert(socket_binds==1);
    upstream_present=false;ml_bind_sock_to_upstream(&active,7);
    assert(socket_binds==1);
    upstream_present=true;upstream_changed=true;ml_bind_sock_to_upstream(&active,7);
    assert(socket_binds==1);
    tailscale_accept_routes=false;tailscale_exit_node_ip=0;
    route_supervisor_poll(request,&fixture_msg);run_queued();
    assert(netif_default==&eth && !last_pin && !s_wg_udp_pinned && s_supervisor_keepalive==0 && published_count==0);
    assert(!active.upstream_ifindex);
    puts("PASS: route supervisor admission, bounded mailbox, route pin before default, stale generation and recovery");
}
'''
with tempfile.TemporaryDirectory(prefix='route-supervisor-') as directory:
    path = Path(directory)
    c = path / 'test.c'
    c.write_text(startup_fixture.replace('@@STARTUP@@', startup).replace('@@MICROLINK@@', microlink_pin), encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(binary)], check=True)
    for mode in range(4):
        subprocess.run([str(binary), str(mode)], check=True, timeout=10)
