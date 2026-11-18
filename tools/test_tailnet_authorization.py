"""Actual pinned MicroLink policy C, synthetic map/pbuf/clock/transport.

NOT a WireGuard crypto test, physical ESP test, or two-real-client ACL test.
Set POLICY_SANITIZE=1 for ASan/UBSan; POLICY_NO_PIE=1 for affected WSL hosts.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'

HEAD = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include "ml_policy.h"
#include "lwip/pbuf.h"
static _Atomic unsigned allocation_fail;
static _Atomic uint32_t clock_ms=1000;
void *policy_test_alloc(size_t n) {return allocation_fail ? NULL : malloc(n);}
uint32_t policy_test_now(void) {return clock_ms;}
static uint8_t key_a[32]={[31]=1}, key_b[32]={[31]=2};
#define KEY_A "nodekey:0000000000000000000000000000000000000000000000000000000000000001"
#define KEY_B "nodekey:0000000000000000000000000000000000000000000000000000000000000002"
#define NODE "\"Node\":{\"Addresses\":[\"100.64.0.10/32\",\"fd7a:115c:a1e0::10/128\"],\"AllowedIPs\":[\"100.64.0.10/32\",\"192.0.2.0/24\",\"fd7a:115c:a1e0::10/128\",\"fd7a:115c:a1e0:b1a:0:1:c000:200/120\"]}"
#define PEER_A "{\"ID\":1,\"Key\":\"" KEY_A "\",\"Addresses\":[\"100.64.0.1/32\",\"fd7a:115c:a1e0::1/128\"]}"
#define PEER_B "{\"ID\":2,\"Key\":\"" KEY_B "\",\"Addresses\":[\"100.64.0.2/32\",\"fd7a:115c:a1e0::2/128\"]}"
#define PEER_LIST "\"Peers\":[" PEER_A "," PEER_B "]"
#define TCP_RULE "{\"SrcIPs\":[\"100.64.0.1\"],\"IPProto\":[6],\"DstPorts\":[{\"IP\":\"100.64.0.10\",\"Ports\":{\"First\":80,\"Last\":80}}]}"
#define UDP_RULE "{\"SrcIPs\":[\"100.64.0.1\"],\"IPProto\":[17],\"DstPorts\":[{\"IP\":\"192.0.2.0/24\",\"Ports\":{\"First\":53,\"Last\":53}}]}"
#define ALL_RULE "{\"SrcIPs\":[\"*\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":0,\"Last\":65535}}]}"
#define FULL "{" NODE "," PEER_LIST ",\"PacketFilter\":[" TCP_RULE "," UDP_RULE "]}"
#define ALL "{" NODE "," PEER_LIST ",\"PacketFilter\":[" ALL_RULE "]}"
static bool apply(const char *s) {
    cJSON *v=cJSON_Parse(s);assert(v);bool ok=ml_policy_apply(v);cJSON_Delete(v);return ok;
}
static struct pbuf packet(unsigned family,unsigned proto,const char *src,const char *dst,unsigned sp,unsigned dp,unsigned flags,unsigned split) {
    static _Thread_local uint8_t bytes[128];
    static _Thread_local struct pbuf tail;
    memset(bytes,0,sizeof bytes);
    unsigned h=family==4?20:40, transport=proto==6?20:8, n=h+transport;
    if (family==4) {
        bytes[0]=0x45;bytes[2]=n>>8;bytes[3]=n;bytes[8]=64;bytes[9]=proto;
        uint8_t unused;assert(ip_parse(src,bytes+12,&unused));assert(ip_parse(dst,bytes+16,&unused));
    } else {
        bytes[0]=0x60;bytes[4]=transport>>8;bytes[5]=transport;bytes[6]=proto;bytes[7]=64;
        uint8_t unused;assert(ip_parse(src,bytes+8,&unused));assert(ip_parse(dst,bytes+24,&unused));
    }
    bytes[h]=sp>>8;bytes[h+1]=sp;bytes[h+2]=dp>>8;bytes[h+3]=dp;
    if(proto==6){bytes[h+12]=0x50;bytes[h+13]=flags;}
    if(proto==17){bytes[h+4]=transport>>8;bytes[h+5]=transport;}
    if(proto==1||proto==58){bytes[h]=flags;bytes[h+1]=0;bytes[h+4]=sp>>8;bytes[h+5]=sp;}
    struct pbuf p={.payload=bytes,.tot_len=n,.len=n};
    if(split && split<n){tail=(struct pbuf){.payload=bytes+split,.tot_len=n-split,.len=n-split};p.next=&tail;p.len=split;}
    return p;
}
static bool rx(unsigned family,unsigned proto,const char *src,const char *dst,unsigned sp,unsigned dp,unsigned flags,const uint8_t key[32]) {
    struct pbuf p=packet(family,proto,src,dst,sp,dp,flags,0);return ml_policy_rx(&p,key);
}
static void standard(void){ml_policy_reset();assert(apply(FULL));}
'''

BODY = r'''
static void basics(void) {
    ml_policy_reset();
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{" NODE "," PEER_LIST "}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"PacketFilter\":null}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    standard();
    for(unsigned split=0;split<40;split++) {
        struct pbuf p=packet(4,6,"100.64.0.1","100.64.0.10",40000,80,2,split);
        assert(ml_policy_rx(&p,key_a));
    }
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,22,2,key_a));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,22,0x10,key_a));
    assert(!rx(4,17,"100.64.0.1","100.64.0.10",40000,80,0,key_a));
    assert(!rx(4,6,"100.64.0.2","100.64.0.10",40000,80,2,key_b));
    assert(ml_policy_peer_status(key_b)==1); /* Visibility is not port permission. */
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_b));
    assert(rx(4,17,"100.64.0.1","192.0.2.50",40000,53,0,key_a));
    assert(!rx(4,17,"100.64.0.1","192.0.2.50",40000,54,0,key_a));
    assert(!rx(4,6,"100.64.0.1","192.0.2.50",40000,53,2,key_a));
    assert(apply("{\"KeepAlive\":true}"));
    assert(apply("{\"PacketFilter\":null,\"PacketFilters\":null}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"PacketFilter\":[]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply(ALL));
    assert(!rx(4,6,"100.64.0.1","198.51.100.10",40000,80,2,key_a));
    assert(rx(6,6,"fd7a:115c:a1e0::1","fd7a:115c:a1e0::10",40000,80,2,key_a));
    assert(!rx(6,6,"fd7a:115c:a1e0::2","fd7a:115c:a1e0::10",40000,80,2,key_a));
    assert(rx(6,6,"fd7a:115c:a1e0::1","fd7a:115c:a1e0:b1a:0:1:c000:232",40000,22,2,key_a));
    assert(rx(4,1,"100.64.0.1","100.64.0.10",123,0,8,key_a));
    assert(!rx(4,1,"100.64.0.1","100.64.0.10",123,0,3,key_a));
    puts("PASS: missing/null/empty policy, visible-but-unauthorized peer, TCP/UDP ports/protocols, direct/subnet/4via6 original-address checks, pbuf splits");
}
static void deltas(void) {
    standard();
    assert(apply("{\"PacketFilters\":{\"extra\":[" ALL_RULE "]}}"));
    assert(rx(4,6,"100.64.0.2","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"PacketFilter\":[]}"));
    assert(rx(4,6,"100.64.0.2","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"PacketFilter\":[],\"PacketFilters\":{\"extra\":null}}"));
    assert(!rx(4,6,"100.64.0.2","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"PacketFilter\":[" ALL_RULE "],\"PacketFilters\":{\"*\":null,\"limited\":[" TCP_RULE "]}}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(!rx(4,6,"100.64.0.2","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"PeersRemoved\":[1]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"PeersChanged\":[" PEER_A "]}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"Peers\":[" PEER_B "]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    standard();
    assert(!apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"Key\":\"" KEY_B "\"}]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    standard();
    /* Rotation to a new key (seamless renewal): applied, old key revoked now. */
    assert(apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"Key\":\"nodekey:0000000000000000000000000000000000000000000000000000000000000003\"}]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    {uint8_t key_c[32]={[31]=3};assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_c));}
    ml_policy_reset();assert(apply("{\"KeepAlive\":true}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"PacketFilter\":[" ALL_RULE "]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    puts("PASS: named replacement/deletion/clear, legacy+named ordering, authoritative omission, immediate peer revoke/key rotation independent of WG queue, reconnect incomplete map");
}
static void replies(void) {
    const char *empty="{" NODE "," PEER_LIST ",\"PacketFilter\":[]}";
    assert(apply(empty));
    for(unsigned proto=6;proto<=17;proto+=11) {
        assert(!rx(4,proto,"100.64.0.1","100.64.0.10",22,45000,0x12,key_a));
        struct pbuf out=packet(4,proto,"100.64.0.10","100.64.0.1",45000,22,2,0);
        assert(ml_policy_tx(&out,key_a));ml_policy_sent(&out,key_a);
        assert(rx(4,proto,"100.64.0.1","100.64.0.10",22,45000,0x12,key_a));
        assert(!rx(4,proto,"100.64.0.1","100.64.0.10",23,45000,0x12,key_a));
        assert(!rx(4,proto,"100.64.0.2","100.64.0.10",22,45000,0x12,key_b));
        if(proto==6) assert(!rx(4,proto,"100.64.0.1","100.64.0.10",22,45000,2,key_a));
        clock_ms+=120001;
        assert(!rx(4,proto,"100.64.0.1","100.64.0.10",22,45000,0x12,key_a));
    }
    /* NATed LAN -> Tailnet tuples at the WG boundary, NOT remote service authorization. */
    assert(apply("{\"PacketFilter\":[" TCP_RULE "]}"));
    struct pbuf out=packet(4,6,"100.64.0.10","100.64.0.1",50001,22,2,0);
    assert(ml_policy_tx(&out,key_a));ml_policy_sent(&out,key_a);
    assert(rx(4,6,"100.64.0.1","100.64.0.10",22,50001,0x12,key_a));
    assert(apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"Online\":true,\"Endpoints\":[\"192.0.2.1:1234\"]}]}"));
    assert(apply("{\"PacketFilter\":[" TCP_RULE "]}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",22,50001,0x12,key_a));
    assert(apply("{\"PacketFilter\":[]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",22,50001,0x12,key_a));
    out=packet(4,6,"100.64.0.10","100.64.0.1",50001,22,0x10,0);ml_policy_sent(&out,key_a);
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",22,50001,0x10,key_a));
    for(unsigned i=0;i<40;i++) {
        out=packet(4,17,"100.64.0.10","100.64.0.1",51000+i,53,0,0);ml_policy_sent(&out,key_a);clock_ms++;
    }
    assert(!rx(4,17,"100.64.0.1","100.64.0.10",53,51000,0,key_a));
    assert(rx(4,17,"100.64.0.1","100.64.0.10",53,51039,0,key_a));
    ml_policy_reset();out=packet(4,17,"100.64.0.10","100.64.0.1",51039,53,0,0);
    assert(!ml_policy_tx(&out,key_a));ml_policy_sent(&out,key_a);
    assert(apply(empty));assert(!rx(4,17,"100.64.0.1","100.64.0.10",53,51039,0,key_a));
    puts("PASS: TCP/UDP bounded reverse flows, wrong peer/port and unsolicited SYN denied, timeout/eviction, revocation and reconnect invalidate return state");
}
static void invalid(void) {
    const char *bad[]={
        "{\"PacketFilter\":{}}", "{\"PacketFilters\":[]}",
        "{\"PacketFilter\":[],\"PacketFilter\":[" ALL_RULE "]}",
        "{\"packetfilter\":[]}", "{\"peers\":[]}",
        "{\"PeersChangedPatch\":[{\"NodeID\":1,\"key\":\"" KEY_B "\"}]}",
        "{\"PeersChangedPatch\":[{\"NodeID\":1,\"AllowedIPs\":[]}]}",
        "{\"PacketFilters\":{\"*\":[]}}",
        /* "cap:" sources narrow (admit nobody) instead of refusing: cap_sources(). */
        "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"SrcBits\":[0],\"DstPorts\":[]}]}",
        "{\"PacketFilter\":[{\"SrcIPs\":[\"*\"],\"Action\":\"accept\",\"DstPorts\":[]}]}",
        "{\"PeersChanged\":[{\"ID\":1,\"Key\":\"" KEY_A "\",\"AllowedIPs\":[\"0.0.0.0/33\"]}]}",
        "{\"PeersChanged\":[{\"ID\":1,\"Key\":\"" KEY_A "\",\"AllowedIPs\":[\"100.64.0.1/32junk\"]}]}",
        "{\"PeersChanged\":[{\"ID\":1,\"Key\":\"" KEY_A "\",\"KeyExpiry\":\"2040-02-30T00:00:00Z\",\"Addresses\":[]}]}",
        "{\"PeersChangedPatch\":[{\"ID\":1}]}", "{\"Node\":{}}"
    };
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++) {
        standard();assert(!apply(bad[i]));
        assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    }
    standard();allocation_fail=1;assert(!apply("{\"PacketFilter\":[]}"));allocation_fail=0;
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply(ALL));
    for(unsigned i=0;i<100000;i++) {
        struct pbuf p=packet(4,6,"100.64.0.1","100.64.0.10",40000,80,2,0);
        uint8_t *b=p.payload;
        switch(i%5) {
            case 0:b[6]=0x20;break; /* first fragment */
            case 1:b[7]=1;break; /* later fragment */
            case 2:b[0]=0x44;break;
            case 3:b[32]=0x40;break;
            default:p.tot_len=i%39;break;
        }
        assert(!ml_policy_rx(&p,key_a));
    }
    struct pbuf p=packet(6,6,"fd7a:115c:a1e0::1","fd7a:115c:a1e0::10",40000,80,2,0);
    ((uint8_t*)p.payload)[6]=44;assert(!ml_policy_rx(&p,key_a));
    assert(apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"KeyExpiry\":\"2000-01-01T00:00:00Z\"}]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"KeyExpiry\":null}]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(!apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"KeyExpiry\":\"0001-01-01T00:00:00.999Z\"}]}"));
    puts("PASS: malformed/duplicate/unsupported policy fail closed, PSRAM failure, 100000 malformed/fragment packets, expired key");
}
static void ownership(void) {
    assert(apply(ALL));
    assert(apply("{\"PeersChanged\":[{\"ID\":2,\"Key\":\"" KEY_B "\",\"AllowedIPs\":[\"0.0.0.0/0\"]}]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_b));
    assert(!rx(4,6,"100.64.0.99","100.64.0.10",40000,80,2,key_b));
    assert(rx(4,6,"203.0.113.50","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"PeersChanged\":[{\"ID\":2,\"Key\":\"" KEY_B "\",\"AllowedIPs\":[]}]}"));
    assert(!rx(4,6,"203.0.113.50","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"PeersChangedPatch\":[{\"NodeID\":1,\"Expired\":true}]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    puts("PASS: longest-prefix ownership, exit route cannot spoof CGNAT identity, empty AllowedIPs and expired peer deny");
}
/* Every array of the policy allocation is 16-byte aligned for any number of
 * rules, peers and prefixes: with an odd rule count the peer table started on
 * a 2-byte boundary (106-byte rules), a LoadStoreAlignment restart on the
 * ESP32-S3 and undefined behaviour on the host. */
static void layout_alignment(void) {
    for (uint32_t e=0;e<9;e++) for (uint32_t pc=1;pc<4;pc++) for (uint32_t pool=1;pool<4;pool++) for (int ix=0;ix<2;ix++) {
        policy *q=policy_alloc_ix(pc,pool,e,ix);assert(q);
        assert(((uintptr_t)q->entries&15)==0&&((uintptr_t)q->peers&15)==0&&((uintptr_t)q->pool&15)==0);
        assert((uint8_t *)q->peers>=(uint8_t *)(q->entries+e)&&(uint8_t *)q->pool>=(uint8_t *)(q->peers+pc));
        if (ix) assert(((uintptr_t)q->index&15)==0&&((uintptr_t)q->ix_groups&15)==0
                       &&(uint8_t *)q->index>=(uint8_t *)(q->pool+pool)&&(uint8_t *)q->ix_groups>=(uint8_t *)(q->index+pool));
        q->peers[pc-1].id=~0ull;q->peers[pc-1].expires=1;q->pool[pool-1].bits=128;   /* last slots writable */
        free(q);
    }
}
static void bounds_and_ranges(void) {
    for(unsigned scenario=0;scenario<5;scenario++) {
        assert(apply(ALL));cJSON *map=cJSON_CreateObject();assert(map);
        if(scenario==0) {
            cJSON *groups=cJSON_AddObjectToObject(map,"PacketFilters");
            for(unsigned i=0;i<33;i++){char name[8];snprintf(name,sizeof name,"g%u",i);assert(cJSON_AddArrayToObject(groups,name));}
        } else if(scenario==1) {
            /* An inverted port range is invalid (rule count has no cap). */
            cJSON *rules=cJSON_AddArrayToObject(map,"PacketFilter");
            cJSON *rule=cJSON_Parse("{\"SrcIPs\":[\"100.64.0.1\"],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":90,\"Last\":80}}]}");
            assert(rule);cJSON_AddItemToArray(rules,rule);
        } else if(scenario==2) {
            /* Same ID 17 times: a duplicate, not a count limit (there is none). */
            cJSON *peers=cJSON_AddArrayToObject(map,"Peers");
            for(unsigned i=0;i<17;i++)cJSON_AddItemToArray(peers,cJSON_Parse(PEER_A));
        } else if(scenario==3) {
            /* A range is not a valid AllowedIPs prefix. */
            cJSON *peers=cJSON_AddArrayToObject(map,"PeersChanged"), *peer=cJSON_Parse(PEER_A);
            cJSON_AddItemToArray(peers,peer);cJSON *ips=cJSON_AddArrayToObject(peer,"AllowedIPs");
            cJSON_AddItemToArray(ips,cJSON_CreateString("100.64.0.1/32"));
            cJSON_AddItemToArray(ips,cJSON_CreateString("100.64.0.1-100.64.0.2"));
        } else {
            cJSON *groups=cJSON_AddObjectToObject(map,"PacketFilters");char name[65];memset(name,'x',64);name[64]=0;
            assert(cJSON_AddArrayToObject(groups,name));
        }
        assert(!ml_policy_apply(map));cJSON_Delete(map);
        assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    }
    assert(apply(ALL));
    assert(apply("{\"PacketFilters\":{\"*\":null,\"g0\":[],\"g1\":[],\"g2\":[],\"g3\":[],\"g4\":[],\"g5\":[],\"g6\":[],\"g7\":[]}}"));
    assert(apply("{\"PacketFilters\":{\"new\":[" TCP_RULE "],\"g0\":null}}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(apply("{\"PacketFilters\":{\"new\":null,\"g0\":[" TCP_RULE "]}}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    ml_policy_reset();
    assert(apply(ALL));
    assert(apply("{\"PacketFilter\":[{\"SrcIPs\":[\"100.64.0.1-100.64.0.2\"],\"IPProto\":[6],\"DstPorts\":[{\"IP\":\"192.0.2.0/24\",\"Ports\":{\"First\":100,\"Last\":102}}]}]}"));
    assert(rx(4,6,"100.64.0.2","192.0.2.255",40000,102,2,key_b));
    assert(!rx(4,6,"100.64.0.2","192.0.2.255",40000,103,2,key_b));
    assert(apply("{\"Node\":{\"AllowedIPs\":[\"100.64.0.10/32\"]}}"));
    assert(!rx(4,6,"100.64.0.2","192.0.2.255",40000,102,2,key_b));
    assert(apply(ALL));
    assert(apply("{\"PacketFilter\":[{\"SrcIPs\":[\"fd7a:115c:a1e0::1-fd7a:115c:a1e0::2\"],\"IPProto\":[17],\"DstPorts\":[{\"IP\":\"fd7a:115c:a1e0::10/128\",\"Ports\":{\"First\":53530,\"Last\":53530}}]}]}"));
    assert(rx(6,17,"fd7a:115c:a1e0::2","fd7a:115c:a1e0::10",40000,53530,0,key_b));
    assert(!rx(6,17,"fd7a:115c:a1e0::2","fd7a:115c:a1e0::10",40000,53531,0,key_b));
    puts("PASS: all snapshot capacity/name limits fail closed; IPv4/IPv6 ranges, CIDR endpoints, port-range bounds, local AllowedIPs shrink");
}
static void *reader(void *unused) {
    (void)unused;
    for(unsigned i=0;i<15000;i++) {
        (void)rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a);
        assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,22,2,key_a));
    }
    return NULL;
}
static void concurrency(void) {
    standard();pthread_t threads[3];
    for(unsigned i=0;i<3;i++)assert(!pthread_create(&threads[i],NULL,reader,NULL));
    for(unsigned i=0;i<2000;i++) {assert(apply(FULL));assert(apply("{\"PacketFilter\":[]}"));}
    for(unsigned i=0;i<3;i++)assert(!pthread_join(threads[i],NULL));
    ml_policy_reset();
    puts("PASS: 4000 atomic policy publications with three concurrent packet readers; no denied port ever admitted");
}
static cJSON *fixture_peer(unsigned id,unsigned address) {
    cJSON *p=cJSON_CreateObject();assert(p);char key[80],ip[40];
    snprintf(key,sizeof key,"nodekey:%064x",id);
    snprintf(ip,sizeof ip,"100.64.1.%u/32",address);
    assert(cJSON_AddNumberToObject(p,"ID",id));assert(cJSON_AddStringToObject(p,"Key",key));
    cJSON *addresses=cJSON_AddArrayToObject(p,"Addresses");assert(addresses);
    assert(cJSON_AddItemToArray(addresses,cJSON_CreateString(ip)));return p;
}
static void peer_replacement(void) {
    ml_policy_reset();cJSON *full=cJSON_Parse("{" NODE ",\"PacketFilter\":[" ALL_RULE "]}");assert(full);
    cJSON *peers=cJSON_AddArrayToObject(full,"Peers");assert(peers);
    for(unsigned id=1;id<=16;id++)assert(cJSON_AddItemToArray(peers,fixture_peer(id,id)));
    assert(ml_policy_apply(full));cJSON_Delete(full);
    assert(rx(4,6,"100.64.1.1","100.64.0.10",40000,80,2,key_a));
    cJSON *delta=cJSON_Parse("{\"PeersRemoved\":[1],\"PeersChanged\":[]}");assert(delta);
    assert(cJSON_AddItemToArray(cJSON_GetObjectItemCaseSensitive(delta,"PeersChanged"),fixture_peer(17,17)));
    assert(ml_policy_apply(delta));cJSON_Delete(delta);
    uint8_t new_key[32]={[31]=17};
    assert(!rx(4,6,"100.64.1.1","100.64.0.10",40000,80,2,key_a));
    assert(rx(4,6,"100.64.1.17","100.64.0.10",40000,80,2,new_key));
    assert(rx(4,6,"100.64.1.2","100.64.0.10",40000,80,2,key_b));
    /* Official delta order: remove first, then upsert; re-added ID wins. */
    delta=cJSON_Parse("{\"PeersRemoved\":[2],\"PeersChanged\":[]}");assert(delta);
    cJSON *rotated=fixture_peer(18,2);assert(cJSON_ReplaceItemInObjectCaseSensitive(rotated,"ID",cJSON_CreateNumber(2)));
    assert(cJSON_AddItemToArray(cJSON_GetObjectItemCaseSensitive(delta,"PeersChanged"),rotated));
    assert(ml_policy_apply(delta));cJSON_Delete(delta);new_key[31]=18;
    assert(!rx(4,6,"100.64.1.2","100.64.0.10",40000,80,2,key_b));
    assert(rx(4,6,"100.64.1.2","100.64.0.10",40000,80,2,new_key));
    /* Nonempty full Peers takes precedence over all peer deltas. */
    full=cJSON_Parse("{\"Peers\":[" PEER_A "],\"PeersChanged\":[" PEER_B "],\"PeersRemoved\":[1],\"PeersChangedPatch\":[{\"NodeID\":1,\"Expired\":true}]}");assert(full);
    assert(ml_policy_apply(full));cJSON_Delete(full);
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(!rx(4,6,"100.64.0.2","100.64.0.10",40000,80,2,key_b));
    assert(apply("{\"KeepAlive\":true,\"PacketFilter\":[],\"PeersRemoved\":[1]}"));
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    ml_policy_reset();
    assert(apply("{\"KeepAlive\":true," NODE "," PEER_LIST ",\"PacketFilter\":[" ALL_RULE "]}"));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    puts("PASS: full-capacity peer replacement, removal-before-upsert, full-map precedence and keepalive fields cannot mutate/initialize authority");
}
/* Maps of any size: no 16-peer / 16-prefix cap (a tailnet of 18 devices was
 * refused whole as "peer-update" in 3.0.24 and blocked the tunnel). */
static void peer_json(char *out,size_t cap,unsigned i,unsigned key,unsigned routes) {
    int n=snprintf(out,cap,"{\"ID\":%u,\"Key\":\"nodekey:%060x%04x\",\"Addresses\":[\"100.65.%u.%u/32\"],\"AllowedIPs\":[\"100.65.%u.%u/32\"",
                   i,0u,key,i/256,i%256,i/256,i%256);
    for(unsigned r=0;r<routes;r++) n+=snprintf(out+n,cap-n,",\"10.%u.%u.0/24\"",i%200,r);
    snprintf(out+n,cap-n,"]}");
}
static cJSON *large_map(unsigned peers,unsigned routes_of_last,int dup_key_of) {
    cJSON *map=cJSON_Parse("{" NODE ",\"PacketFilter\":[" ALL_RULE "]}");assert(map);
    cJSON *list=cJSON_AddArrayToObject(map,"Peers");char text[4096];
    for(unsigned i=1;i<=peers;i++){
        unsigned key=(dup_key_of>0&&i==peers)?(unsigned)dup_key_of:i;
        peer_json(text,sizeof text,i,key,i==peers?routes_of_last:0);
        cJSON *v=cJSON_Parse(text);assert(v);cJSON_AddItemToArray(list,v);
    }
    return map;
}
static void key_of(uint8_t key[32],unsigned i){memset(key,0,32);key[30]=(uint8_t)(i>>8);key[31]=(uint8_t)i;}
static void large_maps(void) {
    uint8_t k300[32],k7[32],k301[32];key_of(k300,300);key_of(k7,7);key_of(k301,301);
    ml_policy_reset();
    cJSON *map=large_map(300,40,0);assert(ml_policy_apply(map));cJSON_Delete(map);
    ml_policy_status_t st;ml_policy_get_status(&st);assert(st.authority_ready&&st.peers==300);
    /* Ownership still exact among 300 peers and 41 prefixes of one peer. */
    assert(rx(4,6,"100.65.1.44","100.64.0.10",40000,80,2,k300));
    assert(!rx(4,6,"100.65.1.44","100.64.0.10",40000,80,2,k7));
    assert(rx(4,6,"10.100.39.7","100.64.0.10",40000,80,2,k300));
    assert(!rx(4,6,"10.100.39.7","100.64.0.10",40000,80,2,k7));
    /* Deltas on a large authority: join, then removal. */
    char text[512];peer_json(text,sizeof text,301,301,0);
    char delta[600];snprintf(delta,sizeof delta,"{\"PeersChanged\":[%s]}",text);
    assert(apply(delta));ml_policy_get_status(&st);assert(st.peers==301);
    assert(rx(4,6,"100.65.1.45","100.64.0.10",40000,80,2,k301));
    assert(apply("{\"PeersRemoved\":[300]}"));ml_policy_get_status(&st);assert(st.peers==300);
    assert(!rx(4,6,"100.65.1.44","100.64.0.10",40000,80,2,k300));
    /* A duplicate key among many peers is still refused, with its reason. */
    map=large_map(64,0,7);assert(!ml_policy_apply(map));cJSON_Delete(map);
    assert(!strcmp(ml_policy_last_reject(),"duplicate-peer"));
    assert(!rx(4,6,"100.65.0.7","100.64.0.10",40000,80,2,k7));
    /* 2000 peers: accepted (memory, not a constant, is the bound). */
    map=large_map(2000,0,0);assert(ml_policy_apply(map));cJSON_Delete(map);
    ml_policy_get_status(&st);assert(st.peers==2000);
    uint8_t k1999[32];key_of(k1999,1999);
    assert(rx(4,6,"100.65.7.207","100.64.0.10",40000,80,2,k1999));
    /* Allocation failure: refused as no-memory, data blocked, not a crash. */
    allocation_fail=1;map=large_map(20,0,0);assert(!ml_policy_apply(map));cJSON_Delete(map);allocation_fail=0;
    assert(!strcmp(ml_policy_last_reject(),"no-memory"));
    assert(!rx(4,6,"100.65.0.7","100.64.0.10",40000,80,2,k7));
    /* Precise reasons instead of one generic "peer-update". */
    assert(!apply("{\"Peers\":[{\"ID\":1,\"Key\":\"nodekey:zz\",\"Addresses\":[\"100.64.0.1/32\"]}]}"));
    assert(!strcmp(ml_policy_last_reject(),"peer-key"));
    assert(!apply("{\"Peers\":[{\"ID\":1,\"Key\":\"" KEY_A "\",\"Addresses\":[\"not-an-ip\"]}]}"));
    assert(!strcmp(ml_policy_last_reject(),"peer-prefixes"));
    assert(!apply("{\"Peers\":[{\"ID\":1,\"Key\":\"" KEY_A "\",\"KeyExpiry\":\"tomorrow\",\"Addresses\":[\"100.64.0.1/32\"]}]}"));
    assert(!strcmp(ml_policy_last_reject(),"peer-expiry"));
    /* ACL rules of any count: 40 sources x 30 destinations = 1200 rules. */
    ml_policy_reset();map=large_map(40,0,0);
    cJSON *pf=cJSON_GetObjectItemCaseSensitive(map,"PacketFilter");cJSON_DeleteItemFromArray(pf,0);
    cJSON *rule=cJSON_CreateObject(),*srcs=cJSON_AddArrayToObject(rule,"SrcIPs"),*dsts=cJSON_AddArrayToObject(rule,"DstPorts");
    cJSON_AddItemToArray(cJSON_AddArrayToObject(rule,"IPProto"),cJSON_CreateNumber(6));
    for(unsigned i=1;i<=40;i++){char ip[32];snprintf(ip,sizeof ip,"100.65.0.%u",i);cJSON_AddItemToArray(srcs,cJSON_CreateString(ip));}
    for(unsigned d=0;d<30;d++){cJSON *dp=cJSON_CreateObject();cJSON_AddStringToObject(dp,"IP","100.64.0.10");
        cJSON *ports=cJSON_AddObjectToObject(dp,"Ports");cJSON_AddNumberToObject(ports,"First",8000+d);cJSON_AddNumberToObject(ports,"Last",8000+d);
        cJSON_AddItemToArray(dsts,dp);}
    cJSON_AddItemToArray(pf,rule);assert(ml_policy_apply(map));cJSON_Delete(map);
    ml_policy_get_status(&st);assert(st.expanded_rules==1200);
    assert(rx(4,6,"100.65.0.7","100.64.0.10",40000,8029,2,k7));
    assert(!rx(4,6,"100.65.0.7","100.64.0.10",40000,8030,2,k7));
    puts("PASS: maps of any size (300 peers with a 41-prefix peer, deltas, 2000 peers, 1200 ACL rules), exact ownership, duplicate and OOM refusals, precise reasons");
    ml_policy_reset();
}
/* The ownership index answers exactly like the reference scan: random maps
 * with nested/overlapping/duplicate prefixes across peers, ties, expired
 * peers, IPv4 and IPv6, CGNAT rules. */
static uint32_t rnd_state=12345;
static uint32_t rnd(void){rnd_state^=rnd_state<<13;rnd_state^=rnd_state>>17;rnd_state^=rnd_state<<5;return rnd_state;}
static void index_differential(void) {
    unsigned checks=0,owned=0;
    for(unsigned round=0;round<60;round++){
        ml_policy_reset();
        cJSON *map=cJSON_Parse("{" NODE ",\"PacketFilter\":[" ALL_RULE "]}");assert(map);
        cJSON *list=cJSON_AddArrayToObject(map,"Peers");unsigned peers=1+rnd()%40;
        for(unsigned i=1;i<=peers;i++){
            char text[2048];int n=snprintf(text,sizeof text,"{\"ID\":%u,\"Key\":\"nodekey:%060x%04x\",%s\"AllowedIPs\":[\"100.66.%u.%u/32\",\"fd7a:115c:a1e0::%x/128\"",
                i,0u,i,(rnd()%7==0)?"\"KeyExpiry\":\"2020-01-01T00:00:00Z\",":"",i/256,i%256,i);
            unsigned extra=rnd()%6;
            for(unsigned r=0;r<extra;r++){
                unsigned kind=rnd()%5,bits;
                if(kind==0){bits=8+rnd()%25;n+=snprintf(text+n,sizeof text-n,",\"10.%u.%u.0/%u\"",rnd()%4,rnd()%4,bits);}
                else if(kind==1){n+=snprintf(text+n,sizeof text-n,",\"0.0.0.0/0\"");}
                else if(kind==2){bits=10+rnd()%23;n+=snprintf(text+n,sizeof text-n,",\"100.66.%u.0/%u\"",rnd()%3,bits);}
                else if(kind==3){bits=48+rnd()%81;n+=snprintf(text+n,sizeof text-n,",\"fd00:%x::/%u\"",rnd()%3,bits);}
                else {n+=snprintf(text+n,sizeof text-n,",\"192.168.%u.0/24\"",rnd()%3);}
            }
            snprintf(text+n,sizeof text-n,"]}");
            cJSON *v=cJSON_Parse(text);assert(v);cJSON_AddItemToArray(list,v);
        }
        assert(ml_policy_apply(map));cJSON_Delete(map);
        policy *cur=acquire();assert(cur&&cur->index);
        for(unsigned q=0;q<400;q++){
            uint8_t ip[16]={0},key[32]={0};unsigned fam=rnd()%4==0?6:4;
            if(fam==4){unsigned pick=rnd()%4;
                if(pick==0){ip[0]=10;ip[1]=rnd()%4;ip[2]=rnd()%4;ip[3]=rnd();}
                else if(pick==1){ip[0]=100;ip[1]=66;ip[2]=rnd()%3;ip[3]=rnd()%(peers+2);}
                else if(pick==2){ip[0]=192;ip[1]=168;ip[2]=rnd()%3;ip[3]=rnd();}
                else {for(int b=0;b<4;b++)ip[b]=rnd();}}
            else {if(rnd()%2){ip[0]=0xfd;ip[1]=0x00;ip[2]=0;ip[3]=rnd()%3;}else{memcpy(ip,(uint8_t[]){0xfd,0x7a,0x11,0x5c,0xa1,0xe0},6);ip[15]=rnd()%(peers+2);}
                for(int b=4;b<15;b++)if(rnd()%3==0)ip[b]=rnd();}
            unsigned who=1+rnd()%peers;
            if(fam==4&&ip[0]==100&&ip[3]>=1&&ip[3]<=peers&&rnd()%2)who=ip[2]*256u+ip[3]; /* the /32 owner, often */
            if(who<1||who>peers)who=1;
            key[30]=(uint8_t)(who>>8);key[31]=(uint8_t)who;
            bool a=peer_owns(cur,key,ip,(uint8_t)fam),b=peer_owns_scan(cur,key,ip,(uint8_t)fam);
            if(a!=b){printf("MISMATCH round %u q %u fam %u\n",round,q,fam);assert(a==b);}
            checks++;owned+=a;
        }
        release(cur);
    }
    if(owned<200){printf("owned only %u\n",owned);assert(owned>=200);}
    printf("PASS: ownership index equals the reference scan on %u random queries (%u owned; 60 random maps with overlaps, ties, expired peers, IPv4/IPv6)\n",checks,owned);
    ml_policy_reset();
}
/* The first map of a session is complete even when Peers / PacketFilter
 * are absent (both omitempty: an empty tailnet omits Peers). Before, a
 * gateway alone in its tailnet never had peer authority, stayed blocked when
 * a device joined, and looped on every reconnect ("delta-while-suspended"). */
#define EMPTY_FIRST "{\"Node\":{\"Addresses\":[\"100.64.0.10/32\"]},\"PacketFilter\":[" ALL_RULE "]}"
static void session_maps(void) {
    ml_policy_status_t st;
    ml_policy_reset();ml_policy_expect_full_map();
    assert(apply(EMPTY_FIRST));ml_policy_get_status(&st);assert(st.authority_ready&&st.peer_authority&&st.peers==0);
    assert(apply("{\"PeersChanged\":[" PEER_A "]}"));ml_policy_get_status(&st);assert(st.authority_ready&&st.peers==1);
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    /* Reconnect of a gateway still alone: the first map has no Peers. */
    ml_policy_suspend();ml_policy_expect_full_map();
    assert(apply(EMPTY_FIRST));ml_policy_get_status(&st);assert(st.authority_ready&&st.peers==0);
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));          /* peer gone with the full map */
    /* No filter field in a complete first map: no rules (deny), authority known. */
    ml_policy_reset();ml_policy_expect_full_map();
    assert(apply("{\"Node\":{\"Addresses\":[\"100.64.0.10/32\"]},\"Peers\":[" PEER_A "]}"));
    ml_policy_get_status(&st);assert(st.authority_ready&&st.filter_authority&&st.expanded_rules==0);
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    /* Without the session mark (OmitPeers, or a later message) nothing is
     * assumed: a delta never wipes peers, a partial map never completes. */
    ml_policy_reset();assert(apply(ALL));
    assert(apply("{\"Node\":{\"Addresses\":[\"100.64.0.10/32\"]}}"));ml_policy_get_status(&st);assert(st.peers==2);
    ml_policy_suspend();assert(!apply(EMPTY_FIRST));assert(!strcmp(ml_policy_last_reject(),"delta-while-suspended"));
    /* The mark is consumed by one map and cleared by a session end. */
    ml_policy_reset();ml_policy_expect_full_map();assert(apply(ALL));
    assert(apply("{\"Node\":{\"Addresses\":[\"100.64.0.10/32\"]}}"));ml_policy_get_status(&st);assert(st.peers==2);
    ml_policy_expect_full_map();ml_policy_suspend();assert(!apply(EMPTY_FIRST));
    /* Keepalives do not consume it. */
    ml_policy_reset();ml_policy_expect_full_map();assert(apply("{\"KeepAlive\":true}"));
    assert(apply(EMPTY_FIRST));ml_policy_get_status(&st);assert(st.authority_ready);
    puts("PASS: first map of a session complete without Peers/PacketFilter (empty tailnet, reconnect alone, join), never assumed for deltas or OmitPeers, consumed once");
    ml_policy_reset();
}
/* "cap:<name>" sources (node-capability match, capver >= 109) admit nobody
 * here and no longer refuse the whole policy. */
static void cap_sources(void) {
    ml_policy_reset();
    assert(apply("{" NODE "," PEER_LIST ",\"PacketFilter\":[{\"SrcIPs\":[\"cap:example.com/cap/posture\"],\"IPProto\":[6],\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":22,\"Last\":22}}]},"
                 "{\"SrcIPs\":[\"100.64.0.1\",\"cap:other\"],\"IPProto\":[6],\"DstPorts\":[{\"IP\":\"100.64.0.10\",\"Ports\":{\"First\":80,\"Last\":80}}]}]}"));
    ml_policy_status_t st;ml_policy_get_status(&st);assert(st.authority_ready&&st.expanded_rules==1);
    assert(rx(4,6,"100.64.0.1","100.64.0.10",40000,80,2,key_a));
    assert(!rx(4,6,"100.64.0.1","100.64.0.10",40000,22,2,key_a));      /* the cap: rule admits nobody */
    assert(!rx(4,6,"100.64.0.2","100.64.0.10",40000,22,2,key_b));
    puts("PASS: cap: sources match nobody, the rest of the policy applies (no whole-policy refusal)");
    ml_policy_reset();
}
int main(void) {
    layout_alignment();peer_replacement();basics();deltas();replies();invalid();ownership();bounds_and_ranges();large_maps();index_differential();session_maps();cap_sources();concurrency();
    printf("RESOURCE BOUNDS: snapshot=%zu bytes; two during normal update=%zu; return cache=%zu (inside PSRAM snapshot); rules, peers, prefixes sized by the map (%zu, %zu, %zu bytes each) groups=%d flows=%d\n",sizeof(policy),2*sizeof(policy),sizeof(((policy*)0)->flows),sizeof(entry),sizeof(peer),sizeof(ip_range),GROUPS,FLOWS);
}
'''

# Same translation unit exposes implementation sizes/helpers, not a reimplementation.
PROGRAM = '#define ML_POLICY_HOST_TEST 1\n#include "ml_policy.c"\n' + HEAD + BODY
wg_source=(ML/'components/wireguard_lwip/src/wireguardif.c').read_text(encoding='utf-8')
# The receive path carries test-only profiling macros (empty unless TSR_PERF_PROFILE).
# The receive path's saturation counter lives outside this function (tested in forward_drop_counters).
wg_receive=('#include "ml_perf.h"\nstatic volatile uint32_t s_wg_rx_input_refused;\n'
            'static inline void wg_tx_count_drop(volatile uint32_t *c){(*c)++;}\n')+'static void wireguardif_process_data_message'+wg_source.split('static void wireguardif_process_data_message',1)[1].split('\nstatic struct pbuf *wireguardif_initiate_handshake',1)[0]
_helpers = wg_source[wg_source.index('static int peer_allowed_count('):]
_helpers = _helpers[:_helpers.index('\nbool wireguardif_has_host_route(')]
wg_receive = _helpers + wg_receive
WG_FIXTURE = r'''
/* Execute the ACTUAL receive function. Crypto/replay and netif are explicit
 * test doubles, NOT a real encrypted transport or a physical packet trace. */
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define WIREGUARD_MAX_SRC_IPS 4
#define WIREGUARD_AUTHTAG_LEN 16
#define REJECT_AFTER_TIME 180000
#define REKEY_TIMEOUT 5
#define PBUF_TRANSPORT 0
#define PBUF_RAM 0
#define ERR_OK 0
#define IPADDR_TYPE_V4 4
#define IPADDR_TYPE_V6 6
#define IPADDR_TYPE_V4 4
typedef uint16_t u16_t;
typedef struct {uint32_t addr;uint8_t type;} ip_addr_t;
struct netif {int (*input)(struct pbuf*,struct netif*);};
struct wireguard_keypair {bool receiving_valid,initiator;uint32_t keypair_millis,last_rx;};
struct wireguard_allowed_ip {bool valid;ip_addr_t ip,mask;};
struct wireguard_peer {uint8_t public_key[32];struct wireguard_allowed_ip allowed_source_ips[4];uint32_t last_rx,last_data_tx,keepalive_interval;bool send_handshake;struct wireguard_keypair kp;};
#define WIREGUARD_EXTRA_SRC_IPS 4
struct wireguard_device {struct netif *netif;struct wireguard_peer peers[1];struct wireguard_allowed_ip (*extra_ips)[WIREGUARD_EXTRA_SRC_IPS];uint8_t extra_count[1];};
struct message_transport_data {uint32_t receiver;uint8_t counter[8],enc_packet[160];};
struct ip_hdr {uint8_t vhl,tos;uint16_t len,id,offset;uint8_t ttl,proto;uint16_t check;uint32_t src,dest;};
#define IPH_V(h) ((h)->vhl>>4)
#define IPH_LEN(h) ((h)->len)
#define PP_NTOHS(n) ntohs(n)
#define ip_addr_copy_from_ip4(a,b) do{(a).addr=(b);(a).type=4;(void)(a);}while(0)
#define IP_ADDR_NETCMP_COMPAT(s,i,m) (((s)->addr & (m)->addr)==((i)->addr & (m)->addr))
#define IP_IS_V4(a) ((a)->type==4)
#define ip_2_ip4(a) (a)
#define ip4_addr_get_u32(a) ((a)->addr)
#define lwip_ntohl(n) ntohl(n)
#define ip_addr_copy(a,b) ((a)=(b))
#define ip_addr_set_any(t,a) do{(a)->addr=0;(a)->type=(t);}while(0)
#define U8TO64_LITTLE(n) ((uint64_t)(n)[0])
#define WG_DEBUG(...) ((void)0)
static bool crypto_ok=true;
static unsigned deliveries,translations,allocs,frees;
static struct wireguard_keypair *get_peer_keypair_for_idx(struct wireguard_peer *p,uint32_t idx){(void)idx;return &p->kp;}
static bool wireguard_expired(uint32_t a,uint32_t b){(void)a;(void)b;return false;}
static uint32_t wireguard_sys_now(void){return clock_ms;}
static void update_peer_addr(struct wireguard_peer *p,const ip_addr_t *a,u16_t port,bool payload){(void)p;(void)a;(void)port;(void)payload;}
static struct wireguard_keypair *keypair_update(struct wireguard_peer *p,struct wireguard_keypair *k){(void)p;return k;}
static void keypair_destroy(struct wireguard_keypair *k){k->receiving_valid=false;}
static void netif_set_link_up(struct netif *n){(void)n;}
static struct pbuf *pbuf_alloc(int type,size_t len,int storage){
    (void)type;(void)storage;struct pbuf *p=calloc(1,sizeof *p);assert(p);p->payload=calloc(1,len?len:1);assert(p->payload);p->len=p->tot_len=len;allocs++;return p;
}
static void pbuf_free(struct pbuf *p){free(p->payload);free(p);frees++;}
static bool wireguard_decrypt_packet(void *dst,const void *src,size_t len,uint64_t nonce,struct wireguard_keypair *k){
    (void)nonce;(void)k;if(!crypto_ok)return false;assert(len>=16);memcpy(dst,src,len-16);return true;
}
static int deliver(struct pbuf *p,struct netif *n){(void)n;deliveries++;pbuf_free(p);return ERR_OK;}
static bool translate(struct pbuf *p,struct netif *n,const ip_addr_t *a){(void)n;(void)a;translations++;pbuf_free(p);return true;}
static bool (*fourvia6_translate_wg_input)(struct pbuf*,struct netif*,const ip_addr_t*)=translate;
static bool (*rx_hook)(const struct pbuf*,const uint8_t[32])=ml_policy_rx;
#define ml_policy_rx rx_hook
static struct pbuf *(*reassembly_hook)(struct pbuf*,const uint8_t[32]);
#define ml_reassemble_rx reassembly_hook
'''
WG_TESTS = r'''
#undef ml_policy_rx
int main(void) {
    struct netif n={.input=deliver};static struct wireguard_device d;d.netif=&n;
    (void)key_b;
    #define peer (d.peers[0])
    peer=(struct wireguard_peer){.kp={.receiving_valid=true}};memcpy(peer.public_key,key_a,32);
    peer.allowed_source_ips[0]=(struct wireguard_allowed_ip){.valid=true,.ip={.addr=htonl(0x64400001),.type=4},.mask={.addr=0xffffffff,.type=4}};
    ip_addr_t outer={0};
    for(unsigned scenario=0;scenario<8;scenario++) {
        standard();crypto_ok=true;deliveries=translations=0;
        bool ipv6=scenario>=4;
        struct pbuf p=packet(ipv6?6:4,6,ipv6?"fd7a:115c:a1e0::1":"100.64.0.1",ipv6?"fd7a:115c:a1e0:b1a:0:1:c000:232":"100.64.0.10",40000,scenario==1?22:80,2,0);
        if(scenario==2)crypto_ok=false;
        if(scenario==3)assert(apply("{\"PeersRemoved\":[1]}"));
        if(scenario>=4)assert(apply(ALL));
        if(scenario==5)memcpy((uint8_t*)p.payload+8,(uint8_t[]){0xfd,0x7a,0x11,0x5c,0xa1,0xe0,0,0,0,0,0,0,0,0,0,2},16);
        if(scenario==6)assert(apply("{\"PacketFilter\":[]}"));
        if(scenario==7)crypto_ok=false;
        struct message_transport_data hdr={0};memcpy(hdr.enc_packet,p.payload,p.tot_len);
        wireguardif_process_data_message(&d,&peer,&hdr,p.tot_len+16,&outer,1234);
        assert(deliveries==(unsigned)(scenario==0));assert(translations==(unsigned)(scenario==4));assert(allocs==frees);
    }
    /* Empty encrypted keepalive still bypasses IP policy without delivering data. */
    ml_policy_reset();crypto_ok=true;struct message_transport_data empty={0};
    wireguardif_process_data_message(&d,&peer,&empty,16,&outer,1234);assert(allocs==frees);
    puts("PASS: actual WG receive C: post-decrypt TCP allow/deny, crypto failure, stale peer revoke; IPv6 source/policy before 4via6 translation; balanced pbuf ownership (MOCK crypto/netif)");
}
'''
PBUF = r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
struct pbuf {struct pbuf *next;void *payload;uint16_t tot_len,len;};
static uint16_t pbuf_copy_partial(const struct pbuf *p,void *dst,uint16_t len,uint16_t offset) {
    unsigned n=0;
    while(p && offset>=p->len){offset-=p->len;p=p->next;}
    while(p && n<len){unsigned k=p->len-offset;if(k>len-n)k=len-n;memcpy((uint8_t*)dst+n,(uint8_t*)p->payload+offset,k);n+=k;offset=0;p=p->next;}
    return n;
}
'''

with tempfile.TemporaryDirectory(prefix='tailnet-authorization-') as directory:
    path = Path(directory)
    (path / 'lwip').mkdir()
    (path / 'lwip/pbuf.h').write_text(PBUF, encoding='utf-8')
    flags = ['-std=c11', '-pthread', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
             '-I', str(path), '-I', str(ML/'include'), '-I', str(ML/'src'),
             '-I', str(ML/'components/wireguard_lwip/src')]
    libs = ['-lws2_32'] if os.name == 'nt' else ['-lm']
    dep = os.environ.get('CJSON_SOURCE')
    if dep:
        flags += ['-I', str(Path(dep).parent), dep]
    else:
        flags += subprocess.check_output(['pkg-config', '--cflags', 'libcjson'], text=True).split()
        libs += subprocess.check_output(['pkg-config', '--libs', 'libcjson'], text=True).split()
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        if os.environ.get('POLICY_NO_PIE') == '1' and os.name != 'nt':
            flags += ['-fno-pie', '-no-pie']
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    for program in (PROGRAM, '#define ML_POLICY_HOST_TEST 1\n#include "ml_policy.c"\n'+HEAD+WG_FIXTURE+wg_receive+WG_TESTS):
        (path/'test.c').write_text(program,encoding='utf-8')
        subprocess.run([os.environ.get('CC','gcc'), *flags, '-Wno-unused-function', str(path/'test.c'), '-o',str(binary), *libs], check=True)
        with (path/'run.log').open('w+b') as log:
            error = None
            try:
                subprocess.run([str(binary)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=90)
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as caught:
                error = caught
            log.seek(0,2);log.seek(max(0,log.tell()-16384));print(log.read().decode(errors='replace'),end='')
            if error:
                raise error

# Wiring checks are structural evidence only, not crypto/ESP/network tests.
coord=(ML/'src/ml_coord.c').read_text(encoding='utf-8')
wg=(ML/'components/wireguard_lwip/src/wireguardif.c').read_text(encoding='utf-8')
assert 'apply_peer_map(ml,map_json)' in coord and 'apply_peer_map(ml,update_json)' in coord
apply_map=coord[coord.index('static bool apply_peer_map('):].split('\n}',1)[0]
assert apply_map.index('ml_policy_apply(map)') < apply_map.index('parse_peers_from_map_response(ml,map)')
assert 'ml_policy_reset()' in apply_map
receive=wg[wg.index('static void wireguardif_process_data_message'):]
assert receive.index('wireguard_decrypt_packet') < receive.index('ml_policy_rx(pbuf, peer->public_key)') < receive.index('translated_4via6 = fourvia6_translate_wg_input')
assert 'fragment_kind=q && ml_fragment_tx_check' in wg
assert '!fragment_kind && ml_policy_tx && !ml_policy_tx(q, peer->public_key)' in wg
assert 'ml_fragment_tx_result(q,peer->public_key,result==ERR_OK)' in wg
assert 'q && result == ERR_OK && ml_policy_sent' in wg
close=coord[coord.index('static void ml_conn_close'):].split('\n}',1)[0]
assert 'ml_policy_suspend()' in close
# Stream start keeps authority only if a complete map of this connection exists.
assert 'if (!ml_policy_authority_active()) ml_policy_suspend();' in coord[coord.index('static int do_start_long_poll'):].split('\n}',1)[0]
assert 'ml_policy_reset(); /* Explicit disconnect' in coord
print('PASS: source wiring: both map paths, RX post-decrypt/pre-translation, TX and sent-success hooks, reconnect suspension/full-map barrier (not end-to-end proof)')
