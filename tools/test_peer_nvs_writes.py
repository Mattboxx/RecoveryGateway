"""Peer cache flash writes (actual ml_peer_nvs.c save path).

Every full map re-adds every peer and tunnel slots can change hands; the
cache used to rewrite its whole NVS blob (about 7.7 KB) on every save, even
when only the in-RAM LRU counter moved: around 140 KB per reconnect with 18
peers, wearing the flash and stalling the WireGuard task. Now an unchanged
peer writes nothing; a real change (endpoint, DERP region, key, name, exit
flag) and a new peer still write; LRU order is kept in RAM, and eviction
uses wrap-safe ages (the 16-bit clock wraps after 65536 saves).
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
SRC = (ML / 'src/ml_peer_nvs.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(sig):
    start = SRC.index(sig)
    return SRC[start:SRC.index('\n}\n', start) + 3]


types = SRC[SRC.index('#define PEER_NVS_BLOB_KEY'):SRC.index('static void load_table(void) {')]
CODE = types + '\n' + function('static esp_err_t flush_table(void) {') + function('esp_err_t ml_peer_nvs_save(const ml_peer_t *peer) {')

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;typedef int nvs_handle_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
typedef struct {uint32_t ip;uint16_t port;bool is_ipv6;} ep_t;
typedef struct {uint32_t vpn_ip;uint8_t public_key[32],disco_key[32];uint16_t derp_region;ep_t endpoints[8];int endpoint_count;char hostname[64];bool is_exit_node;} ml_peer_t;
static int writes;
static esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *v,size_t l){(void)h;(void)k;(void)v;(void)l;writes++;return ESP_OK;}
static esp_err_t nvs_commit(nvs_handle_t h){(void)h;return ESP_OK;}
@@TYPES_AND_CODE@@
int main(void){
    static peer_nvs_table_t table;s_table=&table;s_initialized=true;
    ml_peer_t p;memset(&p,0,sizeof p);p.vpn_ip=0x64400005;p.public_key[0]=5;p.derp_region=2;strcpy(p.hostname,"pc.tail0000.ts.net");
    p.endpoint_count=1;p.endpoints[0].ip=0xC6336401;p.endpoints[0].port=41641;
    assert(ml_peer_nvs_save(&p)==ESP_OK&&writes==1);                 /* new peer */
    for(int i=0;i<20;i++)assert(ml_peer_nvs_save(&p)==ESP_OK);        /* re-added by full maps */
    assert(writes==1&&table.entries[0].lru_counter==21);              /* LRU kept in RAM */
    p.endpoints[0].port=41642;ml_peer_nvs_save(&p);assert(writes==2); /* endpoint changed */
    p.derp_region=4;ml_peer_nvs_save(&p);assert(writes==3);
    strcpy(p.hostname,"pc-renamed.tail0000.ts.net");ml_peer_nvs_save(&p);assert(writes==4);
    p.is_exit_node=true;ml_peer_nvs_save(&p);assert(writes==5);
    p.public_key[0]=6;ml_peer_nvs_save(&p);assert(writes==6&&table.count==1);   /* re-keyed: same slot by address */
    ml_peer_t q=p;q.vpn_ip=0x64400006;q.public_key[0]=9;ml_peer_nvs_save(&q);assert(writes==7&&table.count==2);
    ml_peer_nvs_save(&q);ml_peer_nvs_save(&p);assert(writes==7);
    /* Full cache across a 16-bit clock wrap: the least recently used peer is
     * evicted, not the most recent ones whose counters wrapped to small values. */
    memset(&table,0,sizeof table);table.lru_clock=65535-40;writes=0;
    for(unsigned i=0;i<ML_NVS_MAX_PEERS;i++){ml_peer_t r=p;r.vpn_ip=0x64410000+i;r.public_key[0]=(uint8_t)i;r.public_key[1]=0xAA;assert(ml_peer_nvs_save(&r)==ESP_OK);}
    assert(table.count==ML_NVS_MAX_PEERS&&table.lru_clock<ML_NVS_MAX_PEERS);   /* wrapped */
    ml_peer_t n=p;n.vpn_ip=0x64420001;n.public_key[0]=0xEE;n.public_key[1]=0xBB;ml_peer_nvs_save(&n);
    int gone=1,newest=0;for(int i=0;i<table.count;i++){if(table.entries[i].vpn_ip==0x64410000)gone=0;if(table.entries[i].vpn_ip==0x64410000+ML_NVS_MAX_PEERS-1)newest=1;}
    assert(gone&&newest&&table.count==ML_NVS_MAX_PEERS);
    puts("PASS: actual peer cache: unchanged peers write nothing (LRU in RAM); new, re-keyed and changed peers still write; LRU eviction survives the clock wrap");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='peer-nvs-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@TYPES_AND_CODE@@', CODE), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:])
print('peer nvs writes: no flash write for unchanged peers')
