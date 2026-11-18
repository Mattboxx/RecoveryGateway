"""Several allowed LAN sources per LAN -> Tailnet rule (actual
main/tailnet_forward.c).

A rule admitted one source network. To let a few chosen devices of a network
use one service (for example a friend's devices), several single addresses
were needed. A rule now holds a network or address plus up to 4 single
addresses in the same /16, stored in the former reserved bytes of the saved
rule: the saved layout does not change, older firmware ignores them (it then
admits fewer sources, never more), and a rule without them keeps its time
limit token. Checked: parsing (plain address = /32, list separators, limits,
same /16, no network as an extra), formatting back to the same text, the
packet decision for listed, unlisted and neighbouring addresses, validation
of saved rules (holes, normalisation) and the unchanged layout.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'main/tailnet_forward.c').read_text(encoding='utf-8').replace('\r\n', '\n')
LEASE = (ROOT / 'main/service_lease.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(sig):
    start = SRC.index(sig)
    return SRC[start:SRC.index('\n}\n', start) + 3]


code = ''.join(function(s) for s in (
    'static bool hostname_valid(', 'static bool rule_is_valid(const tailnet_forward_rule_t *r)',
    'bool tailnet_forward_source_allowed(', 'esp_err_t tailnet_forward_parse_cidr(',
    'void tailnet_forward_format_cidr(', 'esp_err_t tailnet_forward_parse_sources(',
    'void tailnet_forward_format_sources('))
assert 'tailnet_forward_source_allowed(r, src)' in function('static bool allow_packet(')
token = LEASE[LEASE.index('uint32_t service_lease_token('):]
token = token[:token.index('\n}\n')]
assert '_reserved' not in token and 'extra_source' not in token   # extras are part of the rule identity

PROGRAM = r'''
#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 0x102
#define TAILNET_FORWARD_NAME_LEN 32
#define TAILNET_FORWARD_DEST_LEN 96
#define TAILNET_FORWARD_EXTRA_SOURCES 4
#define TAILNET_FORWARD_SOURCES_TEXT 96
typedef struct {
    uint8_t valid, enabled, proto, source_prefix;
    uint16_t listen_port, destination_port;
    uint32_t source_network;
    char name[TAILNET_FORWARD_NAME_LEN];
    char destination[TAILNET_FORWARD_DEST_LEN];
    uint16_t extra_source[TAILNET_FORWARD_EXTRA_SOURCES];
} tailnet_forward_rule_t;
typedef struct { uint32_t addr; } ip4_addr_t;
static size_t strlcpy_(char *d,const char *s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
#define strlcpy strlcpy_
static uint32_t lwip_ntohl(uint32_t v){return ((v&255u)<<24)|((v>>8&255u)<<16)|((v>>16&255u)<<8)|(v>>24);}
static int ip4addr_aton(const char *s, ip4_addr_t *a){unsigned b[4];char tail;
    if(sscanf(s,"%u.%u.%u.%u%c",&b[0],&b[1],&b[2],&b[3],&tail)!=4)return 0;
    for(int i=0;i<4;i++)if(b[i]>255)return 0;
    a->addr=lwip_ntohl((b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]);return 1;}
static bool control_parse_index(const char *s,unsigned limit,unsigned *out){
    if(!*s)return false;unsigned v=0;for(;*s;s++){if(!isdigit((unsigned char)*s))return false;v=v*10+(unsigned)(*s-'0');if(v>=limit)return false;}*out=v;return true;}
@@CODE@@
static uint32_t ip(unsigned a,unsigned b,unsigned c,unsigned d){return (a<<24)|(b<<16)|(c<<8)|d;}
static tailnet_forward_rule_t base(void){tailnet_forward_rule_t r;memset(&r,0,sizeof r);r.valid=1;r.proto=6;r.listen_port=8123;r.destination_port=8123;strcpy(r.destination,"100.64.0.2");return r;}
static void roundtrip(const char *in,const char *out){tailnet_forward_rule_t r=base();assert(tailnet_forward_parse_sources(in,&r)==ESP_OK);
    char t[TAILNET_FORWARD_SOURCES_TEXT];tailnet_forward_format_sources(&r,t,sizeof t);if(strcmp(t,out)){printf("%s -> %s\n",in,t);abort();}assert(rule_is_valid(&r));}
int main(void){
    roundtrip("192.168.1.0/24","192.168.1.0/24");
    roundtrip("192.168.1.50","192.168.1.50/32");
    roundtrip("192.168.1.50, 192.168.1.51","192.168.1.50/32, 192.168.1.51");
    roundtrip("192.168.1.50,192.168.1.51 192.168.1.60\t192.168.2.7, 192.168.255.254","192.168.1.50/32, 192.168.1.51, 192.168.1.60, 192.168.2.7, 192.168.255.254");
    roundtrip("10.1.0.0/24, 10.1.9.9","10.1.0.0/24, 10.1.9.9");
    tailnet_forward_rule_t r=base();
    const char *bad[]={"","  ,",", ,","192.168.1.50, 192.168.1.0/24","192.168.1.50, 10.0.0.1","192.168.1.1,192.168.1.2,192.168.1.3,192.168.1.4,192.168.1.5,192.168.1.6",
        "192.168.1.50, 192.168.0.0","300.1.1.1","192.168.1.50/33","192.168.1.50, nonsense",
        "192.168.1.50, 192.168.1.51, 192.168.1.52, 192.168.1.53, 192.168.1.54, 192.168.1.55, 192.168.1.56, 192.168.1.57, 192.168.1.58"};
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];i++){r=base();if(tailnet_forward_parse_sources(bad[i],&r)==ESP_OK){printf("accepted: %s\n",bad[i]);abort();}}
    /* packet decision */
    r=base();assert(tailnet_forward_parse_sources("192.168.1.50, 192.168.1.51, 192.168.1.60",&r)==ESP_OK);
    assert(tailnet_forward_source_allowed(&r,ip(192,168,1,50))&&tailnet_forward_source_allowed(&r,ip(192,168,1,51))&&tailnet_forward_source_allowed(&r,ip(192,168,1,60)));
    assert(!tailnet_forward_source_allowed(&r,ip(192,168,1,52))&&!tailnet_forward_source_allowed(&r,ip(192,169,1,51))&&!tailnet_forward_source_allowed(&r,ip(10,168,1,51)));
    r=base();assert(tailnet_forward_parse_sources("192.168.1.0/24",&r)==ESP_OK);
    assert(tailnet_forward_source_allowed(&r,ip(192,168,1,9))&&!tailnet_forward_source_allowed(&r,ip(192,168,2,9)));
    r=base();assert(tailnet_forward_parse_sources("0.0.0.0/0",&r)==ESP_OK&&tailnet_forward_source_allowed(&r,ip(8,8,8,8)));
    /* an old rule (extras zero) behaves exactly as before */
    r=base();r.source_network=ip(192,168,1,42);r.source_prefix=32;assert(rule_is_valid(&r));
    assert(tailnet_forward_source_allowed(&r,ip(192,168,1,42))&&!tailnet_forward_source_allowed(&r,ip(192,168,1,43)));
    /* saved-rule validation: no hole before a used extra; normalised network */
    r=base();r.source_network=ip(192,168,1,42);r.source_prefix=32;r.extra_source[1]=0x0133;assert(!rule_is_valid(&r));
    r.extra_source[0]=0x0132;assert(rule_is_valid(&r));
    r=base();r.source_network=ip(192,168,1,42);r.source_prefix=24;assert(!rule_is_valid(&r));
    assert(sizeof(tailnet_forward_rule_t)==148&&offsetof(tailnet_forward_rule_t,extra_source)==140);
    puts("PASS: actual LAN source lists: network or address plus 4 addresses of the same /16, round trip, limits, packet decision, old rules unchanged, saved layout kept");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='lan-sources-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@CODE@@', code), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-misleading-indentation']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('lan sources: several allowed devices per LAN to Tailnet rule')
