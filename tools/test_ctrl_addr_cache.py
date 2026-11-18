"""Control host address when DNS fails (actual microlink.c / ml_coord.c).

ml_ctrl_addr_load()/ml_ctrl_addr_save() keep the last IPv4 that connected to
the control host, in RAM and in NVS: saved only when it changes (no flash
write per reconnect), per host (another login server's address is never
used), survives a restart, ignores corrupt records. do_tcp_connect() uses it
only after a DNS failure, saves only real DNS answers that connected, and
never frees its own stack record. The Noise handshake still authenticates
the server, so a stale address can only fail to connect.

beta.22: the same fallback on every path to the control host: the Noise key
fetch (/key, which runs before the handshake for a custom server and failed
on DNS after a restart even though the address was known) and TLS on 443,
where the address is used while the certificate and SNI still check the
name (esp-tls common_name). A failed handshake with a custom server fetches
its key again (it was kept in RAM until a restart).
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
MAIN = (ML / 'src/microlink.c').read_text(encoding='utf-8').replace('\r\n', '\n')
COORD = (ML / 'src/ml_coord.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(src, signature):
    start = src.index(signature)
    return src[start:src.index('\n}\n', start) + 3]


tcp = function(COORD, 'static int do_tcp_connect(')
assert tcp.index('res = ctrl_cached_addr(ml, ml->ctrl_host_parsed') > tcp.index('ml_getaddrinfo(ml->ctrl_host_parsed')
assert 'ctrl_tls_connect(ml, tls, ml->ctrl_host_parsed, ml->ctrl_port_str, cfg)' in tcp and 'esp_tls_conn_new_sync' not in tcp
key = function(COORD, 'static int fetch_server_pubkey(')
assert 'ctrl_tls_connect(ml, tls, host, port, cfg)' in key and 'esp_tls_conn_new_sync' not in key
assert key.index('res = ctrl_cached_addr(ml, host, port, &cached_ai, &cached_sa);') > key.index('ml_getaddrinfo(host, port')
assert 'if (res && !res_cached) ml_freeaddrinfo(res);' in key
hs = COORD[COORD.index('if (do_noise_handshake(ml, &noise) < 0) {'):]
hs = hs[:hs.index('state = COORD_RECONNECTING;')]
assert 'if (ml->ctrl_host[0]) ml->ctrl_noise_pubkey_valid = false;' in hs
HELPERS = function(COORD, 'static struct addrinfo *ctrl_cached_addr(') + function(COORD, 'static int ctrl_tls_connect(')
assert tcp.count('if (!res_cached) ml_freeaddrinfo(res);') == 3 and '    ml_freeaddrinfo(res);' not in tcp.replace('if (!res_cached) ml_freeaddrinfo(res);', '')
assert tcp.index('ml_ctrl_addr_save(ml, ml->ctrl_host_parsed') > tcp.index('if (ml_connect(sock, res->ai_addr, res->ai_addrlen) < 0)')
assert 'if (!res_cached && res->ai_family == AF_INET)' in tcp

rec = MAIN[MAIN.index('typedef struct { char host[64]; uint32_t ip; } ctrl_addr_rec_t;'):]
rec = rec[:rec.index('void ml_identity_mark_expired(')]
PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;typedef int nvs_handle_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define NVS_READWRITE 1
#define NVS_READONLY 0
#define NVS_NAMESPACE "microlink"
#define NVS_KEY_CTRL_ADDR "ctrl_addr"
#define strlcpy test_strlcpy   /* glibc >= 2.38 declares strlcpy under gnu11 */
static size_t strlcpy(char *d,const char *s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
static unsigned char blob[80];static size_t blob_len;static int writes,fail_open;
static esp_err_t nvs_open(const char *ns,int m,nvs_handle_t *h){(void)ns;(void)m;*h=1;return fail_open?ESP_FAIL:ESP_OK;}
static void nvs_close(nvs_handle_t h){(void)h;}
static esp_err_t nvs_get_blob(nvs_handle_t h,const char *k,void *o,size_t *l){(void)h;(void)k;if(!blob_len)return ESP_FAIL;if(*l<blob_len)return ESP_FAIL;memcpy(o,blob,blob_len);*l=blob_len;return ESP_OK;}
static esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *v,size_t l){(void)h;(void)k;memcpy(blob,v,l);blob_len=l;writes++;return ESP_OK;}
static esp_err_t nvs_commit(nvs_handle_t h){(void)h;return ESP_OK;}
typedef struct {char ctrl_addr_host[64];uint32_t ctrl_addr_ip;} microlink_t;
@@REC@@
/* Socket and esp-tls stand-ins for ctrl_cached_addr()/ctrl_tls_connect(). */
#include <stdlib.h>
#define TAG "t"
#define ESP_LOGW(...) ((void)0)
#define AF_UNSPEC 0
#define AF_INET 2
#define SOCK_STREAM 1
typedef unsigned socklen_t;
struct sockaddr{unsigned short sa_family;char d[14];};
struct in_addr{uint32_t s_addr;};
struct sockaddr_in{unsigned short sin_family;uint16_t sin_port;struct in_addr sin_addr;char z[8];};
struct sockaddr_storage{unsigned short ss_family;char d[30];};
struct addrinfo{int ai_flags,ai_family,ai_socktype,ai_protocol;socklen_t ai_addrlen;struct sockaddr *ai_addr;struct addrinfo *ai_next;};
static uint16_t htons(uint16_t v){return (uint16_t)((v>>8)|(v<<8));}
static uint32_t htonl(uint32_t v){return ((v&255u)<<24)|((v>>8&255u)<<16)|((v>>16&255u)<<8)|(v>>24);}
#define ntohl htonl
static int dns_ok,dns_frees;static struct addrinfo dns_ai;
static int ml_getaddrinfo(const char *h,const char *p,const struct addrinfo *hi,struct addrinfo **r){(void)h;(void)p;(void)hi;if(!dns_ok){*r=NULL;return -1;}*r=&dns_ai;return 0;}
static void ml_freeaddrinfo(struct addrinfo *r){assert(r==&dns_ai);dns_frees++;}
typedef struct{const char *common_name;int timeout_ms;} esp_tls_cfg_t;
typedef struct{int fd;} esp_tls_t;
static char tls_target[64],tls_cn[64];static int tls_ok,tls_calls;static uint32_t peer_ip;
static int esp_tls_conn_new_sync(const char *h,int hl,int port,const esp_tls_cfg_t *c,esp_tls_t *t){
    assert(port==443);tls_calls++;snprintf(tls_target,sizeof tls_target,"%.*s",hl,h);
    snprintf(tls_cn,sizeof tls_cn,"%s",c->common_name?c->common_name:"");t->fd=7;return tls_ok?1:-1;}
static int esp_tls_get_conn_sockfd(esp_tls_t *t,int *fd){*fd=t->fd;return ESP_OK;}
static int getpeername(int fd,struct sockaddr *a,socklen_t *l){assert(fd==7&&*l>=sizeof(struct sockaddr_in));
    struct sockaddr_in *in=(struct sockaddr_in *)a;memset(in,0,sizeof *in);in->sin_family=AF_INET;in->sin_addr.s_addr=htonl(peer_ip);return 0;}
@@HELPERS@@
static void tls_and_fallback(void){
    microlink_t ml;memset(&ml,0,sizeof ml);blob_len=0;writes=0;fail_open=0;
    esp_tls_t tls;esp_tls_cfg_t cfg={0};
    /* No DNS, nothing known: TLS by name (it fails on its own), no address. */
    struct addrinfo ai;struct sockaddr_in sa;
    assert(ctrl_cached_addr(&ml,"hs.example","443",&ai,&sa)==NULL);
    dns_ok=0;tls_ok=0;assert(ctrl_tls_connect(&ml,&tls,"hs.example","443",cfg)!=1);
    assert(!strcmp(tls_target,"hs.example")&&!tls_cn[0]&&writes==0);
    /* DNS works: by name, the connected IPv4 is recorded once. */
    dns_ok=1;tls_ok=1;peer_ip=0xC0000207;assert(ctrl_tls_connect(&ml,&tls,"hs.example","443",cfg)==1);
    assert(!strcmp(tls_target,"hs.example")&&!tls_cn[0]&&writes==1&&dns_frees==1);
    assert(ctrl_tls_connect(&ml,&tls,"hs.example","443",cfg)==1&&writes==1);
    /* DNS fails: the known address, certificate and SNI still for the name. */
    dns_ok=0;assert(ctrl_tls_connect(&ml,&tls,"hs.example","443",cfg)==1);
    assert(!strcmp(tls_target,"192.0.2.7")&&!strcmp(tls_cn,"hs.example")&&writes==1);
    assert(cfg.common_name==NULL);                       /* the caller's config is not changed */
    /* Plain path (key fetch and coordination): a one-entry addrinfo. */
    struct addrinfo *r=ctrl_cached_addr(&ml,"hs.example","8080",&ai,&sa);
    assert(r==&ai&&r->ai_family==AF_INET&&r->ai_addr==(struct sockaddr *)&sa&&r->ai_addrlen==sizeof sa);
    assert(sa.sin_port==htons(8080)&&sa.sin_addr.s_addr==htonl(0xC0000207));
    /* Another host's address is never used (that connection then becomes the one remembered). */
    assert(ctrl_tls_connect(&ml,&tls,"other.example","443",cfg)==1&&!strcmp(tls_target,"other.example")&&!tls_cn[0]);
    puts("PASS: actual TLS and key fetch paths: last working address when DNS fails, certificate and SNI still checked for the name, other hosts never use it");
}
int main(void){
    microlink_t ml;memset(&ml,0,sizeof ml);
    assert(ml_ctrl_addr_load(&ml,"controlplane.tailscale.com")==0);
    ml_ctrl_addr_save(&ml,"controlplane.tailscale.com",0x12345678);assert(writes==1);
    ml_ctrl_addr_save(&ml,"controlplane.tailscale.com",0x12345678);assert(writes==1);          /* unchanged: no write */
    assert(ml_ctrl_addr_load(&ml,"controlplane.tailscale.com")==0x12345678);
    assert(ml_ctrl_addr_load(&ml,"hs.example")==0);                                             /* other host */
    microlink_t fresh;memset(&fresh,0,sizeof fresh);                                            /* restart */
    assert(ml_ctrl_addr_load(&fresh,"controlplane.tailscale.com")==0x12345678);
    ml_ctrl_addr_save(&fresh,"controlplane.tailscale.com",0x12345678);assert(writes==1);
    ml_ctrl_addr_save(&fresh,"controlplane.tailscale.com",0x0A000001);assert(writes==2&&fresh.ctrl_addr_ip==0x0A000001);
    ml_ctrl_addr_save(&fresh,"",1);ml_ctrl_addr_save(&fresh,"x",0);assert(writes==2);
    char longhost[100];memset(longhost,'a',99);longhost[99]=0;ml_ctrl_addr_save(&fresh,longhost,5);assert(writes==2);
    /* Corrupt record: wrong length or unterminated host is ignored. */
    blob_len=10;microlink_t c;memset(&c,0,sizeof c);assert(ml_ctrl_addr_load(&c,"controlplane.tailscale.com")==0);
    fail_open=1;assert(ml_ctrl_addr_load(&c,"controlplane.tailscale.com")==0);
    tls_and_fallback();
    puts("PASS: actual control address cache: per host, survives restart, written only on change, bounded host, corrupt/unavailable NVS ignored");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='ctrl-addr-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@REC@@', rec).replace('@@HELPERS@@', HELPERS), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:])
print('control address cache: DNS failure no longer blocks a known control server (plain, TLS, key fetch)')
