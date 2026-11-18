"""Control host address when DNS fails (actual microlink.c / ml_coord.c).

ml_ctrl_addr_load()/ml_ctrl_addr_save() keep the last IPv4 that connected to
the control host, in RAM and in NVS: saved only when it changes (no flash
write per reconnect), per host (another login server's address is never
used), survives a restart, ignores corrupt records. do_tcp_connect() uses it
only after a DNS failure, saves only real DNS answers that connected, and
never frees its own stack record. The Noise handshake still authenticates
the server, so a stale address can only fail to connect.
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
assert tcp.index('uint32_t last = ml_ctrl_addr_load(ml, ml->ctrl_host_parsed);') > tcp.index('ml_getaddrinfo(ml->ctrl_host_parsed')
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
static size_t strlcpy(char *d,const char *s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
static unsigned char blob[80];static size_t blob_len;static int writes,fail_open;
static esp_err_t nvs_open(const char *ns,int m,nvs_handle_t *h){(void)ns;(void)m;*h=1;return fail_open?ESP_FAIL:ESP_OK;}
static void nvs_close(nvs_handle_t h){(void)h;}
static esp_err_t nvs_get_blob(nvs_handle_t h,const char *k,void *o,size_t *l){(void)h;(void)k;if(!blob_len)return ESP_FAIL;if(*l<blob_len)return ESP_FAIL;memcpy(o,blob,blob_len);*l=blob_len;return ESP_OK;}
static esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *v,size_t l){(void)h;(void)k;memcpy(blob,v,l);blob_len=l;writes++;return ESP_OK;}
static esp_err_t nvs_commit(nvs_handle_t h){(void)h;return ESP_OK;}
typedef struct {char ctrl_addr_host[64];uint32_t ctrl_addr_ip;} microlink_t;
@@REC@@
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
    puts("PASS: actual control address cache: per host, survives restart, written only on change, bounded host, corrupt/unavailable NVS ignored");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='ctrl-addr-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@REC@@', rec), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:])
print('control address cache: DNS failure no longer blocks a known control server')
