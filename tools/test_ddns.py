"""Actual dynamic-DNS core of main/ddns.c.

Covered: settings validation for DuckDNS (sub-domain lists, token format),
Cloudflare (record name, zone id, token) and custom HTTPS URLs (scheme,
host, credentials before the host, spaces/control/quote/fragment
characters), the update schedule (first update, address change, daily
refresh, 30-minute refresh while the address is unknown, Cloudflare waiting
for the address, exponential back-off capped at an hour, success resetting
it) and request URLs ({ip} placeholder, unknown address, length limits).
HTTPS, providers and the STUN address source are NOT covered.
DDNS_SANITIZE=1 adds ASan/UBSan on Linux.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/ddns.c').read_text(encoding='utf-8')
core = source.split('/* --- ddns core (begin) --- */', 1)[1].split('/* --- ddns core (end) --- */', 1)[0]

PROGRAM = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ddns.h"
''' + core + r'''
static ddns_config_t duck(void){ddns_config_t c;memset(&c,0,sizeof c);c.provider=DDNS_DUCKDNS;strcpy(c.name,"myhome");strcpy(c.token,"a7c4d2e1-0b3f-4c5d-9e8f-1234567890ab");return c;}
static ddns_config_t cf(void){ddns_config_t c;memset(&c,0,sizeof c);c.provider=DDNS_CLOUDFLARE;strcpy(c.name,"home.example.com");
    strcpy(c.zone,"0123456789abcdef0123456789abcdef");strcpy(c.token,"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCd");return c;}
static ddns_config_t custom(const char *u){ddns_config_t c;memset(&c,0,sizeof c);c.provider=DDNS_CUSTOM;strcpy(c.url,u);return c;}
static bool ok(ddns_config_t c){char why[120]="";bool v=ddns_config_valid(&c,why,sizeof why);assert(v||why[0]);return v;}
#define IP(a,b,c,d) ((uint32_t)(a)|(uint32_t)(b)<<8|(uint32_t)(c)<<16|(uint32_t)(d)<<24)

int main(void){
    ddns_config_t off;memset(&off,0,sizeof off);assert(ok(off)&&!ddns_config_valid(NULL,NULL,0));
    /* DuckDNS. */
    assert(ok(duck()));
    ddns_config_t c=duck();strcpy(c.name,"home,cabin-2,x");assert(ok(c));
    const char *bad_names[]={"","Home","home.duckdns.org","-home","home-","home,,cabin","a,b,c,d,e,f","ho me","home,"};
    for(unsigned i=0;i<sizeof bad_names/sizeof *bad_names;i++){c=duck();strcpy(c.name,bad_names[i]);assert(!ok(c));}
    const char *bad_tokens[]={"","a7c4d2e1-0b3f-4c5d-9e8f-1234567890a","a7c4d2e1-0b3f-4c5d-9e8f-1234567890abc","a7c4d2e10b3f-4c5d-9e8f-1234567890ab-",
        "A7C4D2E1-0B3F-4C5D-9E8F-1234567890AB","a7c4d2e1-0b3f-4c5d-9e8f-1234567890ag"};
    for(unsigned i=0;i<sizeof bad_tokens/sizeof *bad_tokens;i++){c=duck();strcpy(c.token,bad_tokens[i]);assert(!ok(c));}
    /* Cloudflare. */
    assert(ok(cf()));
    c=cf();strcpy(c.name,"*.example.com");assert(ok(c));
    const char *bad_hosts[]={"","home","home.","-home.example.com","home-.example.com","ho_me.example.com","home..example.com","a.*.example.com","home.example.com/x"};
    for(unsigned i=0;i<sizeof bad_hosts/sizeof *bad_hosts;i++){c=cf();strcpy(c.name,bad_hosts[i]);assert(!ok(c));}
    c=cf();strcpy(c.zone,"0123456789abcdef0123456789abcde");assert(!ok(c));strcpy(c.zone,"0123456789abcdef0123456789abcdeg");assert(!ok(c));
    c=cf();strcpy(c.token,"short");assert(!ok(c));strcpy(c.token,"AbCdEfGhIjKlMnOpQrStUvWxYz0123456789 AbCd");assert(!ok(c));
    /* Custom URL. */
    assert(ok(custom("https://dynv6.com/api/update?hostname=x.dynv6.net&token=t&ipv4={ip}")));
    assert(ok(custom("https://example.org:8443/nic/update")));
    const char *bad_urls[]={"http://example.org/u","https://","https:///x","https://user:pw@example.org/u","https://exa mple.org/",
        "https://example.org/u?a=\"b\"","https://example.org/u#frag","https://example.org/\x01","https://localhost/u","https://*.example.org/u",
        "ftp://example.org"};
    for(unsigned i=0;i<sizeof bad_urls/sizeof *bad_urls;i++)assert(!ok(custom(bad_urls[i])));
    assert(ok(custom("https://example.org/u?user=a@b.c")));                     /* @ after the host is fine */
    c=duck();c.provider=9;assert(!ok(c));

    /* Schedule. */
    ddns_state_t st;memset(&st,0,sizeof st);
    uint32_t a=IP(203,0,113,7),b=IP(198,51,100,9);
    assert(!ddns_due(&st,DDNS_OFF,a,100));
    assert(ddns_due(&st,DDNS_DUCKDNS,0,100));                                   /* first update, address unknown */
    assert(ddns_due(&st,DDNS_CLOUDFLARE,0,100)&&ddns_due(&st,DDNS_CLOUDFLARE,a,100));    /* unknown: the worker asks the trace endpoint */
    ddns_result(&st,true,a,100);
    assert(st.ever&&st.last_ip==a&&!st.backoff_s);
    assert(!ddns_due(&st,DDNS_CLOUDFLARE,b,120));                               /* at most one a minute */
    assert(ddns_due(&st,DDNS_CLOUDFLARE,b,160)&&!ddns_due(&st,DDNS_CLOUDFLARE,a,160));   /* changed vs same */
    assert(!ddns_due(&st,DDNS_DUCKDNS,a,100+DDNS_REFRESH_S-1)&&ddns_due(&st,DDNS_DUCKDNS,a,100+DDNS_REFRESH_S));
    assert(!ddns_due(&st,DDNS_DUCKDNS,0,100+DDNS_BLIND_S-1)&&ddns_due(&st,DDNS_DUCKDNS,0,100+DDNS_BLIND_S));
    ddns_result(&st,true,0,5000);assert(st.last_ip==a);                         /* unknown address keeps the last one */
    /* Back-off: 60, 120, 240 ... capped at an hour; success resets it. */
    uint32_t now=10000,expect=60;
    for(int i=0;i<10;i++){ddns_result(&st,false,b,now);assert(st.backoff_s==expect&&st.next_try_s==now+expect);
        assert(!ddns_due(&st,DDNS_CLOUDFLARE,b,now+expect-1)&&ddns_due(&st,DDNS_CLOUDFLARE,b,now+expect));
        now+=expect;expect=expect*2>DDNS_BACKOFF_MAX_S?DDNS_BACKOFF_MAX_S:expect*2;}
    assert(st.backoff_s==DDNS_BACKOFF_MAX_S&&st.last_ip==a);                    /* failures never record the address */
    ddns_result(&st,true,b,now);assert(!st.backoff_s&&st.last_ip==b);
    ddns_result(&st,false,b,now+60);
    assert(!ddns_due(&st,DDNS_DUCKDNS,b,now+119));
    assert(ddns_due(&st,DDNS_DUCKDNS,b,now+120));                              /* manual refresh failed at unchanged address */

    /* Request URLs. */
    char url[320];
    c=duck();assert(ddns_build_url(&c,a,url,sizeof url)&&!strcmp(url,"https://www.duckdns.org/update?domains=myhome&token=a7c4d2e1-0b3f-4c5d-9e8f-1234567890ab&ip=203.0.113.7"));
    assert(ddns_build_url(&c,0,url,sizeof url)&&!strcmp(url+strlen(url)-4,"&ip="));   /* DuckDNS sees the source address */
    assert(!ddns_build_url(&c,a,url,40));
    c=custom("https://e.org/u?ip={ip}&x=1");assert(ddns_build_url(&c,b,url,sizeof url)&&!strcmp(url,"https://e.org/u?ip=198.51.100.9&x=1"));
    assert(!ddns_build_url(&c,0,url,sizeof url));                               /* {ip} needs the address */
    c=custom("https://e.org/u?a={ip}&b={ip}");assert(!ddns_build_url(&c,b,url,sizeof url));   /* one placeholder */
    c=custom("https://e.org/u");assert(ddns_build_url(&c,0,url,sizeof url)&&!strcmp(url,"https://e.org/u"));
    c=cf();assert(!ddns_build_url(&c,a,url,sizeof url));                        /* Cloudflare uses its API */

    /* Cloudflare trace answer, used when Tailscale has not seen the address. */
    uint32_t ip=0;
    assert(ddns_parse_trace("fl=123\nh=www.cloudflare.com\nip=203.0.113.7\nts=1\n",&ip)&&ip==a);
    assert(ddns_parse_trace("ip=198.51.100.9",&ip)&&ip==b);                     /* last line, no newline */
    assert(ddns_parse_trace("ip=198.51.100.9\r\nts=1",&ip)&&ip==b);
    assert(!ddns_parse_trace("fl=1\nh=x\n",&ip));                              /* no ip line */
    assert(!ddns_parse_trace("ip=2001:db8::1\n",&ip));                         /* IPv6: no A record */
    assert(!ddns_parse_trace("ip=256.1.1.1\n",&ip)&&!ddns_parse_trace("ip=1.2.3.4x\n",&ip));
    assert(!ddns_parse_trace("ip=0.0.0.0\n",&ip)&&!ddns_parse_trace("",&ip));
    assert(!ddns_parse_trace("xip=203.0.113.7\n",&ip));                        /* key must start the line */
    puts("ddns core: ok");
    return 0;
}
'''

def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'

PROVIDER = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ddns.h"
#include "json_guard.h"
enum {ESP_OK, HTTP_METHOD_GET, HTTP_METHOD_PATCH, MALLOC_CAP_SPIRAM};
typedef int esp_http_client_method_t;
typedef int esp_http_client_handle_t;
typedef struct {
 const char *url; int method,timeout_ms; void *crt_bundle_attach; bool disable_auto_redirect;
} esp_http_client_config_t;
static void *ml_tls_bundle_attach;
static const char *listing="{\"success\":true,\"result\":[{\"id\":\"0123456789abcdef0123456789abcdef\",\"content\":\"192.0.2.10\"}]}";
static const char *patch,*response;
static unsigned patches,status=200;
static size_t offset,response_len;
static bool truncated,embedded_nul;
static void *heap_caps_malloc(size_t n,int caps){assert(caps==MALLOC_CAP_SPIRAM);return malloc(n);}
static bool request_current(uint32_t generation){return generation==2;}
static int esp_http_client_init(const esp_http_client_config_t *c){
 assert(c->disable_auto_redirect&&c->timeout_ms==15000);
 offset=0;response=c->method==HTTP_METHOD_PATCH?patch:listing;response_len=strlen(response);
 if(c->method==HTTP_METHOD_PATCH){patches++;if(embedded_nul)response_len+=4;}
 return c->method;
}
static void esp_http_client_set_header(int h,const char *name,const char *value){assert(h&&name&&value);}
static int esp_http_client_open(int h,int n){assert((h==HTTP_METHOD_PATCH)==(n>0));return ESP_OK;}
static int esp_http_client_write(int h,const char *buf,int n){assert(h==HTTP_METHOD_PATCH&&buf&&n);return n;}
static int esp_http_client_fetch_headers(int h){assert(h);return (int)response_len;}
static int esp_http_client_get_status_code(int h){return h==HTTP_METHOD_PATCH?(int)status:200;}
static int esp_http_client_read(int h,char *buf,int cap){
 assert(h);
 size_t count=response_len-offset;
 if(count>(size_t)cap)count=(size_t)cap;
 memcpy(buf,response+offset,count);offset+=count;return (int)count;
}
static bool esp_http_client_is_complete_data_received(int h){
 return offset==response_len && (h!=HTTP_METHOD_PATCH||!truncated);
}
static void esp_http_client_cleanup(int h){assert(h);}
''' + core + ''.join(function(s) for s in (
    'static int request(', 'static bool cloudflare_success(', 'static bool cloudflare('
)) + r'''
static bool update(void){
 ddns_config_t c={.provider=DDNS_CLOUDFLARE,.name="demo.example.com",
     .zone="0123456789abcdef0123456789abcdef",.token="fixture"};
 uint32_t ip=0;uint8_t address[4]={192,0,2,11};memcpy(&ip,address,4);
 char why[120]={0};
 bool ok=cloudflare(&c,2,&ip,why,sizeof why);assert(ok||why[0]);return ok;
}
int main(void){
 patch="{ \"success\" : true, \"result\" : {} }";
 assert(update()&&patches==1);
 truncated=true;assert(!update());truncated=false;
 status=403;assert(!update());status=200;
 const char *bad[]={"{\"result\":{\"success\":true}}","{\"success\":true,\"success\":false}",
  "{\"success\":true","{\"success\":\"true\"}","{\"success\":false}","{\"success\":true}junk"};
 for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){patch=bad[i];assert(!update());}
 patch="{\"success\":true}\0bad";embedded_nul=true;assert(!update());embedded_nul=false;
 listing="{\"success\":false,\"result\":[{\"id\":\"0123456789abcdef0123456789abcdef\"}]}";
 unsigned before=patches;assert(!update()&&patches==before);
 puts("PASS: complete Cloudflare response and top-level typed success through real request parser");
}
'''


LIFECYCLE = r'''
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ddns.h"
#define pdTRUE 1
#define pdPASS 1
#define portMAX_DELAY 1
#define MALLOC_CAP_SPIRAM 1
#define ESP_OK 0
enum {HIST_EV_UPLINK,HIST_INFO,HIST_WARN};
typedef struct {void (*callback)(void *);const char *name;bool skip_unhandled_events;} esp_timer_create_args_t;
typedef esp_timer_create_args_t *esp_timer_handle_t;
static esp_timer_create_args_t timer;
static esp_timer_handle_t s_timer;
static unsigned timer_creates,timer_deletes,timer_stops,task_starts,finished,requests,events;
static bool timer_active,fail_create,fail_arm,fail_task,fail_config,change_during_request;
static bool s_running,s_force,locked,*s_lock=&locked;
static ddns_config_t s_cfg;
static ddns_state_t s_state;
static char s_last[96];
static uint32_t s_generation,s_job_generation,s_admission_retry_at,s_scheduler_retry_at,s_seen_ip,now;
static atomic_bool s_scheduler_retry_pending;
static void (*scheduled)(void *);
static esp_err_t xSemaphoreTake(bool *lock,int timeout){
    assert(lock==s_lock);
    if(*lock){assert(!timeout);return 0;}
    *lock=true;return pdTRUE;
}
static void xSemaphoreGive(bool *lock){assert(lock==s_lock && *lock);*lock=false;}
static uint32_t now_s(void){return now;}
static uint32_t public_ip(void){assert(!locked);return 0x010200c0;}
static void *heap_caps_malloc(size_t size,unsigned caps){assert(locked && caps==MALLOC_CAP_SPIRAM);return fail_config ? NULL : malloc(size);}
static esp_err_t esp_timer_create(const esp_timer_create_args_t *args,esp_timer_handle_t *out){
    assert(locked && args->callback && args->skip_unhandled_events);
    timer_creates++;
    if(fail_create)return -1;
    timer=*args;*out=&timer;return ESP_OK;
}
static esp_err_t esp_timer_start_periodic(esp_timer_handle_t t,uint64_t period){
    assert(locked && t==&timer && period==60000000 && !timer_active);
    if(fail_arm)return -1;
    timer_active=true;return ESP_OK;
}
static void esp_timer_stop(esp_timer_handle_t t){assert(locked && t==&timer && timer_active);timer_active=false;timer_stops++;}
static void esp_timer_delete(esp_timer_handle_t t){assert(locked && t==&timer && !timer_active);timer_deletes++;}
static int xTaskCreateWithCaps(void (*entry)(void*),const char *name,int stack,void *arg,int priority,void *out,unsigned caps){
    assert(locked && !scheduled && !strcmp(name,"ddns") && stack==8192 && !arg && priority==2 && !out && caps==MALLOC_CAP_SPIRAM);
    task_starts++;
    if(fail_task)return 0;
    scheduled=entry;return pdPASS;
}
static void run_worker(void){assert(scheduled);void (*run)(void*)=scheduled;scheduled=NULL;run(NULL);}
static void task_reaper_self_delete(void){assert(!locked && !s_running);finished++;}
static void history_event(int kind,int level,const char *fmt,...){
    assert(locked && kind==HIST_EV_UPLINK && (level==HIST_INFO || level==HIST_WARN) && fmt);events++;
}
static bool apply_config_locked(const ddns_config_t *next, bool force);
static bool simple_get(const ddns_config_t *c,uint32_t ip,char *why,size_t cap){
    assert(!locked && c->provider==DDNS_CUSTOM && ip && why && cap);
    requests++;
    if(change_during_request){
        ddns_config_t next=*c;
        strcpy(next.url,"https://example.net/new");
        xSemaphoreTake(s_lock,portMAX_DELAY);
        assert(apply_config_locked(&next,false));
        xSemaphoreGive(s_lock);
    }
    return true;
}
static bool cloudflare(const ddns_config_t *c,uint32_t gen,uint32_t *ip,char *why,size_t cap){
    (void)c;(void)gen;(void)ip;(void)why;(void)cap;
    assert(0);return false;
}
''' + core + ''.join(function(name) for name in (
    'static bool request_current(', 'static void worker(', 'static void tick(',
    'static void scheduler_update_locked(', 'void ddns_retry_scheduler(',
    'static bool apply_config_locked(')) + r'''
int main(void){
    ddns_config_t cfg={.provider=DDNS_CUSTOM,.url="https://example.net/update"};
    ddns_retry_scheduler();assert(!timer_creates);
    fail_create=true;
    xSemaphoreTake(s_lock,portMAX_DELAY);assert(apply_config_locked(&cfg,false));xSemaphoreGive(s_lock);
    assert(!s_timer && s_scheduler_retry_pending && timer_creates==1 && !timer_deletes);
    fail_task=true;tick(NULL);
    assert(!s_running && s_force && s_admission_retry_at==60 && task_starts==1);
    now=59;ddns_retry_scheduler();tick(NULL);assert(timer_creates==1 && task_starts==1);
    now=60;fail_create=false;fail_arm=true;ddns_retry_scheduler();
    assert(!s_timer && timer_creates==2 && timer_deletes==1 && s_scheduler_retry_pending);
    now=120;fail_arm=false;ddns_retry_scheduler();
    assert(s_timer==&timer && !s_scheduler_retry_pending && timer_active);
    fail_task=false;timer.callback(NULL);assert(s_running && !s_force);
    run_worker();assert(s_state.ever && events==1 && requests==1 && finished==1);
    xSemaphoreTake(s_lock,portMAX_DELAY);assert(apply_config_locked(&cfg,true));xSemaphoreGive(s_lock);
    tick(NULL);change_during_request=true;run_worker();
    assert(requests==2 && events==1 && finished==2 && !s_state.ever && s_force);
    change_during_request=false;tick(NULL);run_worker();
    assert(s_state.ever && events==2 && requests==3);
    cfg=s_cfg;
    xSemaphoreTake(s_lock,portMAX_DELAY);assert(apply_config_locked(&cfg,true));xSemaphoreGive(s_lock);
    tick(NULL);assert(s_running && scheduled);
    cfg=(ddns_config_t){0};
    xSemaphoreTake(s_lock,portMAX_DELAY);assert(!apply_config_locked(&cfg,true));xSemaphoreGive(s_lock);
    run_worker();tick(NULL);ddns_retry_scheduler();
    assert(events==2 && requests==3 && !s_force && !s_state.ever && !s_timer && timer_stops==1 && timer_deletes==2);
    puts("PASS: DDNS timer create/arm recovery, queued update survives allocation failure, stale worker suppressed, disabled state inert");
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='ddns-') as folder:
        path = Path(folder)
        (path / 'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n', encoding='utf-8')
        (path / 'esp_http_server.h').write_text('#pragma once\ntypedef void *httpd_handle_t;\n', encoding='utf-8')
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', str(path), '-I', str(ROOT / 'main')]
        if os.environ.get('DDNS_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        for name, program in (('ddns', PROGRAM), ('lifecycle', LIFECYCLE)):
            c = path / (name + '.c')
            c.write_text(program, encoding='utf-8')
            binary = path / (name + ('.exe' if os.name == 'nt' else ''))
            subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=60)
        pp = path / 'provider.c'
        pp.write_text(PROVIDER, encoding='utf-8')
        exe = path / ('provider.exe' if os.name == 'nt' else 'provider')
        cjson = os.environ.get('CJSON_SOURCE')
        if cjson:
            flags += ['-I', str(Path(cjson).parent), cjson]
            libs = []
        else:
            flags += subprocess.check_output(['pkg-config', '--cflags', 'libcjson'], text=True).split()
            libs = subprocess.check_output(['pkg-config', '--libs', 'libcjson'], text=True).split()
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(pp), '-o', str(exe), *libs], check=True)
        subprocess.run([str(exe)], check=True, timeout=60)


if __name__ == '__main__':
    main()
