"""Response headers of the Web UI fit the HTTP server's limit.

esp_http_server keeps at most conf.max_resp_headers additional headers per
response and silently drops the rest. 3.0.1-beta.1 added an ETag to the
page: with the default limit of 8 the Content-Encoding header was dropped and
browsers showed the gzip bytes as text. This counts, in the actual
main/web_ui.c, the headers every handler sets (the shared security headers
included) and checks the limit, and that gzip responses declare their
encoding before the optional headers. Host only.
"""
from email.message import Message
from http.cookiejar import CookieJar
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request

HOST_FLAGS = ['-std=c11', '-Wall', '-Wextra', '-Werror']
if os.environ.get('RESP_HEADERS_SANITIZE') == '1':
    HOST_FLAGS += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')

m = re.search(r'conf\.max_resp_headers\s*=\s*(\d+);', src)
limit = int(m.group(1)) if m else 8          # esp_http_server default
sec = re.search(r'static void set_browser_security_headers\(httpd_req_t \*req\)\n\{(.*?)\n\}', src, re.S).group(1)
shared = sec.count('httpd_resp_set_hdr(')
assert shared >= 6, shared

checked = 0
for m in re.finditer(r'\nstatic esp_err_t (\w+)\(httpd_req_t \*req\)\n\{(.*?)\n\}', src, re.S):
    name, body = m.group(1), m.group(2)
    own = len(re.findall(r'httpd_resp_set_hdr\(', body))
    total = own + (shared if 'set_browser_security_headers(req)' in body else 0)
    assert total <= limit, f'{name}: {total} response headers, server keeps {limit}'
    if '"Content-Encoding", "gzip"' in body and 'set_browser_security_headers(req)' in body:
        assert body.index('"Content-Encoding", "gzip"') < body.index('set_browser_security_headers(req)'), \
            f'{name}: Content-Encoding must be set before the optional headers'
    checked += 1
assert checked > 20, checked
for handler in ('index_handler', 'i18n_handler'):
    assert re.search(r'static esp_err_t ' + handler + r'\(', src), handler
print(f'PASS: {checked} handlers in web_ui.c stay within max_resp_headers={limit} (shared security headers {shared}); '
      'gzip encoding declared before optional headers (host)')

signature = 'static esp_err_t send_session_cookie_response('
start = src.index(signature)
cookie_writer = src[start:src.index('\n}\n', start) + 3]
start = src.index('static esp_err_t auth_logout_handler(')
logout = src[start:src.index('\n}\n', start) + 3]
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef int httpd_req_t,esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
static int httpd_resp_set_hdr(httpd_req_t *r,const char *key,const char *value){
    assert(!strcmp(key,"Set-Cookie"));(*r)++;puts(value);return ESP_OK;
}
static int httpd_resp_set_type(httpd_req_t *r,const char *type){assert(*r&&!strcmp(type,"application/json"));return ESP_OK;}
static int httpd_resp_sendstr(httpd_req_t *r,const char *body){assert(*r&&!strcmp(body,"{\"ok\":true}"));return ESP_OK;}
static bool browser_request_refused(httpd_req_t *r,bool login){assert(r&&!login);return false;}
static int session_find_for_req(httpd_req_t *r){assert(r);return 1;}
static void session_clear_slot(int i){assert(i==1);}
'''
tests = r'''
int main(void){
    httpd_req_t r=0;
    assert(send_session_cookie_response(&r,"synthetic-session")==ESP_OK);
    assert(auth_logout_handler(&r)==ESP_OK&&r==2);
}
'''
with tempfile.TemporaryDirectory(prefix='session-cookie-') as directory:
    path = Path(directory) / 'test.c'
    path.write_text(fixture + cookie_writer + logout + tests, encoding='utf-8')
    binary = path.with_suffix('.exe' if os.name == 'nt' else '.out')
    subprocess.run([os.environ.get('CC', 'gcc'), *HOST_FLAGS,
                    str(path), '-o', str(binary)], check=True)
    login_header, logout_header = subprocess.check_output([str(binary)], text=True).splitlines()


class Response:
    def __init__(self, header):
        self.headers = Message()
        self.headers['Set-Cookie'] = header

    def info(self):
        return self.headers


jar = CookieJar()
url = 'http://gateway.invalid/api/auth/status'
jar.extract_cookies(Response(login_header), Request(url))
cookie, = jar
assert cookie.discard and cookie.expires is None and not cookie.is_expired(4_000_000_000)
assert 'HttpOnly' in login_header and 'SameSite=Strict' in login_header
later = Request(url)
jar.add_cookie_header(later)
assert later.get_header('Cookie') == 'ts_session=synthetic-session'
jar.extract_cookies(Response(logout_header), Request(url))
assert not list(jar)
print('PASS: actual login and logout cookies remain tied to browser sessions and clear on logout')

start = src.index('typedef struct', src.index('static esp_err_t tools_query_get('))
probe = src[start:src.index('static const httpd_uri_t uri_tools_ping', start)]
probe_fixture = r'''
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t,BaseType_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define HTTPD_400_BAD_REQUEST 400
#define pdPASS 1
#define CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM 1
#define MALLOC_CAP_SPIRAM 4
#define MALLOC_CAP_8BIT 8
typedef struct {unsigned status;bool allowed,owned;const char *target,*count;} httpd_req_t;
static httpd_req_t *original;
static bool fail_async,fail_worker,admit=true;
static unsigned began,completed,probes,deletes;
static void (*pending)(void *);
static void *work;
static esp_err_t require_auth(httpd_req_t *r){if(r->allowed)return ESP_OK;r->status=401;return ESP_FAIL;}
static int tools_query_get(httpd_req_t *r,const char *k,char *out,size_t cap){
    const char *v=!strcmp(k,"target")?r->target:r->count;
    if(!v)return ESP_FAIL;
    snprintf(out,cap,"%s",v);return ESP_OK;
}
static size_t strlcpy(char *d,const char *s,size_t n){snprintf(d,n,"%s",s);return strlen(s);}
static bool homelab_ops_admit(void){return admit;}
static char *malloc_body_buf(size_t len){return malloc(len);}
static int httpd_resp_send_err(httpd_req_t *r,int status,const char *message){assert(message);r->status=status;return ESP_OK;}
static int httpd_resp_set_status(httpd_req_t *r,const char *status){r->status=(unsigned)atoi(status);return ESP_OK;}
static int httpd_resp_set_type(httpd_req_t *r,const char *mime){assert(r&&strstr(mime,"text/plain"));return ESP_OK;}
static int httpd_resp_sendstr(httpd_req_t *r,const char *s){assert(s);if(r!=original)original->status=r->status;return ESP_OK;}
static int web_idle_async_begin(httpd_req_t *r,httpd_req_t **copy){
    assert(r==original&&!r->owned);
    if(fail_async)return ESP_FAIL;
    *copy=malloc(sizeof **copy);assert(*copy);**copy=*r;r->owned=true;began++;return ESP_OK;
}
static void web_idle_async_complete(httpd_req_t *r,esp_err_t result){
    assert(r!=original&&original->owned&&result==ESP_OK);original->owned=false;completed++;free(r);
}
static int xTaskCreateWithCaps(void (*fn)(void *),const char *name,unsigned stack,void *arg,int pri,void *handle,int caps){
    assert(original->owned&&!pending&&fn&&name&&arg&&stack==4096&&pri==2&&!handle&&caps==12);
    if(fail_worker)return ESP_FAIL;
    pending=fn;work=arg;return pdPASS;
}
static void net_diag_ping(const char *host,int count,int wait,char *out,size_t len){
    assert(!strcmp(host,"fixture")&&count==10&&wait==1000&&len==2048&&!*out);probes++;
}
static void net_diag_trace(const char *host,int count,int wait,char *out,size_t len){
    assert(!strcmp(host,"fixture")&&count==30&&wait==1500&&len==2048&&!*out);probes++;
}
static void task_reaper_self_delete(void){deletes++;}
'''
probe_tests = r'''
int main(void){
    httpd_req_t first={.target="fixture",.count="99",.status=200};original=&first;
    assert(tools_ping_handler(&first)==ESP_FAIL&&first.status==401&&!began);
    first.allowed=true;admit=false;
    assert(tools_ping_handler(&first)==ESP_OK&&first.status==503&&!first.owned);
    admit=true;fail_async=true;
    assert(tools_ping_handler(&first)==ESP_OK&&first.status==503&&!first.owned);
    fail_async=false;fail_worker=true;
    assert(tools_ping_handler(&first)==ESP_OK&&first.status==503&&!first.owned&&began==completed);
    fail_worker=false;first.status=200;
    assert(tools_ping_handler(&first)==ESP_OK&&first.owned&&pending&&!probes);
    httpd_req_t second={.allowed=true,.target="fixture"};
    assert(tools_trace_handler(&second)==ESP_OK&&second.status==429&&!second.owned&&!probes);
    pending(work);pending=NULL;
    assert(probes==1&&!first.owned&&began==completed&&deletes==1);
    assert(tools_trace_handler(&first)==ESP_OK&&first.owned&&probes==1);
    pending(work);
    assert(probes==2&&!first.owned&&began==completed&&deletes==2);
    puts("PASS: authenticated diagnostics complete asynchronously with one reserved job and release failure paths");
}
'''
with tempfile.TemporaryDirectory(prefix='web-probe-') as directory:
    path = Path(directory) / 'test.c'
    path.write_text(probe_fixture + probe + probe_tests, encoding='utf-8')
    binary = path.with_suffix('.exe' if os.name == 'nt' else '.out')
    subprocess.run([os.environ.get('CC', 'gcc'), *HOST_FLAGS,
                    str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
