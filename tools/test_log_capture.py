"""Actual unchanged log ring functions; synthetic critical sections.
No RTC persistence, concurrent tasks or physical crash/power test is claimed.
LOG_SANITIZE=1 enables host ASan/UBSan.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/log_capture.c').read_text(encoding='utf-8')
def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}', start) + 2] + '\n'

web = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')
start = web.index('static esp_err_t log_raw_handler(httpd_req_t *req)')
log_handler = web[start:web.index('\n}', start) + 2]

constants = '\n'.join(line for line in source.splitlines() if line.startswith((
    '#define DEFAULT_BUFFER_BYTES', '#define INTERNAL_FALLBACK_BYTES',
    '#define MAX_BUFFER_BYTES', '#define ROUND_UP_1K', '#define PRECRASH_RING_BYTES')))
program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MALLOC_CAP_SPIRAM 1
#define taskENTER_CRITICAL(x) ((void)(x))
#define taskEXIT_CRITICAL(x) ((void)(x))
''' + constants + r'''
static char *s_buf;static size_t s_head,s_count,s_cap;static uint64_t s_seq;static int s_lock,s_precrash_lock;
static struct {size_t head,count;char data[PRECRASH_RING_BYTES];} s_precrash;
#include <time.h>
''' + function('static int64_t log_boot_ms(') + function('static void buffer_append(') + function('size_t log_capture_read(') + function('size_t log_capture_read_since(') + function('void log_capture_clear(') + r'''
static void test_log_http(void);
int main(void){
 s_cap=DEFAULT_BUFFER_BYTES;s_buf=calloc(s_cap,1);char input[1024],*out=calloc(s_cap+1,1);assert(s_buf&&out&&s_cap==16*1024);
 for(unsigned i=0;i<72;i++){memset(input,(int)('A'+i%26),sizeof input);buffer_append(input,sizeof input);}
 assert(s_seq==72*1024&&s_count==s_cap&&s_precrash.count==4096);
 assert(log_capture_read(out,s_cap+1)==s_cap);
 for(unsigned i=0;i<16;i++)for(unsigned j=0;j<1024;j++)assert(out[i*1024+j]==(char)('A'+(i+56)%26));
 uint64_t seq;assert(log_capture_read_since(0,out,s_cap+1,&seq)==s_cap&&seq==s_seq);
 char tail[8];assert(log_capture_read(tail,sizeof tail)==7&&!strcmp(tail,"TTTTTTT"));
 assert(log_capture_read_since(s_seq,out,s_cap+1,&seq)==0&&seq==s_seq);
 log_capture_clear();assert(!s_count&&s_seq==72*1024);buffer_append("new",3);
 assert(log_capture_read_since(seq,out,s_cap+1,&seq)==3&&!strcmp(out,"new"));
 /* Start of this boot for dating the next boot's pre-crash lines: none before the clock. */
 assert(log_boot_ms(1699999999,999999,5)==0&&log_boot_ms(0,0,0)==0);
 assert(log_boot_ms(1763460000,500000,61000)==1763460000LL*1000+500-61000);
 test_log_http();
 free(out);free(s_buf);puts("PASS actual log ring: unchanged 16KB capacity, 4KB RTC, wrap, cursor, tail and clear; boot start for dating");
}
'''
program += r'''
#include <stdbool.h>
#include <sys/time.h>
typedef int esp_err_t;
typedef struct { size_t calls, fail_at, length; char output[2048]; } httpd_req_t;
#define ESP_OK 0
#define ESP_FAIL (-2)
#define ESP_ERR_NOT_FOUND (-1)
#define ESP_ERR_HTTPD_RESP_SEND (-27)
static int require_auth(httpd_req_t *req) { (void)req; return ESP_OK; }
static void esp_fill_random(void *dst, size_t n) { memset(dst, 0, n); }
static uint32_t esp_log_timestamp(void) { return 5; }
static size_t log_capture_size(void) { return s_count; }
static size_t log_capture_capacity(void) { return s_cap; }
static int tools_query_get(httpd_req_t *req, const char *key, char *buf, size_t n) {
 (void)req;(void)key;(void)buf;(void)n;return ESP_ERR_NOT_FOUND;
}
static void httpd_resp_set_type(httpd_req_t *req, const char *type) { (void)req;(void)type; }
static void httpd_resp_set_status(httpd_req_t *req, const char *status) { (void)req;(void)status; }
static int httpd_resp_sendstr(httpd_req_t *req, const char *data) { (void)req;(void)data;return ESP_OK; }
static int httpd_resp_send_chunk(httpd_req_t *req, const char *data, size_t n) {
 if (++req->calls == req->fail_at) return ESP_ERR_HTTPD_RESP_SEND;
 assert(req->length + n < sizeof(req->output));
 if (n) memcpy(req->output + req->length, data, n);
 req->length += n;
 return ESP_OK;
}
static int httpd_resp_sendstr_chunk(httpd_req_t *req, const char *data) {
 return httpd_resp_send_chunk(req, data, data ? strlen(data) : 0);
}
''' + log_handler + r'''
static void test_log_http(void) {
 char source[1200];
 memset(source, 'x', sizeof(source));
 memcpy(source, "\"\\\n\r\t\001", 6);
 log_capture_clear();
 buffer_append(source, sizeof(source));
 httpd_req_t response = {0};
 assert(log_raw_handler(&response) == ESP_OK && response.calls == 5);
 assert(strstr(response.output, "\\\"\\\\\\n\\r\\t\\u0001"));
 assert(!strcmp(response.output + response.length - 2, "\"}"));
 for (size_t fail = 1; fail <= response.calls; fail++) {
   httpd_req_t broken = {.fail_at = fail};
   assert(log_raw_handler(&broken) == ESP_ERR_HTTPD_RESP_SEND);
   assert(broken.calls == fail);
 }
 puts("PASS live-log HTTP chunks and early termination for all write failures");
}
'''
flat = source.replace('\r\n', '\n')
store = flat[flat.index('int log_capture_store('):]
store = store[:store.index('\n}\n')]
assert 'if (!s_boot_ms_known) {' in store and 'if (b) { s_precrash.boot_ms = b; s_boot_ms_known = true; }' in store
init = flat[flat.index('esp_err_t log_capture_init('):]
init = init[:init.index('\n}\n')]
assert init.index('s_snapshot_boot_ms = s_precrash.boot_ms > 0') < init.index('s_precrash.boot_ms = 0;')
assert '#define PRECRASH_MAGIC        0xC0DEAFF3u' in flat   # older rings (no boot_ms) are not misread
with tempfile.TemporaryDirectory(prefix='log-capture-') as folder:
    path = Path(folder); c = path / 'case.c'; c.write_text(program, encoding='utf-8')
    binary = path / ('case.exe' if os.name == 'nt' else 'case')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
    if os.environ.get('LOG_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC','gcc'), *flags, str(c), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
