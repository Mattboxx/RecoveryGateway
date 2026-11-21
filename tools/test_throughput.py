"""Actual throughput-test core of main/throughput.c.

Covered: URL validation (schemes, hosts, ports, credentials, spaces,
control and quote characters, length), the rate calculation (rounding,
zero, very large values) and the stop rules (time, size, low internal
memory), request size and the deadline worker with simulated RTOS/SDK time.
Real downloads and TLS require separate device coverage. THR_SANITIZE=1 adds ASan/UBSan on Linux.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/throughput.c').read_text(encoding='utf-8')
core = source.split('/* --- throughput core (begin) --- */', 1)[1].split('/* --- throughput core (end) --- */', 1)[0]

PROGRAM = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "throughput.h"
''' + core + r'''
static void test_gateway_deadline(void);
static void test_blob_admission(void);
static void test_gateway_admission(void);
static bool ok(const char *u){char why[96]="";bool v=throughput_url_valid(u,why,sizeof why);assert(v||why[0]);return v;}
int main(void){
    assert(ok("https://speed.cloudflare.com/__down?bytes=25000000")&&ok("http://100.64.0.7/big.iso")&&ok("http://nas:8080/file.bin")&&ok("http://[fd7a::1]/x")==false);
    assert(ok("https://example.org")&&ok("http://192.168.1.10:65535/a"));
    const char *bad[]={NULL,"","ftp://example.org/x","example.org/x","https://","http:///x","http://user:pw@nas/x","http://nas/a b","http://nas/\x01",
        "http://nas/\"x\"","http://nas:0/x","http://nas:65536/x","http://nas:12a/x","https://nas/\\x"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++)assert(!ok(bad[i]));
    char longurl[300];memset(longurl,'a',sizeof longurl-1);longurl[299]=0;memcpy(longurl,"http://nas/",11);assert(!ok(longurl));
    /* kbit/s */
    assert(throughput_kbps(0,1000)==0&&throughput_kbps(1000,0)==0);
    assert(throughput_kbps(125000,1000000)==1000);                              /* 1 Mbit/s */
    assert(throughput_kbps(2500000,1000000)==20000);
    assert(throughput_kbps(1,3)==2667);                                         /* rounded */
    assert(throughput_kbps(UINT64_MAX/16,1)==UINT32_MAX);                        /* saturates */
    /* stop rules */
    assert(!throughput_stop(0,0,10,100000));
    assert(throughput_stop(0,10*1000000ull,10,100000)&&!throughput_stop(0,10*1000000ull-1,10,100000));
    assert(throughput_stop(THR_MAX_BYTES,1,10,100000)&&!throughput_stop(THR_MAX_BYTES-1,1,10,100000));
    assert(strstr(throughput_stop(5,5,10,1000),"memory"));
    assert(throughput_read_limit(0,4096)==4096);
    assert(throughput_read_limit(THR_MAX_BYTES-3,4096)==3);
    assert(throughput_read_limit(THR_MAX_BYTES,4096)==0&&throughput_read_limit(UINT64_MAX,4096)==0);
    uint32_t blob=0;
    assert(throughput_blob_size("65536",&blob)&&blob==65536);
    assert(throughput_blob_size("16777216",&blob)&&blob==THR_BLOB_MAX);
    const char *invalid_sizes[]={"","65535","16777217","4295032832","-4294901760","+65536"," 65536","65536z"};
    for(unsigned i=0;i<sizeof invalid_sizes/sizeof *invalid_sizes;i++)
        assert(!throughput_blob_size(invalid_sizes[i], &blob));
    test_gateway_deadline();
    test_blob_admission();
    test_gateway_admission();
    puts("throughput core: ok");
    return 0;
}
'''


watchdog = source[source.index('#define THR_CHUNK'):source.index('static void worker(void *arg)')]
PROGRAM += r'''
/* Simulated SDK and RTOS time. A socket shut down here is a fixture, and the
 * real transport wakeup and scheduling latency need hardware coverage. */
typedef void *TaskHandle_t;
typedef void *SemaphoreHandle_t;
typedef void *esp_http_client_handle_t;
typedef unsigned TickType_t;
#define taskENTER_CRITICAL(mux) ((void)(mux))
#define taskEXIT_CRITICAL(mux) ((void)(mux))
#define pdMS_TO_TICKS(ms) ((unsigned)(ms) / 10u)
#define portMAX_DELAY UINT32_MAX
#define pdTRUE 1
#define pdPASS 1
#define eSetBits 1
#define SHUT_RD 0
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_SPIRAM 2
#define ESP_ERR_HTTP_EAGAIN 4
static const int s_mux=0;
static struct {
    bool running;
    char url[244];
    uint32_t seconds;
    uint64_t bytes,elapsed_us;
    int status;
} s_job;
static int64_t now_us, closed_at, read_advance;
static unsigned posted, closes, sem_gives, sem_deletes, waits, reaped, reads;
static int closed_fd, read_result, last_request;
static bool complete, no_sem, no_task;
static int sem_token, task_token;
static unsigned speed_tasks;
static bool speed_task_fail;
static size_t heap_free=30000;

static int64_t esp_timer_get_time(void) {return now_us;}
static int shutdown(int fd,int mode) {assert(mode==SHUT_RD);closes++;closed_fd=fd;closed_at=now_us;return 0;}
static int xTaskNotifyWait(uint32_t entry,uint32_t exit,uint32_t *cmd,TickType_t timeout) {
    assert(!entry&&exit==UINT32_MAX);waits++;
    if (timeout==portMAX_DELAY) {
        *cmd=2;return pdTRUE;
    }
    now_us+=(int64_t)timeout*10000;
    return 0;
}
static SemaphoreHandle_t xSemaphoreCreateBinary(void) {return no_sem?NULL:&sem_token;}
static void xSemaphoreGive(SemaphoreHandle_t sem) {assert(sem==&sem_token);sem_gives++;}
static void xSemaphoreTake(SemaphoreHandle_t sem,TickType_t ticks) {
    assert(sem==&sem_token&&ticks==portMAX_DELAY&&posted==2&&sem_gives);
}
static void vSemaphoreDelete(SemaphoreHandle_t sem) {assert(sem==&sem_token);sem_deletes++;}
static int xTaskCreateWithCaps(void (*fn)(void *), const char *name, unsigned stack, void *arg,
                            unsigned pri, TaskHandle_t *task,int caps) {
    assert(fn&&name&&pri==3&&caps==MALLOC_CAP_SPIRAM);
    if (!strcmp(name,"speedtest")) {
        assert(!arg&&!task&&stack==8192);speed_tasks++;
        return speed_task_fail ? 0 : pdPASS;
    }
    assert(arg&&stack==4096&&task);
    if (no_task) return 0;
    *task=&task_token;return pdPASS;
}
static void xTaskNotify(TaskHandle_t task,unsigned bits,int act) {
    assert(task==&task_token&&act==eSetBits);posted=bits;
}
static void task_reaper_self_delete(void) {reaped++;}
static size_t heap_caps_get_free_size(int caps) {assert(caps==MALLOC_CAP_INTERNAL);return heap_free;}
static int esp_http_client_read(esp_http_client_handle_t client,char *buf,int n) {
    assert(client&&buf&&n>0);reads++;last_request=n;
    now_us+=read_advance;
    assert(read_result<=n);
    return read_result;
}
static bool esp_http_client_is_complete_data_received(esp_http_client_handle_t client) {
    assert(client);return complete;
}
''' + watchdog + r'''
static void test_gateway_deadline(void) {
    throughput_deadline_t job = {0};
    assert(!deadline_start(&job,-1)&&!sem_deletes);
    no_sem=true;assert(!deadline_start(&job,9)&&!sem_deletes);
    no_sem=false;no_task=true;assert(!deadline_start(&job,9)&&sem_deletes==1);
    no_task=false;now_us=1000000;
    assert(deadline_start(&job,9)&&job.due_us==11000000);
    assert(!deadline_for_body(&job,11000000,3));
    deadline_worker(&job);
    assert(job.expired&&closed_fd==9&&closes==1&&closed_at>=11000000&&closed_at<11020000);
    assert(sem_gives==1&&reaped==1&&!deadline_for_body(&job,closed_at,3));
    deadline_finish(&job);
    assert(sem_deletes==2&&posted==2);

    job=(throughput_deadline_t){0};now_us=1000000;
    assert(deadline_start(&job,11));
    assert(deadline_for_body(&job,1500000,3)&&job.due_us==4500000&&posted==1);
    now_us=1500000;deadline_worker(&job);
    assert(job.expired&&closed_fd==11&&closes==2&&closed_at>=4500000&&closed_at<4520000);
    deadline_finish(&job);assert(sem_gives==2&&sem_deletes==3&&reaped==2&&waits==4);

    char buf[4096];
    uint64_t bytes=THR_MAX_BYTES-3;
    now_us=1000000;s_job.seconds=3;read_advance=50000;read_result=3;
    assert(!strcmp(read_test_payload(&job,buf,now_us,&bytes,200),"size limit reached"));
    assert(bytes==THR_MAX_BYTES&&last_request==3&&reads==1&&s_job.status==200);
    bytes=0;read_result=-ESP_ERR_HTTP_EAGAIN;read_advance=1000000;
    assert(!strcmp(read_test_payload(&job,buf,now_us,&bytes,200),"time limit reached"));
    assert(bytes==0&&reads==4);
    read_result=1;read_advance=1000000;
    assert(!strcmp(read_test_payload(&job,buf,now_us,&bytes,200),"time limit reached"));
    assert(bytes==3&&reads==7);
    read_result=0;complete=true;
    assert(!strcmp(read_test_payload(&job,buf,now_us,&bytes,200),"file complete"));
    complete=false;
    assert(!strcmp(read_test_payload(&job,buf,now_us,&bytes,200),"connection closed"));
    unsigned reads_before=reads;heap_free=1000;
    assert(strstr(read_test_payload(&job,buf,now_us,&bytes,200),"memory low"));
    assert(reads==reads_before);
    puts("PASS: gateway header and payload deadlines, socket lifecycle and exact byte budget");
}
'''

blob = source[source.index('static esp_err_t get_blob('):source.index('esp_err_t throughput_register_http(')]
PROGRAM += r'''
typedef struct {const char *query;int status;bool authorized;size_t content_len;} httpd_req_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NOT_FOUND -2
#define HTTPD_400_BAD_REQUEST 400
static uint32_t accepted_bytes;
static unsigned admitted;
static int web_ui_require_auth(httpd_req_t *req) {
    if (req->authorized) return ESP_OK;
    req->status=401;return ESP_FAIL;
}
static size_t httpd_req_get_url_query_len(httpd_req_t *req) {
    return strlen(req->query);
}
static int httpd_req_get_url_query_str(httpd_req_t *req,char *out,size_t capacity) {
    size_t n=strlen(req->query);
    if (n>=capacity) return ESP_FAIL;
    memcpy(out,req->query,n+1);return ESP_OK;
}
static int httpd_query_key_value(const char *query,const char *key,char *out,size_t capacity) {
    assert(!strcmp(key,"bytes"));
    if (strncmp(query,"bytes=",6))return ESP_ERR_NOT_FOUND;
    size_t n=strlen(query+6);
    if(n>=capacity)return ESP_FAIL;
    memcpy(out,query+6,n+1);return ESP_OK;
}
static int httpd_resp_send_err(httpd_req_t *req,int code,const char *text) {
    assert(text);req->status=code;return ESP_OK;
}
static int serve_blob(httpd_req_t *req,const void *arg) {
    assert(req->authorized);memcpy(&accepted_bytes,arg,sizeof accepted_bytes);return ESP_OK;
}
static int web_transfer_start(httpd_req_t *req,int (*serve)(httpd_req_t *,const void *),
                              const void *argument,size_t size) {
    assert(size==sizeof accepted_bytes);admitted++;return serve(req,argument);
}
''' + blob + r'''
static void test_blob_admission(void) {
    httpd_req_t req={.query="",.authorized=true};
    assert(get_blob(&req)==ESP_OK&&accepted_bytes==4194304&&admitted==1);
    req.query="bytes=65536";
    assert(get_blob(&req)==ESP_OK&&accepted_bytes==65536&&admitted==2);
    const char *bad[]={"bytes=","bytes=+65536","bytes=65536z","bytes=4295032832",
                       "bytes=65536&ignored=11111111111111111111","bytes=000000065536"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){
        req.query=bad[i];req.status=0;
        assert(get_blob(&req)==ESP_FAIL&&req.status==400&&admitted==2);
    }
    req.authorized=false;req.query="bytes=65536";
    assert(get_blob(&req)==ESP_FAIL&&req.status==401&&admitted==2);
    puts("PASS: browser blob admission and exact size validation");
}
'''

admission = source[source.index('static esp_err_t post_test('):source.index('static esp_err_t serve_blob(')]
PROGRAM += r'''
typedef struct {int kind;char *valuestring;double valuedouble;} cJSON;
static cJSON fake_root={.kind=1}, fake_url={.kind=2,.valuestring="http://lab.invalid/file"};
static bool guard_open=true;
static unsigned guard_calls;
static char post_message[160];
static int httpd_req_recv(httpd_req_t *req,char *out,size_t len) {
    assert(len==req->content_len&&len==2);memcpy(out,"{}",2);return 2;
}
static cJSON *json_guard_parse(const char *body) {
    return !strcmp(body,"{}")?&fake_root:NULL;
}
static bool cJSON_IsObject(const cJSON *item) {return item&&item->kind==1;}
static bool cJSON_IsString(const cJSON *item) {return item&&item->kind==2;}
static bool cJSON_IsNumber(const cJSON *item) {return item&&item->kind==3;}
static cJSON *cJSON_GetObjectItemCaseSensitive(cJSON *item,const char *key) {
    return item&&!strcmp(key,"url")?&fake_url:NULL;
}
static void cJSON_Delete(cJSON *item) {assert(!item||item==&fake_root);}
static bool homelab_ops_admit(void) {guard_calls++;return guard_open;}
static void worker(void *arg) {assert(!arg);}
static esp_err_t httpd_resp_set_type(httpd_req_t *req,const char *type) {
    assert(req&&!strcmp(type,"application/json"));return ESP_OK;
}
static esp_err_t httpd_resp_set_status(httpd_req_t *req,const char *status) {
    req->status=atoi(status);return ESP_OK;
}
static esp_err_t httpd_resp_sendstr(httpd_req_t *req,const char *body) {
    assert(req);snprintf(post_message,sizeof post_message,"%s",body);return ESP_OK;
}
''' + admission + r'''
static void test_gateway_admission(void) {
    httpd_req_t req={.content_len=2};
    assert(post_test(&req)==ESP_FAIL&&req.status==401&&!speed_tasks&&!guard_calls);
    req.authorized=true;
    char *valid=fake_url.valuestring;
    fake_url.valuestring="bad";
    assert(post_test(&req)==ESP_OK&&req.status==400&&!speed_tasks&&!guard_calls);
    fake_url.valuestring=valid;
    heap_free=24000;
    assert(post_test(&req)==ESP_OK&&req.status==503&&!speed_tasks&&!s_job.running);
    assert(strstr(post_message,"not enough free memory")&&!guard_calls);
    heap_free=30000;guard_open=false;
    assert(post_test(&req)==ESP_OK&&req.status==503&&!speed_tasks&&!s_job.running);
    assert(strstr(post_message,"resource guard")&&guard_calls==1);
    guard_open=true;speed_task_fail=true;
    assert(post_test(&req)==ESP_OK&&req.status==503&&speed_tasks==1&&!s_job.running);
    speed_task_fail=false;req.status=200;
    assert(post_test(&req)==ESP_OK&&req.status==200&&s_job.running&&speed_tasks==2);
    assert(post_test(&req)==ESP_OK&&req.status==409&&speed_tasks==2);
    puts("PASS: gateway speed test respects Resource Guard and reports refusal correctly");
}
'''

def main():
    with tempfile.TemporaryDirectory(prefix='thr-') as folder:
        path = Path(folder)
        (path / 'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n', encoding='utf-8')
        (path / 'esp_http_server.h').write_text('#pragma once\ntypedef void *httpd_handle_t;\n', encoding='utf-8')
        (path / 'thr.c').write_text(PROGRAM, encoding='utf-8')
        binary = path / ('thr.exe' if os.name == 'nt' else 'thr')
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(path), '-I', str(ROOT / 'main')]
        if os.environ.get('THR_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'thr.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=60)


if __name__ == '__main__':
    main()
