"""Exercise the firmware's scan state machine with a stubbed SDK and clock."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')
start = source.rindex('typedef enum {', 0, source.index('    SCAN_IDLE'))
end = source.index('static esp_err_t network_scan_result_handler(')

SDK = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_WIFI_STATE 2
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define EXT_RAM_BSS_ATTR
#define WIFI_EVENT 1
#define WIFI_EVENT_SCAN_DONE 2
#define WIFI_SCAN_TYPE_PASSIVE 1
#define portMAX_DELAY 100
#define pdTRUE 1
#define pdMS_TO_TICKS(n) (n)
typedef int esp_err_t, esp_event_base_t;
typedef int *SemaphoreHandle_t, *esp_timer_handle_t;
typedef struct { int status; } wifi_event_sta_scan_done_t;
typedef struct { int unused; } wifi_ap_record_t;
typedef struct { void *ssid, *bssid; int channel; bool show_hidden; int scan_type; struct { int passive; } scan_time; } wifi_scan_config_t;
typedef struct { void (*callback)(void *); const char *name; bool skip_unhandled_events; } esp_timer_create_args_t;
typedef struct { const char *status; char body[160]; } httpd_req_t;
static bool fail_mutex, fail_timer, fail_event, fail_arm, pause_on_start, paused, armed, held;
static int live_mutex, live_timer, stops, starts, resume_count;
static int64_t now;
static SemaphoreHandle_t xSemaphoreCreateMutex(void) { if (fail_mutex) return NULL; live_mutex++; return &live_mutex; }
static void vSemaphoreDelete(SemaphoreHandle_t mutex) { assert(mutex && !held); live_mutex--; }
static int xSemaphoreTake(SemaphoreHandle_t mutex, int wait) { (void)wait; assert(mutex && !held); held=true; return pdTRUE; }
static void xSemaphoreGive(SemaphoreHandle_t mutex) { assert(mutex && held); held=false; }
static int esp_timer_create(const esp_timer_create_args_t *args, esp_timer_handle_t *timer) {
    assert(args->callback);
    if (fail_timer) return ESP_FAIL;
    live_timer++; *timer=&live_timer; return ESP_OK;
}
static int esp_timer_delete(esp_timer_handle_t timer) { assert(timer && !armed); live_timer--; return ESP_OK; }
static int esp_timer_start_periodic(esp_timer_handle_t timer, uint64_t interval) {
    assert(timer && interval && !armed);
    if (fail_arm) return ESP_FAIL;
    armed=true; return ESP_OK;
}
static int esp_timer_stop(esp_timer_handle_t timer) { assert(timer && armed); armed=false; return ESP_OK; }
static int64_t esp_timer_get_time(void) { return now; }
static int esp_event_handler_register(esp_event_base_t base, int id,
                                      void (*callback)(void *, esp_event_base_t, int32_t, void *), void *arg) {
    assert(base==WIFI_EVENT && id==WIFI_EVENT_SCAN_DONE && callback && !arg);
    return fail_event ? ESP_FAIL : ESP_OK;
}
static int esp_wifi_scan_start(const wifi_scan_config_t *cfg, bool block) {
    assert(cfg->scan_type==WIFI_SCAN_TYPE_PASSIVE && !block && armed);
    starts++; return pause_on_start && !paused ? ESP_ERR_WIFI_STATE : ESP_OK;
}
static int esp_wifi_scan_stop(void) { stops++; return ESP_OK; }
static int esp_wifi_clear_ap_list(void) { return ESP_OK; }
static int esp_wifi_scan_get_ap_num(uint16_t *n) { *n=1; return ESP_OK; }
static int esp_wifi_scan_get_ap_records(uint16_t *n, wifi_ap_record_t *records) { assert(*n==1 && records); return ESP_OK; }
static const char *esp_err_to_name(esp_err_t err) { (void)err; return "error"; }
static void vTaskDelay(int ticks) { (void)ticks; }
static void wifi_sta_pause_for_scan(void) { paused=true; }
static void wifi_sta_resume_after_scan(void) { if (paused) resume_count++; paused=false; }
static bool first_boot_active(void) { return false; }
static bool web_ui_setup_request_ok(httpd_req_t *req) { (void)req; return false; }
static int require_auth(httpd_req_t *req) { (void)req; return ESP_OK; }
static void httpd_resp_set_status(httpd_req_t *req, const char *status) { req->status=status; }
static void httpd_resp_set_type(httpd_req_t *req, const char *type) { (void)req; (void)type; }
static int httpd_resp_sendstr(httpd_req_t *req, const char *body) { snprintf(req->body,sizeof req->body,"%s",body); return ESP_OK; }
'''

TESTS = r'''
int main(void) {
    httpd_req_t req={0};
    fail_mutex=true; network_scan_handler(&req); fail_mutex=false;
    assert(req.status && !live_mutex && !live_timer && !starts);
    fail_timer=true; network_scan_handler(&req); fail_timer=false;
    assert(!live_mutex && !live_timer && !starts);
    fail_event=true; network_scan_handler(&req); fail_event=false;
    assert(!live_mutex && !live_timer && !starts);
    fail_arm=true; network_scan_handler(&req); fail_arm=false;
    assert(s_scan_state==SCAN_ERROR && !armed && !starts);
    pause_on_start=true; network_scan_handler(&req);
    assert(paused && armed && starts==2);
    network_scan_handler(&req); assert(starts==2);
    now=SCAN_TIMEOUT_US-1; scan_timeout(NULL); assert(paused && armed);
    now++; scan_timeout(NULL);
    assert(s_scan_state==SCAN_ERROR && !paused && !armed && stops==1 && resume_count==1);
    network_scan_handler(&req); assert(starts==2);
    wifi_event_sta_scan_done_t complete={0};
    scan_done_event(NULL,WIFI_EVENT,WIFI_EVENT_SCAN_DONE,&complete);
    assert(s_scan_state==SCAN_ERROR);
    now+=SCAN_WATCHDOG_US; pause_on_start=false; network_scan_handler(&req);
    assert(starts==3 && armed);
    scan_done_event(NULL,WIFI_EVENT,WIFI_EVENT_SCAN_DONE,&complete);
    assert(s_scan_state==SCAN_READY && s_scan_count==1 && !armed);
    now+=SCAN_TIMEOUT_US; scan_timeout(NULL); assert(stops==1);
    network_scan_handler(&req); complete.status=1;
    scan_done_event(NULL,WIFI_EVENT,WIFI_EVENT_SCAN_DONE,&complete);
    assert(s_scan_state==SCAN_ERROR && s_scan_count==0 && !armed);
    puts("PASS: actual Wi-Fi scan admission, timeout, reconnect and completion (SDK fixtures)");
}
'''

with tempfile.TemporaryDirectory(prefix='wifi-scan-') as folder:
    directory = Path(folder)
    program = directory / 'scan.c'
    executable = directory / ('scan.exe' if os.name == 'nt' else 'scan')
    program.write_text(SDK + source[start:end] + TESTS, encoding='utf-8')
    subprocess.run([os.environ.get('CC', 'gcc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    str(program), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)
