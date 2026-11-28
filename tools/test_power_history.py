"""Actual checkpoint module with mock NVS, clock and HTTP work queue; no hardware."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include "power_history.h"
#include "nvs_params.h"
static uint32_t persisted;
static bool erase_fail, write_fail, queue_fail;
static unsigned writes, queued;
static int64_t monotonic_us;
static time_t wall;
static void (*callback)(void *);
time_t time(time_t *t) { if(t) *t=wall; return wall; }
int64_t esp_timer_get_time(void) { return monotonic_us; }
esp_err_t nvs_param_get_u32(const char *key,uint32_t *out) {
 (void)key; if(!persisted) return -1; *out=persisted; return ESP_OK;
}
esp_err_t nvs_param_erase(const char *key) {
 (void)key; if(erase_fail) return -1; persisted=0; return ESP_OK;
}
esp_err_t nvs_param_set_u32(const char *key,uint32_t value) {
 (void)key; writes++; if(write_fail) return -1; persisted=value; return ESP_OK;
}
esp_err_t httpd_queue_work(httpd_handle_t server, void (*work)(void *), void *arg) {
 assert(server && !arg); queued++; if(queue_fail) return -1;
 callback=work; return ESP_OK;
}
static void advance(unsigned seconds) { monotonic_us+=(int64_t)seconds*1000000; wall+=seconds; }
static void run(void) { assert(callback); callback(NULL); callback=NULL; }
int main(void) {
 power_history_init();
 assert(power_history_previous_online()==0);
 power_history_tick(); assert(!queued && !writes);
 wall=1704067200; power_history_tick(); assert(!queued);
 power_history_bind((void*)1);
 power_history_tick(); assert(queued==1 && !writes); run(); assert(writes==1 && persisted==wall);
 for(int i=0;i<299;i++){ advance(1);power_history_tick(); }
 assert(queued==1 && writes==1);
 advance(1); power_history_tick(); run(); assert(writes==2);
 /* Saved before power-off, read once before the new boot can overwrite it. */
 uint32_t last=persisted; monotonic_us=0; wall=0;
 power_history_init(); assert(!persisted && power_history_previous_online()==last);
 wall=last+3600; assert(power_history_previous_online()==last);
 power_history_tick();run();
 assert(power_history_previous_online()==last);
 /* A short second boot has no checkpoint to misattribute to that boot. */
 power_history_init();power_history_init();assert(power_history_previous_online()==0);
 /* An untrusted or backwards clock yields unknown. */
 persisted=1704067200;power_history_init();wall=1704067199;
 assert(power_history_previous_online()==0);
 wall=0;unsigned n=queued;power_history_tick();assert(queued==n);
 /* Corrupt/future record, and consume failure, both suppress the report. */
 persisted=123;power_history_init();wall=1704067200;assert(power_history_previous_online()==0);
 persisted=UINT32_MAX;power_history_init();assert(power_history_previous_online()==0);
 persisted=1704067200;erase_fail=true;power_history_init();assert(power_history_previous_online()==0);
 erase_fail=false;power_history_init();
 /* Queue errors and lost deliveries never prevent future checkpoints. */
 queue_fail=true;monotonic_us=0;power_history_tick();n=queued;
 advance(299);power_history_tick();assert(queued==n);
 advance(1);queue_fail=false;power_history_tick();assert(queued==n+1);
 callback=NULL;advance(300);power_history_tick();run();
 /* NVS failure is bounded, and a duplicate callback cannot amplify writes. */
 advance(300);write_fail=true;power_history_tick();
 void (*late)(void*)=callback;run();n=writes;late(NULL);assert(writes==n);
 advance(299);power_history_tick();assert(writes==n);
 advance(1);write_fail=false;power_history_tick();run();assert(writes==n+1);
 puts("PASS: real power checkpoint C, consume-on-boot, invalid clocks, rapid boots, queue loss, NVS failure and 300 s write limit");
}
'''
with tempfile.TemporaryDirectory(prefix='power-history-') as folder:
    p = Path(folder)
    (p/'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n')
    (p/'esp_http_server.h').write_text('#pragma once\n#include "esp_err.h"\ntypedef void *httpd_handle_t;\nesp_err_t httpd_queue_work(httpd_handle_t,void (*)(void*),void*);\n')
    (p/'esp_timer.h').write_text('#pragma once\n#include <stdint.h>\nint64_t esp_timer_get_time(void);\n')
    (p/'test.c').write_text(PROGRAM)
    binary=p/('test.exe' if os.name=='nt' else 'test')
    flags=['-std=c11','-Wall','-Wextra','-Werror','-I',str(p),'-I',str(ROOT/'main')]
    subprocess.run([os.environ.get('CC','gcc'),*flags,str(p/'test.c'),str(ROOT/'main/power_history.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=15)
