"""Actual SDK MQTT startup / teardown and project startup-task behavior tests.

Host allocator/RTOS fixtures, NOT hardware fragmentation or full MQTT testing.
MQTT_SOURCE selects the reviewed ESP-MQTT 1.1.0 managed source. TASKMEM_SANITIZE=1 adds
Linux ASan/UBSan. No device access, downloads or SDK modifications.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SDK_HASH = '83e5a7065b8774dce83dd6b9be0163caed3a4fdbbd7de38b328e7e01911487dc'
sdk_path = Path(os.environ.get('MQTT_SOURCE', str(ROOT /
    'managed_components/espressif__mqtt/mqtt_client.c')))
sdk_bytes = sdk_path.read_bytes()
assert hashlib.sha256(sdk_bytes).hexdigest() == SDK_HASH, 'Unreviewed MQTT source'
sdk = sdk_bytes.decode('utf-8')
sdk_start = 'esp_err_t esp_mqtt_client_start(' + sdk.split(
    'esp_err_t esp_mqtt_client_start(', 1)[1].split('\nesp_err_t esp_mqtt_client_disconnect', 1)[0]
# Use the actual worker's teardown statements, including the paired delete.
sdk_cleanup = 'static void worker_cleanup(esp_mqtt_client_handle_t client) {\n' + (
    '    client->state = MQTT_STATE_DISCONNECTED;' + sdk.split(
        '\nesp_err_t esp_mqtt_client_start', 1)[0].rsplit(
        '    client->state = MQTT_STATE_DISCONNECTED;', 1)[1])

HEADER = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;
typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define pdPASS 1
#define pdTRUE 1
#define MALLOC_CAP_SPIRAM 0x400
#define MALLOC_CAP_8BIT 0x4
#define portMAX_DELAY 0xffffffffu
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
static int locks, allocations, caps_calls, normal_calls, pinned_calls;
static int deletes, caps_deletes, mutex_calls, config_loads;
static bool oom, mutex_oom;
static unsigned largest_internal = 3456;
static void *s_lock;
static void check_create(TaskFunction_t fn, const char *name, unsigned size,
                         void *arg, unsigned priority, TaskHandle_t *out) {
    (void)arg;(void)priority;assert(fn && name && size >= 4096);
    allocations++; if(out) *out = NULL;
}
static int xTaskCreate(TaskFunction_t fn,const char *name,unsigned size,void *arg,
                       unsigned priority,TaskHandle_t *out) {
    check_create(fn,name,size,arg,priority,out);normal_calls++;
    if(oom || size>largest_internal)return 0;
    if(out)*out=(void*)1;return pdPASS;
}
static int xTaskCreatePinnedToCore(TaskFunction_t fn,const char *name,unsigned size,
                                  void *arg,unsigned priority,TaskHandle_t *out,int core) {
    assert(core==1 || core==-1);pinned_calls++;return xTaskCreate(fn,name,size,arg,priority,out);
}
static int xTaskCreateWithCaps(TaskFunction_t fn,const char *name,unsigned size,void *arg,
                               unsigned priority,TaskHandle_t *out,unsigned caps) {
    check_create(fn,name,size,arg,priority,out);caps_calls++;
    assert(caps==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));
    if(oom)return 0; /* includes internal TCB or external-stack OOM */
    if(out)*out=(void*)1;return pdPASS;
}
static int xTaskCreatePinnedToCoreWithCaps(TaskFunction_t fn,const char *name,unsigned size,
                   void *arg,unsigned priority,TaskHandle_t *out,int core,unsigned caps) {
    assert(core==1 || core==-1);pinned_calls++;
    return xTaskCreateWithCaps(fn,name,size,arg,priority,out,caps);
}
static void vTaskDelete(void *task){assert(!task);deletes++;}
static void vTaskDeleteWithCaps(void *task){assert(!task);caps_deletes++;}
/* Project reaper: self-deletion without an exit-time internal allocation. */
static int reaper_deletes;
void task_reaper_delete(void *task){assert(!task);reaper_deletes++;}
static void task_reaper_self_delete(void){reaper_deletes++;}
static void *xSemaphoreCreateMutex(void){mutex_calls++;return mutex_oom?NULL:(void*)2;}
static void xSemaphoreTake(void *mutex,unsigned delay){assert(mutex==s_lock&&delay==portMAX_DELAY&&!locks);locks++;}
static void xSemaphoreGive(void *mutex){assert(mutex==s_lock&&locks==1);locks--;}
static void load_config(void){assert(locks==1);config_loads++;}
#define taskENTER_CRITICAL(m) do{(void)(m);assert(!locks);locks++;}while(0)
#define taskEXIT_CRITICAL(m) do{(void)(m);assert(locks==1);locks--;}while(0)
'''

MQTT_FIXTURE = r'''
enum {MQTT_STATE_INIT, MQTT_STATE_DISCONNECTED, MQTT_STATE_CONNECTED};
typedef struct {unsigned task_stack,task_prio;} config_t;
typedef struct {config_t *config;int state,status_bits;TaskHandle_t task_handle;} mqtt_client_t;
typedef mqtt_client_t *esp_mqtt_client_handle_t;
#define MQTT_TASK_CORE 1
#define MQTT_API_LOCK(c) do{assert((c)&&!locks);locks++;}while(0)
#define MQTT_API_UNLOCK(c) do{assert((c)&&locks==1);locks--;}while(0)
#define STOPPED_BIT 1
static void xEventGroupSetBits(int bits,int flag){assert(bits==4&&flag==STOPPED_BIT);}
static void esp_mqtt_task(void *arg){(void)arg;}
'''
MQTT_TEST = r'''
int main(void){
    config_t config={.task_stack=6144,.task_prio=5};
    mqtt_client_t storage={&config,MQTT_STATE_INIT,4,NULL};
    esp_mqtt_client_handle_t client=&storage;
    assert(esp_mqtt_client_start(NULL)==ESP_ERR_INVALID_ARG && !allocations);
    client->state=MQTT_STATE_CONNECTED;
    assert(esp_mqtt_client_start(client)==ESP_FAIL&&!allocations&&!locks);
    client->state=MQTT_STATE_INIT;oom=true;
    assert(esp_mqtt_client_start(client)==ESP_FAIL&&!client->task_handle&&!locks);
    oom=false;
#if CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY
    assert(esp_mqtt_client_start(client)==ESP_OK&&client->task_handle&&!locks);
    assert(caps_calls==2&&!normal_calls); /* succeeds with only 3456 internal */
#else
    assert(esp_mqtt_client_start(client)==ESP_FAIL&&!client->task_handle&&!locks);
    largest_internal=8192;
    assert(esp_mqtt_client_start(client)==ESP_OK&&normal_calls==3&&!caps_calls);
#endif
    worker_cleanup(client);
    assert(client->state==MQTT_STATE_DISCONNECTED);
#if CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY
    assert(reaper_deletes==1&&!caps_deletes&&!deletes); /* never the SDK self-delete */
#else
    assert(deletes==1&&!caps_deletes);
#endif
    /* The real SDK supports start again after a completed stop. */
    assert(esp_mqtt_client_start(client)==ESP_OK&&!locks);
    assert(pinned_calls==allocations);
    puts("PASS: pinned SDK MQTT start/stop, fragmented internal memory, OOM and core selection (host fixtures)");
}
'''

manager_source = (ROOT / 'main/mqtt_integration.c').read_text(encoding='utf-8')
manager_budget = next(line for line in manager_source.splitlines()
                      if line.startswith('#define MQTT_MANAGER_STACK_BYTES ')) + '\n'
manager_init = 'void mqtt_integration_init(void)' + manager_source.split(
    'void mqtt_integration_init(void)', 1)[1].split('\nvoid mqtt_integration_get_config', 1)[0]
tail_source = (ROOT / 'main/tailscale_manager.c').read_text(encoding='utf-8')
admission = tail_source.split('static void tailscale_admission_schedule(', 1)[1].split(
    '\nstatic void tailscale_connect_task(void *pvParameters)\n', 1)[0]
tail_start = '\n'.join(line for line in tail_source.splitlines() if line.startswith('#define TS_ADMISSION_')) + '\n'
tail_start += 'esp_err_t tailscale_start_error(void)' + tail_source.split(
    'esp_err_t tailscale_start_error(void)', 1)[1].split('static uint32_t s_lifecycle_generation', 1)[0]
tail_start += 'static void tailscale_admission_schedule(' + admission
PROJECT_FIXTURE = r'''
static bool tailscale_enabled, s_connect_in_flight, s_instance_ready, s_start_retrying, s_admission_pending;
static bool s_start_cleanup_failed, cleanup_fails;
static esp_err_t s_start_error;
static unsigned s_admission_backoff;
static int s_connect_lock;
static esp_err_t connect_result = ESP_ERR_NO_MEM;
static unsigned connect_calls, in_task_delays;
#define pdMS_TO_TICKS(ms) (ms)
static void vTaskDelay(unsigned ms){
    assert(!locks && s_start_retrying && s_connect_in_flight);
    assert(ms==(2000u << (in_task_delays++ % 4)));
}
static esp_err_t tailscale_connect(void){
    assert(!locks && s_connect_in_flight);
    connect_calls++;
    if(connect_result==ESP_OK) s_instance_ready=true;
    if(cleanup_fails) s_start_cleanup_failed=true;
    s_start_error=connect_result;
    return connect_result;
}
static TaskHandle_t s_manager_task;
static void tailscale_connect_task(void *arg){(void)arg;}
static void manager_task(void *arg){(void)arg;}
#define ESP_LOGW(...) ((void)0)
typedef int esp_event_base_t;
enum {TAILSCALE_ADMISSION_EVENT=1};
typedef struct {void (*callback)(void *); const char *name;} esp_timer_create_args_t;
typedef esp_timer_create_args_t *esp_timer_handle_t;
static esp_timer_create_args_t timer;
static esp_timer_handle_t s_admission_timer;
static void (*admission_event)(void *,esp_event_base_t,int32_t,void *);
static bool have_uplink=true, fail_post, fail_timer_create, fail_event_register, fail_timer_start;
static uint64_t armed_us;
esp_err_t tailscale_request_connect(void);
static bool uplink_internet_ready(void){assert(!locks);return have_uplink;}
static esp_err_t esp_timer_create(const esp_timer_create_args_t *args,esp_timer_handle_t *out) {
    assert(!locks && args->callback && args->name);
    if(fail_timer_create)return ESP_FAIL;
    timer=*args;*out=&timer;return ESP_OK;
}
static void esp_timer_delete(esp_timer_handle_t handle){assert(handle==&timer&&!armed_us);}
static esp_err_t esp_timer_start_once(esp_timer_handle_t handle,uint64_t delay_us){
    assert(!locks && handle==&timer && delay_us && !armed_us);
    if(fail_timer_start)return ESP_FAIL;
    armed_us=delay_us;return ESP_OK;
}
static esp_err_t esp_event_handler_register(esp_event_base_t base,int32_t id,
    void (*cb)(void *,esp_event_base_t,int32_t,void *),void *arg){
    assert(base==TAILSCALE_ADMISSION_EVENT && !id && cb && !arg);
    if(fail_event_register)return ESP_FAIL;
    admission_event=cb;return ESP_OK;
}
static bool event_enqueued;
static esp_err_t esp_event_post(esp_event_base_t base,int32_t id,void *data,size_t len,int wait){
    assert(!locks && base==TAILSCALE_ADMISSION_EVENT && !id && !data && !len && !wait && !event_enqueued);
    if(fail_post)return ESP_FAIL;
    event_enqueued=true;return ESP_OK;
}
static void fire_retry(uint64_t expected_us){
    assert(armed_us==expected_us && !event_enqueued);
    armed_us=0;timer.callback(NULL);
    if(event_enqueued){event_enqueued=false;admission_event(NULL,TAILSCALE_ADMISSION_EVENT,0,NULL);}
}
'''
PROJECT_TEST = r'''
int main(void){
    assert(tailscale_request_connect()==ESP_OK&&!allocations);
    tailscale_enabled=true;oom=true;fail_timer_create=true;
    tailscale_admission_retry_init();
    assert(!s_admission_timer && !admission_event);
    fail_timer_create=false;fail_event_register=true;
    tailscale_admission_retry_init();
    assert(!s_admission_timer && !admission_event);
    fail_event_register=false;tailscale_admission_retry_init();
    assert(s_admission_timer && admission_event);
    assert(tailscale_request_connect()==ESP_ERR_NO_MEM && !s_connect_in_flight && !locks);
    assert(tailscale_start_error()==ESP_ERR_NO_MEM && tailscale_start_retrying());
    for(int i=0;i<1000;i++)assert(tailscale_request_connect()==ESP_OK);
    assert(allocations==1); /* No fresh IP event is needed. */
    fail_post=true;fire_retry(2000000);
    assert(allocations==1&&armed_us==2000000&&tailscale_start_retrying());
    fail_post=false;
    fire_retry(2000000);
    fire_retry(4000000);
    fire_retry(8000000);
    fire_retry(16000000);
    fire_retry(30000000);
    assert(armed_us==30000000&&tailscale_start_retrying());
    have_uplink=false;fire_retry(30000000);
    assert(!armed_us&&!tailscale_start_retrying()&&!s_admission_backoff&&!s_connect_in_flight);
    have_uplink=true;
    assert(tailscale_request_connect()==ESP_ERR_NO_MEM);
    tailscale_enabled=false;fire_retry(2000000);
    assert(!armed_us&&!tailscale_start_retrying()&&!s_connect_in_flight);
    tailscale_enabled=true;fail_timer_start=true;
    assert(tailscale_request_connect()==ESP_ERR_NO_MEM&&!tailscale_start_retrying()&&!armed_us);
    fail_timer_start=false;
    assert(tailscale_request_connect()==ESP_ERR_NO_MEM && tailscale_start_retrying());
    oom=false;fire_retry(4000000);
    assert(s_connect_in_flight&&!tailscale_start_retrying()&&!armed_us);
    int before=allocations;
    for(int i=0;i<1000;i++)assert(tailscale_request_connect()==ESP_OK);
    assert(allocations==before); /* duplicate GOT_IP never allocates */
    tailscale_start_attempts();
    assert(connect_calls==5 && in_task_delays==4 && !s_connect_in_flight && tailscale_start_retrying());
    assert(tailscale_start_error()==ESP_ERR_NO_MEM && armed_us==8000000);
    assert(tailscale_request_connect()==ESP_OK && allocations==before);
    fire_retry(8000000);tailscale_start_attempts();
    assert(connect_calls==10 && in_task_delays==8 && armed_us==16000000);
    connect_result=ESP_ERR_INVALID_ARG;
    fire_retry(16000000);tailscale_start_attempts();
    assert(connect_calls==11 && !tailscale_start_retrying() && !armed_us);
    assert(tailscale_start_error()==ESP_ERR_INVALID_ARG);
    connect_result=ESP_ERR_INVALID_STATE;cleanup_fails=true;
    assert(tailscale_request_connect()==ESP_OK);
    tailscale_start_attempts();
    assert(s_start_cleanup_failed && !s_connect_in_flight && !armed_us);
    assert(tailscale_request_connect()==ESP_ERR_INVALID_STATE && connect_calls==12);
    s_start_cleanup_failed=false;cleanup_fails=false; /* a clean boot */
    connect_result=ESP_ERR_NO_MEM;
    assert(tailscale_request_connect()==ESP_OK);tailscale_start_attempts();
    assert(connect_calls==17 && armed_us==2000000);
    connect_result=ESP_OK;fire_retry(2000000);tailscale_start_attempts();
    assert(connect_calls==18 && s_instance_ready && !s_connect_in_flight && !armed_us);
    before=allocations;
    for(int i=0;i<1000;i++)assert(tailscale_request_connect()==ESP_OK);
    assert(allocations==before&&!s_connect_in_flight);
    mutex_oom=true;mqtt_integration_init();assert(!s_manager_task&&!s_lock);
    mutex_oom=false;oom=true;mqtt_integration_init();assert(!s_manager_task&&s_lock&&!locks);
    oom=false;mqtt_integration_init();assert(s_manager_task&&!locks&&config_loads==2);
    before=allocations;mqtt_integration_init();assert(before==allocations);
    assert(!normal_calls&&caps_calls==allocations);
    puts("PASS: task admission retry/backoff, lost wakeup, uplink/disable handling, coalesced requests and matching cleanup (host fixtures)");
}
'''

with tempfile.TemporaryDirectory(prefix='task-memory-') as directory:
    path = Path(directory)
    (path / 'freertos').mkdir()
    for name in ('sdkconfig.h', 'freertos/FreeRTOS.h', 'freertos/task.h',
                 'freertos/idf_additions.h', 'esp_heap_caps.h'):
        (path / name).write_text('#pragma once\n', encoding='utf-8')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-Wno-unused-variable', '-Wno-misleading-indentation', '-I', str(path), '-I', str(ROOT / 'main')]
    if os.environ.get('TASKMEM_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    cases = [('project', HEADER + PROJECT_FIXTURE + manager_budget + manager_init + tail_start + PROJECT_TEST)]
    for external in (0, 1):
        for pinned in (0, 1):
            cases.append((f'mqtt-{external}-{pinned}', HEADER +
                f'\n#define CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY {external}\n#define CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM {external}\n#define MQTT_CORE_SELECTION_ENABLED {pinned}\n#define MQTT_TASK_AFFINITY {1 if pinned else -1}\n#define MQTT_TASK_STACK_ON_EXTERNAL_MEMORY 0\n' +
                '#include "mqtt_task_memory.h"\n' + MQTT_FIXTURE + sdk_start + sdk_cleanup + MQTT_TEST))
    for stem, program in cases:
        c = path / (stem + '.c'); c.write_text(program, encoding='utf-8')
        binary = path / (stem + ('.exe' if os.name == 'nt' else ''))
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
