"""Actual notification queue/worker and outage coalescer with deterministic SDK/transport fixtures.

No Telegram, email, board, real TLS or scheduler is exercised. Time, allocation
failure and producer interleavings are injected into the actual C functions.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
src=(ROOT/'main/notify_channels.c').read_text(encoding='utf-8')
types=src[src.index('typedef struct {uint8_t kind, level, channels, attempts;'):src.index('/* --- notify store (begin) --- */')]
code=src[src.index('/* --- delivery worker:'):src.index('void notify_channels_enabled')]
classification=src[src.index('static esp_err_t telegram_failure_status('):src.index('static esp_err_t telegram(')]
wanted=src[src.index('bool notify_wanted('):src.index('typedef struct {',src.index('bool notify_wanted('))]
history=(ROOT/'main/history.c').read_text(encoding='utf-8')
boot=history[history.index('    reset_history_entry_t entry = {0};'):history.index('\n}',history.index('    reset_history_entry_t entry = {0};'))]
fixture=r'''
#include <assert.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "notify_channels.h"
#include "remote_commands.h"
#include "history.h"
#include "notify_text.h"
/* esp_reset_reason_t with the SDK's values (notify_text.c words them) */
typedef enum {ESP_RST_POWERON=1,ESP_RST_SW=3,ESP_RST_PANIC=4,ESP_RST_INT_WDT=5,ESP_RST_TASK_WDT=6,ESP_RST_WDT=7,ESP_RST_BROWNOUT=9} esp_reset_reason_t;
typedef struct {const char *version;} esp_app_desc_t;
static esp_reset_reason_t raw_cause=ESP_RST_SW;
static esp_reset_reason_t esp_reset_reason(void){return raw_cause;}
static const esp_app_desc_t *esp_app_get_description(void){static const esp_app_desc_t app={"fixture"};return &app;}
/* OTA release check (ota_remote.h): the update notice reads only these fields */
typedef struct {bool update_available; char latest_version[32];} ota_remote_state_t;
static ota_remote_state_t fixture_update;
static int update_reads;
static void ota_remote_get_state(ota_remote_state_t *s){update_reads++;*s=fixture_update;}
#define QUEUE_MAX 8
#define MAX_ATTEMPTS 10
#define RETRY_S 30
#define CH_TG 1
#define CH_MAIL 2
#define EXT_RAM_BSS_ATTR
#define MALLOC_CAP_SPIRAM 1
#define pdPASS 1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define portMAX_DELAY 0
#define ESP_LOGW(...) ((void)0)
typedef int SemaphoreHandle_t;
typedef int StaticSemaphore_t;
static uint32_t clock_s;
static int task_ok=1, creates, tg_result, mail_result, sends, mail_sends;
static bool fail_queue, fail_history;
static bool tailnet_up;
static jmp_buf exit_worker;
static char last_text[600];
static void (*during_send)(void);
static void (*registered_poll)(void);
static int64_t esp_timer_get_time(void){return (int64_t)clock_s*1000000;}
static int tailscale_is_connected(void){return tailnet_up;}
static int xSemaphoreTake(int x,int y){(void)x;(void)y;return pdTRUE;}
static void xSemaphoreGive(int x){(void)x;}
static void task_reaper_self_delete(void){longjmp(exit_worker,1);}
static int xTaskCreateWithCaps(void (*fn)(void*),const char*n,int a,void*b,int c,void*d,int e){(void)fn;(void)n;(void)a;(void)b;(void)c;(void)d;(void)e;creates++;return task_ok;}
static const char *esp_err_to_name(int e){(void)e;return "fixture error";}
static void *heap_caps_calloc(size_t n,size_t size,int cap){(void)cap;return fail_queue ? NULL : calloc(n,size);}
static void *heap_caps_malloc(size_t size,int cap){(void)cap;return malloc(size);}
/* The Telegram command helpers in the extracted range use strlcpy; a local
 * copy avoids depending on the host C library (glibc < 2.38, MinGW). */
static size_t fixture_strlcpy(char *d,const char *s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
#define strlcpy fixture_strlcpy
esp_err_t history_set_sink_poller(history_sink_t sink,history_sink_poll_t poll){
    registered_poll=sink && !fail_history ? poll : NULL;
    return sink && fail_history ? ESP_ERR_NO_MEM : ESP_OK;
}
bool notify_wanted(uint8_t setting,unsigned kind,unsigned level){return kind==HIST_EV_SERVICE||setting==NOTIFY_ALL||level>=HIST_WARN;}
static void when_text(uint32_t t,char *s,size_t n){(void)t;if(n)s[0]=0;}
static int telegram(const notify_config_t*c,const char*t,unsigned shortcuts,char*w,size_t n){(void)c;(void)shortcuts;(void)w;(void)n;sends++;snprintf(last_text,sizeof last_text,"%s",t);if(during_send){void(*f)(void)=during_send;during_send=NULL;f();}return tg_result;}
static char last_subject[80];
static int email(const notify_config_t*c,const char*title,const char*t,char*w,size_t n){(void)c;(void)t;(void)w;(void)n;mail_sends++;snprintf(last_subject,sizeof last_subject,"%s",title);return mail_result;}
static bool wan_ready;
static bool uplink_internet_ready(void) { return wan_ready; }
'''+types+classification+code+r'''
static void reset(void){free(s_queue);s_queue=calloc(QUEUE_MAX,sizeof *s_queue);s_head=s_count=s_dropped=0;s_worker=false;
 memset(&s_cfg,0,sizeof s_cfg);s_cfg.tg_enabled=true;s_cfg.level=NOTIFY_PROBLEMS;s_mail_level=NOTIFY_PROBLEMS;s_startup_channels=0;s_link_grace_s=60;
 memset(s_links,0,sizeof s_links);memset(&s_tg,0,sizeof s_tg);memset(&s_mail,0,sizeof s_mail);
 s_tokens=6;s_refill=0;s_worker_retry=0;s_worker_backoff=30;clock_s=0;creates=sends=mail_sends=0;task_ok=1;tg_result=mail_result=0;wan_ready=0;tailnet_up=false;during_send=NULL;
 fail_queue=fail_history=false;s_setup_retry_at=0;atomic_store(&s_setup_pending,false);}
static void drain(void){if(!setjmp(exit_worker))worker(NULL);}
static void lost(void){offer(HIST_EV_UPLINK,HIST_WARN,0,"Internet uplink lost");}
static void up(void){wan_ready=1;offer(HIST_EV_UPLINK,HIST_INFO,0,"Internet uplink connected");}
static void fill_while_sending(void){for(int i=0;i<QUEUE_MAX;i++)enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_TG,0,"new result");}
static void recover_while_sending(void){clock_s=65;up();}
int main(void){
    reset();s_lock=1; strcpy(s_cfg.tg_token,"fixture");strcpy(s_cfg.tg_chat,"42");
    assert(!notify_telegram_destination("fixture","42"));
    notify_telegram_set_commands_enabled(true);
    uint32_t destination=notify_telegram_destination("fixture","42");
    assert(destination && !notify_telegram_destination("fixture","43"));
    assert(notify_telegram_queue_reply(destination,"Recovery completed"));
    notify_telegram_set_commands_enabled(false);
    assert(!notify_telegram_destination("fixture","42"));
    assert(!notify_telegram_command_active(destination));
    enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_TG,0,"Automatic alert");
    drain();assert(sends==1 && strstr(last_text,"Automatic alert"));
    notify_telegram_set_commands_enabled(true);
    assert(!notify_telegram_queue_reply(destination,"Obsolete destination"));
    assert(notify_telegram_queue_reply(notify_telegram_destination("fixture","42"),"Reachable"));
    drain();assert(sends==2 && strstr(last_text,"Reachable"));
 /* The queue retains the entire maximum producer message. */
 reset();char complete[HIST_TEXT_MAX+1];memset(complete,'X',HIST_TEXT_MAX);complete[HIST_TEXT_MAX]=0;
 offer(HIST_EV_SERVICE,HIST_INFO,0,complete);assert(s_count==1&&!strcmp(s_queue[s_head].text,complete));
 /* Telegram: the title on the first line, then the message (ntfy wording). */
 drain();assert(!strncmp(last_text,"ESP32 operational result\n",25)&&!strcmp(last_text+25,complete));
 /* Startup is immediate and independently selected even in Problems mode. */
 for(unsigned enabled=0;enabled<4;enabled++)for(unsigned startup=0;startup<16;startup++){
  for(unsigned power=0;power<2;power++){
  reset();s_cfg.tg_enabled=enabled&CH_TG;s_cfg.mail_enabled=enabled&CH_MAIL;s_startup_channels=startup;
  offer(HIST_EV_BOOT,HIST_INFO,0,power?"Power-on start fixture, reset POWERON":"Started fixture, reset SW");
  unsigned expected=enabled&(power?startup>>2:startup);assert(s_count==(expected?1:0));
  if(expected)assert(s_queue[s_head].channels==expected&&clock_s==0);
 }}
 reset();s_cfg.level=NOTIFY_ALL;offer(HIST_EV_BOOT,HIST_INFO,0,"Started fixture");assert(!s_count);
 reset();offer(HIST_EV_BOOT,HIST_ERROR,0,"Started fixture, reset WDT");assert(s_count==1);
 reset();offer(HIST_EV_CRASH,HIST_ERROR,0,"Crash fixture");assert(s_count==1);
 reset();s_startup_channels=CH_TG;lost();clock_s=1;offer(HIST_EV_BOOT,HIST_INFO,0,"Started fixture");
 assert(s_count==1&&s_queue[s_head].kind==HIST_EV_BOOT&&!s_links[LINK_UPLINK].announced);
 reset();s_link_grace_s=300;lost();clock_s=299;notify_poll();assert(!s_count);clock_s=300;notify_poll();assert(s_count==1);
 s_link_grace_s=600;clock_s=310;up();assert(s_count==1&&strstr(s_queue[s_head].text,"recovered after 310"));
 reset();s_link_grace_s=15;lost();clock_s=14;notify_poll();assert(!s_count);clock_s=15;notify_poll();assert(s_count==1);
 reset();lost();clock_s=59;notify_poll();assert(!s_count&&!creates);up();notify_poll();assert(!s_count&&!sends);
 reset();for(int day=0;day<10;day++){clock_s=(uint32_t)day*86400;wan_ready=0;lost();clock_s+=3;up();notify_poll();}assert(!s_count&&!creates);
 reset();lost();clock_s=60;notify_poll();assert(s_count==1&&s_links[LINK_UPLINK].announced);notify_poll();lost();notify_poll();assert(s_count==1);drain();assert(s_tg.sent==1);clock_s=300;notify_poll();assert(!s_count);
 reset();lost();clock_s=60;notify_poll();clock_s=70;up();assert(s_count==1&&strstr(s_queue[s_head].text,"recovered after 70 seconds"));drain();assert(strstr(last_text,"ESP32 Internet uplink restored\nInternet uplink restored after about 70 s.")&&sends==1);
 reset();lost();clock_s=60;notify_poll();tg_result=ESP_FAIL;drain();
 for(int i=1;i<MAX_ATTEMPTS;i++){clock_s+=RETRY_S;start_worker_locked(clock_s);drain();}
 assert(s_tg.failed==MAX_ATTEMPTS&&!s_count);clock_s=600;up();assert(s_count==1&&strstr(s_queue[s_head].text,"recovered after 600"));tg_result=ESP_OK;drain();assert(s_tg.sent==1);
 reset();lost();clock_s=3;wan_ready=1;notify_poll();assert(!s_links[LINK_UPLINK].down&&!s_count);up();assert(!s_count);
 reset();lost();clock_s=30;offer(HIST_EV_UPLINK,HIST_INFO,0,"Dynamic DNS updated");assert(s_links[LINK_UPLINK].down);clock_s=60;notify_poll();assert(s_count==1);
 reset();offer(HIST_EV_UPLINK,HIST_WARN,0,"Dynamic DNS not updated: fixture");assert(s_count==1);assert(!s_links[LINK_UPLINK].down);
 reset();offer(HIST_EV_TAILNET,HIST_WARN,0,"Tailnet connection lost");clock_s=59;notify_poll();assert(!s_count);tailnet_up=true;notify_poll();offer(HIST_EV_TAILNET,HIST_INFO,0,"Tailnet connected");assert(!s_count);
 reset();offer(HIST_EV_TAILNET,HIST_WARN,0,"Tailnet connection lost");clock_s=60;notify_poll();assert(s_count==1&&s_queue[s_head].link==LINK_TAILNET);
 reset();s_cfg.level=NOTIFY_ALL;lost();clock_s=1;up();assert(!s_count);offer(HIST_EV_UPLINK,HIST_INFO,0,"Dynamic DNS updated");assert(s_count==1);
 reset();offer(HIST_EV_SECURITY,HIST_ERROR,0,"Security fixture");assert(s_count==1);drain();assert(s_tg.sent==1);
 /* A short Wi-Fi station drop: history only with Problems; All events still sends it; a real outage still notifies. */
 reset();offer(HIST_EV_UPLINK,HIST_WARN,0,"Wi-Fi station disconnected (reason 200)");assert(!s_count&&!s_dropped&&!s_links[LINK_UPLINK].down);
 reset();s_cfg.mail_enabled=true;s_mail_level=NOTIFY_ALL;offer(HIST_EV_UPLINK,HIST_WARN,0,"Wi-Fi station disconnected (reason 200)");assert(s_count==1&&s_queue[s_head].channels==CH_MAIL);
 reset();s_cfg.level=NOTIFY_ALL;offer(HIST_EV_UPLINK,HIST_WARN,0,"Wi-Fi station disconnected");assert(s_count==1&&s_queue[s_head].channels==CH_TG);
 reset();offer(HIST_EV_UPLINK,HIST_WARN,0,"Wi-Fi station disconnected (reason 200)");lost();clock_s=59;notify_poll();assert(!s_count);clock_s=60;notify_poll();assert(s_count==1&&s_queue[s_head].link==LINK_UPLINK);
 reset();offer(HIST_EV_UPLINK,HIST_WARN,0,"Wi-Fi station disconnectedX");assert(s_count==1);   /* only the exact event text */
 reset();task_ok=0;enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_TG,0,"result");assert(s_count==1&&!s_worker&&creates==1);clock_s=29;notify_poll();assert(creates==1);clock_s=30;task_ok=1;notify_poll();assert(s_worker&&creates==2);drain();
 reset();enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_TG,0,"old head");during_send=fill_while_sending;drain();assert(s_tg.sent==QUEUE_MAX+1&&s_count==0&&s_dropped==1);
 reset();lost();clock_s=60;notify_poll();during_send=recover_while_sending;drain();assert(strstr(last_text,"restored after about 65 s.")&&s_count==0);
 reset();lost();clock_s=10;s_cfg.tg_enabled=false;apply_locked();assert(!s_queue&&!registered_poll&&!s_links[LINK_UPLINK].down);
 /* Permanent rejection ends its own retry. Other channels keep moving. */
 reset();s_cfg.mail_enabled=true;
 assert(telegram_failure_status(403)==ESP_ERR_NOT_SUPPORTED && telegram_failure_status(400)==ESP_ERR_NOT_SUPPORTED);
 assert(telegram_failure_status(429)==ESP_FAIL && telegram_failure_status(503)==ESP_FAIL);
 tg_result=telegram_failure_status(403);
 enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_TG,0,"denied");
 enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_MAIL,0,"email");
 drain();assert(s_tg.failed==1 && mail_sends==1 && !s_count && !clock_s);
 reset();s_cfg.mail_enabled=true;tg_result=ESP_FAIL;
 enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_TG,0,"temporary outage");
 drain();assert(s_count==1 && s_tg.failed==1 && !s_worker && s_queue[s_head].due==RETRY_S);
 enqueue_locked(HIST_EV_SERVICE,HIST_INFO,CH_MAIL,0,"later email");
 drain();assert(mail_sends==1 && s_count==1 && s_tg.failed==1 && !clock_s);
 clock_s=RETRY_S-1;start_worker_locked(clock_s);assert(!s_worker);
 clock_s=RETRY_S;tg_result=ESP_OK;start_worker_locked(clock_s);drain();assert(!s_count && s_tg.sent==1);
 /* Recovery works without a new configuration save or history event. */
 reset();free(s_queue);s_queue=NULL;fail_queue=true;
 apply_locked();assert(!s_queue && !registered_poll && s_setup_pending);
 clock_s=RETRY_S-1;fail_queue=false;notify_channels_retry_setup();assert(!s_queue);
 clock_s++;fail_history=true;notify_channels_retry_setup();assert(s_queue && !registered_poll && s_setup_pending);
 clock_s+=RETRY_S;fail_history=false;notify_channels_retry_setup();assert(s_queue && registered_poll && !s_setup_pending);
 /* Telegram/email word events as ntfy does (notify_text.c): power-on with
  * the channel's blackout choice, restart cause, Tailnet outage and recovery. */
 reset();raw_cause=ESP_RST_POWERON;s_startup_channels=(CH_TG|CH_MAIL)<<2;s_cfg.mail_enabled=true;
 enqueue_locked(HIST_EV_BOOT,HIST_INFO,CH_TG|CH_MAIL,0,"Power-on start fixture from ota_0, reset POWERON");drain();
 assert(strstr(last_text,"ESP32 power-on detected\nGateway powered on: firmware fixture; reset cause: power restored or first power-up (possible blackout).\nDetails: Power-on start fixture from ota_0, reset POWERON"));
 assert(!strcmp(last_subject,"ESP32 power-on detected"));
 reset();raw_cause=ESP_RST_POWERON;s_startup_channels=CH_TG;
 enqueue_locked(HIST_EV_BOOT,HIST_INFO,CH_TG,0,"Power-on start fixture from ota_0, reset POWERON");drain();
 assert(strstr(last_text,"(power restored or first power-up.")==NULL&&!strstr(last_text,"possible blackout"));
 reset();raw_cause=ESP_RST_BROWNOUT;
 enqueue_locked(HIST_EV_BOOT,HIST_ERROR,CH_TG,0,"Started fixture from ota_1, reset BROWNOUT");drain();
 assert(strstr(last_text,"ESP32 gateway restarted\nGateway restarted: firmware fixture; reset cause: supply voltage drop (brownout)."));
 reset();enqueue_locked(HIST_EV_TAILNET,HIST_WARN,CH_TG,0,"Tailnet connection unavailable for at least 120 seconds.");drain();
 assert(strstr(last_text,"ESP32 Tailscale problem\nInternet uplink is connected, but Tailscale has remained disconnected.\nOpen the local Diagnostics page to inspect logs.\nUnavailable for at least 120 s."));
 reset();enqueue_locked(HIST_EV_TAILNET,HIST_WARN,CH_TG,0,"Tailnet connection recovered after 300 seconds.");drain();
 assert(strstr(last_text,"ESP32 Tailscale restored\nTailscale control connection restored after about 300 s. This does not prove every peer or service is reachable."));
 /* Update available: once per version per boot, on All events or with
  * "other restarts" (ntfy's system events); nothing while not available. */
 reset();s_cfg.level=NOTIFY_PROBLEMS;s_startup_channels=0;fixture_update=(ota_remote_state_t){true,"9.9.9"};
 clock_s=1000;notify_poll();assert(s_count==0);
 reset();s_cfg.level=NOTIFY_PROBLEMS;s_startup_channels=CH_TG;fixture_update=(ota_remote_state_t){true,"9.9.9"};
 s_update_seen=0;s_update_checked=0;clock_s=2000;notify_poll();assert(s_count==1&&s_queue[s_head].kind==HIST_EV_UPDATE);
 drain();assert(strstr(last_text,"ESP32 firmware update available\nFirmware 9.9.9 is available. Nothing was installed"));
 clock_s=2100;notify_poll();assert(s_count==0);                         /* same version: once */
 fixture_update=(ota_remote_state_t){true,"9.9.10"};clock_s=2130;notify_poll();assert(s_count==0);   /* checked at most once a minute */
 clock_s=2161;notify_poll();assert(s_count==1&&strstr(s_queue[s_head].text,"9.9.10"));
 reset();s_cfg.level=NOTIFY_ALL;s_startup_channels=0;fixture_update=(ota_remote_state_t){false,""};
 s_update_seen=0;s_update_checked=0;clock_s=3000;notify_poll();assert(s_count==0);
 free(s_queue);puts("PASS actual notify delivery: independent boot masks, crash bypass, short/daily drops, long outage/recovery, expired retries, lost recovery event, DDNS separation, independent Tailnet grace, critical bypass, task OOM retry, queue overflow and in-flight recovery");
}
'''
producer = r'''
#include <stdarg.h>
typedef struct {char reason[16],who[32],crash[128];} reset_history_entry_t;
typedef struct {const char *label;} esp_partition_t;
typedef int esp_ota_img_states_t;
#define ESP_OTA_IMG_PENDING_VERIFY 1
static const char *recorded_cause="FLASH";
static int reset_history_load(reset_history_entry_t *entry,int n){assert(n==1);snprintf(entry->reason,sizeof entry->reason,"%s",recorded_cause);return 1;}
static const esp_partition_t *esp_ota_get_running_partition(void){static const esp_partition_t p={"ota_0"};return &p;}
static int esp_ota_get_state_partition(const esp_partition_t *p,esp_ota_img_states_t *s){(void)p;(void)s;return ESP_FAIL;}
void history_event(history_kind_t kind,history_level_t level,const char *format,...){
 char text[HIST_TEXT_MAX+1];va_list ap;va_start(ap,format);vsnprintf(text,sizeof text,format,ap);va_end(ap);offer(kind,level,0,text);
}
static void emit_actual_boot(void){
''' + boot + r'''
}
'''
boot_cases=r'''
 /* Actual history producer -> actual sink -> channel selection. History's
  * FLASH label must not hide a power-on or fault from the hardware reason. */
 static const unsigned raws[]={ESP_RST_POWERON,ESP_RST_SW,ESP_RST_PANIC,ESP_RST_INT_WDT,ESP_RST_TASK_WDT,ESP_RST_WDT,ESP_RST_BROWNOUT};
 for(unsigned k=0;k<sizeof raws/sizeof *raws;k++){unsigned raw=raws[k];
  reset();raw_cause=(esp_reset_reason_t)raw;recorded_cause="FLASH";s_startup_channels=CH_TG<<2;
  emit_actual_boot();
  if(raw==ESP_RST_SW)assert(!s_count);
  else {assert(s_count==1);assert(s_queue[s_head].level==(raw==ESP_RST_POWERON?HIST_INFO:HIST_ERROR));}
 }
 reset();raw_cause=ESP_RST_SW;recorded_cause="POWERON";s_startup_channels=CH_TG<<2;
 emit_actual_boot();assert(!s_count);
'''
fixture=fixture.replace('int main(void){',producer+'\nint main(void){'+boot_cases,1)
with tempfile.TemporaryDirectory(prefix='notify-delivery-') as directory:
    p=Path(directory)
    (p/'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n'
                            '#define ESP_ERR_NO_MEM 0x101\n#define ESP_ERR_INVALID_ARG 0x102\n#define ESP_ERR_INVALID_STATE 0x103\n'
                            '#define ESP_ERR_NOT_SUPPORTED 0x106\n')
    (p/'esp_http_server.h').write_text('#pragma once\ntypedef void *httpd_handle_t;\n')
    fixture=fixture.replace('bool notify_wanted(uint8_t setting,unsigned kind,unsigned level){return kind==HIST_EV_SERVICE||setting==NOTIFY_ALL||level>=HIST_WARN;}',wanted)
    (p/'case.c').write_text(fixture,encoding='utf-8')
    binary=p/('case.exe' if os.name=='nt' else 'case')
    flags=['-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(p),'-I',str(ROOT/'main')]
    if os.environ.get('NOTIFY_SANITIZE')=='1':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC','gcc'),*flags,str(p/'case.c'),str(ROOT/'main/notify_text.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=20)
