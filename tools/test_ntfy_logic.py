"""Exercise the actual ntfy command accounting and alert builder.

Synthetic HTTP/log/allocator tripwires; no board access or external traffic.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/ntfy_integration.c').read_text(encoding='utf-8')
# The shared command engine (remote_command_run) and ntfy's handler on top of it.
command = source[source.index('static esp_err_t named_wol_device('):source.index('static void collect_line')]
reset_builder = source[source.index('static const char *reset_reason_text('):source.index('/* The info reply, shared by ntfy and Telegram')]
assert '(unsigned long)esp_get_minimum_free_heap_size(), reset_reason_text(c->poweron_events),' in source
boot = 'static NTFY_NOINLINE esp_err_t send_system_event' + source.split('static NTFY_NOINLINE esp_err_t send_system_event',1)[1].split('static bool operational_destination_equal',1)[0]
alert = 'static NTFY_NOINLINE esp_err_t send_tailscale_alert' + source.split('static NTFY_NOINLINE esp_err_t send_tailscale_alert', 1)[1].split('static NTFY_NOINLINE uint32_t available_update_id', 1)[0]
fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdarg.h>
#define NTFY_NOINLINE
#include "notify_text.h"
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 2
#define ESP_ERR_INVALID_ARG 3
#define ESP_ERR_NOT_SUPPORTED 4
#define ESP_ERR_TIMEOUT 5
#define ESP_ERR_INVALID_STATE 6
#define ESP_ERR_NOT_ALLOWED 7
#define ESP_ERR_INVALID_SIZE 8
#define HTTP_EVENT_ON_DATA 1
#define portMAX_DELAY 0
typedef int esp_err_t;
typedef struct { bool info_enabled, info_include_details, poweron_events, allow_direct_mac; } ntfy_integration_config_t;
typedef struct { int event_id, data_len; void *data, *user_data; } esp_http_client_event_t;
static int s_lock;
static struct { unsigned alerts_sent, commands_received, command_errors; } s_status;
static void xSemaphoreTake(int a,int b) { (void)a; (void)b; }
static void xSemaphoreGive(int a) { (void)a; }
static int publish_result, info_result, allocations, fail_at, live, log_reads;
static char published[2300];
void *checked_malloc(size_t n) {
    if (++allocations == fail_at) return NULL;
    void *p = malloc(n); if(p) live++; return p;
}
void checked_free(void *p) { if(p) live--; free(p); }
#define malloc checked_malloc
#define free checked_free
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
static void *heap_caps_malloc(size_t n,int caps){(void)caps;return checked_malloc(n);}
static esp_err_t publish_message(const ntfy_integration_config_t *c,const char *title,const char *tags,const char *msg) {
    (void)c; (void)title; (void)tags;
    assert(strlen(msg)<sizeof published); strcpy(published,msg); return publish_result;
}
size_t log_capture_read(char *out,size_t capacity) {
    log_reads++;
    const char *marker="PRIVATE_LOCAL_LOG_FIXTURE";
    memset(out,'x',capacity-1);memcpy(out+capacity-1-strlen(marker),marker,strlen(marker));
    out[capacity-1]=0;return capacity-1;
}
static esp_err_t send_info(const ntfy_integration_config_t *c, uint32_t destination) { (void)c;assert(destination==17);return info_result; }
static size_t strlcpy_(char *d,const char *s,size_t n){size_t l=strlen(s);if(n){size_t c=l<n-1?l:n-1;memcpy(d,s,c);d[c]=0;}return l;}
#define strlcpy strlcpy_
#include "remote_commands.h"
static bool commands_enabled=true;
bool remote_command_active(ops_recovery_origin_t origin,uint32_t destination){
    return commands_enabled && origin>=OPS_RECOVERY_NTFY && destination==17;
}
typedef struct {char name[32],broadcast[16];uint8_t mac[6];uint16_t port;} wol_device_t;
static bool wol_parse_mac(const char *s,uint8_t out[6]){(void)s;(void)out;return false;}
#define ESP_ERR_NOT_FOUND -8
static int wol_count_fixture=1, wake_requests;
static int wol_count(void){return wol_count_fixture;}
static bool wol_get(int i,wol_device_t *d){assert(i>=0 && i<wol_count_fixture);*d=(wol_device_t){.name="Home NAS",.mac={2,(uint8_t)i}};return true;}
static int wol_send_saved_mac_text(const char *s){(void)s;return ESP_ERR_NOT_FOUND;}
static int wol_send_mac(const uint8_t mac[6],const char *ip,uint16_t port){(void)ip;(void)port;assert(mac[0]==2);wake_requests++;return ESP_OK;}
static int recovery_result;
static unsigned requests;
static int homelab_ops_remote_request(const uint8_t mac[6],bool wake,ops_recovery_origin_t origin,uint32_t destination){
    assert(mac[0]==2 && wake && (origin==OPS_RECOVERY_NTFY || origin==OPS_RECOVERY_TELEGRAM) && destination==17);
    requests++;
    return recovery_result;
}
static void homelab_ops_device_summary(char *out,size_t cap){snprintf(out,cap,"Home NAS: reachable");}
static bool recovery_permission;
static bool homelab_ops_recovery_allowed(ops_recovery_origin_t origin){return origin>=OPS_RECOVERY_NTFY&&recovery_permission;}
static void saved_tcp_summary(char *out,size_t cap){snprintf(out,cap,"printer: reachable");}
static int saved_tcp_remote_request(const char *name,ops_recovery_origin_t origin,uint32_t destination){
    assert(origin>=OPS_RECOVERY_NTFY && destination==17);return !strcmp(name,"printer")?ESP_OK:ESP_ERR_NOT_FOUND;}
'''
boot_fixture = r'''
#include "ntfy_events.h"
/* ESP-IDF 5.5.3 esp_system.h order, including every reset cause. */
typedef enum {ESP_RST_UNKNOWN,ESP_RST_POWERON,ESP_RST_EXT,ESP_RST_SW,ESP_RST_PANIC,ESP_RST_INT_WDT,ESP_RST_TASK_WDT,ESP_RST_WDT,ESP_RST_DEEPSLEEP,ESP_RST_BROWNOUT,ESP_RST_SDIO,ESP_RST_USB,ESP_RST_JTAG,ESP_RST_EFUSE,ESP_RST_PWR_GLITCH,ESP_RST_CPU_LOCKUP} esp_reset_reason_t;
typedef struct {const char *version;} esp_app_desc_t;
typedef struct {char latest_version[32];} ota_remote_state_t;
static esp_reset_reason_t reset_reason;
static esp_reset_reason_t esp_reset_reason(void){return reset_reason;}
static uint32_t power_history_previous_online(void){return 1704067200;}
static const esp_app_desc_t *esp_app_get_description(void){static const esp_app_desc_t app={"fixture"};return &app;}
static void ota_remote_get_state(ota_remote_state_t *s){strcpy(s->latest_version,"fixture-next");}
'''
tests = r'''
int main(void) {
    char reply[REMOTE_REPLY_MAX]; const char *title;
    for (ops_recovery_origin_t origin=OPS_RECOVERY_NTFY;origin<=OPS_RECOVERY_TELEGRAM;origin++) {
        recovery_permission=false;
#define RUN(s, enabled) remote_command_run(s,enabled,false,origin,17,reply,sizeof reply,&title)
        commands_enabled=false;
        const unsigned requests_before_disable=requests;
        const int wakes_before_disable=wake_requests;
        recovery_permission=true;
        const char *blocked[]={"/help","/start","devices","status","wol Home NAS","recover Home NAS","check Home NAS","checks","probe printer"};
        for(size_t i=0;i<sizeof blocked/sizeof *blocked;i++)
            assert(RUN(blocked[i],true)==REMOTE_CMD_NONE && !reply[0] && !title);
        assert(requests==requests_before_disable && wake_requests==wakes_before_disable);
        commands_enabled=true;
        recovery_permission=false;
        assert(RUN("/help",false)==REMOTE_CMD_HELP && strstr(reply,"devices") && !strstr(reply,"info (or status)"));
        assert(RUN("status",false)==REMOTE_CMD_ERROR && strstr(reply,"disabled"));
        assert(RUN("status",true)==REMOTE_CMD_INFO);
        assert(RUN("/devices",true)==REMOTE_CMD_OK && strstr(reply,"Home NAS"));
        assert(RUN("recover  Home NAS",true)==REMOTE_CMD_ERROR && strstr(reply,"basic commands"));
        assert(RUN("probe printer",true)==REMOTE_CMD_ERROR && strstr(reply,"basic commands"));
        assert(requests==requests_before_disable);
        assert(RUN("wol Home NAS",true)==REMOTE_CMD_OK && wake_requests==wakes_before_disable+1 && !strstr(reply,"Use recover"));
        recovery_permission=true;
        assert(RUN("/start",true)==REMOTE_CMD_HELP && strstr(reply,"probe PRINTER"));
        const unsigned before=requests;
        assert(RUN(" /ReCoVeR\tHome NAS \n",true)==REMOTE_CMD_OK && requests==before+1 && strstr(reply,"will follow here"));
        assert(RUN("recover Unknown",true)==REMOTE_CMD_ERROR && requests==before+1 && strstr(reply,"not found"));
        wol_count_fixture=2;
        assert(RUN("recover Home NAS",true)==REMOTE_CMD_ERROR && requests==before+1 && strstr(reply,"More than one"));
        wake_requests=0;
        assert(RUN("wol Home NAS",true)==REMOTE_CMD_ERROR && !wake_requests);
        wol_count_fixture=1;
        assert(RUN("wol Home NAS",true)==REMOTE_CMD_OK && wake_requests==1 && strstr(reply,"Use recover"));
        assert(RUN("recover",true)==REMOTE_CMD_ERROR && strstr(reply,"Usage"));
        recovery_result=ESP_ERR_TIMEOUT;
        assert(RUN("recover Home NAS",true)==REMOTE_CMD_ERROR && strstr(reply,"recently") && !strstr(reply,"basic commands"));
        recovery_result=ESP_ERR_NOT_ALLOWED;
        assert(RUN("recover Home NAS",true)==REMOTE_CMD_ERROR && strstr(reply,"low on resources"));
        recovery_result=ESP_OK;
        assert(RUN("probe printer",true)==REMOTE_CMD_OK);
        assert(RUN("probe 192.0.2.15:443",true)==REMOTE_CMD_ERROR);
        assert(RUN("checks",true)==REMOTE_CMD_OK&&strstr(reply,"printer: reachable"));
    }
    ntfy_integration_config_t c={.info_enabled=true};
    commands_enabled=false; handle_command(&c,17,"help");
    assert(!s_status.commands_received && !s_status.command_errors && !published[0]);
    commands_enabled=true;
    info_result=ESP_FAIL; handle_command(&c,17," info\n");
    assert(s_status.command_errors==1 && s_status.commands_received==0);
    info_result=ESP_OK; handle_command(&c,17,"INFO");
    assert(s_status.command_errors==1 && s_status.commands_received==1);
    handle_command(&c,17,"unknown"); assert(s_status.command_errors==1);
    publish_result=ESP_FAIL; handle_command(&c,17,"help");
    assert(s_status.command_errors==2 && strstr(published,"COMMANDS"));
    assert(live==0 && allocations>0);
    const unsigned before_oom=requests;
    fail_at=allocations+1;
    handle_command(&c,17,"recover Home NAS");
    assert(s_status.command_errors==3 && requests==before_oom && live==0);
    allocations=fail_at=0;
    for(int details=0;details<=1;details++) {
        c.info_include_details=details!=0;
        publish_result=ESP_OK;assert(send_tailscale_alert(&c)==ESP_OK);
        assert(s_status.alerts_sent==(unsigned)details+1&&live==0&&strlen(published)<2300);
        assert(!strstr(published,"PRIVATE_LOCAL_LOG_FIXTURE"));
        assert(!strstr(published,"Recent local log tail:"));
        assert(strstr(published,"Tailscale is disconnected"));
        assert(log_reads==0&&allocations==0);
    }
    publish_result=ESP_FAIL; assert(send_tailscale_alert(&c)==ESP_FAIL);
    assert(s_status.alerts_sent==2 && live==0);
    publish_result=ESP_ERR_NO_MEM;assert(send_tailscale_alert(&c)==ESP_ERR_NO_MEM);
    assert(s_status.alerts_sent==2&&live==0&&log_reads==0&&allocations==0);
    publish_result=ESP_OK;fail_at=1;assert(send_tailscale_alert(&c)==ESP_OK);
    assert(s_status.alerts_sent==3&&live==0&&log_reads==0&&allocations==0);
    fail_at=0;publish_result=ESP_OK;
    const char *descriptions[]={"unknown reset cause","power restored or first power-up","external reset pin","software-requested restart","firmware crash (panic/exception)","interrupt watchdog timeout","task watchdog timeout","watchdog timeout","wake from deep sleep","supply voltage drop (brownout)","SDIO reset","USB peripheral reset","JTAG/debugger reset","eFuse error","power glitch detected","CPU lockup (double exception)"};
    for(unsigned enabled=0;enabled<2;enabled++){
      c.poweron_events=enabled!=0;
      for(unsigned reason=0;reason<sizeof descriptions/sizeof *descriptions;reason++){
        reset_reason=(esp_reset_reason_t)reason;
        assert(send_system_event(&c,NTFY_EVENT_BOOT,0)==ESP_OK);
        bool power_notice = enabled && reason == ESP_RST_POWERON;
        if (power_notice)
            assert(!strcmp(published,"Power restored.\nLast recorded activity: 2024-01-01 00:00 UTC."));
        else
            assert(strstr(published,descriptions[reason]));
        assert((strstr(published,"2024-01-01 00:00 UTC")!=NULL)==power_notice);
        assert(!strstr(published,"reset reason ")&&!strstr(published,"outage lasted")&&!strstr(published,"PRIVATE_LOCAL_LOG_FIXTURE"));
        assert(strlen(published)<NOTIFY_MESSAGE_MAX&&live==0&&log_reads==0&&allocations==0);
        const char *info_line=reset_reason_text(c.poweron_events);
        assert(strstr(info_line,descriptions[reason]));
        assert((strstr(info_line,"(possible blackout)")!=NULL)==(enabled&&reason==ESP_RST_POWERON));
        if (!power_notice) assert(strstr(published,info_line));

      }
    }
    reset_reason=(esp_reset_reason_t)255;
    assert(send_system_event(&c,NTFY_EVENT_BOOT,0)==ESP_OK&&strstr(published,"unknown reset cause")&&!strstr(published,"possible blackout"));
    puts("PASS: ntfy info/transport accounting and alert privacy; boot/info:16 explicit reset causes with power-on option ON/OFF, unknown-cause fallback, no allocations or blackout labels on faults");
}
'''
with tempfile.TemporaryDirectory(prefix='ntfy-logic-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(fixture + boot_fixture + reset_builder + command + alert + boot + tests)
    # notify_text.c (the wording shared with Telegram and email) includes history.h
    (path / 'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n')
    (path / 'esp_http_server.h').write_text('#pragma once\ntypedef void *httpd_handle_t;\n')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(path), '-I', str(ROOT/'main')]
    if os.environ.get('NTFY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'test.c'), str(ROOT / 'main/notify_text.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

# Actual opt-in system-event scheduler (main/ntfy_events.h).
EVENTS = r'''
#include <assert.h>
#include <stdio.h>
#include "ntfy_events.h"
int main(void){
    bool other,power;
    for(unsigned v=0;v<256;v++){
      ntfy_events_decode((uint8_t)v,&other,&power);
      assert(other==(v==1||v==3)&&power==(v==1||v==2));
      if(v<4)assert(ntfy_events_options(other,power)==v);
    }
    for(int boot=0;boot<2;boot++)for(int rest=0;rest<2;rest++){
      ntfy_events_t selected;ntfy_events_init(&selected);
      ntfy_events_select(&selected,true,boot,rest);assert(ntfy_events_due(&selected)==(boot?NTFY_EVENT_BOOT:0));
      ntfy_events_tick(&selected,true,rest,rest?123:0);
      ntfy_events_select(&selected,false,boot,rest);assert(!ntfy_events_due(&selected));
    }
    ntfy_events_t s;ntfy_events_init(&s);
    assert(ntfy_events_due(&s)==NTFY_EVENT_BOOT);
    ntfy_events_tick(&s,true,false,0);assert(ntfy_events_due(&s)==NTFY_EVENT_BOOT);
    ntfy_events_result(&s,NTFY_EVENT_BOOT,false);assert(!ntfy_events_due(&s)&&s.retry_s==60); /* bounded retry */
    for(int i=0;i<59;i++)ntfy_events_tick(&s,true,false,0);
    assert(!ntfy_events_due(&s));ntfy_events_tick(&s,true,false,0);assert(ntfy_events_due(&s)==NTFY_EVENT_BOOT);
    ntfy_events_result(&s,NTFY_EVENT_BOOT,true);assert(!ntfy_events_due(&s));
    /* Restored and update both pending: one message per call, boot-restored-update order. */
    ntfy_events_tick(&s,true,true,0xabc);assert(ntfy_events_due(&s)==NTFY_EVENT_RESTORED);
    ntfy_events_result(&s,NTFY_EVENT_RESTORED,true);assert(ntfy_events_due(&s)==NTFY_EVENT_UPDATE);
    ntfy_events_result(&s,NTFY_EVENT_UPDATE,true);assert(!ntfy_events_due(&s));
    ntfy_events_tick(&s,true,false,0xabc);assert(!ntfy_events_due(&s)); /* same version announced once */
    ntfy_events_tick(&s,true,false,0);ntfy_events_tick(&s,true,false,0xabc);assert(!ntfy_events_due(&s)); /* vanished+returned: still once */
    ntfy_events_tick(&s,true,false,0xdef);assert(ntfy_events_due(&s)==NTFY_EVENT_UPDATE);
    /* Disabled: nothing queued, versions seen while off are not replayed later. */
    ntfy_events_init(&s);ntfy_events_tick(&s,false,true,0x111);assert(!s.pending&&!ntfy_events_due(&s));
    ntfy_events_tick(&s,true,false,0x111);assert(!ntfy_events_due(&s));
    ntfy_events_result(&s,NTFY_EVENT_UPDATE,false);ntfy_events_tick(&s,false,false,0);assert(!s.retry_s); /* disable clears retry */
    puts("PASS: actual ntfy system events: boot once, bounded 60 s retry, ordering, update announced once per version, no backlog while disabled");
}
'''
with tempfile.TemporaryDirectory(prefix='ntfy-events-') as directory:
    path = Path(directory); (path / 'events.c').write_text(EVENTS)
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(ROOT / 'main')]
    if os.environ.get('NTFY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    binary = path / ('events.exe' if os.name == 'nt' else 'events')
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'events.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
