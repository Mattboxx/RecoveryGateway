"""Actual retry/clock/callback/manager logic with mocked SDK, broker and time."""
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'main/mqtt_integration.c').read_text()
def section(start,end):return start+source.split(start,1)[1].split(end,1)[0]
clock=section('static void broker_clock_set','extern bool wifi_ap_policy_auto_off')
callback=section('static void mqtt_event_handler','static bool start_client')
status=section('static void status_update','static void manager_task')
manager=section('static void manager_task','void mqtt_integration_init').replace('while (true)', 'while (fixture_step())')
PROGRAM=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "service_retry.h"
#include "discovery_budget.h"
#include "mqtt_power_event.h"
typedef int esp_err_t;
typedef void *esp_event_base_t;
typedef struct {void *client; int msg_id,retain,dup,current_data_offset,data_len,total_data_len,topic_len;char *topic,*data;} event_t;
typedef event_t *esp_mqtt_event_handle_t;
typedef struct {bool enabled,broker_watchdog_enabled,poweron_events,home_assistant_discovery;char uri[80],base_topic[80],broker_watchdog_wol_mac[18],discovery_prefix[48];int interval_seconds,broker_watchdog_timeout_seconds;} mqtt_integration_config_t;
#define ESP_RST_POWERON 1
static int raw_reset=ESP_RST_POWERON;static bool power_selected=true,ha_discovery;
static int esp_reset_reason(void){return raw_reset;}
static uint32_t power_history_previous_online(void){return 0;}
static uint32_t esp_random(void){return 0x13579abc;}
#define BROKER_CONNECTED 1u
#define BROKER_DISCONNECTED 2u
#define MQTT_EVENT_CONNECTED 1
#define MQTT_EVENT_DISCONNECTED 2
#define MQTT_EVENT_DATA 3
#define MQTT_EVENT_ERROR 4
#define MQTT_EVENT_SUBSCRIBED 5
#define MQTT_EVENT_PUBLISHED 6
#define ESP_OK 0
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
static int s_broker_clock_mux,client_token;
static void *s_client;
static bool s_connected,s_publish_requested,s_discovery_requested,s_watchdog_triggered,s_restart_requested,s_wifi_reconnect_requested;
static uint32_t s_connection_events,s_watchdog_wake_count;
static uint32_t s_subscription_ack;
static int s_last_puback;
static bool s_commands_ready;
static int64_t s_last_broker_ok_us,now_us;
static char s_availability_topic[128];
static discovery_budget_t s_discovery;
typedef struct {bool configured,connected,connecting,discovery_pending,commands_ready;uint8_t retry_level;uint32_t retry_in_seconds;uint16_t discovery_entities;} mqtt_integration_status_t;
static mqtt_integration_status_t s_status;static int s_status_mux;
static mqtt_integration_status_t seen[130];
static unsigned tick,starts,reconnects,subscribes,states,discovery,wakes,stops;
static unsigned power_events, offline_messages, power_tick, command_deliveries;
static bool sub_mode, discovery_stalled;
static int64_t esp_timer_get_time(void){return now_us;}
static int esp_mqtt_client_enqueue(void *p,const char *t,const char *m,int len,int qos,int retain,bool store){
    assert(p==s_client && !strcmp(t,"old/availability") && !strcmp(m,"offline") && len==7 && qos==1 && retain && store);
    offline_messages++;s_last_puback=42;return 42;
}
static int esp_mqtt_client_stop(void *p){assert(p);stops++;return 0;}
static int esp_mqtt_client_destroy(void *p){assert(p);return 0;}
static void handle_command(const char *a,const char *b){
    assert(!strcmp(a,"fixture/command/publish") && !strcmp(b,"PRESS"));command_deliveries++;
}
static void mqtt_integration_get_config(mqtt_integration_config_t *c){*c=(mqtt_integration_config_t){.enabled=true,.broker_watchdog_enabled=true,.poweron_events=power_selected,.home_assistant_discovery=ha_discovery,.discovery_prefix="homeassistant",.uri="mqtt://fixture",.base_topic="fixture",.broker_watchdog_wol_mac="00:00:00:00:00:01",.interval_seconds=30,.broker_watchdog_timeout_seconds=30};}
static int publish(const char *a,const char *b,int c){if(strstr(a,"/event/power")){assert(!c&&strstr(b,"possible_blackout")&&strstr(b,"13579abc"));power_events++;power_tick=tick;}return 0;}
static void publish_state(const mqtt_power_event_t *power,bool selected){assert(power->boot_id==0x13579abc&&selected==power_selected);states++;}
static void publish_discovery(const mqtt_integration_config_t *cfg){assert(cfg);discovery++;if(ha_discovery&&discovery_visit(&s_discovery))discovery_result(&s_discovery,!discovery_stalled);}
static int esp_mqtt_client_subscribe(void *p,const char *t,int qos){
    assert(p&&t&&qos==1);subscribes++;return sub_mode && subscribes==1 ? -1 : (int)(100+subscribes);
}
static bool homelab_ops_admit(void){return true;}
static bool uplink_ready=true,offline_mode;static unsigned uplink_checks,first_start_tick;
static bool mqtt_uplink_ready(void){uplink_checks++;return uplink_ready;}
static bool start_client(void){if(!first_start_tick)first_start_tick=tick;starts++;if(starts<3)return false;s_client=&client_token;return true;}
static int esp_mqtt_client_reconnect(void *p){assert(p);reconnects++;return -1;}
static uint32_t ulTaskNotifyTake(int a,int b){(void)a;(void)b;return 0;}
static void vTaskDelay(int n){(void)n;assert(false);}
static void esp_restart(void){assert(false);}
static int esp_wifi_disconnect(void){assert(false);return 0;}
static int esp_wifi_connect(void){assert(false);return 0;}
static int wol_send_saved_mac_count(const char *m,uint8_t *sent){
    assert(m[0]);wakes++;
    *sent=uplink_ready ? (offline_mode ? 1 : 3) : 0;
    return *sent==3 ? ESP_OK : -1;
}
static bool fixture_step(void);
'''
TAIL=r'''
static bool fixture_step(void){
    if(tick)seen[tick]=s_status;
    if(++tick>120)return false;
    now_us=(int64_t)tick*1000000;
    if(offline_mode){uplink_ready=tick>=60;return true;}   /* no address until 60 s, no broker events */
    event_t ev={.client=s_client};
    if(sub_mode || discovery_stalled){
        if(tick==17)mqtt_event_handler(NULL,NULL,MQTT_EVENT_CONNECTED,&ev);
        if(sub_mode && (tick==23 || tick==34 || tick==35)){
            char answer=tick==23?(char)0x80:1;
            ev.msg_id=tick==35?103:102;ev.data=&answer;ev.data_len=1;
            mqtt_event_handler(NULL,NULL,MQTT_EVENT_SUBSCRIBED,&ev);
        }
        if(sub_mode && (tick==34 || tick==36)){
            ev=(event_t){.client=s_client,.topic="fixture/command/publish",.topic_len=23,
                         .data="PRESS",.data_len=5,.total_data_len=5};
            mqtt_event_handler(NULL,NULL,MQTT_EVENT_DATA,&ev);
        }
        return true;
    }
    if(tick==17||tick==80){assert(s_client);mqtt_event_handler(NULL,NULL,MQTT_EVENT_CONNECTED,&ev);}
    if(tick==20||tick==21||tick==25||tick==85||tick==86){assert(s_client);mqtt_event_handler(NULL,NULL,MQTT_EVENT_DISCONNECTED,&ev);}
    return true;
}
int main(int argc,char **argv){
    if(argc>1){raw_reset=!strcmp(argv[1],"software")?2:ESP_RST_POWERON;power_selected=strcmp(argv[1],"disabled")!=0;ha_discovery=!strcmp(argv[1],"ha");}
    sub_mode=argc>1&&!strcmp(argv[1],"sub");
    discovery_stalled=argc>1&&!strcmp(argv[1],"ha-stalled");
    if(sub_mode || discovery_stalled){
        ha_discovery=discovery_stalled;now_us=1;manager_task(NULL);
        if(sub_mode)assert(subscribes==3 && !seen[34].commands_ready && seen[35].commands_ready && command_deliveries==1);
        else assert(discovery>1 && seen[107].discovery_pending && power_events==1 && power_tick==107);
        return 0;
    }
    if(argc>1&&!strcmp(argv[1],"offline")){
        /* No uplink address for 60 s: no broker attempt, no failure counted,
         * no backoff shown; the first attempt starts in the second the
         * address appears. */
        offline_mode=true;uplink_ready=false;now_us=1;manager_task(NULL);
        assert(uplink_checks>=59&&first_start_tick==60&&starts>=1);
        for(unsigned i=1;i<60;i++){mqtt_integration_status_t s=seen[i];assert(s.configured&&!s.connecting&&!s.connected&&!s.retry_level&&!s.retry_in_seconds);}
        assert(seen[60].connecting||seen[60].retry_in_seconds);
        assert(wakes==2 && s_watchdog_wake_count==1 && s_watchdog_triggered);
        puts("PASS: no MQTT broker attempt and no backoff before the uplink has an address; first attempt when it appears");
        return 0;
    }
    service_retry_t r={0};assert(service_retry_due(&r,0));
    service_retry_begin(&r,0);assert(!service_retry_due(&r,30000));assert(!service_retry_timed_out(&r,29999));assert(service_retry_timed_out(&r,30000));
    uint64_t now=0;for(unsigned i=0;i<100;i++){service_retry_failed(&r,now);uint64_t delay=r.next_ms-now;assert(delay>=5000&&delay<=300000);assert(!service_retry_due(&r,r.next_ms-1));assert(service_retry_due(&r,r.next_ms));now=r.next_ms;}
    service_retry_reset(&r);assert(!r.failures&&service_retry_due(&r,0));
    now_us=1000000;broker_clock_set(false,true);now_us=5000000;broker_clock_set(false,false);assert(broker_silence_us()==4000000);
    s_client=&client_token;event_t stale={.client=&tick};mqtt_event_handler(NULL,NULL,MQTT_EVENT_CONNECTED,&stale);assert(!s_connected);
    event_t live={.client=s_client};mqtt_event_handler(NULL,NULL,MQTT_EVENT_CONNECTED,&live);assert(s_connected&&!subscribes&&!discovery&&!states);
    strcpy(s_availability_topic,"old/availability");
    stop_client();assert(!s_connected&&!s_connection_events&&offline_messages==1);
    now_us=1;manager_task(NULL);
    assert(starts==3&&reconnects>0&&reconnects<12);
    assert(subscribes==2&&discovery==2&&states>=2);
    assert(power_events==(unsigned)(raw_reset==ESP_RST_POWERON&&power_selected));
    assert(wakes==2&&s_watchdog_wake_count==2&&s_watchdog_triggered);
    /* Last failed reconnect did not reset the genuine second outage at 85 s. */
    assert(s_last_broker_ok_us==85000000);
    /* Published status: backoff countdown before the first success, an
     * in-flight attempt, connected with Discovery, then backoff again. */
    unsigned backoff=0,connecting=0,connected=0;
    for(unsigned i=1;i<=120;i++){
        mqtt_integration_status_t s=seen[i];assert(s.configured);
        assert(!(s.connected&&(s.connecting||s.retry_in_seconds)));
        assert(s.retry_in_seconds<=300&&s.retry_level<=7);
        if(s.retry_in_seconds){backoff++;assert(!s.connecting&&s.retry_level);}
        if(s.connecting)connecting++;
        if(s.connected){connected++;assert(!s.retry_level);}
        if(!s.connected)assert(!s.discovery_pending&&!s.discovery_entities);
    }
    assert(backoff&&connecting&&connected);
    assert(seen[3].retry_in_seconds&&!seen[3].connected);
    assert(!seen[16].connected&&seen[17].connected&&seen[19].connected);
    assert(!seen[17].discovery_pending); /* fixture Discovery enumerates no entities */
    assert(!seen[20].connected&&seen[80].connected&&!seen[85].connected);
    mqtt_integration_config_t off={0};service_retry_t idle={.failures=3,.next_ms=999999};s_connected=false;
    status_update(&off,&idle,true,0);assert(!s_status.configured&&!s_status.retry_in_seconds&&!s_status.connecting);
    puts("PASS: actual worker/callback/clock and bounded retry; startup recovery, delayed retry, two outage bursts, stale events, deferred Discovery, published status snapshot (mock SDK/broker)");
}
'''
assert '.network.disable_auto_reconnect = true' in source
assert 'connecting to %s' not in source
with tempfile.TemporaryDirectory(prefix='service-retry-') as folder:
    p=Path(folder);(p/'test.c').write_text(PROGRAM+clock+callback+status+manager+TAIL)
    binary=p/('test.exe' if os.name=='nt' else 'test');flags=['-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT/'main')]
    if os.environ.get('RETRY_SANITIZE')=='1':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC','gcc'),*flags,str(p/'test.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
    for mode in ('software','disabled','ha','offline','sub','ha-stalled'):
        subprocess.run([str(binary),mode],check=True,timeout=30)

# Actual mqtt_uplink_ready(): LAN-side uplink (broker on the local network)
# or the Internet uplink (also mobile) with an address.
helper = source[source.index('static bool mqtt_uplink_ready(void)'):]
helper = helper[:helper.index('\n}\n') + 3]
UPLINK = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
typedef struct {int ip;} esp_netif_ip_info_t;
typedef struct {int has;} esp_netif_t;
static esp_netif_t lan, wan;
static esp_netif_t *eth_uplink_service_netif(void){return &lan;}
static esp_netif_t *uplink_internet_netif(void){return &wan;}
static bool uplink_address(esp_netif_t *n,esp_netif_ip_info_t *ip){assert(ip);return n&&n->has;}
@@HELPER@@
int main(void){
    assert(!mqtt_uplink_ready());
    lan.has=1;assert(mqtt_uplink_ready());            /* broker on the LAN, mobile uplink still dialing */
    lan.has=0;wan.has=1;assert(mqtt_uplink_ready());  /* only the mobile uplink */
    lan.has=1;assert(mqtt_uplink_ready());
    puts("PASS: actual mqtt_uplink_ready (LAN or Internet uplink address)");
}
'''
with tempfile.TemporaryDirectory(prefix='mqtt-uplink-') as folder:
    p=Path(folder);(p/'u.c').write_text(UPLINK.replace('@@HELPER@@',helper))
    binary=p/('u.exe' if os.name=='nt' else 'u')
    subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror',str(p/'u.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
    bad=UPLINK.replace('@@HELPER@@',helper.replace('uplink_address(eth_uplink_service_netif(), &ip) || ',''))
    (p/'m.c').write_text(bad);mb=p/('m.exe' if os.name=='nt' else 'm')
    subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-w',str(p/'m.c'),'-o',str(mb)],check=True)
    assert subprocess.run([str(mb)],capture_output=True,timeout=30).returncode!=0,'Internet-only gate must fail (LAN broker)'

# Actual optional-module supervisor backoff (main/module_supervisor.h).
SUPERVISOR = r'''
#include <assert.h>
#include <stdio.h>
#include "module_supervisor.h"
int main(void){
    module_supervisor_t s={0};
    assert(!module_supervisor_due(&s,0,true)); /* everything running: never acts */
    assert(module_supervisor_due(&s,0,false));
    uint64_t now=1000;unsigned expected[]={60,120,240,480,900,900,900};
    for(unsigned i=0;i<sizeof expected/sizeof *expected;i++){
        module_supervisor_result(&s,now,0,false);
        assert(s.next_ms==now+expected[i]*1000ull&&!module_supervisor_due(&s,s.next_ms-1,false)&&module_supervisor_due(&s,s.next_ms,false));
        now=s.next_ms;
    }
    module_supervisor_result(&s,now,1,false);assert(s.restarts==1&&s.failures>4); /* partial restart keeps backing off */
    module_supervisor_result(&s,now,1,true);assert(s.restarts==2&&!s.failures&&!s.next_ms);
    for(int i=0;i<1000;i++){module_supervisor_result(&s,now,0,false);}
    assert(s.failures==255&&module_supervisor_delay_s(s.failures)==900);
    puts("PASS: actual optional-module supervisor: idle when running, 60 s doubling to 15 min, restart accounting, reset on recovery");
}
'''
with tempfile.TemporaryDirectory(prefix='module-supervisor-') as folder:
    p=Path(folder);(p/'s.c').write_text(SUPERVISOR)
    binary=p/('s.exe' if os.name=='nt' else 's');flags=['-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT/'main')]
    if os.environ.get('RETRY_SANITIZE')=='1':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC','gcc'),*flags,str(p/'s.c'),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
