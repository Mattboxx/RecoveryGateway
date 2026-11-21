"""Production Wi-Fi event handlers with a virtual clock and SDK fixtures."""
import os
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'main/main.c').read_text(encoding='utf-8')


def function(name):
    start = re.search(r'^static \w+ ' + name + r'\(', source, re.M).start()
    return source[start:source.index('\n}', start) + 2]


constants = re.findall(r'^#define WIFI_(?:DHCP_[A-Z]+_US|RETRIES_PER_NETWORK) .*$', source, re.M)
handlers = [
    'wifi_ap_napt_retry_tick', 'wifi_ap_napt_stop_retry', 'wifi_ap_napt_attempt',
    'wifi_ap_start_napt', 'wifi_ap_retry_napt', 'wifi_ap_stopped',
    'wifi_station_reconnect', 'wifi_lease_watch_allowed', 'wifi_lease_timer_tick',
    'wifi_lease_watch_stop', 'wifi_lease_watch_start', 'wifi_station_refresh',
    'wifi_lease_check_event', 'wifi_event_handler',
]

fixture = r'''
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
enum {ESP_OK, ESP_FAIL, ESP_ERR_INVALID_STATE, ESP_ERR_NOT_SUPPORTED};
enum {UPLINK_SERVICES_EVENT, WIFI_EVENT, IP_EVENT};
enum {UPLINK_REFRESH_EVENT, WIFI_LEASE_CHECK_EVENT, AP_NAPT_RETRY_EVENT};
enum {WIFI_EVENT_AP_STACONNECTED, WIFI_EVENT_AP_STADISCONNECTED, WIFI_EVENT_STA_START,
      WIFI_EVENT_STA_CONNECTED, WIFI_EVENT_STA_STOP, WIFI_EVENT_STA_DISCONNECTED};
enum {IP_EVENT_STA_GOT_IP, IP_EVENT_STA_LOST_IP};
enum {HIST_EV_UPLINK, HIST_WARN, HIST_INFO, BOOT_TL_WIFI_ASSOC, BOOT_TL_IP};
enum {FB_WIFI_TESTING, FB_WIFI_OK, WIFI_IF_AP, WIFI_SECOND_CHAN_NONE};
#define MALLOC_CAP_INTERNAL 1
#define MALLOC_CAP_8BIT 2
#define MACSTR "%u"
#define MAC2STR(mac) ((unsigned)(mac)[0])
#define IPSTR "%u"
#define IP2STR(ip) ((unsigned)(ip)->addr)
static const char *TAG_AP="AP", *TAG_STA="STA";
static void log_message(const char *tag, const char *fmt, ...) {(void)tag; (void)fmt;}
#define ESP_LOGI log_message
#define ESP_LOGW log_message
#define ESP_LOGE log_message
typedef int esp_err_t, esp_event_base_t, esp_netif_t, wifi_second_chan_t;
typedef struct {uint8_t mac[6]; int aid, reason;} wifi_event_ap_staconnected_t, wifi_event_ap_stadisconnected_t;
typedef struct {int reason;} wifi_event_sta_disconnected_t;
typedef struct {uint8_t primary;} wifi_ap_record_t;
typedef struct {struct {uint8_t channel;} ap;} wifi_config_t;
typedef struct {struct {uint32_t addr;} ip, netmask;} esp_netif_ip_info_t;
typedef struct {esp_netif_ip_info_t ip_info;} ip_event_got_ip_t;
typedef struct {void (*callback)(void *); const char *name; bool skip_unhandled_events;} esp_timer_create_args_t;
typedef esp_timer_create_args_t *esp_timer_handle_t;
static int s_net_current, s_net_retries, ap_connect, connect_count, s_setup_test;
static uint32_t s_setup_test_ip, s_setup_test_mask;
static bool s_sta_uses_dhcp=true, s_sta_associated, s_manual_scan_active, s_rotate_after_dhcp_timeout;
static int64_t s_wifi_lease_deadline, now;
static int networks=2, connects, disconnects, applied=-1, timer_creates, posts, updates, lost, eth, portmap, setup_disconnects;
static bool first_boot, shutting_down, driver_associated, ip, active, timer_fails, post_fails, disconnect_fails;
static esp_timer_create_args_t timer;
static esp_timer_handle_t s_wifi_lease_timer;
static esp_netif_t sta, ap;
static bool ap_up, s_ap_napt_retrying;
static atomic_bool s_ap_napt_ready;
static esp_timer_handle_t s_ap_napt_timer;
static esp_err_t napt_result;
static int napt_attempts, ap_wakeups, name_updates;

static bool first_boot_active(void) {return first_boot;}
static bool ap_policy_is_shutdown(void) {return shutting_down;}
static int wifi_networks_count(void) {return networks;}
static void wifi_apply_network(int slot) {assert(!driver_associated); applied=slot;}
static esp_err_t esp_wifi_connect(void) {connects++; return ESP_OK;}
static esp_err_t esp_wifi_disconnect(void) {
    assert(driver_associated);
    disconnects++;
    if (disconnect_fails) return ESP_FAIL;
    driver_associated=false;
    return ESP_OK;
}
static const char *esp_err_to_name(esp_err_t error) {assert(error); return "fixture error";}
static int64_t esp_timer_get_time(void) {return now;}
static esp_err_t esp_timer_create(const esp_timer_create_args_t *cfg, esp_timer_handle_t *out) {
    assert(cfg->callback && cfg->skip_unhandled_events);
    timer_creates++;
    if (timer_fails) return ESP_FAIL;
    timer=*cfg; *out=&timer; return ESP_OK;
}
static esp_err_t esp_timer_stop(esp_timer_handle_t handle) {
    assert(handle==&timer); active=false; return ESP_OK;
}
static esp_err_t esp_timer_start_periodic(esp_timer_handle_t handle, uint64_t period) {
    assert(handle==&timer && !active && period==WIFI_DHCP_POLL_US); active=true; return ESP_OK;
}
static esp_err_t esp_event_post(esp_event_base_t base, int32_t id, void *data, size_t len, int wait) {
    assert(base==UPLINK_SERVICES_EVENT && !data && !len && !wait);
    if (post_fails) return ESP_FAIL;
    if (id==WIFI_LEASE_CHECK_EVENT) posts++;
    else {assert(id==AP_NAPT_RETRY_EVENT); ap_wakeups++;}
    return ESP_OK;
}
static bool esp_netif_is_netif_up(esp_netif_t *netif) {assert(netif==&ap); return ap_up;}
static esp_err_t esp_netif_napt_enable(esp_netif_t *netif) {assert(netif==&ap && ap_up); napt_attempts++; return napt_result;}
static void lan_name_uplink_up(void) {name_updates++;}
static esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) {assert(!strcmp(key,"WIFI_STA_DEF")); return &sta;}
static bool uplink_address(esp_netif_t *netif, esp_netif_ip_info_t *info) {
    assert(netif==&sta && !info->ip.addr); info->ip.addr=ip; return ip;
}
static void history_event(int group, int level, const char *fmt, ...) {
    assert(group==HIST_EV_UPLINK && (level==HIST_INFO || level==HIST_WARN) && fmt);
}
static void eth_uplink_wifi_changed(void) {eth++;}
static void uplink_services_refresh(bool disconnected) {updates++; lost+=disconnected;}
static void portmap_install_all(void) {portmap++;}
static void boot_timeline_mark(int event) {(void)event;}
static esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *record) {
    record->primary=1; return driver_associated ? ESP_OK : ESP_FAIL;
}
static int nvs_param_get_int(const char *key, int32_t *out) {assert(!strcmp(key,"ap_chan_learned")); *out=1; return ESP_OK;}
static int nvs_param_set_int(const char *key, int32_t value) {(void)key; (void)value; abort();}
static esp_err_t esp_wifi_get_channel(uint8_t *primary, wifi_second_chan_t *secondary) {
    *primary=1; *secondary=0; return ESP_OK;
}
static esp_err_t esp_wifi_get_config(int iface, wifi_config_t *cfg) {assert(iface==WIFI_IF_AP); cfg->ap.channel=1; return ESP_OK;}
static void setup_test_disconnected(int reason) {assert(!reason); setup_disconnects++;}
static bool mac_deny_is_blocked(const uint8_t *mac) {(void)mac; return false;}
static void esp_wifi_deauth_sta(int aid) {(void)aid;}
static size_t heap_caps_get_free_size(int caps) {(void)caps; return 12000;}
static size_t heap_caps_get_largest_free_block(int caps) {(void)caps; return 8000;}
@@HANDLERS@@
static void wifi(int id) {wifi_event_handler(NULL,WIFI_EVENT,id,NULL);}
static void got_address(void) {
    ip_event_got_ip_t event={.ip_info={.ip={1},.netmask={255}}};
    ip=true;
    wifi_event_handler(NULL,IP_EVENT,IP_EVENT_STA_GOT_IP,&event);
}
static void tick(int64_t time) {
    now=time;
    assert(active);
    timer.callback(NULL);
    if (!post_fails) wifi_lease_check_event(NULL,UPLINK_SERVICES_EVENT,WIFI_LEASE_CHECK_EVENT,NULL);
}
static void associate(void) {driver_associated=true; ip=false; wifi(WIFI_EVENT_STA_CONNECTED);}
static void disconnect(void) {driver_associated=false; ip=false; wifi(WIFI_EVENT_STA_DISCONNECTED);}
int main(void) {
    associate();
    assert(active && timer_creates==1 && s_wifi_lease_deadline==WIFI_DHCP_GRACE_US);
    post_fails=true;
    tick(WIFI_DHCP_POLL_US);
    assert(!posts && !disconnects);
    post_fails=false;
    tick(WIFI_DHCP_GRACE_US-1);
    assert(!disconnects);
    tick(WIFI_DHCP_GRACE_US);
    assert(disconnects==1 && s_rotate_after_dhcp_timeout && applied==-1 && !connects);
    got_address(); /* Late SDK event for a profile being retired. */
    assert(!ap_connect);
    disconnect();
    assert(!active && applied==1 && connects==1 && !s_rotate_after_dhcp_timeout);

    associate();
    got_address();
    assert(ap_connect && !s_wifi_lease_deadline && active && timer_creates==1);
    int old_updates=updates, old_lost=lost;
    wifi_event_handler(NULL,IP_EVENT,IP_EVENT_STA_LOST_IP,NULL);
    assert(ap_connect && updates==old_updates); /* stale event */
    ip=false;
    wifi_event_handler(NULL,IP_EVENT,IP_EVENT_STA_LOST_IP,NULL);
    assert(!ap_connect && updates==old_updates+1 && lost==old_lost+1);
    tick(s_wifi_lease_deadline-1);
    assert(disconnects==1 && lost==old_lost+1);
    ip=true; /* IDF's event queue dropped the got-IP notification. */
    tick(s_wifi_lease_deadline);
    assert(ap_connect && !s_wifi_lease_deadline && updates==old_updates+2);
    ip=false;
    tick(now+WIFI_DHCP_POLL_US);
    assert(!ap_connect && lost==old_lost+2);
    s_manual_scan_active=true;
    tick(s_wifi_lease_deadline);
    assert(disconnects==1);
    s_manual_scan_active=false;
    driver_associated=false;
    tick(s_wifi_lease_deadline);
    assert(disconnects==1); /* avoid interrupting a new association */
    driver_associated=true;
    disconnect_fails=true;
    tick(s_wifi_lease_deadline);
    assert(disconnects==2 && !s_rotate_after_dhcp_timeout);
    disconnect_fails=false;
    tick(s_wifi_lease_deadline);
    assert(disconnects==3 && s_rotate_after_dhcp_timeout);
    networks=1;
    disconnect();
    assert(connects==2 && applied==1 && !active);
    s_sta_uses_dhcp=false;
    associate(); got_address();
    assert(ap_connect && !active);
    wifi(WIFI_EVENT_STA_STOP);
    assert(!s_sta_associated && !s_wifi_lease_deadline);
    s_sta_uses_dhcp=true;
    first_boot=true;
    associate();
    s_setup_test=FB_WIFI_TESTING;
    got_address();
    assert(s_setup_test==FB_WIFI_OK && s_setup_test_ip==1 && s_setup_test_mask==255 && !active);
    disconnect();
    assert(setup_disconnects==1 && connects==2);
    first_boot=false;
    shutting_down=true;
    associate();
    assert(!active);
    disconnect();
    assert(connects==2);
    shutting_down=false;
    s_wifi_lease_timer=NULL; timer_fails=true;
    associate();
    assert(!active && timer_creates==2);
    disconnect();
    timer_fails=false;
    associate();
    assert(active && timer_creates==3);
    disconnect();
    assert(updates==eth && updates==portmap);

    networks=2;
    s_net_current=s_net_retries=0;
    for (int i=0;i<WIFI_RETRIES_PER_NETWORK-1;i++) disconnect();
    assert(!s_net_current);
    disconnect();
    assert(s_net_current==1);
    puts("PASS: DHCP acquisition, lost/stale IP, retry/rotation, and wizard/static exclusion");

    int old_portmap=portmap;
    s_ap_napt_timer=&timer;
    first_boot=true;
    wifi_ap_start_napt(&ap,WIFI_EVENT,0,NULL);
    assert(!napt_attempts && !active && !atomic_load(&s_ap_napt_ready));
    first_boot=false;
    wifi_ap_start_napt(&ap,WIFI_EVENT,0,NULL);
    assert(!napt_attempts && active && s_ap_napt_retrying && !atomic_load(&s_ap_napt_ready));
    ap_up=true;
    napt_result=ESP_FAIL;
    post_fails=true;
    wifi_ap_napt_retry_tick(NULL);
    assert(!ap_wakeups && active);
    post_fails=false;
    wifi_ap_napt_retry_tick(NULL);
    assert(ap_wakeups==1);
    wifi_ap_retry_napt(&ap,UPLINK_SERVICES_EVENT,AP_NAPT_RETRY_EVENT,NULL);
    assert(napt_attempts==1 && active && !atomic_load(&s_ap_napt_ready));
    napt_result=ESP_OK;
    wifi_ap_retry_napt(&ap,UPLINK_SERVICES_EVENT,AP_NAPT_RETRY_EVENT,NULL);
    assert(napt_attempts==2 && !active && !s_ap_napt_retrying && atomic_load(&s_ap_napt_ready));
    assert(portmap==old_portmap+1 && name_updates==1);
    napt_result=ESP_FAIL;
    wifi_ap_start_napt(&ap,WIFI_EVENT,0,NULL);
    assert(active && !atomic_load(&s_ap_napt_ready));
    wifi_ap_stopped(NULL,WIFI_EVENT,0,NULL);
    wifi_ap_retry_napt(&ap,UPLINK_SERVICES_EVENT,AP_NAPT_RETRY_EVENT,NULL);
    assert(napt_attempts==3 && !active && !atomic_load(&s_ap_napt_ready) && name_updates==2);
    napt_result=ESP_ERR_NOT_SUPPORTED;
    wifi_ap_start_napt(&ap,WIFI_EVENT,0,NULL);
    assert(napt_attempts==4 && !active);
    puts("PASS: AP NAPT recovery, truthful readiness, saturated event queue and obsolete retry cancellation");
}
'''

with tempfile.TemporaryDirectory(prefix='wifi-lease-') as folder:
    path = Path(folder)
    test = path / 'test.c'
    test.write_text('\n'.join(constants) + '\n' + fixture.replace('@@HANDLERS@@', '\n'.join(map(function, handlers))),
                    encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter']
    if os.environ.get('WIFI_LEASE_SANITIZE') == '1':
        flags.extend(['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(test), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], timeout=10, check=True)
