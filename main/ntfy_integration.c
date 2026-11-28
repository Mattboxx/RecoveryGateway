/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Optional ntfy integration.
 *
 * No traffic is emitted unless explicitly enabled. The access token is never
 * returned by the web API, written to logs, or included in status replies.
 */
#include "ntfy_integration.h"
#include "ntfy_json_stream.h"
#include "remote_commands.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "runtime_metrics.h"
#include "snmp_agent.h"
#include "dhcps_ext.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_crt_bundle.h"
#include "ml_tls_distrust.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "eth_uplink.h"
#include "uplink_services.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "fourvia6.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/ip4_addr.h"
#include "microlink.h"
#include "mqtt_integration.h"
#include "nvs_params.h"
#include "wifi_power_save.h"
#include "nvs.h"
#include "tailscale_config.h"
#include "peer_dns.h"
#include "ota_remote.h"
#include "wol.h"
#include "homelab_ops.h"
#include "health_monitor.h"
#include "service_lease.h"
#include "service_retry.h"
#include "ntfy_events.h"
#include "notify_text.h"
#include "power_history.h"
#include "notify_channels.h"
#include "tailnet_forward.h"
#include "web_ui.h"
#include "history.h"

static const char *TAG = "ntfy";
_Static_assert(sizeof(ntfy_integration_config_t) == 428, "Keep the existing configuration RAM footprint");
static ntfy_integration_config_t s_config;
static ntfy_integration_status_t s_status;
static SemaphoreHandle_t s_lock;
static TaskHandle_t s_task;
static char s_last_event_id[48];
/* Changes invalidate queued replies, including a disable/re-enable cycle. */
static uint64_t s_config_generation;
#define NTFY_OPERATIONAL_CAPACITY 6
#define NTFY_OPERATIONAL_ATTEMPTS 3
#define NTFY_OPERATIONAL_TTL_MS 300000

typedef struct {
    char message[160];
    uint64_t queued_ms;
    uint32_t destination;
} operational_event_t;

/* Task-only text. Keep the queue in PSRAM and send at most one at a time. */
EXT_RAM_BSS_ATTR static operational_event_t s_operational[NTFY_OPERATIONAL_CAPACITY];
static unsigned s_operational_head;
static unsigned s_operational_count;
static unsigned s_operational_attempts;
static uint64_t s_operational_retry_ms;
static uint32_t s_operational_generation = 1;
static remote_command_gate_t s_command_gate;
static time_t s_command_floor;
static char s_priming_cursor[48];
static bool s_priming_legacy;

static void operational_pop(bool dropped)
{
    s_operational_head = (s_operational_head + 1) % NTFY_OPERATIONAL_CAPACITY;
    --s_operational_count;
    s_operational_attempts = 0;
    s_operational_retry_ms = 0;
    if (dropped) ++s_status.operational_dropped;
}

static void operational_expire(uint64_t now)
{
    while (s_operational_count &&
           now - s_operational[s_operational_head].queued_ms >= NTFY_OPERATIONAL_TTL_MS)
        operational_pop(true);
}

static bool queue_operational(uint32_t destination, const char *message)
{
    if (!s_lock || !message || !message[0] || strlen(message) >= sizeof s_operational[0].message)
        return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool accepted = false;
    if (s_config.enabled && (!destination || destination == remote_command_ticket(&s_command_gate))) {
        uint64_t now = (uint64_t)esp_timer_get_time() / 1000;
        /* Only the worker may evict the head while a send can be in flight. */
        if (s_operational_count < NTFY_OPERATIONAL_CAPACITY) {
            unsigned tail = (s_operational_head + s_operational_count) % NTFY_OPERATIONAL_CAPACITY;
            strlcpy(s_operational[tail].message, message, sizeof s_operational[tail].message);
            s_operational[tail].queued_ms = now;
            s_operational[tail].destination = destination;
            ++s_operational_count;
            accepted = true;
        } else {
            ++s_status.operational_dropped;
        }
    }
    xSemaphoreGive(s_lock);
    return accepted;
}

bool ntfy_integration_queue_event(const char *message)
{
    /* History forwards independently to the enabled Telegram/email channels. */
    if (message) history_event(HIST_EV_SERVICE, HIST_INFO, "%s", message);
    return queue_operational(0, message);
}

bool ntfy_integration_queue_reply(uint32_t destination, const char *message)
{
    return destination && queue_operational(destination, message);
}

bool remote_command_active(ops_recovery_origin_t origin, uint32_t destination)
{
    if (origin == OPS_RECOVERY_TELEGRAM) return notify_telegram_command_active(destination);
    if (origin == OPS_RECOVERY_NTFY) return destination && destination == remote_command_ticket(&s_command_gate);
    return destination == 0 && (origin == OPS_RECOVERY_LOCAL || origin == OPS_RECOVERY_MQTT);
}

bool remote_command_reply(ops_recovery_origin_t origin, uint32_t destination, const char *message)
{
    if (origin == OPS_RECOVERY_TELEGRAM) return notify_telegram_queue_reply(destination, message);
    if (origin == OPS_RECOVERY_NTFY) return ntfy_integration_queue_reply(destination, message);
    return false;
}

/* TLS certificate verification needs its own stack reserve. Keep the large
 * reporting/polling frames out of ntfy_task_main: GCC otherwise inlines them and
 * permanently reserves their buffers even on a simple command poll. */
#define NTFY_TASK_STACK_BYTES 12288
#define NTFY_NOINLINE __attribute__((noinline))

extern bool wifi_ap_runtime_enabled(void);
extern bool wifi_ap_policy_auto_off(void);

#define NTFY_POLL_BATCH 32
typedef struct {
    ntfy_json_parser_t parser;
    ntfy_json_event_t events[NTFY_POLL_BATCH];
    size_t count;
    char read_buffer[512];
} command_batch_t;

static void defaults(ntfy_integration_config_t *c)
{
    memset(c, 0, sizeof *c);
    strlcpy(c->server, "https://ntfy.sh", sizeof c->server);
    c->failure_delay_seconds = 120;
    c->poll_interval_seconds = 15;
    c->commands_only_when_tailscale_down = true;
    c->info_enabled = true;
}

static bool load_string(const char *key, char *out, size_t size)
{
    /* Distinguish a missing optional key from a read/allocation/type error.
     * Never turn a failed token read into an anonymous configuration. */
    size_t length = size;
    esp_err_t err = nvs_param_get_str_buf(key, out, &length);
    return err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND;
}

static bool load_config(ntfy_integration_config_t *c)
{
    defaults(c);
    bool valid = true;
#define LOAD_U8(key, field) do { uint8_t b; esp_err_t err = nvs_param_get_u8((key), &b); \
    if (err == ESP_OK && b <= 1) (field) = b != 0; \
    else if (err != ESP_ERR_NVS_NOT_FOUND) valid = false; } while (0)
#define LOAD_U16(key, field) do { uint16_t n; esp_err_t err = nvs_param_get_u16((key), &n); \
    if (err == ESP_OK) (field) = n; \
    else if (err != ESP_ERR_NVS_NOT_FOUND) valid = false; } while (0)
    LOAD_U8("ntfy_en", c->enabled); LOAD_U8("ntfy_alert", c->tailscale_alerts);
    LOAD_U8("ntfy_cmd", c->commands_enabled);
    LOAD_U8("ntfy_down", c->commands_only_when_tailscale_down);
    LOAD_U8("ntfy_mac", c->allow_direct_mac); LOAD_U8("ntfy_info", c->info_enabled);
    LOAD_U8("ntfy_infdet", c->info_include_details);
    LOAD_U16("ntfy_delay", c->failure_delay_seconds);
    LOAD_U16("ntfy_poll", c->poll_interval_seconds);
#undef LOAD_U8
#undef LOAD_U16
    valid = load_string("ntfy_srv", c->server, sizeof c->server) && valid;
    valid = load_string("ntfy_topic", c->topic, sizeof c->topic) && valid;
    valid = load_string("ntfy_token", c->token, sizeof c->token) && valid;
    return valid;
}

static bool topic_valid(const char *topic)
{
    if (!topic || !topic[0]) return false;
    for (const unsigned char *p = (const unsigned char *)topic; *p; p++)
        if (!isalnum(*p) && *p != '-' && *p != '_') return false;
    return true;
}

static bool token_header_valid(const char *token)
{
    if (!token) return false;
    for (const unsigned char *p = (const unsigned char *)token; *p; ++p)
        if (*p <= 32 || *p >= 127) return false;
    return true; /* Empty token is valid for explicitly anonymous topics. */
}

static bool config_valid(const ntfy_integration_config_t *c)
{
    if (!c || !memchr(c->server, 0, sizeof c->server) ||
        !memchr(c->topic, 0, sizeof c->topic) ||
        !memchr(c->token, 0, sizeof c->token) || !token_header_valid(c->token)) return false;
    bool server_ok = strncmp(c->server, "https://", 8) == 0
                   || strncmp(c->server, "http://", 7) == 0;
    /* Topic is appended as a path segment, so query/fragment syntax has no
     * valid role in the base URL. Reject whitespace/control characters and
     * URI user-info as well: tokens use the write-only Authorization field
     * and must never become part of a URL that may be logged or returned. */
    if (strpbrk(c->server, "@?#\r\n\t ") != NULL) server_ok = false;
    for (const unsigned char *p = (const unsigned char *)c->server; *p; ++p)
        if (*p <= 32 || *p >= 127 || *p == '\\') server_ok = false;
    return (!c->enabled || (server_ok && topic_valid(c->topic)))
        && c->failure_delay_seconds >= 15 && c->failure_delay_seconds <= 3600
        && c->poll_interval_seconds >= 5 && c->poll_interval_seconds <= 300;
}

/* Configuration and its endpoint-bound replay cursor are one versioned NVS
 * value. Writing individual keys can leave a partially updated configuration
 * after a flash allocation failure or reset. Never serialize native bools:
 * validate an explicit bitset before decoding untrusted persisted bytes. */
typedef struct {
    uint32_t schema;
    uint32_t flags;
    uint16_t delay, poll;
    char server[160], topic[96], token[160], cursor[48];
} saved_ntfy_state_t;

static bool event_id_valid(const char *id)
{
    size_t length = 0;
    if (!id || !id[0]) return false;
    for (const unsigned char *p = (const unsigned char *)id; *p; ++p) {
        if (++length >= sizeof s_last_event_id ||
            !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_')) return false;
    }
    return true;
}

/* Caller holds s_lock (or runs before the worker is started). This lock is
 * held only for short NVS operations, never across HTTP/TLS or command work. */
static NTFY_NOINLINE esp_err_t save_state(const ntfy_integration_config_t *c,
                                        const char *cursor)
{
    saved_ntfy_state_t saved = {0};
    saved.schema = 1;
    saved.flags = (c->enabled ? 1U : 0) | (c->tailscale_alerts ? 2U : 0) |
        (c->commands_enabled ? 4U : 0) | (c->commands_only_when_tailscale_down ? 8U : 0) |
        (c->allow_direct_mac ? 16U : 0) | (c->info_enabled ? 32U : 0) |
        (c->info_include_details ? 64U : 0);
    saved.delay = c->failure_delay_seconds; saved.poll = c->poll_interval_seconds;
    strlcpy(saved.server, c->server, sizeof saved.server);
    strlcpy(saved.topic, c->topic, sizeof saved.topic);
    strlcpy(saved.token, c->token, sizeof saved.token);
    strlcpy(saved.cursor, cursor, sizeof saved.cursor);
    return nvs_param_set_blob("ntfy_state_v1", &saved, sizeof saved);
}

static void load_state(ntfy_integration_config_t *c)
{
    defaults(c);
    s_last_event_id[0] = 0;
    saved_ntfy_state_t saved;
    size_t length = sizeof saved;
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        err = nvs_get_blob(nvs, "ntfy_state_v1", &saved, &length);
        nvs_close(nvs);
    }
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        /* One-time migration. Keep legacy values untouched for recovery;
         * after success the new record is authoritative, even if corrupt. */
        bool legacy_valid = load_config(c);
        if (!load_string("ntfy_last", s_last_event_id, sizeof s_last_event_id))
            s_last_event_id[0] = 0;
        if (!event_id_valid(s_last_event_id)) s_last_event_id[0] = 0;
        if (legacy_valid && config_valid(c) && save_state(c, s_last_event_id) == ESP_OK) return;
    } else if (err == ESP_OK && length == sizeof saved && saved.schema == 1 &&
               (saved.flags & ~127U) == 0 &&
               memchr(saved.server, 0, sizeof saved.server) &&
               memchr(saved.topic, 0, sizeof saved.topic) &&
               memchr(saved.token, 0, sizeof saved.token) &&
               memchr(saved.cursor, 0, sizeof saved.cursor) &&
               (!saved.cursor[0] || event_id_valid(saved.cursor))) {
        c->enabled = (saved.flags & 1U) != 0;
        c->tailscale_alerts = (saved.flags & 2U) != 0;
        c->commands_enabled = (saved.flags & 4U) != 0;
        c->commands_only_when_tailscale_down = (saved.flags & 8U) != 0;
        c->allow_direct_mac = (saved.flags & 16U) != 0;
        c->info_enabled = (saved.flags & 32U) != 0;
        c->info_include_details = (saved.flags & 64U) != 0;
        c->failure_delay_seconds = saved.delay; c->poll_interval_seconds = saved.poll;
        strlcpy(c->server, saved.server, sizeof c->server);
        strlcpy(c->topic, saved.topic, sizeof c->topic);
        strlcpy(c->token, saved.token, sizeof c->token);
        if (config_valid(c)) {
            strlcpy(s_last_event_id, saved.cursor, sizeof s_last_event_id);
            return;
        }
    }
    /* Never fall back to an old enabled configuration on corruption/errors. */
    defaults(c); s_last_event_id[0] = 0;
    ESP_LOGW(TAG, "Stored settings unavailable or invalid; integration disabled");
}

static uint64_t snapshot(ntfy_integration_config_t *out)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(out, &s_config, sizeof *out);
    uint64_t generation = s_config_generation;
    xSemaphoreGive(s_lock);
    return generation;
}

static void build_url(const ntfy_integration_config_t *c, const char *suffix,
                      char *out, size_t out_size)
{
    size_t n = strlen(c->server);
    while (n > 0 && c->server[n - 1] == '/') n--;
    snprintf(out, out_size, "%.*s/%s%s", (int)n, c->server, c->topic,
             suffix ? suffix : "");
}

static esp_err_t set_auth(esp_http_client_handle_t client,
                     const ntfy_integration_config_t *c)
{
    if (!memchr(c->token, 0, sizeof c->token) || !token_header_valid(c->token))
        return ESP_ERR_INVALID_ARG;
    if (!c->token[0]) return ESP_OK;
    char value[176];
    snprintf(value, sizeof value, "Bearer %s", c->token);
    return esp_http_client_set_header(client, "Authorization", value);
}

static NTFY_NOINLINE esp_err_t publish_message(const ntfy_integration_config_t *c,
                                 const char *title, const char *tags,
                                 const char *message)
{
    if(!homelab_ops_admit())return ESP_ERR_NO_MEM;
    char url[288];
    build_url(c, NULL, url, sizeof url);
    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 12000,
        .crt_bundle_attach = ml_tls_bundle_attach,
        /* SDK redirection retains manually installed Authorization headers
         * and POST data. Never replay the token or private info to a new
         * origin (or silently downgrade HTTPS). Configure the final URL. */
        .disable_auto_redirect = true,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return ESP_ERR_NO_MEM;
    esp_err_t err = set_auth(client, c);
    esp_http_client_set_header(client, "Content-Type", "text/plain; charset=utf-8");
    if (title) esp_http_client_set_header(client, "Title", title);
    if (tags) esp_http_client_set_header(client, "Tags", tags);
    esp_http_client_set_post_field(client, message, strlen(message));
    if (err == ESP_OK) err = esp_http_client_perform(client);
    int status = err == ESP_OK ? esp_http_client_get_status_code(client) : 0;
    esp_http_client_cleanup(client);
    bool ok = err == ESP_OK && status >= 200 && status < 300;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.last_publish_ok = ok;
    xSemaphoreGive(s_lock);
    if (!ok) ESP_LOGW(TAG, "publish failed: %s HTTP %d", esp_err_to_name(err), status);
    if (ok) return ESP_OK;
    if (err == ESP_OK && status >= 400 && status < 500 && status != 408 && status != 429)
        return ESP_ERR_INVALID_RESPONSE;
    return err == ESP_OK ? ESP_FAIL : err;
}

static void appendf(char *out, size_t size, const char *fmt, ...)
{
    size_t used = strlen(out);
    if (used >= size - 1) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(out + used, size - used, fmt, args);
    va_end(args);
}

/* Static text shared by info and boot messages (notify_text.c, the same
 * wording Telegram and email use). */
static const char *reset_reason_text(bool poweron_events)
{
    return notify_text_reset_cause((int)esp_reset_reason(), poweron_events);
}


/* The info reply, shared by ntfy and Telegram commands (remote_commands.h).
 * Never contains passwords, Wi-Fi keys, Tailscale keys or service tokens;
 * private network details only with include_details. Caller frees. */
NTFY_NOINLINE char *remote_info_text(bool include_details, bool poweron_events)
{
    const struct { bool info_include_details, poweron_events; } cfg = {include_details, poweron_events}, *c = &cfg;
    char *text = calloc(1, 8192);
    if (!text) return NULL;
    const esp_app_desc_t *app = esp_app_get_description();
    appendf(text, 8192, "GATEWAY\n");
    runtime_metrics_t cpu = runtime_metrics_get();
    if (cpu.valid)
        appendf(text, 8192, "CPU: %u%% (core 0: %u%%, core 1: %u%%)\n",
                cpu.load_pct, cpu.core_pct[0], cpu.core_pct[1]);
    else
        appendf(text, 8192, "CPU: sample not available yet\n");
    appendf(text, 8192, "Firmware: %s\nUptime: %llu s\nFree heap: %lu B (minimum %lu B)\nReset reason: %s\nWeb UI port: %u\n",
            app ? app->version : "unknown", esp_timer_get_time() / 1000000ULL,
            (unsigned long)esp_get_free_heap_size(),
            (unsigned long)esp_get_minimum_free_heap_size(), reset_reason_text(c->poweron_events),
            (unsigned)web_ui_configured_port());
    appendf(text, 8192, "Socket limit: %d\nSNMP: %s (%s)\n",
            CONFIG_LWIP_MAX_SOCKETS, snmp_agent_is_enabled() ? "enabled" : "disabled",
            snmp_agent_is_running() ? "running" : "stopped");
    ops_resources_t resources;homelab_ops_resources(&resources);
    appendf(text,8192,"Operational resources: sockets %d/%d, internal min %lu B, largest block %lu B\n",
        resources.sockets_used,resources.socket_limit,(unsigned long)resources.internal_min,(unsigned long)resources.internal_largest);
    cJSON *operations=homelab_ops_snapshot(false);
    if(operations){
        const cJSON *state=cJSON_GetObjectItemCaseSensitive(operations,"recovery_state");
        appendf(text,8192,"Recovery job: %s\n",cJSON_IsString(state)?state->valuestring:"unavailable");
        const cJSON *health=cJSON_GetObjectItemCaseSensitive(operations,"health"),*check;
        cJSON_ArrayForEach(check,cJSON_GetObjectItemCaseSensitive(health,"checks")){
            const cJSON *role=cJSON_GetObjectItemCaseSensitive(check,"role"),*status=cJSON_GetObjectItemCaseSensitive(check,"state");
            appendf(text,8192,"Health check (%s): %s\n",cJSON_IsString(role)?role->valuestring:"check",cJSON_IsString(status)?status->valuestring:"unknown");
        }
        cJSON_Delete(operations);
    }
    cJSON *leases=service_lease_snapshot();
    if(leases){const cJSON *lease;cJSON_ArrayForEach(lease,leases){
        const cJSON *status=cJSON_GetObjectItemCaseSensitive(lease,"status"),*index=cJSON_GetObjectItemCaseSensitive(lease,"index"),*remaining=cJSON_GetObjectItemCaseSensitive(lease,"remaining_s");
        appendf(text,8192,"LAN→Tailnet rule %d lease: %s, %.0f seconds remaining\n",cJSON_IsNumber(index)?index->valueint+1:0,cJSON_IsString(status)?status->valuestring:"unknown",cJSON_IsNumber(remaining)?remaining->valuedouble:0);
    }cJSON_Delete(leases);}

    esp_netif_ip_info_t ip = {0};
    wifi_ap_record_t ap = {0};
    bool uplink = uplink_address(uplink_internet_netif(), &ip);
    bool have_ap = esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
    appendf(text, 8192, "\nCONNECTIVITY\nInternet uplink: %s\n",
            uplink ? "connected" : "disconnected");
    if (have_ap) appendf(text, 8192, "Wi-Fi signal: %d dBm\n", ap.rssi);
    bool wifi_ps_active = false;
    bool wifi_ps_known = wifi_power_save_runtime(&wifi_ps_active);
    appendf(text, 8192, "WiFi power save: %s (runtime: %s)\n",
            wifi_power_save_configured() ? "on" : "off",
            wifi_ps_known ? (wifi_ps_active ? "on" : "off") : "unknown");
    if (c->info_include_details) {
        appendf(text, 8192, "WiFi SSID: %s\nLocal IP: " IPSTR
                "\nNetmask: " IPSTR "\nGateway: " IPSTR "\n",
                have_ap ? (char *)ap.ssid : "", IP2STR(&ip.ip),
                IP2STR(&ip.netmask), IP2STR(&ip.gw));
    }

    bool ts = tailscale_is_connected();
    ip4_addr_t ts_ip = {.addr = tailscale_tunnel_ip};
    appendf(text, 8192, "\nTAILNET\nTailscale: %s\nAdvertise as exit node: %s\n",
            !tailscale_enabled ? "disabled" : ts ? "connected" : "disconnected",
            tailscale_advertise_exit_node ? "yes" : "no");
    microlink_t *ml = tailscale_get_microlink();
    ota_remote_state_t update; ota_remote_get_state(&update);
    appendf(text, 8192, "\nUPDATES\nPeriodic checks: %s\nAutomatic install: %s\nChannel: %s\nLatest release: %s\nStatus: %s\n",
            update.config.enabled ? "on" : "off", update.config.auto_install ? "on" : "off",
            update.config.beta_channel ? "stable + beta" : "stable only",
            update.latest_version[0] ? update.latest_version : "none", update.status);
    appendf(text, 8192, "\nTAILNET ROUTING\nExit-node server (this boot): %s\nExit-node DNS: %s (port %u)\n",
            tailscale_exit_server_active() ? "active" : "inactive",
            peer_dns_is_running() ? "running" : "stopped", (unsigned)tailscale_peerapi_port());
    appendf(text, 8192, "Exit-node server configured: %s (manual default route: %s)\n",
            tailscale_exit_server_configured() ? "yes" : "no",
            tailscale_manual_exit_configured() ? "yes" : "no");
    appendf(text, 8192, "Automatic AP advertisement (configured): %s\n",
            tailscale_advertise_ap ? "yes" : "no");
    int peers = ml ? microlink_get_peer_count(ml) : 0;
    appendf(text, 8192, "Known peers: %d\n", peers);
    if (c->info_include_details) {
        appendf(text, 8192, "Tailscale IP: " IPSTR
                "\nActive advertised routes: %s\nAccept peer routes: %s\nSource NAT: %s\n",
                IP2STR(&ts_ip), tailscale_active_routes(),
                tailscale_accept_routes ? "yes" : "no", tailscale_snat_subnet_routes ? "yes" : "no");
        for (int i = 0; i < peers; i++) {
            microlink_peer_info_t p = {0};
            if (microlink_get_peer_info(ml, i, &p) != ESP_OK) continue;
            appendf(text, 8192, "- %s %u.%u.%u.%u %s via %s\n", p.hostname,
                    (p.vpn_ip >> 24) & 255, (p.vpn_ip >> 16) & 255,
                    (p.vpn_ip >> 8) & 255, p.vpn_ip & 255,
                    p.online ? "online" : "offline", p.direct_path ? "direct" : "DERP");
        }
    }

    fourvia6_status_t v6;
    fourvia6_get_status(&v6);
    appendf(text, 8192, "\n4via6: %s\nFlows: %lu\n",
            v6.enabled ? "enabled" : "disabled", (unsigned long)v6.active_flows);
    if (c->info_include_details) {
        appendf(text, 8192, "LAN: %s\nSite ID: %u\nPrefix: %s\n",
                v6.lan_cidr, v6.site_id, v6.advertised_prefix);
    }
    wifi_sta_list_t clients = {0};
    int clients_n = wifi_ap_runtime_enabled() && esp_wifi_ap_get_sta_list(&clients) == ESP_OK
                    ? clients.num : 0;
    appendf(text, 8192, "\nWI-FI GATEWAY\nAccess point: %s\nPolicy: %s\nConnected devices: %d\n",
            wifi_ap_runtime_enabled() ? "enabled" : "disabled",
            wifi_ap_policy_auto_off() ? "standby while uplink is connected" : "always available", clients_n);
    if (c->info_include_details) {
        for (int i = 0; i < clients_n; i++) {
            uint8_t *m = clients.sta[i].mac;
            appendf(text, 8192, "- %02x:%02x:%02x:%02x:%02x:%02x RSSI %d dBm\n",
                    m[0],m[1],m[2],m[3],m[4],m[5], clients.sta[i].rssi);
        }
    }
    uint32_t tf_enabled=0,tf_installed=0,tf_accepted=0,tf_blocked=0;
    tailnet_forward_totals(&tf_enabled,&tf_installed,&tf_accepted,&tf_blocked);
    appendf(text,8192,"\nSERVICE GATEWAY\nRules: %lu saved, %lu enabled, %lu active\nPackets: %lu accepted, %lu blocked\n",
            (unsigned long)tailnet_forward_count(),(unsigned long)tf_enabled,(unsigned long)tf_installed,
            (unsigned long)tf_accepted,(unsigned long)tf_blocked);
    if(c->info_include_details){for(int i=0;i<tailnet_forward_count();i++){tailnet_forward_rule_t r;tailnet_forward_runtime_t rt;if(!tailnet_forward_get(i,&r,&rt))continue;char cidr[TAILNET_FORWARD_SOURCES_TEXT];tailnet_forward_format_sources(&r,cidr,sizeof cidr);appendf(text,8192,"- %s: %s/%u -> %s:%u, source %s [%s]\n",r.name[0]?r.name:"unnamed",r.proto==17?"UDP":"TCP",r.listen_port,r.destination,r.destination_port,cidr,rt.installed?"active":(rt.error[0]?rt.error:"inactive"));}}

    mqtt_integration_config_t mqtt;
    mqtt_integration_get_config(&mqtt);
    appendf(text, 8192, "\nAUTOMATION\nMQTT: %s\n\nWAKE-ON-LAN\nSaved devices: %d\n",
            !mqtt.enabled ? "disabled" : mqtt_integration_connected() ? "connected" : "disconnected",
            wol_count());
    for (int i = 0; i < wol_count(); i++) {
        wol_device_t w;
        if (!wol_get(i, &w)) continue;
        appendf(text, 8192, "- %s", w.name[0] ? w.name : "unnamed");
        if (c->info_include_details) {
            char mac[18]; wol_format_mac(w.mac, mac); appendf(text, 8192, " (%s)", mac);
        }
        appendf(text, 8192, "\n");
    }
    return text;
}

static NTFY_NOINLINE esp_err_t send_info(const ntfy_integration_config_t *c, uint32_t destination)
{
    char *text = remote_info_text(c->info_include_details, c->poweron_events);
    if (!text) return ESP_ERR_NO_MEM;
    /* ntfy messages are limited in size. Send deterministic chunks; no chunk
     * contains passwords, WiFi keys, Tailscale keys, or broker/ntfy tokens. */
    size_t length = strlen(text), offset = 0;
    unsigned part = 1, parts = 0;
    for (size_t start = 0; start < length; ) {
        size_t take = remote_reply_chunk_size(text, length, start, 3500);
        if (!take) { free(text); return ESP_FAIL; }
        start += take;
        parts++;
    }
    esp_err_t result = ESP_OK;
    while (offset < length) {
        if (!remote_command_active(OPS_RECOVERY_NTFY, destination)) {
            result = ESP_ERR_INVALID_STATE;
            break;
        }
        size_t take = remote_reply_chunk_size(text, length, offset, 3500);
        if (!take) { result = ESP_FAIL; break; }
        char saved = text[offset + take]; text[offset + take] = '\0';
        char title[64];
        if (parts > 1) snprintf(title, sizeof title, "ESP32 gateway status %u/%u", part, parts);
        else strlcpy(title, "ESP32 gateway status", sizeof title);
        esp_err_t err = publish_message(c, title, "information,mattboxx-response", text + offset);
        text[offset + take] = saved;
        if (err != ESP_OK) { result = err; break; }
        offset += take; part++;
    }
    free(text);
    return result;
}

static esp_err_t named_wol_device(const char *name, wol_device_t *device)
{
    bool found = false;
    for (int i = 0; i < wol_count(); i++) {
        wol_device_t d;
        if (!wol_get(i, &d) || !d.name[0] || strcasecmp(d.name, name)) continue;
        if (found) return ESP_ERR_INVALID_SIZE;
        *device = d;
        found = true;
    }
    return found ? ESP_OK : ESP_ERR_NOT_FOUND;
}

static esp_err_t wake_argument(bool allow_direct_mac, const char *argument)
{
    wol_device_t device;
    esp_err_t found = named_wol_device(argument, &device);
    if (found == ESP_OK) return wol_send_mac(device.mac, device.broadcast, device.port);
    if (found != ESP_ERR_NOT_FOUND) return found;
    uint8_t mac[6];
    if (!wol_parse_mac(argument, mac)) return ESP_ERR_NOT_FOUND;
    esp_err_t err = wol_send_saved_mac_text(argument);
    if (err != ESP_ERR_NOT_FOUND) return err;
    return allow_direct_mac ? wol_send_mac(mac, NULL, 9) : ESP_ERR_INVALID_STATE;
}

/* One remote command, shared by ntfy and Telegram (remote_commands.h). */
static const char *remote_error(esp_err_t err, bool probe)
{
    switch (err) {
        case ESP_ERR_NOT_SUPPORTED: return "This channel is set to basic commands. In Automation, enable verified recovery for this channel.";
        case ESP_ERR_NOT_FOUND: return probe ? "Saved TCP check not found. Send checks for the names." :
                                             "Saved device not found. Send devices for the names.";
        case ESP_ERR_INVALID_ARG: return probe ? "Enter the name of a saved TCP check." :
                                               "Set a verification address and enough attempts in Devices & Recovery.";
        case ESP_ERR_INVALID_SIZE: return "More than one device has this name. Use the saved MAC address or give each device a unique name.";
        case ESP_ERR_TIMEOUT: return probe ? "A TCP check ran recently. Try again in a few seconds." :
                                             "This device was checked recently. Wait a minute and try again.";
        case ESP_ERR_INVALID_STATE: return "Another operation is running or delivering its result. Try again shortly.";
        case ESP_ERR_NOT_ALLOWED:
        case ESP_ERR_NO_MEM: return "The gateway is low on resources. Try again after traffic settles.";
        default: return "The operation could not start. Check the gateway diagnostics.";
    }
}

remote_cmd_kind_t remote_command_run(const char *message, bool info_enabled, bool allow_direct_mac,
                                     ops_recovery_origin_t origin, uint32_t destination,
                                     char *reply, size_t cap, const char **title)
{
    reply[0] = '\0';
    *title = NULL;
    if (!remote_command_active(origin, destination)) return REMOTE_CMD_NONE;
    while (*message && isspace((unsigned char)*message)) message++;
    if (*message == '/') message++;
    /* Mobile clients often append a newline. Trim edges without changing
     * spaces within a saved WOL device name; reject oversized commands. */
    size_t length = strlen(message);
    while (length && isspace((unsigned char)message[length - 1])) length--;
    char command[128];
    if (!length || length >= sizeof command) return REMOTE_CMD_NONE;
    memcpy(command, message, length);
    command[length] = '\0';
    char *argument = command;
    while (*argument && !isspace((unsigned char)*argument)) argument++;
    if (*argument) *argument++ = '\0';
    while (isspace((unsigned char)*argument)) argument++;
    const bool help = !strcasecmp(command, "help") || !strcasecmp(command, "start");
    const bool info = !strcasecmp(command, "info") || !strcasecmp(command, "status");
    const bool devices = !strcasecmp(command, "devices");
    const bool wol = !strcasecmp(command, "wol");
    const bool recover = !strcasecmp(command, "recover");
    const bool check = !strcasecmp(command, "check");
    const bool probe = !strcasecmp(command, "probe");
    const bool checks = !strcasecmp(command, "checks");
    if (!(help || info || devices || wol || recover || check || probe || checks)) return REMOTE_CMD_NONE;
    *title = "ESP32 command response";
    const bool has_target = wol || recover || check || probe;
    if (has_target == (*argument == '\0')) {
        snprintf(reply, cap, "Usage: %s%s. Send help for examples.", command, has_target ? " NAME" : "");
        return REMOTE_CMD_ERROR;
    }
    if (help) {
        *title = "ESP32 command guide";
        snprintf(reply, cap,
            "COMMANDS\n\n"
            "help — show this guide\n"
            "devices — last result for each saved device\n"
            "wol NAS — send a Wake-on-LAN packet\n"
            "%s%s\nReplace NAS and PRINTER with your saved names. Names can contain spaces.",
            info_enabled ? "info (or status) — gateway status\n" : "",
            homelab_ops_recovery_allowed(origin) ?
            "\nRECOVERY AND CHECKS\n"
            "recover NAS — wake if needed and verify online status\n"
            "check NAS — verify without waking\n"
            "probe PRINTER — test a saved TCP service\n"
            "checks — saved TCP services and last results\n" :
            "\nEnable verified recovery for this channel in Automation to use recover, check, probe and checks.\n");
        return REMOTE_CMD_HELP;
    }
    if (info) {
        if (info_enabled) return REMOTE_CMD_INFO;
        strlcpy(reply, "The info command is disabled for this channel. Use help for available commands.", cap);
        return REMOTE_CMD_ERROR;
    }
    if (devices) {
        *title = "ESP32 saved devices";
        homelab_ops_device_summary(reply, cap);
        return REMOTE_CMD_OK;
    }
    if (wol) {
        if (!remote_command_active(origin, destination)) return REMOTE_CMD_NONE;
        *title = "ESP32 Wake-on-LAN";
        esp_err_t err = wake_argument(allow_direct_mac, argument);
        if (err == ESP_OK) snprintf(reply, cap, "Device: %s\nWake packet: sent.%s", argument,
            homelab_ops_recovery_allowed(origin) ? "\nUse recover to check online status." : "");
        else strlcpy(reply, err == ESP_ERR_INVALID_STATE ?
            "Wake failed. Check the uplink and whether this channel allows unsaved MAC addresses." :
            err == ESP_ERR_NOT_FOUND || err == ESP_ERR_INVALID_SIZE ? remote_error(err, false) :
            "The wake packet could not be sent. Check the uplink.", cap);
        return err == ESP_OK ? REMOTE_CMD_OK : REMOTE_CMD_ERROR;
    }
    if (!homelab_ops_recovery_allowed(origin)) {
        strlcpy(reply, remote_error(ESP_ERR_NOT_SUPPORTED, probe), cap);
        return REMOTE_CMD_ERROR;
    }
    if (checks) {
        *title = "ESP32 TCP checks";
        saved_tcp_summary(reply, cap);
        return REMOTE_CMD_OK;
    }
    esp_err_t err = ESP_ERR_NOT_FOUND;
    if (probe) {
        err = saved_tcp_remote_request(argument, origin, destination);
    } else {
        uint8_t mac[6];
        if (wol_parse_mac(argument, mac)) {
            err = homelab_ops_remote_request(mac, recover, origin, destination);
        } else {
            wol_device_t device;
            err = named_wol_device(argument, &device);
            if (err == ESP_OK) err = homelab_ops_remote_request(device.mac, recover, origin, destination);
        }
    }
    if (err == ESP_OK) snprintf(reply, cap, "%s queued.\nTarget: %s\nThe result will follow here.",
                               probe ? "TCP check" : recover ? "Recovery" : "Reachability check", argument);
    else strlcpy(reply, remote_error(err, probe), cap);
    return err == ESP_OK ? REMOTE_CMD_OK : REMOTE_CMD_ERROR;
}

static NTFY_NOINLINE void handle_command(const ntfy_integration_config_t *c, uint32_t destination, const char *message)
{
    if (!remote_command_active(OPS_RECOVERY_NTFY, destination)) return;
    char *reply = heap_caps_malloc(REMOTE_REPLY_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    esp_err_t err = ESP_ERR_NO_MEM;
    if (reply) {
        const char *title = NULL;
        remote_cmd_kind_t kind = remote_command_run(message, c->info_enabled, c->allow_direct_mac,
                                                    OPS_RECOVERY_NTFY, destination, reply, REMOTE_REPLY_MAX, &title);
        err = kind == REMOTE_CMD_ERROR ? ESP_FAIL : ESP_OK;
        if (kind == REMOTE_CMD_INFO) err = send_info(c, destination);
        else if (reply[0] && title && remote_command_active(OPS_RECOVERY_NTFY, destination) &&
                 publish_message(c, title, "mattboxx-response", reply) != ESP_OK) err = ESP_FAIL;
        free(reply);
        if (kind == REMOTE_CMD_NONE) return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (err == ESP_OK) s_status.commands_received++;
    else s_status.command_errors++;
    xSemaphoreGive(s_lock);
}

static void collect_line(command_batch_t *batch)
{
    ntfy_json_parser_t *p = &batch->parser;
    if (batch->count < NTFY_POLL_BATCH && ntfy_json_finish(p) &&
        strcmp(p->event.event, "message") == 0 && event_id_valid(p->event.id))
        batch->events[batch->count++] = p->event;
    ntfy_json_reset(p);
}

static void collect_bytes(command_batch_t *batch, const char *bytes, size_t length)
{
    for (size_t i = 0; i < length && batch->count < NTFY_POLL_BATCH; ++i) {
        unsigned char b = (unsigned char)bytes[i];
        if (b == '\n') collect_line(batch);
        else ntfy_json_feed(&batch->parser, b);
    }
}

static NTFY_NOINLINE esp_err_t read_command_batch(esp_http_client_handle_t client,
                                                command_batch_t *batch, int *status)
{
    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) return err;
    if (esp_http_client_fetch_headers(client) < 0) return ESP_FAIL;
    *status = esp_http_client_get_status_code(client);
    if (*status != 200) return ESP_FAIL;
    int64_t deadline = esp_timer_get_time() + 30000000;
    while (batch->count < NTFY_POLL_BATCH) {
        if (esp_timer_get_time() >= deadline) return ESP_ERR_TIMEOUT;
        int n = esp_http_client_read(client, batch->read_buffer, sizeof batch->read_buffer);
        if (n < 0) return ESP_FAIL;
        if (!n) {
            if (!esp_http_client_is_complete_data_received(client)) return ESP_FAIL;
            /* A final valid JSON object may omit its newline. A truncated or
             * malformed object never advances the cursor or runs a command. */
            collect_line(batch);
            return ESP_OK;
        }
        collect_bytes(batch, batch->read_buffer, (size_t)n);
    }
    /* Deliberately close after a complete bounded prefix. The next poll
     * resumes at its last durable ID; unread commands are not skipped. */
    return ESP_OK;
}

static bool config_equal(const ntfy_integration_config_t *a, const ntfy_integration_config_t *b)
{
    return a->enabled == b->enabled && a->tailscale_alerts == b->tailscale_alerts &&
           a->commands_enabled == b->commands_enabled &&
           a->commands_only_when_tailscale_down == b->commands_only_when_tailscale_down &&
           a->allow_direct_mac == b->allow_direct_mac && a->info_enabled == b->info_enabled &&
           a->info_include_details == b->info_include_details &&
           a->system_events == b->system_events && a->poweron_events == b->poweron_events &&
           a->failure_delay_seconds == b->failure_delay_seconds &&
           a->poll_interval_seconds == b->poll_interval_seconds &&
           strcmp(a->server, b->server) == 0 && strcmp(a->topic, b->topic) == 0 &&
           strcmp(a->token, b->token) == 0;
}

static bool poll_current_locked(const ntfy_integration_config_t *c, uint64_t generation)
{
    return generation == s_config_generation && config_equal(c, &s_config) &&
           c->enabled && c->commands_enabled &&
           (!c->commands_only_when_tailscale_down ||
            !tailscale_enabled || !tailscale_is_connected());
}

static NTFY_NOINLINE bool poll_commands(const ntfy_integration_config_t *c)
{
    if(!homelab_ops_admit())return false;
    char cursor[sizeof s_last_event_id];
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint64_t generation = s_config_generation;
    if (!poll_current_locked(c, generation)) { xSemaphoreGive(s_lock); return false; }
    uint32_t destination = remote_command_ticket(&s_command_gate);
    time_t floor = s_command_floor;
    bool priming = !s_last_event_id[0] && !floor;
    bool legacy = s_priming_legacy;
    strlcpy(cursor, priming ? s_priming_cursor : s_last_event_id, sizeof cursor);
    xSemaphoreGive(s_lock);
    if (!destination) return false;

    /* A reset cursor means command permissions or the endpoint changed.
     * Observe the latest cached ID without dispatching it. */
    time_t checked_at = priming ? time(NULL) : 0;
    char since[48];
    if (cursor[0]) strlcpy(since, cursor, sizeof since);
    else if (priming) strlcpy(since, legacy ? "all" : "latest", sizeof since);
    else snprintf(since, sizeof since, "%lld", (long long)floor);
    char suffix[96];
    snprintf(suffix, sizeof suffix, "/json?poll=1&since=%s", since);
    /* Fixed heap batch, allocation-free JSON projection. Neither total
     * response size nor individual notification text grows the task stack. */
    char url[352];
    command_batch_t *batch = calloc(1, sizeof *batch);
    if (!batch) return false;
    build_url(c, suffix, url, sizeof url);
    esp_http_client_config_t config = {.url=url,.method=HTTP_METHOD_GET,.timeout_ms=12000,
        .crt_bundle_attach=ml_tls_bundle_attach,.disable_auto_redirect=true};
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) { free(batch); return false; }
    esp_err_t err = set_auth(client, c);
    int status = 0;
    if (err == ESP_OK) err = read_command_batch(client, batch, &status);
    esp_http_client_cleanup(client);
    if (status == 400 && priming && !cursor[0] && !legacy) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        bool current = poll_current_locked(c, generation) && destination == remote_command_ticket(&s_command_gate);
        if (current) s_priming_legacy = true;
        xSemaphoreGive(s_lock);
        free(batch);
        return current;
    }
    if (err != ESP_OK || status != 200) {
        ESP_LOGW(TAG, "command poll failed: %s HTTP %d", esp_err_to_name(err), status);
        free(batch);
        return false;
    }
    if (priming) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        bool current = poll_current_locked(c, generation) && destination == remote_command_ticket(&s_command_gate);
        bool armed = false;
        if (current && (batch->count || cursor[0])) {
            const char *last = batch->count ? batch->events[batch->count - 1].id : cursor;
            if (batch->count == NTFY_POLL_BATCH) {
                /* Older servers may replay multiple results. Retain progress
                 * in RAM until reaching the end, with dispatch still off. */
                armed = strcmp(last, cursor) != 0;
                if (armed) strlcpy(s_priming_cursor, last, sizeof s_priming_cursor);
            } else {
                armed = save_state(c, last) == ESP_OK;
                if (armed) strlcpy(s_last_event_id, last, sizeof s_last_event_id);
            }
        } else if (current && !batch->count && checked_at >= 1704067200) {
            /* Keep a stable lower bound until the first durable ID. */
            s_command_floor = checked_at;
            armed = true;
        }
        xSemaphoreGive(s_lock);
        free(batch);
        return armed;
    }
    bool completed = true;
    for (size_t i = 0; i < batch->count; ++i) {
            const ntfy_json_event_t *event = &batch->events[i];
            xSemaphoreTake(s_lock, portMAX_DELAY);
            if (!poll_current_locked(c, generation) || destination != remote_command_ticket(&s_command_gate)) {
                xSemaphoreGive(s_lock); completed = false; break;
            }
            bool duplicate = strcmp(s_last_event_id, event->id) == 0;
            /* Persist BEFORE dispatch; otherwise a flash error followed by a
             * reboot can replay WOL. Serialized with configuration saves so
             * an old poll cannot overwrite a new topic's cursor/settings. */
            esp_err_t saved = duplicate ? ESP_OK : save_state(c, event->id);
            if (saved == ESP_OK && !duplicate)
                strlcpy(s_last_event_id, event->id, sizeof s_last_event_id);
            xSemaphoreGive(s_lock);
            if (saved != ESP_OK) {
                ESP_LOGW(TAG, "Cannot persist command cursor; dispatch deferred");
                completed = false;
                break;
            }
            if (!duplicate && event->has_message && !event->message_too_long &&
                strncmp(event->title, "ESP32 ", 6) != 0)
                handle_command(c, destination, event->message);
    }
    free(batch);
    return completed;
}

static bool uplink_connected(void)
{
    esp_netif_t *sta = uplink_internet_netif();
    esp_netif_ip_info_t ip = {0};
    return sta && esp_netif_is_netif_up(sta) && esp_netif_get_ip_info(sta, &ip) == ESP_OK && ip.ip.addr != 0;
}

static NTFY_NOINLINE esp_err_t send_tailscale_alert(const ntfy_integration_config_t *c)
{
    /* Alerts report connectivity, never export the local log buffer. Private
     * details for an explicitly requested info reply are a separate policy. */
    char title[NOTIFY_TITLE_MAX], message[160];
    notify_text_tailscale_problem(title, message, sizeof message);
    esp_err_t err = publish_message(c, title, "warning,mattboxx-response", message);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (err == ESP_OK)
        s_status.alerts_sent++;
    xSemaphoreGive(s_lock);
    return err;
}

/* Kept out of ntfy_task_main's frame: the OTA state copy is several hundred bytes. */
static NTFY_NOINLINE uint32_t available_update_id(void)
{
    ota_remote_state_t update;
    ota_remote_get_state(&update);
    if (!update.update_available || !update.latest_version[0]) return 0;
    uint32_t hash = 2166136261u;
    for (const char *p = update.latest_version; *p; p++) hash = (hash ^ (uint8_t)*p) * 16777619u;
    return hash | 1u;
}

static NTFY_NOINLINE esp_err_t send_system_event(const ntfy_integration_config_t *c, unsigned event,
                                                uint32_t outage_seconds)
{
    /* Wording shared with Telegram and email (notify_text.c). */
    char message[NOTIFY_MESSAGE_MAX], title[NOTIFY_TITLE_MAX];
    if (event == NTFY_EVENT_BOOT) {
        const esp_app_desc_t *app = esp_app_get_description();
        notify_text_boot(title, message, sizeof message, app ? app->version : "unknown",
                         (int)esp_reset_reason(), c->poweron_events);
        if (esp_reset_reason() == ESP_RST_POWERON && c->poweron_events)
            notify_text_power_interruption(message, sizeof message, power_history_previous_online());
    } else if (event == NTFY_EVENT_RESTORED) {
        notify_text_tailscale_restored(title, message, sizeof message, outage_seconds);
    } else {
        ota_remote_state_t update;
        ota_remote_get_state(&update);
        notify_text_update_available(title, message, sizeof message, update.latest_version);
    }
    return publish_message(c, title, "mattboxx-response", message);
}

static bool operational_destination_equal(const ntfy_integration_config_t *a,
                                          const ntfy_integration_config_t *b)
{
    return a->enabled == b->enabled && !strcmp(a->server, b->server) &&
           !strcmp(a->topic, b->topic) && !strcmp(a->token, b->token);
}

static NTFY_NOINLINE void operational_tick(const ntfy_integration_config_t *c,
                                            uint64_t generation, bool online)
{
    char message[sizeof s_operational[0].message];
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint64_t now = (uint64_t)esp_timer_get_time() / 1000;
    operational_expire(now);
    while (s_operational_count && s_operational[s_operational_head].destination &&
           !remote_command_active(OPS_RECOVERY_NTFY, s_operational[s_operational_head].destination))
        operational_pop(true);
    uint32_t queue_generation = s_operational_generation;
    bool due = online && generation == s_config_generation && s_operational_count &&
               now >= s_operational_retry_ms;
    if (due) memcpy(message, s_operational[s_operational_head].message, sizeof message);
    xSemaphoreGive(s_lock);
    if (!due) return;

    esp_err_t err = publish_message(c, "ESP32 operational result", "mattboxx-response", message);
    now = (uint64_t)esp_timer_get_time() / 1000;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (queue_generation == s_operational_generation) {
        if (err == ESP_OK) operational_pop(false);
        else if (err == ESP_ERR_INVALID_RESPONSE || ++s_operational_attempts >= NTFY_OPERATIONAL_ATTEMPTS)
            operational_pop(true);
        else s_operational_retry_ms = now + (s_operational_attempts == 1 ? 5000 : 15000);
    }
    xSemaphoreGive(s_lock);
}

static void ntfy_task_main(void *arg)
{
    (void)arg;
    uint32_t down_seconds = 0, retry_seconds = 0;
    service_retry_t polling = {0};
    uint64_t polling_generation = 0;
    bool alerted = false;
    bool could_poll_before = false;
    ntfy_events_t events;
    ntfy_events_init(&events);
    uint32_t restored_after = 0;
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        ntfy_integration_config_t c;
        uint64_t generation = snapshot(&c);
        bool boot_enabled = esp_reset_reason() == ESP_RST_POWERON ? c.poweron_events : c.system_events;
        ntfy_events_select(&events, c.enabled, boot_enabled, c.system_events);
        if (!c.enabled || (!boot_enabled && !c.system_events)) ntfy_events_tick(&events, false, false, 0);
        bool online = c.enabled && uplink_connected();
        operational_tick(&c, generation, online);
        if (!online) {
            down_seconds = retry_seconds = 0;
            service_retry_reset(&polling);
            alerted = false;
            could_poll_before = false;
            continue;
        }
        bool ts_down = tailscale_enabled && !tailscale_is_connected();
        bool restored = alerted && !ts_down;
        if (restored) restored_after = down_seconds;
        if (ts_down) down_seconds++; else { down_seconds = 0; alerted = false; }
        if (boot_enabled || c.system_events) {
            ntfy_events_tick(&events, true, c.system_events && restored, c.system_events ? available_update_id() : 0);
            unsigned due = ntfy_events_due(&events);
            if (due) ntfy_events_result(&events, due, send_system_event(&c, due, restored_after) == ESP_OK);
        }
        if (retry_seconds) retry_seconds--;
        if (c.tailscale_alerts && ts_down && down_seconds >= c.failure_delay_seconds
            && !alerted && retry_seconds == 0) {
            alerted = send_tailscale_alert(&c) == ESP_OK;
            if (!alerted) retry_seconds = 60;
        }
        bool can_poll = c.commands_enabled
                     && (!c.commands_only_when_tailscale_down || !tailscale_enabled || ts_down);
        /* Arm immediately after enabling commands (or after the
         * Tailscale-down condition becomes true) instead of waiting one
         * complete poll interval before establishing the server cursor. */
        if (can_poll && (!could_poll_before || generation != polling_generation))
            service_retry_reset(&polling);
        polling_generation = generation;
        could_poll_before = can_poll;
        uint64_t now = (uint64_t)esp_timer_get_time()/1000;
        if (can_poll && service_retry_due(&polling,now)) {
            bool ok = poll_commands(&c);
            now = (uint64_t)esp_timer_get_time()/1000;
            if(ok){service_retry_reset(&polling);polling.next_ms=now+(uint64_t)c.poll_interval_seconds*1000;}
            else {
                service_retry_failed(&polling,now);
                uint64_t configured_min=now+(uint64_t)c.poll_interval_seconds*1000;
                if(polling.next_ms<configured_min)polling.next_ms=configured_min;
            }
        } else if (!can_poll) service_retry_reset(&polling);
    }
}

void ntfy_integration_init(void)
{
    if (s_task) return;
    /* Retry-safe: the module supervisor may call this again after a failed start. */
    if (!s_lock) s_lock = xSemaphoreCreateMutex();
    if (!s_lock) return;
    load_state(&s_config);
    uint8_t system_events = 0;
    if (nvs_param_get_u8("ntfy_sysev", &system_events) == ESP_OK) {
        bool other, poweron;
        ntfy_events_decode(system_events, &other, &poweron);
        s_config.system_events = other; s_config.poweron_events = poweron;
    }
    remote_command_gate_reset(&s_command_gate, s_config.enabled && s_config.commands_enabled);
    if (xTaskCreate(ntfy_task_main, "ntfy", NTFY_TASK_STACK_BYTES, NULL, 3, &s_task) != pdPASS) {
        remote_command_gate_reset(&s_command_gate, false);
        s_task = NULL;
        ESP_LOGE(TAG, "Cannot allocate ntfy worker stack");
    }
}

void ntfy_integration_get_config(ntfy_integration_config_t *out)
{
    if (!out) return;
    if (!s_lock) { defaults(out); return; }
    snapshot(out);
}

void ntfy_integration_get_status(ntfy_integration_status_t *out)
{
    if (!out) return;
    if (!s_lock) { memset(out, 0, sizeof *out); return; }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    memcpy(out, &s_status, sizeof *out);
    out->operational_pending = s_operational_count;
    xSemaphoreGive(s_lock);
    out->task_running = s_task != NULL;
    /* ESP-IDF reports the high-water mark in bytes, not FreeRTOS words. */
    out->stack_min_free_bytes = s_task ? uxTaskGetStackHighWaterMark(s_task) : 0;
}

esp_err_t ntfy_integration_set_config_recovery(const ntfy_integration_config_t *c,int recovery)
{
    if (!config_valid(c)) return ESP_ERR_INVALID_ARG;
    if (!s_lock || !s_task) return ESP_ERR_INVALID_STATE;
    esp_err_t e=nvs_param_txn_begin();
    if(e!=ESP_OK)return e;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool command_change = !operational_destination_equal(&s_config, c) ||
        s_config.commands_enabled != c->commands_enabled ||
        s_config.commands_only_when_tailscale_down != c->commands_only_when_tailscale_down ||
        s_config.allow_direct_mac != c->allow_direct_mac || s_config.info_enabled != c->info_enabled ||
        s_config.info_include_details != c->info_include_details ||
        (recovery >= 0 && ((recovery != 0) != homelab_ops_recovery_allowed(OPS_RECOVERY_NTFY)));
    /* Separate key keeps the main record compatible on rollback. */
    /* 0=neither, 1=both (legacy system-events), 2=power only, 3=other only.
     * Old firmware still accepts its core record; 2/3 require reselecting the
     * optional event choice after a rollback. No endpoint or replay changes. */
    uint8_t flags = ntfy_events_options(c->system_events, c->poweron_events);
    uint8_t old_flags = ntfy_events_options(s_config.system_events, s_config.poweron_events);
    bool events_changed = flags != old_flags;
    uint8_t staged=0;
    if(events_changed)e=nvs_param_set_u8("ntfy_sysev",flags);
    if(e==ESP_OK)e=save_state(c,command_change ? "" : s_last_event_id);
    if(e==ESP_OK)e=homelab_ops_stage_recovery(OPS_RECOVERY_NTFY,recovery,&staged);
    esp_err_t end=nvs_param_txn_end(e==ESP_OK);
    if(e==ESP_OK)e=end;
    if (e == ESP_OK) {
        if (command_change) remote_command_gate_reset(&s_command_gate, false);
        if (!operational_destination_equal(&s_config, c)) {
            if (++s_operational_generation == 0) ++s_operational_generation;
            while (s_operational_count) operational_pop(true);
        }
        memcpy(&s_config, c, sizeof *c);
        homelab_ops_publish_recovery(staged);
        s_config_generation++;
        if (command_change) {
            s_last_event_id[0] = '\0';
            s_command_floor = 0;
            s_priming_cursor[0] = '\0';
            s_priming_legacy = false;
            remote_command_gate_reset(&s_command_gate, c->enabled && c->commands_enabled);
        }
    }
    xSemaphoreGive(s_lock);
    return e;
}

esp_err_t ntfy_integration_set_config(const ntfy_integration_config_t *c)
{
    return ntfy_integration_set_config_recovery(c,-1);
}

esp_err_t ntfy_integration_send_test(void)
{
    if (!s_lock || !s_task) return ESP_ERR_INVALID_STATE;
    ntfy_integration_config_t c;
    snapshot(&c);
    if (!c.enabled) return ESP_ERR_INVALID_STATE;
    return publish_message(&c, "ESP32 router test", "white_check_mark,mattboxx-response",
                           "ntfy integration is working.");
}
