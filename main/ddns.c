/* Dynamic DNS; see ddns.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "ddns.h"
#include <stdio.h>
#include <string.h>

/* --- ddns core (begin) --- */
static bool fail(char *why, size_t cap, const char *text)
{
    if (why && cap) snprintf(why, cap, "%s", text);
    return false;
}

static bool lower_alnum(char c) {return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');}
static bool alnum(char c) {return lower_alnum(c) || (c >= 'A' && c <= 'Z');}
static bool hexdigit(char c) {return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');}

static bool host_valid(const char *h)
{
    size_t n = strlen(h), label = 0;
    if (!n || n > 127 || h[0] == '.' || h[n - 1] == '.' || !strchr(h, '.')) return false;
    for (size_t i = 0; i < n; i++) {
        char c = h[i];
        if (c == '.') {if (!label || h[i - 1] == '-') return false; label = 0; continue;}
        if (!alnum(c) && c != '-' && !(c == '*' && i == 0 && h[1] == '.')) return false;
        if (c == '-' && !label) return false;
        if (++label > 63) return false;
    }
    return h[n - 1] != '-';
}

bool ddns_config_valid(const ddns_config_t *c, char *why, size_t cap)
{
    if (!c) return fail(why, cap, "missing settings");
    if (c->provider == DDNS_OFF) return true;
    if (c->provider == DDNS_DUCKDNS) {
        /* "home" or "home,cabin"; the duckdns.org suffix is added by DuckDNS. */
        size_t n = strlen(c->name), label = 0, count = 0;
        if (!n) return fail(why, cap, "enter the DuckDNS sub-domain, e.g. myhome");
        for (size_t i = 0; i <= n; i++) {
            char ch = c->name[i];
            if (ch == ',' || !ch) {if (!label || c->name[i - 1] == '-' || ++count > 5) return fail(why, cap, "sub-domains are letters, digits and -, separated by commas (at most 5)"); label = 0; continue;}
            if (!lower_alnum(ch) && !(ch == '-' && label)) return fail(why, cap, "sub-domains are lower-case letters, digits and -, without .duckdns.org");
            if (++label > 63) return fail(why, cap, "sub-domain too long");
        }
        size_t t = strlen(c->token);
        bool ok = t == 36;
        for (size_t i = 0; ok && i < t; i++) ok = (i == 8 || i == 13 || i == 18 || i == 23) ? c->token[i] == '-' : hexdigit(c->token[i]);
        return ok || fail(why, cap, "the DuckDNS token looks like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
    }
    if (c->provider == DDNS_CLOUDFLARE) {
        if (!host_valid(c->name)) return fail(why, cap, "enter the full record name, e.g. home.example.com");
        size_t z = strlen(c->zone);
        bool ok = z == 32;
        for (size_t i = 0; ok && i < z; i++) ok = hexdigit(c->zone[i]);
        if (!ok) return fail(why, cap, "the zone id is 32 hexadecimal characters (Cloudflare dashboard, Overview)");
        size_t t = strlen(c->token);
        ok = t >= 40 && t <= 100;
        for (size_t i = 0; ok && i < t; i++) ok = alnum(c->token[i]) || c->token[i] == '_' || c->token[i] == '-';
        return ok || fail(why, cap, "enter a Cloudflare API token with Zone.DNS edit permission");
    }
    if (c->provider == DDNS_CUSTOM) {
        size_t n = strlen(c->url);
        if (n < 12 || n >= sizeof c->url || strncmp(c->url, "https://", 8)) return fail(why, cap, "the update URL must start with https://");
        const char *host = c->url + 8, *end = host;
        while (*end && *end != '/' && *end != '?' && *end != ':') end++;
        char h[128];
        size_t hl = (size_t)(end - host);
        if (!hl || hl >= sizeof h) return fail(why, cap, "the update URL needs a host name");
        memcpy(h, host, hl); h[hl] = 0;
        if (!host_valid(h) || strchr(h, '*')) return fail(why, cap, "the update URL needs a valid host name");
        for (size_t i = 0; i < n; i++)
            if ((unsigned char)c->url[i] <= 0x20 || (unsigned char)c->url[i] >= 0x7F || c->url[i] == '"' || c->url[i] == '\\' || c->url[i] == '#')
                return fail(why, cap, "the update URL contains spaces or characters that are not allowed");
        const char *at = strchr(c->url, '@');
        if (at && at < end) return fail(why, cap, "put credentials in the query, not before the host name");
        return true;
    }
    return fail(why, cap, "unknown provider");
}

bool ddns_due(const ddns_state_t *st, uint8_t provider, uint32_t ip, uint32_t now)
{
    if (provider == DDNS_OFF || now < st->next_try_s) return false;
    if (!st->ever || st->backoff_s) return true;
    if (ip && ip != st->last_ip) return true;                      /* the address changed */
    /* Daily refresh; every 30 minutes while the address cannot be seen. */
    return now - st->last_ok_s >= (ip ? DDNS_REFRESH_S : DDNS_BLIND_S);
}

void ddns_result(ddns_state_t *st, bool ok, uint32_t ip, uint32_t now)
{
    if (ok) {
        st->ever = true; st->last_ok_s = now; st->backoff_s = 0; st->next_try_s = now + 60;
        if (ip) st->last_ip = ip;
        return;
    }
    st->backoff_s = !st->backoff_s ? 60 : st->backoff_s * 2 > DDNS_BACKOFF_MAX_S ? DDNS_BACKOFF_MAX_S : st->backoff_s * 2;
    st->next_try_s = now + st->backoff_s;
}

static void ip_text(uint32_t ip, char out[16])
{
    const uint8_t *b = (const uint8_t *)&ip;
    if (ip) snprintf(out, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]); else out[0] = 0;
}

bool ddns_build_url(const ddns_config_t *c, uint32_t ip, char *out, size_t cap)
{
    char addr[16];
    ip_text(ip, addr);
    int n = -1;
    if (c->provider == DDNS_DUCKDNS) {
        n = snprintf(out, cap, "https://www.duckdns.org/update?domains=%s&token=%s&ip=%s", c->name, c->token, addr);
    } else if (c->provider == DDNS_CUSTOM) {
        const char *mark = strstr(c->url, "{ip}");
        if (!mark) n = snprintf(out, cap, "%s", c->url);
        else if (!ip) return false;                                /* the URL needs the address */
        else n = snprintf(out, cap, "%.*s%s%s", (int)(mark - c->url), c->url, addr, mark + 4);
        if (n > 0 && strstr(out, "{ip}")) return false;            /* one placeholder only */
    }
    return n > 0 && (size_t)n < cap;
}
bool ddns_parse_trace(const char *text, uint32_t *ip)
{
    for (const char *p = text; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
        if (strncmp(p, "ip=", 3)) continue;
        unsigned part[4];
        int used = 0;
        if (sscanf(p + 3, "%3u.%3u.%3u.%3u%n", &part[0], &part[1], &part[2], &part[3], &used) != 4) return false;
        char end = p[3 + used];
        if ((end && end != '\n' && end != '\r') || part[0] > 255 || part[1] > 255 || part[2] > 255 || part[3] > 255) return false;
        uint8_t b[4] = {(uint8_t)part[0], (uint8_t)part[1], (uint8_t)part[2], (uint8_t)part[3]};
        memcpy(ip, b, 4);
        return *ip != 0;
    }
    return false;
}
/* --- ddns core (end) --- */

#ifdef ESP_PLATFORM
#include "history.h"
#include "json_guard.h"
#include "tailscale_config.h"
#include "task_reaper.h"
#include "web_ui.h"
#include "microlink.h"
#include "esp_attr.h"
#include "esp_crt_bundle.h"
#include "ml_tls_distrust.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_rom_crc.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "nvs.h"
#include <stdatomic.h>
#include <stdlib.h>

static const char *TAG = "ddns";
#define CFG_MAGIC 0x44444e31u   /* DDN1 */
typedef struct {uint32_t magic, version; ddns_config_t config; uint32_t checksum;} cfg_record_t;

EXT_RAM_BSS_ATTR static ddns_config_t s_cfg;   /* PSRAM: no internal RAM while off */
static ddns_state_t s_state;
static SemaphoreHandle_t s_lock;
static StaticSemaphore_t s_lock_storage;
static esp_timer_handle_t s_timer;
static bool s_running, s_force;
static uint32_t s_generation, s_job_generation, s_admission_retry_at;
static atomic_bool s_scheduler_retry_pending;
static uint32_t s_scheduler_retry_at;
EXT_RAM_BSS_ATTR static char s_last[96];
static uint32_t s_seen_ip;

static uint32_t now_s(void) {return (uint32_t)(esp_timer_get_time() / 1000000);}
static uint32_t checksum(const cfg_record_t *r) {return esp_rom_crc32_le(0, (const uint8_t *)r, offsetof(cfg_record_t, checksum));}

static void load(ddns_config_t *c)
{
    memset(c, 0, sizeof *c);
    nvs_handle_t h;
    if (nvs_open("tsr", NVS_READONLY, &h) != ESP_OK) return;
    cfg_record_t *r = calloc(1, sizeof *r);
    size_t n = sizeof *r;
    /* Fail closed: a damaged record means off. */
    if (r && nvs_get_blob(h, "ddns_cfg", r, &n) == ESP_OK && n == sizeof *r && r->magic == CFG_MAGIC && r->version == 1 &&
        r->checksum == checksum(r) && ddns_config_valid(&r->config, NULL, 0)) *c = r->config;
    if (r) {memset(r, 0, sizeof *r); free(r);}
    nvs_close(h);
}

static esp_err_t save(const ddns_config_t *c)
{
    cfg_record_t *r = calloc(1, sizeof *r);
    if (!r) return ESP_ERR_NO_MEM;
    r->magic = CFG_MAGIC; r->version = 1; r->config = *c; r->checksum = checksum(r);
    nvs_handle_t h;
    esp_err_t err = nvs_open("tsr", NVS_READWRITE, &h);
    if (!err) {err = nvs_set_blob(h, "ddns_cfg", r, sizeof *r); if (!err) err = nvs_commit(h); nvs_close(h);}
    memset(r, 0, sizeof *r);
    free(r);
    return err;
}

static uint32_t public_ip(void)
{
    microlink_t *ml = tailscale_get_microlink();
    microlink_diag_t d;
    return ml && microlink_get_diag(ml, &d) == ESP_OK && d.wan_public_ip ? htonl(d.wan_public_ip) : 0;
}

/* One HTTPS request; `body` NULL = GET. Reads up to cap-1 bytes of the answer. */
static int request(const char *url, esp_http_client_method_t method, const char *token, const char *body,
                   char *answer, size_t cap, bool complete_json)
{
    esp_http_client_config_t hc = {.url = url, .method = method, .timeout_ms = 15000,
                                   .crt_bundle_attach = ml_tls_bundle_attach, .disable_auto_redirect = true};
    esp_http_client_handle_t client = esp_http_client_init(&hc);
    if (!client) return -1;
    if (token) {
        char auth[140];
        snprintf(auth, sizeof auth, "Bearer %s", token);
        esp_http_client_set_header(client, "Authorization", auth);
        memset(auth, 0, sizeof auth);
    }
    if (body) esp_http_client_set_header(client, "Content-Type", "application/json");
    int status = -1, len = body ? (int)strlen(body) : 0;
    answer[0] = 0;
    if (esp_http_client_open(client, len) == ESP_OK && (!len || esp_http_client_write(client, body, len) == len) &&
        esp_http_client_fetch_headers(client) >= 0) {
        status = esp_http_client_get_status_code(client);
        int got = 0, n;
        while (got < (int)cap - 1 && (n = esp_http_client_read(client, answer + got, (int)cap - 1 - got)) > 0) got += n;
        answer[got > 0 ? got : 0] = 0;
        if (complete_json && status == 200 &&
            (!esp_http_client_is_complete_data_received(client) || memchr(answer, 0, got)))
            status = -1;
    }
    esp_http_client_cleanup(client);
    return status;
}

static bool request_current(uint32_t generation)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool current = generation == s_generation && s_cfg.provider != DDNS_OFF;
    xSemaphoreGive(s_lock);
    return current;
}

static bool cloudflare_success(const cJSON *root)
{
    return cJSON_IsObject(root) && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "success"));
}

static bool cloudflare(const ddns_config_t *c, uint32_t generation, uint32_t *ip_io, char *why, size_t cap)
{
    char url[256], addr[16], *answer = heap_caps_malloc(4096, MALLOC_CAP_SPIRAM);
    if (!answer) return fail(why, cap, "out of memory");
    if (!*ip_io) {
        /* Tailscale has not seen the public address: ask Cloudflare itself. */
        int st = request("https://www.cloudflare.com/cdn-cgi/trace", HTTP_METHOD_GET, NULL, NULL, answer, 1024, false);
        if (st != 200 || !ddns_parse_trace(answer, ip_io)) {free(answer); return fail(why, cap, "public address unknown (no Tailscale address, Cloudflare trace failed)");}
    }
    uint32_t ip = *ip_io;
    ip_text(ip, addr);
    snprintf(url, sizeof url, "https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=A&name=%s", c->zone, c->name);
    int status = request(url, HTTP_METHOD_GET, c->token, NULL, answer, 4096, true);
    bool ok = false;
    cJSON *root = status == 200 ? json_guard_parse(answer) : NULL;
    const cJSON *result = cJSON_GetObjectItemCaseSensitive(root, "result");
    const cJSON *first = cJSON_IsArray(result) ? cJSON_GetArrayItem(result, 0) : NULL;
    const cJSON *id = cJSON_GetObjectItemCaseSensitive(first, "id"), *content = cJSON_GetObjectItemCaseSensitive(first, "content");
    if (status < 0) fail(why, cap, "cannot reach api.cloudflare.com");
    else if (status != 200) snprintf(why, cap, "Cloudflare answered %d (check the token permission and zone id)", status);
    else if (!cloudflare_success(root)) fail(why, cap, "Cloudflare did not return a successful record lookup");
    else if (!cJSON_IsString(id) || strlen(id->valuestring) != 32 ||
             strspn(id->valuestring, "0123456789abcdef") != 32)
        fail(why, cap, "no A record with this name: create it once in Cloudflare");
    else if (cJSON_IsString(content) && !strcmp(content->valuestring, addr)) ok = true;     /* already right */
    else if (request_current(generation)) {
        snprintf(url, sizeof url, "https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", c->zone, id->valuestring);
        cJSON_Delete(root);
        root = NULL;
        char body[48];
        snprintf(body, sizeof body, "{\"content\":\"%s\"}", addr);
        status = request(url, HTTP_METHOD_PATCH, c->token, body, answer, 4096, true);
        cJSON *reply = status == 200 ? json_guard_parse(answer) : NULL;
        ok = cloudflare_success(reply);
        cJSON_Delete(reply);
        if (!ok) snprintf(why, cap, "Cloudflare refused the change (%d)", status);
    }
    cJSON_Delete(root);
    free(answer);
    return ok;
}

static bool simple_get(const ddns_config_t *c, uint32_t ip, char *why, size_t cap)
{
    char url[320], answer[256];
    if (!ddns_build_url(c, ip, url, sizeof url)) return fail(why, cap, ip ? "the update URL is too long" : "waiting for the public address (Tailscale)");
    int status = request(url, HTTP_METHOD_GET, NULL, NULL, answer, sizeof answer, false);
    memset(url, 0, sizeof url);                              /* carries the token */
    if (status < 0) return fail(why, cap, c->provider == DDNS_DUCKDNS ? "cannot reach www.duckdns.org" : "cannot reach the update server");
    if (c->provider == DDNS_DUCKDNS) {
        if (status == 200 && !strncmp(answer, "OK", 2)) return true;
        return fail(why, cap, "DuckDNS answered KO: check the sub-domain and the token");
    }
    if (status >= 200 && status < 300) return true;
    snprintf(why, cap, "the update server answered %d", status);
    return false;
}

static void worker(void *arg)
{
    (void)arg;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t generation = s_job_generation;
    if (generation != s_generation || s_cfg.provider == DDNS_OFF) {
        s_running = false;
        xSemaphoreGive(s_lock);
        task_reaper_self_delete();
        return;
    }
    ddns_config_t *c = heap_caps_malloc(sizeof *c, MALLOC_CAP_SPIRAM);
    if (c) *c = s_cfg;
    xSemaphoreGive(s_lock);
    uint32_t ip = public_ip();
    char why[96] = "";
    if (!c) snprintf(why, sizeof why, "out of memory");
    bool ok = c && request_current(generation) &&
              (c->provider == DDNS_CLOUDFLARE ? cloudflare(c, generation, &ip, why, sizeof why) :
                                              simple_get(c, ip, why, sizeof why));
    if (c) {memset(c, 0, sizeof *c); free(c);}
    char addr[16];
    ip_text(ip, addr);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (generation == s_generation && s_cfg.provider != DDNS_OFF) {
        bool was_failing = s_state.backoff_s != 0;
        ddns_result(&s_state, ok, ip, now_s());
        if (ok) {
            snprintf(s_last, sizeof s_last, "Updated%s%s", addr[0] ? " to " : "", addr);
            history_event(HIST_EV_UPLINK, HIST_INFO, "Dynamic DNS updated%s%s", addr[0] ? " to " : "", addr);
        } else {
            snprintf(s_last, sizeof s_last, "Not updated: %.82s", why);
            if (!was_failing) history_event(HIST_EV_UPLINK, HIST_WARN, "Dynamic DNS not updated: %s", why);
        }
    }
    s_running = false;
    xSemaphoreGive(s_lock);
    task_reaper_self_delete();
}

static void tick(void *arg)
{
    (void)arg;
    uint32_t ip = public_ip();
    if (xSemaphoreTake(s_lock, 0) != pdTRUE) return;
    s_seen_ip = ip;
    uint32_t now = now_s();
    bool due = s_cfg.provider != DDNS_OFF && !s_running && now >= s_admission_retry_at &&
               (s_force || ddns_due(&s_state, s_cfg.provider, ip, now));
    if (due) {
        /* A short-lived worker; nothing stays allocated between updates. */
        s_job_generation = s_generation;
        s_running = xTaskCreateWithCaps(worker, "ddns", 8192, NULL, 2, NULL, MALLOC_CAP_SPIRAM) == pdPASS;
        if (s_running) {
            s_force = false;
            s_admission_retry_at = 0;
        } else {
            s_admission_retry_at = now + 60;
            snprintf(s_last, sizeof s_last, "Update queued: worker unavailable; retrying");
        }
    }
    xSemaphoreGive(s_lock);
}

static void scheduler_update_locked(void)
{
    if (s_cfg.provider != DDNS_OFF && !s_timer) {
        const esp_timer_create_args_t args = {.callback = tick, .name = "ddns", .skip_unhandled_events = true};
        esp_timer_handle_t timer = NULL;
        if (esp_timer_create(&args, &timer) == ESP_OK) {
            if (esp_timer_start_periodic(timer, 60ULL * 1000000) == ESP_OK) s_timer = timer;
            else esp_timer_delete(timer);
        }
        if (!s_timer) s_scheduler_retry_at = now_s() + 60;
    } else if (s_cfg.provider == DDNS_OFF && s_timer) {
        esp_timer_stop(s_timer);
        esp_timer_delete(s_timer);
        s_timer = NULL;
    }
    atomic_store(&s_scheduler_retry_pending, s_cfg.provider != DDNS_OFF && !s_timer);
}

void ddns_retry_scheduler(void)
{
    if (!atomic_load(&s_scheduler_retry_pending) || xSemaphoreTake(s_lock, 0) != pdTRUE) return;
    if (s_cfg.provider != DDNS_OFF && !s_timer && now_s() >= s_scheduler_retry_at) {
        scheduler_update_locked();
    }
    xSemaphoreGive(s_lock);
}

static bool apply_config_locked(const ddns_config_t *next, bool force)
{
    bool changed = memcmp(&s_cfg, next, sizeof *next) != 0;
    s_cfg = *next;
    if (changed) {
        s_generation++;
        s_admission_retry_at = 0;
        memset(&s_state, 0, sizeof s_state);
        snprintf(s_last, sizeof s_last, "Not updated yet");
    }
    s_force = s_cfg.provider != DDNS_OFF && (s_force || force || changed);
    scheduler_update_locked();
    return s_force;
}

void ddns_init(void)
{
    if (!s_lock) s_lock = xSemaphoreCreateMutexStatic(&s_lock_storage);
    snprintf(s_last, sizeof s_last, "Not updated yet");
    load(&s_cfg);
    if (s_cfg.provider != DDNS_OFF) {xSemaphoreTake(s_lock, portMAX_DELAY); scheduler_update_locked(); xSemaphoreGive(s_lock);}
}

uint8_t ddns_provider(void)
{
    if (!s_lock) return DDNS_OFF;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint8_t provider = s_cfg.provider;
    xSemaphoreGive(s_lock);
    return provider;
}

bool ddns_last_update_ok(void)
{
    if (!s_lock) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool ok = s_cfg.provider != DDNS_OFF && s_timer && s_state.ever && !s_state.backoff_s;
    xSemaphoreGive(s_lock);
    return ok;
}

static const char *provider_name(uint8_t p) {return p == DDNS_DUCKDNS ? "duckdns" : p == DDNS_CLOUDFLARE ? "cloudflare" : p == DDNS_CUSTOM ? "custom" : "off";}

static esp_err_t get_ddns(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    cJSON *root = cJSON_CreateObject();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    cJSON_AddStringToObject(root, "provider", provider_name(s_cfg.provider));
    cJSON_AddStringToObject(root, "name", s_cfg.name);
    cJSON_AddStringToObject(root, "zone", s_cfg.zone);
    cJSON_AddBoolToObject(root, "has_token", s_cfg.token[0] != 0);
    cJSON_AddBoolToObject(root, "has_url", s_cfg.url[0] != 0);   /* the URL may carry a secret: never returned */
    cJSON_AddStringToObject(root, "status", s_cfg.provider != DDNS_OFF && !s_timer ?
                            "Automatic checks waiting for resources" : s_last);
    char addr[16];
    ip_text(s_seen_ip ? s_seen_ip : public_ip(), addr);
    cJSON_AddStringToObject(root, "public_ip", addr);
    ip_text(s_state.last_ip, addr);
    cJSON_AddStringToObject(root, "updated_ip", addr);
    cJSON_AddNumberToObject(root, "updated_ago_s", s_state.ever ? now_s() - s_state.last_ok_s : -1);
    cJSON_AddBoolToObject(root, "running", s_running);
    cJSON_AddBoolToObject(root, "pending", s_force || s_admission_retry_at != 0);
    cJSON_AddBoolToObject(root, "scheduler_ready", s_timer != NULL);
    xSemaphoreGive(s_lock);
    char *text = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!text) {httpd_resp_send_500(req); return ESP_FAIL;}
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, text);
    cJSON_free(text);
    return err;
}

static esp_err_t post_ddns(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    char *body = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
    ddns_config_t *next = heap_caps_malloc(sizeof *next, MALLOC_CAP_SPIRAM);
    if (!body || !next) {free(body); free(next); httpd_resp_send_500(req); return ESP_FAIL;}
    int total = req->content_len, received = 0;
    bool ok = total > 0 && total < 1024;
    while (ok && received < total) {int n = httpd_req_recv(req, body + received, total - received); if (n <= 0) ok = false; else received += n;}
    body[ok ? received : 0] = 0;
    cJSON *root = ok ? json_guard_parse(body) : NULL;
    memset(body, 0, 1024);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *next = s_cfg;
    xSemaphoreGive(s_lock);
    char why[120] = "invalid request";
    const cJSON *provider = cJSON_GetObjectItemCaseSensitive(root, "provider"), *update = cJSON_GetObjectItemCaseSensitive(root, "update_now");
    static const char *const names[] = {"off", "duckdns", "cloudflare", "custom"};
    int chosen = -1;
    for (int i = 0; cJSON_IsString(provider) && i < 4; i++) if (!strcmp(provider->valuestring, names[i])) chosen = i;
    ok = cJSON_IsObject(root) && chosen >= 0 && (!update || cJSON_IsBool(update));
    const char *keys[] = {"name", "zone", "token", "url"};
    char *fields[] = {next->name, next->zone, next->token, next->url};
    size_t caps[] = {sizeof next->name, sizeof next->zone, sizeof next->token, sizeof next->url};
    for (int i = 0; ok && i < 4; i++) {
        cJSON *v = cJSON_GetObjectItemCaseSensitive(root, keys[i]);
        if (!v) continue;
        if (!cJSON_IsString(v) || strlen(v->valuestring) >= caps[i]) {ok = false; break;}
        /* Secrets (token, URL) are write-only: empty keeps the saved value. */
        if ((i >= 2 && !v->valuestring[0])) continue;
        strcpy(fields[i], v->valuestring);
    }
    if (ok && chosen != next->provider) {
        /* Another provider: never reuse the old provider's secret. */
        if (!cJSON_GetObjectItemCaseSensitive(root, "token") || !cJSON_GetObjectItemCaseSensitive(root, "token")->valuestring[0]) next->token[0] = 0;
        if (chosen != DDNS_CUSTOM) next->url[0] = 0;
    }
    if (ok) next->provider = (uint8_t)chosen;
    if (ok && next->provider == DDNS_OFF) memset(next, 0, sizeof *next);   /* off: forget the secrets */
    bool force = cJSON_IsTrue(update);
    for (int i = 2; root && i < 4; i++) {cJSON *v = cJSON_GetObjectItemCaseSensitive(root, keys[i]); if (cJSON_IsString(v)) memset(v->valuestring, 0, strlen(v->valuestring));}
    cJSON_Delete(root);
    if (ok && !ddns_config_valid(next, why, sizeof why)) ok = false;
    esp_err_t err = ESP_OK;
    if (ok) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        if (memcmp(&s_cfg, next, sizeof *next) != 0) err = save(next);
        bool immediate = !err && apply_config_locked(next, force);
        xSemaphoreGive(s_lock);
        if (immediate) tick(NULL);
    }
    memset(next, 0, sizeof *next); free(next); free(body);
    httpd_resp_set_type(req, "application/json");
    if (!ok || err) {
        httpd_resp_set_status(req, ok ? "500 Internal Server Error" : "400 Bad Request");
        cJSON *r = cJSON_CreateObject();
        cJSON_AddBoolToObject(r, "ok", false);
        cJSON_AddStringToObject(r, "error", ok ? esp_err_to_name(err) : why);
        char *text = cJSON_PrintUnformatted(r);
        cJSON_Delete(r);
        esp_err_t e = httpd_resp_sendstr(req, text ? text : "{\"ok\":false}");
        cJSON_free(text);
        return e;
    }
    ESP_LOGI(TAG, "provider %s", provider_name(chosen));
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool scheduler_ready = s_timer != NULL;
    xSemaphoreGive(s_lock);
    return httpd_resp_sendstr(req, scheduler_ready ? "{\"ok\":true,\"scheduler_ready\":true}" :
                                                   "{\"ok\":true,\"scheduler_ready\":false}");
}

esp_err_t ddns_register_http(httpd_handle_t server)
{
    const httpd_uri_t routes[] = {
        {.uri = "/api/ddns", .method = HTTP_GET, .handler = get_ddns},
        {.uri = "/api/ddns", .method = HTTP_POST, .handler = post_ddns}};
    for (unsigned i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        esp_err_t err = httpd_register_uri_handler(server, &routes[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}
#endif
