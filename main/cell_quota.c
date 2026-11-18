/* Monthly mobile data counter; see cell_quota.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "cell_quota.h"
#include <stdio.h>
#include <string.h>

/* --- cell_quota core (begin) --- */
static bool cq_fail(char *why, size_t n, const char *text)
{
    if (why && n) snprintf(why, n, "%s", text);
    return false;
}

bool cell_quota_config_valid(const cell_quota_config_t *c, char *why, size_t n)
{
    if (!c) return cq_fail(why, n, "missing settings");
    if (c->limit_mb > CELL_QUOTA_MAX_MB) return cq_fail(why, n, "monthly limit must be 0 (off) to 1000000 MB");
    if (c->warn_pct > 99) return cq_fail(why, n, "early warning must be 0 (none) to 99 %");
    if (c->reset_day < 1 || c->reset_day > 28) return cq_fail(why, n, "the period must start on day 1 to 28");
    if (c->pause > 1) return cq_fail(why, n, "invalid switch value");
    return true;
}

uint32_t cell_quota_period(int year, int month, int day, uint8_t reset_day)
{
    if (year < 2024 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 || reset_day < 1 || reset_day > 28) return 0;
    uint32_t months = (uint32_t)year * 12u + (uint32_t)(month - 1);
    if (day < reset_day) months--;                       /* still in the period that began last month */
    return months + 1u;
}

void cell_quota_period_start(uint32_t period, uint8_t reset_day, int *year, int *month, int *day)
{
    uint32_t months = period ? period - 1u : 0;
    *year = (int)(months / 12u);
    *month = (int)(months % 12u) + 1;
    *day = reset_day;
}

static uint64_t cq_limit(const cell_quota_config_t *c) {return (uint64_t)c->limit_mb * 1024u * 1024u;}

static bool cq_warn_reached(const cell_quota_config_t *c, uint64_t used)
{
    return c->limit_mb && c->warn_pct && used * 100u >= cq_limit(c) * c->warn_pct;
}

bool cell_quota_limit_reached(const cell_quota_config_t *c, const cell_quota_state_t *s)
{
    return c->limit_mb && s->used >= cq_limit(c);
}

int cell_quota_add(const cell_quota_config_t *c, cell_quota_state_t *s, uint64_t delta, uint32_t period, uint64_t *previous)
{
    int events = 0;
    if (previous) *previous = 0;
    if (period && period != s->period) {
        if (s->period && period > s->period) {      /* a new month: start again */
            if (previous) *previous = s->used;
            s->used = 0;
            s->alerted = 0;
            events |= CELL_QUOTA_EV_NEW_PERIOD;
        }
        /* First clock reading, or a clock set back: same use, the right period. */
        s->period = period;
    }
    s->used = s->used + delta < s->used ? UINT64_MAX : s->used + delta;
    if (!(s->alerted & CELL_QUOTA_WARNED) && cq_warn_reached(c, s->used) && !cell_quota_limit_reached(c, s)) {
        s->alerted |= CELL_QUOTA_WARNED;
        events |= CELL_QUOTA_EV_WARN;
    }
    if (!(s->alerted & CELL_QUOTA_LIMITED) && cell_quota_limit_reached(c, s)) {
        s->alerted |= CELL_QUOTA_LIMITED | CELL_QUOTA_WARNED;   /* one message, not two */
        events |= CELL_QUOTA_EV_LIMIT;
    }
    return events;
}

void cell_quota_rearm(const cell_quota_config_t *c, cell_quota_state_t *s)
{
    if (!cell_quota_limit_reached(c, s)) s->alerted &= (uint8_t)~CELL_QUOTA_LIMITED;
    if (!cq_warn_reached(c, s->used) && !cell_quota_limit_reached(c, s)) s->alerted &= (uint8_t)~CELL_QUOTA_WARNED;
}

bool cell_quota_save_due(uint64_t used, uint64_t saved_used, uint32_t now_s, uint32_t saved_at_s, int events)
{
    if (events) return true;
    return used >= saved_used + CELL_QUOTA_SAVE_BYTES && now_s - saved_at_s >= CELL_QUOTA_SAVE_S;
}
/* --- cell_quota core (end) --- */

#if !defined(CELL_QUOTA_HOST_TEST)
#include "history.h"
#include "nvs.h"
#include "nvs_params.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include <time.h>

#define TAG "cell_quota"
#define CQ_MAGIC 0x43515431u   /* CQT1 */
typedef struct {uint32_t magic, version; cell_quota_config_t config; uint32_t checksum;} cq_config_record_t;
typedef struct {uint32_t magic, version; cell_quota_state_t state; uint32_t checksum;} cq_state_record_t;

static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
/* Plain data in PSRAM: no internal RAM, whether used or not. */
EXT_RAM_BSS_ATTR static cell_quota_config_t s_cfg;
EXT_RAM_BSS_ATTR static cell_quota_state_t s_state;
EXT_RAM_BSS_ATTR static uint64_t s_last_total, s_saved_used;
EXT_RAM_BSS_ATTR static uint32_t s_saved_at;
static bool s_loaded;

static uint32_t cq_fnv(const void *data, size_t n)
{
    uint32_t h = 2166136261u;
    const uint8_t *p = data;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
    return h;
}

static uint32_t uptime_s(void) {return (uint32_t)(esp_timer_get_time() / 1000000);}

static uint32_t period_now(uint8_t reset_day)
{
    time_t t = time(NULL);
    struct tm local;
    if (t < 1700000000 || !localtime_r(&t, &local)) return 0;   /* clock not set yet */
    return cell_quota_period(local.tm_year + 1900, local.tm_mon + 1, local.tm_mday, reset_day);
}

void cell_quota_init(void)
{
    cell_quota_config_t c = {.reset_day = 1, .warn_pct = 80};
    cell_quota_state_t st = {0};
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) == ESP_OK) {
        cq_config_record_t rc;
        size_t size = sizeof rc;
        if (nvs_get_blob(nvs, "cell_qcfg", &rc, &size) == ESP_OK && size == sizeof rc && rc.magic == CQ_MAGIC && rc.version == 1
            && rc.checksum == cq_fnv(&rc, offsetof(cq_config_record_t, checksum)) && cell_quota_config_valid(&rc.config, NULL, 0))
            c = rc.config;
        cq_state_record_t rs;
        size = sizeof rs;
        if (c.limit_mb && nvs_get_blob(nvs, "cell_quse", &rs, &size) == ESP_OK && size == sizeof rs && rs.magic == CQ_MAGIC
            && rs.version == 1 && rs.checksum == cq_fnv(&rs, offsetof(cq_state_record_t, checksum)))
            st = rs.state;
        nvs_close(nvs);
    }
    portENTER_CRITICAL(&s_mux);
    s_cfg = c;
    s_state = st;
    s_saved_used = st.used;
    s_saved_at = 0;
    s_last_total = 0;
    s_loaded = true;
    portEXIT_CRITICAL(&s_mux);
}

/* Internal-stack job (NVS writes need one; the cellular task's is PSRAM). */
static esp_err_t save_state_job(void *arg)
{
    const cell_quota_state_t *st = arg;
    cq_state_record_t r;
    memset(&r, 0, sizeof r);
    r.magic = CQ_MAGIC; r.version = 1; r.state = *st;
    r.checksum = cq_fnv(&r, offsetof(cq_state_record_t, checksum));
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(nvs, "cell_quse", &r, sizeof r);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

static void save_state(const cell_quota_state_t *st)
{
    cell_quota_state_t copy = *st;
    if (history_run_job(save_state_job, &copy) == ESP_OK) {
        portENTER_CRITICAL(&s_mux);
        s_saved_used = copy.used;
        s_saved_at = uptime_s();
        portEXIT_CRITICAL(&s_mux);
    } else {
        ESP_LOGW(TAG, "mobile data counter not saved");
    }
}

static void report(int events, const cell_quota_config_t *c, const cell_quota_state_t *st, uint64_t previous)
{
    unsigned used_mb = (unsigned)(st->used / (1024u * 1024u));
    if (events & CELL_QUOTA_EV_NEW_PERIOD)
        history_event(HIST_EV_UPLINK, HIST_INFO, "Mobile data: new monthly period, counter reset (previous period %u MB)",
                      (unsigned)(previous / (1024u * 1024u)));
    if (events & CELL_QUOTA_EV_WARN)
        history_event(HIST_EV_UPLINK, HIST_WARN, "Mobile data: %u%% of the monthly limit used (%u MB of %u MB)",
                      (unsigned)c->warn_pct, used_mb, (unsigned)c->limit_mb);
    if (events & CELL_QUOTA_EV_LIMIT)
        history_event(HIST_EV_UPLINK, HIST_WARN, c->pause ? "Mobile data: monthly limit of %u MB reached; mobile data paused until the next period"
                                                          : "Mobile data: monthly limit of %u MB reached",
                      (unsigned)c->limit_mb);
}

void cell_quota_tick(uint64_t total_bytes)
{
    if (!s_loaded) return;
    portENTER_CRITICAL(&s_mux);
    bool on = s_cfg.limit_mb != 0;
    uint64_t delta = total_bytes >= s_last_total ? total_bytes - s_last_total : total_bytes;
    s_last_total = total_bytes;
    portEXIT_CRITICAL(&s_mux);
    if (!on) return;                                  /* off: no counting, no flash writes */
    uint32_t period = period_now(s_cfg.reset_day);
    uint64_t previous = 0;
    portENTER_CRITICAL(&s_mux);
    int events = cell_quota_add(&s_cfg, &s_state, delta, period, &previous);
    cell_quota_config_t c = s_cfg;
    cell_quota_state_t st = s_state;
    bool due = cell_quota_save_due(st.used, s_saved_used, uptime_s(), s_saved_at, events);
    portEXIT_CRITICAL(&s_mux);
    if (events) report(events, &c, &st, previous);
    if (due) save_state(&st);
}

bool cell_quota_paused(void)
{
    portENTER_CRITICAL(&s_mux);
    bool paused = s_cfg.pause && cell_quota_limit_reached(&s_cfg, &s_state);
    portEXIT_CRITICAL(&s_mux);
    return paused;
}

void cell_quota_get(cell_quota_config_t *c, cell_quota_state_t *s)
{
    portENTER_CRITICAL(&s_mux);
    if (c) *c = s_cfg;
    if (s) *s = s_state;
    portEXIT_CRITICAL(&s_mux);
}

esp_err_t cell_quota_set(const cell_quota_config_t *c, bool reset_usage, char *why, size_t n)
{
    if (!cell_quota_config_valid(c, why, n)) return ESP_ERR_INVALID_ARG;
    cq_config_record_t r;
    memset(&r, 0, sizeof r);
    r.magic = CQ_MAGIC; r.version = 1; r.config = *c;
    r.checksum = cq_fnv(&r, offsetof(cq_config_record_t, checksum));
    cell_quota_state_t st;
    portENTER_CRITICAL(&s_mux);
    st = s_state;
    portEXIT_CRITICAL(&s_mux);
    if (reset_usage || !c->limit_mb) {st.used = 0; st.alerted = 0;}
    cell_quota_rearm(c, &st);
    cq_state_record_t rs;
    memset(&rs, 0, sizeof rs);
    rs.magic = CQ_MAGIC; rs.version = 1; rs.state = st;
    rs.checksum = cq_fnv(&rs, offsetof(cq_state_record_t, checksum));
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, "cell_qcfg", &r, sizeof r);
        /* Off: the counter is dropped, not kept in flash. */
        if (err == ESP_OK) err = c->limit_mb ? nvs_set_blob(nvs, "cell_quse", &rs, sizeof rs) : nvs_erase_key(nvs, "cell_quse");
        if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (err != ESP_OK) {snprintf(why, n, "settings not saved"); return err;}   /* RAM keeps the previous values */
    portENTER_CRITICAL(&s_mux);
    s_cfg = *c;
    s_state = st;
    s_saved_used = st.used;
    s_saved_at = uptime_s();
    s_loaded = true;
    portEXIT_CRITICAL(&s_mux);
    return ESP_OK;
}

void cell_quota_json(cJSON *parent)
{
    cell_quota_config_t c;
    cell_quota_state_t s;
    cell_quota_get(&c, &s);
    cJSON *o = cJSON_AddObjectToObject(parent, "data_limit");
    if (!o) return;
    cJSON_AddNumberToObject(o, "limit_mb", c.limit_mb);
    cJSON_AddNumberToObject(o, "warn_percent", c.warn_pct);
    cJSON_AddNumberToObject(o, "reset_day", c.reset_day ? c.reset_day : 1);
    cJSON_AddBoolToObject(o, "pause", c.pause);
    cJSON_AddNumberToObject(o, "used_bytes", (double)(c.limit_mb ? s.used : 0));
    cJSON_AddBoolToObject(o, "paused", c.pause && cell_quota_limit_reached(&c, &s));
    cJSON_AddBoolToObject(o, "clock", period_now(c.reset_day ? c.reset_day : 1) != 0);
    if (c.limit_mb && s.period) {
        int y, m, d;
        char date[40];   /* the compiler bounds every int field */
        cell_quota_period_start(s.period, c.reset_day, &y, &m, &d);
        snprintf(date, sizeof date, "%04d-%02d-%02d", y, m, d);
        cJSON_AddStringToObject(o, "period_start", date);
    } else {
        cJSON_AddNullToObject(o, "period_start");
    }
}
#endif
