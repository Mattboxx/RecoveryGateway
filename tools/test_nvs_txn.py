"""Actual main/nvs_params.c settings transactions (undo journal) on a fake NVS.

Saves that touch several keys used to commit key by key: a failure (or a
power cut) part way left some settings changed. The journal records each
key's previous value before its first write; end(true) drops it, a failed
write or end(false) restores every key, and nvs_param_txn_recover() undoes a
journal left by a power cut.

Covered: a power cut before every single NVS operation of a mixed
transaction (strings, i32/u8/u32, blob, erase, rewrite of the same key, a
key whose stored type changes, nesting), then a power cut before every
operation of the recovery itself, always ending in the complete old or
complete new state with no journal left; fault injection on every operation;
end(false); nested failure; writes by other tasks not journaled; the journal
size bound; damaged journals discarded without being applied; an incomplete
rollback retried before the next transaction.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
setup_source = (ROOT / 'main/first_boot.c').read_text(encoding='utf-8')
setup_finish = setup_source[setup_source.index('    TaskHandle_t reboot = NULL;'):
                            setup_source.index('\nstatic esp_err_t apply_handler')]

HEADERS = {
    'esp_err.h': r'''#pragma once
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_SUPPORTED 0x106
#define ESP_ERR_TIMEOUT 0x107
#define ESP_ERR_INVALID_CRC 0x109
#define ESP_ERR_NVS_NOT_FOUND 0x1102
#define ESP_ERR_NVS_INVALID_LENGTH 0x110c
const char *esp_err_to_name(esp_err_t e);
''',
    'esp_log.h': r'''#pragma once
#include "esp_err.h"
#define ESP_LOGE(t, ...) ((void)(t))
#define ESP_LOGW(t, ...) ((void)(t))
#define ESP_LOGI(t, ...) ((void)(t))
''',
    'nvs_flash.h': '#pragma once\n',
    'esp_attr.h': '#pragma once\n#define EXT_RAM_BSS_ATTR\n',
    # strlcpy for hosts without it (forced into every unit with -include)
    'host_compat.h': r'''#pragma once
#include <string.h>
#define strlcpy host_strlcpy
static inline size_t host_strlcpy(char *d, const char *s, size_t n) {
    size_t l = strlen(s);
    if (n) { size_t c = l < n - 1 ? l : n - 1; memcpy(d, s, c); d[c] = '\0'; }
    return l;
}
''',
    'nvs.h': r'''#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef uint32_t nvs_handle_t;
typedef enum { NVS_READONLY, NVS_READWRITE } nvs_open_mode_t;
typedef enum { NVS_TYPE_U8 = 0x01, NVS_TYPE_I8 = 0x11, NVS_TYPE_U16 = 0x02, NVS_TYPE_I16 = 0x12,
               NVS_TYPE_U32 = 0x04, NVS_TYPE_I32 = 0x14, NVS_TYPE_U64 = 0x08, NVS_TYPE_I64 = 0x18,
               NVS_TYPE_STR = 0x21, NVS_TYPE_BLOB = 0x42, NVS_TYPE_ANY = 0xff } nvs_type_t;
esp_err_t nvs_open(const char *ns, nvs_open_mode_t m, nvs_handle_t *h);
void nvs_close(nvs_handle_t h);
esp_err_t nvs_commit(nvs_handle_t h);
esp_err_t nvs_find_key(nvs_handle_t h, const char *k, nvs_type_t *t);
esp_err_t nvs_erase_key(nvs_handle_t h, const char *k);
esp_err_t nvs_erase_all(nvs_handle_t h);
esp_err_t nvs_get_i32(nvs_handle_t h, const char *k, int32_t *v);
esp_err_t nvs_get_u8(nvs_handle_t h, const char *k, uint8_t *v);
esp_err_t nvs_get_u16(nvs_handle_t h, const char *k, uint16_t *v);
esp_err_t nvs_get_u32(nvs_handle_t h, const char *k, uint32_t *v);
esp_err_t nvs_get_str(nvs_handle_t h, const char *k, char *v, size_t *n);
esp_err_t nvs_get_blob(nvs_handle_t h, const char *k, void *v, size_t *n);
esp_err_t nvs_set_i32(nvs_handle_t h, const char *k, int32_t v);
esp_err_t nvs_set_u8(nvs_handle_t h, const char *k, uint8_t v);
esp_err_t nvs_set_u16(nvs_handle_t h, const char *k, uint16_t v);
esp_err_t nvs_set_u32(nvs_handle_t h, const char *k, uint32_t v);
esp_err_t nvs_set_str(nvs_handle_t h, const char *k, const char *v);
esp_err_t nvs_set_blob(nvs_handle_t h, const char *k, const void *v, size_t n);
''',
    'freertos/FreeRTOS.h': r'''#pragma once
#include <stdint.h>
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define portMAX_DELAY 0
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(mux) ((void)(mux))
#define portEXIT_CRITICAL(mux) ((void)(mux))
''',
    'freertos/semphr.h': r'''#pragma once
typedef int StaticSemaphore_t;
typedef int *SemaphoreHandle_t;
static inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *s) { return s; }
static inline int xSemaphoreTake(SemaphoreHandle_t s, int t) { (void)t; if (*s) return 0; *s = 1; return 1; }
static inline int xSemaphoreGive(SemaphoreHandle_t s) { *s = 0; return 1; }
''',
    'freertos/task.h': r'''#pragma once
typedef void *TaskHandle_t;
extern TaskHandle_t fake_task;
static inline TaskHandle_t xTaskGetCurrentTaskHandle(void) { return fake_task; }
''',
}

PROGRAM = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"
#include "nvs_params.h"
#include "nvs_flags.h"
#include "wifi_networks.h"
#include "freertos/task.h"

static int task_a, task_b;
TaskHandle_t fake_task = &task_a;
const char *esp_err_to_name(esp_err_t e) { (void)e; return "err"; }

/* ---- fake NVS: one item per key (writing another type replaces it, as in
 * ESP-IDF); every set/erase is atomic. ops counts mutating operations; a
 * power cut before op crash_at saves the store and exits; fail_at / fail_key
 * make one operation fail without changing anything. */
#define MAXI 32
#define MAXV 7000
typedef struct { char key[16]; uint8_t type, used; uint16_t len; uint8_t data[MAXV]; } item_t;
static item_t st[MAXI];
static const char *store_path;
static int ops, crash_at, fail_at;
static const char *fail_key;
static void save_store(void) { FILE *f = fopen(store_path, "wb"); assert(f); fwrite(st, sizeof st, 1, f); fclose(f); }
static void load_store(void) { FILE *f = fopen(store_path, "rb"); memset(st, 0, sizeof st); if (f) { assert(fread(st, sizeof st, 1, f) == 1); fclose(f); } }
static item_t *find(const char *k) { for (int i = 0; i < MAXI; i++) if (st[i].used && !strcmp(st[i].key, k)) return &st[i]; return NULL; }
static esp_err_t mutate(const char *k) {
    ++ops;
    if (crash_at && ops == crash_at) { save_store(); exit(3); }
    if ((fail_at && ops == fail_at) || (fail_key && !strcmp(fail_key, k))) return ESP_FAIL;
    return ESP_OK;
}
static esp_err_t put(const char *k, uint8_t type, const void *v, size_t n) {
    assert(strlen(k) <= 15 && n <= MAXV);
    esp_err_t e = mutate(k); if (e) return e;
    item_t *it = find(k);
    if (!it) { for (int i = 0; i < MAXI; i++) if (!st[i].used) { it = &st[i]; break; } }
    assert(it);
    strcpy(it->key, k); it->type = type; it->used = 1; it->len = (uint16_t)n; memcpy(it->data, v, n);
    return ESP_OK;
}
static esp_err_t get(const char *k, uint8_t type, void *v, size_t n) {
    item_t *it = find(k); if (!it || it->type != type) return ESP_ERR_NVS_NOT_FOUND;
    assert(it->len == n); memcpy(v, it->data, n); return ESP_OK;
}
static esp_err_t getv(const char *k, uint8_t type, void *v, size_t *n) {
    item_t *it = find(k); if (!it || it->type != type) return ESP_ERR_NVS_NOT_FOUND;
    if (!v) { *n = it->len; return ESP_OK; }
    if (*n < it->len) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(v, it->data, it->len); *n = it->len; return ESP_OK;
}
esp_err_t nvs_open(const char *ns, nvs_open_mode_t m, nvs_handle_t *h) { (void)m; assert(!strcmp(ns, "tsr")); *h = 1; return ESP_OK; }
void nvs_close(nvs_handle_t h) { (void)h; }
esp_err_t nvs_commit(nvs_handle_t h) { (void)h; return ESP_OK; }
esp_err_t nvs_find_key(nvs_handle_t h, const char *k, nvs_type_t *t) { (void)h; item_t *it = find(k); if (!it) return ESP_ERR_NVS_NOT_FOUND; *t = (nvs_type_t)it->type; return ESP_OK; }
esp_err_t nvs_erase_key(nvs_handle_t h, const char *k) { (void)h; item_t *it = find(k); if (!it) return ESP_ERR_NVS_NOT_FOUND; esp_err_t e = mutate(k); if (e) return e; it->used = 0; return ESP_OK; }
esp_err_t nvs_erase_all(nvs_handle_t h) { (void)h; memset(st, 0, sizeof st); return ESP_OK; }
esp_err_t nvs_get_i32(nvs_handle_t h, const char *k, int32_t *v) { (void)h; return get(k, NVS_TYPE_I32, v, 4); }
esp_err_t nvs_get_u8(nvs_handle_t h, const char *k, uint8_t *v) { (void)h; return get(k, NVS_TYPE_U8, v, 1); }
esp_err_t nvs_get_u16(nvs_handle_t h, const char *k, uint16_t *v) { (void)h; return get(k, NVS_TYPE_U16, v, 2); }
esp_err_t nvs_get_u32(nvs_handle_t h, const char *k, uint32_t *v) { (void)h; return get(k, NVS_TYPE_U32, v, 4); }
esp_err_t nvs_get_str(nvs_handle_t h, const char *k, char *v, size_t *n) { (void)h; return getv(k, NVS_TYPE_STR, v, n); }
esp_err_t nvs_get_blob(nvs_handle_t h, const char *k, void *v, size_t *n) { (void)h; return getv(k, NVS_TYPE_BLOB, v, n); }
esp_err_t nvs_set_i32(nvs_handle_t h, const char *k, int32_t v) { (void)h; return put(k, NVS_TYPE_I32, &v, 4); }
esp_err_t nvs_set_u8(nvs_handle_t h, const char *k, uint8_t v) { (void)h; return put(k, NVS_TYPE_U8, &v, 1); }
esp_err_t nvs_set_u16(nvs_handle_t h, const char *k, uint16_t v) { (void)h; return put(k, NVS_TYPE_U16, &v, 2); }
esp_err_t nvs_set_u32(nvs_handle_t h, const char *k, uint32_t v) { (void)h; return put(k, NVS_TYPE_U32, &v, 4); }
esp_err_t nvs_set_str(nvs_handle_t h, const char *k, const char *v) { (void)h; return put(k, NVS_TYPE_STR, v, strlen(v) + 1); }
esp_err_t nvs_set_blob(nvs_handle_t h, const char *k, const void *v, size_t n) { (void)h; return put(k, NVS_TYPE_BLOB, v, n); }

/* ---- the scenario ---- */
static uint8_t old_blob[300], new_blob[200];
static void init_state(void) {
    memset(st, 0, sizeof st);
    for (int i = 0; i < 300; i++) old_blob[i] = (uint8_t)i;
    assert(nvs_param_set_str("a", "old-a") == ESP_OK && nvs_param_set_int("b", 1) == ESP_OK);
    assert(nvs_param_set_blob("d", old_blob, sizeof old_blob) == ESP_OK && nvs_param_set_u16("e", 5) == ESP_OK);
    assert(nvs_param_set_u8("f", 9) == ESP_OK);
}
static esp_err_t run_txn(bool keep) {
    for (int i = 0; i < 200; i++) new_blob[i] = (uint8_t)(255 - i);
    assert(nvs_param_txn_begin() == ESP_OK);
    esp_err_t e = ESP_OK, r;
#define W(x) do { r = (x); if (e == ESP_OK) e = r; } while (0)
    W(nvs_param_set_str("a", "new-a"));
    W(nvs_param_set_int("b", 2));
    W(nvs_param_set_u8("c", 7));                     /* absent before */
    assert(nvs_param_txn_begin() == ESP_OK);         /* nested */
    W(nvs_param_set_blob("d", new_blob, sizeof new_blob));
    W(nvs_param_erase("e"));
    assert(nvs_param_txn_end(true) == ESP_OK);
    W(nvs_param_set_str("a", "newer-a"));           /* second write: still restores old-a */
    W(nvs_param_set_u32("f", 70000));               /* stored type changes u8 -> u32 */
#undef W
    esp_err_t end = nvs_param_txn_end(keep);
    if (e != ESP_OK || !keep) assert(end != ESP_OK);
    return end;
}
/* "old", "new" or "mixed"; asserts that no journal is left. */
static const char *state(void) {
    assert(!find("txn_undo"));
    char a[16] = ""; size_t n = sizeof a; int32_t b = 0; uint8_t c = 0, f8 = 0; uint16_t e = 0; uint32_t f32 = 0;
    uint8_t d[400]; size_t dn = sizeof d;
    bool ha = nvs_param_get_str_buf("a", a, &n) == ESP_OK, hb = nvs_param_get_int("b", &b) == ESP_OK;
    bool hc = nvs_param_get_u8("c", &c) == ESP_OK, hd = nvs_param_get_blob("d", d, &dn) == ESP_OK;
    bool he = nvs_param_get_u16("e", &e) == ESP_OK, hf8 = nvs_param_get_u8("f", &f8) == ESP_OK;
    bool hf32 = nvs_param_get_u32("f", &f32) == ESP_OK;
    if (ha && !strcmp(a, "old-a") && hb && b == 1 && !hc && hd && dn == 300 && !memcmp(d, old_blob, 300)
        && he && e == 5 && hf8 && f8 == 9 && !hf32) return "old";
    if (ha && !strcmp(a, "newer-a") && hb && b == 2 && hc && c == 7 && hd && dn == 200 && !memcmp(d, new_blob, 200)
        && !he && !hf8 && hf32 && f32 == 70000) return "new";
    return "mixed";
}

static void unit_tests(void) {
    /* Fault on every operation of the transaction: always all old. */
    for (int at = 1; at < 40; at++) {
        init_state(); ops = 0; fail_at = at;
        esp_err_t end = run_txn(true);
        fail_at = 0;
        const char *s = state();
        if (end == ESP_OK) { assert(!strcmp(s, "new")); break; }
        assert(!strcmp(s, "old"));
    }
    /* end(false) restores; a failed nested end restores at the outer end. */
    init_state(); run_txn(false); assert(!strcmp(state(), "old"));
    init_state(); assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_int("b", 3) == ESP_OK);
    assert(nvs_param_txn_begin() == ESP_OK); assert(nvs_param_txn_end(false) == ESP_OK);
    assert(nvs_param_txn_end(true) == ESP_ERR_INVALID_STATE && !strcmp(state(), "old"));
    /* nvs_param_txn_fail (a non-NVS step failed) restores too. */
    init_state(); assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_int("b", 3) == ESP_OK);
    nvs_param_txn_fail(); assert(nvs_param_txn_end(true) != ESP_OK && !strcmp(state(), "old"));
    /* No transaction / not the owner: end refused; empty transaction fine. */
    assert(nvs_param_txn_end(true) == ESP_ERR_INVALID_STATE);
    assert(nvs_param_txn_begin() == ESP_OK && nvs_param_txn_end(true) == ESP_OK);
    /* Another task's write during a transaction is not journaled or undone,
     * and another task cannot join or end the transaction. */
    init_state(); assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_int("b", 3) == ESP_OK);
    fake_task = &task_b;
    assert(nvs_param_set_u8("g", 1) == ESP_OK);
    assert(nvs_param_txn_end(true) == ESP_ERR_INVALID_STATE);
    assert(nvs_param_txn_begin() == ESP_ERR_TIMEOUT);
    fake_task = &task_a;
    assert(nvs_param_txn_end(false) != ESP_OK);
    uint8_t g = 0; assert(nvs_param_get_u8("g", &g) == ESP_OK && g == 1 && !strcmp(state(), "old"));
    /* Size bound: previous values beyond NVS_PARAM_TXN_MAX_BYTES are refused,
     * the write does not happen and the transaction rolls back. */
    init_state();
    static uint8_t big[NVS_PARAM_TXN_MAX_BYTES]; memset(big, 0x5a, sizeof big);
    assert(nvs_param_set_blob("big", big, sizeof big) == ESP_OK);
    assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_int("b", 3) == ESP_OK);
    assert(nvs_param_set_blob("big", big, 10) == ESP_ERR_NO_MEM);
    size_t bn = 0; assert(nvs_param_get_blob("big", NULL, &bn) == ESP_OK && bn == sizeof big);
    assert(nvs_param_txn_end(true) != ESP_OK && !strcmp(state(), "old"));
    assert(nvs_param_erase("big") == ESP_OK);
    /* The journal key itself cannot be written through a transaction. */
    assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_u8("txn_undo", 1) == ESP_ERR_INVALID_ARG);
    assert(nvs_param_txn_end(true) != ESP_OK);
    /* Damaged journals are discarded, never applied. */
    uint8_t junk[64]; memset(junk, 0, sizeof junk);
    for (int k = 0; k < 3; k++) {
        init_state();
        if (k == 0) put("txn_undo", NVS_TYPE_BLOB, junk, 3);               /* too short */
        if (k == 1) put("txn_undo", NVS_TYPE_BLOB, junk, sizeof junk);     /* bad magic */
        if (k == 2) { memcpy(junk, "TXN1", 4); junk[4] = 1; put("txn_undo", NVS_TYPE_BLOB, junk, sizeof junk); }
        assert(nvs_param_txn_recover() == ESP_OK && !strcmp(state(), "old"));
    }
    /* A rollback that cannot restore a key keeps the journal; the next
     * transaction first finishes the rollback. */
    init_state(); assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_int("b", 3) == ESP_OK);
    fail_key = "b"; assert(nvs_param_txn_end(false) == ESP_FAIL); fail_key = NULL;
    assert(find("txn_undo"));
    int32_t b = 0; assert(nvs_param_get_int("b", &b) == ESP_OK && b == 3);
    assert(nvs_param_txn_begin() == ESP_OK && nvs_param_txn_end(true) == ESP_OK && !strcmp(state(), "old"));
    /* Nothing pending: recover is a no-op. */
    assert(nvs_param_txn_recover() == ESP_OK && !strcmp(state(), "old"));
    /* Actual Wi-Fi table: readers see the old table even between writes. */
    memset(st, 0, sizeof st);
    wifi_network_t wa[2] = {0}, wb[3] = {0}, got;
    strcpy(wa[0].ssid, "home"); strcpy(wa[0].passwd, "pw-old");
    assert(wifi_networks_set_all(wa, 1) == ESP_OK && wifi_networks_count() == 1);
    strcpy(wb[0].ssid, "new1"); strcpy(wb[2].ssid, "new2");        /* wb[1] empty: dropped */
    fail_key = "wifi_nets"; assert(wifi_networks_set_all(wb, 3) != ESP_OK); fail_key = NULL;
    assert(wifi_networks_count() == 1 && wifi_networks_get(0, &got) && !strcmp(got.ssid, "home"));
    assert(nvs_param_txn_begin() == ESP_OK && wifi_networks_stage(wb, 3) == ESP_OK);
    assert(wifi_networks_count() == 1 && wifi_networks_get(0, &got) && !strcmp(got.ssid, "home"));
    fail_key = "later"; assert(nvs_param_set_u8("later", 1) != ESP_OK); fail_key = NULL;
    assert(nvs_param_txn_end(true) != ESP_OK && !find("txn_undo"));
    wifi_networks_finish_staged(false);
    assert(wifi_networks_count() == 1 && wifi_networks_get(0, &got) && !strcmp(got.ssid, "home")
           && !strcmp(got.passwd, "pw-old") && !wifi_networks_get(1, &got));
    assert(nvs_param_txn_begin() == ESP_OK && wifi_networks_stage(wb, 3) == ESP_OK);
    assert(nvs_param_txn_end(true) == ESP_OK && wifi_networks_count() == 1);
    wifi_networks_finish_staged(true);
    assert(wifi_networks_count() == 2 && wifi_networks_get(1, &got) && !strcmp(got.ssid, "new2"));
    assert(nvs_param_txn_begin() == ESP_OK && wifi_networks_store_for_reboot(wa, 1) == ESP_OK);
    assert(nvs_param_txn_end(true) == ESP_OK && wifi_networks_count() == 2);
    assert(wifi_networks_set_all(wa, 0) == ESP_OK);
    assert(wifi_networks_has_saved_table() && wifi_networks_count() == 0);
    size_t saved_wifi_size = 0;
    assert(nvs_param_get_blob("wifi_nets", NULL, &saved_wifi_size) == ESP_OK);
    assert(saved_wifi_size == WIFI_NETWORKS_MAX * sizeof(wifi_network_t));
    assert(nvs_param_set_u8("dns_relay_en", 1) == ESP_OK);
    assert(nvs_param_set_str("dns_relay_up", "192.0.2.1") == ESP_OK);
    assert(nvs_param_txn_begin() == ESP_OK && nvs_param_set_u8("dns_relay_en", 0) == ESP_OK);
    fail_key = "dns_relay_up";
    assert(nvs_param_set_str("dns_relay_up", "") != ESP_OK);
    fail_key = NULL;
    assert(nvs_param_txn_end(true) != ESP_OK);
    uint8_t relay = 0;
    assert(nvs_param_get_u8("dns_relay_en", &relay) == ESP_OK && relay == 1);
    char *upstream = nvs_param_get_str("dns_relay_up");
    assert(upstream && !strcmp(upstream, "192.0.2.1"));
    free(upstream);
    puts("unit ok");
}

/* First-boot writes after input validation. Use the actual Wi-Fi and flags
 * stores. The validated Ethernet/SIM encoders and password hashing are
 * represented by fixed NVS payloads through their real settings interfaces. */
typedef struct { const char *valuestring; } cJSON;
typedef unsigned httpd_req_t, eth_config_t, cell_config_t;
static const char *const hist_keys[]={"hist_ev","hist_mx","hist_snap"}, *const names_keys[]={"tn_names","tn_names_lan"};
static const nvs_flags_t history_flags={"hist_cfg",hist_keys,3}, tailnet_names_flags={"tn_names_cfg",names_keys,2};
static const char *TAG="setup";
static bool fail_restart, s_finished;
static unsigned restart_signal;
static unsigned s_lock_storage;
static TaskHandle_t s_lock=&s_lock_storage;
static unsigned s_ctx;
#define LAN_NAME_MAX 32
#define xSemaphoreTake(s,t) ((void)(s),(void)(t))
#define xSemaphoreGive(s) ((void)(s))
#define cJSON_ArrayForEach(element,array) for ((element)=(array);(element);(element)=NULL)
static const cJSON *cJSON_GetObjectItem(const cJSON *o,const char *k){(void)o;(void)k;return NULL;}
static bool cJSON_IsString(const cJSON *o){return o && o->valuestring;}
#define strlcat fixture_strlcat
static size_t strlcat(char *d,const char *s,size_t n){size_t l=strlen(d);return l+strlcpy(d+l,s,n-l);}
static bool bool_of(const cJSON *o,const char *k,bool d){(void)o;(void)k;return d;}
static const char *str_of(const cJSON *o,const char *k){(void)o;assert(!strcmp(k,"device_name"));return "setup-fixture";}
static void fb_wipe(unsigned *c){*c=0;}
static void dns_relay_set_captive(int i){assert(!i);}
static void lan_name_get(char *out,size_t cap){strlcpy(out,"fixture-gateway",cap);}
static esp_err_t send_error(httpd_req_t *r,const char *s,const char *k,const char *v){
    (void)r;(void)s;assert(k&&v);return ESP_FAIL;}
static void httpd_resp_set_type(httpd_req_t *r,const char *s){(void)r;assert(!strcmp(s,"application/json"));}
static void httpd_resp_set_hdr(httpd_req_t *r,const char *k,const char *s){(void)r;assert(k&&s);}
static esp_err_t httpd_resp_sendstr(httpd_req_t *r,const char *s){
    (void)r;assert(strstr(s,"\"ok\":true") && strstr(s,"\"restart_in_s\":1"));return ESP_OK;}
static esp_err_t web_ui_reserve_restart(TaskHandle_t *task){*task=&restart_signal;return fail_restart?ESP_FAIL:ESP_OK;}
static void web_ui_finish_restart(TaskHandle_t task,bool commit){assert(task==&restart_signal);restart_signal=1+(unsigned)commit;}
static esp_err_t web_password_store_for_reboot(const char *p,esp_err_t (*writer)(const char *,const char *)){
    assert(!strcmp(p,"fixture-phrase"));return writer("web_password","verifier");}
static esp_err_t eth_uplink_store_for_reboot(const eth_config_t *c,char *why,size_t n){
    assert(why && n);return nvs_param_set_blob("eth_cfg",c,sizeof *c);}
static esp_err_t cell_uplink_store_for_reboot(const cell_config_t *c,char *why,size_t n){
    assert(why && n);return nvs_param_set_blob("cell_cfg",c,sizeof *c);}

static esp_err_t run_setup(int kind) {
    httpd_req_t *req=NULL;
    const cJSON *cmd=NULL;
    const char *admin="fixture-phrase", *ssid="fixture-wifi", *wpw="fixture-wifi-passphrase";
    const char *ap_ssid="fixture-ap", *ap_pw="fixture-ap-passphrase";
    const char *key="permit-fixture", *server="https://test.invalid", *host="fixture-tailnet";
    const char *tz="UTC0", *lan="fixture-gateway";
    bool has_wifi=kind==0, eth_up=kind==1, cell_up=kind==2;
    const char *type=has_wifi?"wifi":eth_up?"ethernet":"cellular";
    bool ap_open=false, ap_recovery=true, share_ap=true, exit_node=false;
    const char *cidr="192.0.2.0/24";
    eth_config_t eth=1;
    cell_config_t cell=2;
    char why[2]="";
''' + setup_finish + r'''
static const char *setup_state(int kind) {
    const char *const keys[]={"ap_ssid","ap_passwd","ap_open","ap_auto_off","ts_enabled","ts_authkey",
        "ts_login","ts_hostname","hostname","ts_adv_ap","ts_routes","tz","ts_adv_exit","ui_roles",
        "ui_adv","hist_cfg","tn_names_cfg","dev_name","web_password","setup_done"};
    bool done=find("setup_done")!=NULL;
    for (unsigned i=0;i<sizeof keys/sizeof *keys;i++) if ((find(keys[i])!=NULL)!=done) return "mixed";
    if ((find("wifi_nets")!=NULL)!=(done && kind==0) ||
        (find("eth_cfg")!=NULL)!=(done && kind==1) ||
        (find("cell_cfg")!=NULL)!=(done && kind==2) || find("txn_undo")) return "mixed";
    return done?"new":"old";
}

int main(int argc, char **argv) {
    store_path = argv[2];
    const char *mode = argv[1];
    crash_at = argc > 3 ? atoi(argv[3]) : 0;
    if (!strcmp(mode, "unit")) { unit_tests(); return 0; }
    if (!strcmp(mode, "init")) { crash_at = 0; init_state(); save_store(); return 0; }
    load_store();
    if (!strcmp(mode, "setup-init")) { memset(st,0,sizeof st);save_store();return 0; }
    if (!strncmp(mode, "setup-", 6)) {
        int kind = argc > 4 ? atoi(argv[4]) : 0;
        if (!strcmp(mode, "setup-reserve-failure")) {
            fail_restart=true;
            assert(run_setup(kind)!=ESP_OK && !ops && !restart_signal && !s_finished);
        } else if (!strcmp(mode, "setup-commit-failure")) {
            fail_key="setup_done";
            assert(run_setup(kind)!=ESP_OK && restart_signal==1 && !s_finished);
        } else if (!strcmp(mode,"setup-save")) {
            assert(run_setup(kind)==ESP_OK && restart_signal==2 && s_finished);
            printf("ops %d\n", ops);
        } else {
            assert(nvs_param_txn_recover()==ESP_OK);
            puts(setup_state(kind));
        }
        save_store();
        return 0;
    }
    for (int i = 0; i < 300; i++) old_blob[i] = (uint8_t)i;
    for (int i = 0; i < 200; i++) new_blob[i] = (uint8_t)(255 - i);
    if (!strcmp(mode, "save")) { run_txn(true); save_store(); printf("ops %d\n", ops); return 0; }
    /* boot: recover (may itself be cut), then report */
    nvs_param_txn_recover();
    save_store();
    printf("%s\n", state());
    return 0;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='nvs-txn-') as folder:
        path = Path(folder)
        (path / 'freertos').mkdir()
        for name, text in HEADERS.items():
            (path / name).write_text(text, encoding='utf-8')
        (path / 'test.c').write_text(PROGRAM, encoding='utf-8')
        binary = path / ('txn.exe' if os.name == 'nt' else 'txn')
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(path), '-I', str(ROOT / 'main'),
                 '-include', str(path / 'host_compat.h')]
        if os.environ.get('NVS_TXN_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'test.c'),
                        str(ROOT / 'main/nvs_params.c'), str(ROOT / 'main/wifi_networks.c'),
                        str(ROOT / 'main/nvs_flags.c'), '-o', str(binary)], check=True)
        store = str(path / 'store.bin')

        def run(*args, expect=0):
            r = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=60)
            assert r.returncode == expect, (args, r.returncode, r.stdout, r.stderr)
            return r.stdout.strip()

        assert run('unit', store) == 'unit ok'
        run('init', store)
        total = int(run('save', store).split()[1])
        assert run('boot', store) == 'new'
        assert total > 10, total
        cuts = 0
        for at in range(1, total + 1):
            run('init', store)
            run('save', store, str(at), expect=3)            # power cut before op `at`
            # a second power cut during the recovery, before each of its ops
            for rec in range(1, 40):
                r = subprocess.run([str(binary), 'boot', store, str(rec)], capture_output=True, text=True, timeout=60)
                cuts += 1
                if r.returncode == 0:
                    assert r.stdout.strip() == 'old', (at, rec, r.stdout)
                    break
                assert r.returncode == 3, (at, rec, r.returncode, r.stderr)
            assert run('boot', store) == 'old', at
        print(f'PASS: actual nvs_params undo journal: {total} power-cut points in a mixed save and '
              f'{cuts} during recovery end all old or all new, fault injection, nesting, other tasks, '
              'size bound, damaged journals discarded, incomplete rollback retried, Wi-Fi cache published only after commit (fake NVS)')
        setup_cuts = 0
        for kind in ('0', '1', '2'):
            run('setup-init', store)
            for fault in ('setup-reserve-failure', 'setup-commit-failure'):
                run(fault, store, '0', kind)
                assert run('setup-boot', store, '0', kind) == 'old'
            total = int(run('setup-save', store, '0', kind).split()[1])
            assert run('setup-boot', store, '0', kind) == 'new'
            for at in range(1, total + 1):
                run('setup-init', store)
                run('setup-save', store, str(at), kind, expect=3)
                assert run('setup-boot', store, '0', kind) == 'old'
                setup_cuts += 1
        print(f'PASS: first-boot commit body: checked restart reservation, final-write failure and {setup_cuts} power-cut points across Wi-Fi, Ethernet and cellular (fake NVS)')


if __name__ == '__main__':
    main()
