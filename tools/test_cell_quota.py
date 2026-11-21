"""Monthly mobile data counter core (actual main/cell_quota.c, host build).

- settings: limit 0-1000000 MB, early warning 0-99 %, period start day
  1-28, pause 0/1; anything else refused;
- the period of a date: before the start day it is still last month's
  (also across the year boundary); an implausible date (clock not set) is 0;
- counting: the early warning fires once, the limit fires once (and alone
  when one jump passes both), never again in the same period;
- a later period starts from zero, reports the finished period's use and
  re-arms the alerts; an unknown period (no clock) keeps counting in the
  stored one; the first clock reading or a clock set back keeps the use;
- the counter saturates instead of wrapping;
- raising the limit re-arms alerts no longer reached, lowering keeps them;
- flash writes: on every alert or new period, otherwise only after 1 MB
  more and 10 minutes since the last write;
- "stop at the limit" is only reported with a limit set.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/cell_quota.c').read_text(encoding='utf-8')
core = source[source.index('/* --- cell_quota core (begin) --- */'):source.index('/* --- cell_quota core (end) --- */')]

PROGRAM = r'''
#define CELL_QUOTA_HOST_TEST 1
#include "cell_quota.h"
#include <stdio.h>
#include <string.h>
@@CORE@@
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
#define MB (1024ull * 1024ull)
int main(void)
{
    char why[96];
    cell_quota_config_t c = {.limit_mb = 1000, .warn_pct = 80, .reset_day = 1, .pause = 1};
    CHECK(cell_quota_config_valid(&c, why, sizeof why));
    cell_quota_config_t bad = c; bad.limit_mb = 1000001; CHECK(!cell_quota_config_valid(&bad, why, sizeof why));
    bad = c; bad.warn_pct = 100; CHECK(!cell_quota_config_valid(&bad, why, sizeof why));
    bad = c; bad.reset_day = 0; CHECK(!cell_quota_config_valid(&bad, why, sizeof why));
    bad = c; bad.reset_day = 29; CHECK(!cell_quota_config_valid(&bad, why, sizeof why));
    bad = c; bad.pause = 2; CHECK(!cell_quota_config_valid(&bad, why, sizeof why));
    bad = c; bad.limit_mb = 0; CHECK(cell_quota_config_valid(&bad, why, sizeof why));

    /* periods */
    uint32_t nov = cell_quota_period(2026, 11, 15, 1), dec = cell_quota_period(2026, 12, 1, 1);
    CHECK(nov && dec == nov + 1);
    CHECK(cell_quota_period(2026, 11, 9, 10) == cell_quota_period(2026, 10, 10, 10));      /* before day 10: October's */
    CHECK(cell_quota_period(2026, 11, 10, 10) == cell_quota_period(2026, 11, 28, 10));
    CHECK(cell_quota_period(2027, 1, 5, 10) == cell_quota_period(2026, 12, 20, 10));       /* across the year */
    CHECK(cell_quota_period(1970, 1, 1, 1) == 0 && cell_quota_period(2026, 13, 1, 1) == 0 && cell_quota_period(2026, 1, 1, 0) == 0);
    int y, m, d; cell_quota_period_start(cell_quota_period(2027, 1, 5, 10), 10, &y, &m, &d);
    CHECK(y == 2026 && m == 12 && d == 10);

    /* counting and alerts */
    cell_quota_state_t s = {0};
    uint64_t prev = 99;
    CHECK(cell_quota_add(&c, &s, 100 * MB, 0, &prev) == 0 && s.used == 100 * MB && s.period == 0 && prev == 0);   /* no clock yet */
    CHECK(cell_quota_add(&c, &s, 0, nov, &prev) == 0 && s.period == nov && s.used == 100 * MB);                     /* first clock reading */
    CHECK(cell_quota_add(&c, &s, 699 * MB, nov, NULL) == 0);
    CHECK(cell_quota_add(&c, &s, 1 * MB, nov, NULL) == CELL_QUOTA_EV_WARN);                                         /* 800 MB = 80 % */
    CHECK(cell_quota_add(&c, &s, 1 * MB, nov, NULL) == 0);                                                          /* once */
    CHECK(!cell_quota_limit_reached(&c, &s));
    CHECK(cell_quota_add(&c, &s, 199 * MB, nov, NULL) == CELL_QUOTA_EV_LIMIT && cell_quota_limit_reached(&c, &s));
    CHECK(cell_quota_add(&c, &s, 50 * MB, nov, NULL) == 0);
    CHECK(cell_quota_add(&c, &s, 0, 0, NULL) == 0 && s.period == nov);                                             /* clock lost: same period */
    CHECK(cell_quota_add(&c, &s, 1 * MB, nov - 1, NULL) == 0 && s.period == nov && s.used == 1051 * MB);       /* clock set back */
    CHECK(cell_quota_add(&c, &s, 0, nov, NULL) == 0 && s.used == 1051 * MB); /* returning to the same month retains usage */

    cq_clock_t clock = {0};
    int64_t wall = INT64_C(1795996800);
    CHECK(!cq_clock_ready(&clock,wall,5));
    CHECK(!cq_clock_ready(&clock,wall+119,124));
    CHECK(cq_clock_ready(&clock,wall+120,125));
    CHECK(!cq_clock_ready(&clock,wall+8640000,130)); /* bad forward jump */
    CHECK(!cq_clock_ready(&clock,wall+8640030,160));
    CHECK(!cq_clock_ready(&clock,wall+160,165)); /* correct before the hold expires */
    CHECK(cq_clock_ready(&clock,wall+280,285));
    CHECK(!cq_clock_ready(&clock,0,286));
    CHECK(!cq_clock_ready(&clock,wall+282,287));
    /* Reboot with an old future marker: correcting keeps usage and limits. */
    s = (cell_quota_state_t){.period=nov+6,.used=1051*MB,.alerted=CELL_QUOTA_WARNED|CELL_QUOTA_LIMITED};
    clock = (cq_clock_t){0};
    CHECK(!cq_clock_ready(&clock,wall,0));
    CHECK(cell_quota_add(&c,&s,MB,0,NULL)==0 && s.period==nov+6);
    CHECK(cq_clock_ready(&clock,wall+120,120));
    CHECK(cell_quota_add(&c,&s,0,nov,NULL)==CELL_QUOTA_EV_CLOCK_CORRECTED);
    CHECK(s.period==nov && s.used==1052*MB && cell_quota_limit_reached(&c,&s));
    CHECK(cell_quota_add(&c,&s,MB,dec,&prev)==CELL_QUOTA_EV_NEW_PERIOD && prev==1052*MB && s.used==MB);
    s = (cell_quota_state_t){.period = nov, .used = 1051 * MB, .alerted = CELL_QUOTA_WARNED | CELL_QUOTA_LIMITED};
    CHECK(cell_quota_add(&c, &s, 5 * MB, dec, &prev) == CELL_QUOTA_EV_NEW_PERIOD && prev == 1051 * MB && s.used == 5 * MB && s.alerted == 0);
    /* one jump past both thresholds: only the limit message */
    s = (cell_quota_state_t){.period = dec};
    CHECK(cell_quota_add(&c, &s, 2000 * MB, dec, NULL) == CELL_QUOTA_EV_LIMIT && (s.alerted & CELL_QUOTA_WARNED));
    /* saturates */
    s.used = UINT64_MAX - 5; cell_quota_add(&c, &s, 100, dec, NULL); CHECK(s.used == UINT64_MAX);
    /* no early warning configured */
    cell_quota_config_t nowarn = c; nowarn.warn_pct = 0; s = (cell_quota_state_t){.period = dec};
    CHECK(cell_quota_add(&nowarn, &s, 999 * MB, dec, NULL) == 0 && cell_quota_add(&nowarn, &s, 1 * MB, dec, NULL) == CELL_QUOTA_EV_LIMIT);
    /* off: never an alert */
    cell_quota_config_t off = c; off.limit_mb = 0; s = (cell_quota_state_t){.period = dec};
    CHECK(cell_quota_add(&off, &s, 5000 * MB, dec, NULL) == 0 && !cell_quota_limit_reached(&off, &s));

    /* settings change re-arms */
    s = (cell_quota_state_t){.period = dec, .used = 1100 * MB, .alerted = CELL_QUOTA_WARNED | CELL_QUOTA_LIMITED};
    cell_quota_config_t raised = c; raised.limit_mb = 2000;
    cell_quota_rearm(&raised, &s); CHECK(s.alerted == 0);
    CHECK(cell_quota_add(&raised, &s, 500 * MB, dec, NULL) == CELL_QUOTA_EV_WARN);                                 /* 1600 = 80 % of 2000 */
    s = (cell_quota_state_t){.period = dec, .used = 1100 * MB, .alerted = CELL_QUOTA_WARNED | CELL_QUOTA_LIMITED};
    cell_quota_config_t lower = c; lower.limit_mb = 500;
    cell_quota_rearm(&lower, &s); CHECK(s.alerted == (CELL_QUOTA_WARNED | CELL_QUOTA_LIMITED));

    /* flash write policy */
    CHECK(cell_quota_save_due(0, 0, 0, 0, CELL_QUOTA_EV_WARN));
    CHECK(!cell_quota_save_due(MB - 1, 0, 10000, 0, 0));
    CHECK(!cell_quota_save_due(5 * MB, 0, 599, 0, 0));
    CHECK(cell_quota_save_due(MB, 0, 600, 0, 0));
    CHECK(cell_quota_save_due(10 * MB, 9 * MB, 1300, 700, 0));
    CHECK(!cell_quota_save_due(UINT64_MAX, UINT64_MAX, 1300, 700, 0));
    puts("cell quota ok");
    return 0;
}
'''


def run(core_text, program=PROGRAM):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'cell_quota.h').write_text((ROOT / 'main/cell_quota.h').read_text(encoding='utf-8'), encoding='utf-8')
        (tmp / 't.c').write_text(program.replace('@@CORE@@', core_text), encoding='utf-8')
        exe = tmp / ('t.exe' if os.name == 'nt' else 't')
        flags = ['-fsanitize=address,undefined'] if os.environ.get('CELL_SANITIZE') == '1' else []
        build = subprocess.run(['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter', *flags,
                                '-I', str(tmp), str(tmp / 't.c'), '-o', str(exe)], capture_output=True, text=True)
        if build.returncode:
            return build
        return subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)


ok = run(core)
assert ok.returncode == 0 and 'cell quota ok' in ok.stdout, (ok.returncode, ok.stdout, ok.stderr)
for old, new in (('if (day < reset_day) months--;', ''),
                 ('if (period > s->period) {', 'if (period && period != s->period) {'),
                 ('!(s->alerted & CELL_QUOTA_WARNED) && cq_warn_reached', 'cq_warn_reached'),
                 ('now_s - saved_at_s >= CELL_QUOTA_SAVE_S', 'true')):
    assert old in core, old
    assert run(core.replace(old, new)).returncode != 0, 'mutant survived: ' + old
print('cell quota: periods, one alert each, new month resets, clock changes kept, saturating, re-armed, bounded flash writes')


runtime = source[source.index("#define CQ_MAGIC"):source.index("static uint32_t uptime_s")]
runtime += "\n@@STUBS@@\n"
runtime += source[source.index("void cell_quota_tick("):source.index("void cell_quota_json(")]
RUNTIME = r"""
#define CELL_QUOTA_HOST_TEST 1
#include "cell_quota.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
typedef int esp_err_t;
typedef int portMUX_TYPE;
typedef int StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
#define EXT_RAM_BSS_ATTR
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG -2
#define ESP_ERR_TIMEOUT -3
#define pdTRUE 1
#define pdMS_TO_TICKS(ms) (ms)
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))
static int xSemaphoreTake(SemaphoreHandle_t lock, unsigned wait) {
    (void)wait;
    if (*lock) return 0;
    *lock = 1;
    return pdTRUE;
}
static void xSemaphoreGive(SemaphoreHandle_t lock) { assert(*lock); *lock = 0; }
@@CORE@@
int main(void)
{
    s_writer = &s_writer_storage;
    s_loaded = true;
    s_cfg = (cell_quota_config_t){.limit_mb=10, .reset_day=1};
    wire_total = 10; cell_quota_tick();
    cell_quota_config_t next = s_cfg;
    next.limit_mb = 20;
    char why[40];
    poll_during_save = 30;
    failed_write = true;
    assert(cell_quota_set(&next, false, why, sizeof why) != ESP_OK);
    assert(s_cfg.limit_mb == 10 && s_state.used == 10 && s_last_total == 10);
    assert(!committed && !*s_writer);
    wire_total = 40; cell_quota_tick();
    assert(s_state.used == 40);

    failed_write = false;
    poll_during_save = 50;
    assert(cell_quota_set(&next, false, why, sizeof why) == ESP_OK);
    assert(committed && s_cfg.limit_mb == 20 && s_state.used == 40);
    wire_total = 60; cell_quota_tick();
    assert(s_state.used == 60);

    poll_during_save = 70;
    assert(cell_quota_set(&next, true, why, sizeof why) == ESP_OK);
    assert(s_state.used == 0 && s_last_total == 70);
    wire_total = 73; cell_quota_tick();
    assert(s_state.used == 3);
    puts("cell quota runtime serialization and reset baseline PASS");
    return 0;
}
"""
STUBS = r"""
static uint64_t poll_during_save, wire_total;
static bool failed_write, committed;
static uint32_t uptime_s(void) { return 1; }
static uint32_t period_at(time_t wall, uint8_t reset_day) { (void)wall; (void)reset_day; return 999; }
static void report(int e, const cell_quota_config_t *c, const cell_quota_state_t *s, uint64_t previous)
{ (void)e; (void)c; (void)s; (void)previous; }
static void save_state(const cell_quota_state_t *state) { (void)state; }
void cell_quota_tick(void);
static esp_err_t nvs_param_txn_begin(void) { committed = false; return ESP_OK; }
static esp_err_t nvs_param_set_blob(const char *key, const void *value, size_t len)
{
    assert(*s_writer);
    (void)value; (void)len;
    wire_total = poll_during_save;
    cell_quota_tick();
    return failed_write && strcmp(key, "cell_quse") == 0 ? ESP_ERR_INVALID_ARG : ESP_OK;
}
static esp_err_t nvs_param_erase(const char *key) { (void)key; return ESP_OK; }
static esp_err_t nvs_param_txn_end(bool success) { committed = success; return ESP_OK; }
static void netif_hooks_get_mobile_bytes(uint64_t *rx, uint64_t *tx) { *rx = wire_total; *tx = 0; }
"""
ok = run(core + runtime.replace("@@STUBS@@", STUBS), RUNTIME)
assert ok.returncode == 0, (ok.returncode, ok.stdout, ok.stderr)
print(ok.stdout.strip())


hooks = (ROOT / "main/netif_hooks.c").read_text(encoding="utf-8")
mobile = hooks[hooks.index("static portMUX_TYPE s_mobile_bytes_lock"):hooks.index("/* Wire-byte counters.")]
mobile += hooks[hooks.index("static err_t usbnet_input_hook"):hooks.index("bool netif_hooks_register_usbnet")]
mobile += hooks[hooks.index("static err_t ppp_output_hook"):hooks.index("bool netif_hooks_install_ppp")]
COUNTERS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef int portMUX_TYPE;
typedef int err_t;
typedef uint32_t ip4_addr_t;
struct netif { int dummy; };
struct pbuf { uint16_t tot_len; };
#define ERR_OK 0
#define ERR_VAL -1
#define ACL_FROM_ESP 0
#define ACL_TO_ESP 1
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(lock) do { assert(!*(lock)); *(lock)=1; } while(0)
#define taskEXIT_CRITICAL(lock) do { assert(*(lock)); *(lock)=0; } while(0)
static bool denied;
static uint64_t s_ppp_bytes_in, s_ppp_bytes_out, s_usbnet_bytes_in, s_usbnet_bytes_out;
static err_t (*original_usbnet_input)(struct pbuf *, struct netif *);
static err_t (*original_usbnet_linkoutput)(struct netif *, struct pbuf *);
static err_t (*original_ppp_output)(struct netif *, struct pbuf *, const ip4_addr_t *);
static bool acl_check_and_tap(int direction, struct pbuf *p, bool none)
{ (void)direction; (void)p; (void)none; return denied; }
static bool acl_check_ip_packet(int direction, struct pbuf *p)
{ (void)direction; (void)p; return denied; }
static bool acl_drops(bool drop) { return drop; }
static void pbuf_free(struct pbuf *p) { (void)p; }
@@CORE@@
static err_t result;
static err_t driver_usb(struct netif *n, struct pbuf *p)
{ (void)n; (void)p; assert(!s_mobile_bytes_lock); return result; }
static err_t driver_ppp(struct netif *n, struct pbuf *p, const ip4_addr_t *ip)
{ (void)ip; return driver_usb(n,p); }

int main(void)
{
    original_usbnet_linkoutput=driver_usb;
    original_ppp_output=driver_ppp;
    s_ppp_bytes_in=100; s_usbnet_bytes_in=512;
    s_ppp_bytes_out=UINT32_MAX; s_usbnet_bytes_out=30;
    struct netif n={0}; struct pbuf p={.tot_len=45};
    uint64_t rx,tx;
    denied=true;
    assert(usbnet_linkoutput_hook(&n,&p)==ERR_OK && ppp_output_hook(&n,&p,NULL)==ERR_OK);
    netif_hooks_get_mobile_bytes(&rx,&tx);
    assert(rx==612 && tx==UINT64_C(4294967325));

    denied=false; result=ERR_VAL;
    assert(usbnet_linkoutput_hook(&n,&p)==ERR_VAL && ppp_output_hook(&n,&p,NULL)==ERR_VAL);
    netif_hooks_get_mobile_bytes(&rx,&tx);
    assert(tx==UINT64_C(4294967325));

    result=ERR_OK;
    assert(usbnet_linkoutput_hook(&n,&p)==ERR_OK && ppp_output_hook(&n,&p,NULL)==ERR_OK);
    netif_hooks_get_mobile_bytes(&rx,&tx);
    assert(rx==612 && tx==UINT64_C(4294967415));
    puts("PPP and USB network accounting across 4 GiB PASS");
    return 0;
}
"""
ok = run(mobile, COUNTERS)
assert ok.returncode == 0, (ok.returncode, ok.stdout, ok.stderr)
print(ok.stdout.strip())
