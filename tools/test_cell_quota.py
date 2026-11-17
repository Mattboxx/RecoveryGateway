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
    CHECK(cell_quota_add(&c, &s, 1 * MB, nov - 1, NULL) == 0 && s.period == nov - 1 && s.used == 1051 * MB);       /* clock set back */
    CHECK(cell_quota_add(&c, &s, 0, nov, NULL) == CELL_QUOTA_EV_NEW_PERIOD);                                       /* forward again: new period */
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
    puts("cell quota ok");
    return 0;
}
'''


def run(core_text):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'cell_quota.h').write_text((ROOT / 'main/cell_quota.h').read_text(encoding='utf-8'), encoding='utf-8')
        (tmp / 't.c').write_text(PROGRAM.replace('@@CORE@@', core_text), encoding='utf-8')
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
                 ('if (s->period && period > s->period) {', 'if (s->period) {'),
                 ('!(s->alerted & CELL_QUOTA_WARNED) && cq_warn_reached', 'cq_warn_reached'),
                 ('&& now_s - saved_at_s >= CELL_QUOTA_SAVE_S', '')):
    assert old in core, old
    assert run(core.replace(old, new)).returncode != 0, 'mutant survived: ' + old
print('cell quota: periods, one alert each, new month resets, clock changes kept, saturating, re-armed, bounded flash writes')
