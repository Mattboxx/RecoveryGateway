"""Date and time on microSD log lines (actual components/sdlog/sdlog.c).

Log lines carried only the time since boot ("W (123456) tag: ..."), so a log
read later did not say when anything happened. The microSD recorder now
starts each line with "YYYY-MM-DD HH:MM:SS " in the device's time zone once
the clock is set (nothing before NTP); the live view shows the date in the
browser from the device's boot time (browser scenario in
test_automation_ui.cjs). Checked here on the actual prefix function: no
prefix before the clock is set, the device time zone applied, a buffer too
small never overflows, and the SD line keeps its text after the prefix
within the line limit.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'components/sdlog/sdlog.c').read_text(encoding='utf-8').replace('\r\n', '\n')
WEB = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(sig):
    start = SRC.index(sig)
    return SRC[start:SRC.index('\n}\n', start) + 3]


prefix = function('static int sdlog_time_prefix(char *out, size_t cap, time_t now)')
hook = function('static int sdlog_vprintf(const char *fmt, va_list args)')
assert 'int tp = sdlog_time_prefix(m.data, sizeof m.data, time(NULL));' in hook
assert 'if (dl > SDLOG_LINE_MAX - 1 - tp) dl = SDLOG_LINE_MAX - 1 - tp;' in hook
raw = WEB[WEB.index('static esp_err_t log_raw_handler(httpd_req_t *req)'):]
raw = raw[:raw.index('\n}\n')]
assert '- (long long)esp_log_timestamp();' in raw and 'tv.tv_sec >= 1700000000' in raw and '\\"boot_ms\\":%lld' in raw

PROGRAM = r'''
#define _POSIX_THREAD_SAFE_FUNCTIONS 200112L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define SET_TZ(v) _putenv("TZ=" v)
#else
#define SET_TZ(v) setenv("TZ", v, 1)
#endif
@@PREFIX@@
int main(void) {
    char b[64];
    SET_TZ("UTC0"); tzset();
    memset(b, 'x', sizeof b);
    assert(sdlog_time_prefix(b, sizeof b, 0) == 0 && b[0] == 'x');            /* clock not set */
    assert(sdlog_time_prefix(b, sizeof b, 1699999999) == 0);
    time_t t = 1794996000;                                                     /* 2026-11-18 10:00:00 UTC */
    assert(sdlog_time_prefix(b, sizeof b, t) == 20 && !memcmp(b, "2026-11-18 10:00:00 ", 20));
    SET_TZ("CET-1"); tzset();                                         /* the device's zone */
    assert(sdlog_time_prefix(b, sizeof b, t) == 20 && !memcmp(b, "2026-11-18 11:00:00 ", 20));
    memset(b, 'x', sizeof b);
    assert(sdlog_time_prefix(b, 20, t) == 0 && b[20] == 'x');                 /* no room: nothing */
    assert(sdlog_time_prefix(b, 21, t) == 20 && b[20] == 0);
    puts("PASS: actual microSD time prefix: none before the clock is set, device time zone, bounded");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='log-time-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@PREFIX@@', prefix), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('log time: microSD lines carry date and time once the clock is set')
