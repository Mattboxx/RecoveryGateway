"""microSD probing of the SD recorder (actual components/sdlog/sdlog.c code).

Compiles the real probe_card_locked(), sdlog_init(), sdlog_enable() and the
probing start of sdlog_get_status() with a scripted card slot:
- recorder off at boot: the SD bus is not touched (no mount attempt);
- the first status read probes once; further reads do not probe again;
- enabling the recorder looks again (a card inserted later is found), and
  without a card it is refused and stays off;
- recorder on at boot: probed at boot, found card starts the writer; on
  without a card: the flag is kept off at runtime;
- a mounted card is never probed again.
Found on board A (2026-11-17): every boot logged three SD init errors with
the recorder off and no card.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'components/sdlog/sdlog.c').read_text(encoding='utf-8').replace('\r\n', '\n')
HDR = (ROOT / 'components/sdlog/include/sdlog.h').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(signature):
    i = SRC.index(signature)
    return SRC[i:SRC.index('\n}\n', i) + 3]


status_t = HDR[HDR.index('typedef struct {', HDR.index('#define SDLOG_LVL_INFO')):HDR.index('} sdlog_status_t;') + len('} sdlog_status_t;')]
get_status = function('void sdlog_get_status(sdlog_status_t *out)')
probe_part = get_status[:get_status.index('    if (!out) return;')] + '    (void)out;\n}\n'
code = function('static void probe_card_locked(bool retry)') + function('esp_err_t sdlog_init(void)') \
    + function('esp_err_t sdlog_enable(uint8_t sd_level)') + probe_part

PROGRAM = r'''
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_STATE 0x103
#define SDLOG_LVL_OFF 0
#define SDLOG_LVL_ERROR 1
#define SDLOG_LVL_WARN 2
#define SDLOG_LVL_INFO 3
#define SDLOG_NAME_MAX 16
#define NVS_KEY_SDLVL "sdlvl"
#define NVS_KEY_ENABLED "sden"
#define ESP_LOGW(...) ((void)0)
#define portMAX_DELAY 0
typedef int StaticSemaphore_t;
typedef void *SemaphoreHandle_t;
static int g_locks, g_lock_depth;
static SemaphoreHandle_t xSemaphoreCreateMutex(void) {static int m; return &m;}
static SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *s) {return s;}
static int xSemaphoreTake(SemaphoreHandle_t m, int t) {(void)m; (void)t; assert(g_lock_depth == 0); g_lock_depth++; g_locks++; return 1;}
static int xSemaphoreGive(SemaphoreHandle_t m) {(void)m; assert(g_lock_depth == 1); g_lock_depth--; return 1;}
typedef int (*vprintf_like_t)(const char *, __builtin_va_list);
static vprintf_like_t esp_log_set_vprintf(vprintf_like_t f) {(void)f; return 0;}
static int sdlog_vprintf(const char *fmt, __builtin_va_list a) {(void)fmt; (void)a; return 0;}
@@STATUS_T@@
static SemaphoreHandle_t s_state_mutex, s_file_mutex, s_ml_mutex;
static StaticSemaphore_t s_ml_mutex_storage;
static vprintf_like_t s_original_vprintf;
static atomic_bool s_enabled, s_present;
static _Atomic uint8_t s_sd_level = SDLOG_LVL_WARN;
static bool s_probed;
static uint32_t s_boot_count;
/* scripted slot */
static bool card_inserted, saved_enabled;
static int mounts, writers, saves;
static esp_err_t mount_card(void) {mounts++; assert(g_lock_depth == 1 || !s_state_mutex || g_locks == 0); if (card_inserted) atomic_store(&s_present, true); return card_inserted ? ESP_OK : 0x107;}
static void load_config(void) {atomic_store(&s_enabled, saved_enabled);}
static uint32_t bump_boot_counter(void) {return 1;}
static void start_writer(void) {writers++;}
static void apply_master_level(void) {}
static void save_u8(const char *k, uint8_t v) {(void)k; (void)v; saves++;}
static void reset(bool enabled, bool card)
{
    s_state_mutex = s_file_mutex = s_ml_mutex = NULL; s_probed = false; mounts = writers = saves = 0; g_locks = 0;
    atomic_store(&s_present, false); atomic_store(&s_enabled, false); saved_enabled = enabled; card_inserted = card;
}
@@CODE@@
int main(void)
{
    sdlog_status_t st;
    /* off at boot, no card: no probe at boot; the first status read probes once */
    reset(false, false);
    assert(sdlog_init() == ESP_OK && mounts == 0);
    sdlog_get_status(&st); assert(mounts == 1);
    sdlog_get_status(&st); sdlog_get_status(&st); assert(mounts == 1);
    /* enabling without a card: looks again, refused, stays off */
    assert(sdlog_enable(SDLOG_LVL_WARN) == ESP_ERR_INVALID_STATE && mounts == 2 && !atomic_load(&s_enabled) && saves == 0);
    /* card inserted later: enabling finds it and starts the writer */
    card_inserted = true;
    assert(sdlog_enable(SDLOG_LVL_INFO) == ESP_OK && mounts == 3 && atomic_load(&s_present) && atomic_load(&s_enabled) && writers == 1);
    /* mounted: never probed again */
    sdlog_get_status(&st); assert(sdlog_enable(SDLOG_LVL_WARN) == ESP_OK && mounts == 3);
    /* off at boot with a card: still not touched until looked at */
    reset(false, true);
    assert(sdlog_init() == ESP_OK && mounts == 0 && !atomic_load(&s_present));
    sdlog_get_status(&st); assert(mounts == 1 && atomic_load(&s_present));
    /* on at boot with a card: probed at boot, writer started */
    reset(true, true);
    assert(sdlog_init() == ESP_OK && mounts == 1 && writers == 1);
    sdlog_get_status(&st); assert(mounts == 1);
    /* on at boot without a card: probed, kept off at runtime */
    reset(true, false);
    assert(sdlog_init() == ESP_OK && mounts == 1 && !atomic_load(&s_enabled) && writers == 0);
    sdlog_get_status(&st); assert(mounts == 1);              /* already tried this boot */
    puts("sdlog probe ok");
    return 0;
}
'''


def run(code_text):
    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / 't.c'
        c.write_text(PROGRAM.replace('@@STATUS_T@@', status_t).replace('@@CODE@@', code_text), encoding='utf-8')
        exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
        flags = ['-fsanitize=address,undefined'] if os.environ.get('SDLOG_SANITIZE') == '1' else []
        b = subprocess.run(['gcc', '-std=gnu11', '-O1', '-Wall', '-Wno-unused-function', '-Wno-unused-variable', *flags, str(c), '-o', str(exe)],
                           capture_output=True, text=True)
        if b.returncode:
            return b
        return subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)


ok = run(code)
assert ok.returncode == 0 and 'sdlog probe ok' in ok.stdout, (ok.returncode, ok.stdout, ok.stderr[-2000:])
old = '    if (atomic_load(&s_enabled)) probe_card_locked(false);   /* off: no SD probe at boot */'
assert old in code
assert run(code.replace(old, '    probe_card_locked(false);')).returncode != 0, 'probing at every boot must fail'
print('sdlog probe: no SD probe at boot while the recorder is off; probed on first look or when enabled; never twice')
