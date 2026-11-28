"""microSD probing of the SD recorder (actual components/sdlog/sdlog.c code).

Compiles the actual initialization, status, check and enable paths with
a scripted card slot. Passive diagnostics never mount, expected boot
behavior is retained, and the owner can retry an explicit check.
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
code = ''.join(function(signature) for signature in (
    'static void probe_card_locked(void)', 'bool sdlog_check_card(void)',
    'esp_err_t sdlog_init(void)', 'esp_err_t sdlog_enable(uint8_t sd_level)',
    'void sdlog_get_status(sdlog_status_t *out)',
))


PROGRAM = r'''
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
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
#define pdMS_TO_TICKS(t) (t)
#define pdTRUE 1
#define SDLOG_MOUNT_POINT "/sdcard"
#define SDLOG_DIR "/sdcard/eslog"
#define DT_DIR 4
typedef void DIR;
struct dirent { int d_type; char d_name[16]; };
static DIR *opendir(const char *path) {(void)path; return NULL;}
static struct dirent *readdir(DIR *dir) {(void)dir; return NULL;}
static void closedir(DIR *dir) {(void)dir;}
static size_t strlcpy(char *dst, const char *src, size_t n)
{
    return (size_t)snprintf(dst, n, "%s", src);
}
static esp_err_t esp_vfs_fat_info(const char *path, uint64_t *total, uint64_t *freeb)
{
    (void)path; *total = 32ULL << 20; *freeb = 16ULL << 20; return ESP_OK;
}
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
static atomic_bool s_checked;
static _Atomic uint8_t s_console_level = SDLOG_LVL_WARN;
static _Atomic uint32_t s_dropped;
static const char s_cur_name[] = "";
static uint64_t s_bytes_written;
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
    s_state_mutex = s_file_mutex = s_ml_mutex = NULL; atomic_store(&s_checked, false); mounts = writers = saves = 0; g_locks = 0;
    atomic_store(&s_present, false); atomic_store(&s_enabled, false); saved_enabled = enabled; card_inserted = card;
}
@@CODE@@
int main(void)
{
    sdlog_status_t st;
    reset(false, false);
    assert(sdlog_init() == ESP_OK && mounts == 0);
    for (int i = 0; i < 5; i++) {
        sdlog_get_status(&st);
        if (mounts != 0) {
            fputs("passive status attempted a mount\n", stderr);
            return 17;
        }
        assert(!st.checked && !st.present && !st.enabled);
        assert(st.console_level == SDLOG_LVL_WARN);
    }
    assert(!sdlog_check_card() && mounts == 1 && writers == 0 && saves == 0);
    sdlog_get_status(&st);
    assert(st.checked && !st.present && !st.enabled && mounts == 1);
    assert(sdlog_enable(SDLOG_LVL_WARN) == ESP_ERR_INVALID_STATE && mounts == 2 && saves == 0);

    /* Explicit retry after insertion, without starting or enabling the writer. */
    card_inserted = true;
    assert(sdlog_check_card() && mounts == 3 && writers == 0 && saves == 0);
    sdlog_get_status(&st);
    assert(st.checked && st.present && !st.enabled && st.card_mb == 32 && st.free_mb == 16);
    assert(sdlog_enable(SDLOG_LVL_INFO) == ESP_OK && mounts == 3 && writers == 1);
    assert(sdlog_check_card() && mounts == 3);
    sdlog_get_status(&st);
    assert(st.enabled && st.sd_level == SDLOG_LVL_INFO);

    reset(false, true);
    assert(sdlog_init() == ESP_OK && mounts == 0);
    sdlog_get_status(&st);
    assert(!st.checked && !st.present && mounts == 0);

    reset(true, true);
    assert(sdlog_init() == ESP_OK && mounts == 1 && writers == 1);
    sdlog_get_status(&st);
    assert(st.checked && st.present && st.enabled && mounts == 1);

    reset(true, false);
    assert(sdlog_init() == ESP_OK && mounts == 1 && writers == 0);
    sdlog_get_status(&st);
    assert(st.checked && !st.present && !st.enabled && mounts == 1);
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
legacy = code.replace('    if (!out) return;', '    (void)sdlog_check_card();\n    if (!out) return;')
regression = run(legacy)
assert regression.returncode == 17 and 'passive status attempted a mount' in regression.stderr, regression
print('PASS: passive SD status, explicit check/retry, recording enable and boot behavior')
