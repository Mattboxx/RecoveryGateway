"""Web UI session admission (main/web_idle.c), compiled from the source on the host.

Checks the idle clock (open, receive and send activity), the 5 s close
threshold, sessions that disappear, unknown sessions found by the sweep, a
full tracking table, a refused close that is retried, socket error mapping
without activity, and a sweep timer that cannot be created. The web_ui.c
wiring (no LRU purge, open_fn, start after httpd_start) is checked
structurally. HOTLOOP_SANITIZE=1 enables ASan/UBSan on Linux.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'main/web_idle.c').read_text(encoding='utf-8')
UI = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8').replace('\r\n', '\n')

start = UI.index('conf.lru_purge_enable         = false;')
assert 'conf.open_fn                  = web_open;' in UI[start:start + 200]
web_open = UI[UI.index('static esp_err_t web_open(httpd_handle_t hd, int fd)'):]
web_open = web_open[:web_open.index('\n}\n')]
assert web_open.rstrip().endswith('return web_idle_open(hd, fd);'), 'every accepted connection still gets the idle clock'
# A connection outside the administration scope is closed silently (no
# "session creation failed" error line per attempt from ESP-IDF).
assert 'return web_idle_refuse(hd, fd);' in web_open and 'return ESP_FAIL;' not in web_open
assert 'cJSON_AddNumberToObject(root, "admin_refused", web_idle_refused());' in UI
assert 'lru_purge_enable         = true' not in UI
assert UI.index('web_idle_start(server);') > UI.index('esp_err_t start = httpd_start(&server, &conf);')

STUBS = {
    'esp_http_server.h': r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
typedef void *httpd_handle_t;
#define HTTPD_SOCK_ERR_FAIL -1
#define HTTPD_SOCK_ERR_INVALID -2
#define HTTPD_SOCK_ERR_TIMEOUT -3
typedef int (*httpd_send_func_t)(httpd_handle_t, int, const char *, size_t, int);
typedef int (*httpd_recv_func_t)(httpd_handle_t, int, char *, size_t, int);
typedef void (*httpd_work_fn_t)(void *);
esp_err_t httpd_sess_set_send_override(httpd_handle_t, int, httpd_send_func_t);
esp_err_t httpd_sess_set_recv_override(httpd_handle_t, int, httpd_recv_func_t);
esp_err_t httpd_sess_trigger_close(httpd_handle_t, int);
esp_err_t httpd_get_client_list(httpd_handle_t, size_t *, int *);
esp_err_t httpd_queue_work(httpd_handle_t, httpd_work_fn_t, void *);
''',
    'esp_log.h': '#pragma once\n#define ESP_LOGW(tag, ...) ((void)(tag))\n',
    'esp_timer.h': r'''
#pragma once
#include <stdint.h>
typedef struct timer *esp_timer_handle_t;
typedef struct { void (*callback)(void *); const char *name; } esp_timer_create_args_t;
int64_t esp_timer_get_time(void);
int esp_timer_create(const esp_timer_create_args_t *, esp_timer_handle_t *);
int esp_timer_start_periodic(esp_timer_handle_t, uint64_t);
int esp_timer_stop(esp_timer_handle_t);
''',
    'lwip/sockets.h': '#pragma once\n#include <stddef.h>\n#define SHUT_RDWR 2\n'
                      'int send(int, const void *, size_t, int);\nint recv(int, void *, size_t, int);\nint shutdown(int, int);\n',
}

TEST = r'''
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "web_idle.h"
#include "esp_timer.h"
#include "lwip/sockets.h"

static int64_t now_us;
int64_t esp_timer_get_time(void) { return now_us; }
static httpd_send_func_t send_fn;
static httpd_recv_func_t recv_fn;
static int override_fail;   /* 1: recv override refused, 2: send override refused */
esp_err_t httpd_sess_set_send_override(httpd_handle_t h, int fd, httpd_send_func_t f) { (void)h; (void)fd; if (override_fail == 2) return ESP_FAIL; send_fn = f; return ESP_OK; }
esp_err_t httpd_sess_set_recv_override(httpd_handle_t h, int fd, httpd_recv_func_t f) { (void)h; (void)fd; if (override_fail == 1) return ESP_FAIL; recv_fn = f; return ESP_OK; }
static int shut_fd = -1, shut_how, shuts;
int shutdown(int fd, int how) { shut_fd = fd; shut_how = how; shuts++; return 0; }
static int closed[64], n_closed, refuse_close;
esp_err_t httpd_sess_trigger_close(httpd_handle_t h, int fd) {
    (void)h;
    if (refuse_close) return ESP_FAIL;
    closed[n_closed++] = fd; return ESP_OK;
}
static int clients[16]; static size_t n_clients;
esp_err_t httpd_get_client_list(httpd_handle_t h, size_t *n, int *fds) {
    (void)h; assert(*n >= n_clients); for (size_t i = 0; i < n_clients; i++) fds[i] = clients[i]; *n = n_clients; return ESP_OK;
}
static httpd_work_fn_t work; static void *work_arg;
esp_err_t httpd_queue_work(httpd_handle_t h, httpd_work_fn_t f, void *a) { (void)h; work = f; work_arg = a; return ESP_OK; }
static void (*timer_cb)(void *); static int timer_fail, timer_running;
int esp_timer_create(const esp_timer_create_args_t *a, esp_timer_handle_t *t) {
    if (timer_fail) return -1;
    timer_cb = a->callback; *t = (esp_timer_handle_t)1; return 0;
}
int esp_timer_start_periodic(esp_timer_handle_t t, uint64_t us) { (void)t; assert(us == 1000000); timer_running = 1; return 0; }
int esp_timer_stop(esp_timer_handle_t t) { (void)t; timer_running = 0; return 0; }
static int sock_ret, sock_errno;
int send(int fd, const void *b, size_t n, int f) { (void)fd; (void)b; (void)f; if (sock_ret < 0) { errno = sock_errno; return -1; } return (int)n; }
int recv(int fd, void *b, size_t n, int f) { (void)fd; (void)b; (void)f; if (sock_ret < 0) { errno = sock_errno; return -1; } return (int)n; }

#define S(x) ((int64_t)(x) * 1000000)
static void sweep_at(int64_t t) { now_us = t; timer_cb(NULL); assert(work); work(work_arg); work = NULL; }

int main(void) {
    httpd_handle_t hd = (httpd_handle_t)0x1234;
    char buf[8] = "x";
    /* A sweep timer that cannot be created: start/stop still work. */
    timer_fail = 1; web_idle_start(hd); assert(!timer_running); web_idle_stop();
    timer_fail = 0; web_idle_start(hd); assert(timer_running && timer_cb);
    /* A fresh session waiting for its request is not closed before 5 s. */
    now_us = S(100); assert(web_idle_open(hd, 54) == ESP_OK && send_fn && recv_fn);
    clients[0] = 54; n_clients = 1;
    sweep_at(S(104) + 900000); assert(n_closed == 0);
    /* Receive and send activity restart the idle clock. */
    now_us = S(104) + 950000; assert(recv_fn(hd, 54, buf, 1, 0) == 1);
    sweep_at(S(109)); assert(n_closed == 0);
    now_us = S(109) + 500000; assert(send_fn(hd, 54, buf, 1, 0) == 1);
    sweep_at(S(114) + 400000); assert(n_closed == 0);
    sweep_at(S(114) + 500000); assert(n_closed == 1 && closed[0] == 54);
    /* Socket errors keep the default mapping and are not activity. */
    now_us = S(200); web_idle_open(hd, 55); clients[0] = 55; n_clients = 1;
    sock_ret = -1;
    sock_errno = EAGAIN; now_us = S(204); assert(send_fn(hd, 55, buf, 1, 0) == HTTPD_SOCK_ERR_TIMEOUT);
    sock_errno = EINTR; assert(recv_fn(hd, 55, buf, 1, 0) == HTTPD_SOCK_ERR_TIMEOUT);
    sock_errno = EBADF; assert(send_fn(hd, 55, buf, 1, 0) == HTTPD_SOCK_ERR_INVALID);
    sock_errno = ENOTSOCK; assert(recv_fn(hd, 55, buf, 1, 0) == HTTPD_SOCK_ERR_INVALID);
    sock_errno = ECONNRESET; assert(send_fn(hd, 55, buf, 1, 0) == HTTPD_SOCK_ERR_FAIL);
    assert(send_fn(hd, 55, NULL, 1, 0) == HTTPD_SOCK_ERR_INVALID && recv_fn(hd, 55, NULL, 1, 0) == HTTPD_SOCK_ERR_INVALID);
    sock_ret = 0;
    sweep_at(S(205)); assert(n_closed == 2 && closed[1] == 55);   /* errors did not reset the clock */
    /* A refused close is retried by the next sweep. */
    now_us = S(300); web_idle_open(hd, 56); clients[0] = 56;
    refuse_close = 1; sweep_at(S(306)); assert(n_closed == 2);
    refuse_close = 0; sweep_at(S(307)); assert(n_closed == 3 && closed[2] == 56);
    /* Sessions found only by the sweep start their clock then; gone ones are forgotten. */
    clients[0] = 57; clients[1] = 58; n_clients = 2;
    sweep_at(S(400)); assert(n_closed == 3);
    n_clients = 1;                                    /* 58 closed by its client */
    sweep_at(S(404)); assert(n_closed == 3);
    sweep_at(S(405)); assert(n_closed == 4 && closed[3] == 57);
    /* Full table (WEB_IDLE_SLOTS): the oldest entry makes room, nothing crashes. */
    for (int i = 0; i < WEB_IDLE_SLOTS + 2; i++) { now_us = S(500) + i; web_idle_open(hd, 60 + i); }   /* 60, 61 evicted */
    for (int i = 0; i < WEB_IDLE_SLOTS; i++) clients[i] = 62 + i;
    n_clients = WEB_IDLE_SLOTS;
    sweep_at(S(504) + 999999); assert(n_closed == 4);   /* none idle 5 s yet */
    sweep_at(S(505) + 100);
    assert(n_closed == 4 + WEB_IDLE_SLOTS);
    for (int i = 4; i < n_closed; i++) assert(closed[i] >= 62 && closed[i] < 62 + WEB_IDLE_SLOTS);
    assert(web_idle_closed() == (uint32_t)n_closed);
    /* Refused connection (outside the administration scope): accepted by the
     * server so ESP-IDF logs nothing, but nothing is read or sent and the
     * socket is shut down at once; the idle clock is the backstop. */
    send_fn = NULL; recv_fn = NULL; sock_ret = 0;
    now_us = S(600); assert(web_idle_refuse(hd, 70) == ESP_OK && web_idle_refused() == 1);
    assert(shuts == 1 && shut_fd == 70 && shut_how == SHUT_RDWR && send_fn && recv_fn);
    assert(recv_fn(hd, 70, buf, sizeof buf, 0) == HTTPD_SOCK_ERR_FAIL);   /* data pending: still never read */
    assert(send_fn(hd, 70, buf, 1, 0) == HTTPD_SOCK_ERR_FAIL);
    assert(send_fn(hd, 70, NULL, 0, 0) == HTTPD_SOCK_ERR_FAIL && recv_fn(hd, 70, NULL, 0, 0) == HTTPD_SOCK_ERR_FAIL);
    clients[0] = 70; n_clients = 1; int before = n_closed;
    sweep_at(S(604) + 999999); assert(n_closed == before);
    sweep_at(S(605)); assert(n_closed == before + 1 && closed[before] == 70);   /* backstop close */
    /* An override that cannot be set: refused the old way (fail closed, the
     * server closes it), no shutdown, not counted. */
    for (override_fail = 1; override_fail <= 2; override_fail++) {
        send_fn = NULL; recv_fn = NULL;
        assert(web_idle_refuse(hd, 71) == ESP_FAIL && shuts == 1 && web_idle_refused() == 1);
        assert(override_fail != 2 || recv_fn(hd, 71, buf, sizeof buf, 0) == HTTPD_SOCK_ERR_FAIL);   /* recv already refusing */
    }
    override_fail = 0;
    assert(web_idle_refuse(hd, 72) == ESP_OK && web_idle_refused() == 2 && shut_fd == 72);
    web_idle_stop(); assert(!timer_running);
    timer_cb(NULL); assert(!work);                    /* stopped: no work queued */
    puts("PASS: web_idle (fresh session kept < 5 s, recv/send restart the clock, close at 5 s, errors mapped and "
         "not activity, refused close retried, sweep-found and gone sessions, full table, timer failure; "
         "out-of-scope connection never read, shut down, counted, idle backstop, override failure fails closed); "
         "web_ui wiring structural");
    return 0;
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix='web-idle-') as folder:
        path = Path(folder)
        for name, text in STUBS.items():
            (path / name).parent.mkdir(parents=True, exist_ok=True)
            (path / name).write_text(text, encoding='utf-8')
        (path / 'test.c').write_text(TEST, encoding='utf-8')
        exe = path / ('test.exe' if os.name == 'nt' else 'test')
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(path), '-I', str(ROOT / 'main')]
        if os.environ.get('HOTLOOP_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(ROOT / 'main/web_idle.c'), str(path / 'test.c'),
                        '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True, timeout=30)


if __name__ == '__main__':
    main()
