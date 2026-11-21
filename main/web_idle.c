/* Web UI session admission without closing waiting requests.
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The HTTP server used to close its least-recently-used session to admit a
 * new connection (lru_purge). The session it picked was usually one accepted
 * a moment earlier whose request bytes had not arrived yet, so the client
 * saw a reset: PERF-09 on 3.0.7-beta.2 recorded connection resets after
 * 0.2-0.5 s in bursts of 16 parallel status reads (3.0.6 behaved the same).
 *
 * Now the server keeps its slots and new connections wait in the listen
 * backlog. Sessions with no traffic in either direction for WEB_IDLE_CLOSE_MS
 * are closed, so idle keep-alive connections cannot hold every slot. A UI
 * polling once a second is never idle that long. The sweep runs as httpd
 * work, so it never runs while a handler does. */
#include "web_idle.h"

#include <errno.h>
#include <stdatomic.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "lwip/sockets.h"

static const char *TAG = "web_idle";

typedef struct { int fd; bool async_owned; int64_t last_us; } web_idle_slot_t;
static web_idle_slot_t s_slots[WEB_IDLE_SLOTS];
static portMUX_TYPE s_slot_lock = portMUX_INITIALIZER_UNLOCKED;
static esp_timer_handle_t s_timer;
static _Atomic(httpd_handle_t) s_server;
static atomic_bool s_sweep_pending;
static uint32_t s_closed;

static web_idle_slot_t *slot_find(int fd)
{
    for (int i = 0; i < WEB_IDLE_SLOTS; i++)
        if (s_slots[i].fd == fd) return &s_slots[i];
    return NULL;
}

/* A server has fewer live sessions than tracking slots. Only evict
 * entries without an async owner. The caller holds s_slot_lock. */
static web_idle_slot_t *track_slot(int fd, int64_t now_us)
{
    web_idle_slot_t *s = slot_find(fd);
    if (!s) s = slot_find(-1);
    if (!s) {
        for (int i = 0; i < WEB_IDLE_SLOTS; i++) {
            if (!s_slots[i].async_owned && (!s || s_slots[i].last_us < s->last_us))
                s = &s_slots[i];
        }
    }
    if (s) {
        if (s->fd != fd) *s = (web_idle_slot_t){ .fd = fd };
        s->last_us = now_us;
    }
    return s;
}

void web_idle_touch(int fd, int64_t now_us)
{
    taskENTER_CRITICAL(&s_slot_lock);
    track_slot(fd, now_us);
    taskEXIT_CRITICAL(&s_slot_lock);
}

static void set_async_owner(int fd, bool owned)
{
    int64_t now_us = esp_timer_get_time();
    taskENTER_CRITICAL(&s_slot_lock);
    web_idle_slot_t *slot = track_slot(fd, now_us);
    if (slot) slot->async_owned = owned;
    taskEXIT_CRITICAL(&s_slot_lock);
}

esp_err_t web_idle_async_begin(httpd_req_t *req, httpd_req_t **copy)
{
    int fd = httpd_req_to_sockfd(req);
    if (fd < 0) return ESP_ERR_INVALID_ARG;
    esp_err_t err = httpd_req_async_handler_begin(req, copy);
    if (err == ESP_OK) set_async_owner(fd, true);
    return err;
}

void web_idle_async_complete(httpd_req_t *req, esp_err_t result)
{
    int fd = httpd_req_to_sockfd(req);
    if (fd >= 0) {
        if (result != ESP_OK) (void)shutdown(fd, SHUT_RDWR);
        /* Start a fresh idle window before the SDK returns the slot to the
         * server. The sweep will never close the still-active response. */
        set_async_owner(fd, false);
    }
    httpd_req_async_handler_complete(req);
}

/* Socket error codes as the server's default send/recv report them. */
static int sock_err(void)
{
    switch (errno) {
    case EAGAIN:
    case EINTR:  return HTTPD_SOCK_ERR_TIMEOUT;
    case EINVAL:
    case EBADF:
    case EFAULT:
    case ENOTSOCK: return HTTPD_SOCK_ERR_INVALID;
    default:     return HTTPD_SOCK_ERR_FAIL;
    }
}

static int idle_send(httpd_handle_t hd, int fd, const char *buf, size_t len, int flags)
{
    (void)hd;
    if (!buf) return HTTPD_SOCK_ERR_INVALID;
    int ret = send(fd, buf, len, flags);
    if (ret < 0) return sock_err();
    web_idle_touch(fd, esp_timer_get_time());
    return ret;
}

static int idle_recv(httpd_handle_t hd, int fd, char *buf, size_t len, int flags)
{
    (void)hd;
    if (!buf) return HTTPD_SOCK_ERR_INVALID;
    int ret = recv(fd, buf, len, flags);
    if (ret < 0) return sock_err();
    web_idle_touch(fd, esp_timer_get_time());
    return ret;
}

esp_err_t web_idle_open(httpd_handle_t hd, int fd)
{
    web_idle_touch(fd, esp_timer_get_time());
    httpd_sess_set_send_override(hd, fd, idle_send);
    httpd_sess_set_recv_override(hd, fd, idle_recv);
    return ESP_OK;
}

static uint32_t s_refused;

static int refused_send(httpd_handle_t hd, int fd, const char *buf, size_t len, int flags)
{
    (void)hd; (void)fd; (void)buf; (void)len; (void)flags;
    return HTTPD_SOCK_ERR_FAIL;
}

static int refused_recv(httpd_handle_t hd, int fd, char *buf, size_t len, int flags)
{
    (void)hd; (void)fd; (void)buf; (void)len; (void)flags;
    return HTTPD_SOCK_ERR_FAIL;
}

/* A connection the administration is not allowed on. Failing open_fn made
 * ESP-IDF log "session creation failed" at error level for every attempt, so
 * a LAN device retrying filled the log. The session is kept instead, with a
 * receive and send that always fail: not a byte of a request is read and no
 * handler runs. The socket is shut down, which wakes the server's select at
 * once; the first receive fails and the server deletes the session without a
 * log line. The idle clock is a backstop. If an override cannot be set, the
 * connection is refused the old way (fail closed, logged). */
esp_err_t web_idle_refuse(httpd_handle_t hd, int fd)
{
    if (httpd_sess_set_recv_override(hd, fd, refused_recv) != ESP_OK
        || httpd_sess_set_send_override(hd, fd, refused_send) != ESP_OK)
        return ESP_FAIL;
    web_idle_touch(fd, esp_timer_get_time());
    (void)shutdown(fd, SHUT_RDWR);
    __atomic_add_fetch(&s_refused, 1, __ATOMIC_RELAXED);
    return ESP_OK;
}

uint32_t web_idle_refused(void)
{
    return __atomic_load_n(&s_refused, __ATOMIC_RELAXED);
}

static bool socket_idle(int fd)
{
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(fd, &readable);
    struct timeval immediate = {0};
    return select(fd + 1, &readable, NULL, NULL, &immediate) == 0;
}

/* Only the server task runs this sweep. Its control callbacks run before the
 * HTTP data handlers, so freshly arrived input must win over the idle timer.
 * Shut down the receive side now and let HTTPD clean up on EOF. No delayed
 * close can act on the same session record after the SDK reuses it. */
static void sweep_idle_fds(const int *fds, size_t n, int64_t now_us)
{
    int closed = 0;
    taskENTER_CRITICAL(&s_slot_lock);
    for (int i = 0; i < WEB_IDLE_SLOTS; i++) {
        bool live = false;
        for (size_t j = 0; j < n; j++) live |= s_slots[i].fd == fds[j];
        if (!live && !s_slots[i].async_owned) s_slots[i].fd = -1;
    }
    taskEXIT_CRITICAL(&s_slot_lock);
    for (size_t j = 0; j < n; j++) {
        int fd = fds[j];
        taskENTER_CRITICAL(&s_slot_lock);
        web_idle_slot_t *s = slot_find(fd);
        bool expired = s && !s->async_owned &&
                       now_us - s->last_us >= (int64_t)WEB_IDLE_CLOSE_MS * 1000;
        if (!s) track_slot(fd, now_us);
        taskEXIT_CRITICAL(&s_slot_lock);
        if (expired && socket_idle(fd) && shutdown(fd, SHUT_RD) == 0) {
            taskENTER_CRITICAL(&s_slot_lock);
            s = slot_find(fd);
            if (s) s->fd = -1;
            taskEXIT_CRITICAL(&s_slot_lock);
            closed++;
        }
    }
    s_closed += (uint32_t)closed;
}

static void sweep_work(void *arg)
{
    httpd_handle_t hd = arg;
    size_t n = WEB_IDLE_SLOTS;
    int fds[WEB_IDLE_SLOTS];
    if (hd == atomic_load(&s_server) && httpd_get_client_list(hd, &n, fds) == ESP_OK)
        sweep_idle_fds(fds, n, esp_timer_get_time());
    atomic_store(&s_sweep_pending, false);
}

static void sweep_timer(void *arg)
{
    (void)arg;
    httpd_handle_t server = atomic_load(&s_server);
    if (!server || atomic_exchange(&s_sweep_pending, true)) return;
    /* Leave queue slots available for OTA and other control work. */
    if (httpd_queue_work(server, sweep_work, server) != ESP_OK)
        atomic_store(&s_sweep_pending, false);
}

void web_idle_reset(void)
{
    taskENTER_CRITICAL(&s_slot_lock);
    for (int i = 0; i < WEB_IDLE_SLOTS; i++) s_slots[i] = (web_idle_slot_t){ .fd = -1 };
    taskEXIT_CRITICAL(&s_slot_lock);
}

void web_idle_start(httpd_handle_t hd)
{
    web_idle_reset();
    atomic_store(&s_server, hd);
    if (!s_timer) {
        const esp_timer_create_args_t args = { .callback = sweep_timer, .name = "web_idle" };
        if (esp_timer_create(&args, &s_timer) != ESP_OK) {
            ESP_LOGW(TAG, "idle sweep unavailable; sessions close only when the client closes");
            s_timer = NULL;
            return;
        }
    }
    esp_timer_stop(s_timer);
    esp_timer_start_periodic(s_timer, 1000 * 1000);
}

void web_idle_stop(void)
{
    if (s_timer) esp_timer_stop(s_timer);
    atomic_store(&s_server, NULL);
}

uint32_t web_idle_closed(void) { return s_closed; }
