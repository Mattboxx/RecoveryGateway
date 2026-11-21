/* Throughput test; see throughput.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "throughput.h"
#include <stdio.h>
#include <string.h>

/* --- throughput core (begin) --- */
#define THR_MEMORY_FLOOR 12288u   /* stop below this much free internal RAM */

static bool fail(char *why, size_t cap, const char *text)
{
    if (why && cap) snprintf(why, cap, "%s", text);
    return false;
}

bool throughput_url_valid(const char *url, char *why, size_t cap)
{
    if (!url) return fail(why, cap, "enter a URL");
    size_t n = strlen(url), skip = !strncmp(url, "https://", 8) ? 8 : !strncmp(url, "http://", 7) ? 7 : 0;
    if (!skip) return fail(why, cap, "the URL must start with http:// or https://");
    if (n > 240) return fail(why, cap, "the URL is too long");
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)url[i] <= 0x20 || (unsigned char)url[i] >= 0x7F || url[i] == '"' || url[i] == '\\')
            return fail(why, cap, "the URL contains spaces or characters that are not allowed");
    const char *host = url + skip, *end = host;
    while (*end && *end != '/' && *end != '?' && *end != ':' && *end != '#') end++;
    if (end == host) return fail(why, cap, "the URL needs a host");
    for (const char *p = host; p < end; p++) if (*p == '@') return fail(why, cap, "credentials before the host are not supported");
    if (*end == ':') {
        unsigned port = 0;
        const char *p = end + 1;
        while (*p >= '0' && *p <= '9' && port <= 65535) port = port * 10 + (unsigned)(*p++ - '0');
        if (!port || port > 65535 || (*p && *p != '/' && *p != '?')) return fail(why, cap, "invalid port");
    }
    return true;
}

uint32_t throughput_kbps(uint64_t bytes, uint64_t us)
{
    if (!bytes || !us) return 0;
    while (us > (1ull << 40)) {us >>= 10; bytes >>= 10;}   /* keep rest * 8000 in range */
    if (!us) return 0;
    uint64_t whole = bytes / us, rest = bytes % us;        /* bytes per us, then kbit/s */
    if (whole > UINT32_MAX / 8000u) return UINT32_MAX;
    uint64_t kbps = whole * 8000u + (rest * 8000u + us / 2) / us;
    return kbps > UINT32_MAX ? UINT32_MAX : (uint32_t)kbps;
}

const char *throughput_stop(uint64_t bytes, uint64_t us, uint32_t seconds, size_t internal_free)
{
    if (internal_free < THR_MEMORY_FLOOR) return "stopped early: internal memory low";
    if (bytes >= THR_MAX_BYTES) return "size limit reached";
    if (us >= (uint64_t)seconds * 1000000u) return "time limit reached";
    return NULL;
}
static size_t throughput_read_limit(uint64_t bytes, size_t capacity)
{
    if (bytes >= THR_MAX_BYTES) return 0;
    uint64_t remaining = THR_MAX_BYTES - bytes;
    return remaining < capacity ? (size_t)remaining : capacity;
}

static bool throughput_blob_size(const char *value, uint32_t *bytes)
{
    uint32_t n = 0;
    for (const char *p = value; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (n > (THR_BLOB_MAX - digit) / 10) return false;
        n = n * 10 + digit;
    }
    if (n < 65536) return false;
    *bytes = n;
    return true;
}

/* --- throughput core (end) --- */

#ifdef ESP_PLATFORM
#include "history.h"
#include "homelab_ops.h"
#include "json_guard.h"
#include "task_reaper.h"
#include "web_ui.h"
#include "web_transfer.h"
#include "esp_attr.h"
#include "esp_crt_bundle.h"
#include "ml_tls_distrust.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include <stdlib.h>

typedef struct {
    bool running;
    char url[244];
    uint32_t seconds;
    uint64_t bytes, elapsed_us, first_byte_us;
    int status;
    char result[96];
} job_t;
EXT_RAM_BSS_ATTR static job_t s_job;            /* PSRAM: no internal RAM between tests */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

/* The HTTP client's receive timeout is renewed on each transport read.
 * A separate on-demand task ends a stalled header or body read without
 * blocking the ESP timer task. Join it before closing the borrowed socket. */
#define THR_CHUNK 4096
#define THR_HEADER_US 10000000LL
#define THR_DEADLINE_REARM 1u
#define THR_DEADLINE_STOP 2u

typedef struct {
    int fd;
    int64_t due_us;
    bool expired;
    TaskHandle_t task;
    SemaphoreHandle_t done;
} throughput_deadline_t;

static void deadline_worker(void *arg)
{
    throughput_deadline_t *deadline = arg;
    for (;;) {
        int64_t now = esp_timer_get_time();
        taskENTER_CRITICAL(&s_mux);
        int64_t remaining = deadline->due_us - now;
        bool expire_now = !deadline->expired && remaining <= 0;
        if (expire_now) deadline->expired = true;
        bool expired = deadline->expired;
        taskEXIT_CRITICAL(&s_mux);

        if (expire_now) (void)shutdown(deadline->fd, SHUT_RD);
        /* Round up rather than polling at the final sub-tick boundary. */
        TickType_t timeout = expired ? portMAX_DELAY :
            pdMS_TO_TICKS((remaining + 999) / 1000) + 1;
        uint32_t command = 0;
        if (xTaskNotifyWait(0, UINT32_MAX, &command, timeout) == pdTRUE &&
            (command & THR_DEADLINE_STOP)) break;
    }
    xSemaphoreGive(deadline->done);
    task_reaper_self_delete();
}

static bool deadline_start(throughput_deadline_t *deadline, int fd)
{
    if (fd < 0) return false;
    deadline->fd = fd;
    deadline->due_us = esp_timer_get_time() + THR_HEADER_US;
    deadline->done = xSemaphoreCreateBinary();
    if (!deadline->done) return false;
    if (xTaskCreateWithCaps(deadline_worker, "speed_deadline", 4096, deadline,
                            3, &deadline->task, MALLOC_CAP_SPIRAM) != pdPASS) {
        vSemaphoreDelete(deadline->done);
        return false;
    }
    return true;
}

static bool deadline_for_body(throughput_deadline_t *deadline, int64_t start,
                              uint32_t seconds)
{
    taskENTER_CRITICAL(&s_mux);
    bool ready = !deadline->expired && start < deadline->due_us;
    if (ready) deadline->due_us = start + (int64_t)seconds * 1000000;
    taskEXIT_CRITICAL(&s_mux);
    if (ready) xTaskNotify(deadline->task, THR_DEADLINE_REARM, eSetBits);
    return ready;
}

static void deadline_finish(throughput_deadline_t *deadline)
{
    xTaskNotify(deadline->task, THR_DEADLINE_STOP, eSetBits);
    xSemaphoreTake(deadline->done, portMAX_DELAY);
    vSemaphoreDelete(deadline->done);
}

static const char *read_test_payload(esp_http_client_handle_t client, char *buffer,
                                     int64_t body_start, uint64_t *bytes, int status)
{
    for (;;) {
        uint64_t elapsed = (uint64_t)(esp_timer_get_time() - body_start);
        const char *stop = throughput_stop(*bytes, elapsed, s_job.seconds,
                                          heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        if (stop) return stop;

        size_t limit = throughput_read_limit(*bytes, THR_CHUNK);
        int n = esp_http_client_read(client, buffer, (int)limit);
        if (n == -ESP_ERR_HTTP_EAGAIN) continue;
        if (n < 0) return "connection lost";
        if (n == 0)
            return esp_http_client_is_complete_data_received(client) ? "file complete" : "connection closed";

        *bytes += (uint64_t)n;
        elapsed = (uint64_t)(esp_timer_get_time() - body_start);
        taskENTER_CRITICAL(&s_mux);
        s_job.bytes = *bytes;
        s_job.elapsed_us = elapsed;
        s_job.status = status;
        taskEXIT_CRITICAL(&s_mux);
    }
}

static void worker(void *arg)
{
    (void)arg;
    char *buffer = heap_caps_malloc(THR_CHUNK, MALLOC_CAP_SPIRAM);
    esp_http_client_config_t hc = {.url = s_job.url, .timeout_ms = 10000, .buffer_size = THR_CHUNK,
                                   .crt_bundle_attach = ml_tls_bundle_attach, .max_redirection_count = 3};
    esp_http_client_handle_t client = buffer ? esp_http_client_init(&hc) : NULL;
    const char *why = "out of memory";
    int64_t start = esp_timer_get_time(), header_end = 0, body_start = 0;
    uint64_t bytes = 0;
    int status = 0;
    int64_t payload_end = 0;

    if (client) {
        why = "cannot connect (check the URL, DNS and the certificate)";
        if (esp_http_client_open(client, 0) == ESP_OK) {
            throughput_deadline_t deadline = {0};
            why = "test deadline unavailable";
            if (deadline_start(&deadline, esp_http_client_get_socket(client))) {
                why = "cannot read the response headers";
                if (esp_http_client_fetch_headers(client) >= 0) {
                    header_end = esp_timer_get_time();
                    status = esp_http_client_get_status_code(client);
                    if (!deadline_for_body(&deadline, header_end, s_job.seconds))
                        why = "response headers timed out";
                    else if (status < 200 || status >= 300)
                        why = "the server did not return the file";
                    else {
                        body_start = header_end;
                        why = read_test_payload(client, buffer, body_start, &bytes, status);
                        payload_end = esp_timer_get_time();
                    }
                }
                int64_t finished = body_start ? payload_end : esp_timer_get_time();
                if (finished >= deadline.due_us)
                    why = body_start ? "time limit reached" : "response headers timed out";
                deadline_finish(&deadline);
            }
        }
    }
    if (client) esp_http_client_cleanup(client);
    free(buffer);
    uint64_t elapsed = body_start ? (uint64_t)(payload_end - body_start) : 0;
    uint32_t kbps = throughput_kbps(bytes, elapsed);
    taskENTER_CRITICAL(&s_mux);
    s_job.bytes = bytes; s_job.elapsed_us = elapsed; s_job.status = status;
    s_job.first_byte_us = header_end ? (uint64_t)(header_end - start) : 0;
    snprintf(s_job.result, sizeof s_job.result, "%s", why);
    s_job.running = false;
    taskEXIT_CRITICAL(&s_mux);
    if (bytes) history_event(HIST_EV_UPLINK, HIST_INFO, "Throughput test: %lu.%02lu Mbit/s over %lu KB",
                             (unsigned long)(kbps / 1000), (unsigned long)(kbps % 1000 / 10), (unsigned long)(bytes / 1024));
    task_reaper_self_delete();
}

static esp_err_t get_test(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    job_t j;
    taskENTER_CRITICAL(&s_mux);
    j.running = s_job.running; j.bytes = s_job.bytes; j.elapsed_us = s_job.elapsed_us; j.status = s_job.status;
    j.first_byte_us = s_job.first_byte_us;
    memcpy(j.result, s_job.result, sizeof j.result);
    taskEXIT_CRITICAL(&s_mux);
    char out[256];
    snprintf(out, sizeof out, "{\"running\":%s,\"bytes\":%llu,\"elapsed_ms\":%llu,\"kbps\":%lu,\"first_byte_ms\":%llu,\"http\":%d,\"result\":\"%s\"}",
             j.running ? "true" : "false", (unsigned long long)j.bytes, (unsigned long long)(j.elapsed_us / 1000),
             (unsigned long)throughput_kbps(j.bytes, j.elapsed_us), (unsigned long long)(j.first_byte_us / 1000), j.status, j.result);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, out);
}

static esp_err_t post_test(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    char body[384], why[96] = "invalid request";
    int total = req->content_len, received = 0;
    bool ok = total > 0 && total < (int)sizeof body;
    while (ok && received < total) {int n = httpd_req_recv(req, body + received, total - received); if (n <= 0) ok = false; else received += n;}
    body[ok ? received : 0] = 0;
    cJSON *root = ok ? json_guard_parse(body) : NULL;
    const cJSON *url = cJSON_GetObjectItemCaseSensitive(root, "url"), *seconds = cJSON_GetObjectItemCaseSensitive(root, "seconds");
    ok = cJSON_IsObject(root) && cJSON_IsString(url) && throughput_url_valid(url->valuestring, why, sizeof why) &&
         (!seconds || (cJSON_IsNumber(seconds) && seconds->valuedouble >= 3 && seconds->valuedouble <= THR_MAX_S));
    bool admitted = false;
    if (ok) {
        if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) < 24576)
            snprintf(why, sizeof why, "not enough free memory right now");
        else if (!homelab_ops_admit())
            snprintf(why, sizeof why, "resource guard is deferring this test");
        else
            admitted = true;
    }
    bool started = false, busy = false;
    if (admitted) {
        taskENTER_CRITICAL(&s_mux);
        busy = s_job.running;
        if (!busy) {
            memset(&s_job, 0, sizeof s_job);
            snprintf(s_job.url, sizeof s_job.url, "%s", url->valuestring);
            s_job.seconds = seconds ? (uint32_t)seconds->valuedouble : 10;
            s_job.running = true;
        }
        taskEXIT_CRITICAL(&s_mux);
        if (!busy) {
            started = xTaskCreateWithCaps(worker, "speedtest", 8192, NULL, 3, NULL, MALLOC_CAP_SPIRAM) == pdPASS;
            if (!started) {taskENTER_CRITICAL(&s_mux); s_job.running = false; taskEXIT_CRITICAL(&s_mux); snprintf(why, sizeof why, "out of memory");}
        }
    }
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    if (busy) {httpd_resp_set_status(req, "409 Conflict"); return httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"a test is already running\"}");}
    if (!started) {
        httpd_resp_set_status(req, ok ? "503 Service Unavailable" : "400 Bad Request");
        char out[160];
        snprintf(out, sizeof out, "{\"ok\":false,\"error\":\"%s\"}", why);
        return httpd_resp_sendstr(req, out);
    }
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t serve_blob(httpd_req_t *req, const void *argument)
{
    uint32_t bytes;
    memcpy(&bytes, argument, sizeof bytes);
    char *chunk = heap_caps_calloc(1, 4096, MALLOC_CAP_SPIRAM);
    if (!chunk) {httpd_resp_send_500(req); return ESP_FAIL;}
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = ESP_OK;
    for (uint32_t sent = 0; sent < bytes && err == ESP_OK; sent += 4096)
        err = httpd_resp_send_chunk(req, chunk, (ssize_t)(bytes - sent < 4096 ? bytes - sent : 4096));
    if (err == ESP_OK) err = httpd_resp_send_chunk(req, NULL, 0);
    free(chunk);
    return err;
}

/* Zero bytes to the browser, which measures the link to the gateway. */
static esp_err_t get_blob(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    char query[32], value[12];
    uint32_t bytes = 4u * 1024u * 1024u;
    if (httpd_req_get_url_query_len(req) > 0) {
        esp_err_t query_result = httpd_req_get_url_query_str(req, query, sizeof query);
        bool valid = query_result == ESP_OK;
        if (valid) {
            query_result = httpd_query_key_value(query, "bytes", value, sizeof value);
            valid = query_result == ESP_ERR_NOT_FOUND ||
                    (query_result == ESP_OK && throughput_blob_size(value, &bytes));
        }
        if (!valid) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bytes must be 65536-16777216");
            return ESP_FAIL;
        }
    }
    return web_transfer_start(req, serve_blob, &bytes, sizeof bytes);
}

esp_err_t throughput_register_http(httpd_handle_t server)
{
    const httpd_uri_t routes[] = {
        {.uri = "/api/diag/speedtest", .method = HTTP_GET, .handler = get_test},
        {.uri = "/api/diag/speedtest", .method = HTTP_POST, .handler = post_test},
        {.uri = "/api/diag/speedtest/blob", .method = HTTP_GET, .handler = get_blob}};
    for (unsigned i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        esp_err_t err = httpd_register_uri_handler(server, &routes[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}
#endif
