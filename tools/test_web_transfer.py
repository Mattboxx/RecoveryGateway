"""Exercise the HTTP transfer worker with an SDK and RTOS fixture."""
import os
from pathlib import Path
import subprocess
import tempfile

source = (Path(__file__).resolve().parents[1] / "main/web_transfer.c").read_text(encoding="utf-8")
source = source[source.index("typedef struct {"):]
stubs = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef int esp_err_t;
typedef int BaseType_t;
typedef struct { unsigned status; bool held; } httpd_req_t;
typedef esp_err_t (*web_transfer_serve_t)(httpd_req_t *, const void *);
#define ESP_OK 0
#define ESP_FAIL (-1)
#define pdPASS 1
#define MALLOC_CAP_SPIRAM 2
#define MALLOC_CAP_8BIT 4
#define CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM 1
static bool admit = true, alloc_fail, async_fail, task_fail;
static unsigned releases, deletes, sent, completions;
static int last_result;
static httpd_req_t *owner;
static void (*queued)(void *);
static void *queued_arg;

static void *fixture_alloc(size_t size) { return alloc_fail ? NULL : malloc(size); }
#define malloc fixture_alloc
static bool homelab_ops_admit(void) { return admit; }
static int web_idle_async_begin(httpd_req_t *req, httpd_req_t **copy) {
    assert(!req->held && !owner);
    if (async_fail) return ESP_FAIL;
    req->held = true; owner = req; *copy = req;
    return ESP_OK;
}
static void web_idle_async_complete(httpd_req_t *req, esp_err_t result) {
    assert(req->held && owner == req);
    owner = NULL; req->held = false; releases++; last_result = result;
}
static int xTaskCreateWithCaps(void (*fn)(void *), const char *name, unsigned stack,
                               void *job, unsigned priority, void *handle, int caps) {
    assert(fn && !queued && owner && job && !handle && priority == 2u);
    assert(caps == (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) && stack == 8192u);
    assert(!strcmp(name, "web_transfer"));
    if (task_fail) return 0;
    queued = fn; queued_arg = job;
    return pdPASS;
}
static int httpd_resp_set_status(httpd_req_t *req, const char *status) {
    req->status = (unsigned)atoi(status); return ESP_OK;
}
static int httpd_resp_sendstr(httpd_req_t *req, const char *message) {
    assert(req->status && message); sent++; return ESP_OK;
}
static void task_reaper_self_delete(void) { deletes++; }
"""
tests = r"""
static int serve(httpd_req_t *req, const void *argument) {
    assert(req == owner && req->held && !strcmp(argument, "file"));
    completions++;
    return completions == 1 ? ESP_FAIL : ESP_OK;
}
static void run(void) {
    assert(queued);
    void (*fn)(void *) = queued;
    queued = NULL; fn(queued_arg);
    assert(!owner);
}
int main(void) {
    httpd_req_t req = {0}, other = {0};
    char argument[] = "file";
    admit = false;
    assert(web_transfer_start(&req, serve, argument, sizeof argument) == ESP_OK);
    assert(req.status == 503 && !owner && !queued);
    admit = true; alloc_fail = true;
    assert(web_transfer_start(&req, serve, argument, sizeof argument) == ESP_OK);
    assert(req.status == 503 && !owner && !queued);
    alloc_fail = false; async_fail = true;
    assert(web_transfer_start(&req, serve, argument, sizeof argument) == ESP_OK);
    assert(req.status == 503 && !owner && !queued);
    async_fail = false; task_fail = true;
    assert(web_transfer_start(&req, serve, argument, sizeof argument) == ESP_OK);
    assert(req.status == 503 && !owner && !queued && releases == 1);
    task_fail = false;
    assert(web_transfer_start(&req, serve, argument, sizeof argument) == ESP_OK);
    assert(req.held && queued && completions == 0);
    argument[0] = 'x';
    assert(web_transfer_start(&other, serve, argument, sizeof argument) == ESP_OK);
    assert(other.status == 429 && !other.held && completions == 0);
    run();
    assert(last_result == ESP_FAIL && releases == 2 && deletes == 1);
    argument[0] = 'f';
    assert(web_transfer_start(&other, serve, argument, sizeof argument) == ESP_OK);
    run();
    assert(last_result == ESP_OK && releases == 3 && deletes == 2 && sent == 5);
    puts("PASS background transfer grant, exclusion, copied arguments, and all failure cleanup");
}
"""

with tempfile.TemporaryDirectory(prefix="web-transfer-") as temp:
    path = Path(temp) / "test.c"
    path.write_text(stubs + source + tests, encoding="utf-8")
    exe = path.with_suffix(".exe" if os.name == "nt" else ".out")
    args = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
    if os.environ.get("WEB_TRANSFER_SANITIZE") == "1":
        args += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    subprocess.run([os.environ.get("CC", "gcc"), *args, str(path), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=30)
