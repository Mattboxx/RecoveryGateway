/* Bounded background HTTP response streaming.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "web_transfer.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/task.h"
#include "homelab_ops.h"
#include "task_reaper.h"
#include "web_idle.h"

typedef struct {
    httpd_req_t *req;
    web_transfer_serve_t serve;
    unsigned char argument[];
} web_transfer_job_t;

static atomic_bool s_busy;

static void transfer_worker(void *context)
{
    web_transfer_job_t *job = context;
    esp_err_t result = job->serve(job->req, job->argument);
    web_idle_async_complete(job->req, result);
    free(job);
    atomic_store(&s_busy, false);
#if CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
    task_reaper_self_delete();
#else
    vTaskDelete(NULL);
#endif
}

esp_err_t web_transfer_start(httpd_req_t *req, web_transfer_serve_t serve,
                             const void *argument, size_t argument_size)
{
    if (atomic_exchange(&s_busy, true)) {
        httpd_resp_set_status(req, "429 Too Many Requests");
        return httpd_resp_sendstr(req, "A download is already running");
    }

    web_transfer_job_t *job = homelab_ops_admit() ?
        malloc(sizeof *job + argument_size) : NULL;
    if (!job || web_idle_async_begin(req, &job->req) != ESP_OK) {
        free(job);
        atomic_store(&s_busy, false);
        httpd_resp_set_status(req, "503 Service Unavailable");
        return httpd_resp_sendstr(req, "Download resources are unavailable");
    }

    job->serve = serve;
    memcpy(job->argument, argument, argument_size);
#if CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
    BaseType_t started = xTaskCreateWithCaps(transfer_worker, "web_transfer", 8192, job,
                                             2, NULL, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#else
    BaseType_t started = xTaskCreate(transfer_worker, "web_transfer", 8192, job, 2, NULL);
#endif
    if (started != pdPASS) {
        httpd_resp_set_status(job->req, "503 Service Unavailable");
        esp_err_t result = httpd_resp_sendstr(job->req, "Download worker is unavailable");
        web_idle_async_complete(job->req, result);
        free(job);
        atomic_store(&s_busy, false);
    }
    return ESP_OK;
}
