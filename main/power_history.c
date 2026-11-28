/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. */
#include "power_history.h"
#include "nvs_params.h"
#include "esp_timer.h"
#include <stdbool.h>
#include <time.h>

#define KEY "power_alive"
#define VALID_TIME 1700000000
static uint32_t s_previous;
static int64_t s_next_queue, s_next_write;
static httpd_handle_t s_server;

/* Called once before workers start. Consume the previous boot's checkpoint
 * before any new clock sync or notification; quick reboots cannot replay it. */
void power_history_init(void)
{
    uint32_t old = 0;
    s_previous = 0;
    if (nvs_param_get_u32(KEY, &old) == ESP_OK &&
        nvs_param_erase(KEY) == ESP_OK && old > VALID_TIME)
        s_previous = old;
    s_next_queue = s_next_write = 0;
}

void power_history_bind(httpd_handle_t server)
{
    __atomic_store_n(&s_server, server, __ATOMIC_RELEASE);
}

uint32_t power_history_previous_online(void)
{
    time_t now = time(NULL);
    if (s_previous <= VALID_TIME) return 0;
    /* This value was saved with a valid clock in the preceding boot. An
     * early notification can precede this boot's first SNTP response. */
    if (now > VALID_TIME && (uint64_t)now <= UINT32_MAX &&
        s_previous > (uint32_t)now) return 0;
    return s_previous;
}

/* The existing HTTP server has an internal stack suitable for NVS flash
 * writes. Never do this on TCPIP, the timer task or a PSRAM worker stack. */
static void checkpoint(void *unused)
{
    (void)unused;
    int64_t now_us = esp_timer_get_time();
    time_t now = time(NULL);
    if (now_us < s_next_write || now <= VALID_TIME || (uint64_t)now > UINT32_MAX)
        return;
    /* Limit failed writes too. Checkpoint availability is best effort. */
    s_next_write = now_us + (int64_t)POWER_HISTORY_INTERVAL_S * 1000000;
    (void)nvs_param_set_u32(KEY, (uint32_t)now);
}

/* Single caller, existing runtime sampler. At most one queued callback per
 * interval; a dropped server-control datagram is retried next interval.
 * A stale/delayed callback still observes the write limit in checkpoint(). */
void power_history_tick(void)
{
    int64_t now = esp_timer_get_time();
    if (now < s_next_queue || time(NULL) <= VALID_TIME) return;
    httpd_handle_t server = __atomic_load_n(&s_server, __ATOMIC_ACQUIRE);
    if (!server) return;
    s_next_queue = now + (int64_t)POWER_HISTORY_INTERVAL_S * 1000000;
    (void)httpd_queue_work(server, checkpoint, NULL);
}
