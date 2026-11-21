/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
#include "forwarding_config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static StaticSemaphore_t s_config_storage;
static SemaphoreHandle_t s_config_lock;
static portMUX_TYPE s_init_lock = portMUX_INITIALIZER_UNLOCKED;

static SemaphoreHandle_t forwarding_config_mutex(void)
{
    /* Static creation cannot run out of heap. Serialize first use, including
     * callers on different cores, before entering the blocking mutex. */
    portENTER_CRITICAL(&s_init_lock);
    if (!s_config_lock)
        s_config_lock = xSemaphoreCreateMutexStatic(&s_config_storage);
    SemaphoreHandle_t lock = s_config_lock;
    portEXIT_CRITICAL(&s_init_lock);
    configASSERT(lock);
    return lock;
}

void forwarding_config_lock(void)
{
    xSemaphoreTake(forwarding_config_mutex(), portMAX_DELAY);
}

bool forwarding_config_try_lock(void)
{
    return xSemaphoreTake(forwarding_config_mutex(), 0) == pdTRUE;
}

void forwarding_config_unlock(void)
{
    xSemaphoreGive(s_config_lock);
}
