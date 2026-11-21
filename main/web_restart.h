/* SPDX-License-Identifier: GPL-3.0-only */
#pragma once

#include <stdbool.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Reserve a restart before a configuration write, then commit or cancel it. */
esp_err_t web_ui_reserve_restart(TaskHandle_t *task);
void web_ui_finish_restart(TaskHandle_t task, bool commit);
