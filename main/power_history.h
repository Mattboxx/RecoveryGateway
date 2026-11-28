/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. */
#pragma once
#include <stdint.h>
#include "esp_http_server.h"

/* Five-minute, best-effort checkpoint. No power-loss interrupt or RTC. */
#define POWER_HISTORY_INTERVAL_S 300
void power_history_init(void);
void power_history_bind(httpd_handle_t server);
void power_history_tick(void);
uint32_t power_history_previous_online(void);
