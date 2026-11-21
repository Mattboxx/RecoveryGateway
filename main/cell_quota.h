/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Monthly mobile data counter of the cellular uplink (PPP or USB network
 * stick): bytes in both directions, as carriers count them. Off (limit 0)
 * by default: nothing is counted, stored or written to flash. With a limit
 * it warns once at a chosen percentage and once at the limit, and can stop
 * using mobile data until the next period. A power cut can lose the usage
 * since the last checkpoint. Regular checkpoints need at least 1 MiB of
 * new data and 10 minutes since the last successful write.
 * Original implementation, Mattboxx Edition. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CELL_QUOTA_MAX_MB 1000000u          /* 1 TB */
#define CELL_QUOTA_SAVE_BYTES (1024u * 1024u)
#define CELL_QUOTA_SAVE_S 600u

typedef struct {
    uint32_t limit_mb;                      /* 0: off */
    uint8_t warn_pct;                       /* 0: no early warning, else 1-99 */
    uint8_t reset_day;                      /* the period starts on this day, 1-28 */
    uint8_t pause;                          /* stop using mobile data at the limit */
} cell_quota_config_t;

enum {CELL_QUOTA_WARNED = 1, CELL_QUOTA_LIMITED = 2};
typedef struct {
    uint32_t period;                        /* months since year 0, plus 1; 0: unknown */
    uint64_t used;                          /* bytes this period */
    uint8_t alerted;                        /* CELL_QUOTA_* */
} cell_quota_state_t;

enum {CELL_QUOTA_EV_NEW_PERIOD = 1, CELL_QUOTA_EV_WARN = 2, CELL_QUOTA_EV_LIMIT = 4,
      CELL_QUOTA_EV_CLOCK_CORRECTED = 8};

/* Core (pure, host-tested). */
bool cell_quota_config_valid(const cell_quota_config_t *c, char *why, size_t n);
/* The period a local date belongs to (month 1-12): 0 when the date is not
 * plausible (clock not set). */
uint32_t cell_quota_period(int year, int month, int day, uint8_t reset_day);
/* Year, month and day the period starts. */
void cell_quota_period_start(uint32_t period, uint8_t reset_day, int *year, int *month, int *day);
/* Adds `delta` bytes in `period` (0: unknown, the stored period goes on).
 * A later period starts from zero; *previous gets the finished period's
 * use. A distant backward correction moves the marker and keeps usage.
 * Pass only periods from a stable clock. Returns CELL_QUOTA_EV_* flags. */
int cell_quota_add(const cell_quota_config_t *c, cell_quota_state_t *s, uint64_t delta, uint32_t period, uint64_t *previous);
/* After a settings change: alerts whose threshold is no longer reached are
 * re-armed. */
void cell_quota_rearm(const cell_quota_config_t *c, cell_quota_state_t *s);
bool cell_quota_limit_reached(const cell_quota_config_t *c, const cell_quota_state_t *s);
/* Whether the state is worth writing to flash now. */
bool cell_quota_save_due(uint64_t used, uint64_t saved_used, uint32_t now_s, uint32_t saved_at_s, int events);

#if !defined(CELL_QUOTA_HOST_TEST)
#include "esp_err.h"
#include "cJSON.h"
void cell_quota_init(void);
/* Cellular task: snapshot the uplink's totals since boot. Cheap when off. */
void cell_quota_tick(void);
/* True while the limit is reached and "stop at the limit" is on. */
bool cell_quota_paused(void);
void cell_quota_get(cell_quota_config_t *c, cell_quota_state_t *s);
esp_err_t cell_quota_set(const cell_quota_config_t *c, bool reset_usage, char *why, size_t n);
/* {"limit_mb","warn_percent","reset_day","pause","used_bytes","period_start","paused","clock"} */
void cell_quota_json(cJSON *parent);
#endif
