/* SPDX-License-Identifier: GPL-3.0-only */
#pragma once
#include "lwip/timeouts.h"

/* Storage lives for the full owner lifetime. Initialize to zero, schedule
 * and cancel with TCP/IP ownership, and cancel before destroying the owner. */
typedef struct {
    struct sys_timeo node;
    sys_timeout_handler handler;
    void *arg;
    u8_t pending;
} lwip_owned_timeout_t;

void lwip_owned_timeout_schedule(lwip_owned_timeout_t *timer, u32_t delay_ms,
                                 sys_timeout_handler handler, void *arg, const char *name);
void lwip_owned_timeout_cancel(lwip_owned_timeout_t *timer);
