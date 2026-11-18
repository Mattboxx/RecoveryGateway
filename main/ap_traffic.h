/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. ESP32 Tailnet Gateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Optional traffic count per device on the gateway's access point, keyed by
 * the client's MAC address: bytes the device sent and bytes it received
 * since it was first seen (or the count was turned on). Off by default:
 * while off the packet path pays one flag check and nothing is stored.
 * Original implementation, Mattboxx Edition. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AP_TRAFFIC_SLOTS 16                 /* more than the AP admits at once */

typedef struct {
    uint8_t mac[6];
    bool used;
    uint64_t from_client, to_client, order;
} ap_traffic_entry_t;

typedef struct {
    ap_traffic_entry_t e[AP_TRAFFIC_SLOTS];
    uint64_t order;
} ap_traffic_table_t;

/* Core (pure, host-tested). Group (multicast/broadcast) and all-zero
 * addresses are not devices and are not counted; with every slot in use the
 * device seen longest ago gives its slot up. */
void ap_traffic_add(ap_traffic_table_t *t, const uint8_t mac[6], uint32_t bytes, bool from_client);
bool ap_traffic_find(const ap_traffic_table_t *t, const uint8_t mac[6], uint64_t *from_client, uint64_t *to_client);

#if !defined(AP_TRAFFIC_HOST_TEST)
#include "esp_err.h"
extern volatile bool ap_traffic_on;
void ap_traffic_init(void);
/* TCP/IP thread: an Ethernet frame from (or to) an AP client. */
void ap_traffic_frame(const uint8_t *frame, size_t len, uint32_t bytes, bool from_client);
bool ap_traffic_get(const uint8_t mac[6], uint64_t *from_client, uint64_t *to_client);
/* Saved setting, applied at once; turning it off forgets the counts. */
esp_err_t ap_traffic_set(bool on);
#endif
