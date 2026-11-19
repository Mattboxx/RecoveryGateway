/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Signal and operator of a Huawei HiLink 4G stick in USB network mode,
 * read from the stick's own local web API (the address its DHCP gives as the
 * gateway): /api/webserver/SesTokInfo for a session, then
 * /api/device/signal and /api/net/current-plmn. Read-only, bounded, every
 * minute; other sticks and failures just leave the values unknown.
 * Experimental: not validated with a physical stick.
 * Original implementation, Mattboxx Edition. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HILINK_VENDOR 0x12d1
#define HILINK_RESPONSE_MAX 2048

/* Core (pure, host-tested). The text between <tag> and </tag> (first match,
 * no nesting), trimmed; false when absent, empty or longer than cap - 1. */
bool hilink_xml_value(const char *xml, size_t len, const char *tag, char *out, size_t cap);
/* "-73dBm", ">=-51dBm", "-105" to dBm; 0 when not a plausible value. */
int hilink_dbm(const char *text);
/* Operator name: printable ASCII kept, anything else dropped. */
void hilink_clean_name(const char *in, char *out, size_t cap);

#if !defined(HILINK_HOST_TEST)
/* Reads the stick at `gateway_nbo`. *rssi_dbm (0 unknown) and `operator_name`
 * are updated only with what was read. Blocking, about 6 s at most. */
bool cell_hilink_poll(uint32_t gateway_nbo, int16_t *rssi_dbm, char *operator_name, size_t cap);
#endif
