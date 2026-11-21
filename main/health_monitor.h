/* Opt-in layered evidence, not a connectivity guarantee. SPDX-License-Identifier: GPL-3.0-only */
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "remote_commands.h"
#include "cJSON.h"
typedef struct {
    uint8_t enabled,notify,failure_threshold,reserved;
    uint16_t interval_s,gateway_port,internet_port,tailnet_port;
    char dns_name[96],internet_ip[16],tailnet_target[96];
} health_config_t;
void health_monitor_init(void);
bool health_monitor_enabled(void);
esp_err_t health_monitor_set(const health_config_t *config);
esp_err_t health_monitor_set_enabled(bool enabled);
/* On success, holds the settings lock until first-party profile commit or
 * rollback. MQTT updates cannot interleave with the staged setting. */
esp_err_t health_monitor_stage_enabled(bool expected, bool enabled);
void health_monitor_finish_staged(bool enabled, bool committed);
/* Single optional ops worker only; no new task, timer, socket queue or reboot. */
void health_monitor_poll(void);
/* Detailed includes user targets; sanitized never includes those identifiers. */
cJSON *health_monitor_snapshot(bool detailed);
/* Per check (gateway, DNS, Internet, Tailnet): 0 disabled, 1 not configured,
 * 2 unverified, 3 ok, 4 degraded, 5 down, 6 unknown, 7 resource-deferred,
 * 8 stale. Same derivation as the snapshot; no targets or identifiers. */
void health_monitor_codes(uint8_t out[4]);

#define SAVED_TCP_MAX 4
typedef struct {
    char name[21], address[16];
    uint16_t port, interval_s; /* zero interval: manual only */
    uint8_t notify;
} saved_tcp_target_t;
bool saved_tcp_schedule_enabled(void);
esp_err_t saved_tcp_set(const saved_tcp_target_t targets[SAVED_TCP_MAX]);
esp_err_t saved_tcp_request(const char *name, ops_recovery_origin_t origin);
esp_err_t saved_tcp_remote_request(const char *name, ops_recovery_origin_t origin, uint32_t destination);
void saved_tcp_summary(char *out, size_t capacity);
