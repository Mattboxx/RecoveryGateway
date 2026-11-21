/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
#pragma once

/* Remote commands shared by ntfy and Telegram, with the same options:
 *   help, devices                command guide and saved device observations
 *   info / status                operational state (info_enabled)
 *   wol NAME | wol MAC           Wake-on-LAN; an unsaved MAC needs allow_direct_mac
 *   recover NAME|MAC, check ...  bounded recovery job / reachability check
 *   probe NAME, checks           run a saved TCP check / list last results
 * Edges are trimmed; commands of 128 characters or more are ignored.
 * Implemented in ntfy_integration.c. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

typedef enum {
    OPS_RECOVERY_LOCAL, OPS_RECOVERY_MQTT, OPS_RECOVERY_NTFY, OPS_RECOVERY_TELEGRAM
} ops_recovery_origin_t;

typedef enum {
    REMOTE_CMD_NONE,    /* not a command: ignore, count nothing */
    REMOTE_CMD_INFO,    /* the caller sends remote_info_text() */
    REMOTE_CMD_HELP,    /* the caller sends the guide (and Telegram shortcuts) */
    REMOTE_CMD_OK,      /* done; reply/title describe it */
    REMOTE_CMD_ERROR,   /* refused or failed; reply may be empty (info disabled) */
} remote_cmd_kind_t;

#define REMOTE_REPLY_MAX 768

/* Writers hold the channel mutex. Workers can revoke an old request without
 * taking a channel mutex while holding their own lock. Zero means inactive. */
typedef _Atomic(uint32_t) remote_command_gate_t;

static inline uint32_t remote_command_ticket(const remote_command_gate_t *gate)
{
    uint32_t value = atomic_load(gate);
    return (value & 1u) ? value : 0;
}

static inline void remote_command_gate_reset(remote_command_gate_t *gate, bool enabled)
{
    uint32_t generation = (atomic_load(gate) & ~1u) + 2u;
    atomic_store(gate, generation | (uint32_t)enabled);
}

bool remote_command_active(ops_recovery_origin_t origin, uint32_t destination);
remote_cmd_kind_t remote_command_run(const char *message, bool info_enabled, bool allow_direct_mac,
                                     ops_recovery_origin_t origin, uint32_t destination,
                                     char *reply, size_t cap, const char **title);
bool remote_command_reply(ops_recovery_origin_t origin, uint32_t destination, const char *message);

/* Heap text of the info reply (about 8 KB at most); the caller frees it.
 * Never contains passwords, Wi-Fi keys, Tailscale keys or service tokens. */
char *remote_info_text(bool include_details, bool poweron_events);
