/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Where the web administration may be reached from, and the client address a
 * web session is bound to (pure helpers, host-tested).
 * Original implementation, Mattboxx Edition. */
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum {WEB_ADMIN_ANYWHERE = 0, WEB_ADMIN_TAILNET_AP = 1};

/* A socket address as 16 bytes: IPv4 as ::ffff:a.b.c.d. */
typedef struct {uint8_t b[16];} web_addr_t;

static inline web_addr_t web_addr_v4(uint32_t ip_nbo)
{
    web_addr_t a = {{0}};
    a.b[10] = a.b[11] = 0xff;
    memcpy(a.b + 12, &ip_nbo, 4);
    return a;
}

static inline bool web_addr_is_v4(const web_addr_t *a, uint32_t *ip_nbo)
{
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(a->b, mapped, 12)) return false;
    if (ip_nbo) memcpy(ip_nbo, a->b + 12, 4);
    return true;
}

static inline bool web_addr_same(const web_addr_t *x, const web_addr_t *y) {return !memcmp(x->b, y->b, 16);}

/* Whether a connection made to the gateway address `local` may reach the
 * administration. With WEB_ADMIN_TAILNET_AP only the tailnet address (or a
 * Tailscale IPv6 address), the access point address (ap_ip_nbo, 0 while the
 * AP is off) and loopback are. While the tailnet is down every address is
 * allowed: the local network is the way back in, never a lock-out. */
static inline bool web_admin_allowed(uint8_t scope, const web_addr_t *local, uint32_t ap_ip_nbo, uint32_t tailnet_ip_nbo, bool tailnet_up)
{
    if (scope != WEB_ADMIN_TAILNET_AP || !tailnet_up) return true;
    uint32_t ip;
    if (web_addr_is_v4(local, &ip)) {
        uint8_t first;
        memcpy(&first, &ip, 1);
        if (first == 127) return true;
        return (ap_ip_nbo && ip == ap_ip_nbo) || (tailnet_ip_nbo && ip == tailnet_ip_nbo);
    }
    static const uint8_t tailscale6[6] = {0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0};   /* fd7a:115c:a1e0::/48 */
    static const uint8_t loopback6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return !memcmp(local->b, tailscale6, 6) || !memcmp(local->b, loopback6, 16);
}
