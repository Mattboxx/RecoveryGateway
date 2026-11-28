/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Notification wording shared by ntfy, Telegram and email (notify_text.h). */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "notify_text.h"
#include "history.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* esp_reset_reason_t values (esp_system.h), kept numeric so this file builds
 * on the host without the SDK; tools/test_notify_text.py checks them. */
enum {
    RST_UNKNOWN, RST_POWERON, RST_EXT, RST_SW, RST_PANIC, RST_INT_WDT, RST_TASK_WDT, RST_WDT,
    RST_DEEPSLEEP, RST_BROWNOUT, RST_SDIO, RST_USB, RST_JTAG, RST_EFUSE, RST_PWR_GLITCH, RST_CPU_LOCKUP
};

const char *notify_text_reset_cause(int r, bool poweron_events)
{
    switch (r) {
    case RST_POWERON: return poweron_events
        ? "power restored or first power-up (possible blackout)"
        : "power restored or first power-up";
    case RST_EXT: return "external reset pin";
    case RST_SW: return "software-requested restart";
    case RST_PANIC: return "firmware crash (panic/exception)";
    case RST_INT_WDT: return "interrupt watchdog timeout";
    case RST_TASK_WDT: return "task watchdog timeout";
    case RST_WDT: return "watchdog timeout";
    case RST_DEEPSLEEP: return "wake from deep sleep";
    case RST_BROWNOUT: return "supply voltage drop (brownout)";
    case RST_SDIO: return "SDIO reset";
    case RST_USB: return "USB peripheral reset";
    case RST_JTAG: return "JTAG/debugger reset";
    case RST_EFUSE: return "eFuse error";
    case RST_PWR_GLITCH: return "power glitch detected";
    case RST_CPU_LOCKUP: return "CPU lockup (double exception)";
    default: return "unknown reset cause";
    }
}

static void set_title(char title[NOTIFY_TITLE_MAX], const char *t) {snprintf(title, NOTIFY_TITLE_MAX, "%s", t);}

void notify_text_boot(char title[NOTIFY_TITLE_MAX], char *msg, size_t cap,
                      const char *version, int r, bool poweron_events)
{
    if (r == RST_POWERON && poweron_events) {
        set_title(title, "ESP32 possible blackout");
        snprintf(msg, cap, "Power restored.");
        return;
    }
    (void)version; /* Firmware version remains available in diagnostics/info. */
    snprintf(msg, cap, "Reason: %s.", notify_text_reset_cause(r, poweron_events));
    set_title(title, r == RST_POWERON ? "ESP32 power-on detected" : "ESP32 gateway restarted");
}

void notify_text_power_interruption(char *msg, size_t cap, uint32_t last_online)
{
    if (!msg || !cap) return;
    size_t used = 0;
    while (used < cap && msg[used]) used++;
    if (used == cap) return;
    char stamp[32] = "";
    time_t wall = (time_t)last_online;
    struct tm utc;
#ifdef _WIN32
    bool valid = last_online > 1700000000 && gmtime_s(&utc, &wall) == 0;
#else
    bool valid = last_online > 1700000000 && gmtime_r(&wall, &utc) != NULL;
#endif
    if (valid)
        strftime(stamp, sizeof stamp, "%Y-%m-%d %H:%M UTC", &utc);
    if (stamp[0])
        snprintf(msg + used, cap - used,
                 "\nLast recorded activity: %s.", stamp);
    else
        snprintf(msg + used, cap - used,
                 "\nLast recorded activity: unavailable.");
}

void notify_text_tailscale_problem(char title[NOTIFY_TITLE_MAX], char *msg, size_t cap)
{
    /* Alerts report connectivity, never export the local log buffer. */
    snprintf(msg, cap, "Tailscale is disconnected.\nInternet uplink: connected.");
    set_title(title, "ESP32 Tailscale problem");
}

void notify_text_tailscale_restored(char title[NOTIFY_TITLE_MAX], char *msg, size_t cap, uint32_t outage_seconds)
{
    snprintf(msg, cap, "Tailscale control connection restored.\nInterruption: %lu s.",
             (unsigned long)outage_seconds);
    set_title(title, "ESP32 Tailscale restored");
}

void notify_text_update_available(char title[NOTIFY_TITLE_MAX], char *msg, size_t cap, const char *version)
{
    snprintf(msg, cap, "Firmware %.31s is available.\nUpdate from System > Firmware.",
             version ? version : "");
    set_title(title, "ESP32 firmware update available");
}

/* "<prefix>%lu seconds." as notify_channels.c writes its link notes. */
static bool seconds_after(const char *text, const char *prefix, unsigned long *out)
{
    size_t n = strlen(prefix);
    if (strncmp(text, prefix, n) != 0) return false;
    char *end = NULL;
    unsigned long v = strtoul(text + n, &end, 10);
    if (end == text + n || strcmp(end, " seconds.") != 0) return false;
    *out = v;
    return true;
}

void notify_text_compose(unsigned kind, unsigned level, const char *text,
                         const char *version, int r, bool poweron_events,
                         char title[NOTIFY_TITLE_MAX], char *msg, size_t cap)
{
    unsigned long s = 0;
    if (!text) text = "";
    if (kind == HIST_EV_BOOT && (!strncmp(text, "Power-on start ", 15) || !strncmp(text, "Started ", 8))) {
        notify_text_boot(title, msg, cap, version, r, poweron_events);
    } else if (kind == HIST_EV_TAILNET && seconds_after(text, "Tailnet connection unavailable for at least ", &s)) {
        char head[NOTIFY_MESSAGE_MAX];
        notify_text_tailscale_problem(title, head, sizeof head);
        snprintf(msg, cap, "%s\nDuration: at least %lu s.", head, s);
    } else if (kind == HIST_EV_TAILNET && seconds_after(text, "Tailnet connection recovered after ", &s)) {
        notify_text_tailscale_restored(title, msg, cap, (uint32_t)s);
    } else if (kind == HIST_EV_UPLINK && seconds_after(text, "Internet uplink unavailable for at least ", &s)) {
        snprintf(msg, cap, "Internet uplink unavailable.\nDuration: at least %lu s.", s);
        set_title(title, "ESP32 Internet uplink problem");
    } else if (kind == HIST_EV_UPLINK && seconds_after(text, "Internet uplink recovered after ", &s)) {
        snprintf(msg, cap, "Internet uplink restored.\nInterruption: %lu s.", s);
        set_title(title, "ESP32 Internet uplink restored");
    } else if (kind == HIST_EV_UPDATE && !strncmp(text, "Firmware ", 9) && strstr(text, " is available.")) {
        snprintf(msg, cap, "%s", text);
        set_title(title, "ESP32 firmware update available");
    } else {
        snprintf(msg, cap, "%s", text);
        set_title(title, kind == HIST_EV_SERVICE ? "ESP32 operational result"
                       : kind == HIST_EV_CRASH ? "ESP32 firmware crash"
                       : kind == HIST_EV_SECURITY ? "ESP32 security event"
                       : level >= HIST_ERROR ? "ESP32 gateway error"
                       : level >= HIST_WARN ? "ESP32 gateway warning" : "ESP32 gateway event");
    }
}
