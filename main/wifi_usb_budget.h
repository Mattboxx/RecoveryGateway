/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. ESP32 Tailnet Gateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Internal RAM for the optional USB connection. The ESP32-S3 USB DMA cannot
 * reach PSRAM, so its transfers come from the same internal RAM the Wi-Fi
 * driver keeps its static receive buffers in (24 x about 1.6 KB, raised from
 * 16 on 2026-05-24 for phone speed-test bursts through the access point).
 * Only while a USB connection is enabled at boot, the Wi-Fi returns to 16:
 * about 12.8 KB back, slightly less headroom for receive bursts. Without a
 * USB connection nothing changes. Original implementation, Mattboxx Edition. */
#pragma once
#include <stdbool.h>

#define WIFI_USB_STATIC_RX 16

/* Works on any struct with the esp_wifi_init fields static_rx_buf_num and
 * rx_ba_win (wifi_init_config_t). True when the configuration was reduced. */
#define wifi_lean_rx_for_usb(usb, cfg) wifi_lean_rx_apply((usb), &(cfg)->static_rx_buf_num, &(cfg)->rx_ba_win)

static inline bool wifi_lean_rx_apply(bool usb, int *static_rx, int *ba_win)
{
    if (!usb || *static_rx <= WIFI_USB_STATIC_RX) return false;
    *static_rx = WIFI_USB_STATIC_RX;
    if (*ba_win > 2 * WIFI_USB_STATIC_RX) *ba_win = 2 * WIFI_USB_STATIC_RX;   /* esp_wifi_init: BA window <= 2 x static RX */
    return true;
}

/* Set once at boot, before esp_wifi_init; read by the status API. */
extern bool wifi_rx_lean_for_usb;
