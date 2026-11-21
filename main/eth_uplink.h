/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Conditional Ethernet uplink: a W5500 module wired to SPI pins, or a USB
 * Ethernet adapter / phone USB tethering on the native USB port (CDC-ECM,
 * CDC-NCM or RNDIS through usb_port.c).
 * OFF by default: a WiFi-only board never touches SPI/GPIO/USB and keeps the
 * STA route path unchanged. Pins and IP settings apply at the next boot. This is
 * not a claim that any ESP32-S3 has Ethernet, and it is not physically
 * qualified. Original implementation, Mattboxx Edition. MIT. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_http_server.h"
#include "esp_netif.h"

enum {ETH_CHIP_W5500 = 1};
enum {ETH_PREF_WIFI_FIRST = 0, ETH_PREF_ETHERNET_FIRST = 1};
enum {ETH_CHOICE_LEGACY = 0, ETH_CHOICE_STA = 1, ETH_CHOICE_ETH = 2};
enum {ETH_TRANSPORT_SPI = 0, ETH_TRANSPORT_USB = 1};

typedef struct {
    uint8_t enabled, chip, spi_host, spi_mhz, ip_static, preference;
    int8_t sclk, mosi, miso, cs, intr, rst;  /* -1: not connected (intr/rst only) */
    uint8_t transport, reserved[3];          /* ETH_TRANSPORT_*; reserved: 0 */
    uint32_t ip, mask, gw, dns;              /* network byte order, static mode */
} eth_config_t;

typedef struct {
    bool compiled, enabled_at_boot, driver_started, link_up, has_ip, selected, restart_required;
    uint32_t ip, mask, gw;                   /* network byte order */
    uint32_t link_changes;
    char error[160];
    /* USB transport. */
    uint8_t transport, usb_net;              /* USBP_NET_* in use */
    bool usb_present;
    uint16_t usb_vid, usb_pid;
    uint32_t usb_ram_host, usb_ram_session, usb_ram_free, usb_ram_min;   /* measured internal RAM, bytes */
    bool usb_ram_lean;                    /* the session runs with one transfer per direction */
} eth_status_t;

/* Uplink selection with a short stability window before moving to Ethernet;
 * losing the Ethernet link falls back at once. */
typedef struct {uint8_t eth_streak;} eth_selector_t;
#define ETH_STABLE_SAMPLES 3

bool eth_config_valid(const eth_config_t *c, char *why, size_t why_size);
int eth_uplink_choose(eth_selector_t *s, bool enabled, uint8_t preference, bool sta_ok, bool eth_ok);

/* Boot: prepare (before netif_hooks_init), then start (after it). */
void eth_uplink_init(void);
/* Before Wi-Fi starts: true when the saved settings enable the USB connection. */
bool eth_uplink_usb_configured(void);
void eth_uplink_start(void);
void eth_uplink_get_config(eth_config_t *out);
esp_err_t eth_uplink_set_config(const eth_config_t *c, char *why, size_t why_size);
esp_err_t eth_uplink_store_for_reboot(const eth_config_t *c, char *why, size_t why_size);
void eth_uplink_get_status(eth_status_t *out);
bool eth_uplink_restart_required(void);
/* TCP/IP context only (route supervisor). NULL: Ethernet disabled, keep the
 * legacy STA default; otherwise the lwIP netif to use as uplink. */
struct netif *eth_uplink_lwip_select(struct netif *sta);
/* TCP/IP context only. NULL when Ethernet is not the active service uplink. */
struct netif *eth_uplink_selected_lwip(void);
esp_err_t eth_uplink_register_http(httpd_handle_t server);
/* The uplink that LAN-to-Tailnet/AP-side bindings listen on: the Ethernet
 * netif while it is the selected uplink, otherwise the WiFi STA netif. */
esp_netif_t *eth_uplink_service_netif(void);
esp_netif_t *eth_uplink_netif(void);
void eth_uplink_wifi_changed(void);
