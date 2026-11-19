/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. RecoveryGateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* Optional cellular (GSM/LTE) data uplink through an external modem
 * (for example SIMCom SIM7600/A7670 or Quectel EC2x) with a SIM card, wired
 * to a UART or plugged into the native USB port (USB OTG host; CDC-ACM or
 * vendor serial interface). Both transports share one AT/PPP engine.
 * AT commands bring the modem up (SIM PIN, registration, APN) and the data
 * call runs as PPP over the same serial channel through the ESP-IDF PPP
 * netif. The USB host stack is installed only when USB is selected.
 * OFF by default: nothing dials until it is enabled, configured and the data
 * notice is acknowledged. It is the Internet uplink only (primary or
 * failover); LAN-side services stay on WiFi or Ethernet. Settings apply at
 * the next boot. Not physically qualified on any modem yet.
 * Original implementation, Mattboxx Edition. MIT. */
#pragma once
#include "esp_netif.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_http_server.h"

enum {CELL_MODE_FAILOVER = 0, CELL_MODE_PRIMARY = 1};
enum {CELL_SIM_READY = 0, CELL_SIM_PIN = 1, CELL_SIM_PUK = 2, CELL_SIM_OTHER = 3};
enum {CELL_OFF, CELL_POWERING, CELL_SYNC, CELL_SIM, CELL_REGISTERING, CELL_DIALING,
      CELL_CONNECTED, CELL_BACKOFF, CELL_STOPPED};
enum {CELL_TRANSPORT_UART = 0, CELL_TRANSPORT_USB = 1};
#define CELL_USB_IFACE_AUTO 0xff          /* usb_iface: automatic choice */
#define CELL_USB_IFACE_MAX 15

typedef struct {
    uint8_t enabled, uart, mode, roaming, data_ack, pwrkey_active_high;
    int8_t tx, rx, rts, cts, pwrkey;      /* rts/cts/pwrkey: -1 not connected */
    uint8_t transport, usb_iface;         /* CELL_TRANSPORT_*; USB interface or AUTO */
    uint8_t usb_mode;                     /* USBP_MODE_*: automatic, serial (PPP), network */
    uint32_t baud;
    char apn[64], user[32], password[64], pin[9];
} cell_config_t;

typedef struct {
    bool compiled, enabled_at_boot, task_running, has_ip, selected, restart_required;
    uint8_t state, registration;          /* registration: 3GPP stat, 0xff unknown */
    int16_t rssi_dbm;                     /* 0: unknown */
    uint32_t ip, connects;
    uint64_t bytes_in, bytes_out;
    char model[32], operator_name[32], error[160];
    /* USB transport (running configuration). */
    uint8_t transport, usb_iface, usb_how; /* usb_iface: 0xff none open */
    uint8_t usb_action, usb_net;          /* USBP_ACT_* in use, USBP_NET_* */
    bool usb_present;
    uint16_t usb_vid, usb_pid;
    uint32_t usb_rx_dropped, usb_switches;
    uint32_t usb_ram_host, usb_ram_session, usb_ram_free, usb_ram_min;   /* measured internal RAM, bytes */
    bool usb_ram_lean;                    /* the session runs with one transfer per direction */
} cell_status_t;

/* How the USB serial interface was chosen. */
enum {CELL_USB_HOW_NONE, CELL_USB_HOW_KNOWN, CELL_USB_HOW_ACM, CELL_USB_HOW_PROBE, CELL_USB_HOW_MANUAL};
#define CELL_USB_MAX_CANDIDATES 6
typedef struct {
    uint8_t count, how;
    bool network_only;                    /* only RNDIS/ECM/NCM/MBIM network interfaces */
    uint8_t iface[CELL_USB_MAX_CANDIDATES];
} cell_usb_plan_t;

/* Core (pure, host-tested). */
bool cell_config_valid(const cell_config_t *c, char *why, size_t why_size);
int cell_csq_to_dbm(int csq);                  /* 0..31 -> -113..-51 dBm, else 0 */
int cell_parse_csq(const char *response);      /* "+CSQ: n,m" -> n, -1 */
int cell_parse_reg(const char *response, const char *prefix);  /* stat or -1 */
int cell_parse_cpin(const char *response);     /* CELL_SIM_* */
bool cell_parse_cops(const char *response, char *name, size_t n);
bool cell_registered(int stat, bool roaming);  /* 1 home; 5 roaming only if allowed */
typedef struct {uint8_t streak;} cell_selector_t;
#define CELL_STABLE_SAMPLES 3
/* true: route Internet traffic over cellular. Failover takes it only while
 * the WiFi/Ethernet uplink is down; primary after a short stable window. */
bool cell_uplink_choose(cell_selector_t *s, uint8_t mode, bool other_ok, bool cell_ok);
/* Reporting when mobile data starts or stops carrying the Internet traffic:
 * a change is reported once it has lasted CELL_CARRY_SETTLE_S (short flips
 * stay quiet). Returns CELL_CARRY_* for the change to report now. */
#define CELL_CARRY_SETTLE_S 30
enum {CELL_CARRY_NONE, CELL_CARRY_STARTED, CELL_CARRY_ENDED};
typedef struct {bool reported, pending; uint32_t since_s;} cell_carry_t;
int cell_carry_update(cell_carry_t *c, bool carrying, uint32_t now_s);
/* One AT response line: 1 final OK (or `final` seen), 0 final error, -1 not final. */
int cell_at_line(const char *line, const char *final);
/* USB serial interface plan from a raw configuration descriptor (bounded
 * parse). Candidates are tried in order with an AT probe; `override` is a
 * user-chosen interface or CELL_USB_IFACE_AUTO. Returns the candidate count,
 * -1 for a malformed descriptor. */
int cell_usb_plan(uint16_t vid, uint16_t pid, const uint8_t *config, size_t len, uint8_t override, cell_usb_plan_t *out);

/* Boot: after netif_hooks_init (the ACL hooks are a start condition). */
void cell_uplink_init(void);
/* Before Wi-Fi starts: true when the saved settings enable the USB connection. */
bool cell_uplink_usb_configured(void);
/* Secrets (password, PIN) are never returned by the HTTP API. */
void cell_uplink_get_config(cell_config_t *out);
esp_err_t cell_uplink_set_config(const cell_config_t *c, char *why, size_t why_size);
void cell_uplink_get_status(cell_status_t *out);
/* TCP/IP context only (route supervisor): the cellular netif when it should
 * carry the Internet uplink instead of `current`, otherwise NULL. */
struct netif *cell_uplink_lwip_select(struct netif *current);
struct netif *cell_uplink_selected_lwip(void);
/* TCP/IP context only: the cellular netif while it has an address, selected
 * or not (route hook: a modem network that overlaps the LAN prefix). */
struct netif *cell_uplink_lwip(void);
esp_netif_t *cell_uplink_preferred_netif(esp_netif_t *lan);
esp_err_t cell_uplink_register_http(httpd_handle_t server);
