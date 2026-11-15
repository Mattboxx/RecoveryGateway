/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Mattboxx. ESP32 Tailnet Gateway, Mattboxx Edition: see LICENSE
 * and LICENSE-EXCEPTION.md. */
/* The native USB port as a USB host for one device at a time (no hubs):
 * a cellular modem or 4G stick (cell_uplink) or a USB Ethernet adapter or
 * phone tethering (eth_uplink). This module owns the USB host stack, device
 * detection, USB mode switching of sticks that first appear as a CD-ROM or
 * mass-storage device, the choice of an alternative USB configuration, and an
 * Ethernet data path over CDC-ECM, CDC-NCM or RNDIS. Nothing is installed
 * unless the cellular or Ethernet uplink is enabled with its USB connection.
 * Mode-switch messages come from the usb_modeswitch device reference data by
 * Josua Dietze (GPL-2.0-or-later); see NOTICE.md.
 * Original implementation, Mattboxx Edition. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Network function kinds. UNSUPPORTED: MBIM, vendor-only Ethernet chips. */
enum {USBP_NET_NONE, USBP_NET_ECM, USBP_NET_NCM, USBP_NET_RNDIS, USBP_NET_UNSUPPORTED};
/* What to do with an attached device. */
enum {USBP_ACT_NONE, USBP_ACT_SERIAL, USBP_ACT_NETWORK, USBP_ACT_SWITCH, USBP_ACT_NEXT_CONFIG};
/* Cellular usb_mode setting. */
enum {USBP_MODE_AUTO = 0, USBP_MODE_SERIAL = 1, USBP_MODE_NETWORK = 2};

#define USBP_CBW_LEN 31
#define USBP_MSW_MAX 5
#define USBP_MAX_CONFIGS 4

typedef struct {
    uint8_t kind;                          /* USBP_NET_* */
    uint8_t ctrl, data, data_alt;          /* interface numbers, data alternate setting */
    uint8_t ep_in, ep_out, ep_notify;      /* bulk IN/OUT, interrupt IN (0: none) */
    uint8_t mac_index;                     /* ECM/NCM iMACAddress string, 0: none */
    uint16_t mps_in, mps_out;
} usbp_net_t;

typedef struct {
    bool present;
    uint8_t iface, ep_in, ep_out;
    uint16_t mps_out;
} usbp_storage_t;

typedef struct {
    uint8_t count;
    uint8_t message[USBP_MSW_MAX][USBP_CBW_LEN];
} usbp_msw_t;

/* NCM receive iterator. */
typedef struct {size_t ndp, entry; unsigned ndps, frames;} usbp_ncm_rx_t;

/* Core (pure, host-tested). */
/* Network and mass-storage functions of a configuration descriptor, with a
 * bounded walk. -1 malformed, 0 otherwise. Prefers NCM, then ECM, then
 * RNDIS when a configuration has several. */
int usbp_scan(const uint8_t *cfg, size_t len, usbp_net_t *net, usbp_storage_t *storage);
/* The action for a device. `serial` is the number of serial (AT) interface
 * candidates (0 for the Ethernet uplink); `want_serial` false for the
 * Ethernet uplink. Automatic cellular mode prefers the serial interface: it
 * keeps the SIM PIN, APN and signal under the gateway's control. */
int usbp_action(bool want_serial, uint8_t usb_mode, int serial, const usbp_net_t *net, const usbp_storage_t *storage,
                uint8_t num_configs, uint8_t config_value);
/* Mode-switch messages for a storage-mode device: the reference entry for
 * vid:pid, else Huawei's switch for Huawei, else a standard SCSI eject. */
void usbp_msw_plan(uint16_t vid, uint16_t pid, usbp_msw_t *out);
/* RNDIS control messages (little endian); return the length or 0. */
size_t usbp_rndis_init(uint8_t *out, size_t cap, uint32_t request_id, uint32_t max_transfer);
size_t usbp_rndis_query(uint8_t *out, size_t cap, uint32_t request_id, uint32_t oid);
size_t usbp_rndis_set(uint8_t *out, size_t cap, uint32_t request_id, uint32_t oid, uint32_t value);
/* A completion of message `type` for `request_id` with success status; for
 * a query also its information buffer (bounded to the message). */
bool usbp_rndis_cmplt(const uint8_t *msg, size_t len, uint32_t type, uint32_t request_id,
                      const uint8_t **info, size_t *info_len);
/* RNDIS data message around a frame; 0 if it does not fit. */
size_t usbp_rndis_wrap(uint8_t *out, size_t cap, const uint8_t *frame, size_t len);
/* Next frame of a received RNDIS transfer: 1 frame, 0 end, -1 malformed. */
int usbp_rndis_next(const uint8_t *buf, size_t len, size_t *offset, const uint8_t **frame, size_t *frame_len);
/* NCM transfer block (NTB16) around one frame; 0 if it does not fit.
 * `divisor`/`remainder` place the datagram as the device asked (0: none). */
size_t usbp_ncm_wrap(uint8_t *out, size_t cap, const uint8_t *frame, size_t len, uint16_t seq,
                     uint16_t divisor, uint16_t remainder);
/* Next frame of a received NTB16: 1 frame, 0 end, -1 malformed. */
int usbp_ncm_next(const uint8_t *buf, size_t len, usbp_ncm_rx_t *it, const uint8_t **frame, size_t *frame_len);
/* iMACAddress string descriptor (UTF-16LE, 12 hex digits) to a MAC. */
bool usbp_mac_string(const uint8_t *desc, size_t len, uint8_t mac[6]);
/* Configuration to enumerate next after `current` found nothing usable: 0
 * when there is none (bounded to USBP_MAX_CONFIGS). */
uint8_t usbp_next_config(uint8_t num_configs, uint8_t current);

#if !defined(USBP_HOST_TEST)
#include "esp_err.h"
#include "esp_netif.h"

typedef struct {
    bool present;
    uint8_t address, num_configs, config_value;
    uint16_t vid, pid;
    uint32_t seq;                          /* changes on every attach */
} usbp_device_t;

typedef void (*usbp_link_cb_t)(bool up, void *ctx);

/* Installs the USB host stack, its event task and the gateway's own USB host
 * client (PSRAM stacks); `cdc_acm` also installs the CDC-ACM driver for
 * serial modems. Once per boot; the port stays a host until restart. */
esp_err_t usb_port_start(bool cdc_acm);
/* Snapshot of the attached device and its configuration descriptor. */
bool usb_port_device(usbp_device_t *out, uint8_t *cfg, size_t cap, size_t *len);
/* Waits up to `ms` for an attach or a removal after `seq`. */
void usb_port_wait(uint32_t seq, uint32_t ms);
/* Sends mode-switch messages (bounded; at most once per vid:pid per boot). */
esp_err_t usb_port_switch(const usbp_device_t *d, const usbp_storage_t *st);
/* Re-enumerates with the next configuration (bounded per vid:pid). */
bool usb_port_next_config(const usbp_device_t *d);
/* The esp_netif driver handle to attach once to the consumer's netif. */
void *usb_port_net_glue(void);
/* Opens the network function and starts the data path (MAC set on `netif`). */
esp_err_t usb_port_net_open(const usbp_device_t *d, const usbp_net_t *fn, esp_netif_t *netif,
                            usbp_link_cb_t link, void *ctx, const char **why);
bool usb_port_net_alive(void);
void usb_port_net_close(void);
void usb_port_counters(uint32_t *rx_dropped, uint32_t *tx_dropped, uint64_t *rx_bytes, uint64_t *tx_bytes);
#endif
