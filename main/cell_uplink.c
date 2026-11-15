/* Optional cellular (GSM/LTE) uplink over a UART or USB modem; see cell_uplink.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "cell_uplink.h"
#include "uplink_services.h"
#include "eth_uplink.h"
#include "json_guard.h"
#include "netif_hooks.h"
#include "nvs.h"
#include "nvs_params.h"
#include "tailscale_config.h"
#include "web_ui.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#if CONFIG_LWIP_PPP_SUPPORT
#include "esp_netif_ppp.h"
#include "freertos/stream_buffer.h"
#include "usb/cdc_acm_host.h"
#endif
#include "usb_port.h"
#include "esp_netif_net_stack.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <ctype.h>
#include <math.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "cell_uplink"

/* --- cell core (begin) --- */
/* Same usable set as the Ethernet pins on ESP32-S3 N8R8/N16R8: flash/octal
 * PSRAM, USB, console UART, strapping and microSD pins are excluded. */
static bool cell_pin_allowed(int pin)
{
    static const int8_t allowed[] = {1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 21, 41, 42, 47, 48};
    for (size_t i = 0; i < sizeof allowed; i++) if (allowed[i] == pin) return true;
    return false;
}

static bool cell_fail(char *why, size_t n, const char *text)
{
    if (why && n) snprintf(why, n, "%s", text);
    return false;
}

/* Text sent inside a quoted AT argument: printable ASCII without quotes or
 * backslashes, so it can never end the argument or inject a command. */
static bool cell_text_ok(const char *s, size_t cap, bool allow_empty)
{
    size_t n = strnlen(s, cap);
    if (n == cap || (!n && !allow_empty)) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x20 || ch > 0x7e || ch == '"' || ch == '\\') return false;
    }
    return true;
}

bool cell_config_valid(const cell_config_t *c, char *why, size_t n)
{
    if (!c || c->enabled > 1 || c->mode > CELL_MODE_PRIMARY || c->roaming > 1 || c->data_ack > 1 || c->pwrkey_active_high > 1)
        return cell_fail(why, n, "invalid switch value");
    if (c->enabled && !c->data_ack) return cell_fail(why, n, "acknowledge the data-use notice before enabling");
    if (c->transport > CELL_TRANSPORT_USB) return cell_fail(why, n, "connection must be UART or USB");
    if (c->usb_iface != CELL_USB_IFACE_AUTO && c->usb_iface > CELL_USB_IFACE_MAX)
        return cell_fail(why, n, "USB interface must be automatic or 0-15");
    if (c->usb_mode > 2) return cell_fail(why, n, "USB mode must be automatic, serial or network");
    bool usb = c->transport == CELL_TRANSPORT_USB;
    if (c->uart != 1 && c->uart != 2) return cell_fail(why, n, "UART must be UART1 or UART2");
    static const uint32_t bauds[] = {9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600};
    bool baud_ok = false;
    for (size_t i = 0; i < sizeof bauds / sizeof bauds[0]; i++) baud_ok |= c->baud == bauds[i];
    if (!baud_ok) return cell_fail(why, n, "unsupported baud rate");
    /* USB: the UART pins are kept for a later switch back but not used, so
     * only the optional PWRKEY GPIO is checked. */
    int8_t pins[] = {c->tx, c->rx, c->rts, c->cts, c->pwrkey};
    for (unsigned i = usb ? 4 : 0; i < sizeof pins; i++) {
        if (pins[i] == -1 && i >= 2) continue;
        if (!cell_pin_allowed(pins[i])) return cell_fail(why, n, "pin not usable on this board (flash/PSRAM/USB/UART/strap/microSD)");
        for (unsigned j = 0; j < i; j++) if (pins[j] == pins[i]) return cell_fail(why, n, "pins must be distinct");
    }
    if (!usb && (c->rts == -1) != (c->cts == -1)) return cell_fail(why, n, "hardware flow control needs both RTS and CTS");
    /* USB: an empty APN keeps the modem's default (and a network stick has its own). */
    if (!cell_text_ok(c->apn, sizeof c->apn, !c->enabled || usb)) return cell_fail(why, n, "APN required (letters, digits and dots; no quotes)");
    if (!cell_text_ok(c->user, sizeof c->user, true) || !cell_text_ok(c->password, sizeof c->password, true))
        return cell_fail(why, n, "user name and password: printable characters without quotes");
    size_t pin = strnlen(c->pin, sizeof c->pin);
    if (pin == sizeof c->pin || (pin && (pin < 4 || pin > 8))) return cell_fail(why, n, "SIM PIN: 4-8 digits or empty");
    for (size_t i = 0; i < pin; i++) if (!isdigit((unsigned char)c->pin[i])) return cell_fail(why, n, "SIM PIN: 4-8 digits or empty");
    return true;
}

int cell_csq_to_dbm(int csq)
{
    return csq >= 0 && csq <= 31 ? -113 + 2 * csq : 0;
}

/* Value after "<prefix>: " in a response, NULL when absent. */
static const char *cell_field(const char *response, const char *prefix)
{
    const char *p = response ? strstr(response, prefix) : NULL;
    if (!p) return NULL;
    p += strlen(prefix);
    if (*p != ':') return NULL;
    p++;
    while (*p == ' ') p++;
    return p;
}

int cell_parse_csq(const char *response)
{
    const char *p = cell_field(response, "+CSQ");
    if (!p || !isdigit((unsigned char)*p)) return -1;
    long v = strtol(p, NULL, 10);
    return v >= 0 && v <= 99 ? (int)v : -1;
}

/* "+CREG: <n>,<stat>[,...]" (query form) or "+CREG: <stat>" (URC form). */
int cell_parse_reg(const char *response, const char *prefix)
{
    const char *p = cell_field(response, prefix);
    if (!p || !isdigit((unsigned char)*p)) return -1;
    char *end;
    long first = strtol(p, &end, 10);
    long stat = first;
    if (*end == ',') {
        if (!isdigit((unsigned char)end[1])) return -1;
        stat = strtol(end + 1, NULL, 10);
    }
    return stat >= 0 && stat <= 10 ? (int)stat : -1;
}

int cell_parse_cpin(const char *response)
{
    const char *p = cell_field(response, "+CPIN");
    if (!p) return CELL_SIM_OTHER;
    if (!strncmp(p, "READY", 5)) return CELL_SIM_READY;
    if (!strncmp(p, "SIM PIN", 7) && strncmp(p, "SIM PIN2", 8)) return CELL_SIM_PIN;
    if (!strncmp(p, "SIM PUK", 7) && strncmp(p, "SIM PUK2", 8)) return CELL_SIM_PUK;
    return CELL_SIM_OTHER;
}

/* +COPS: 0,0,"Operator Name",7 -> Operator Name */
bool cell_parse_cops(const char *response, char *name, size_t n)
{
    const char *p = cell_field(response, "+COPS");
    const char *open = p ? strchr(p, '"') : NULL;
    const char *close = open ? strchr(open + 1, '"') : NULL;
    if (!close || !n) return false;
    size_t len = (size_t)(close - open - 1);
    if (len >= n) len = n - 1;
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)open[1 + i];
        name[i] = ch >= 0x20 && ch <= 0x7e ? (char)ch : '?';
    }
    name[len] = 0;
    return len > 0;
}

bool cell_registered(int stat, bool roaming)
{
    return stat == 1 || (stat == 5 && roaming);
}

bool cell_uplink_choose(cell_selector_t *s, uint8_t mode, bool other_ok, bool cell_ok)
{
    if (!cell_ok) {s->streak = 0; return false;}
    if (s->streak < CELL_STABLE_SAMPLES) s->streak++;
    if (mode == CELL_MODE_PRIMARY) return s->streak >= CELL_STABLE_SAMPLES || !other_ok;
    return !other_ok;
}

int cell_at_line(const char *line, const char *final)
{
    if (!strcmp(line, "OK") || (final && strstr(line, final))) return 1;
    if (!strcmp(line, "ERROR") || !strncmp(line, "+CME ERROR", 10) || !strcmp(line, "NO CARRIER")
        || !strcmp(line, "BUSY") || !strcmp(line, "NO DIALTONE")) return 0;
    return -1;
}

/* Known USB layouts: the PPP-capable modem port first, then the AT port.
 * From the vendors' Linux USB guides (ttyUSB order); not yet tested here. */
static const struct {uint16_t vid, pid; uint8_t modem, at;} CELL_USB_KNOWN[] = {
    {0x2c7c, 0x0125, 3, 2},   /* Quectel EC25 / EG25-G */
    {0x2c7c, 0x0121, 3, 2},   /* Quectel EC21 */
    {0x2c7c, 0x0195, 3, 2},   /* Quectel EG95 / EG91 */
    {0x2c7c, 0x0296, 3, 2},   /* Quectel BG96 */
    {0x1e0e, 0x9001, 3, 2},   /* SIMCom SIM7600 series */
};

#define CELL_USB_IFACES 32
typedef struct {bool seen; uint8_t cls, sub, proto; bool bulk_in, bulk_out, intr_in;} cell_usb_iface_t;

/* A vendor-specific interface with a bulk pair: a modem's serial port, or a
 * diagnostics/GNSS/QMI port that simply never answers the AT probe. */
static bool cell_usb_serial(const cell_usb_iface_t *f)
{
    return f->seen && f->bulk_in && f->bulk_out && f->cls == 0xff;
}

static void cell_usb_add(cell_usb_plan_t *p, uint8_t iface)
{
    for (unsigned i = 0; i < p->count; i++) if (p->iface[i] == iface) return;
    if (p->count < CELL_USB_MAX_CANDIDATES) p->iface[p->count++] = iface;
}

int cell_usb_plan(uint16_t vid, uint16_t pid, const uint8_t *cfg, size_t len, uint8_t override, cell_usb_plan_t *out)
{
    if (!out) return -1;
    *out = (cell_usb_plan_t){0};
    if (!cfg || len < 9 || cfg[0] < 9 || cfg[1] != 0x02) return -1;
    size_t total = (size_t)cfg[2] | (size_t)cfg[3] << 8;
    if (total < 9 || total > len) return -1;            /* truncated copy: never guess */
    cell_usb_iface_t f[CELL_USB_IFACES] = {0};
    int cur = -1;                                       /* interface (alt 0) owning endpoints */
    bool net = false, acm[CELL_USB_IFACES] = {0};
    for (size_t at = cfg[0]; at < total;) {
        uint8_t l = cfg[at];
        if (l < 2 || at + l > total) return -1;
        uint8_t type = cfg[at + 1];
        if (type == 0x04) {
            if (l < 9) return -1;
            uint8_t num = cfg[at + 2], alt = cfg[at + 3], cls = cfg[at + 5], sub = cfg[at + 6], proto = cfg[at + 7];
            cur = alt == 0 && num < CELL_USB_IFACES ? num : -1;
            /* Network functions this firmware does not drive: RNDIS
             * (02/02/ff, e0/01/03), ECM 02/06, NCM 02/0d, MBIM 02/0e. */
            if ((cls == 0x02 && (sub == 0x06 || sub == 0x0d || sub == 0x0e || (sub == 0x02 && proto == 0xff)))
                || (cls == 0xe0 && sub == 0x01 && proto == 0x03)) net = true;
            else if (cur >= 0 && cls == 0x02 && sub == 0x02) acm[cur] = true;   /* CDC-ACM control interface */
            if (cur >= 0 && !f[cur].seen) f[cur] = (cell_usb_iface_t){.seen = true, .cls = cls, .sub = sub, .proto = proto};
        } else if (type == 0x05 && cur >= 0) {
            if (l < 7) return -1;
            uint8_t addr = cfg[at + 2], kind = cfg[at + 3] & 3;
            if (kind == 2 && (addr & 0x80)) f[cur].bulk_in = true;
            else if (kind == 2) f[cur].bulk_out = true;
            else if (kind == 3 && (addr & 0x80)) f[cur].intr_in = true;
        }
        at += l;
    }
    if (override != CELL_USB_IFACE_AUTO) {
        out->how = CELL_USB_HOW_MANUAL;
        if (override < CELL_USB_IFACES && (acm[override] || cell_usb_serial(&f[override]))) cell_usb_add(out, override);
        return out->count;
    }
    for (size_t i = 0; i < sizeof CELL_USB_KNOWN / sizeof CELL_USB_KNOWN[0]; i++) {
        if (CELL_USB_KNOWN[i].vid != vid || CELL_USB_KNOWN[i].pid != pid) continue;
        if (cell_usb_serial(&f[CELL_USB_KNOWN[i].modem])) cell_usb_add(out, CELL_USB_KNOWN[i].modem);
        if (cell_usb_serial(&f[CELL_USB_KNOWN[i].at])) cell_usb_add(out, CELL_USB_KNOWN[i].at);
        if (out->count) {out->how = CELL_USB_HOW_KNOWN; return out->count;}
    }
    for (unsigned i = 0; i < CELL_USB_IFACES; i++) if (acm[i]) cell_usb_add(out, (uint8_t)i);
    if (out->count) {out->how = CELL_USB_HOW_ACM; return out->count;}
    /* Vendor serial ports: those with a status (interrupt) endpoint first,
     * as Qualcomm-style AT/modem ports have one and diagnostics ports not. */
    for (int pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < CELL_USB_IFACES; i++)
            if (cell_usb_serial(&f[i]) && f[i].intr_in == (pass == 0)) cell_usb_add(out, (uint8_t)i);
    if (out->count) out->how = CELL_USB_HOW_PROBE;
    else out->network_only = net;
    return out->count;
}
/* --- cell core (end) --- */

#define CELL_MAGIC 0x43454c31u /* CEL1 */
typedef struct {uint32_t magic, version; cell_config_t config; uint32_t checksum;} cell_record_t;
/* Version 1 (UART only, up to 3.0.24): read and migrated, never written.
 * A rollback to such a firmware finds a version 2 record and keeps the
 * cellular uplink off (fail closed) until it is saved there again. */
typedef struct {
    uint8_t enabled, uart, mode, roaming, data_ack, pwrkey_active_high;
    int8_t tx, rx, rts, cts, pwrkey;
    uint32_t baud;
    char apn[64], user[32], password[64], pin[9];
} cell_config_v1_t;
typedef struct {uint32_t magic, version; cell_config_v1_t config; uint32_t checksum;} cell_record_v1_t;

static SemaphoreHandle_t s_lock;
static StaticSemaphore_t s_lock_storage;
static cell_config_t s_saved, s_running;
static cell_status_t s_status;
static atomic_bool s_has_ip;
static atomic_bool s_selected_cell;
static atomic_bool s_link_dead __attribute__((unused));   /* PPP builds only */
static esp_netif_t *s_netif;
static struct netif *s_lwip;           /* read in TCP/IP context only after creation */
static cell_selector_t s_selector;     /* TCP/IP context only */
static uart_port_t s_port __attribute__((unused));       /* PPP builds only */

static void defaults(cell_config_t *c)
{
    memset(c, 0, sizeof *c);
    c->uart = 1; c->baud = 115200; c->tx = 17; c->rx = 18; c->rts = -1; c->cts = -1; c->pwrkey = -1;
    c->transport = CELL_TRANSPORT_UART; c->usb_iface = CELL_USB_IFACE_AUTO;
}

static uint32_t cell_fnv(const void *data, size_t n)
{
    uint32_t h = 2166136261u;
    const uint8_t *p = data;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
    return h;
}

static uint32_t record_checksum(const cell_record_t *r)
{
    return cell_fnv(r, offsetof(cell_record_t, checksum));
}

/* Version 1 fields onto the current layout: a UART modem, automatic USB. */
static void migrate_v1(const cell_config_v1_t *v1, cell_config_t *c)
{
    defaults(c);
    c->enabled = v1->enabled; c->uart = v1->uart; c->mode = v1->mode; c->roaming = v1->roaming;
    c->data_ack = v1->data_ack; c->pwrkey_active_high = v1->pwrkey_active_high;
    c->tx = v1->tx; c->rx = v1->rx; c->rts = v1->rts; c->cts = v1->cts; c->pwrkey = v1->pwrkey; c->baud = v1->baud;
    memcpy(c->apn, v1->apn, sizeof c->apn); memcpy(c->user, v1->user, sizeof c->user);
    memcpy(c->password, v1->password, sizeof c->password); memcpy(c->pin, v1->pin, sizeof c->pin);
}

static void load(cell_config_t *out)
{
    defaults(out);
    union {cell_record_t v2; cell_record_v1_t v1;} r;
    _Static_assert(sizeof(cell_record_t) != sizeof(cell_record_v1_t), "record versions must differ in size");
    size_t size = sizeof r;
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return;
    /* Invalid or foreign data means "cellular off", never a guessed modem. */
    cell_config_t c;
    bool ok = false;
    if (nvs_get_blob(nvs, "cell_cfg", &r, &size) == ESP_OK && r.v2.magic == CELL_MAGIC) {
        if (size == sizeof r.v2 && r.v2.version == 2 && r.v2.checksum == record_checksum(&r.v2)) {
            memcpy(&c, &r.v2.config, sizeof c);
            ok = true;
        } else if (size == sizeof r.v1 && r.v1.version == 1
                   && r.v1.checksum == cell_fnv(&r.v1, offsetof(cell_record_v1_t, checksum))) {
            migrate_v1(&r.v1.config, &c);
            ok = true;
        }
    }
    if (ok && cell_config_valid(&c, NULL, 0)) memcpy(out, &c, sizeof c);
    memset(&r, 0, sizeof r);
    memset(&c, 0, sizeof c);
    nvs_close(nvs);
}

static void ensure_lock(void)
{
    static portMUX_TYPE init = portMUX_INITIALIZER_UNLOCKED;
    portENTER_CRITICAL(&init);
    if (!s_lock) s_lock = xSemaphoreCreateMutexStatic(&s_lock_storage);
    portEXIT_CRITICAL(&init);
}

static void set_state(uint8_t state, const char *error)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.state = state;
    if (error) snprintf(s_status.error, sizeof s_status.error, "%s", error);
    xSemaphoreGive(s_lock);
    if (error && error[0]) ESP_LOGW(TAG, "%s", error);
}

#if CONFIG_LWIP_PPP_SUPPORT
/* --- Serial channel: UART pins or a USB serial interface --- */
typedef struct {
    int (*write)(const void *data, size_t len, uint32_t timeout_ms);  /* bytes written, -1 error */
    int (*read)(uint8_t *buf, size_t cap, uint32_t timeout_ms);       /* bytes, 0 timeout, -1 gone */
    void (*flush)(void);
} cell_io_t;
static const cell_io_t *s_io;
static TaskHandle_t s_task;

static int uart_io_write(const void *data, size_t len, uint32_t timeout_ms)
{
    (void)timeout_ms;   /* waits for room in the 2 KB driver ring, as before */
    return uart_write_bytes(s_port, data, len);
}
static int uart_io_read(uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    return uart_read_bytes(s_port, buf, cap, pdMS_TO_TICKS(timeout_ms));
}
static void uart_io_flush(void) {uart_flush_input(s_port);}
static const cell_io_t UART_IO = {uart_io_write, uart_io_read, uart_io_flush};

/* USB serial (CDC-ACM or vendor port): the CDC-ACM driver task delivers
 * received data into a PSRAM stream buffer (single writer, single reader:
 * the modem task). Detection, mode switching and USB network sticks are in
 * usb_port.c. */
#define CELL_USB_CFG_MAX 1024          /* configuration descriptor copy */
#define CELL_USB_RX_BUFFER 4096
#define CELL_USB_OUT_BUFFER 1024       /* one bulk OUT transfer (internal DMA RAM) */
#define CELL_USB_IN_BUFFER 512
/* Estimate, not measured with a modem: USB host objects, the 4 KB CDC driver
 * stack and the DMA transfers, above the 40 KB internal RAM floor. */
#define CELL_USB_INTERNAL_MIN (56 * 1024)
#define CELL_USB_PPP_TX_MS 50          /* TCP/IP thread: never block it long */
static StreamBufferHandle_t s_usb_rx;
static cdc_acm_dev_hdl_t s_usb_dev;    /* opened and closed by the modem task only */
static atomic_bool s_usb_gone;
static atomic_uint s_usb_rx_dropped;
static uint8_t *s_usb_cfg;             /* modem task only */
enum {CELL_NETIF_NONE, CELL_NETIF_PPP, CELL_NETIF_USBNET};
static uint8_t s_netif_kind;           /* modem task (and init) only */

static int usb_io_write(const void *data, size_t len, uint32_t timeout_ms)
{
    cdc_acm_dev_hdl_t dev = s_usb_dev;
    if (!dev || atomic_load(&s_usb_gone)) return -1;
    return cdc_acm_host_data_tx_blocking(dev, data, len, timeout_ms) == ESP_OK ? (int)len : -1;
}
static int usb_io_read(uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    if (!s_usb_dev || atomic_load(&s_usb_gone)) return -1;
    return (int)xStreamBufferReceive(s_usb_rx, buf, cap, pdMS_TO_TICKS(timeout_ms));
}
static void usb_io_flush(void)
{
    uint8_t sink[64];
    while (xStreamBufferReceive(s_usb_rx, sink, sizeof sink, 0) > 0) {}
}
static const cell_io_t USB_IO = {usb_io_write, usb_io_read, usb_io_flush};

/* CDC-ACM driver task context. */
static bool usb_rx(const uint8_t *data, size_t len, void *arg)
{
    (void)arg;
    size_t sent = xStreamBufferSend(s_usb_rx, data, len, 0);
    if (sent < len) atomic_fetch_add(&s_usb_rx_dropped, (unsigned)(len - sent));   /* PPP/TCP recover */
    return true;
}

static void usb_event(const cdc_acm_host_dev_event_data_t *event, void *arg)
{
    (void)arg;
    if (event->type != CDC_ACM_HOST_DEVICE_DISCONNECTED) return;   /* stalls end in AT/PPP timeouts */
    atomic_store(&s_usb_gone, true);
    atomic_store(&s_link_dead, true);
}

/* --- AT command channel (modem task only) --- */
static char s_line[256];

/* Sends `command` and collects the response until OK/ERROR/`final` or the
 * timeout. 1: OK (or `final` seen), 0: ERROR, -1: timeout or channel gone. */
static int at(const char *command, const char *final, char *response, size_t n, int timeout_ms)
{
    if (response && n) response[0] = 0;
    s_io->flush();
    if (command && (s_io->write(command, strlen(command), 1000) < 0 || s_io->write("\r", 1, 1000) < 0)) return -1;
    size_t used = 0, line = 0;
    TickType_t end = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while ((int32_t)(end - xTaskGetTickCount()) > 0) {
        uint8_t ch;
        int got = s_io->read(&ch, 1, 20);
        if (got < 0) return -1;
        if (got != 1) continue;
        if (ch != '\r' && ch != '\n') {
            if (line < sizeof s_line - 1) s_line[line++] = (char)ch;
            continue;
        }
        if (!line) continue;
        s_line[line] = 0;
        line = 0;
        if (command && !strcmp(s_line, command)) continue;   /* echo before ATE0 */
        if (response && used + strlen(s_line) + 2 < n) {
            used += (size_t)snprintf(response + used, n - used, "%s\n", s_line);
        }
        int result = cell_at_line(s_line, final);
        if (result >= 0) return result;
    }
    return -1;
}

static bool at_sync(void)
{
    for (int i = 0; i < 30; i++) if (at("AT", NULL, NULL, 0, 1000) == 1) return true;
    return false;
}

static void modem_power_pulse(void)
{
    if (s_running.pwrkey < 0) return;
    gpio_reset_pin(s_running.pwrkey);
    gpio_set_direction(s_running.pwrkey, GPIO_MODE_OUTPUT);
    int active = s_running.pwrkey_active_high ? 1 : 0;
    gpio_set_level(s_running.pwrkey, !active);
    vTaskDelay(pdMS_TO_TICKS(100));
    gpio_set_level(s_running.pwrkey, active);
    vTaskDelay(pdMS_TO_TICKS(1200));
    gpio_set_level(s_running.pwrkey, !active);
    vTaskDelay(pdMS_TO_TICKS(8000));   /* typical modem boot before AT answers */
}

/* Leaves data mode after the PPP link ended: guard time, "+++", hang up. */
static void hang_up(void)
{
    vTaskDelay(pdMS_TO_TICKS(1100));
    (void)s_io->write("+++", 3, 1000);
    vTaskDelay(pdMS_TO_TICKS(1100));
    (void)at("ATH", NULL, NULL, 0, 3000);
}

static void refresh_info(void)
{
    char response[160], name[32] = "";
    int csq = at("AT+CSQ", NULL, response, sizeof response, 2000) == 1 ? cell_parse_csq(response) : -1;
    bool have_name = at("AT+COPS?", NULL, response, sizeof response, 3000) == 1 && cell_parse_cops(response, name, sizeof name);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.rssi_dbm = (int16_t)cell_csq_to_dbm(csq);
    if (have_name) snprintf(s_status.operator_name, sizeof s_status.operator_name, "%s", name);
    xSemaphoreGive(s_lock);
}

static int registration(void)
{
    static const char *const queries[][2] = {{"AT+CEREG?", "+CEREG"}, {"AT+CGREG?", "+CGREG"}, {"AT+CREG?", "+CREG"}};
    char response[160];
    int best = -1;
    for (size_t i = 0; i < 3; i++) {
        if (at(queries[i][0], NULL, response, sizeof response, 2000) != 1) continue;
        int stat = cell_parse_reg(response, queries[i][1]);
        if (cell_registered(stat, s_running.roaming)) return stat;
        if (stat >= 0) best = stat;
    }
    return best;
}

/* --- PPP netif glue --- */
typedef struct {esp_netif_driver_base_t base;} cell_driver_t;
static cell_driver_t s_driver;

static esp_err_t cell_transmit(void *handle, void *buffer, size_t len)
{
    (void)handle;
    return s_io->write(buffer, len, CELL_USB_PPP_TX_MS) == (int)len ? ESP_OK : ESP_FAIL;
}

static esp_err_t cell_post_attach(esp_netif_t *netif, void *args)
{
    cell_driver_t *driver = args;
    driver->base.netif = netif;
    const esp_netif_driver_ifconfig_t ifconfig = {.handle = driver, .transmit = cell_transmit};
    return esp_netif_set_driver_config(netif, &ifconfig);
}

static void apply_choice(void)
{
    if (tailscale_exit_node_ip != 0) return;
    esp_netif_t *want = uplink_internet_netif();
    esp_netif_ip_info_t info = {0};
    if (uplink_address(want, &info) && esp_netif_get_default_netif() != want) {
        uplink_services_schedule_refresh();
    }
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == NETIF_PPP_STATUS) {
        if (id > NETIF_PPP_ERRORNONE && id < NETIF_PP_PHASE_OFFSET) atomic_store(&s_link_dead, true);
        return;
    }
    if (base == IP_EVENT && (id == IP_EVENT_PPP_GOT_IP || id == IP_EVENT_PPP_LOST_IP)) {
        bool got = id == IP_EVENT_PPP_GOT_IP;
        if (got && ((const ip_event_got_ip_t *)data)->esp_netif != s_netif) return;
        atomic_store(&s_has_ip, got);
        if (!got) atomic_store(&s_link_dead, true);
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_status.ip = got ? ((const ip_event_got_ip_t *)data)->ip_info.ip.addr : 0;
        if (got) s_status.connects++;
        xSemaphoreGive(s_lock);
        uplink_services_refresh(!got);
    }
}

static esp_err_t create_netif(void)
{
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_PPP();
    base.if_desc = "cell";
    base.route_prio = 5;   /* never the automatic default over WiFi or Ethernet */
    esp_netif_config_t config = {.base = &base, .driver = NULL, .stack = ESP_NETIF_NETSTACK_DEFAULT_PPP};
    s_netif = esp_netif_new(&config);
    if (!s_netif) return ESP_ERR_NO_MEM;
    s_driver.base.post_attach = cell_post_attach;
    esp_err_t err = esp_netif_attach(s_netif, &s_driver);
    esp_netif_ppp_config_t ppp = {.ppp_phase_event_enabled = false, .ppp_error_event_enabled = true};
    if (err == ESP_OK) err = esp_netif_ppp_set_params(s_netif, &ppp);
    if (err == ESP_OK && s_running.user[0])
        err = esp_netif_ppp_set_auth(s_netif, NETIF_PPP_AUTHTYPE_PAP, s_running.user, s_running.password);
    /* Fail closed: without the PPP ACL hooks the link never carries traffic. */
    struct netif *lwip = esp_netif_get_netif_impl(s_netif);
    if (err == ESP_OK && !netif_hooks_install_ppp(lwip)) err = ESP_ERR_INVALID_STATE;
    if (err == ESP_OK)
        err = esp_event_handler_register(NETIF_PPP_STATUS, ESP_EVENT_ANY_ID, on_event, NULL);
    if (err == ESP_OK)
        err = esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    if (err != ESP_OK) {esp_netif_destroy(s_netif); s_netif = NULL; return err;}
    s_lwip = lwip;
    return ESP_OK;
}

static esp_err_t open_uart(void)
{
    s_port = s_running.uart == 1 ? UART_NUM_1 : UART_NUM_2;
    uart_config_t config = {.baud_rate = (int)s_running.baud, .data_bits = UART_DATA_8_BITS, .parity = UART_PARITY_DISABLE,
                            .stop_bits = UART_STOP_BITS_1, .source_clk = UART_SCLK_DEFAULT,
                            .flow_ctrl = s_running.rts >= 0 ? UART_HW_FLOWCTRL_CTS_RTS : UART_HW_FLOWCTRL_DISABLE,
                            .rx_flow_ctrl_thresh = 100};
    esp_err_t err = uart_driver_install(s_port, 4096, 2048, 0, NULL, 0);
    if (err == ESP_OK) err = uart_param_config(s_port, &config);
    if (err == ESP_OK) err = uart_set_pin(s_port, s_running.tx, s_running.rx,
                                          s_running.rts >= 0 ? s_running.rts : UART_PIN_NO_CHANGE,
                                          s_running.cts >= 0 ? s_running.cts : UART_PIN_NO_CHANGE);
    if (err == ESP_OK) s_io = &UART_IO;
    return err;
}

/* USB connection: the USB host stack, the gateway's USB client and the
 * CDC-ACM driver are installed only here, only when the USB connection is
 * selected and enabled. The native USB port then stays a host port until
 * the next restart (no USB-Serial-JTAG console on it). */
static esp_err_t open_usb(void)
{
    if (heap_caps_get_free_size(MALLOC_CAP_INTERNAL) < CELL_USB_INTERNAL_MIN) return ESP_ERR_NO_MEM;
    s_usb_cfg = heap_caps_malloc(CELL_USB_CFG_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_usb_rx = xStreamBufferCreateWithCaps(CELL_USB_RX_BUFFER, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_usb_cfg || !s_usb_rx) return ESP_ERR_NO_MEM;
    esp_err_t err = usb_port_start(true);
    if (err == ESP_OK) s_io = &USB_IO;
    return err;   /* a partial install stays until restart; the uplink is stopped */
}

/* Ethernet-type netif for a USB network stick (DHCP from the stick). It
 * reports PPP address events so the cellular selection treats it exactly
 * like the PPP link; the ACL hooks attach when lwIP adds it (fail closed). */
static esp_err_t create_usbnet_netif(void)
{
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
    base.if_key = "CELL_USB";
    base.if_desc = "cellusb";
    base.route_prio = 5;   /* never the automatic default over WiFi or Ethernet */
    base.get_ip_event = IP_EVENT_PPP_GOT_IP;
    base.lost_ip_event = IP_EVENT_PPP_LOST_IP;
    esp_netif_config_t config = {.base = &base, .driver = NULL, .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH};
    esp_netif_t *netif = esp_netif_new(&config);
    if (!netif) return ESP_ERR_NO_MEM;
    esp_err_t err = esp_netif_attach(netif, usb_port_net_glue());
    struct netif *lwip = esp_netif_get_netif_impl(netif);
    if (err == ESP_OK && !netif_hooks_register_usbnet(lwip)) err = ESP_ERR_INVALID_STATE;
    if (err == ESP_OK) err = esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    if (err != ESP_OK) {esp_netif_destroy(netif); return err;}
    s_netif = netif;
    s_lwip = lwip;
    return ESP_OK;
}

/* One netif per boot: the first USB device decides serial (PPP) or network. */
static esp_err_t ensure_netif(uint8_t kind, const char **why)
{
    if (s_netif_kind == kind) return ESP_OK;
    if (s_netif_kind != CELL_NETIF_NONE) {
        *why = kind == CELL_NETIF_PPP ? "this USB device needs the serial connection: restart the gateway to switch to it"
                                      : "this USB device needs the network connection: restart the gateway to switch to it";
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t err = kind == CELL_NETIF_PPP ? create_netif() : create_usbnet_netif();
    if (err != ESP_OK) {*why = "could not create the network interface"; return err;}
    s_netif_kind = kind;
    return ESP_OK;
}

static void usb_close(void)
{
    if (s_usb_dev) cdc_acm_host_close(s_usb_dev);
    s_usb_dev = NULL;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.usb_iface = 0xff;
    s_status.usb_how = CELL_USB_HOW_NONE;
    s_status.usb_action = USBP_ACT_NONE;
    s_status.usb_net = USBP_NET_NONE;
    xSemaphoreGive(s_lock);
}

/* Tries the planned serial interfaces in order (at most
 * CELL_USB_MAX_CANDIDATES, each with a 3 s open and three 1 s AT probes). */
static bool usb_serial_open(const usbp_device_t *d, const cell_usb_plan_t *plan, const char **why)
{
    atomic_store(&s_usb_gone, false);
    for (int i = 0; i < plan->count; i++) {
        const cdc_acm_host_open_config_t open = {.vid = d->vid, .pid = d->pid, .interface_idx = plan->iface[i],
            .dev_addr = d->address, .connection_timeout_ms = 3000, .out_buffer_size = CELL_USB_OUT_BUFFER,
            .in_buffer_size = CELL_USB_IN_BUFFER, .event_cb = usb_event, .data_cb = usb_rx};
        cdc_acm_dev_hdl_t dev = NULL;
        if (cdc_acm_host_open_v2(&open, &dev) != ESP_OK || !dev) continue;
        s_usb_dev = dev;
        (void)cdc_acm_host_set_control_line_state(dev, true, true);   /* DTR: some modems need it; vendor ports may refuse */
        usb_io_flush();
        bool answered = false;
        for (int t = 0; t < 3 && !answered && !atomic_load(&s_usb_gone); t++) answered = at("AT", NULL, NULL, 0, 1000) == 1;
        if (answered) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            s_status.usb_iface = plan->iface[i];
            s_status.usb_how = plan->how;
            s_status.usb_action = USBP_ACT_SERIAL;
            xSemaphoreGive(s_lock);
            ESP_LOGI(TAG, "USB modem %04x:%04x answers AT on interface %u", d->vid, d->pid, plan->iface[i]);
            return true;
        }
        usb_close();
        if (atomic_load(&s_usb_gone)) break;
    }
    *why = "no USB interface of the modem answered AT";
    return false;
}

/* Waits up to `ms` for a device whose attach sequence differs from `seq`. */
static bool usb_wait_device(uint32_t seq, uint32_t ms, usbp_device_t *d, size_t *len)
{
    TickType_t end = xTaskGetTickCount() + pdMS_TO_TICKS(ms);
    for (;;) {
        if (usb_port_device(d, s_usb_cfg, CELL_USB_CFG_MAX, len) && d->seq != seq) return true;
        int32_t left = (int32_t)(end - xTaskGetTickCount());
        if (left <= 0) return false;
        usb_port_wait(d->seq, (uint32_t)left * portTICK_PERIOD_MS);
    }
}

/* Brings up the attached USB device: a serial (AT) interface, or a network
 * function, after a mode switch or another configuration if needed
 * (bounded rounds). Returns USBP_ACT_SERIAL, USBP_ACT_NETWORK or -1. */
static int usb_attach(uint32_t wait_ms, const char **why)
{
    if (s_usb_dev && !atomic_load(&s_usb_gone)) return USBP_ACT_SERIAL;
    usb_close();
    usbp_device_t d = {0};
    size_t len = 0;
    uint32_t seen = 0;   /* 0: any device; otherwise wait for a new attach */
    for (int round = 0; round < 4; round++) {
        if (!usb_wait_device(seen, round ? 25000 : wait_ms, &d, &len)) {
            *why = round ? "the USB device did not come back after switching its mode"
                         : "no USB device on the USB port: check the cable, the OTG port and the device's 5 V supply";
            return -1;
        }
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_status.usb_vid = d.vid; s_status.usb_pid = d.pid;
        xSemaphoreGive(s_lock);
        cell_usb_plan_t plan;
        usbp_net_t net;
        usbp_storage_t storage;
        int serial = cell_usb_plan(d.vid, d.pid, s_usb_cfg, len, s_running.usb_iface, &plan);
        if (serial < 0 || usbp_scan(s_usb_cfg, len, &net, &storage) < 0) {*why = "USB device descriptor unreadable or larger than 1 KB"; return -1;}
        int action = usbp_action(true, s_running.usb_mode, serial, &net, &storage, d.num_configs, d.config_value);
        if (action == USBP_ACT_SERIAL) {
            if (ensure_netif(CELL_NETIF_PPP, why) != ESP_OK) return -1;
            return usb_serial_open(&d, &plan, why) ? USBP_ACT_SERIAL : -1;
        }
        if (action == USBP_ACT_NETWORK) {
            if (ensure_netif(CELL_NETIF_USBNET, why) != ESP_OK) return -1;
            if (usb_port_net_open(&d, &net, s_netif, NULL, NULL, why) != ESP_OK) return -1;
            xSemaphoreTake(s_lock, portMAX_DELAY);
            s_status.usb_action = USBP_ACT_NETWORK;
            s_status.usb_net = net.kind;
            s_status.usb_iface = net.data;
            xSemaphoreGive(s_lock);
            return USBP_ACT_NETWORK;
        }
        if (action == USBP_ACT_SWITCH || action == USBP_ACT_NEXT_CONFIG) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            s_status.usb_action = USBP_ACT_SWITCH;
            if (action == USBP_ACT_SWITCH) s_status.usb_switches++;
            xSemaphoreGive(s_lock);
            set_state(CELL_SYNC, action == USBP_ACT_SWITCH ? "switching the USB stick from storage to modem mode"
                                                           : "trying another USB configuration of the device");
            bool started = action == USBP_ACT_SWITCH ? usb_port_switch(&d, &storage) != ESP_ERR_INVALID_STATE
                                                     : usb_port_next_config(&d);
            if (!started) {
                *why = action == USBP_ACT_SWITCH ? "the USB stick stays in storage mode: it may need a switch this firmware does not know"
                                                 : "no configuration of this USB device has a usable modem or network interface";
                return -1;
            }
            seen = d.seq;
            continue;
        }
        *why = net.kind == USBP_NET_UNSUPPORTED ? "the device's USB network function (for example MBIM) is not supported: use a mode with serial AT ports or RNDIS/ECM/NCM"
             : plan.network_only && s_running.usb_mode == USBP_MODE_SERIAL ? "the device has no serial (AT) interface: set the USB mode to automatic or network"
             : serial > 0 && s_running.usb_mode == USBP_MODE_NETWORK ? "the device has no USB network interface: set the USB mode to automatic or serial"
             : plan.how == CELL_USB_HOW_MANUAL ? "the chosen USB interface is not a serial interface on this modem"
             : "no serial or network interface found on the USB device";
        return -1;
    }
    *why = "the USB device did not settle in a usable mode";
    return -1;
}

/* Bounded retry: 30 s doubling to 10 min; a SIM PIN/PUK problem stops. */
static uint32_t backoff_s(unsigned failures)
{
    uint32_t s = 30u << (failures < 5 ? failures : 5);
    return s > 600 ? 600 : s;
}

static void cell_task(void *arg)
{
    (void)arg;
    unsigned failures = 0;
    /* PWRKEY toggles many modems: pulse only at start and after the modem
     * stopped answering AT, never after an ordinary end of the data call. */
    bool power_pulse = true, pin_sent = false;
    char response[192];
    uint8_t *buffer = heap_caps_malloc(512, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buffer) {set_state(CELL_STOPPED, "not enough memory for the modem buffer"); vTaskDelete(NULL); return;}
    for (;;) {
        if (power_pulse) {set_state(CELL_POWERING, NULL); modem_power_pulse(); power_pulse = false;}
        set_state(CELL_SYNC, NULL);
        if (s_running.transport == CELL_TRANSPORT_USB) {
            const char *why = "USB modem not ready";
            /* Enumeration after power-on or a PWRKEY pulse takes seconds. */
            int attached = usb_attach(20000, &why);
            if (attached < 0) {
                power_pulse = s_running.pwrkey >= 0;
                set_state(CELL_BACKOFF, why);
                goto retry;
            }
            if (attached == USBP_ACT_NETWORK) {
                /* The stick dials by itself (its own APN/PIN settings); the
                 * gateway runs DHCP over USB and watches the data path. */
                set_state(CELL_DIALING, "");
                TickType_t last_choice = xTaskGetTickCount();
                while (usb_port_net_alive()) {
                    vTaskDelay(pdMS_TO_TICKS(250));
                    if (atomic_load(&s_has_ip) && s_status.state != CELL_CONNECTED) set_state(CELL_CONNECTED, "");
                    if (xTaskGetTickCount() - last_choice > pdMS_TO_TICKS(2000)) {apply_choice(); last_choice = xTaskGetTickCount();}
                }
                usb_port_net_close();
                atomic_store(&s_has_ip, false);
                apply_choice();
                usb_close();
                set_state(CELL_BACKOFF, "USB network device disconnected; waiting for it to come back");
                failures = 0;
                goto retry;
            }
        }
        if (!at_sync()) {
            power_pulse = true;
            if (s_running.transport == CELL_TRANSPORT_USB) usb_close();
            set_state(CELL_BACKOFF, s_running.transport == CELL_TRANSPORT_USB ? "USB modem stopped answering AT"
                                                                              : "modem does not answer AT: check wiring, baud rate and power");
            goto retry;
        }
        (void)at("ATE0", NULL, NULL, 0, 1000);
        (void)at("AT+CMEE=2", NULL, NULL, 0, 1000);
        if (at("AT+CGMM", NULL, response, sizeof response, 2000) == 1) {
            char *end = strchr(response, '\n');
            if (end) *end = 0;
            xSemaphoreTake(s_lock, portMAX_DELAY);
            snprintf(s_status.model, sizeof s_status.model, "%.31s", response);
            xSemaphoreGive(s_lock);
        }
        set_state(CELL_SIM, NULL);
        int sim = at("AT+CPIN?", "+CPIN", response, sizeof response, 5000) == 1 ? cell_parse_cpin(response) : CELL_SIM_OTHER;
        if (sim == CELL_SIM_PUK) {set_state(CELL_STOPPED, "SIM is PUK-locked: unlock it in a phone, then restart"); break;}
        if (sim == CELL_SIM_PIN) {
            /* One attempt per boot: a wrong PIN must never count down to PUK. */
            if (!s_running.pin[0]) {set_state(CELL_STOPPED, "SIM needs a PIN: enter it and restart"); break;}
            if (pin_sent) {set_state(CELL_STOPPED, "SIM PIN rejected: check it and restart"); break;}
            char command[32];
            snprintf(command, sizeof command, "AT+CPIN=\"%s\"", s_running.pin);
            pin_sent = true;
            if (at(command, NULL, NULL, 0, 10000) != 1) {set_state(CELL_STOPPED, "SIM PIN rejected: check it and restart"); break;}
            vTaskDelay(pdMS_TO_TICKS(5000));
            sim = at("AT+CPIN?", "+CPIN", response, sizeof response, 5000) == 1 ? cell_parse_cpin(response) : CELL_SIM_OTHER;
        }
        if (sim != CELL_SIM_READY) {set_state(CELL_BACKOFF, "SIM not ready (inserted?)"); goto retry;}
        set_state(CELL_REGISTERING, NULL);
        int stat = -1;
        for (int i = 0; i < 60 && !cell_registered(stat, s_running.roaming); i++) {
            stat = registration();
            if (!cell_registered(stat, s_running.roaming)) vTaskDelay(pdMS_TO_TICKS(2000));
        }
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_status.registration = stat < 0 ? 0xff : (uint8_t)stat;
        xSemaphoreGive(s_lock);
        refresh_info();
        if (!cell_registered(stat, s_running.roaming)) {
            set_state(CELL_BACKOFF, stat == 5 ? "roaming network: allow roaming to use it" : "not registered on a mobile network");
            goto retry;
        }
        set_state(CELL_DIALING, NULL);
        char command[96];
        snprintf(command, sizeof command, "AT+CGDCONT=1,\"IP\",\"%s\"", s_running.apn);
        /* USB without an APN: the modem's own default context. */
        if (s_running.apn[0] && at(command, NULL, NULL, 0, 5000) != 1) {set_state(CELL_BACKOFF, "APN rejected by the modem"); goto retry;}
        if (at("ATD*99#", "CONNECT", NULL, 0, 30000) != 1) {set_state(CELL_BACKOFF, "data call refused (APN, plan or coverage)"); goto retry;}
        atomic_store(&s_link_dead, false);
        set_state(CELL_CONNECTED, "");
        esp_netif_action_start(s_netif, 0, 0, 0);
        TickType_t last_choice = xTaskGetTickCount();
        while (!atomic_load(&s_link_dead)) {
            int n = s_io->read(buffer, 512, 50);
            if (n > 0) esp_netif_receive(s_netif, buffer, (size_t)n, NULL);
            else if (n < 0) atomic_store(&s_link_dead, true);   /* USB modem gone */
            if (xTaskGetTickCount() - last_choice > pdMS_TO_TICKS(2000)) {apply_choice(); last_choice = xTaskGetTickCount();}
        }
        esp_netif_action_stop(s_netif, 0, 0, 0);
        atomic_store(&s_has_ip, false);
        apply_choice();
        bool unplugged = s_running.transport == CELL_TRANSPORT_USB && atomic_load(&s_usb_gone);
        if (!unplugged) hang_up();
        set_state(CELL_BACKOFF, unplugged ? "USB modem disconnected; waiting for it to come back" : "data link ended; reconnecting");
        failures = 0;
retry:
        if (++failures > 30) failures = 30;
        vTaskDelay(pdMS_TO_TICKS(backoff_s(failures - 1) * 1000));
    }
    free(buffer);
    vTaskDelete(NULL);
}

#endif /* CONFIG_LWIP_PPP_SUPPORT */

void cell_uplink_init(void)
{
    ensure_lock();
    load(&s_saved);
    s_running = s_saved;
    s_status.enabled_at_boot = s_running.enabled;
    s_status.registration = 0xff;
    s_status.transport = s_running.transport;
    s_status.usb_iface = 0xff;
#if !CONFIG_LWIP_PPP_SUPPORT
    /* The 2.1 migration bridge has no PPP: settings are kept, nothing runs. */
    if (s_running.enabled) set_state(CELL_STOPPED, "cellular support is not in this firmware");
#else
    s_status.compiled = true;
    if (!s_running.enabled) return;   /* nothing touched: no UART, USB host, GPIO or netif */
    esp_err_t err = s_running.transport == CELL_TRANSPORT_USB ? open_usb() : open_uart();
    /* UART: PPP now. USB: the first device decides PPP or a USB network netif. */
    if (err == ESP_OK && s_running.transport == CELL_TRANSPORT_UART) {
        err = create_netif();   /* fails closed without the PPP ACL hooks */
        if (err == ESP_OK) s_netif_kind = CELL_NETIF_PPP;
    }
    if (err != ESP_OK) {
        char text[80];
        snprintf(text, sizeof text, "not started: %s", esp_err_to_name(err));
        set_state(CELL_STOPPED, text);
        return;
    }
    /* PSRAM stack: the task never writes flash (no NVS access). */
    if (xTaskCreatePinnedToCoreWithCaps(cell_task, "cell_modem", 6144, NULL, 5, &s_task, tskNO_AFFINITY,
                                        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
        set_state(CELL_STOPPED, "not started: no memory for the modem task");
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.task_running = true;
    xSemaphoreGive(s_lock);
#endif
}

void cell_uplink_get_config(cell_config_t *out)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_saved;
    xSemaphoreGive(s_lock);
}

esp_err_t cell_uplink_set_config(const cell_config_t *c, char *why, size_t n)
{
    ensure_lock();
    if (!cell_config_valid(c, why, n)) return ESP_ERR_INVALID_ARG;
    if (c->enabled) {
        /* Never share a pin with an enabled Ethernet module. */
        eth_config_t e;
        eth_uplink_get_config(&e);
        int8_t mine[] = {c->tx, c->rx, c->rts, c->cts, c->pwrkey}, theirs[] = {e.sclk, e.mosi, e.miso, e.cs, e.intr, e.rst};
        /* One USB port: one device at a time (no hubs). */
        if (e.enabled && e.transport == ETH_TRANSPORT_USB && c->transport == CELL_TRANSPORT_USB) {
            snprintf(why, n, "the USB port is already used by the Ethernet uplink");
            return ESP_ERR_INVALID_ARG;
        }
        /* USB uses no GPIO besides the optional PWRKEY; a USB Ethernet adapter none. */
        for (unsigned i = c->transport == CELL_TRANSPORT_USB ? 4 : 0; e.enabled && e.transport == ETH_TRANSPORT_SPI && i < sizeof mine; i++)
            for (unsigned j = 0; mine[i] >= 0 && j < sizeof theirs; j++)
                if (mine[i] == theirs[j]) {snprintf(why, n, "pin %d is used by the Ethernet module", mine[i]); return ESP_ERR_INVALID_ARG;}
    }
    cell_record_t r;
    memset(&r, 0, sizeof r);
    r.magic = CELL_MAGIC; r.version = 2;
    memcpy(&r.config, c, sizeof r.config);
    r.checksum = record_checksum(&r);
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, "cell_cfg", &r, sizeof r);
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (err != ESP_OK) return err;   /* RAM keeps the previously saved value */
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_saved = *c;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

void cell_uplink_get_status(cell_status_t *out)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_status;
    out->restart_required = memcmp(&s_saved, &s_running, sizeof s_saved) != 0;
    xSemaphoreGive(s_lock);
    out->has_ip = atomic_load(&s_has_ip);
    out->selected = s_netif && uplink_internet_netif() == s_netif;
    out->bytes_in = netif_hooks_get_ppp_bytes_in() + netif_hooks_get_usbnet_bytes_in();
    out->bytes_out = netif_hooks_get_ppp_bytes_out() + netif_hooks_get_usbnet_bytes_out();
#if CONFIG_LWIP_PPP_SUPPORT
    uint32_t net_rx_dropped = 0;
    if (s_running.transport == CELL_TRANSPORT_USB && s_running.enabled) {
        usbp_device_t d;
        out->usb_present = usb_port_device(&d, NULL, 0, NULL);
        usb_port_counters(&net_rx_dropped, NULL, NULL, NULL);
    }
    out->usb_rx_dropped = atomic_load(&s_usb_rx_dropped) + net_rx_dropped;
#endif
}

struct netif *cell_uplink_lwip_select(struct netif *current)
{
    if (!s_running.enabled || !s_lwip) return NULL;
    bool other_ok = current && netif_is_up(current) && netif_is_link_up(current) && ip4_addr_get_u32(netif_ip4_addr(current));
    bool cell_ok = atomic_load(&s_has_ip) && netif_is_up(s_lwip) && ip4_addr_get_u32(netif_ip4_addr(s_lwip));
    bool use = cell_uplink_choose(&s_selector, s_running.mode, other_ok, cell_ok);
    atomic_store(&s_selected_cell, use);
    return use ? s_lwip : NULL;
}

struct netif *cell_uplink_selected_lwip(void)
{
    return s_lwip && atomic_load(&s_has_ip) && netif_is_up(s_lwip) &&
           (atomic_load(&s_selected_cell) || netif_default == s_lwip) ? s_lwip : NULL;
}

esp_netif_t *cell_uplink_preferred_netif(esp_netif_t *lan)
{
    esp_netif_ip_info_t info = {0};
    cell_selector_t immediate = {.streak = CELL_STABLE_SAMPLES};
    bool use = s_netif && cell_uplink_choose(&immediate, s_running.mode,
                                           uplink_address(lan, &info), atomic_load(&s_has_ip));
    return use ? s_netif : lan;
}

/* --- HTTP --- */
static const char *const STATE_NAMES[] = {"off", "powering", "sync", "sim", "registering", "dialing", "connected", "backoff", "stopped"};
static const char *const USB_HOW_NAMES[] = {"none", "known", "acm", "probe", "manual"};
static const char *const USB_MODE_NAMES[] = {"auto", "serial", "network"};
static const char *const USB_ACTION_NAMES[] = {"none", "serial", "network", "switching", "switching"};
static const char *const USB_NET_NAMES[] = {"none", "ecm", "ncm", "rndis", "unsupported"};

static esp_err_t send_json(httpd_req_t *req, cJSON *root)
{
    char *body = root ? cJSON_PrintUnformatted(root) : NULL;
    cJSON_Delete(root);
    if (!body) {httpd_resp_send_500(req); return ESP_FAIL;}
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t err = httpd_resp_sendstr(req, body);
    free(body);
    return err;
}

static esp_err_t get_cellular(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    cell_config_t c; cell_status_t s;
    cell_uplink_get_config(&c);
    cell_uplink_get_status(&s);
    cJSON *root = cJSON_CreateObject();
    cJSON *config = root ? cJSON_AddObjectToObject(root, "config") : NULL;
    cJSON *status = root ? cJSON_AddObjectToObject(root, "status") : NULL;
    if (!config || !status) {cJSON_Delete(root); return send_json(req, NULL);}
    cJSON_AddBoolToObject(config, "enabled", c.enabled);
    cJSON_AddStringToObject(config, "mode", c.mode == CELL_MODE_PRIMARY ? "primary" : "failover");
    cJSON_AddBoolToObject(config, "roaming", c.roaming);
    cJSON_AddBoolToObject(config, "data_ack", c.data_ack);
    cJSON_AddStringToObject(config, "transport", c.transport == CELL_TRANSPORT_USB ? "usb" : "uart");
    cJSON_AddNumberToObject(config, "usb_interface", c.usb_iface == CELL_USB_IFACE_AUTO ? -1 : c.usb_iface);
    cJSON_AddStringToObject(config, "usb_mode", USB_MODE_NAMES[c.usb_mode <= 2 ? c.usb_mode : 0]);
    cJSON_AddNumberToObject(config, "uart", c.uart);
    cJSON_AddNumberToObject(config, "baud", c.baud);
    cJSON_AddNumberToObject(config, "tx", c.tx); cJSON_AddNumberToObject(config, "rx", c.rx);
    cJSON_AddNumberToObject(config, "rts", c.rts); cJSON_AddNumberToObject(config, "cts", c.cts);
    cJSON_AddNumberToObject(config, "pwrkey", c.pwrkey);
    cJSON_AddBoolToObject(config, "pwrkey_active_high", c.pwrkey_active_high);
    cJSON_AddStringToObject(config, "apn", c.apn);
    cJSON_AddStringToObject(config, "user", c.user);
    /* Write-only secrets: presence only. */
    cJSON_AddBoolToObject(config, "has_password", c.password[0] != 0);
    cJSON_AddBoolToObject(config, "has_pin", c.pin[0] != 0);
    cJSON_AddBoolToObject(status, "compiled", s.compiled);
    cJSON_AddBoolToObject(status, "enabled_at_boot", s.enabled_at_boot);
    cJSON_AddBoolToObject(status, "task_running", s.task_running);
    cJSON_AddStringToObject(status, "state", s.state < sizeof STATE_NAMES / sizeof STATE_NAMES[0] ? STATE_NAMES[s.state] : "unknown");
    if (s.registration == 0xff) cJSON_AddNullToObject(status, "registration");
    else cJSON_AddNumberToObject(status, "registration", s.registration);
    if (s.rssi_dbm) cJSON_AddNumberToObject(status, "rssi_dbm", s.rssi_dbm);
    else cJSON_AddNullToObject(status, "rssi_dbm");
    cJSON_AddStringToObject(status, "model", s.model);
    cJSON_AddStringToObject(status, "operator", s.operator_name);
    char ip[16] = "";
    if (s.ip) {struct in_addr a = {.s_addr = s.ip}; inet_ntoa_r(a, ip, sizeof ip);}
    cJSON_AddStringToObject(status, "ip", ip);
    cJSON_AddBoolToObject(status, "has_ip", s.has_ip);
    cJSON_AddBoolToObject(status, "selected_uplink", s.selected);
    cJSON_AddBoolToObject(status, "restart_required", s.restart_required);
    cJSON_AddNumberToObject(status, "connects", s.connects);
    cJSON_AddNumberToObject(status, "bytes_in", (double)s.bytes_in);
    cJSON_AddNumberToObject(status, "bytes_out", (double)s.bytes_out);
    cJSON_AddStringToObject(status, "error", s.error);
    cJSON_AddStringToObject(status, "transport", s.transport == CELL_TRANSPORT_USB ? "usb" : "uart");
    if (s.transport != CELL_TRANSPORT_USB || !s.enabled_at_boot) cJSON_AddNullToObject(status, "usb");
    else {
        cJSON *usb = cJSON_AddObjectToObject(status, "usb");
        if (usb) {
            char id[10] = "";
            if (s.usb_present) snprintf(id, sizeof id, "%04x:%04x", s.usb_vid, s.usb_pid);
            cJSON_AddBoolToObject(usb, "present", s.usb_present);
            cJSON_AddStringToObject(usb, "id", id);
            cJSON_AddNumberToObject(usb, "interface", s.usb_iface == 0xff ? -1 : s.usb_iface);
            cJSON_AddStringToObject(usb, "chosen_by", s.usb_how < sizeof USB_HOW_NAMES / sizeof USB_HOW_NAMES[0] ? USB_HOW_NAMES[s.usb_how] : "none");
            cJSON_AddNumberToObject(usb, "rx_dropped", s.usb_rx_dropped);
            cJSON_AddStringToObject(usb, "mode", s.usb_action < 5 ? USB_ACTION_NAMES[s.usb_action] : "none");
            cJSON_AddStringToObject(usb, "network", s.usb_net < 5 ? USB_NET_NAMES[s.usb_net] : "none");
            cJSON_AddNumberToObject(usb, "switches", s.usb_switches);
        }
    }
    cJSON_AddStringToObject(status, "qualification", "experimental: not physically validated with a modem");
    return send_json(req, root);
}

static bool json_int(const cJSON *root, const char *name, int lo, int hi, int *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsNumber(v) || !isfinite(v->valuedouble) || v->valuedouble < lo || v->valuedouble > hi
        || floor(v->valuedouble) != v->valuedouble) return false;
    *out = (int)v->valuedouble;
    return true;
}

static bool json_text(const cJSON *root, const char *name, char *out, size_t cap)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(v) || strlen(v->valuestring) >= cap) return false;
    snprintf(out, cap, "%s", v->valuestring);
    return true;
}

/* A write-only secret: absent or "" keeps the saved value, clear_<name>
 * removes it, any other string replaces it. */
static bool json_secret(const cJSON *root, const char *name, const char *clear, const char *saved, char *out, size_t cap)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    const cJSON *drop = cJSON_GetObjectItemCaseSensitive(root, clear);
    if (drop && !cJSON_IsBool(drop)) return false;
    snprintf(out, cap, "%s", saved);
    if (cJSON_IsTrue(drop)) out[0] = 0;
    if (!v) return true;
    if (!cJSON_IsString(v) || strlen(v->valuestring) >= cap) return false;
    if (v->valuestring[0]) snprintf(out, cap, "%s", v->valuestring);
    return true;
}

static esp_err_t post_cellular(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    char body[768], why[96] = "invalid request";
    int total = req->content_len, received = 0;
    if (total <= 0 || total >= (int)sizeof body) {httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body size"); return ESP_FAIL;}
    while (received < total) {
        int n = httpd_req_recv(req, body + received, total - received);
        if (n <= 0) {httpd_resp_send_408(req); return ESP_FAIL;}
        received += n;
    }
    body[received] = 0;
    cell_config_t saved, c = {0};
    cell_uplink_get_config(&saved);
    cJSON *root = json_guard_parse(body);
    int uart = 0, baud = 0, tx, rx, rts, cts, pwrkey, usb_iface = saved.usb_iface == CELL_USB_IFACE_AUTO ? -1 : saved.usb_iface;
    uint8_t transport = saved.transport;
    /* transport/usb_interface are optional: older clients keep the saved choice. */
    const cJSON *jt = cJSON_GetObjectItemCaseSensitive(root, "transport");
    bool transport_ok = !jt || (cJSON_IsString(jt) && (!strcmp(jt->valuestring, "uart") || !strcmp(jt->valuestring, "usb")));
    if (transport_ok && jt) transport = !strcmp(jt->valuestring, "usb") ? CELL_TRANSPORT_USB : CELL_TRANSPORT_UART;
    bool iface_ok = !cJSON_GetObjectItemCaseSensitive(root, "usb_interface") || json_int(root, "usb_interface", -1, CELL_USB_IFACE_MAX, &usb_iface);
    uint8_t usb_mode = saved.usb_mode;
    const cJSON *jm = cJSON_GetObjectItemCaseSensitive(root, "usb_mode");
    bool mode_ok = !jm;
    for (uint8_t i = 0; jm && cJSON_IsString(jm) && i < 3; i++)
        if (!strcmp(jm->valuestring, USB_MODE_NAMES[i])) {usb_mode = i; mode_ok = true;}
    const cJSON *enabled = cJSON_GetObjectItemCaseSensitive(root, "enabled"), *mode = cJSON_GetObjectItemCaseSensitive(root, "mode");
    const cJSON *roaming = cJSON_GetObjectItemCaseSensitive(root, "roaming"), *ack = cJSON_GetObjectItemCaseSensitive(root, "data_ack");
    const cJSON *high = cJSON_GetObjectItemCaseSensitive(root, "pwrkey_active_high");
    bool parsed = cJSON_IsObject(root) && transport_ok && iface_ok && mode_ok && cJSON_IsBool(enabled) && cJSON_IsBool(roaming) && cJSON_IsBool(ack) && cJSON_IsBool(high)
        && cJSON_IsString(mode) && (!strcmp(mode->valuestring, "failover") || !strcmp(mode->valuestring, "primary"))
        && json_int(root, "uart", 1, 2, &uart) && json_int(root, "baud", 9600, 921600, &baud)
        && json_int(root, "tx", 0, 48, &tx) && json_int(root, "rx", 0, 48, &rx)
        && json_int(root, "rts", -1, 48, &rts) && json_int(root, "cts", -1, 48, &cts) && json_int(root, "pwrkey", -1, 48, &pwrkey)
        && json_text(root, "apn", c.apn, sizeof c.apn) && json_text(root, "user", c.user, sizeof c.user)
        && json_secret(root, "password", "clear_password", saved.password, c.password, sizeof c.password)
        && json_secret(root, "pin", "clear_pin", saved.pin, c.pin, sizeof c.pin);
    if (parsed) {
        c.enabled = cJSON_IsTrue(enabled); c.roaming = cJSON_IsTrue(roaming); c.data_ack = cJSON_IsTrue(ack);
        c.pwrkey_active_high = cJSON_IsTrue(high);
        c.mode = !strcmp(mode->valuestring, "primary") ? CELL_MODE_PRIMARY : CELL_MODE_FAILOVER;
        c.uart = (uint8_t)uart; c.baud = (uint32_t)baud;
        c.tx = (int8_t)tx; c.rx = (int8_t)rx; c.rts = (int8_t)rts; c.cts = (int8_t)cts; c.pwrkey = (int8_t)pwrkey;
        c.transport = transport;
        c.usb_iface = usb_iface < 0 ? CELL_USB_IFACE_AUTO : (uint8_t)usb_iface;
        c.usb_mode = usb_mode;
    }
    cJSON_Delete(root);
    esp_err_t err = parsed ? cell_uplink_set_config(&c, why, sizeof why) : ESP_ERR_INVALID_ARG;
    memset(&c, 0, sizeof c);
    memset(&saved, 0, sizeof saved);
    memset(body, 0, sizeof body);   /* the request carried the secrets */
    cJSON *reply = cJSON_CreateObject();
    if (err != ESP_OK) {
        httpd_resp_set_status(req, err == ESP_ERR_INVALID_ARG ? "400 Bad Request" : "500 Internal Server Error");
        if (reply) {cJSON_AddBoolToObject(reply, "ok", false); cJSON_AddStringToObject(reply, "error", err == ESP_ERR_INVALID_ARG ? why : esp_err_to_name(err));}
    } else if (reply) {cJSON_AddBoolToObject(reply, "ok", true); cJSON_AddBoolToObject(reply, "restart_required", true);}
    return send_json(req, reply);
}

esp_err_t cell_uplink_register_http(httpd_handle_t server)
{
    const httpd_uri_t routes[] = {
        {.uri = "/api/cellular", .method = HTTP_GET, .handler = get_cellular},
        {.uri = "/api/cellular", .method = HTTP_POST, .handler = post_cellular}};
    for (unsigned i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        esp_err_t err = httpd_register_uri_handler(server, &routes[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}
