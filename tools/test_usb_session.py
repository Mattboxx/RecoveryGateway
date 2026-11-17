"""Actual USB port session code (main/usb_port.c) against a scripted USB host.

Compiles the real session part of usb_port.c (not only the USBP_HOST_TEST
core) with stand-ins for the ESP-IDF USB host library, FreeRTOS ticks,
semaphores and byte ring buffers, then checks (3.0.25 fixes):

Network sessions (send slots):
- a frame is sent on a free slot, both slots busy drop the frame without
  waiting, a completed transfer gives its slot back;
- closing while a sender still holds a slot (it passed the running check
  just before) waits for that slot before freeing anything; the transfer
  is freed only after the sender let go;
- a slot never given back: nothing is freed (bounded loss), the port is
  marked unusable until restart, the wait is bounded;
- after the close a late sender drops its frame and touches no transfer;
- a second close in a row (each session open starts with one) returns at
  once, without marking anything lost.

Serial sessions (PPP over a USB modem):
- a write from the TCP/IP thread (no timeout) queues the whole frame and
  returns at once, never waiting for a transfer (no tick passes);
- queued bytes leave in order across transfers, chunked to the transfer
  size, the next transfer chained from the completion callback;
- a frame that does not fit is dropped whole (nothing partial queued);
- an AT command write (with a timeout) waits for room and then succeeds;
  a write after the session ended fails.

Real USB devices and the real USB host stack are NOT covered.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

STUBS = r'''
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_TIMEOUT 0x107
#define EXT_RAM_BSS_ATTR
#define ESP_INTR_FLAG_LOWMED 0
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define MALLOC_CAP_INTERNAL 4
static size_t heap_caps_get_free_size(int caps) {(void)caps; return 200000;}
static size_t heap_caps_get_minimum_free_size(int caps) {(void)caps; return 150000;}
static void *heap_caps_malloc(size_t n, int caps) {(void)caps; return malloc(n);}
#define ESP_MAC_ETH 3
static esp_err_t esp_read_mac(uint8_t *mac, int type) {(void)type; memset(mac, 0x24, 6); return ESP_OK;}
/* netif */
typedef struct {int dummy;} esp_netif_t;
typedef struct esp_netif_driver_base_s {esp_err_t (*post_attach)(esp_netif_t *netif, void *args); esp_netif_t *netif;} esp_netif_driver_base_t;
typedef struct {void *handle; esp_err_t (*transmit)(void *h, void *buffer, size_t len); void (*driver_free_rx_buffer)(void *h, void *buffer);} esp_netif_driver_ifconfig_t;
static esp_err_t esp_netif_set_driver_config(esp_netif_t *n, const esp_netif_driver_ifconfig_t *c) {(void)n; (void)c; return ESP_OK;}
static esp_err_t esp_netif_receive(esp_netif_t *n, void *b, size_t l, void *e) {(void)n; (void)l; (void)e; free(b); return ESP_OK;}
static void esp_netif_action_start(void *n, void *b, int32_t i, void *d) {(void)n; (void)b; (void)i; (void)d;}
static void esp_netif_action_stop(void *n, void *b, int32_t i, void *d) {(void)n; (void)b; (void)i; (void)d;}
static void esp_netif_action_connected(void *n, void *b, int32_t i, void *d) {(void)n; (void)b; (void)i; (void)d;}
static void esp_netif_action_disconnected(void *n, void *b, int32_t i, void *d) {(void)n; (void)b; (void)i; (void)d;}
static esp_err_t esp_netif_set_mac(esp_netif_t *n, uint8_t m[]) {(void)n; (void)m; return ESP_OK;}
/* FreeRTOS: a tick counter; vTaskDelay runs the test's "other task" hook */
typedef uint32_t TickType_t;
typedef int BaseType_t;
typedef unsigned UBaseType_t;
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY 0xffffffffu
#define tskNO_AFFINITY 0x7fffffff
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
typedef struct {int x;} portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED {0}
#define portENTER_CRITICAL(m) ((void)(m))
#define portEXIT_CRITICAL(m) ((void)(m))
static TickType_t g_ticks;
static unsigned g_delays;
static void (*g_other_task)(void);
static TickType_t xTaskGetTickCount(void) {return g_ticks;}
static void vTaskDelay(TickType_t t) {g_delays++; g_ticks += t ? t : 1; if (g_other_task) g_other_task();}
typedef void *SemaphoreHandle_t;
static SemaphoreHandle_t xSemaphoreCreateMutex(void) {return malloc(1);}
static SemaphoreHandle_t xSemaphoreCreateBinary(void) {return malloc(1);}
static BaseType_t xSemaphoreTake(SemaphoreHandle_t s, TickType_t t) {(void)s; (void)t; return pdTRUE;}
static BaseType_t xSemaphoreGive(SemaphoreHandle_t s) {(void)s; return pdTRUE;}
typedef void (*TaskFunction_t)(void *);
static BaseType_t xTaskCreatePinnedToCoreWithCaps(TaskFunction_t f, const char *n, uint32_t st, void *a, UBaseType_t p, void *h, BaseType_t c, int caps)
{(void)f; (void)n; (void)st; (void)a; (void)p; (void)h; (void)c; (void)caps; return pdPASS;}
/* byte ring buffer */
typedef struct {uint8_t *d; size_t cap, head, used; uint8_t out[8192];} ring_t;
typedef ring_t *RingbufHandle_t;
#define RINGBUF_TYPE_BYTEBUF 2
static RingbufHandle_t xRingbufferCreateWithCaps(size_t n, int type, int caps)
{(void)type; (void)caps; ring_t *r = calloc(1, sizeof *r); r->d = malloc(n); r->cap = n; return r;}
static size_t xRingbufferGetCurFreeSize(RingbufHandle_t r) {return r->cap - r->used;}
static BaseType_t xRingbufferSend(RingbufHandle_t r, const void *data, size_t n, TickType_t ticks)
{
    TickType_t end = g_ticks + ticks;
    while (r->cap - r->used < n) {                        /* waits: the other task drains */
        if (!ticks || (int32_t)(end - g_ticks) <= 0) return pdFALSE;
        vTaskDelay(1);
    }
    for (size_t i = 0; i < n; i++) r->d[(r->head + r->used + i) % r->cap] = ((const uint8_t *)data)[i];
    r->used += n;
    return pdTRUE;
}
static void *xRingbufferReceiveUpTo(RingbufHandle_t r, size_t *n, TickType_t t, size_t max)
{
    (void)t;
    if (!r->used) return NULL;
    size_t k = r->used < max ? r->used : max;
    if (k > r->cap - r->head) k = r->cap - r->head;           /* contiguous up to the wrap */
    memcpy(r->out, r->d + r->head, k);
    r->head = (r->head + k) % r->cap; r->used -= k; *n = k;
    return r->out;
}
static void vRingbufferReturnItem(RingbufHandle_t r, void *item) {(void)r; (void)item;}
static void vRingbufferGetInfo(RingbufHandle_t r, UBaseType_t *f, UBaseType_t *rd, UBaseType_t *w, UBaseType_t *a, UBaseType_t *waiting)
{(void)f; (void)rd; (void)w; (void)a; if (waiting) *waiting = (UBaseType_t)r->used;}
/* USB host */
typedef void *usb_host_client_handle_t;
typedef void *usb_device_handle_t;
typedef struct usb_transfer_s usb_transfer_t;
typedef void (*usb_transfer_cb_t)(usb_transfer_t *t);
enum {USB_TRANSFER_STATUS_COMPLETED, USB_TRANSFER_STATUS_ERROR, USB_TRANSFER_STATUS_TIMED_OUT, USB_TRANSFER_STATUS_CANCELED,
      USB_TRANSFER_STATUS_STALL, USB_TRANSFER_STATUS_OVERFLOW, USB_TRANSFER_STATUS_SKIPPED, USB_TRANSFER_STATUS_NO_DEVICE};
#define USB_TRANSFER_FLAG_ZERO_PACK 1
struct usb_transfer_s {uint8_t *data_buffer; size_t data_buffer_size; int num_bytes, actual_num_bytes; uint32_t flags;
    usb_device_handle_t device_handle; uint8_t bEndpointAddress; int status; uint32_t timeout_ms; usb_transfer_cb_t callback; void *context;};
typedef struct {uint8_t bmRequestType, bRequest; uint16_t wValue, wIndex, wLength;} usb_setup_packet_t;
typedef struct {uint16_t idVendor, idProduct; uint8_t bNumConfigurations;} usb_device_desc_t;
typedef struct {uint16_t wTotalLength;} usb_config_desc_t;
typedef struct {uint8_t bConfigurationValue;} usb_device_info_t;
typedef struct {bool skip_phy_setup; int intr_flags; void *enum_filter_cb;} usb_host_config_t;
enum {USB_HOST_CLIENT_EVENT_NEW_DEV = 1, USB_HOST_CLIENT_EVENT_DEV_GONE, USB_HOST_CLIENT_EVENT_DEV_REMOVED};
typedef struct {int event; union {struct {uint8_t address;} new_dev; struct {usb_device_handle_t dev_hdl;} dev_gone; struct {uint8_t address;} dev_removed;};} usb_host_client_event_msg_t;
typedef void (*usb_host_client_event_cb_t)(const usb_host_client_event_msg_t *m, void *arg);
typedef struct {bool is_synchronous; int max_num_event_msg; struct {usb_host_client_event_cb_t client_event_callback; void *callback_arg;} async;} usb_host_client_config_t;
#define USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS 1
static int g_submits, g_frees, g_freed_while_held;
static usb_transfer_t *g_last_submit;
static esp_err_t usb_host_transfer_alloc(size_t n, int iso, usb_transfer_t **t)
{(void)iso; *t = calloc(1, sizeof **t); (*t)->data_buffer = calloc(1, n); (*t)->data_buffer_size = n; return ESP_OK;}
static bool slot_held_by_sender(usb_transfer_t *t);
static esp_err_t usb_host_transfer_free(usb_transfer_t *t)
{g_frees++; if (slot_held_by_sender(t)) g_freed_while_held++; free(t->data_buffer); free(t); return ESP_OK;}
static esp_err_t usb_host_transfer_submit(usb_transfer_t *t) {g_submits++; g_last_submit = t; return ESP_OK;}
static esp_err_t usb_host_transfer_submit_control(usb_host_client_handle_t c, usb_transfer_t *t) {(void)c; (void)t; return ESP_FAIL;}
static esp_err_t usb_host_endpoint_halt(usb_device_handle_t d, uint8_t ep) {(void)d; (void)ep; return ESP_OK;}
static esp_err_t usb_host_endpoint_flush(usb_device_handle_t d, uint8_t ep) {(void)d; (void)ep; return ESP_OK;}
static esp_err_t usb_host_endpoint_clear(usb_device_handle_t d, uint8_t ep) {(void)d; (void)ep; return ESP_OK;}
static esp_err_t usb_host_interface_claim(usb_host_client_handle_t c, usb_device_handle_t d, uint8_t i, uint8_t a) {(void)c; (void)d; (void)i; (void)a; return ESP_OK;}
static esp_err_t usb_host_interface_release(usb_host_client_handle_t c, usb_device_handle_t d, uint8_t i) {(void)c; (void)d; (void)i; return ESP_OK;}
static esp_err_t usb_host_device_open(usb_host_client_handle_t c, uint8_t a, usb_device_handle_t *d) {(void)c; (void)a; *d = (void *)1; return ESP_OK;}
static esp_err_t usb_host_device_close(usb_host_client_handle_t c, usb_device_handle_t d) {(void)c; (void)d; return ESP_OK;}
static esp_err_t usb_host_device_free_all(void) {return ESP_OK;}
static esp_err_t usb_host_device_info(usb_device_handle_t d, usb_device_info_t *i) {(void)d; (void)i; return ESP_FAIL;}
static esp_err_t usb_host_get_device_descriptor(usb_device_handle_t d, const usb_device_desc_t **x) {(void)d; (void)x; return ESP_FAIL;}
static esp_err_t usb_host_get_active_config_descriptor(usb_device_handle_t d, const usb_config_desc_t **x) {(void)d; (void)x; return ESP_FAIL;}
static esp_err_t usb_host_install(const usb_host_config_t *c) {(void)c; return ESP_OK;}
static esp_err_t usb_host_client_register(const usb_host_client_config_t *c, usb_host_client_handle_t *h) {(void)c; *h = (void *)2; return ESP_OK;}
static esp_err_t usb_host_client_handle_events(usb_host_client_handle_t h, TickType_t t) {(void)h; (void)t; return ESP_OK;}
static esp_err_t usb_host_lib_handle_events(TickType_t t, uint32_t *f) {(void)t; (void)f; return ESP_OK;}
static esp_err_t usb_host_lib_set_root_port_power(bool on) {(void)on; return ESP_OK;}
'''

PROGRAM = r'''
#include "usb_port.c"
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
static int g_sender_slot = -1;                 /* a "TCP/IP thread" holding a slot */
static int g_release_after = -1;               /* ticks until it lets go; -1 never */
static bool slot_held_by_sender(usb_transfer_t *t)
{
    return g_sender_slot >= 0 && (t == s_net.out[0] ? g_sender_slot == 0 : t == s_net.out[1] ? g_sender_slot == 1 : false);
}
static void sender_runs(void)
{
    if (g_sender_slot >= 0 && g_release_after >= 0 && --g_release_after <= 0) {slot_release(g_sender_slot); g_sender_slot = -1;}
}
static esp_netif_t g_netif;
static void net_session(void)
{
    memset(&s_net, 0, sizeof s_net);
    s_poisoned = false; s_parked[0] = s_parked[1] = false;
    s_net.kind = USBP_NET_ECM; s_net.n_in = 1; s_net.n_out = 2; s_net.dev = (void *)1; s_net.netif = &g_netif;
    s_net.ep_in = 0x81; s_net.ep_out = 0x02; s_net.out_max = USBP_TX_SIZE;
    alloc(USBP_FRAME_RX, &s_net.in[0], 0x81, in_cb, 0);
    alloc(USBP_TX_SIZE, &s_net.out[0], 0x02, out_cb, 0);
    alloc(USBP_TX_SIZE, &s_net.out[1], 0x02, out_cb, 1);
    atomic_store(&s_net.running, true); atomic_store(&s_net.link, true); atomic_store(&s_net.link_known, true);
}
static void complete(usb_transfer_t *t, int status)
{
    t->status = status; t->actual_num_bytes = t->num_bytes; t->callback(t);
}
static uint8_t g_wire[20000]; static size_t g_wire_len;
static void modem_reads(void)                 /* the client task completing serial transfers */
{
    if (atomic_load(&s_net.out_busy[0]) && g_last_submit == s_net.out[0] && atomic_load(&s_net.inflight) > 0) {
        usb_transfer_t *t = s_net.out[0];
        memcpy(g_wire + g_wire_len, t->data_buffer, (size_t)t->num_bytes); g_wire_len += (size_t)t->num_bytes;
        complete(t, USB_TRANSFER_STATUS_COMPLETED);
    }
}
static void drain(void) {for (int i = 0; i < 1000 && atomic_load(&s_net.inflight) > 0; i++) modem_reads();}

int main(void)
{
    uint8_t frame[1500];
    TickType_t t0;
    for (unsigned i = 0; i < sizeof frame; i++) frame[i] = (uint8_t)i;

    /* --- network session: slots --- */
    net_session();
    int before = g_submits;
    CHECK(glue_transmit(NULL, frame, 1000) == ESP_OK && g_submits == before + 1 && atomic_load(&s_net.out_busy[0]));
    CHECK(glue_transmit(NULL, frame, 1000) == ESP_OK && atomic_load(&s_net.out_busy[1]));
    unsigned dropped = atomic_load(&s_tx_dropped), delays = g_delays;
    CHECK(glue_transmit(NULL, frame, 1000) == ESP_FAIL && atomic_load(&s_tx_dropped) == dropped + 1 && g_delays == delays);  /* no wait */
    complete(s_net.out[0], USB_TRANSFER_STATUS_COMPLETED);
    complete(s_net.out[1], USB_TRANSFER_STATUS_COMPLETED);
    CHECK(!atomic_load(&s_net.out_busy[0]) && !atomic_load(&s_net.out_busy[1]) && atomic_load(&s_net.inflight) == 0);

    /* close while a sender holds slot 1: waits for it, frees afterwards */
    CHECK(slot_claim(1));
    g_sender_slot = 1; g_release_after = 30; g_other_task = sender_runs;
    int frees = g_frees; g_freed_while_held = 0;
    usb_port_net_close();
    CHECK(g_sender_slot == -1 && g_freed_while_held == 0 && g_frees == frees + 3 && !s_poisoned);
    CHECK(s_net.out[0] == NULL && s_net.out[1] == NULL);
    /* a second close (every session open starts with one): immediate, no loss */
    t0 = g_ticks; usb_port_net_close();
    CHECK(g_ticks - t0 <= 1 && !s_poisoned && !s_net.leaked);
    /* a late sender after the close: dropped, touches nothing */
    before = g_submits; dropped = atomic_load(&s_tx_dropped);
    CHECK(glue_transmit(NULL, frame, 100) == ESP_FAIL && g_submits == before && atomic_load(&s_tx_dropped) == dropped + 1);

    /* a slot never given back: nothing freed, port unusable, bounded wait */
    net_session();
    CHECK(slot_claim(0));
    g_sender_slot = 0; g_release_after = -1;
    frees = g_frees; t0 = g_ticks;
    usb_port_net_close();
    CHECK(g_frees == frees && s_poisoned && g_ticks - t0 <= USBP_CLOSE_CLAIM_MS + 100);
    g_sender_slot = -1; g_other_task = NULL;

    /* --- serial session: queue --- */
    memset(&s_net, 0, sizeof s_net);
    s_poisoned = false; s_parked[0] = s_parked[1] = false;
    s_net.kind = USBP_SERIAL; s_net.n_in = 1; s_net.n_out = 1; s_net.dev = (void *)1; s_net.ep_out = 0x02;
    s_net.out_max = 64;                                     /* small transfers: chunking */
    alloc(64, &s_net.out[0], 0x02, out_cb, 0);
    s_net.tx = xRingbufferCreateWithCaps(USBP_SERIAL_TX_BUFFER, RINGBUF_TYPE_BYTEBUF, 0);
    s_net.rx = xRingbufferCreateWithCaps(USBP_SERIAL_RX_BUFFER, RINGBUF_TYPE_BYTEBUF, 0);
    atomic_store(&s_net.running, true);
    g_wire_len = 0;
    delays = g_delays; before = g_submits;
    CHECK(usb_port_serial_write(frame, 100, 0) == 100 && g_delays == delays && g_submits == before + 1);   /* queued, no wait */
    CHECK(usb_port_serial_write(frame + 100, 50, 0) == 50 && g_delays == delays && g_submits == before + 1);   /* behind it */
    drain();
    CHECK(g_wire_len == 150 && memcmp(g_wire, frame, 150) == 0 && !atomic_load(&s_net.out_busy[0]));
    /* fill the queue while the modem is not reading: a frame that does not fit is dropped whole */
    g_wire_len = 0;
    int queued = 0;
    while (usb_port_serial_write(frame, 1400, 0) == 1400) queued++;
    CHECK(queued >= 4 && g_delays == delays);
    size_t used = s_net.tx->used;
    dropped = atomic_load(&s_tx_dropped);
    CHECK(usb_port_serial_write(frame, 1400, 0) == -1 && s_net.tx->used == used && atomic_load(&s_tx_dropped) == dropped + 1);
    /* an AT write waits for room (the modem reads meanwhile) */
    g_other_task = modem_reads;
    CHECK(usb_port_serial_write(frame, 1400, 2000) == 1400);
    drain();
    g_other_task = NULL;
    CHECK(g_wire_len == (size_t)(queued + 1) * 1400);
    for (int i = 0; i <= queued; i++) CHECK(memcmp(g_wire + (size_t)i * 1400, frame, 1400) == 0);   /* in order */
    /* session over: writes fail */
    atomic_store(&s_net.gone, true);
    CHECK(usb_port_serial_write(frame, 10, 0) == -1 && usb_port_serial_write(frame, 10, 100) == -1);
    puts("usb session ok");
    return 0;
}
'''


def run(source_text):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'usb').mkdir()
        (tmp / 'freertos').mkdir()
        (tmp / 'esp_err.h').write_text(STUBS, encoding='utf-8')
        for name in ('esp_netif.h', 'esp_heap_caps.h', 'esp_attr.h', 'esp_log.h', 'esp_mac.h', 'esp_netif_net_stack.h',
                     'freertos/FreeRTOS.h', 'freertos/semphr.h', 'freertos/ringbuf.h', 'freertos/task.h', 'usb/usb_host.h'):
            (tmp / name).write_text('#pragma once\n#include "esp_err.h"\n', encoding='utf-8')
        (tmp / 'sdkconfig.h').write_text('#pragma once\n#define CONFIG_SOC_USB_OTG_SUPPORTED 1\n', encoding='utf-8')
        (tmp / 'usb_port.h').write_text((ROOT / 'main/usb_port.h').read_text(encoding='utf-8'), encoding='utf-8')
        (tmp / 'usb_port.c').write_text(source_text, encoding='utf-8')
        (tmp / 'test.c').write_text(PROGRAM, encoding='utf-8')
        exe = tmp / ('t.exe' if os.name == 'nt' else 't')
        flags = ['-fsanitize=address,undefined'] if os.environ.get('USBP_SANITIZE') == '1' else []
        build = subprocess.run(['gcc', '-std=gnu11', '-O1', '-Wall', '-Wno-unused-function', '-Wno-unused-variable',
                                *flags, '-I', str(tmp), str(tmp / 'test.c'), '-o', str(exe)], capture_output=True, text=True)
        if build.returncode:
            return build
        return subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)


source = (ROOT / 'main/usb_port.c').read_text(encoding='utf-8')
ok = run(source)
assert ok.returncode == 0 and 'usb session ok' in ok.stdout, (ok.returncode, ok.stdout, ok.stderr[-3000:])

# The 3.0.24 behaviour must fail: close frees without claiming the slots,
# and a serial write waits on the transfer instead of queueing.
for old, new in (('if (!claim_all_slots(held, USBP_CLOSE_CLAIM_MS) || atomic_load(&s_net.inflight) > 0) s_net.leaked = true;',
                  'if (atomic_load(&s_net.inflight) > 0) s_net.leaked = true;'),
                 ('if (len > USBP_SERIAL_TX_BUFFER / 2 || xRingbufferSend(s_net.tx, data, len, 0) != pdTRUE) {',
                  'vTaskDelay(1); if (len > USBP_SERIAL_TX_BUFFER / 2 || xRingbufferSend(s_net.tx, data, len, 0) != pdTRUE) {')):
    assert old in source, old
    bad = run(source.replace(old, new))
    assert bad.returncode != 0, 'mutant survived: ' + old
print('usb session: close waits for held send slots, bounded; serial writes queue without waiting, in order, whole-frame drops')
