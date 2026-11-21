/* Conditional Ethernet uplink (SPI W5500 or USB); see eth_uplink.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "eth_uplink.h"
#include "cell_uplink.h"
#include "usb_port.h"
#include "uplink_services.h"
#include "sdkconfig.h"
#include "json_guard.h"
#include "nvs.h"
#include "nvs_params.h"
#include "tailscale_config.h"
#include "web_ui.h"
#include "netif_hooks.h"
#include "portmap.h"
#include "esp_event.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/netif.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include <math.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if CONFIG_ETH_SPI_ETHERNET_W5500
#include "esp_eth.h"
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"
#include "driver/gpio.h"
#include "driver/spi_master.h"
#endif

#define TAG "eth_uplink"

/* --- eth core (begin) --- */
/* ESP32-S3 N16R8: GPIO26-37 belong to flash/octal PSRAM, 19/20 USB, 43/44
 * the console UART, 0/3/45/46 are strapping pins and 38-40 the microSD log. */
static bool eth_pin_allowed(int pin)
{
    static const int8_t allowed[] = {1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 21, 41, 42, 47, 48};
    for (size_t i = 0; i < sizeof allowed; i++) if (allowed[i] == pin) return true;
    return false;
}

static bool eth_fail(char *why, size_t n, const char *text)
{
    if (why && n) snprintf(why, n, "%s", text);
    return false;
}

static bool eth_mask_valid(uint32_t mask_nbo)
{
    uint32_t m = ntohl(mask_nbo);
    return m && (~m & (~m + 1)) == 0 && m != UINT32_MAX;
}

bool eth_config_valid(const eth_config_t *c, char *why, size_t n)
{
    if (!c || c->enabled > 1 || c->ip_static > 1 || c->preference > ETH_PREF_ETHERNET_FIRST)
        return eth_fail(why, n, "invalid switch value");
    if (c->chip != ETH_CHIP_W5500) return eth_fail(why, n, "only the W5500 SPI module is supported");
    if (c->transport > ETH_TRANSPORT_USB) return eth_fail(why, n, "connection must be SPI or USB");
    bool usb = c->transport == ETH_TRANSPORT_USB;   /* SPI pins kept for a later switch back, not used */
    if (c->spi_host != 1 && c->spi_host != 2) return eth_fail(why, n, "SPI host must be SPI2 or SPI3");
    if (c->spi_mhz < 1 || c->spi_mhz > 40) return eth_fail(why, n, "SPI clock must be 1-40 MHz");
    int8_t pins[] = {c->sclk, c->mosi, c->miso, c->cs, c->intr, c->rst};
    for (unsigned i = 0; !usb && i < sizeof pins; i++) {
        if (pins[i] == -1 && i >= 4) continue;
        if (!eth_pin_allowed(pins[i])) return eth_fail(why, n, "pin not usable on this board (flash/PSRAM/USB/UART/strap/microSD)");
        for (unsigned j = 0; j < i; j++) if (pins[j] == pins[i]) return eth_fail(why, n, "pins must be distinct");
    }
    if (c->ip_static) {
        uint32_t ip = ntohl(c->ip), mask = ntohl(c->mask), gw = ntohl(c->gw);
        if (!eth_mask_valid(c->mask)) return eth_fail(why, n, "invalid netmask");
        if (!ip || (ip & ~mask) == 0 || (ip & ~mask) == ~mask || (ip >> 24) == 127 || (ip >> 28) >= 14)
            return eth_fail(why, n, "invalid static address");
        if (!gw || (gw & mask) != (ip & mask) || gw == ip) return eth_fail(why, n, "gateway must be another address in the same subnet");
    }
    return true;
}

int eth_uplink_choose(eth_selector_t *s, bool enabled, uint8_t preference, bool sta_ok, bool eth_ok)
{
    if (!enabled) {s->eth_streak = 0; return ETH_CHOICE_LEGACY;}
    if (!eth_ok) s->eth_streak = 0;
    else if (s->eth_streak < ETH_STABLE_SAMPLES) s->eth_streak++;
    bool eth_stable = s->eth_streak >= ETH_STABLE_SAMPLES;
    if (preference == ETH_PREF_ETHERNET_FIRST) return (eth_stable || (!sta_ok && eth_ok)) ? ETH_CHOICE_ETH : ETH_CHOICE_STA;
    return sta_ok ? ETH_CHOICE_STA : eth_ok ? ETH_CHOICE_ETH : ETH_CHOICE_STA;
}
/* --- eth core (end) --- */

#define ETH_MAGIC 0x45544831u /* ETH1 */
typedef struct {uint32_t magic, version; eth_config_t config; uint32_t checksum;} eth_record_t;
/* Version 1 (SPI only, up to 3.0.24) is still written for the W5500, so an
 * older firmware keeps working after a rollback. The USB connection is
 * written as version 2, which an older firmware refuses (Ethernet off). */
typedef struct {
    uint8_t enabled, chip, spi_host, spi_mhz, ip_static, preference;
    int8_t sclk, mosi, miso, cs, intr, rst;
    uint32_t ip, mask, gw, dns;
} eth_config_v1_t;
typedef struct {uint32_t magic, version; eth_config_v1_t config; uint32_t checksum;} eth_record_v1_t;

static SemaphoreHandle_t s_lock;
static StaticSemaphore_t s_lock_storage;
/* Plain data under s_lock, read by tasks only: PSRAM keeps it out of
 * internal RAM (the 40 KB floor) whether or not the uplink is used. */
EXT_RAM_BSS_ATTR static eth_config_t s_saved, s_running;
EXT_RAM_BSS_ATTR static eth_status_t s_status;
static atomic_bool s_link, s_has_ip;
static struct netif *s_lwip;           /* read in TCP/IP context only after start */
static eth_selector_t s_selector;      /* TCP/IP context only */
static esp_netif_t *s_netif;
static atomic_bool s_selected_eth;  /* last applied choice; drives listener rebinding */
#if CONFIG_ETH_SPI_ETHERNET_W5500
static esp_eth_handle_t s_handle;
#endif

static void defaults(eth_config_t *c)
{
    memset(c, 0, sizeof *c);
    c->chip = ETH_CHIP_W5500; c->spi_host = 1; c->spi_mhz = 20;
    c->sclk = 12; c->mosi = 11; c->miso = 13; c->cs = 10; c->intr = 14; c->rst = 9;
    c->transport = ETH_TRANSPORT_SPI;
}

static uint32_t eth_fnv(const void *data, size_t n)
{
    uint32_t h = 2166136261u;
    const uint8_t *p = data;
    for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
    return h;
}

static uint32_t record_checksum(const eth_record_t *r)
{
    return eth_fnv(r, offsetof(eth_record_t, checksum));
}

static void migrate_v1(const eth_config_v1_t *v1, eth_config_t *c)
{
    defaults(c);
    c->enabled = v1->enabled; c->chip = v1->chip; c->spi_host = v1->spi_host; c->spi_mhz = v1->spi_mhz;
    c->ip_static = v1->ip_static; c->preference = v1->preference;
    c->sclk = v1->sclk; c->mosi = v1->mosi; c->miso = v1->miso; c->cs = v1->cs; c->intr = v1->intr; c->rst = v1->rst;
    c->ip = v1->ip; c->mask = v1->mask; c->gw = v1->gw; c->dns = v1->dns;
}

/* The record bytes for `c`: version 1 for SPI, else version 2. */
static size_t record_encode(const eth_config_t *c, void *out)
{
    if (c->transport == ETH_TRANSPORT_SPI) {
        eth_record_v1_t r;
        memset(&r, 0, sizeof r);
        r.magic = ETH_MAGIC; r.version = 1;
        r.config.enabled = c->enabled; r.config.chip = c->chip; r.config.spi_host = c->spi_host; r.config.spi_mhz = c->spi_mhz;
        r.config.ip_static = c->ip_static; r.config.preference = c->preference;
        r.config.sclk = c->sclk; r.config.mosi = c->mosi; r.config.miso = c->miso; r.config.cs = c->cs;
        r.config.intr = c->intr; r.config.rst = c->rst;
        r.config.ip = c->ip; r.config.mask = c->mask; r.config.gw = c->gw; r.config.dns = c->dns;
        r.checksum = eth_fnv(&r, offsetof(eth_record_v1_t, checksum));
        memcpy(out, &r, sizeof r);
        return sizeof r;
    }
    eth_record_t r;
    memset(&r, 0, sizeof r);
    r.magic = ETH_MAGIC; r.version = 2;
    memcpy(&r.config, c, sizeof r.config);
    r.checksum = record_checksum(&r);
    memcpy(out, &r, sizeof r);
    return sizeof r;
}

static void load(eth_config_t *out)
{
    defaults(out);
    union {eth_record_t v2; eth_record_v1_t v1;} r;
    _Static_assert(sizeof(eth_record_t) != sizeof(eth_record_v1_t), "record versions must differ in size");
    size_t size = sizeof r;
    nvs_handle_t nvs;
    if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return;
    /* Invalid or foreign data means "Ethernet off", never a guessed pin map. */
    eth_config_t c;
    bool ok = false;
    if (nvs_get_blob(nvs, "eth_cfg", &r, &size) == ESP_OK && r.v2.magic == ETH_MAGIC) {
        if (size == sizeof r.v2 && r.v2.version == 2 && r.v2.checksum == record_checksum(&r.v2)) {
            memcpy(&c, &r.v2.config, sizeof c);
            ok = true;
        } else if (size == sizeof r.v1 && r.v1.version == 1 && r.v1.checksum == eth_fnv(&r.v1, offsetof(eth_record_v1_t, checksum))) {
            migrate_v1(&r.v1.config, &c);
            ok = true;
        }
    }
    if (ok && eth_config_valid(&c, NULL, 0)) memcpy(out, &c, sizeof c);
    nvs_close(nvs);
}

static void ensure_lock(void)
{
    static portMUX_TYPE init = portMUX_INITIALIZER_UNLOCKED;
    portENTER_CRITICAL(&init);
    if (!s_lock) s_lock = xSemaphoreCreateMutexStatic(&s_lock_storage);
    portEXIT_CRITICAL(&init);
}

static void set_error(const char *text)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    snprintf(s_status.error, sizeof s_status.error, "%s", text);
    xSemaphoreGive(s_lock);
}

static atomic_bool s_stability_lost;

/* Select the LAN independently of the Internet uplink (which can be PPP). */
static void apply_choice(void)
{
    if (!s_netif) return;
    esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t info = {0};
    bool sta_ok = uplink_address(sta, &info);
    bool eth_ok = atomic_load(&s_link) && atomic_load(&s_has_ip);
    if (eth_ok && sta_ok && s_running.preference == ETH_PREF_ETHERNET_FIRST) {
        /* Only the route supervisor may promote Ethernet when Wi-Fi works.
         * Refresh already-selected bindings when Ethernet changes address. */
        if (atomic_load(&s_selected_eth)) portmap_install_all();
        return;
    }
    bool eth = eth_ok && !sta_ok;
    if (atomic_exchange(&s_selected_eth, eth) != eth || eth) portmap_install_all();
}

static void link_changed(bool up)
{
    atomic_store(&s_link, up);
    if (!up) {
        atomic_store(&s_has_ip, false);
        atomic_store(&s_stability_lost, true);
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.link_changes++;
    if (up && s_running.ip_static) {
        s_status.ip = s_running.ip; s_status.mask = s_running.mask; s_status.gw = s_running.gw;
        atomic_store(&s_has_ip, true);
    } else if (!up) {s_status.ip = s_status.mask = s_status.gw = 0;}
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "link %s", up ? "up" : "down");
}

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    bool lost = false;
#if CONFIG_ETH_SPI_ETHERNET_W5500
    if (base == ETH_EVENT && (id == ETHERNET_EVENT_CONNECTED || id == ETHERNET_EVENT_DISCONNECTED)) {
        bool up = id == ETHERNET_EVENT_CONNECTED;
        lost = !up;
        link_changed(up);
    } else
#endif
    if (base == IP_EVENT && (id == IP_EVENT_ETH_GOT_IP || id == IP_EVENT_ETH_LOST_IP)) {
        bool got = id == IP_EVENT_ETH_GOT_IP;
        if (got && ((const ip_event_got_ip_t *)data)->esp_netif != s_netif) return;
        lost = !got;
        atomic_store(&s_has_ip, got);
        if (!got) atomic_store(&s_stability_lost, true);
        xSemaphoreTake(s_lock, portMAX_DELAY);
        if (got) {
            const ip_event_got_ip_t *e = data;
            s_status.ip = e->ip_info.ip.addr; s_status.mask = e->ip_info.netmask.addr; s_status.gw = e->ip_info.gw.addr;
        } else s_status.ip = s_status.mask = s_status.gw = 0;
        xSemaphoreGive(s_lock);
    } else return;
    apply_choice();
    uplink_services_refresh(lost);
}

void eth_uplink_wifi_changed(void) { apply_choice(); }

static esp_err_t apply_static(esp_netif_t *netif, const eth_config_t *c);

#if CONFIG_ETH_SPI_ETHERNET_W5500
static esp_err_t subscribe_w5500_events(void)
{
    esp_event_handler_instance_t eth_events;
    esp_err_t err = esp_event_handler_instance_register(ETH_EVENT, ESP_EVENT_ANY_ID,
                                                         on_event, NULL, &eth_events);
    if (err != ESP_OK) return err;
    err = esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL, NULL);
    if (err != ESP_OK) esp_event_handler_instance_unregister(ETH_EVENT, ESP_EVENT_ANY_ID, eth_events);
    return err;
}

static esp_err_t start_w5500(const eth_config_t *c)
{
    esp_err_t err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) return err;
    spi_host_device_t host = c->spi_host == 1 ? SPI2_HOST : SPI3_HOST;
    spi_bus_config_t bus = {.mosi_io_num = c->mosi, .miso_io_num = c->miso, .sclk_io_num = c->sclk,
                            .quadwp_io_num = -1, .quadhd_io_num = -1};
    err = spi_bus_initialize(host, &bus, SPI_DMA_CH_AUTO);
    if (err != ESP_OK) return err;
    spi_device_interface_config_t dev = {.mode = 0, .clock_speed_hz = c->spi_mhz * 1000000, .queue_size = 20,
                                         .spics_io_num = c->cs};
    eth_w5500_config_t w5500 = ETH_W5500_DEFAULT_CONFIG(host, &dev);
    w5500.base.int_gpio_num = c->intr;
    if (c->intr < 0) w5500.base.poll_period_ms = 10;
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.reset_gpio_num = c->rst;
    esp_eth_mac_t *mac = esp_eth_mac_new_w5500(&w5500, &mac_config);
    esp_eth_phy_t *phy = mac ? esp_eth_phy_new_w5500(&phy_config) : NULL;
    esp_eth_handle_t handle = NULL;
    esp_eth_netif_glue_handle_t glue = NULL;
    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    err = mac && phy ? esp_eth_driver_install(&config, &handle) : ESP_ERR_NO_MEM;
    if (err != ESP_OK) goto fail;
    uint8_t address[6];
    if ((err = esp_read_mac(address, ESP_MAC_ETH)) != ESP_OK
        || (err = esp_eth_ioctl(handle, ETH_CMD_S_MAC_ADDR, address)) != ESP_OK) goto fail_driver;
    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_ETH();
    s_netif = esp_netif_new(&netif_config);
    if (!s_netif) {err = ESP_ERR_NO_MEM; goto fail_driver;}
    glue = esp_eth_new_netif_glue(handle);
    if (!glue) {err = ESP_ERR_NO_MEM; goto fail_netif;}
    if ((err = esp_netif_attach(s_netif, glue)) != ESP_OK) goto fail_netif;
    if ((err = apply_static(s_netif, c)) != ESP_OK) goto fail_netif;
    if ((err = subscribe_w5500_events()) != ESP_OK) goto fail_netif;
    s_handle = handle;  /* started by eth_uplink_start() after the ACL hooks */
    return ESP_OK;
fail_netif:
    if (glue) esp_eth_del_netif_glue(glue);
    esp_netif_destroy(s_netif);
    s_netif = NULL;
fail_driver:
    esp_eth_driver_uninstall(handle);  /* MAC/PHY objects are still ours */
fail:
    if (phy) phy->del(phy);
    if (mac) mac->del(mac);
    spi_bus_free(host);
    return err;
}
#endif

static esp_err_t apply_static(esp_netif_t *netif, const eth_config_t *c)
{
    if (!c->ip_static) return ESP_OK;
    esp_netif_ip_info_t info = {.ip.addr = c->ip, .netmask.addr = c->mask, .gw.addr = c->gw};
    (void)esp_netif_dhcpc_stop(netif);
    esp_err_t err = esp_netif_set_ip_info(netif, &info);
    if (err == ESP_OK && c->dns) {
        esp_netif_dns_info_t dns = {.ip.u_addr.ip4.addr = c->dns, .ip.type = ESP_IPADDR_TYPE_V4};
        (void)esp_netif_set_dns_info(netif, ESP_NETIF_DNS_MAIN, &dns);
    }
    return err;
}

#if CONFIG_SOC_USB_OTG_SUPPORTED
/* --- USB Ethernet adapter / phone tethering --- */
static bool s_usb;

/* The standard Ethernet netif ("ETH_DEF": the same ACL hooks, events and
 * selection as the W5500) with the USB data path as its driver. */
static esp_err_t prepare_usb(const eth_config_t *c)
{
    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_ETH();
    s_netif = esp_netif_new(&netif_config);
    if (!s_netif) return ESP_ERR_NO_MEM;
    esp_err_t err = esp_netif_attach(s_netif, usb_port_net_glue());
    if (err == ESP_OK) err = apply_static(s_netif, c);
    if (err == ESP_OK) err = esp_event_handler_register(IP_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    if (err != ESP_OK) {esp_netif_destroy(s_netif); s_netif = NULL; return err;}
    s_usb = true;   /* started by eth_uplink_start() after the ACL hooks */
    return ESP_OK;
}

/* usb_port client task context: the CDC NETWORK_CONNECTION state. */
static void usb_link(bool up, void *ctx)
{
    (void)ctx;
    link_changed(up);
    apply_choice();
    uplink_services_refresh(!up);
}

static void usb_note(uint8_t net, const char *text)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.usb_net = net;
    snprintf(s_status.error, sizeof s_status.error, "%s", text);
    xSemaphoreGive(s_lock);
    if (text[0]) ESP_LOGW(TAG, "%s", text);
}

static void usb_task(void *arg)
{
    (void)arg;
    const uint32_t retry_ms = 30000;
    uint8_t *cfg = NULL;
    while (!(cfg = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT))) {
        usb_note(USBP_NET_NONE, "not enough memory for the USB device");
        vTaskDelay(pdMS_TO_TICKS(retry_ms));
    }
    uint32_t handled = 0;   /* attach already acted on */
    TickType_t retry_at = 0;
    bool retry = false;
    for (;;) {
        usbp_device_t d;
        size_t len = 0;
        if (!usb_port_device(&d, cfg, 1024, &len)) {
            retry = false;
            usb_note(USBP_NET_NONE, "no USB device on the USB port");
            usb_port_wait(d.seq, retry_ms);
            continue;
        }
        if (d.seq == handled) {
            int32_t left = retry ? (int32_t)(retry_at - xTaskGetTickCount()) : 0;
            if (!retry || left > 0) {
                usb_port_wait(d.seq, retry ? pdTICKS_TO_MS((TickType_t)left) : retry_ms);
                continue;
            }
        }
        handled = d.seq;
        retry = false;
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_status.usb_vid = d.vid; s_status.usb_pid = d.pid;
        xSemaphoreGive(s_lock);
        usbp_net_t net;
        usbp_storage_t storage;
        if (usbp_scan(cfg, len, &net, &storage) < 0) {usb_note(USBP_NET_NONE, "USB device descriptor unreadable or larger than 1 KB"); continue;}
        int action = usbp_action(false, USBP_MODE_NETWORK, 0, &net, &storage, d.num_configs, d.config_value);
        if (action == USBP_ACT_NETWORK) {
            const char *why = "";
            esp_err_t err = usb_port_net_open(&d, &net, s_netif, usb_link, NULL, &why);
            if (err == ESP_OK) {
                usb_note(net.kind, "");
                while (usb_port_net_alive()) vTaskDelay(pdMS_TO_TICKS(250));
                usb_port_net_close();
                usb_note(USBP_NET_NONE, "USB Ethernet device stopped or disconnected");
                retry = true;
            } else {
                usb_note(USBP_NET_NONE, why);
                /* Invalid/poisoned sessions need a new attachment or restart.
                 * Allocation and other transient failures may clear in place. */
                retry = err != ESP_ERR_INVALID_ARG && err != ESP_ERR_INVALID_STATE;
            }
            retry_at = xTaskGetTickCount() + pdMS_TO_TICKS(retry_ms);
        } else if (action == USBP_ACT_SWITCH) {
            usb_note(USBP_NET_NONE, usb_port_switch(&d, &storage) == ESP_ERR_INVALID_STATE
                     ? "the USB device stays in storage mode: it may need a switch this firmware does not know"
                     : "switching the USB device out of storage mode");
        } else if (action == USBP_ACT_NEXT_CONFIG) {
            usb_note(USBP_NET_NONE, usb_port_next_config(&d) ? "trying another USB configuration of the device"
                                                              : "no configuration of this USB device has a supported network interface");
        } else {
            usb_note(USBP_NET_NONE, net.kind == USBP_NET_UNSUPPORTED
                ? "this USB network device is not supported (vendor-only chip such as ASIX AX88179, or MBIM): use an adapter or phone with CDC-ECM, CDC-NCM or RNDIS"
                : "no USB network interface on this device (a modem with serial ports belongs to the cellular uplink)");
        }
    }
}
#endif

bool eth_uplink_usb_configured(void)
{
    eth_config_t c;
    load(&c);
    return c.enabled && c.transport == ETH_TRANSPORT_USB;
}

void eth_uplink_init(void)
{
    ensure_lock();
    load(&s_saved);
    s_running = s_saved;
#if CONFIG_ETH_SPI_ETHERNET_W5500
    s_status.compiled = true;
#endif
    s_status.enabled_at_boot = s_running.enabled;
    s_status.transport = s_running.transport;
    if (!s_running.enabled) return;   /* WiFi-only path: no SPI/GPIO/USB/netif touched */
    if (s_running.transport == ETH_TRANSPORT_USB) {
#if CONFIG_SOC_USB_OTG_SUPPORTED
        s_status.compiled = true;
        esp_err_t err = prepare_usb(&s_running);
        if (err != ESP_OK) {
            char text[64];
            snprintf(text, sizeof text, "USB Ethernet not prepared: %s", esp_err_to_name(err));
            set_error(text);
        }
#else
        set_error("USB host not available on this chip");
#endif
        return;
    }
#if CONFIG_ETH_SPI_ETHERNET_W5500
    esp_err_t err = start_w5500(&s_running);
    if (err != ESP_OK) {
        char text[64];
        snprintf(text, sizeof text, "driver start failed: %s", esp_err_to_name(err));
        set_error(text);
        ESP_LOGE(TAG, "%s (WiFi uplink unaffected)", text);
        return;
    }
#else
    set_error("Ethernet driver not compiled into this firmware");
#endif
}

void eth_uplink_start(void)
{
#if CONFIG_SOC_USB_OTG_SUPPORTED
    if (s_usb) {
        /* Fail closed: without the ACL hooks the interface never carries traffic. */
        if (!netif_hooks_eth_ready()) {set_error("not started: firewall hooks unavailable"); return;}
        s_lwip = esp_netif_get_netif_impl(s_netif);
        const char *why = "";
        esp_err_t err = usb_port_start(&why);
        if (err == ESP_OK && xTaskCreatePinnedToCoreWithCaps(usb_task, "eth_usb", 4096, NULL, 5, NULL, tskNO_AFFINITY,
                                                             MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) err = ESP_ERR_NO_MEM;
        if (err != ESP_OK) {
            char text[sizeof s_status.error];
            snprintf(text, sizeof text, "USB not started: %s", why[0] ? why : esp_err_to_name(err));
            set_error(text);
            return;
        }
        xSemaphoreTake(s_lock, portMAX_DELAY);
        s_status.driver_started = true;
        xSemaphoreGive(s_lock);
        return;
    }
#endif
#if CONFIG_ETH_SPI_ETHERNET_W5500
    if (!s_handle) return;
    /* Fail closed: without the ACL hooks the interface never carries traffic. */
    if (!netif_hooks_eth_ready()) {set_error("not started: firewall hooks unavailable"); return;}
    s_lwip = esp_netif_get_netif_impl(s_netif);
    esp_err_t err = esp_eth_start(s_handle);
    if (err != ESP_OK) {
        char text[64];
        snprintf(text, sizeof text, "start failed: %s", esp_err_to_name(err));
        set_error(text);
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_status.driver_started = true;
    xSemaphoreGive(s_lock);
#endif
}

void eth_uplink_get_config(eth_config_t *out)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_saved;
    xSemaphoreGive(s_lock);
}

esp_err_t eth_uplink_store_for_reboot(const eth_config_t *c, char *why, size_t n)
{
    if (!eth_config_valid(c, why, n)) return ESP_ERR_INVALID_ARG;
    if (c->enabled && c->transport == ETH_TRANSPORT_USB) {
        /* One USB port: one device at a time (no hubs). */
        cell_config_t cell;
        cell_uplink_get_config(&cell);
        if (cell.enabled && cell.transport == CELL_TRANSPORT_USB) {
            snprintf(why, n, "the USB port is already used by the cellular uplink");
            return ESP_ERR_INVALID_ARG;
        }
    }
    union {eth_record_t v2; eth_record_v1_t v1;} r;
    size_t size = record_encode(c, &r);
    return nvs_param_set_blob("eth_cfg", &r, size);
}

esp_err_t eth_uplink_set_config(const eth_config_t *c, char *why, size_t n)
{
    ensure_lock();
    esp_err_t err = eth_uplink_store_for_reboot(c, why, n);
    if (err != ESP_OK) return err;   /* RAM keeps the previously saved value */
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_saved = *c;
    xSemaphoreGive(s_lock);
    return ESP_OK;
}

bool eth_uplink_restart_required(void)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool pending = memcmp(&s_saved, &s_running, sizeof s_saved) != 0;
    xSemaphoreGive(s_lock);
    return pending;
}

void eth_uplink_get_status(eth_status_t *out)
{
    ensure_lock();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_status;
    out->restart_required = memcmp(&s_saved, &s_running, sizeof s_saved) != 0;
    xSemaphoreGive(s_lock);
    out->link_up = atomic_load(&s_link);
    out->has_ip = atomic_load(&s_has_ip);
    out->selected = s_netif && uplink_internet_netif() == s_netif;
#if CONFIG_SOC_USB_OTG_SUPPORTED
    if (s_usb) {
        usbp_device_t d;
        usbp_memory_t m;
        out->usb_present = usb_port_device(&d, NULL, 0, NULL);
        usb_port_memory(&m);
        out->usb_ram_host = m.host_bytes; out->usb_ram_session = m.session_bytes;
        out->usb_ram_free = m.free_now; out->usb_ram_min = m.min_free; out->usb_ram_lean = m.lean;
    }
#endif
}

struct netif *eth_uplink_lwip_select(struct netif *sta)
{
    if (!s_running.enabled || !s_lwip) return NULL;
    bool sta_ok = sta && netif_is_up(sta) && netif_is_link_up(sta) && ip4_addr_get_u32(netif_ip4_addr(sta));
    bool eth_ok = atomic_load(&s_link) && atomic_load(&s_has_ip) &&
                  netif_is_up(s_lwip) && netif_is_link_up(s_lwip) && ip4_addr_get_u32(netif_ip4_addr(s_lwip));
    if (atomic_exchange(&s_stability_lost, false)) s_selector.eth_streak = 0;
    int choice = eth_uplink_choose(&s_selector, true, s_running.preference, sta_ok, eth_ok);
    bool eth = choice == ETH_CHOICE_ETH;
    /* Already in TCP/IP context: rebind listeners in place, never queue-wait on ourselves. */
    if (atomic_exchange(&s_selected_eth, eth) != eth) {
        portmap_install_now();
        uplink_services_schedule_refresh();
    }
    return eth ? s_lwip : sta;
}

esp_netif_t *eth_uplink_service_netif(void)
{
    if (s_netif && atomic_load(&s_selected_eth) && atomic_load(&s_has_ip)) return s_netif;
    return esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
}

esp_netif_t *eth_uplink_netif(void) { return atomic_load(&s_has_ip) ? s_netif : NULL; }

struct netif *eth_uplink_selected_lwip(void)
{
    if (!atomic_load(&s_selected_eth) || !atomic_load(&s_has_ip)) return NULL;
    return s_lwip;
}

/* --- HTTP --- */
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

static void add_ip(cJSON *o, const char *name, uint32_t nbo)
{
    char text[16] = "";
    if (nbo) {struct in_addr a = {.s_addr = nbo}; inet_ntoa_r(a, text, sizeof text);}
    cJSON_AddStringToObject(o, name, text);
}

static cJSON *config_json(const eth_config_t *c)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "enabled", c->enabled);
    cJSON_AddStringToObject(o, "transport", c->transport == ETH_TRANSPORT_USB ? "usb" : "spi");
    cJSON_AddStringToObject(o, "chip", "w5500");
    cJSON_AddNumberToObject(o, "spi_host", c->spi_host == 1 ? 2 : 3);
    cJSON_AddNumberToObject(o, "spi_mhz", c->spi_mhz);
    cJSON_AddNumberToObject(o, "sclk", c->sclk); cJSON_AddNumberToObject(o, "mosi", c->mosi);
    cJSON_AddNumberToObject(o, "miso", c->miso); cJSON_AddNumberToObject(o, "cs", c->cs);
    cJSON_AddNumberToObject(o, "int", c->intr); cJSON_AddNumberToObject(o, "rst", c->rst);
    cJSON_AddBoolToObject(o, "static_ip", c->ip_static);
    add_ip(o, "ip", c->ip); add_ip(o, "netmask", c->mask); add_ip(o, "gateway", c->gw); add_ip(o, "dns", c->dns);
    cJSON_AddStringToObject(o, "preference", c->preference == ETH_PREF_ETHERNET_FIRST ? "ethernet_first" : "wifi_first");
    return o;
}

static esp_err_t get_ethernet(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    eth_config_t c; eth_status_t s;
    eth_uplink_get_config(&c);
    eth_uplink_get_status(&s);
    cJSON *root = cJSON_CreateObject(), *status = root ? cJSON_AddObjectToObject(root, "status") : NULL;
    cJSON *config = config_json(&c);
    if (!status || !config || !cJSON_AddItemToObject(root, "config", config)) {cJSON_Delete(config); cJSON_Delete(root); return send_json(req, NULL);}
    cJSON_AddBoolToObject(status, "compiled", s.compiled);
    cJSON_AddBoolToObject(status, "enabled_at_boot", s.enabled_at_boot);
    cJSON_AddBoolToObject(status, "driver_started", s.driver_started);
    cJSON_AddBoolToObject(status, "link_up", s.link_up);
    cJSON_AddBoolToObject(status, "has_ip", s.has_ip);
    cJSON_AddBoolToObject(status, "selected_uplink", s.selected);
    cJSON_AddBoolToObject(status, "restart_required", s.restart_required);
    cJSON_AddNumberToObject(status, "link_changes", s.link_changes);
    add_ip(status, "ip", s.ip); add_ip(status, "netmask", s.mask); add_ip(status, "gateway", s.gw);
    cJSON_AddStringToObject(status, "error", s.error);
    cJSON_AddStringToObject(status, "transport", s.transport == ETH_TRANSPORT_USB ? "usb" : "spi");
    if (s.transport != ETH_TRANSPORT_USB || !s.enabled_at_boot) cJSON_AddNullToObject(status, "usb");
    else {
        static const char *const NET[] = {"none", "ecm", "ncm", "rndis", "unsupported"};
        cJSON *usb = cJSON_AddObjectToObject(status, "usb");
        char id[10] = "";
        if (s.usb_present && (s.usb_vid || s.usb_pid)) snprintf(id, sizeof id, "%04x:%04x", s.usb_vid, s.usb_pid);
        if (usb) {
            cJSON_AddBoolToObject(usb, "present", s.usb_present);
            cJSON_AddStringToObject(usb, "id", id);
            cJSON_AddStringToObject(usb, "network", s.usb_net < 5 ? NET[s.usb_net] : "none");
            cJSON *ram = cJSON_AddObjectToObject(usb, "internal_ram");
            if (ram) {
                cJSON_AddNumberToObject(ram, "usb_host_bytes", s.usb_ram_host);
                cJSON_AddNumberToObject(ram, "usb_session_bytes", s.usb_ram_session);
                cJSON_AddNumberToObject(ram, "free_bytes", s.usb_ram_free);
                cJSON_AddNumberToObject(ram, "min_free_bytes", s.usb_ram_min);
                cJSON_AddBoolToObject(ram, "lean_session", s.usb_ram_lean);
            }
        }
    }
    cJSON_AddStringToObject(status, "qualification", "not physically validated on this candidate");
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

static bool json_ip(const cJSON *root, const char *name, uint32_t *out)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(root, name);
    if (!cJSON_IsString(v)) return false;
    if (!v->valuestring[0]) {*out = 0; return true;}
    struct in_addr a;
    if (inet_pton(AF_INET, v->valuestring, &a) != 1) return false;
    *out = a.s_addr;
    return true;
}

static esp_err_t post_ethernet(httpd_req_t *req)
{
    if (web_ui_require_auth(req) != ESP_OK) return ESP_FAIL;
    char body[512], why[96] = "invalid request";
    int total = req->content_len, received = 0;
    if (total <= 0 || total >= (int)sizeof body) {httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "invalid body size"); return ESP_FAIL;}
    while (received < total) {
        int n = httpd_req_recv(req, body + received, total - received);
        if (n <= 0) {httpd_resp_send_408(req); return ESP_FAIL;}
        received += n;
    }
    body[received] = 0;
    cJSON *root = json_guard_parse(body);
    eth_config_t saved, c;
    eth_uplink_get_config(&saved);
    memset(&c, 0, sizeof c);
    c.chip = ETH_CHIP_W5500;
    /* transport is optional: older clients keep the saved choice. */
    c.transport = saved.transport;
    const cJSON *jt = cJSON_GetObjectItemCaseSensitive(root, "transport");
    bool transport_ok = !jt || (cJSON_IsString(jt) && (!strcmp(jt->valuestring, "spi") || !strcmp(jt->valuestring, "usb")));
    if (transport_ok && jt) c.transport = !strcmp(jt->valuestring, "usb") ? ETH_TRANSPORT_USB : ETH_TRANSPORT_SPI;
    int host = 0, mhz = 0, sclk, mosi, miso, cs, intr, rst;
    const cJSON *enabled = cJSON_GetObjectItemCaseSensitive(root, "enabled"), *st = cJSON_GetObjectItemCaseSensitive(root, "static_ip");
    const cJSON *pref = cJSON_GetObjectItemCaseSensitive(root, "preference"), *chip = cJSON_GetObjectItemCaseSensitive(root, "chip");
    bool parsed = cJSON_IsObject(root) && transport_ok && cJSON_IsBool(enabled) && cJSON_IsBool(st) && cJSON_IsString(pref)
        && cJSON_IsString(chip) && !strcmp(chip->valuestring, "w5500")
        && (!strcmp(pref->valuestring, "wifi_first") || !strcmp(pref->valuestring, "ethernet_first"))
        && json_int(root, "spi_host", 2, 3, &host) && json_int(root, "spi_mhz", 1, 40, &mhz)
        && json_int(root, "sclk", 0, 48, &sclk) && json_int(root, "mosi", 0, 48, &mosi) && json_int(root, "miso", 0, 48, &miso)
        && json_int(root, "cs", 0, 48, &cs) && json_int(root, "int", -1, 48, &intr) && json_int(root, "rst", -1, 48, &rst)
        && json_ip(root, "ip", &c.ip) && json_ip(root, "netmask", &c.mask) && json_ip(root, "gateway", &c.gw) && json_ip(root, "dns", &c.dns);
    if (parsed) {
        c.enabled = cJSON_IsTrue(enabled); c.ip_static = cJSON_IsTrue(st);
        c.preference = !strcmp(pref->valuestring, "ethernet_first") ? ETH_PREF_ETHERNET_FIRST : ETH_PREF_WIFI_FIRST;
        c.spi_host = (uint8_t)(host - 1); c.spi_mhz = (uint8_t)mhz;
        c.sclk = (int8_t)sclk; c.mosi = (int8_t)mosi; c.miso = (int8_t)miso; c.cs = (int8_t)cs; c.intr = (int8_t)intr; c.rst = (int8_t)rst;
        if (!c.ip_static) c.ip = c.mask = c.gw = c.dns = 0;
    }
    cJSON_Delete(root);
    esp_err_t err = parsed ? eth_uplink_set_config(&c, why, sizeof why) : ESP_ERR_INVALID_ARG;
    cJSON *reply = cJSON_CreateObject();
    if (err != ESP_OK) {
        httpd_resp_set_status(req, err == ESP_ERR_INVALID_ARG ? "400 Bad Request" : "500 Internal Server Error");
        if (reply) {cJSON_AddBoolToObject(reply, "ok", false); cJSON_AddStringToObject(reply, "error", err == ESP_ERR_INVALID_ARG ? why : esp_err_to_name(err));}
    } else if (reply) {cJSON_AddBoolToObject(reply, "ok", true); cJSON_AddBoolToObject(reply, "restart_required", eth_uplink_restart_required());}
    return send_json(req, reply);
}

esp_err_t eth_uplink_register_http(httpd_handle_t server)
{
    const httpd_uri_t routes[] = {
        {.uri = "/api/ethernet", .method = HTTP_GET, .handler = get_ethernet},
        {.uri = "/api/ethernet", .method = HTTP_POST, .handler = post_ethernet}};
    for (unsigned i = 0; i < sizeof routes / sizeof routes[0]; i++) {
        esp_err_t err = httpd_register_uri_handler(server, &routes[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}
