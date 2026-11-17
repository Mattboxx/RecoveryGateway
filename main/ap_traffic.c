/* Traffic per access-point device; see ap_traffic.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "ap_traffic.h"
#include <string.h>

/* --- ap_traffic core (begin) --- */
static bool ap_traffic_device(const uint8_t mac[6])
{
    static const uint8_t zero[6];
    return !(mac[0] & 1) && memcmp(mac, zero, 6) != 0;
}

void ap_traffic_add(ap_traffic_table_t *t, const uint8_t mac[6], uint32_t bytes, bool from_client)
{
    if (!ap_traffic_device(mac)) return;
    ap_traffic_entry_t *slot = NULL, *oldest = &t->e[0], *free_slot = NULL;
    for (int i = 0; i < AP_TRAFFIC_SLOTS; i++) {
        ap_traffic_entry_t *e = &t->e[i];
        if (e->used && !memcmp(e->mac, mac, 6)) {slot = e; break;}
        if (!e->used && !free_slot) free_slot = e;
        if (e->used && e->order < oldest->order) oldest = e;
    }
    if (!slot) {
        slot = free_slot ? free_slot : oldest;
        memset(slot, 0, sizeof *slot);
        memcpy(slot->mac, mac, 6);
        slot->used = true;
    }
    if (from_client) slot->from_client += bytes;
    else slot->to_client += bytes;
    slot->order = ++t->order;
}

bool ap_traffic_find(const ap_traffic_table_t *t, const uint8_t mac[6], uint64_t *from_client, uint64_t *to_client)
{
    for (int i = 0; i < AP_TRAFFIC_SLOTS; i++)
        if (t->e[i].used && !memcmp(t->e[i].mac, mac, 6)) {
            *from_client = t->e[i].from_client;
            *to_client = t->e[i].to_client;
            return true;
        }
    return false;
}
/* --- ap_traffic core (end) --- */

#if !defined(AP_TRAFFIC_HOST_TEST)
#include "nvs_params.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"

volatile bool ap_traffic_on;
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
EXT_RAM_BSS_ATTR static ap_traffic_table_t s_table;   /* PSRAM: nothing internal while off */

void ap_traffic_init(void)
{
    uint8_t on = 0;
    ap_traffic_on = nvs_param_get_u8("ap_traffic", &on) == ESP_OK && on == 1;
}

void ap_traffic_frame(const uint8_t *frame, size_t len, uint32_t bytes, bool from_client)
{
    if (!frame || len < 14) return;
    /* From a client: its address is the source; to a client: the destination. */
    portENTER_CRITICAL(&s_mux);
    ap_traffic_add(&s_table, from_client ? frame + 6 : frame, bytes, from_client);
    portEXIT_CRITICAL(&s_mux);
}

bool ap_traffic_get(const uint8_t mac[6], uint64_t *from_client, uint64_t *to_client)
{
    if (!ap_traffic_on) return false;
    portENTER_CRITICAL(&s_mux);
    bool found = ap_traffic_find(&s_table, mac, from_client, to_client);
    portEXIT_CRITICAL(&s_mux);
    return found;
}

esp_err_t ap_traffic_set(bool on)
{
    esp_err_t err = nvs_param_set_u8("ap_traffic", on ? 1 : 0);
    if (err != ESP_OK) return err;
    if (!on) {
        ap_traffic_on = false;
        portENTER_CRITICAL(&s_mux);
        memset(&s_table, 0, sizeof s_table);
        portEXIT_CRITICAL(&s_mux);
    } else {
        ap_traffic_on = true;
    }
    return ESP_OK;
}
#endif
