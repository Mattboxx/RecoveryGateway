/* Huawei HiLink signal and operator; see cell_hilink.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "cell_hilink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- hilink core (begin) --- */
static const char *hl_find(const char *hay, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || n > len) return NULL;
    for (size_t i = 0; i + n <= len; i++)
        if (hay[i] == needle[0] && !memcmp(hay + i, needle, n)) return hay + i;
    return NULL;
}

bool hilink_xml_value(const char *xml, size_t len, const char *tag, char *out, size_t cap)
{
    if (!xml || !tag || !out || cap < 2 || strlen(tag) > 40) return false;
    out[0] = 0;
    char open[48], close[48];
    snprintf(open, sizeof open, "<%s>", tag);
    snprintf(close, sizeof close, "</%s>", tag);
    const char *start = hl_find(xml, len, open);
    if (!start) return false;
    start += strlen(open);
    const char *end = hl_find(start, len - (size_t)(start - xml), close);
    if (!end) return false;
    while (start < end && (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')) start++;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) end--;
    size_t n = (size_t)(end - start);
    if (!n || n >= cap) return false;
    memcpy(out, start, n);
    out[n] = 0;
    return true;
}

int hilink_dbm(const char *text)
{
    if (!text) return 0;
    while (*text == '>' || *text == '<' || *text == '=' || *text == ' ') text++;
    char *end = NULL;
    long v = strtol(text, &end, 10);
    if (end == text || (*end && strcmp(end, "dBm") && strcmp(end, "dbm"))) return 0;
    return v <= -20 && v >= -140 ? (int)v : 0;
}

void hilink_clean_name(const char *in, char *out, size_t cap)
{
    size_t n = 0;
    for (; in && *in && n + 1 < cap; in++)
        if ((unsigned char)*in >= 0x20 && (unsigned char)*in < 0x7f) out[n++] = *in;
    if (cap) out[n] = 0;
}
/* --- hilink core (end) --- */

#if !defined(HILINK_HOST_TEST)
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "lwip/inet.h"

#define TAG "cell_hilink"

/* One bounded GET; the body (up to HILINK_RESPONSE_MAX - 1) into buf. */
static int hl_get(uint32_t gw, const char *path, const char *cookie, const char *token, char *buf)
{
    char url[64];
    struct in_addr a = {.s_addr = gw};
    char ip[16];
    snprintf(url, sizeof url, "http://%s%s", inet_ntoa_r(a, ip, sizeof ip), path);
    esp_http_client_config_t cfg = {.url = url, .timeout_ms = 2000, .disable_auto_redirect = true, .buffer_size = 1024};
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return -1;
    if (cookie && cookie[0]) esp_http_client_set_header(c, "Cookie", cookie);
    if (token && token[0]) esp_http_client_set_header(c, "__RequestVerificationToken", token);
    int total = -1;
    if (esp_http_client_open(c, 0) == ESP_OK && esp_http_client_fetch_headers(c) >= 0 && esp_http_client_get_status_code(c) == 200) {
        total = 0;
        int n;
        while (total < HILINK_RESPONSE_MAX - 1 && (n = esp_http_client_read(c, buf + total, HILINK_RESPONSE_MAX - 1 - total)) > 0) total += n;
        buf[total] = 0;
    }
    esp_http_client_close(c);
    esp_http_client_cleanup(c);
    return total;
}

bool cell_hilink_poll(uint32_t gateway_nbo, int16_t *rssi_dbm, char *operator_name, size_t cap)
{
    if (!gateway_nbo) return false;
    char *buf = heap_caps_malloc(HILINK_RESPONSE_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) return false;
    char session[160] = "", token[80] = "", cookie[176] = "", value[64];
    bool any = false;
    int n = hl_get(gateway_nbo, "/api/webserver/SesTokInfo", NULL, NULL, buf);
    if (n > 0 && hilink_xml_value(buf, (size_t)n, "SesInfo", session, sizeof session)) {
        hilink_xml_value(buf, (size_t)n, "TokInfo", token, sizeof token);
        /* SesInfo is "SessionID=..." already; keep it as the cookie. */
        snprintf(cookie, sizeof cookie, "%s", session);
    }
    n = hl_get(gateway_nbo, "/api/device/signal", cookie, token, buf);
    if (n > 0) {
        int dbm = 0;
        if (hilink_xml_value(buf, (size_t)n, "rssi", value, sizeof value)) dbm = hilink_dbm(value);
        if (!dbm && hilink_xml_value(buf, (size_t)n, "rsrp", value, sizeof value)) dbm = hilink_dbm(value);
        if (dbm) {*rssi_dbm = (int16_t)dbm; any = true;}
    }
    n = hl_get(gateway_nbo, "/api/net/current-plmn", cookie, token, buf);
    if (n > 0 && (hilink_xml_value(buf, (size_t)n, "FullName", value, sizeof value)
                  || hilink_xml_value(buf, (size_t)n, "ShortName", value, sizeof value))) {
        hilink_clean_name(value, operator_name, cap);
        any |= operator_name[0] != 0;
    }
    memset(session, 0, sizeof session);
    memset(token, 0, sizeof token);
    memset(cookie, 0, sizeof cookie);
    heap_caps_free(buf);
    if (!any) ESP_LOGD(TAG, "no signal or operator from the stick");
    return any;
}
#endif
