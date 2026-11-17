/* Mattboxx Edition changes: Copyright (C) 2026 Mattboxx, GPL-3.0-only (LICENSE,
 * LICENSE-EXCEPTION.md). The original code keeps the licence stated in its own
 * notice below (see also NOTICE.md and licenses/upstream/). */
/* DNS forwarder + cache for AP clients.
 *
 * Architecture: one listener task binds AP:53/udp and recvfrom()s client
 * queries. A SPIRAM direct-mapped response cache answers repeats instantly
 * (no upstream round-trip); cache misses are handed over a small work queue
 * to a pool of worker tasks, each owning its own upstream UDP socket. So a
 * single bound listener (one port-53 socket) still serves many concurrent
 * in-flight upstream queries, and a slow/stuck upstream query ties up only
 * one worker — not the whole relay.
 *
 * The cache lives in SPIRAM (heap_caps), and per-miss work items are SPIRAM-
 * allocated, so the relay's internal-DRAM footprint is just the three small
 * task stacks. Lookup is O(1): FNV-1a hash of the question -> one slot, with
 * a full-question memcmp so a hash collision is a miss, never a wrong answer.
 *
 * SPDX-License-Identifier: MIT
 */

#include "dns_relay.h"

#include <string.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"   /* xTaskCreateWithCaps — PSRAM stacks */
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "task_reaper.h"

#define DNS_RELAY_PORT          53
#define DNS_RELAY_BUF_SIZE      1024     /* RFC 1035 §2.3.4: 512 udp, EDNS0 lifts it; 1024 ceiling. */
#define DNS_RELAY_UP_TIMEOUT_MS 3500
#define DNS_RELAY_BOOT_DELAY_MS 3000     /* Settle window before the first bind attempt. */
#define DNS_RELAY_TX_RETRIES    4        /* upstream sendto ENOMEM: retry, don't drop the query */
#define DNS_RELAY_TX_RETRY_MS   5        /* per-retry backoff; WiFi TX buffers free within a few ms */
#define DNS_RELAY_MAX_STRAY     8        /* unmatched datagrams discarded per query before giving up */
/* DNS over TCP (RFC 7766): what a client does after a truncated UDP answer.
 * One connection at a time (a worker stays free for UDP), one query per
 * connection, bounded waits; the answer buffer lives in PSRAM. */
#define DNS_TCP_MAX_ANSWER      4096
#define DNS_TCP_CLIENT_MS       1500     /* client must send its query within this */
#define DNS_TCP_UPSTREAM_MS     DNS_RELAY_UP_TIMEOUT_MS
#define DNS_TCP_ACTIVE_MAX      1

/* PSRAM-backed stacks (see xTaskCreateWithCaps below), so generous sizing is
 * cheap. Bumped 2026-06-10: at INFO verbosity (SD recorder sd_level=3) the
 * per-line vsnprintf formatting on the task stack overflowed the old 4096-byte
 * listener stack at boot -> "stack overflow in task dns_relay" PANIC -> boot
 * loop. The recorder's INFO option is user-selectable and must not be able to
 * crash these tasks. */
#define DNS_LISTENER_STACK      8192
#define DNS_WORKER_STACK        8192
#define DNS_RELAY_TASK_PRIO     4
#define DNS_WORKER_COUNT        2
#define DNS_WORK_QUEUE_DEPTH    8

/* SPIRAM direct-mapped response cache. 256 entries * ~1.3 KB ~= 330 KB SPIRAM. */
#define DNS_CACHE_ENTRIES       256
#define DNS_CACHE_KEY_MAX       256      /* DNS question section ceiling (qname<=255 + qtype/qclass) */
#define DNS_CACHE_TTL_MIN_S     10
#define DNS_CACHE_TTL_MAX_S     3600
#define DNS_CACHE_TTL_NEG_S     15       /* empty / NXDOMAIN brief negative cache */

#define DNS_RELAY_NVS_NS        "tsr"
#define KEY_ENABLED             "dns_relay_en"
#define KEY_UPSTREAM            "dns_relay_up"

static const char *TAG = "dns_relay";

static volatile bool     s_enabled       = false;
static volatile uint32_t s_upstream_nbo  = 0;      /* 0 = use STA-learned */
static volatile uint32_t s_bind_nbo      = 0;      /* AP IP; 0 = wait, don't bind yet */
static volatile bool     s_socket_dirty  = false;  /* tell the listener to rebind */
static volatile bool     s_healthy       = false;  /* bound and serving — softap_set_dns_addr gates on this */
static volatile int      s_listen_sock   = -1;     /* listener-owned; workers reply through it */

static TaskHandle_t s_listener = NULL;
static volatile uint32_t s_captive_nbo = 0;        /* first-boot captive answer; 0 = relay */

/* Optional second listener on the uplink (LAN) address, and an optional local
 * resolver consulted before the cache. Both off unless the firmware turns
 * them on; off, each costs one load per query. */
static volatile bool     s_lan_on        = false;
static volatile uint32_t s_lan_nbo       = 0;      /* uplink IP; 0 = not bound */
static volatile bool     s_lan_dirty     = false;
static volatile int      s_lan_sock      = -1;
static volatile dns_relay_local_cb_t s_local_cb = NULL;
static volatile dns_relay_route_cb_t s_route_cb = NULL;

/* Explicit registration-based health callback (see git history: weak-symbol
 * overrides didn't resolve reliably across the component link boundary). */
static dns_relay_state_cb_t s_state_cb = NULL;
void dns_relay_set_state_cb(dns_relay_state_cb_t cb) { s_state_cb = cb; }
static void notify_state(bool healthy)
{
    dns_relay_state_cb_t cb = s_state_cb;
    if (cb) cb(healthy);
}

/* ---- listener -> worker hand-off: a pointer queue; items live in SPIRAM ---- */
typedef struct {
    struct sockaddr_in client;
    socklen_t          client_len;
    bool               lan;            /* reply through the LAN listener */
    uint32_t           upstream;       /* effective resolver selected by the listener */
    uint32_t           cache_epoch;
    int                tcp;            /* accepted TCP connection, or -1 for UDP */
    int                qlen;
    uint8_t            q[DNS_RELAY_BUF_SIZE];
} dns_work_t;
static QueueHandle_t s_workq = NULL;

/* ---- SPIRAM direct-mapped response cache ---- */
typedef struct {
    int64_t  expiry_us;                 /* esp_timer_get_time() deadline; 0 = empty slot */
    uint32_t upstream;
    uint32_t epoch;
    uint16_t key_len;
    uint16_t resp_len;
    uint8_t  key[DNS_CACHE_KEY_MAX];    /* question section (from offset 12): qname+qtype+qclass */
    uint8_t  resp[DNS_RELAY_BUF_SIZE];  /* full upstream response */
} dns_cache_entry_t;
static dns_cache_entry_t *s_cache = NULL;       /* SPIRAM */
static SemaphoreHandle_t  s_cache_mtx = NULL;
static atomic_uint s_cache_epoch;

/* Diagnostics counters. Unlocked: a torn increment only skews a stat by one,
 * which is irrelevant — the cache *data* is what the mutex protects. */
static volatile uint32_t st_queries, st_hits, st_misses, st_inserts, st_evictions, st_stray, st_tcp, st_truncated;
static atomic_int s_tcp_active;

/* Resolve the live upstream IP every forward. Priority: explicit operator
 * override, then DNS learned from the STA DHCP lease. No public resolver is
 * contacted unless the operator or upstream DHCP server selected it. */
static esp_netif_t *(*s_uplink_provider)(void);

void dns_relay_set_uplink_provider(esp_netif_t *(*provider)(void))
{
    s_uplink_provider = provider;
}

static uint32_t pick_upstream(void)
{
    if (s_upstream_nbo) return s_upstream_nbo;
    esp_netif_t *sta = s_uplink_provider ? s_uplink_provider() : esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta) {
        esp_netif_dns_info_t info = {0};
        if (esp_netif_get_dns_info(sta, ESP_NETIF_DNS_MAIN, &info) == ESP_OK &&
            info.ip.type == ESP_IPADDR_TYPE_V4) {
            uint32_t a = info.ip.u_addr.ip4.addr;
            if (a != 0) return a;
        }
    }
    return 0;
}

/* Open + bind a listening socket. Returns the fd or -1. */
static int open_listen_sock(uint32_t bind_nbo)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        ESP_LOGE(TAG, "listen socket() failed: errno=%d", errno);
        return -1;
    }
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_RELAY_PORT),
        .sin_addr.s_addr = bind_nbo ? bind_nbo : INADDR_ANY,
    };
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind() failed: errno=%d", errno);
        close(s);
        return -1;
    }
    struct timeval rcvto = { .tv_sec = 0, .tv_usec = 500 * 1000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
    ESP_LOGI(TAG, "listening on %d.%d.%d.%d:%d",
             (int)(addr.sin_addr.s_addr        & 0xFF),
             (int)((addr.sin_addr.s_addr >> 8) & 0xFF),
             (int)((addr.sin_addr.s_addr >> 16)& 0xFF),
             (int)((addr.sin_addr.s_addr >> 24)& 0xFF),
             DNS_RELAY_PORT);
    return s;
}

/* TCP listening socket (non-blocking accept) on the same address, or -1. */
static int open_tcp_listen(uint32_t bind_nbo)
{
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return -1;
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(DNS_RELAY_PORT), .sin_addr.s_addr = bind_nbo};
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(s, 2) < 0) {close(s); return -1;}
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
    return s;
}

/* A pending TCP connection: handed to a worker when none is busy with TCP,
 * else closed at once (the client falls back to another resolver). */
static void tcp_accept(int ls, bool lan)
{
    struct sockaddr_in client = {0};
    socklen_t client_len = sizeof client;
    int fd = accept(ls, (struct sockaddr *)&client, &client_len);
    if (fd < 0) return;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
    if (atomic_fetch_add(&s_tcp_active, 1) >= DNS_TCP_ACTIVE_MAX) {
        atomic_fetch_sub(&s_tcp_active, 1);
        close(fd);
        return;
    }
    dns_work_t *w = heap_caps_malloc(sizeof(dns_work_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (w) {
        memset(w, 0, offsetof(dns_work_t, q));
        w->client = client; w->client_len = client_len; w->lan = lan; w->tcp = fd;
        if (xQueueSend(s_workq, &w, 0) == pdTRUE) return;
        heap_caps_free(w);
    }
    close(fd);
    atomic_fetch_sub(&s_tcp_active, 1);
}

/* ───────────────────── DNS packet helpers ───────────────────── */

/* Byte length of the question section starting at offset 12 (qname labels +
 * qtype + qclass), or 0 if malformed / oversized / not a single clean
 * question. Compression pointers are illegal in a question -> reject. */
static int dns_question_len(const uint8_t *p, int len)
{
    if (len < 12 + 5) return 0;          /* header + at least root(1) + qtype/qclass(4) */
    int i = 12;
    while (i < len) {
        uint8_t c = p[i];
        if (c == 0) { i += 1 + 4; break; }   /* root label terminator + qtype + qclass */
        if (c & 0xC0) return 0;              /* compression / reserved in a question */
        i += 1 + c;
    }
    if (i > len) return 0;
    int qlen = i - 12;
    return (qlen >= 5 && qlen <= DNS_CACHE_KEY_MAX) ? qlen : 0;
}

/* Index after the domain name at `i` (labels, maybe ending in a pointer), or
 * -1 when it runs past `len`. */
static int dns_skip_name(const uint8_t *p, int len, int i)
{
    for (int labels = 0; labels < 128; labels++) {
        if (i >= len) return -1;
        uint8_t c = p[i];
        if (c == 0) return i + 1;
        if ((c & 0xC0) == 0xC0) return i + 2 <= len ? i + 2 : -1;
        if (c & 0xC0) return -1;
        i += 1 + c;
    }
    return -1;
}

/* Lowers the EDNS(0) UDP payload size a query advertises to `max`, so the
 * upstream never sends an answer larger than the relay can receive: it sets
 * TC instead and the client retries over TCP. Returns true when the query
 * is well formed (changed or not); a query without EDNS is limited to 512
 * bytes by the protocol already. */
static bool dns_edns_clamp(uint8_t *p, int len, uint16_t max)
{
    if (len < 12) return false;
    int counts = ((p[4] << 8) | p[5]), rrs = ((p[6] << 8) | p[7]) + ((p[8] << 8) | p[9]), ar = (p[10] << 8) | p[11];
    if (counts > 8 || rrs > 32 || ar > 32) return false;
    int i = 12;
    for (int q = 0; q < counts; q++) {
        if ((i = dns_skip_name(p, len, i)) < 0 || i + 4 > len) return false;
        i += 4;
    }
    for (int r = 0; r < rrs + ar; r++) {
        if ((i = dns_skip_name(p, len, i)) < 0 || i + 10 > len) return false;
        uint16_t type = (uint16_t)(p[i] << 8 | p[i + 1]), size = (uint16_t)(p[i + 2] << 8 | p[i + 3]);
        uint16_t rdlen = (uint16_t)(p[i + 8] << 8 | p[i + 9]);
        if (r >= rrs && type == 41 && size > max) {uint8_t *cls = p + i + 2; cls[0] = (uint8_t)(max >> 8); cls[1] = (uint8_t)max;}
        if (i + 10 + rdlen > len) return false;
        i += 10 + rdlen;
    }
    return true;
}

/* An upstream answer longer than the relay's buffer: keep its header and
 * question, set TC and drop the records, so the client gets a valid
 * "truncated, ask over TCP" reply instead of a cut datagram. `q` is the
 * query it answers. Returns the new length, or 0 when it cannot be done. */
static int dns_truncated_reply(uint8_t *r, int rlen, const uint8_t *q, int qlen)
{
    int ql = dns_question_len(q, qlen);
    if (ql <= 0 || rlen < 12 + ql || ((r[4] << 8) | r[5]) != 1) return 0;
    uint8_t *h = r;                                   /* header: TC on, no records */
    h[2] |= 0x02;
    memset(h + 6, 0, 6);
    return 12 + ql;
}

/* Cacheable standard query? QR=0, opcode=0, QDCOUNT==1. */
static bool dns_is_std_query(const uint8_t *p, int len)
{
    if (len < 12) return false;
    if (p[2] & 0x80) return false;             /* QR=1 => a response, not a query */
    if ((p[2] >> 3) & 0x0F) return false;      /* opcode != 0 (QUERY) */
    return ((p[4] << 8) | p[5]) == 1;          /* QDCOUNT == 1 */
}

/* Cache TTL for a response: min TTL across the answer RRs, clamped. Returns 0
 * if the response must not be cached (RCODE other than NOERROR/NXDOMAIN). An
 * empty answer section (incl. NXDOMAIN) gets a brief negative-cache TTL.
 * qlen is the question length from dns_question_len(). */
static uint32_t dns_resp_ttl(const uint8_t *p, int len, int qlen)
{
    if (len < 12 + qlen) return 0;
    uint8_t rcode = p[3] & 0x0F;
    if (rcode != 0 && rcode != 3) return 0;    /* only NOERROR / NXDOMAIN */
    if (p[2] & 0x02) return 0;                 /* TC: a partial answer, never cached */
    uint16_t an = (p[6] << 8) | p[7];
    if (an == 0) return DNS_CACHE_TTL_NEG_S;
    int i = 12 + qlen;                          /* start of answer section */
    uint32_t minttl = 0xFFFFFFFFu;
    for (int a = 0; a < an; a++) {
        if (i + 1 > len) return DNS_CACHE_TTL_NEG_S;
        if ((p[i] & 0xC0) == 0xC0) {            /* compressed name -> 2 bytes */
            i += 2;
        } else {                                /* labels, maybe ending in a pointer */
            while (i < len && p[i] && (p[i] & 0xC0) != 0xC0) i += 1 + p[i];
            i += (i < len && (p[i] & 0xC0) == 0xC0) ? 2 : 1;
        }
        if (i + 10 > len) return DNS_CACHE_TTL_NEG_S;
        uint32_t ttl = ((uint32_t)p[i+4] << 24) | ((uint32_t)p[i+5] << 16) |
                       ((uint32_t)p[i+6] << 8)  |  (uint32_t)p[i+7];
        uint16_t rdlen = (p[i+8] << 8) | p[i+9];
        if (ttl < minttl) minttl = ttl;
        i += 10 + rdlen;
    }
    if (minttl == 0xFFFFFFFFu) return DNS_CACHE_TTL_NEG_S;
    if (minttl < DNS_CACHE_TTL_MIN_S) minttl = DNS_CACHE_TTL_MIN_S;
    if (minttl > DNS_CACHE_TTL_MAX_S) minttl = DNS_CACHE_TTL_MAX_S;
    return minttl;
}

static uint32_t fnv1a(const uint8_t *d, int n)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < n; i++) { h ^= d[i]; h *= 16777619u; }
    return h;
}

/* Two-way set-associative: a question may live in either entry of its set,
 * so two busy names that hash to the same set no longer evict each other. */
#define DNS_CACHE_WAYS 2
static uint32_t cache_set(const uint8_t *q, int key_len)
{
    return (fnv1a(q + 12, key_len) % (DNS_CACHE_ENTRIES / DNS_CACHE_WAYS)) * DNS_CACHE_WAYS;
}

static bool cache_same_key(const dns_cache_entry_t *e, const uint8_t *q, int key_len)
{
    return e->expiry_us != 0 && e->key_len == key_len && memcmp(e->key, q + 12, key_len) == 0;
}

/* Look the question up. On hit, copies the response to out (*out_len set) and
 * rewrites the txid to the querying client's. Returns true on hit. */
static bool cache_get(const uint8_t *q, int key_len, uint32_t upstream, uint32_t epoch,
                      uint8_t *out, int *out_len)
{
    if (!s_cache || !s_cache_mtx) return false;
    uint32_t set = cache_set(q, key_len);
    bool hit = false;
    xSemaphoreTake(s_cache_mtx, portMAX_DELAY);
    int64_t now = esp_timer_get_time();
    for (uint32_t w = 0; w < DNS_CACHE_WAYS && !hit; w++) {
        dns_cache_entry_t *e = &s_cache[set + w];
        if (cache_same_key(e, q, key_len) && e->upstream == upstream && e->epoch == epoch && now < e->expiry_us) {
            memcpy(out, e->resp, e->resp_len);
            *out_len = e->resp_len;
            hit = true;
        }
    }
    xSemaphoreGive(s_cache_mtx);
    if (hit) { out[0] = q[0]; out[1] = q[1]; }   /* match the client's transaction id */
    return hit;
}

static void cache_put(const uint8_t *q, int key_len, uint32_t upstream, uint32_t epoch,
                      const uint8_t *resp, int resp_len, uint32_t ttl_s)
{
    if (!s_cache || !s_cache_mtx) return;
    if (key_len <= 0 || key_len > DNS_CACHE_KEY_MAX) return;
    if (resp_len <= 0 || resp_len > DNS_RELAY_BUF_SIZE) return;
    uint32_t set = cache_set(q, key_len);
    xSemaphoreTake(s_cache_mtx, portMAX_DELAY);
    /* The same question's entry, else a free or expired one, else the one
     * that expires first. */
    int64_t now = esp_timer_get_time();
    dns_cache_entry_t *e = NULL;
    for (uint32_t w = 0; w < DNS_CACHE_WAYS && !e; w++)
        if (cache_same_key(&s_cache[set + w], q, key_len)) e = &s_cache[set + w];
    for (uint32_t w = 0; w < DNS_CACHE_WAYS && !e; w++)
        if (s_cache[set + w].expiry_us == 0 || now >= s_cache[set + w].expiry_us) e = &s_cache[set + w];
    if (!e) e = s_cache[set].expiry_us <= s_cache[set + 1].expiry_us ? &s_cache[set] : &s_cache[set + 1];
    bool was_other = e->expiry_us != 0 && now < e->expiry_us && !cache_same_key(e, q, key_len);
    e->expiry_us = esp_timer_get_time() + (int64_t)ttl_s * 1000000;
    e->upstream  = upstream;
    e->epoch     = epoch;
    e->key_len   = (uint16_t)key_len;
    memcpy(e->key, q + 12, key_len);
    e->resp_len  = (uint16_t)resp_len;
    memcpy(e->resp, resp, resp_len);
    xSemaphoreGive(s_cache_mtx);
    st_inserts++;
    if (was_other) st_evictions++;
}

/* ───────────────────── Worker pool ───────────────────── */

/* The answer to the query just sent: same ID, a response, and the same
 * question (ASCII case-insensitive; resolvers may randomise case). Anything
 * else (a late answer to an earlier query, a forged datagram) is not ours. */
static bool dns_reply_matches(const uint8_t *r, int rlen, const uint8_t *q, int qlen)
{
    if (rlen < 12 || qlen < 12) return false;
    if (r[0] != q[0] || r[1] != q[1] || !(r[2] & 0x80)) return false;
    if ((r[2] & 0x78) != (q[2] & 0x78)) return false;          /* same opcode */
    int ql = dns_question_len(q, qlen);
    if (ql <= 0) return true;                                  /* nothing more to compare */
    if (((r[4] << 8) | r[5]) != 1 || rlen < 12 + ql) return false;
    for (int i = 12; i < 12 + ql; i++) {
        uint8_t a = r[i], b = q[i];
        if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
        if (a != b) return false;
    }
    return true;
}

/* Receive the upstream answer to q: only from the server it was sent to,
 * only a matching reply. Stray datagrams are discarded (bounded). Returns
 * the length, 0 when none arrived in time, -1 on a socket error. */
static int upstream_recv(int up, uint8_t *rbuf, const uint8_t *q, int qlen, const struct sockaddr_in *server)
{
    /* rbuf holds DNS_RELAY_BUF_SIZE + 1 bytes: a longer answer is detected
     * (lwIP cuts a datagram to the buffer) instead of being passed on cut. */
    for (int stray = 0; stray <= DNS_RELAY_MAX_STRAY; stray++) {
        struct sockaddr_in from = {0};
        socklen_t from_len = sizeof from;
        int rlen = recvfrom(up, rbuf, DNS_RELAY_BUF_SIZE + 1, 0, (struct sockaddr *)&from, &from_len);
        if (rlen <= 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
        if (from.sin_addr.s_addr == server->sin_addr.s_addr && from.sin_port == server->sin_port &&
            dns_reply_matches(rbuf, rlen, q, qlen))
            return rlen;
        st_stray++;
    }
    return 0;
}

/* ---- DNS over TCP (worker side) ---- */

/* Reads or writes exactly n bytes before `deadline_us` (sockets carry short
 * timeouts, so a silent peer cannot hold a worker longer). */
static bool tcp_all(int fd, uint8_t *buf, int n, bool sending, int64_t deadline_us)
{
    int done = 0;
    while (done < n) {
        if (esp_timer_get_time() >= deadline_us) return false;
        int r = sending ? send(fd, buf + done, n - done, 0) : recv(fd, buf + done, n - done, 0);
        if (r > 0) {done += r; continue;}
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return false;
    }
    return true;
}

/* One length-prefixed DNS message; its length, or -1 (also when > cap). */
static int tcp_read_msg(int fd, uint8_t *buf, int cap, int64_t deadline_us)
{
    uint8_t lp[2];
    if (!tcp_all(fd, lp, 2, false, deadline_us)) return -1;
    int n = lp[0] << 8 | lp[1];
    if (n < 12 || n > cap || !tcp_all(fd, buf, n, false, deadline_us)) return -1;
    return n;
}

static bool tcp_write_msg(int fd, const uint8_t *buf, int n, int64_t deadline_us)
{
    uint8_t lp[2] = {(uint8_t)(n >> 8), (uint8_t)n};
    return n > 0 && n <= 0xffff && tcp_all(fd, lp, 2, true, deadline_us) && tcp_all(fd, (uint8_t *)buf, n, true, deadline_us);
}

static void tcp_timeouts(int fd, int ms)
{
    struct timeval to = {.tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof to);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof to);
}

/* TCP connection to the resolver within `ms`, or -1. */
static int tcp_connect(uint32_t upstream, int ms)
{
    int u = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (u < 0) return -1;
    int flags = fcntl(u, F_GETFL, 0);
    fcntl(u, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(DNS_RELAY_PORT), .sin_addr.s_addr = upstream};
    if (connect(u, (struct sockaddr *)&a, sizeof a) < 0 && errno != EINPROGRESS) {close(u); return -1;}
    fd_set w;
    FD_ZERO(&w); FD_SET(u, &w);
    struct timeval to = {.tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000};
    int err = 0;
    socklen_t el = sizeof err;
    if (select(u + 1, NULL, &w, NULL, &to) != 1 || getsockopt(u, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err) {close(u); return -1;}
    fcntl(u, F_SETFL, flags & ~O_NONBLOCK);
    tcp_timeouts(u, 500);
    return u;
}

/* Answers one query of an accepted TCP connection: tailnet names locally,
 * anything else through the same resolver choice as UDP, over TCP. Not
 * cached (TCP answers may exceed a cache slot). Closes the connection. */
static void tcp_serve(dns_work_t *w, uint8_t *answer)
{
    int fd = w->tcp, up = -1;
    int64_t deadline = esp_timer_get_time() + (int64_t)DNS_TCP_CLIENT_MS * 1000;
    tcp_timeouts(fd, 500);
    int qlen = tcp_read_msg(fd, w->q, DNS_RELAY_BUF_SIZE, deadline);
    if (qlen < 12) goto done;
    st_queries++;
    st_tcp++;
    deadline = esp_timer_get_time() + (int64_t)(DNS_TCP_UPSTREAM_MS + 1000) * 1000;
    if (s_captive_nbo) goto done;                     /* first-boot setup answers over UDP only */
    dns_relay_local_cb_t local = s_local_cb;
    int rl = local ? local(w->q, qlen, answer, DNS_RELAY_BUF_SIZE) : 0;
    if (rl > 0) {
        st_hits++;
        (void)tcp_write_msg(fd, answer, rl, deadline);
        goto done;
    }
    dns_relay_route_cb_t route = s_route_cb;
    uint32_t upstream = route ? route(w->q, qlen) : 0;
    if (!upstream) upstream = pick_upstream();
    if (!upstream || (up = tcp_connect(upstream, DNS_TCP_UPSTREAM_MS)) < 0) goto done;
    st_misses++;
    uint8_t client_id[2] = {w->q[0], w->q[1]};
    uint32_t up_id = esp_random();
    w->q[0] = (uint8_t)(up_id >> 8);
    w->q[1] = (uint8_t)up_id;
    if (!tcp_write_msg(up, w->q, qlen, deadline)) goto done;
    rl = tcp_read_msg(up, answer, DNS_TCP_MAX_ANSWER, deadline);
    if (rl < 12 || !dns_reply_matches(answer, rl, w->q, qlen)) goto done;
    answer[0] = client_id[0];
    answer[1] = client_id[1];
    (void)tcp_write_msg(fd, answer, rl, deadline);
done:
    if (up >= 0) close(up);
    close(fd);
    atomic_fetch_sub(&s_tcp_active, 1);
}

/* Each worker owns one upstream UDP socket so concurrent in-flight queries
 * never cross responses. A send/recv hard error rebuilds just this socket. */
static void worker_task(void *arg)
{
    (void)arg;
    int up = -1;
    /* One byte more than a cached answer (oversize detection); also the TCP
     * answer buffer. */
    uint8_t *rbuf = heap_caps_malloc(DNS_TCP_MAX_ANSWER, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    bool tcp_ok = rbuf != NULL;                       /* TCP answers need the PSRAM buffer */
    if (!rbuf) rbuf = malloc(DNS_RELAY_BUF_SIZE + 1);   /* fall back to internal, UDP only */
    if (!rbuf) { ESP_LOGE(TAG, "worker rbuf alloc failed"); task_reaper_self_delete(); }

    for (;;) {
        dns_work_t *w = NULL;
        if (xQueueReceive(s_workq, &w, portMAX_DELAY) != pdTRUE || !w) continue;
        if (w->tcp >= 0) {
            if (tcp_ok) tcp_serve(w, rbuf);
            else {close(w->tcp); atomic_fetch_sub(&s_tcp_active, 1);}
            heap_caps_free(w);
            continue;
        }

        if (up < 0) {
            up = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (up >= 0) {
                struct timeval to = {
                    .tv_sec  = DNS_RELAY_UP_TIMEOUT_MS / 1000,
                    .tv_usec = (DNS_RELAY_UP_TIMEOUT_MS % 1000) * 1000,
                };
                setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
            }
        }
        if (up < 0) { heap_caps_free(w); continue; }

        uint32_t upstream = w->upstream;
        if (w->cache_epoch != atomic_load(&s_cache_epoch)) {
            heap_caps_free(w);
            continue;
        }
        struct sockaddr_in up_addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(DNS_RELAY_PORT),
            .sin_addr.s_addr = upstream,
        };
        /* A fresh random ID per upstream query, whatever the client chose:
         * a forged answer has to guess it, the port and the question. */
        uint8_t client_id[2] = {w->q[0], w->q[1]};
        uint32_t up_id = esp_random();
        w->q[0] = (uint8_t)(up_id >> 8);
        w->q[1] = (uint8_t)up_id;
        /* Never invite an answer larger than the relay can take. */
        (void)dns_edns_clamp(w->q, w->qlen, DNS_RELAY_BUF_SIZE);
        int sent = -1;
        for (int attempt = 0; attempt < DNS_RELAY_TX_RETRIES; attempt++) {
            sent = sendto(up, w->q, w->qlen, 0, (struct sockaddr *)&up_addr, sizeof(up_addr));
            if (sent >= 0) break;
            /* ENOMEM/EAGAIN here is a transient WiFi TX-buffer shortage (the
             * DMA/cache TX pool is momentarily full under forwarding load), not
             * a socket error — the buffers free within a few ms. Back off and
             * retry rather than dropping the query: a dropped DNS query stalls
             * the client's "connecting..." for its full 1-5s resolver timeout.
             * Any other errno is a real socket fault → break and rebuild. */
            if (errno != ENOMEM && errno != EAGAIN && errno != EWOULDBLOCK) break;
            vTaskDelay(pdMS_TO_TICKS(DNS_RELAY_TX_RETRY_MS));
        }
        if (sent < 0) {
            ESP_LOGW(TAG, "upstream sendto() failed: errno=%d", errno);
            close(up); up = -1;
            heap_caps_free(w);
            continue;
        }
        int rlen = upstream_recv(up, rbuf, w->q, w->qlen, &up_addr);
        if (rlen <= 0) {
            if (rlen < 0) { close(up); up = -1; }
            heap_caps_free(w);
            continue;
        }
        if (w->cache_epoch != atomic_load(&s_cache_epoch)) {
            heap_caps_free(w);
            continue;
        }
        if (rlen > DNS_RELAY_BUF_SIZE) {
            /* A resolver that ignored the advertised size: pass a valid
             * truncated reply (the client retries over TCP), never a cut one. */
            st_truncated++;
            if ((rlen = dns_truncated_reply(rbuf, rlen, w->q, w->qlen)) <= 0) {heap_caps_free(w); continue;}
        }
        rbuf[0] = client_id[0];
        rbuf[1] = client_id[1];

        int ls = w->lan ? s_lan_sock : s_listen_sock;   /* listener-owned sockets */
        if (ls >= 0) {
            sendto(ls, rbuf, rlen, 0, (struct sockaddr *)&w->client, w->client_len);
        }

        /* Cache the answer if it's a cacheable standard query/response. */
        int kl = dns_is_std_query(w->q, w->qlen) ? dns_question_len(w->q, w->qlen) : 0;
        if (kl > 0) {
            uint32_t ttl = dns_resp_ttl(rbuf, rlen, kl);
            if (ttl) cache_put(w->q, kl, upstream, w->cache_epoch, rbuf, rlen, ttl);
        }
        heap_caps_free(w);
    }
}

/* ───────────────────── Listener ───────────────────── */

/* Captive-portal answer for first-boot setup: every A query resolves to the
 * setup AP address with a short TTL, any other type gets an empty NOERROR,
 * so phones and PCs open the setup page. Returns the response length, or 0
 * for anything that is not a single standard query (dropped). */
static int dns_captive_answer(const uint8_t *q, int qlen, uint32_t ip_nbo, uint8_t *out, int cap)
{
    if (!dns_is_std_query(q, qlen)) return 0;
    int ql = dns_question_len(q, qlen);
    if (ql <= 0) return 0;
    int end = 12 + ql;
    if (end + 16 > cap) return 0;
    memcpy(out, q, end);
    out[2] = 0x84 | (q[2] & 0x01);                    /* QR, AA, keep RD */
    out[3] = 0x80;                                    /* RA, NOERROR */
    out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
    uint16_t qtype = (uint16_t)(q[end - 4] << 8 | q[end - 3]);
    uint16_t qclass = (uint16_t)(q[end - 2] << 8 | q[end - 1]);
    if (qtype != 1 || qclass != 1) return end;
    out[7] = 1;                                       /* ANCOUNT = 1 */
    static const uint8_t rr[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4};
    memcpy(out + end, rr, sizeof rr);
    memcpy(out + end + sizeof rr, &ip_nbo, 4);
    return end + (int)sizeof rr + 4;
}


static void listener_task(void *arg)
{
    (void)arg;
    int listen_sock = -1, lan_sock = -1;
    /* TCP listeners follow their UDP socket: reopened with each new one. */
    int tcp_ap = -1, tcp_lan = -1;
    unsigned ap_gen = 0, lan_gen = 0, tcp_ap_gen = 0, tcp_lan_gen = 0;
    int64_t lan_retry_us = 0, tcp_retry_us = 0;
    uint8_t qbuf[DNS_RELAY_BUF_SIZE];
    uint8_t cbuf[DNS_RELAY_BUF_SIZE];      /* cache-hit response scratch */

    /* Settle delay before the first bind: the very first DNS relay we shipped
     * panicked at boot trying to bind 53/udp before WiFi drove lwIP. */
    vTaskDelay(pdMS_TO_TICKS(DNS_RELAY_BOOT_DELAY_MS));
    ESP_LOGI(TAG, "task started (enabled=%d, upstream override=0x%08x, cache=%s)",
             (int)s_enabled, (unsigned)s_upstream_nbo, s_cache ? "on" : "off");

    int bind_backoff_ms = 2000;
    for (;;) {
        bool want_listening = s_enabled && s_bind_nbo != 0;
        if (want_listening && (listen_sock < 0 || s_socket_dirty)) {
            if (listen_sock >= 0) { s_listen_sock = -1; close(listen_sock); listen_sock = -1; }
            listen_sock = open_listen_sock(s_bind_nbo);
            s_socket_dirty = false;
            if (listen_sock < 0) {
                s_healthy = false;
                vTaskDelay(pdMS_TO_TICKS(bind_backoff_ms));
                if (bind_backoff_ms < 30000) bind_backoff_ms *= 2;
                continue;
            }
            bind_backoff_ms = 2000;
            ap_gen++;
            s_listen_sock = listen_sock;
            bool was_healthy = s_healthy;
            s_healthy = true;
            if (!was_healthy) {
                ESP_LOGI(TAG, "first healthy transition — notifying softap dns reapply");
                notify_state(true);
            }
        } else if (!want_listening && listen_sock >= 0) {
            ESP_LOGI(TAG, "disabled — closing listen socket");
            s_listen_sock = -1;
            close(listen_sock);
            listen_sock = -1;
            bool was_healthy = s_healthy;
            s_healthy = false;
            if (was_healthy) notify_state(false);
        }

        if (listen_sock < 0) {
            s_healthy = false;
            if (lan_sock >= 0) {s_lan_sock = -1; close(lan_sock); lan_sock = -1;}
            if (tcp_ap >= 0) {close(tcp_ap); tcp_ap = -1;}
            if (tcp_lan >= 0) {close(tcp_lan); tcp_lan = -1;}
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        /* LAN listener: only while switched on and the uplink has an address. */
        bool want_lan = s_lan_on && s_lan_nbo != 0 && s_lan_nbo != s_bind_nbo && !s_captive_nbo;
        if (lan_sock >= 0 && (!want_lan || s_lan_dirty)) {s_lan_sock = -1; close(lan_sock); lan_sock = -1;}
        if (want_lan && lan_sock < 0 && esp_timer_get_time() >= lan_retry_us) {
            s_lan_dirty = false;
            lan_sock = open_listen_sock(s_lan_nbo);
            s_lan_sock = lan_sock;
            lan_gen++;
            if (lan_sock < 0) lan_retry_us = esp_timer_get_time() + 10LL * 1000000;
        }

        /* TCP next to each UDP listener (not during first-boot setup). */
        bool tcp_wanted = !s_captive_nbo;
        if (tcp_ap >= 0 && (!tcp_wanted || tcp_ap_gen != ap_gen)) {close(tcp_ap); tcp_ap = -1;}
        if (tcp_lan >= 0 && (!tcp_wanted || tcp_lan_gen != lan_gen || lan_sock < 0)) {close(tcp_lan); tcp_lan = -1;}
        if (tcp_wanted && (tcp_ap < 0 || (lan_sock >= 0 && tcp_lan < 0)) && esp_timer_get_time() >= tcp_retry_us) {
            if (tcp_ap < 0 && (tcp_ap = open_tcp_listen(s_bind_nbo)) >= 0) tcp_ap_gen = ap_gen;
            if (lan_sock >= 0 && tcp_lan < 0 && (tcp_lan = open_tcp_listen(s_lan_nbo)) >= 0) tcp_lan_gen = lan_gen;
            if (tcp_ap < 0 || (lan_sock >= 0 && tcp_lan < 0)) tcp_retry_us = esp_timer_get_time() + 10LL * 1000000;
        }

        fd_set ready;
        FD_ZERO(&ready);
        int top = listen_sock;
        int fds[] = {listen_sock, lan_sock, tcp_ap, tcp_lan};
        for (unsigned i = 0; i < sizeof fds / sizeof fds[0]; i++)
            if (fds[i] >= 0) {FD_SET(fds[i], &ready); if (fds[i] > top) top = fds[i];}
        struct timeval wait = {.tv_sec = 0, .tv_usec = 500 * 1000};
        if (select(top + 1, &ready, NULL, NULL, &wait) <= 0) continue;   /* timeout -> re-check state */
        if (tcp_ap >= 0 && FD_ISSET(tcp_ap, &ready)) tcp_accept(tcp_ap, false);
        if (tcp_lan >= 0 && FD_ISSET(tcp_lan, &ready)) tcp_accept(tcp_lan, true);
        int sock = FD_ISSET(listen_sock, &ready) ? listen_sock : lan_sock >= 0 && FD_ISSET(lan_sock, &ready) ? lan_sock : -1;
        if (sock < 0) continue;
        bool from_lan = sock == lan_sock;

        struct sockaddr_in client = {0};
        socklen_t client_len = sizeof(client);
        int qlen = recvfrom(sock, qbuf, sizeof(qbuf), 0,
                            (struct sockaddr *)&client, &client_len);
        if (qlen <= 0) continue;            /* timeout -> re-check enable state */

        st_queries++;

        uint32_t captive = s_captive_nbo;
        if (captive) {
            int rl = dns_captive_answer(qbuf, qlen, captive, cbuf, sizeof cbuf);
            if (rl > 0) sendto(sock, cbuf, rl, 0, (struct sockaddr *)&client, client_len);
            continue;
        }

        /* Local names (e.g. tailnet peers): answered here, never forwarded. */
        dns_relay_local_cb_t local = s_local_cb;
        if (local) {
            int rl = local(qbuf, qlen, cbuf, sizeof cbuf);
            if (rl > 0) {
                st_hits++;
                sendto(sock, cbuf, rl, 0, (struct sockaddr *)&client, client_len);
                continue;
            }
        }

        /* Select the resolver before checking the cache. A question may
         * have a different answer after a split-DNS or uplink change. */
        uint32_t epoch = atomic_load(&s_cache_epoch);
        dns_relay_route_cb_t route = s_route_cb;
        uint32_t upstream = route ? route(qbuf, qlen) : 0;
        if (!upstream) upstream = pick_upstream();
        if (!upstream) continue;
        int kl = dns_is_std_query(qbuf, qlen) ? dns_question_len(qbuf, qlen) : 0;
        if (kl > 0) {
            int rl = 0;
            if (cache_get(qbuf, kl, upstream, epoch, cbuf, &rl) &&
                epoch == atomic_load(&s_cache_epoch)) {
                st_hits++;
                sendto(sock, cbuf, rl, 0, (struct sockaddr *)&client, client_len);
                continue;
            }
        }

        /* Miss (or uncacheable): dispatch to a worker. */
        st_misses++;
        dns_work_t *w = heap_caps_malloc(sizeof(dns_work_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!w) continue;                   /* out of SPIRAM -> drop; client retries */
        w->client     = client;
        w->client_len = client_len;
        w->lan        = from_lan;
        w->upstream   = upstream;
        w->cache_epoch = epoch;
        w->tcp        = -1;
        w->qlen       = qlen;
        memcpy(w->q, qbuf, qlen);
        if (xQueueSend(s_workq, &w, 0) != pdTRUE) {
            heap_caps_free(w);              /* both workers busy + queue full -> drop */
        }
    }
}

/* ───────────────────── Public API ───────────────────── */

void dns_relay_init(void)
{
    if (s_listener) return;

    nvs_handle_t h;
    if (nvs_open(DNS_RELAY_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        uint8_t en = 1;
        if (nvs_get_u8(h, KEY_ENABLED, &en) != ESP_OK) en = 1;
        s_enabled = en != 0;

        char up_str[20] = {0};
        size_t len = sizeof(up_str);
        if (nvs_get_str(h, KEY_UPSTREAM, up_str, &len) == ESP_OK && up_str[0]) {
            ip4_addr_t a;
            if (ip4addr_aton(up_str, &a) && a.addr) s_upstream_nbo = a.addr;
        }
        nvs_close(h);
    } else {
        s_enabled = true;
    }

    /* SPIRAM response cache + hand-off queue. If SPIRAM is exhausted the relay
     * still works, just cache-less (cache_get/put degrade to no-ops). */
    s_cache = heap_caps_calloc(DNS_CACHE_ENTRIES, sizeof(dns_cache_entry_t),
                               MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_cache) ESP_LOGW(TAG, "SPIRAM cache alloc failed — running cache-less");
    s_cache_mtx = xSemaphoreCreateMutex();
    s_workq     = xQueueCreate(DNS_WORK_QUEUE_DEPTH, sizeof(dns_work_t *));
    if (!s_workq) { ESP_LOGE(TAG, "work queue alloc failed"); return; }

    /* Stacks in PSRAM (TCB stays internal): these tasks never touch SPI flash,
     * and XIP_FROM_PSRAM keeps the cache live during flash ops, so PSRAM stacks
     * are safe here. Frees ~13K internal DRAM for the WiFi DMA pools. */
    xTaskCreateWithCaps(listener_task, "dns_relay", DNS_LISTENER_STACK, NULL,
                        DNS_RELAY_TASK_PRIO, &s_listener, MALLOC_CAP_SPIRAM);
    for (int i = 0; i < DNS_WORKER_COUNT; i++) {
        xTaskCreateWithCaps(worker_task, "dns_worker", DNS_WORKER_STACK, NULL,
                            DNS_RELAY_TASK_PRIO, NULL, MALLOC_CAP_SPIRAM);
    }
}

void dns_relay_set_enabled(bool on)
{
    if (s_enabled == on) return;
    s_enabled = on;
    s_socket_dirty = true;

    nvs_handle_t h;
    if (nvs_open(DNS_RELAY_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, KEY_ENABLED, on ? 1 : 0);
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGI(TAG, "enabled=%d", (int)on);
}

bool dns_relay_is_enabled(void) { return s_enabled; }
bool dns_relay_is_healthy(void) { return s_healthy; }

void dns_relay_set_upstream(uint32_t ip_nbo)
{
    s_upstream_nbo = ip_nbo;

    nvs_handle_t h;
    if (nvs_open(DNS_RELAY_NVS_NS, NVS_READWRITE, &h) == ESP_OK) {
        if (ip_nbo == 0) {
            nvs_erase_key(h, KEY_UPSTREAM);
        } else {
            char buf[16];
            snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                     (int)( ip_nbo        & 0xFF),
                     (int)((ip_nbo >>  8) & 0xFF),
                     (int)((ip_nbo >> 16) & 0xFF),
                     (int)((ip_nbo >> 24) & 0xFF));
            nvs_set_str(h, KEY_UPSTREAM, buf);
        }
        nvs_commit(h);
        nvs_close(h);
    }
    ESP_LOGI(TAG, "upstream override=0x%08x", (unsigned)ip_nbo);
}

uint32_t dns_relay_get_upstream(void) { return s_upstream_nbo; }

void dns_relay_set_bind_addr(uint32_t ip_nbo)
{
    if (s_bind_nbo == ip_nbo) return;
    s_bind_nbo = ip_nbo;
    s_socket_dirty = true;
    ESP_LOGI(TAG, "bind addr changed to 0x%08x — rebinding", (unsigned)ip_nbo);
}

void dns_relay_get_stats(dns_relay_stats_t *out)
{
    if (!out) return;
    out->queries     = st_queries;
    out->hits        = st_hits;
    out->misses      = st_misses;
    out->inserts     = st_inserts;
    out->evictions   = st_evictions;
    out->stray       = st_stray;
    out->tcp         = st_tcp;
    out->truncated   = st_truncated;
    out->capacity    = DNS_CACHE_ENTRIES;
    out->cache_bytes = s_cache ? (uint32_t)(DNS_CACHE_ENTRIES * sizeof(dns_cache_entry_t)) : 0;
    out->enabled     = s_enabled ? 1 : 0;
    out->healthy     = s_healthy ? 1 : 0;

    uint32_t denom = st_hits + st_misses;
    out->hit_pct = denom ? (uint32_t)(((uint64_t)st_hits * 100) / denom) : 0;

    uint32_t used = 0;
    if (s_cache && s_cache_mtx) {
        int64_t now = esp_timer_get_time();
        xSemaphoreTake(s_cache_mtx, portMAX_DELAY);
        for (int i = 0; i < DNS_CACHE_ENTRIES; i++)
            if (s_cache[i].expiry_us > now) used++;
        xSemaphoreGive(s_cache_mtx);
    }
    out->entries = used;
}

void dns_relay_set_captive(uint32_t answer_ip_nbo)
{
    s_captive_nbo = answer_ip_nbo;
    ESP_LOGI(TAG, "captive portal answers %s", answer_ip_nbo ? "on" : "off");
}

void dns_relay_set_lan(bool on, uint32_t ip_nbo)
{
    if (s_lan_on == on && s_lan_nbo == ip_nbo) return;
    s_lan_on = on;
    s_lan_nbo = ip_nbo;
    s_lan_dirty = true;
    atomic_fetch_add(&s_cache_epoch, 1);
}

bool dns_relay_lan_listening(void) { return s_lan_sock >= 0; }

void dns_relay_set_local_resolver(dns_relay_local_cb_t cb) { s_local_cb = cb; }
void dns_relay_set_route(dns_relay_route_cb_t cb)
{
    s_route_cb = cb;
    atomic_fetch_add(&s_cache_epoch, 1);
}
