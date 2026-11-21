"""AP DNS relay upstream answers (actual dns_relay.c helpers) on the host.

Until 3.0.7-beta.11 a worker took the first datagram on its upstream socket
as the answer: a late answer to an earlier, timed-out query (or a forged
datagram from any host able to reach the port) was sent to the client and
cached under the new question. Checked with a scripted recvfrom():
- the matching answer from the server is accepted;
- other source address or port, other ID, a query (QR=0), other opcode,
  other question, QDCOUNT != 1, a short datagram: discarded, the right
  answer after them still accepted; ASCII case differences accepted;
- at most DNS_RELAY_MAX_STRAY strays per query, then no answer (bounded);
- timeout -> 0, socket error -> -1;
- dns_resp_ttl: short responses not cached, names ending in a compression
  pointer after labels parsed, min TTL clamped; every byte access bounds-
  checked over 200,000 random mutations;
- the worker sends a random ID upstream and restores the client's ID;
- the cache is two-way set-associative: two names of one set both stay, a
  third evicts the entry expiring first, a name is refreshed in place.

3.0.25 (answers above 1 KB reached clients cut, and were cached):
- the EDNS(0) payload size of a forwarded query is lowered to the relay's
  1024-byte buffer, other records untouched, a query without EDNS or with a
  smaller size unchanged, malformed queries left alone, bounds-checked;
- an answer longer than the buffer is detected (one byte of headroom) and
  turned into a valid truncated reply: header and question, TC set, no
  records; truncated (TC) answers are never cached;
- DNS over TCP: length-prefixed messages read across partial segments,
  over-long or short lengths refused, a silent client bounded by the
  deadline, the reply written with its length prefix.
- tcp_serve (actual): a query over TCP is asked upstream over UDP with a
  4 KB answer buffer first; an answer above 4 KB comes back whole over TCP (home routers often refuse DNS over TCP, found on
  board A with 3.0.25-beta.10) and the whole answer goes back with the
  client's ID, no TCP connection to the resolver; a truncated UDP answer
  falls back to TCP; local (tailnet) names are answered without upstream;
  the connection is always closed and the TCP slot released.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'components/dns_relay/dns_relay.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(signature):
    start = source.index(signature)
    return source[start:source.index('\n}\n', start) + 3]


worker = function('static void worker_task(void *arg)')
assert 'uint32_t up_id = esp_random();' in worker and 'rbuf[0] = client_id[0];' in worker
assert 'recvfrom(up, rbuf, DNS_RELAY_BUF_SIZE, 0, NULL, NULL)' not in source
assert 'upstream_recv(up, rbuf, DNS_RELAY_BUF_SIZE + 1, w->q, w->qlen, &up_addr)' in worker
assert '(void)dns_edns_clamp(qbuf, qlen, DNS_RELAY_BUF_SIZE);' in function('static void listener_task(')
assert 'dns_truncated_reply(rbuf, rlen, w->q, w->qlen)' in worker

helpers = (function('static int dns_question_len(') + function('static int dns_skip_name(')
           + function('static bool dns_edns_clamp(') + function('static int dns_truncated_reply(')
           + function('static bool dns_is_std_query(') + function('static int dns_cache_key_len(')
           + function('static uint32_t dns_read_u32(') + function('static uint32_t dns_resp_ttl(')
           + function('static bool dns_reply_matches(') + function('static int upstream_recv('))
checked = re.sub(r'\bp\[([^\]]+)\]', r'AT(\1)', helpers)
tcp_helpers = function('static bool tcp_all(') + function('static int tcp_read_msg(') + function('static bool tcp_write_msg(')
cache_decl = source.split('/* ---- SPIRAM direct-mapped response cache ---- */', 1)[1].split('static atomic_uint s_cache_epoch;', 1)[0]
cache_helpers = (cache_decl + function('static uint32_t fnv1a(') + '#define DNS_CACHE_WAYS 2\n' + function('static uint32_t cache_set(')
                 + function('static bool cache_same_key(') + function('static bool cache_get(') + function('static void cache_put('))

PROGRAM = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DNS_RELAY_BUF_SIZE 1024
#define DNS_CACHE_KEY_MAX 256
#define DNS_CACHE_ENTRIES 4
#define DNS_CACHE_TTL_NEG_S 30
#define DNS_CACHE_TTL_MIN_S 10
#define DNS_CACHE_TTL_MAX_S 3600
#define DNS_RELAY_MAX_STRAY 8
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
typedef unsigned socklen_t;
struct in_addr_ { uint32_t s_addr; };
struct sockaddr { int x; };
struct sockaddr_in { uint16_t sin_family; uint16_t sin_port; struct in_addr_ sin_addr; };
static volatile uint32_t st_stray;
static size_t cur_len; static const uint8_t *cur_p;
static uint8_t at_(const uint8_t *p, int i) {
    if (p == cur_p && (i < 0 || (size_t)i >= cur_len)) { printf("OOB %d of %u\n", i, (unsigned)cur_len); exit(3); }
    return p[i];
}
#define AT(i) at_(p, (int)(i))
/* scripted upstream socket */
typedef struct { uint8_t d[1600]; int len; uint32_t ip; uint16_t port; int err; } dgram_t;
static dgram_t script[32]; static int nscript, spos;
static int recvfrom(int s, void *buf, size_t cap, int fl, struct sockaddr *from, socklen_t *fl_) {
    (void)s; (void)fl; (void)fl_;
    if (spos >= nscript) { errno = EAGAIN; return -1; }
    dgram_t *d = &script[spos++];
    if (d->err) { errno = d->err; return -1; }
    struct sockaddr_in *f = (struct sockaddr_in *)from; f->sin_addr.s_addr = d->ip; f->sin_port = d->port;
    int n = d->len < (int)cap ? d->len : (int)cap; memcpy(buf, d->d, n); return n;
}
@@HELPERS@@
typedef void *SemaphoreHandle_t;
#define portMAX_DELAY 0
#define xSemaphoreTake(mutex, ticks) ((void)(mutex), (void)(ticks))
#define xSemaphoreGive(mutex) ((void)(mutex))
static int64_t now_us = 1000000;
static int64_t esp_timer_get_time(void) { return now_us; }
/* scripted TCP peer: recv hands out chunks, send collects */
static const uint8_t *tcp_in; static int tcp_in_len, tcp_in_pos, tcp_chunk, tcp_silent;
static uint8_t tcp_out[8192]; static int tcp_out_len;
static int recv(int fd, void *buf, size_t n, int fl) {
    (void)fd; (void)fl;
    if (tcp_in_pos >= tcp_in_len) { if (tcp_silent) { now_us += 100000; errno = EAGAIN; return -1; } return 0; }
    int k = tcp_in_len - tcp_in_pos; if (k > (int)n) k = (int)n; if (k > tcp_chunk) k = tcp_chunk;
    memcpy(buf, tcp_in + tcp_in_pos, k); tcp_in_pos += k; return k;
}
static int send(int fd, const void *buf, size_t n, int fl) {
    (void)fd; (void)fl; int k = n > 3 ? 3 : (int)n;    /* partial writes */
    memcpy(tcp_out + tcp_out_len, buf, k); tcp_out_len += k; return k;
}
@@TCP@@
static uint32_t st_inserts, st_evictions;
@@CACHE@@
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
static uint8_t q[128]; static int qlen;
static uint8_t r[1600]; static int rlen;
static void build_q(uint16_t id, const char *name) {
    q[0] = id >> 8; q[1] = id; q[2] = 0x01; q[3] = 0; q[4] = 0; q[5] = 1; memset(q + 6, 0, 6); qlen = 12;
    const char *s = name;
    while (*s) { const char *dot = strchr(s, '.'); int l = dot ? (int)(dot - s) : (int)strlen(s);
        q[qlen++] = (uint8_t)l; memcpy(q + qlen, s, l); qlen += l; s += l; if (*s) s++; }
    q[qlen++] = 0; q[qlen++] = 0; q[qlen++] = 1; q[qlen++] = 0; q[qlen++] = 1;
}
static void build_r(uint32_t ttl) {           /* answer to q: one A record via pointer */
    memcpy(r, q, qlen); r[2] = 0x81; r[3] = 0x80; r[7] = 1; rlen = qlen;
    uint8_t rr[] = {0xC0, 0x0C, 0, 1, 0, 1, ttl >> 24, ttl >> 16, ttl >> 8, ttl, 0, 4, 192, 0, 2, 1};
    memcpy(r + rlen, rr, sizeof rr); rlen += sizeof rr;
}
static void store_response(const uint8_t *query, int len, uint32_t upstream, uint32_t ttl)
{
    memcpy(q, query, len); qlen = len;
    build_r(ttl);
    cache_put(q, dns_cache_key_len(q, qlen), upstream, 1, r, rlen, ttl);
}
static void add(const uint8_t *d, int len, uint32_t ip, uint16_t port) {
    dgram_t *g = &script[nscript++]; memcpy(g->d, d, len); g->len = len; g->ip = ip; g->port = port; g->err = 0;
}
static int recv_now(uint8_t *buf) { struct sockaddr_in srv = {2, 53, {0x0101A8C0}}; return upstream_recv(1, buf, DNS_RELAY_BUF_SIZE + 1, q, qlen, &srv); }
int main(void) {
    uint8_t buf[DNS_RELAY_BUF_SIZE + 1];
    const uint32_t SRV = 0x0101A8C0; const uint16_t P53 = 53;
    build_q(0xBEEF, "www.example.com"); build_r(300);
    dns_cache_entry_t entries[DNS_CACHE_ENTRIES] = {0};
    s_cache = entries;
    s_cache_mtx = entries;
    int key_len = dns_cache_key_len(q, qlen), cached_len = 0;
    CHECK(key_len == qlen - 2);
    cache_put(q, key_len, SRV, 1, r, rlen, 300);
    CHECK(cache_get(q, key_len, SRV, 1, buf, &cached_len) && cached_len == rlen);
    now_us += 3000001;
    CHECK(cache_get(q, key_len, SRV, 1, buf, &cached_len));
    CHECK(dns_read_u32(buf + qlen + 6) == 296 && buf[0] == 0xBE && buf[1] == 0xEF);
    now_us += 296999999;
    CHECK(!cache_get(q, key_len, SRV, 1, buf, &cached_len));
    now_us = 1000000;
    CHECK(!cache_get(q, key_len, SRV + 1, 1, buf, &cached_len));
    CHECK(!cache_get(q, key_len, SRV, 2, buf, &cached_len));
    q[3] = 0x10; /* checking disabled */
    CHECK(!cache_get(q, key_len, SRV, 1, buf, &cached_len));
    q[3] = 0;
    q[1] = 0xED;
    CHECK(cache_get(q, key_len, SRV, 1, buf, &cached_len) && buf[1] == 0xED);
    {
        const uint8_t opt[] = {0, 0, 41, 4, 0, 0, 0, 0, 0, 0, 0};
        int question_end = qlen;
        memcpy(q + qlen, opt, sizeof opt); qlen += sizeof opt; q[11] = 1;
        int edns_key = dns_cache_key_len(q, qlen);
        CHECK(edns_key == qlen - 2 && !cache_get(q, edns_key, SRV, 1, buf, &cached_len));
        cache_put(q, edns_key, SRV, 1, r, rlen, 300);
        CHECK(cache_get(q, edns_key, SRV, 1, buf, &cached_len));
        q[question_end + 7] = 0x80;  /* DNSSEC OK */
        CHECK(!cache_get(q, edns_key, SRV, 1, buf, &cached_len));
        q[question_end + 7] = 0;
        q[question_end + 3] = 2;     /* different advertised UDP size */
        CHECK(!cache_get(q, edns_key, SRV, 1, buf, &cached_len));
        q[question_end + 6] = 1;     /* unsupported EDNS version */
        CHECK(dns_cache_key_len(q, qlen) == 0);
        q[question_end + 6] = 0;
        q[qlen - 1] = 4; memset(q + qlen, 0, 4);
        CHECK(dns_cache_key_len(q, qlen + 4) == 0);
    }
    /* Two-way sets: two names of the same set both stay; a third evicts the
     * one expiring first; the same name is updated in place. */
    {
        memset(entries, 0, sizeof entries);
        uint8_t qa[64], qb[64], qc[64]; int la = 0, lb = 0, lc = 0; char nm[32]; int found = 0;
        uint32_t want = 0;
        for (int i = 0; i < 2000 && found < 3; i++) {
            snprintf(nm, sizeof nm, "host%d.example", i); build_q(1, nm);
            if (found == 0) want = cache_set(q, qlen - 2);
            if (cache_set(q, qlen - 2) != want) continue;
            if (found == 0) {memcpy(qa, q, qlen); la = qlen;} else if (found == 1) {memcpy(qb, q, qlen); lb = qlen;} else {memcpy(qc, q, qlen); lc = qlen;}
            found++;
        }
        CHECK(found == 3);
        store_response(qa, la, SRV, 300);
        now_us += 1000000;
        store_response(qb, lb, SRV, 300);
        int n = 0;
        CHECK(cache_get(qa, la - 2, SRV, 1, buf, &n) && cache_get(qb, lb - 2, SRV, 1, buf, &n));
        store_response(qa, la, SRV, 600);                             /* same name: in place */
        CHECK(cache_get(qb, lb - 2, SRV, 1, buf, &n));
        store_response(qc, lc, SRV, 300);                             /* b expires first: b goes */
        CHECK(cache_get(qa, la - 2, SRV, 1, buf, &n) && cache_get(qc, lc - 2, SRV, 1, buf, &n) && !cache_get(qb, lb - 2, SRV, 1, buf, &n));
        now_us = 1000000;
        build_q(0xBEEF, "www.example.com"); build_r(300);
    }

    nscript = spos = 0; add(r, rlen, SRV, P53);
    CHECK(recv_now(buf) == rlen && memcmp(buf, r, rlen) == 0);

    /* strays first, then the answer */
    uint8_t bad[600]; st_stray = 0; nscript = spos = 0;
    add(r, rlen, 0x0201A8C0, P53);                                   /* other host */
    add(r, rlen, SRV, 5353);                                         /* other port */
    memcpy(bad, r, rlen); bad[1] ^= 1; add(bad, rlen, SRV, P53);     /* other ID (late answer) */
    memcpy(bad, r, rlen); bad[2] &= 0x7F; add(bad, rlen, SRV, P53);  /* not a response */
    memcpy(bad, r, rlen); bad[2] |= 0x10; add(bad, rlen, SRV, P53);  /* other opcode */
    memcpy(bad, r, rlen); bad[14] = 'x'; add(bad, rlen, SRV, P53);   /* other question */
    memcpy(bad, r, rlen); bad[5] = 2; add(bad, rlen, SRV, P53);      /* QDCOUNT 2 */
    add(r, 11, SRV, P53);                                            /* short */
    add(r, 20, SRV, P53);                                            /* question truncated */
    CHECK(recv_now(buf) == 0 && st_stray == 9);                      /* bounded: 9 strays, no answer */
    st_stray = 0; spos = 1;                                          /* from the 2nd stray: 8 strays then answer */
    script[9] = script[0]; script[9].ip = SRV; nscript = 10;
    CHECK(recv_now(buf) == rlen && st_stray == 8);

    /* 0x20 case randomisation by the resolver */
    nscript = spos = 0; memcpy(bad, r, rlen); bad[13] = 'W'; bad[18] = 'X'; add(bad, rlen, SRV, P53);
    CHECK(recv_now(buf) == rlen);

    /* timeout and socket error */
    nscript = spos = 0; CHECK(recv_now(buf) == 0);
    nscript = 1; spos = 0; script[0].err = EBADF; CHECK(recv_now(buf) == -1); script[0].err = 0;

    /* TTL parsing */
    int ql = dns_question_len(q, qlen); CHECK(ql == qlen - 12);
    cur_p = r; cur_len = rlen;
    CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == 300);
    build_r(2); CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == 2);
    build_r(0); CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == 0);
    build_r(999999); CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == DNS_CACHE_TTL_MAX_S);
    cur_len = 11; CHECK(dns_resp_ttl(r, 11, ql, NULL, 0) == 0);
    /* answer name "a" + pointer: labels then compression */
    build_r(300); { int at = qlen; uint8_t nm[] = {1, 'a', 0xC0, 0x0C}; memmove(r + at + 4, r + at + 2, rlen - at - 2);
        memcpy(r + at, nm, 4); rlen += 2; }
    cur_len = rlen; CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == 300);

    /* TC answers are not cached */
    build_r(300); r[2] |= 0x02; cur_p = r; cur_len = rlen; CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == 0);

    /* NXDOMAIN needs an SOA; use its MINIMUM and preserve OPT's flags. */
    memcpy(r, q, qlen); r[2] = 0x81; r[3] = 0x83; rlen = qlen;
    cur_len = rlen; CHECK(dns_resp_ttl(r, rlen, ql, NULL, 0) == 0);
    uint8_t soa[36] = {0xC0, 0x0C, 0, 6, 0, 1, 0, 0, 0, 60, 0, 24, 0xC0, 0x0C, 0xC0, 0x0C};
    soa[35] = 7;
    const uint8_t flags_opt[] = {0, 0, 41, 4, 0, 0, 0, 0x80, 0, 0, 0};
    r[9] = r[11] = 1;
    memcpy(r + rlen, soa, sizeof soa); rlen += sizeof soa;
    memcpy(r + rlen, flags_opt, sizeof flags_opt); rlen += sizeof flags_opt;
    cur_len = rlen; memcpy(buf, r, rlen);
    CHECK(dns_resp_ttl(r, rlen, ql, buf, 2) == 7 && dns_read_u32(buf + qlen + 6) == 5);
    CHECK(memcmp(buf + qlen + sizeof soa, flags_opt, sizeof flags_opt) == 0);
    CHECK(dns_resp_ttl(r, rlen - 1, ql, NULL, 0) == 0);

    /* EDNS clamp: OPT RR in the additional section */
    build_q(0x1234, "big.example.com");
    { uint8_t opt[] = {0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0}; memcpy(q + qlen, opt, sizeof opt); qlen += sizeof opt; q[11] = 1; }
    uint8_t keep[128]; memcpy(keep, q, qlen);
    cur_p = q; cur_len = qlen;
    CHECK(dns_edns_clamp(q, qlen, 1024) && q[qlen - 8] == 0x04 && q[qlen - 7] == 0x00);
    CHECK(memcmp(q, keep, qlen - 8) == 0 && memcmp(q + qlen - 6, keep + qlen - 6, 6) == 0);   /* only the size changed */
    memcpy(q, keep, qlen); q[qlen - 8] = 0x02; q[qlen - 7] = 0x00;                             /* 512: unchanged */
    CHECK(dns_edns_clamp(q, qlen, 1024) && q[qlen - 8] == 0x02 && q[qlen - 7] == 0x00);
    build_q(0x1234, "plain.example.com"); memcpy(keep, q, qlen); cur_p = q; cur_len = qlen;
    CHECK(dns_edns_clamp(q, qlen, 1024) && memcmp(q, keep, qlen) == 0);                        /* no EDNS */
    q[11] = 1; CHECK(!dns_edns_clamp(q, qlen, 1024));                                          /* ARCOUNT 1, no record */
    build_q(0x1234, "big.example.com");
    { uint8_t ans[] = {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 9, 0, 4, 1, 2, 3, 4, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0};
      memcpy(q + qlen, ans, sizeof ans); qlen += sizeof ans; q[7] = 1; q[11] = 1; }               /* an answer RR, then OPT */
    cur_p = q; cur_len = qlen;
    CHECK(dns_edns_clamp(q, qlen, 1024) && q[qlen - 8] == 0x04 && q[qlen - 7] == 0x00);
    { uint8_t base2[128]; int b2 = qlen; memcpy(base2, q, qlen); uint32_t sd = 7;
      for (int it = 0; it < 100000; it++) {
          memcpy(q, base2, b2);
          for (int j = 0; j < 1 + it % 3; j++) { sd = sd * 1664525u + 1013904223u; q[4 + (sd >> 8) % (b2 - 4)] = (uint8_t)(sd >> 3); }
          sd = sd * 1664525u + 1013904223u; int len = (sd & 1) ? b2 : (int)(sd >> 8) % (b2 + 1);
          uint8_t *heap = malloc(len ? len : 1); memcpy(heap, q, len); cur_p = heap; cur_len = (size_t)len;
          (void)dns_edns_clamp(heap, len, 1024); free(heap);
      } }

    /* Oversized answer: detected with one byte of headroom, made a TC reply */
    build_q(0xBEEF, "www.example.com"); build_r(300);
    { int big = 1500; memset(r + rlen, 0x41, big - rlen); rlen = big; }
    nscript = spos = 0; add(r, rlen, SRV, P53);
    int got = recv_now(buf);
    CHECK(got == DNS_RELAY_BUF_SIZE + 1);
    int tl = dns_truncated_reply(buf, got, q, qlen);
    CHECK(tl == qlen && (buf[2] & 0x02) && buf[7] == 0 && buf[9] == 0 && buf[11] == 0 && buf[5] == 1);
    CHECK(memcmp(buf + 12, q + 12, qlen - 12) == 0 && (buf[2] & 0x80));
    cur_p = buf; cur_len = tl; CHECK(dns_resp_ttl(buf, tl, ql, NULL, 0) == 0);                 /* not cached */
    CHECK(dns_truncated_reply(buf, 11, q, qlen) == 0);

    /* DNS over TCP framing */
    { uint8_t msg[2 + 40], in[64]; msg[0] = 0; msg[1] = 40; for (int i = 0; i < 40; i++) msg[2 + i] = (uint8_t)i;
      tcp_in = msg; tcp_in_len = 42; tcp_in_pos = 0; tcp_chunk = 5; tcp_silent = 0;
      CHECK(tcp_read_msg(3, in, sizeof in, now_us + 1000000) == 40 && memcmp(in, msg + 2, 40) == 0);
      tcp_in_pos = 0; CHECK(tcp_read_msg(3, in, 39, now_us + 1000000) == -1);                 /* longer than the buffer */
      msg[1] = 11; tcp_in_pos = 0; CHECK(tcp_read_msg(3, in, sizeof in, now_us + 1000000) == -1);   /* shorter than a header */
      msg[1] = 40; tcp_in_len = 20; tcp_in_pos = 0; tcp_silent = 1;                            /* stalls mid-message */
      int64_t t0 = now_us; CHECK(tcp_read_msg(3, in, sizeof in, now_us + 1000000) == -1 && now_us - t0 <= 1100000);
      tcp_silent = 0; tcp_in_pos = 0; CHECK(tcp_read_msg(3, in, sizeof in, now_us + 1000000) == -1);   /* peer closed */
      tcp_out_len = 0; CHECK(tcp_write_msg(3, msg + 2, 40, now_us + 1000000) && tcp_out_len == 42 && tcp_out[0] == 0 && tcp_out[1] == 40
                             && memcmp(tcp_out + 2, msg + 2, 40) == 0);
      CHECK(!tcp_write_msg(3, msg, 0, now_us + 1000000)); }

    /* random mutations: no out-of-bounds access */
    build_r(300); uint8_t base[600]; int blen = rlen; memcpy(base, r, rlen);
    uint32_t seed = 0xD15EA5E;
    for (int it = 0; it < 200000; it++) {
        memcpy(r, base, blen); rlen = blen;
        for (int j = 0; j < 1 + it % 4; j++) { seed = seed * 1664525u + 1013904223u; r[12 + (seed >> 8) % (blen - 12)] = (uint8_t)(seed >> 2); }
        seed = seed * 1664525u + 1013904223u; int len = (seed & 1) ? blen : (int)(seed >> 8) % (blen + 1);
        uint8_t *heap = malloc(len ? len : 1); memcpy(heap, r, len);
        cur_p = heap; cur_len = (size_t)len;
        (void)dns_resp_ttl(heap, len, ql, NULL, 0);
        (void)dns_reply_matches(heap, len, q, qlen);
        (void)dns_question_len(heap, len);
        free(heap);
    }
    puts("dns relay upstream ok");
    return 0;
}
'''


def run(code, cache=None):
    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / 'relay.c'
        c.write_text(PROGRAM.replace('@@HELPERS@@', code).replace('@@CACHE@@', cache if cache is not None else cache_helpers).replace('@@TCP@@', tcp_helpers), encoding='utf-8')
        exe = Path(tmp) / ('relay.exe' if os.name == 'nt' else 'relay')
        subprocess.run(['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-unused-variable', str(c), '-o', str(exe)], check=True)
        return subprocess.run([str(exe)], capture_output=True, text=True)


ok = run(checked)
assert ok.returncode == 0 and 'dns relay upstream ok' in ok.stdout, (ok.returncode, ok.stdout, ok.stderr)
# The pre-fix behaviour: the first datagram is the answer.
mutant = checked.replace('dns_reply_matches(rbuf, rlen, q, qlen))', 'true)').replace(
    'from.sin_addr.s_addr == server->sin_addr.s_addr && from.sin_port == server->sin_port &&', '')
assert mutant != checked
bad = run(mutant)
assert bad.returncode != 0, 'accepting the first datagram must fail'
print('dns relay upstream: only matching answers accepted, bounded, TTL parser in bounds')
# Pre-3.0.25 behaviour: no EDNS clamp, TC answers cached.
for old, new in (('type == 41 && size > max', 'type == 41 && size > max && !rrs && rrs'),
                 ('if (AT(2) & 0x02) return 0;', ''),
                 ('r[4] << 8) | r[5]) != 1) return 0;', 'r[4] << 8) | r[5]) != 1) return rlen;'),
                 ('w < DNS_CACHE_WAYS && !hit', 'w < 1 && !hit')):
    target = checked if old in checked else None
    if target is None:
        assert old in cache_helpers, old
        bad = run(checked, cache_helpers.replace(old, new))
    else:
        bad = run(checked.replace(old, new))
    assert bad.returncode != 0, 'mutant survived: ' + old
print('dns relay 3.0.25: EDNS size clamped, oversized answers made truncated replies, TC not cached, TCP framing bounded')

# ---- tcp_serve against scripted sockets ----
serve_code = (function('static int dns_question_len(') + function('static int dns_skip_name(') + function('static bool dns_edns_clamp(')
              + function('static bool dns_reply_matches(') + function('static int upstream_recv(') + function('static bool tcp_all(')
              + function('static int tcp_read_msg(') + function('static bool tcp_write_msg(') + function('static void tcp_timeouts(')
              + function('static int tcp_connect(') + function('static int udp_ask(') + function('static void tcp_serve('))
SERVE = r"""
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DNS_RELAY_PORT 53
#define DNS_RELAY_BUF_SIZE 1024
#define DNS_CACHE_KEY_MAX 256
#define DNS_RELAY_MAX_STRAY 8
#define DNS_TCP_MAX_ANSWER 16384
#define DNS_UDP_LARGE_ANSWER 4096
#define DNS_TCP_CLIENT_MS 1500
#define DNS_TCP_UPSTREAM_MS 3500
#define AF_INET 2
#define SOCK_DGRAM 2
#define SOCK_STREAM 1
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6
#define SOL_SOCKET 1
#define SO_RCVTIMEO 2
#define SO_SNDTIMEO 3
#define SO_ERROR 4
#define F_GETFL 3
#define F_SETFL 4
#define O_NONBLOCK 1
#ifndef EINPROGRESS
#define EINPROGRESS 115
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif
/* Stand-ins for the lwIP socket API; renamed so they never clash with what
 * glibc already declares under gnu11 (stdlib.h pulls in sys/select.h). */
#define socklen_t test_socklen_t
#define fd_set test_fd_set
#define select test_select
#define close test_close
#define connect test_connect
#define fcntl test_fcntl
#define getsockopt test_getsockopt
#define setsockopt test_setsockopt
#define recv test_recv
#define recvfrom test_recvfrom
#define send test_send
#define sendto test_sendto
#define socket test_socket
#undef FD_ZERO
#undef FD_SET
typedef unsigned socklen_t;
#define timeval test_timeval
struct timeval {long tv_sec, tv_usec;};
struct in_addr_ {uint32_t s_addr;};
struct sockaddr {int x;};
struct sockaddr_in {uint16_t sin_family; uint16_t sin_port; struct in_addr_ sin_addr;};
typedef struct {int n;} fd_set;
#define FD_ZERO(s) ((s)->n = 0)
#define FD_SET(f, s) ((s)->n = (f))
static uint16_t htons(uint16_t v) {return (uint16_t)(v << 8 | v >> 8);}
static volatile uint32_t st_stray, st_queries, st_tcp, st_hits, st_misses;
static atomic_int s_tcp_active;
static atomic_uint s_cache_epoch;
static bool change_epoch_on_udp, change_epoch_on_tcp;
static volatile uint32_t s_captive_nbo;
typedef int (*dns_relay_local_cb_t)(const uint8_t *q, int len, uint8_t *out, int cap);
typedef uint32_t (*dns_relay_route_cb_t)(const uint8_t *q, int len);
static volatile dns_relay_local_cb_t s_local_cb;
static volatile dns_relay_route_cb_t s_route_cb;
static uint32_t pick_upstream(void) {return 0x0101A8C0;}
static uint32_t esp_random(void) {return 0xA5A5;}
static int64_t now_us = 1000000;
static int64_t esp_timer_get_time(void) {return now_us += 1000;}
/* fd 3: client TCP; fd 7: upstream UDP; fd 9: upstream TCP */
static uint8_t client_in[600]; static int client_in_len, client_in_pos;
static uint8_t client_out[20000]; static int client_out_len;
static uint8_t udp_answer[5000]; static int udp_answer_len;
static int tcp_connects, closes, udp_sends;
static uint8_t last_udp_query[600]; static int last_udp_len;
static int socket(int d, int type, int p) {(void)d; (void)p; return type == SOCK_DGRAM ? 7 : 9;}
static int setsockopt(int f, int l, int o, const void *v, socklen_t n) {(void)f; (void)l; (void)o; (void)v; (void)n; return 0;}
static int getsockopt(int f, int l, int o, void *v, socklen_t *n) {(void)f; (void)l; (void)o; (void)n; *(int *)v = 0; return 0;}
static int fcntl(int f, int c, int v) {(void)f; (void)c; (void)v; return 0;}
static int tcp_connect_ok, tcp_answer_size, up_sent;
static uint8_t up_query[600]; static int up_query_len; static uint8_t up_reply[20000]; static int up_reply_len, up_reply_pos;
static int connect(int f, const struct sockaddr *a, socklen_t n) {(void)f; (void)a; (void)n; tcp_connects++; if (tcp_connect_ok) {errno = EINPROGRESS; return -1;} errno = 111; return -1;}
static int select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *t) {(void)n; (void)r; (void)w; (void)e; (void)t; return tcp_connect_ok ? 1 : 0;}
static int close(int f) {(void)f; closes++; return 0;}
static int sendto(int f, const void *b, size_t n, int fl, const struct sockaddr *a, socklen_t l)
{(void)f; (void)fl; (void)a; (void)l; udp_sends++; memcpy(last_udp_query, b, n); last_udp_len = (int)n; return (int)n;}
static int recvfrom(int f, void *b, size_t cap, int fl, struct sockaddr *from, socklen_t *fl_)
{
    (void)f; (void)fl; (void)fl_;
    if (!udp_answer_len) {errno = EAGAIN; return -1;}
    int n = udp_answer_len < (int)cap ? udp_answer_len : (int)cap;
    memcpy(b, udp_answer, (size_t)n);
    udp_answer[0] = last_udp_query[0]; udp_answer[1] = last_udp_query[1];   /* the resolver echoes our ID */
    memcpy(b, udp_answer, 2);
    struct sockaddr_in *s = (struct sockaddr_in *)from; s->sin_addr.s_addr = 0x0101A8C0; s->sin_port = htons(53);
    udp_answer_len = 0;
    if (change_epoch_on_udp) atomic_fetch_add(&s_cache_epoch, 1);
    return n;
}
static int recv(int f, void *b, size_t n, int fl)
{
    (void)fl;
    if (f == 9) {                                         /* the resolver over TCP */
        if (!up_reply_len) {
            int q = up_query_len - 2; uint8_t *m = up_reply + 2;
            memcpy(m, up_query + 2, (size_t)q); m[2] = 0x81; m[3] = 0x80; m[7] = 1; m[11] = 0;
            int len = q - 11; while (len < tcp_answer_size) m[len++] = 'y';
            up_reply[0] = (uint8_t)(len >> 8); up_reply[1] = (uint8_t)len; up_reply_len = len + 2; up_reply_pos = 0;
        }
        if (up_reply_pos >= up_reply_len) return 0;
        int k = up_reply_len - up_reply_pos; if (k > (int)n) k = (int)n; if (k > 1460) k = 1460;
        memcpy(b, up_reply + up_reply_pos, (size_t)k); up_reply_pos += k;
        if (change_epoch_on_tcp) atomic_fetch_add(&s_cache_epoch, 1);
        return k;
    }
    if (f != 3) {errno = EBADF; return -1;}
    if (client_in_pos >= client_in_len) return 0;
    int k = client_in_len - client_in_pos; if (k > (int)n) k = (int)n;
    memcpy(b, client_in + client_in_pos, (size_t)k); client_in_pos += k; return k;
}
static int send(int f, const void *b, size_t n, int fl)
{
    (void)fl;
    if (f == 9) {memcpy(up_query + up_query_len, b, n); up_query_len += (int)n; up_reply_len = 0; return (int)n;}
    if (f != 3) return -1;
    memcpy(client_out + client_out_len, b, n); client_out_len += (int)n; return (int)n;
}
typedef struct {int tcp; int qlen; uint32_t cache_epoch; uint8_t q[DNS_RELAY_BUF_SIZE];} dns_work_t;
@@SERVE@@
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d\n", __LINE__); return 1; } } while (0)
static uint8_t q[128]; static int qlen;
static void build(uint16_t id, const char *name)
{
    q[0] = (uint8_t)(id >> 8); q[1] = (uint8_t)id; q[2] = 1; q[3] = 0; q[4] = 0; q[5] = 1; memset(q + 6, 0, 6); q[11] = 1; qlen = 12;
    for (const char *s = name; *s;) {const char *d = strchr(s, '.'); int l = d ? (int)(d - s) : (int)strlen(s);
        q[qlen++] = (uint8_t)l; memcpy(q + qlen, s, (size_t)l); qlen += l; s += l; if (*s) s++;}
    q[qlen++] = 0; q[qlen++] = 0; q[qlen++] = 16; q[qlen++] = 0; q[qlen++] = 1;
    uint8_t opt[] = {0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0}; memcpy(q + qlen, opt, sizeof opt); qlen += sizeof opt;
    client_in[0] = (uint8_t)(qlen >> 8); client_in[1] = (uint8_t)qlen; memcpy(client_in + 2, q, (size_t)qlen);
    client_in_len = qlen + 2; client_in_pos = 0; client_out_len = 0; up_query_len = 0; up_reply_len = 0;
}
static void answer_of(int size, bool tc)
{
    memcpy(udp_answer, q, (size_t)qlen - 11); udp_answer_len = qlen - 11;      /* header + question */
    udp_answer[2] = (uint8_t)(0x81 | (tc ? 0x02 : 0)); udp_answer[3] = 0x80; udp_answer[7] = 1; udp_answer[11] = 0;
    while (udp_answer_len < size) udp_answer[udp_answer_len++] = 'x';
}
static int local_name(const uint8_t *qq, int len, uint8_t *out, int cap) {(void)cap; memcpy(out, qq, (size_t)len); out[2] = 0x84; return len;}
int main(void)
{
    static dns_work_t w;
    static uint8_t ans[DNS_TCP_MAX_ANSWER];
    /* 1. a 2.5 KB answer over UDP comes back whole over TCP, no TCP upstream */
    build(0x1234, "big.example.com"); answer_of(2500, false);
    w.tcp = 3; atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(udp_sends == 1 && tcp_connects == 0);
    CHECK(client_out_len == 2 + 2500 && client_out[0] == (2500 >> 8) && client_out[1] == (2500 & 255));
    CHECK(client_out[2] == 0x12 && client_out[3] == 0x34);                          /* the client's ID */
    CHECK(atomic_load(&s_tcp_active) == 0 && closes >= 2);
    CHECK(last_udp_query[last_udp_len - 8] == 0x0f && last_udp_query[last_udp_len - 7] == 0xff);   /* EDNS 4095 */
    /* 2. truncated even over UDP: TCP to the resolver is tried */
    build(0x2222, "huge.example.com"); answer_of(200, true); atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(tcp_connects == 1 && client_out_len == 0 && atomic_load(&s_tcp_active) == 0);
    /* 2b. truncated over UDP, a 6 KB answer over TCP: passed on whole */
    build(0x2b2b, "huge.example.com"); answer_of(200, true); atomic_store(&s_tcp_active, 1);
    tcp_answer_size = 6000; tcp_connect_ok = 1;
    tcp_serve(&w, ans);
    CHECK(client_out_len == 2 + 6000 && client_out[0] == (6000 >> 8) && client_out[2] == 0x2b && client_out[3] == 0x2b);
    tcp_connect_ok = 0;
    /* 3. no UDP answer at all: TCP tried, the client gets nothing (closed) */
    build(0x3333, "slow.example.com"); udp_answer_len = 0; atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(tcp_connects == 3 && client_out_len == 0);
    /* 4. a tailnet name: answered locally, nothing sent upstream */
    s_local_cb = local_name; int sends = udp_sends;
    build(0x4444, "nas.tail.ts.net"); atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(udp_sends == sends && client_out_len == 2 + qlen && client_out[2] == 0x44 && client_out[4] == 0x84);
    s_local_cb = NULL;
    /* 5. a client that sends a malformed length: closed, nothing asked */
    build(0x5555, "x.example.com"); client_in[0] = 0; client_in[1] = 5; sends = udp_sends; atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(udp_sends == sends && client_out_len == 0 && atomic_load(&s_tcp_active) == 0);
    /* Drop replies across a resolver change during each transport. */
    build(0x6666, "x.example.com"); answer_of(2500, false);
    change_epoch_on_udp = true; atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(client_out_len == 0 && atomic_load(&s_tcp_active) == 0);
    change_epoch_on_udp = false;
    build(0x7777, "x.example.com"); answer_of(200, true);
    w.cache_epoch = atomic_load(&s_cache_epoch);
    tcp_connect_ok = 1; change_epoch_on_tcp = true; atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(client_out_len == 0 && atomic_load(&s_tcp_active) == 0);
    change_epoch_on_tcp = false;
    build(0x8888, "x.example.com"); answer_of(2500, false);
    w.cache_epoch = atomic_load(&s_cache_epoch);
    atomic_store(&s_tcp_active, 1);
    tcp_serve(&w, ans);
    CHECK(client_out_len == 2502 && client_out[2] == 0x88 && client_out[3] == 0x88);
    puts("tcp serve ok");
    return 0;
}
"""


def run_serve(code):
    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / 'serve.c'
        c.write_text(SERVE.replace('@@SERVE@@', code), encoding='utf-8')
        exe = Path(tmp) / ('serve.exe' if os.name == 'nt' else 'serve')
        build = subprocess.run(['gcc', '-std=gnu11', '-O1', '-Wall', '-Wno-unused-function', '-Wno-unused-parameter', str(c), '-o', str(exe)],
                               capture_output=True, text=True)
        if build.returncode:
            return build
        return subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)


served = run_serve(serve_code)
assert served.returncode == 0 and 'tcp serve ok' in served.stdout, (served.returncode, served.stdout, served.stderr[-3000:])
# 3.0.25-beta.10 asked the resolver over TCP only: fails here as on board A.
old = 'rl = udp_ask(upstream, w->q, qlen, answer, DNS_UDP_LARGE_ANSWER);'
assert old in serve_code
assert run_serve(serve_code.replace(old, 'rl = 0;')).returncode != 0, 'TCP-only upstream must fail'
print('dns relay tcp: UDP first with a 4 KB buffer, whole answer to the TCP client, TCP upstream only when truncated, local names, bounded')

STARTUP = r"""
#include <assert.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DNS_WORKER_COUNT 2
#define DNS_WORK_QUEUE_DEPTH 8
#define DNS_RELAY_BUF_SIZE 1024
#define DNS_TCP_MAX_ANSWER 16384
#define DNS_WORKER_RETRY_US 2000000LL
#define DNS_LISTENER_RETRY_US 5000000LL
#define DNS_RELAY_BOOT_DELAY_MS 3000
#define DNS_LISTENER_STACK 8192
#define DNS_WORKER_STACK 8192
#define DNS_RELAY_TASK_PRIO 4
#define MALLOC_CAP_SPIRAM 1
#define MALLOC_CAP_8BIT 2
#define ESP_OK 0
#define pdPASS 1
#define pdTRUE 1
#define pdMS_TO_TICKS(ms) (ms)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#undef FD_SET
#undef FD_ISSET
#undef FD_ZERO
#define fd_set fixture_fd_set
typedef unsigned fixture_fd_set;
#define FD_SET(fd, set) (*(set) |= 1u << (fd))
#define FD_ISSET(fd, set) (*(set) & (1u << (fd)))
#define FD_ZERO(set) (*(set) = 0)
#define select fixture_select
#define close fixture_close
#define timeval fixture_timeval
struct fixture_timeval { long tv_sec, tv_usec; };
typedef unsigned socklen_t;
struct sockaddr { uint32_t addr; };
struct sockaddr_in { uint32_t addr; };
typedef struct {
    struct sockaddr_in client;
    socklen_t client_len;
    bool lan;
    uint32_t upstream, cache_epoch;
    unsigned udp_generation;
    int tcp, qlen;
    uint8_t q[DNS_RELAY_BUF_SIZE];
} dns_work_t;
typedef int (*dns_relay_local_cb_t)(const uint8_t *, int, uint8_t *, int);
typedef uint32_t (*dns_relay_route_cb_t)(const uint8_t *, int);
static dns_relay_local_cb_t s_local_cb;
static dns_relay_route_cb_t s_route_cb;
static atomic_uint s_bind_nbo=1, s_cache_epoch;
static atomic_bool s_healthy;
static bool s_enabled=true, s_lan_on, s_lan_dirty;
static uint32_t s_captive_nbo=1, s_lan_nbo, s_upstream_nbo;
static atomic_int s_listen_sock=-1, s_lan_sock=-1;
static unsigned s_udp_generation[2], worker_replies;
typedef bool StaticSemaphore_t;
static StaticSemaphore_t *s_udp_io;
#define portMAX_DELAY 0
#define MSG_DONTWAIT 0x08
static StaticSemaphore_t *xSemaphoreCreateMutexStatic(StaticSemaphore_t *s) { assert(!*s); return s; }
static void xSemaphoreTake(StaticSemaphore_t *s, int timeout) { assert(!*s && timeout==portMAX_DELAY); *s=true; }
static void xSemaphoreGive(StaticSemaphore_t *s) { assert(*s); *s=false; }
static void *s_cache, *s_workq;
static uint8_t *s_tcp_answer, *owned[DNS_WORKER_COUNT];
static unsigned st_queries, st_hits, st_misses;
static unsigned step, admissions, task_limit, closed, freed, captive_replies, tcp_accepts;
static unsigned queue_attempts, transitions;
static bool allow_queue, allow_psram_udp, allow_internal_udp, allow_tcp, fail_bind;
static bool checked_backoff;
static bool allow_listener, timer_alloc_ok, timer_start_ok, armed;
static unsigned listener_attempts, timer_deleted;
typedef struct { void (*callback)(void *); } fixture_timer_t;
typedef fixture_timer_t *esp_timer_handle_t;
typedef struct { void (*callback)(void *); const char *name; bool skip_unhandled_events; } esp_timer_create_args_t;
static fixture_timer_t fixture_timer;
static esp_timer_handle_t s_listener_retry;
static int64_t clock_us;
static jmp_buf finish;
static void notify_state(bool healthy) {
    static const bool expected[]={true, false, true, false, true};
    assert(transitions < sizeof expected / sizeof *expected);
    assert(healthy==expected[transitions++] && atomic_load(&s_healthy)==healthy);
}
static void *xQueueCreate(unsigned depth, size_t size) {
    assert(depth==DNS_WORK_QUEUE_DEPTH && size==sizeof(dns_work_t *));
    queue_attempts++;
    return allow_queue ? &queue_attempts : NULL;
}
static int xQueueSend(void *queue, dns_work_t **work, int wait) {
    (void)queue; (void)work; (void)wait;
    abort(); /* This scenario serves only captive queries. */
}
static void *fixture_malloc(size_t size) {
    assert(size==DNS_RELAY_BUF_SIZE+1);
    return allow_internal_udp ? malloc(size) : NULL;
}
static void *heap_caps_malloc(size_t size, unsigned caps) {
    assert(caps==(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    bool allow = size==DNS_TCP_MAX_ANSWER ? allow_tcp : allow_psram_udp;
    return allow ? malloc(size) : NULL;
}
static void heap_caps_free(void *ptr) { freed++; free(ptr); }
static void worker_task(void *arg) { (void)arg; abort(); }
static void listener_task(void *arg);
static int xTaskCreateWithCaps(void (*task)(void *), const char *name, int stack, void *arg,
                               int priority, void *handle, unsigned caps) {
    assert(priority==DNS_RELAY_TASK_PRIO && !handle && caps==MALLOC_CAP_SPIRAM);
    if (task==listener_task) {
        assert(!strcmp(name,"dns_relay") && stack==DNS_LISTENER_STACK && !arg);
        listener_attempts++;
        return allow_listener ? pdPASS : 0;
    }
    assert(task==worker_task && !strcmp(name,"dns_worker") && arg && s_workq);
    assert(stack==DNS_WORKER_STACK);
    if (admissions>=task_limit) return 0;
    assert(admissions<DNS_WORKER_COUNT);
    owned[admissions++]=arg;
    return pdPASS;
}
static int64_t esp_timer_get_time(void) { return clock_us; }
static void vTaskDelay(int ms) {
    clock_us+=(int64_t)ms*1000;
    if (fail_bind) {
        assert(!atomic_load(&s_healthy) && s_listen_sock==-1 && closed==2);
        fail_bind=false;
    }
}
static int open_listen_sock(uint32_t ip) { return fail_bind ? -1 : ip==1 ? 11 : 12; }
static int open_tcp_listen(uint32_t ip) { return ip==1 ? 13 : 14; }
static void close(int fd) { assert(fd==11 || fd==12 || fd==13 || fd==16); assert(!*s_udp_io); closed++; }
static void tcp_accept(int fd, bool lan) { assert(fd==13 && !lan && s_tcp_answer && admissions==2); tcp_accepts++; }
static int select(int top, fd_set *ready, void *write, void *except, struct timeval *wait) {
    (void)write; (void)except; assert(wait->tv_usec==500000);
    clock_us+=DNS_WORKER_RETRY_US;
    switch (step++) {
    case 0:
        assert(top==12 && atomic_load(&s_healthy) && !queue_attempts && !admissions);
        return 1; /* A received captive query. */
    case 1:
        assert(captive_replies==1 && !admissions);
        s_captive_nbo=0;
        break;
    case 2:
        assert(queue_attempts==1 && !s_workq && !atomic_load(&s_healthy));
        if (!checked_backoff) {
            checked_backoff=true;
            clock_us-=DNS_WORKER_RETRY_US-500000;
            step--;
            break;
        }
        allow_queue=true;
        break;
    case 3:
        assert(queue_attempts==2 && s_workq && !admissions && !atomic_load(&s_healthy));
        allow_internal_udp=true;
        break;
    case 4:
        assert(!admissions && freed==1 && !atomic_load(&s_healthy));
        task_limit=1;
        break;
    case 5:
        assert(admissions==1 && freed==2 && atomic_load(&s_healthy) && !s_tcp_answer && top==12);
        task_limit=2;
        allow_psram_udp=true;
        break;
    case 6:
        assert(admissions==2 && atomic_load(&s_healthy) && !s_tcp_answer && top==12);
        allow_tcp=true;
        break;
    case 7:
        assert(admissions==2 && s_tcp_answer && top==14);
        *ready=1u<<13;
        return 1;
    case 8:
        assert(tcp_accepts==1 && transitions==3);
        atomic_store(&s_bind_nbo,2);
        fail_bind=true;
        break;
    case 9:
        assert(top==15 && atomic_load(&s_healthy) && s_listen_sock==12);
        assert(closed==2 && transitions==5 && admissions==2 && queue_attempts==2);
        longjmp(finish, 1);
    default: abort();
    }
    return 0;
}
static int recvfrom(int fd, uint8_t *q, size_t cap, int flags, struct sockaddr *from, socklen_t *len) {
    (void)flags; (void)from; (void)len;
    assert(step==1 && fd==11 && cap>0);
    *q=42; return 1;
}
static int dns_captive_answer(const uint8_t *q, int len, uint32_t ip, uint8_t *answer, int cap) {
    assert(*q==42 && len==1 && ip==1 && cap>0);
    *answer=99; return 1;
}
static int sendto(int fd, const uint8_t *answer, int len, int flags, const struct sockaddr *to, socklen_t to_len) {
    (void)to; (void)to_len;
    if (flags == MSG_DONTWAIT) {
        assert(*s_udp_io && (fd==12 || fd==16) && *answer==55 && len==1);
        worker_replies++;
        return len;
    }
    assert(fd==11 && *answer==99 && len==1);
    captive_replies++; return len;
}
static uint32_t pick_upstream(void) { return 0; }
static bool dns_edns_clamp(uint8_t *q, int n, uint16_t limit) { (void)q; (void)n; (void)limit; return false; }
static int dns_cache_key_len(const uint8_t *q, int n) { (void)q; (void)n; return 0; }
static bool cache_get(const uint8_t *q, int len, uint32_t upstream, uint32_t epoch, uint8_t *res, int *rl) {
    (void)q; (void)len; (void)upstream; (void)epoch; (void)res; (void)rl; return false;
}
static int esp_timer_create(const esp_timer_create_args_t *args, esp_timer_handle_t *out) {
    assert(args->callback && args->skip_unhandled_events && !armed);
    if (!timer_alloc_ok) return -1;
    fixture_timer.callback=args->callback;
    *out=&fixture_timer;
    return ESP_OK;
}
static int esp_timer_start_periodic(esp_timer_handle_t timer, uint64_t period) {
    assert(timer==&fixture_timer && period==DNS_LISTENER_RETRY_US && !armed);
    if (!timer_start_ok) return -1;
    armed=true;
    return ESP_OK;
}
static int esp_timer_stop(esp_timer_handle_t timer) {
    assert(timer==&fixture_timer && armed);
    armed=false;
    return ESP_OK;
}
static int esp_timer_delete(esp_timer_handle_t timer) {
    assert(timer==&fixture_timer && !armed);
    timer_deleted++;
    return ESP_OK;
}
#define malloc fixture_malloc
@@STARTUP@@
#undef malloc
int main(void) {
    (void)s_cache; (void)s_upstream_nbo;
    assert(!start_listener() && listener_attempts==1);
    assert(!schedule_listener_retry() && !s_listener_retry && !timer_deleted);
    timer_alloc_ok=true;
    assert(!schedule_listener_retry() && !s_listener_retry && timer_deleted==1);
    timer_start_ok=true;
    assert(schedule_listener_retry() && armed);
    fixture_timer.callback(NULL);
    assert(listener_attempts==2 && armed && timer_deleted==1);
    allow_listener=true;
    fixture_timer.callback(NULL);
    assert(listener_attempts==3 && !armed && !s_listener_retry && timer_deleted==2);
    if (!setjmp(finish)) { listener_task(NULL); abort(); }
    dns_work_t ap = {.udp_generation=2}, lan = {.lan=true, .udp_generation=1};
    uint8_t reply=55;
    publish_udp_listener(true, 16, 1);
    udp_reply(&ap, &reply, 1);
    udp_reply(&lan, &reply, 1);
    assert(worker_replies==2);
    publish_udp_listener(false, -1, 2);
    udp_reply(&ap, &reply, 1);
    assert(worker_replies==2);
    publish_udp_listener(false, 12, 3); /* the same descriptor is reused */
    udp_reply(&ap, &reply, 1);
    udp_reply(&lan, &reply, 1);          /* LAN is unaffected by AP retirement */
    assert(worker_replies==3);
    ap.udp_generation=3;
    udp_reply(&ap, &reply, 1);
    publish_udp_listener(true, -1, 1);
    publish_udp_listener(true, 16, 2);
    udp_reply(&lan, &reply, 1);
    assert(worker_replies==4);
    atomic_fetch_add(&s_cache_epoch, 1);
    udp_reply(&ap, &reply, 1);
    assert(worker_replies==4);
    for (unsigned i=0; i<admissions; i++) free(owned[i]);
    free(s_tcp_answer);
    puts("dns relay startup ok");
}
"""

startup = (function('static void update_health(') + function('static void publish_udp_listener(')
           + function('static void udp_reply(') + function('static void ensure_workers(') + function('static void listener_task(')
           + function('static bool start_listener(') + function('static void retry_listener(') + function('static bool schedule_listener_retry('))
with tempfile.TemporaryDirectory() as tmp:
    c = Path(tmp) / 'startup.c'
    c.write_text(STARTUP.replace('@@STARTUP@@', startup), encoding='utf-8')
    exe = Path(tmp) / ('startup.exe' if os.name == 'nt' else 'startup')
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=10)
