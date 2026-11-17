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
- the worker sends a random ID upstream and restores the client's ID.

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
assert 'upstream_recv(up, rbuf, w->q, w->qlen, &up_addr)' in worker
assert 'recvfrom(up, rbuf, DNS_RELAY_BUF_SIZE, 0, NULL, NULL)' not in source
assert 'recvfrom(up, rbuf, DNS_RELAY_BUF_SIZE + 1, 0,' in source
assert '(void)dns_edns_clamp(w->q, w->qlen, DNS_RELAY_BUF_SIZE);' in worker
assert 'dns_truncated_reply(rbuf, rlen, w->q, w->qlen)' in worker

helpers = (function('static int dns_question_len(') + function('static int dns_skip_name(')
           + function('static bool dns_edns_clamp(') + function('static int dns_truncated_reply(')
           + function('static uint32_t dns_resp_ttl(')
           + function('static bool dns_reply_matches(') + function('static int upstream_recv('))
checked = re.sub(r'\bp\[([^\]]+)\]', r'AT(\1)', helpers)
tcp_helpers = function('static bool tcp_all(') + function('static int tcp_read_msg(') + function('static bool tcp_write_msg(')
cache_decl = source.split('/* ---- SPIRAM direct-mapped response cache ---- */', 1)[1].split('static atomic_uint s_cache_epoch;', 1)[0]
cache_helpers = cache_decl + function('static uint32_t fnv1a(') + function('static bool cache_get(') + function('static void cache_put(')

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
static void add(const uint8_t *d, int len, uint32_t ip, uint16_t port) {
    dgram_t *g = &script[nscript++]; memcpy(g->d, d, len); g->len = len; g->ip = ip; g->port = port; g->err = 0;
}
static int recv_now(uint8_t *buf) { struct sockaddr_in srv = {2, 53, {0x0101A8C0}}; return upstream_recv(1, buf, q, qlen, &srv); }
int main(void) {
    uint8_t buf[DNS_RELAY_BUF_SIZE + 1];
    const uint32_t SRV = 0x0101A8C0; const uint16_t P53 = 53;
    build_q(0xBEEF, "www.example.com"); build_r(300);
    dns_cache_entry_t entries[DNS_CACHE_ENTRIES] = {0};
    s_cache = entries;
    s_cache_mtx = entries;
    int key_len = qlen - 12, cached_len = 0;
    cache_put(q, key_len, SRV, 1, r, rlen, 300);
    CHECK(cache_get(q, key_len, SRV, 1, buf, &cached_len) && cached_len == rlen);
    CHECK(!cache_get(q, key_len, SRV + 1, 1, buf, &cached_len));
    CHECK(!cache_get(q, key_len, SRV, 2, buf, &cached_len));

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
    CHECK(dns_resp_ttl(r, rlen, ql) == 300);
    build_r(2); CHECK(dns_resp_ttl(r, rlen, ql) == DNS_CACHE_TTL_MIN_S);
    build_r(999999); CHECK(dns_resp_ttl(r, rlen, ql) == DNS_CACHE_TTL_MAX_S);
    cur_len = 11; CHECK(dns_resp_ttl(r, 11, ql) == 0);
    /* answer name "a" + pointer: labels then compression */
    build_r(300); { int at = qlen; uint8_t nm[] = {1, 'a', 0xC0, 0x0C}; memmove(r + at + 4, r + at + 2, rlen - at - 2);
        memcpy(r + at, nm, 4); rlen += 2; }
    cur_len = rlen; CHECK(dns_resp_ttl(r, rlen, ql) == 300);

    /* TC answers are not cached */
    build_r(300); r[2] |= 0x02; cur_p = r; cur_len = rlen; CHECK(dns_resp_ttl(r, rlen, ql) == 0);

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
    cur_p = buf; cur_len = tl; CHECK(dns_resp_ttl(buf, tl, ql) == 0);                          /* not cached */
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
        (void)dns_resp_ttl(heap, len, ql);
        (void)dns_reply_matches(heap, len, q, qlen);
        (void)dns_question_len(heap, len);
        free(heap);
    }
    puts("dns relay upstream ok");
    return 0;
}
'''


def run(code):
    with tempfile.TemporaryDirectory() as tmp:
        c = Path(tmp) / 'relay.c'
        c.write_text(PROGRAM.replace('@@HELPERS@@', code).replace('@@CACHE@@', cache_helpers).replace('@@TCP@@', tcp_helpers), encoding='utf-8')
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
                 ('r[4] << 8) | r[5]) != 1) return 0;', 'r[4] << 8) | r[5]) != 1) return rlen;')):
    assert old in checked, old
    assert run(checked.replace(old, new)).returncode != 0, 'mutant survived: ' + old
print('dns relay 3.0.25: EDNS size clamped, oversized answers made truncated replies, TC not cached, TCP framing bounded')
