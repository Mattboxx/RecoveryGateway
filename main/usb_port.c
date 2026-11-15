/* The native USB port as a USB host; see usb_port.h.
 * Original implementation, Mattboxx Edition. SPDX-License-Identifier: GPL-3.0-only */
#include "usb_port.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- usb_port core (begin) --- */
static uint16_t usbp_le16(const uint8_t *p) {return (uint16_t)(p[0] | p[1] << 8);}
static uint32_t usbp_le32(const uint8_t *p) {return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;}
static void usbp_put16(uint8_t *p, uint16_t v) {p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);}
static void usbp_put32(uint8_t *p, uint32_t v) {for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));}

#define USBP_FUNCS 8
#define USBP_DATA_ALTS 16
typedef struct {uint8_t kind, ctrl, data, ep_notify, mac_index; bool has_union;} usbp_func_t;
typedef struct {uint8_t iface, alt, ep_in, ep_out; uint16_t mps_in, mps_out;} usbp_alt_t;

/* Communication interface (class, subclass, protocol) to a network kind. */
static uint8_t usbp_comm_kind(uint8_t cls, uint8_t sub, uint8_t proto)
{
    if (cls == 0x02 && sub == 0x0d) return USBP_NET_NCM;
    if (cls == 0x02 && sub == 0x06) return USBP_NET_ECM;
    if ((cls == 0x02 && sub == 0x02 && proto == 0xff) || (cls == 0xe0 && sub == 0x01 && proto == 0x03)
        || (cls == 0xef && sub == 0x04 && proto == 0x01)) return USBP_NET_RNDIS;
    if (cls == 0x02 && sub == 0x0e) return USBP_NET_UNSUPPORTED;   /* MBIM */
    return USBP_NET_NONE;
}

int usbp_scan(const uint8_t *cfg, size_t len, usbp_net_t *net, usbp_storage_t *storage)
{
    if (!net || !storage) return -1;
    memset(net, 0, sizeof *net);
    memset(storage, 0, sizeof *storage);
    if (!cfg || len < 9 || cfg[0] < 9 || cfg[1] != 0x02) return -1;
    size_t total = usbp_le16(cfg + 2);
    if (total < 9 || total > len) return -1;
    usbp_func_t f[USBP_FUNCS];
    usbp_alt_t a[USBP_DATA_ALTS];
    unsigned nf = 0, na = 0;
    int cur_func = -1, cur_alt = -1;       /* where endpoints of the current interface go */
    bool in_storage = false, unsupported = false;
    usbp_storage_t st = {0};
    uint8_t st_iface = 0;
    for (size_t at = cfg[0]; at < total;) {
        uint8_t l = cfg[at];
        if (l < 2 || at + l > total) return -1;
        const uint8_t *d = cfg + at;
        if (d[1] == 0x04) {
            if (l < 9) return -1;
            uint8_t num = d[2], alt = d[3], cls = d[5], sub = d[6], proto = d[7];
            cur_func = cur_alt = -1;
            in_storage = false;
            uint8_t kind = alt == 0 ? usbp_comm_kind(cls, sub, proto) : USBP_NET_NONE;
            if (kind == USBP_NET_UNSUPPORTED) unsupported = true;
            else if (kind != USBP_NET_NONE && nf < USBP_FUNCS) {
                f[nf] = (usbp_func_t){.kind = kind, .ctrl = num, .data = (uint8_t)(num + 1)};
                cur_func = (int)nf++;
            } else if (cls == 0x0a && na < USBP_DATA_ALTS) {
                a[na] = (usbp_alt_t){.iface = num, .alt = alt};
                cur_alt = (int)na++;
            } else if (cls == 0x08 && sub == 0x06 && proto == 0x50 && alt == 0 && !st.present) {
                in_storage = true;           /* SCSI over bulk-only transport */
                st_iface = num;
            }
        } else if (d[1] == 0x24 && cur_func >= 0) {   /* class-specific: functional descriptors */
            if (l >= 5 && d[2] == 0x06) {f[cur_func].data = d[4]; f[cur_func].has_union = true;}
            else if (l >= 4 && d[2] == 0x0f) f[cur_func].mac_index = d[3];
        } else if (d[1] == 0x05) {
            if (l < 7) return -1;
            uint8_t addr = d[2], type = d[3] & 3;
            uint16_t mps = usbp_le16(d + 4) & 0x7ff;
            if (cur_func >= 0 && type == 3 && (addr & 0x80)) f[cur_func].ep_notify = addr;
            else if (cur_alt >= 0 && type == 2 && (addr & 0x80)) {a[cur_alt].ep_in = addr; a[cur_alt].mps_in = mps;}
            else if (cur_alt >= 0 && type == 2) {a[cur_alt].ep_out = addr; a[cur_alt].mps_out = mps;}
            else if (in_storage && type == 2 && (addr & 0x80)) st.ep_in = addr;
            else if (in_storage && type == 2) {st.ep_out = addr; st.mps_out = mps;}
            if (in_storage && st.ep_in && st.ep_out) {st.present = true; st.iface = st_iface; in_storage = false;}
        }
        at += l;
    }
    *storage = st;
    static const uint8_t preference[] = {USBP_NET_NCM, USBP_NET_ECM, USBP_NET_RNDIS};
    for (unsigned p = 0; p < sizeof preference; p++)
        for (unsigned i = 0; i < nf; i++) {
            if (f[i].kind != preference[p]) continue;
            for (unsigned j = 0; j < na; j++) {
                if (a[j].iface != f[i].data || !a[j].ep_in || !a[j].ep_out || !a[j].mps_in || !a[j].mps_out) continue;
                *net = (usbp_net_t){.kind = f[i].kind, .ctrl = f[i].ctrl, .data = f[i].data, .data_alt = a[j].alt,
                                    .ep_in = a[j].ep_in, .ep_out = a[j].ep_out, .ep_notify = f[i].ep_notify,
                                    .mac_index = f[i].mac_index, .mps_in = a[j].mps_in, .mps_out = a[j].mps_out};
                return 0;
            }
        }
    if (unsupported || nf) net->kind = USBP_NET_UNSUPPORTED;   /* a network function without a usable data path */
    return 0;
}

uint8_t usbp_next_config(uint8_t num_configs, uint8_t current)
{
    if (num_configs < 2 || current < 1 || current >= num_configs || current >= USBP_MAX_CONFIGS) return 0;
    return (uint8_t)(current + 1);
}

int usbp_action(bool want_serial, uint8_t usb_mode, int serial, const usbp_net_t *net, const usbp_storage_t *storage,
                uint8_t num_configs, uint8_t config_value)
{
    bool net_ok = net && (net->kind == USBP_NET_ECM || net->kind == USBP_NET_NCM || net->kind == USBP_NET_RNDIS);
    if (want_serial) {
        if (usb_mode != USBP_MODE_NETWORK && serial > 0) return USBP_ACT_SERIAL;
        if (usb_mode != USBP_MODE_SERIAL && net_ok) return USBP_ACT_NETWORK;
    } else if (net_ok) return USBP_ACT_NETWORK;
    /* Storage only (a stick in its CD-ROM/driver mode): switch it. A storage
     * interface next to modem functions is the usual driver disk: leave it. */
    if (storage && storage->present && serial <= 0 && net && net->kind == USBP_NET_NONE) return USBP_ACT_SWITCH;
    if (usbp_next_config(num_configs, config_value)) return USBP_ACT_NEXT_CONFIG;
    return USBP_ACT_NONE;
}

/* usb_modeswitch reference data (GPL-2.0-or-later, Josua Dietze):
 * usb_modeswitch.d entries of usb-modeswitch-data 20251207 and the built-in
 * HuaweiNewMode / StandardEject messages of usb_modeswitch.c 2.6.2. */
enum {USBP_EJECT = 1, USBP_HUAWEI = 2, USBP_MESSAGE = 4};
static const char USBP_HUAWEI_NEW[] = "55534243123456780000000000000011062000000101000100000000000000";
static const char *const USBP_STANDARD_EJECT[] = {
    "5553424387654321000000000000061e000000000000000000000000000000",
    "5553424397654321000000000000061b000000020000000000000000000000",
    "5553424387654321000000000001061e000000000000000000000000000000",
    "5553424397654321000000000001061b000000020000000000000000000000"};
static const struct {uint16_t vid, pid; uint8_t method; const char *message;} USBP_MSW[] = {
    {0x12d1, 0x1f01, USBP_HUAWEI, NULL},   /* Huawei E353 and others (HiLink) */
    {0x12d1, 0x14fe, USBP_HUAWEI, NULL},   /* Huawei E352, E173s */
    {0x12d1, 0x1446, USBP_HUAWEI, NULL},   /* Huawei, newer modems and rebrandings */
    {0x19d2, 0x1225, USBP_EJECT, NULL},    /* ZTE MF668, MF70 */
    {0x19d2, 0x0166, USBP_MESSAGE, "55534243123456782400000080000685000000240000000000000000000000"},   /* ZTE MF820 */
    {0x19d2, 0x1588, USBP_EJECT | USBP_MESSAGE, "55534243123456702000000080000c85010101180101010101000000000000"}, /* ZTE MF710M */
    {0x1bbb, 0xf000, USBP_MESSAGE, "55534243123456788000000080000606f50402527000000000000000000000"},   /* Alcatel X200, L100V */
    {0x1bbb, 0xf017, USBP_MESSAGE, "55534243123456788000000080000606f50402527000000000000000000000"},   /* Alcatel OT-X220D */
    {0x05c6, 0xf000, USBP_EJECT | USBP_MESSAGE, "5553424308306384c000000080000671030000000000000000000000000000"}, /* Qualcomm-based */
    {0x2020, 0xf00e, USBP_EJECT, NULL},    /* SpeedUp SU-8000 and others */
    {0x1c9e, 0xf000, USBP_MESSAGE, "555342431234567800000000000001ff000000000000000000000000000000"},   /* Longcheer */
};

static bool usbp_hex(const char *hex, uint8_t out[USBP_CBW_LEN])
{
    if (strlen(hex) != 2 * USBP_CBW_LEN) return false;
    for (int i = 0; i < USBP_CBW_LEN; i++) {
        unsigned v = 0;
        for (int k = 0; k < 2; k++) {
            char c = hex[2 * i + k];
            unsigned n = c >= '0' && c <= '9' ? (unsigned)(c - '0') : c >= 'a' && c <= 'f' ? (unsigned)(c - 'a' + 10) : 16;
            if (n > 15) return false;
            v = v << 4 | n;
        }
        out[i] = (uint8_t)v;
    }
    return true;
}

static void usbp_msw_add(usbp_msw_t *out, const char *hex)
{
    if (out->count < USBP_MSW_MAX && usbp_hex(hex, out->message[out->count])) out->count++;
}

void usbp_msw_plan(uint16_t vid, uint16_t pid, usbp_msw_t *out)
{
    memset(out, 0, sizeof *out);
    uint8_t method = vid == 0x12d1 ? USBP_HUAWEI : USBP_EJECT;
    const char *message = NULL;
    for (size_t i = 0; i < sizeof USBP_MSW / sizeof USBP_MSW[0]; i++)
        if (USBP_MSW[i].vid == vid && USBP_MSW[i].pid == pid) {method = USBP_MSW[i].method; message = USBP_MSW[i].message;}
    if (method & USBP_HUAWEI) usbp_msw_add(out, USBP_HUAWEI_NEW);
    if (method & USBP_EJECT) for (int i = 0; i < 4; i++) usbp_msw_add(out, USBP_STANDARD_EJECT[i]);
    if ((method & USBP_MESSAGE) && message) usbp_msw_add(out, message);
}

#define USBP_RNDIS_PACKET 0x00000001u
#define USBP_RNDIS_HEADER 44u
size_t usbp_rndis_init(uint8_t *out, size_t cap, uint32_t request_id, uint32_t max_transfer)
{
    if (!out || cap < 24) return 0;
    memset(out, 0, 24);
    usbp_put32(out, 0x00000002u); usbp_put32(out + 4, 24); usbp_put32(out + 8, request_id);
    usbp_put32(out + 12, 1); usbp_put32(out + 16, 0); usbp_put32(out + 20, max_transfer);
    return 24;
}

size_t usbp_rndis_query(uint8_t *out, size_t cap, uint32_t request_id, uint32_t oid)
{
    if (!out || cap < 28) return 0;
    memset(out, 0, 28);
    usbp_put32(out, 0x00000004u); usbp_put32(out + 4, 28); usbp_put32(out + 8, request_id);
    usbp_put32(out + 12, oid); usbp_put32(out + 20, 20);
    return 28;
}

size_t usbp_rndis_set(uint8_t *out, size_t cap, uint32_t request_id, uint32_t oid, uint32_t value)
{
    if (!out || cap < 32) return 0;
    memset(out, 0, 32);
    usbp_put32(out, 0x00000005u); usbp_put32(out + 4, 32); usbp_put32(out + 8, request_id);
    usbp_put32(out + 12, oid); usbp_put32(out + 16, 4); usbp_put32(out + 20, 20); usbp_put32(out + 28, value);
    return 32;
}

bool usbp_rndis_cmplt(const uint8_t *msg, size_t len, uint32_t type, uint32_t request_id, const uint8_t **info, size_t *info_len)
{
    if (info) *info = NULL;
    if (info_len) *info_len = 0;
    if (!msg || len < 16) return false;
    uint32_t mlen = usbp_le32(msg + 4);
    if (usbp_le32(msg) != (type | 0x80000000u) || mlen < 16 || mlen > len || usbp_le32(msg + 8) != request_id
        || usbp_le32(msg + 12) != 0) return false;
    if (type == 0x00000002u && mlen < 52) return false;
    if (type == 0x00000004u) {
        if (mlen < 24) return false;
        uint32_t ilen = usbp_le32(msg + 16), ioff = usbp_le32(msg + 20);
        if (ioff > mlen || ilen > mlen || 8u + ioff > mlen || 8u + ioff + ilen > mlen) return false;
        if (info) *info = msg + 8 + ioff;
        if (info_len) *info_len = ilen;
    }
    return true;
}

size_t usbp_rndis_wrap(uint8_t *out, size_t cap, const uint8_t *frame, size_t len)
{
    if (!out || !frame || !len || len > 1514 || cap < USBP_RNDIS_HEADER + len) return 0;
    memset(out, 0, USBP_RNDIS_HEADER);
    usbp_put32(out, USBP_RNDIS_PACKET); usbp_put32(out + 4, (uint32_t)(USBP_RNDIS_HEADER + len));
    usbp_put32(out + 8, USBP_RNDIS_HEADER - 8); usbp_put32(out + 12, (uint32_t)len);
    memcpy(out + USBP_RNDIS_HEADER, frame, len);
    return USBP_RNDIS_HEADER + len;
}

int usbp_rndis_next(const uint8_t *buf, size_t len, size_t *offset, const uint8_t **frame, size_t *frame_len)
{
    while (*offset + 8 <= len) {
        const uint8_t *m = buf + *offset;
        uint32_t type = usbp_le32(m), mlen = usbp_le32(m + 4);
        if (!type && !mlen) return 0;                         /* zero padding */
        if (mlen < 8 || mlen > len - *offset) return -1;
        *offset += mlen;
        if (type != USBP_RNDIS_PACKET) continue;              /* not data: skip */
        if (mlen < USBP_RNDIS_HEADER) return -1;
        uint32_t doff = usbp_le32(m + 8), dlen = usbp_le32(m + 12);
        if (doff > mlen || dlen > mlen || 8u + doff + dlen > mlen || dlen < 14 || dlen > 1514) return -1;
        *frame = m + 8 + doff;
        *frame_len = dlen;
        return 1;
    }
    return 0;
}

#define USBP_NTH16 0x484d434eu   /* "NCMH" */
#define USBP_NDP16 0x304d434eu   /* "NCM0" */
#define USBP_NDP16_CRC 0x314d434eu
size_t usbp_ncm_wrap(uint8_t *out, size_t cap, const uint8_t *frame, size_t len, uint16_t seq, uint16_t divisor, uint16_t remainder)
{
    if (!out || !frame || !len || len > 1514) return 0;
    size_t at = 12 + 16;                                      /* NTH16 + NDP16 with one entry and the terminator */
    if (divisor > 1) at += (size_t)((remainder % divisor) + divisor - at % divisor) % divisor;
    if (at > 0xffff || cap < at + len || at + len > 0xffff) return 0;
    memset(out, 0, at);
    usbp_put32(out, USBP_NTH16); usbp_put16(out + 4, 12); usbp_put16(out + 6, seq);
    usbp_put16(out + 8, (uint16_t)(at + len)); usbp_put16(out + 10, 12);
    usbp_put32(out + 12, USBP_NDP16); usbp_put16(out + 16, 16); usbp_put16(out + 18, 0);
    usbp_put16(out + 20, (uint16_t)at); usbp_put16(out + 22, (uint16_t)len);
    memcpy(out + at, frame, len);
    return at + len;
}

#define USBP_NCM_MAX_NDPS 8
int usbp_ncm_next(const uint8_t *buf, size_t len, usbp_ncm_rx_t *it, const uint8_t **frame, size_t *frame_len)
{
    if (len < 12 || usbp_le32(buf) != USBP_NTH16 || usbp_le16(buf + 4) != 12) return -1;
    size_t block = usbp_le16(buf + 8);
    if (block < 12 || block > len) return -1;
    if (!it->ndp) {
        size_t first = usbp_le16(buf + 10);
        if (first < 12 || first % 4 || first + 8 > block) return -1;
        it->ndp = first; it->entry = 0; it->ndps = 1;
    }
    for (;;) {
        const uint8_t *n = buf + it->ndp;
        if (it->ndp + 8 > block) return -1;
        uint32_t sig = usbp_le32(n);
        size_t nlen = usbp_le16(n + 4);
        if ((sig != USBP_NDP16 && sig != USBP_NDP16_CRC) || nlen < 16 || nlen % 4 || it->ndp + nlen > block) return -1;
        size_t entries = (nlen - 8) / 4;
        while (it->entry < entries) {
            size_t index = usbp_le16(n + 8 + 4 * it->entry), dlen = usbp_le16(n + 10 + 4 * it->entry);
            if (!index || !dlen) {it->entry = entries; break;}     /* terminator */
            it->entry++;
            if (index + dlen > block || dlen < 14 || dlen > 1514) return -1;
            if (++it->frames > 64) return -1;
            *frame = buf + index;
            *frame_len = dlen;
            return 1;
        }
        size_t next = usbp_le16(n + 6);
        if (!next) return 0;
        if (next < 12 || next % 4 || next + 8 > block || ++it->ndps > USBP_NCM_MAX_NDPS) return -1;
        it->ndp = next; it->entry = 0;
    }
}

bool usbp_mac_string(const uint8_t *desc, size_t len, uint8_t mac[6])
{
    if (!desc || len < 26 || desc[0] < 26 || desc[0] > len || desc[1] != 0x03) return false;
    for (int i = 0; i < 12; i++) {
        uint8_t c = desc[2 + 2 * i];
        unsigned v = c >= '0' && c <= '9' ? (unsigned)(c - '0') : (c | 0x20) >= 'a' && (c | 0x20) <= 'f' ? (unsigned)((c | 0x20) - 'a' + 10) : 16;
        if (desc[3 + 2 * i] || v > 15) return false;
        if (i % 2 == 0) mac[i / 2] = (uint8_t)(v << 4);
        else mac[i / 2] |= (uint8_t)v;
    }
    static const uint8_t zero[6];
    return memcmp(mac, zero, 6) != 0 && !(mac[0] & 1);       /* unicast, not all zero */
}
bool usbp_fits(size_t free_internal, size_t need)
{
    return free_internal >= need && free_internal - need >= USBP_INTERNAL_FLOOR;
}

#define USBP_IFACES 32
int usbp_serial_find(const uint8_t *cfg, size_t len, uint8_t iface, usbp_net_t *out)
{
    if (!out) return -1;
    memset(out, 0, sizeof *out);
    if (!cfg || len < 9 || cfg[0] < 9 || cfg[1] != 0x02) return -1;
    size_t total = usbp_le16(cfg + 2);
    if (total < 9 || total > len) return -1;
    struct {bool seen; uint8_t cls, sub, proto, union_data, ep_in, ep_out, ep_int; bool has_union; uint16_t mps_in, mps_out;} f[USBP_IFACES];
    memset(f, 0, sizeof f);
    int cur = -1;
    for (size_t at = cfg[0]; at < total;) {
        uint8_t l = cfg[at];
        if (l < 2 || at + l > total) return -1;
        const uint8_t *d = cfg + at;
        if (d[1] == 0x04) {
            if (l < 9) return -1;
            cur = d[3] == 0 && d[2] < USBP_IFACES ? d[2] : -1;
            if (cur >= 0 && !f[cur].seen) {f[cur].seen = true; f[cur].cls = d[5]; f[cur].sub = d[6]; f[cur].proto = d[7];}
            else if (cur >= 0) cur = -1;               /* a repeated alt 0: keep the first */
        } else if (d[1] == 0x24 && cur >= 0) {
            if (l >= 5 && d[2] == 0x06) {f[cur].union_data = d[4]; f[cur].has_union = true;}
        } else if (d[1] == 0x05 && cur >= 0) {
            if (l < 7) return -1;
            uint8_t addr = d[2], type = d[3] & 3;
            uint16_t mps = usbp_le16(d + 4) & 0x7ff;
            if (type == 2 && (addr & 0x80) && !f[cur].ep_in) {f[cur].ep_in = addr; f[cur].mps_in = mps;}
            else if (type == 2 && !(addr & 0x80) && !f[cur].ep_out) {f[cur].ep_out = addr; f[cur].mps_out = mps;}
            else if (type == 3 && (addr & 0x80) && !f[cur].ep_int) f[cur].ep_int = addr;
        }
        at += l;
    }
    if (iface >= USBP_IFACES || !f[iface].seen) return 0;
    if (f[iface].cls == 0x02 && f[iface].sub == 0x02 && f[iface].proto != 0xff) {   /* CDC-ACM, not RNDIS */
        uint8_t data = f[iface].has_union ? f[iface].union_data : (uint8_t)(iface + 1);
        if (data >= USBP_IFACES || data == iface || !f[data].seen || f[data].cls != 0x0a
            || !f[data].ep_in || !f[data].ep_out || !f[data].mps_in || !f[data].mps_out) return 0;
        *out = (usbp_net_t){.kind = USBP_SERIAL, .ctrl = iface, .data = data, .ep_in = f[data].ep_in, .ep_out = f[data].ep_out,
                            .ep_notify = f[iface].ep_int, .mps_in = f[data].mps_in, .mps_out = f[data].mps_out};
        return 1;
    }
    if (f[iface].cls == 0xff && f[iface].ep_in && f[iface].ep_out && f[iface].mps_in && f[iface].mps_out) {
        *out = (usbp_net_t){.kind = USBP_SERIAL, .ctrl = iface, .data = iface, .ep_in = f[iface].ep_in, .ep_out = f[iface].ep_out,
                            .ep_notify = f[iface].ep_int, .mps_in = f[iface].mps_in, .mps_out = f[iface].mps_out};
        return 1;
    }
    return 0;
}
/* --- usb_port core (end) --- */

#if !defined(USBP_HOST_TEST)
#include "sdkconfig.h"
#if CONFIG_SOC_USB_OTG_SUPPORTED
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif_net_stack.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "freertos/task.h"
#include "usb/usb_host.h"

#define TAG "usb_port"
#define USBP_CFG_MAX 1024              /* configuration descriptor copy (PSRAM) */
#define USBP_NCM_RX 2048               /* NCM: the smallest NTB a device must accept */
#define USBP_FRAME_RX 1600             /* ECM/RNDIS: one frame per transfer (25 x 64) */
#define USBP_TX_SIZE 1664              /* a frame plus RNDIS/NCM headers (26 x 64) */
#define USBP_SERIAL_IN 512
#define USBP_SERIAL_OUT 1600
#define USBP_SERIAL_RX_BUFFER 4096     /* PSRAM stream buffer */
#define USBP_NOTIFY_SIZE 64
#define USBP_CTRL_SIZE (8 + 256)
/* USB host library objects, enumeration buffers and FIFO setup before any
 * device: an estimate, refined by the measurement in usb_port_memory(). */
#define USBP_HOST_ESTIMATE (6 * 1024)
#define USBP_TRANSFER_OVERHEAD 256     /* per transfer: URB and DMA descriptors (estimate) */

static SemaphoreHandle_t s_lock, s_changed, s_done;   /* created by usb_port_start only */
static usb_host_client_handle_t s_client;
static bool s_started;
static usbp_device_t s_dev;            /* under s_lock */
static uint8_t *s_cfg;
static size_t s_cfg_len;
static portMUX_TYPE s_choice_mux = portMUX_INITIALIZER_UNLOCKED;
static struct {uint16_t vid, pid; uint8_t config, tries;} s_choice[4];
static struct {uint16_t vid, pid;} s_switched[4];
static unsigned s_switched_count;
/* A transfer that never completed may still be owned by the stack: it is
 * never freed or reused, and no new session starts until restart (bounded
 * loss instead of a leak per retry). */
static bool s_poisoned;
static usbp_memory_t s_mem;            /* measured internal RAM use */

/* One data session at a time: a serial (AT/PPP) port or a network function.
 * State is written by the open/close owner task; transfer callbacks run in
 * the client task. */
static struct {
    usb_device_handle_t dev;
    uint8_t kind, ctrl, data, data_alt, ep_in, ep_out, ep_notify, mac_index, n_out;
    esp_netif_t *netif;
    StreamBufferHandle_t rx;           /* serial only */
    usb_transfer_t *in[2], *out[2], *notify, *ctrl_xfer;
    atomic_bool out_busy[2], running, gone, link, link_known;
    atomic_int inflight;
    uint16_t seq, ncm_div, ncm_rem;
    size_t out_max;
    TickType_t opened;
    bool claimed_ctrl, claimed_data, leaked;
    usbp_link_cb_t link_cb;
    void *ctx;
} s_net;
static atomic_uint s_rx_dropped, s_tx_dropped, s_rx_errors;
static atomic_ullong s_rx_bytes, s_tx_bytes;

/* --- Detection --- */
#if CONFIG_USB_HOST_ENABLE_ENUM_FILTER_CALLBACK
static bool enum_filter(const usb_device_desc_t *d, uint8_t *config)
{
    *config = 1;
    portENTER_CRITICAL(&s_choice_mux);
    for (unsigned i = 0; i < sizeof s_choice / sizeof s_choice[0]; i++)
        if (s_choice[i].vid == d->idVendor && s_choice[i].pid == d->idProduct && s_choice[i].config
            && s_choice[i].config <= d->bNumConfigurations) *config = s_choice[i].config;
    portEXIT_CRITICAL(&s_choice_mux);
    return true;
}
#endif

static void read_device(uint8_t address)
{
    usb_device_handle_t h;
    if (usb_host_device_open(s_client, address, &h) != ESP_OK) return;
    const usb_device_desc_t *d;
    const usb_config_desc_t *c;
    usb_device_info_t info;
    if (usb_host_get_device_descriptor(h, &d) == ESP_OK && usb_host_get_active_config_descriptor(h, &c) == ESP_OK
        && usb_host_device_info(h, &info) == ESP_OK) {
        size_t n = c->wTotalLength < USBP_CFG_MAX ? c->wTotalLength : USBP_CFG_MAX;   /* longer: refused by the scan */
        xSemaphoreTake(s_lock, portMAX_DELAY);
        memcpy(s_cfg, c, n);
        s_cfg_len = n;
        s_dev = (usbp_device_t){.present = true, .address = address, .num_configs = d->bNumConfigurations,
                                .config_value = info.bConfigurationValue, .vid = d->idVendor, .pid = d->idProduct,
                                .seq = s_dev.seq + 1};
        xSemaphoreGive(s_lock);
        ESP_LOGI(TAG, "device %04x:%04x, configuration %u of %u", d->idVendor, d->idProduct,
                 info.bConfigurationValue, d->bNumConfigurations);
        xSemaphoreGive(s_changed);
    }
    usb_host_device_close(s_client, h);
}

static void device_removed(int address)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool changed = s_dev.present && (address < 0 || s_dev.address == address);
    if (changed) {s_dev.present = false; s_dev.seq++;}
    xSemaphoreGive(s_lock);
    if (changed) xSemaphoreGive(s_changed);
}

static void client_event(const usb_host_client_event_msg_t *m, void *arg)
{
    (void)arg;
    switch (m->event) {
    case USB_HOST_CLIENT_EVENT_NEW_DEV: read_device(m->new_dev.address); break;
    case USB_HOST_CLIENT_EVENT_DEV_GONE:
        if (m->dev_gone.dev_hdl == s_net.dev) {atomic_store(&s_net.gone, true); atomic_store(&s_net.link, false);}
        device_removed(-1);
        break;
    case USB_HOST_CLIENT_EVENT_DEV_REMOVED: device_removed(m->dev_removed.address); break;
    default: break;
    }
}

static void client_task(void *arg)
{
    (void)arg;
    for (;;) usb_host_client_handle_events(s_client, portMAX_DELAY);
}

static void lib_task(void *arg)
{
    (void)arg;
    for (;;) {
        uint32_t flags = 0;
        usb_host_lib_handle_events(portMAX_DELAY, &flags);
        if (flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) usb_host_device_free_all();
    }
}

static size_t internal_free(void) {return heap_caps_get_free_size(MALLOC_CAP_INTERNAL);}

esp_err_t usb_port_start(const char **why)
{
    *why = "";
    if (s_started) return ESP_OK;
    size_t before = internal_free();
    s_mem.free_at_start = (uint32_t)before;
    if (!usbp_fits(before, USBP_HOST_ESTIMATE)) {
        *why = "not enough internal RAM for the USB port (it keeps 40 KB free for the rest of the gateway): turn off unused features";
        return ESP_ERR_NO_MEM;
    }
    s_lock = xSemaphoreCreateMutex();
    s_changed = xSemaphoreCreateBinary();
    s_done = xSemaphoreCreateBinary();
    s_cfg = heap_caps_malloc(USBP_CFG_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s_lock || !s_changed || !s_done || !s_cfg) {*why = "no memory for the USB port"; return ESP_ERR_NO_MEM;}
    usb_host_config_t host = {.skip_phy_setup = false, .intr_flags = ESP_INTR_FLAG_LOWMED};
#if CONFIG_USB_HOST_ENABLE_ENUM_FILTER_CALLBACK
    host.enum_filter_cb = enum_filter;
#endif
    esp_err_t err = usb_host_install(&host);
    if (err != ESP_OK) {*why = "the USB host did not start"; return err;}
    s_started = true;   /* the PHY now belongs to the OTG host until restart */
    if (xTaskCreatePinnedToCoreWithCaps(lib_task, "usb_lib", 3072, NULL, 7, NULL, tskNO_AFFINITY,
                                        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {*why = "no memory for the USB task"; return ESP_ERR_NO_MEM;}
    const usb_host_client_config_t client = {.is_synchronous = false, .max_num_event_msg = 5,
                                             .async = {.client_event_callback = client_event, .callback_arg = NULL}};
    if ((err = usb_host_client_register(&client, &s_client)) != ESP_OK) {*why = "the USB host did not start"; return err;}
    if (xTaskCreatePinnedToCoreWithCaps(client_task, "usb_port", 4096, NULL, 7, NULL, tskNO_AFFINITY,
                                        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {*why = "no memory for the USB task"; return ESP_ERR_NO_MEM;}
    size_t after = internal_free();
    s_mem.host_bytes = (uint32_t)(before > after ? before - after : 0);
    ESP_LOGI(TAG, "USB host started: %u bytes of internal RAM, %u free", (unsigned)s_mem.host_bytes, (unsigned)after);
    return ESP_OK;
}

void usb_port_memory(usbp_memory_t *out)
{
    *out = s_mem;
    out->free_now = (uint32_t)internal_free();
    out->min_free = (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
}

bool usb_port_device(usbp_device_t *out, uint8_t *cfg, size_t cap, size_t *len)
{
    if (!s_started) {memset(out, 0, sizeof *out); if (len) *len = 0; return false;}
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *out = s_dev;
    size_t n = s_cfg_len < cap ? s_cfg_len : cap;
    if (cfg && n) memcpy(cfg, s_cfg, n);
    if (len) *len = n;
    xSemaphoreGive(s_lock);
    return out->present;
}

void usb_port_wait(uint32_t seq, uint32_t ms)
{
    if (!s_started) {vTaskDelay(pdMS_TO_TICKS(ms)); return;}
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool same = s_dev.seq == seq;
    xSemaphoreGive(s_lock);
    if (same) xSemaphoreTake(s_changed, pdMS_TO_TICKS(ms));
}

/* --- Synchronous transfers for the owner task (bounded) --- */
static void done_cb(usb_transfer_t *t) {(void)t; xSemaphoreGive(s_done);}

/* false: the transfer may still be in flight and must not be reused. */
static bool xfer(usb_transfer_t *t, bool control, uint32_t ms, esp_err_t *result)
{
    t->callback = done_cb;
    t->context = NULL;
    xSemaphoreTake(s_done, 0);
    esp_err_t err = control ? usb_host_transfer_submit_control(s_client, t) : usb_host_transfer_submit(t);
    if (err != ESP_OK) {*result = err; return true;}
    if (xSemaphoreTake(s_done, pdMS_TO_TICKS(ms)) == pdTRUE) {
        *result = t->status == USB_TRANSFER_STATUS_COMPLETED ? ESP_OK : ESP_FAIL;
        return true;
    }
    *result = ESP_ERR_TIMEOUT;
    if (control) return false;   /* EP0 cannot be cancelled here */
    usb_host_endpoint_halt(t->device_handle, t->bEndpointAddress);
    usb_host_endpoint_flush(t->device_handle, t->bEndpointAddress);
    bool finished = xSemaphoreTake(s_done, pdMS_TO_TICKS(1000)) == pdTRUE;
    usb_host_endpoint_clear(t->device_handle, t->bEndpointAddress);
    return finished;
}

static bool control(usb_transfer_t *t, uint8_t type, uint8_t request, uint16_t value, uint16_t index,
                    const void *data, uint16_t length, esp_err_t *result)
{
    if (8u + length > t->data_buffer_size) {*result = ESP_ERR_INVALID_SIZE; return true;}
    usb_setup_packet_t *s = (usb_setup_packet_t *)t->data_buffer;
    s->bmRequestType = type; s->bRequest = request; s->wValue = value; s->wIndex = index; s->wLength = length;
    if (data && !(type & 0x80)) memcpy(t->data_buffer + 8, data, length);
    t->num_bytes = 8 + length;
    t->bEndpointAddress = 0;
    return xfer(t, true, 1000, result);
}

esp_err_t usb_port_switch(const usbp_device_t *d, const usbp_storage_t *st)
{
    if (s_poisoned) return ESP_ERR_INVALID_STATE;
    for (unsigned i = 0; i < s_switched_count; i++)
        if (s_switched[i].vid == d->vid && s_switched[i].pid == d->pid) return ESP_ERR_INVALID_STATE;
    if (s_switched_count < sizeof s_switched / sizeof s_switched[0])
        s_switched[s_switched_count++] = (typeof(s_switched[0])){d->vid, d->pid};
    usbp_msw_t plan;
    usbp_msw_plan(d->vid, d->pid, &plan);
    usb_device_handle_t h;
    esp_err_t err = usb_host_device_open(s_client, d->address, &h);
    if (err != ESP_OK) return err;
    usb_transfer_t *t = NULL;
    bool reusable = true;
    if ((err = usb_host_interface_claim(s_client, h, st->iface, 0)) != ESP_OK) goto close;
    if ((err = usb_host_transfer_alloc(512, 0, &t)) != ESP_OK) goto release;
    t->device_handle = h;
    ESP_LOGI(TAG, "switching %04x:%04x out of storage mode (%u messages)", d->vid, d->pid, plan.count);
    for (unsigned i = 0; i < plan.count && reusable; i++) {
        esp_err_t r;
        memcpy(t->data_buffer, plan.message[i], USBP_CBW_LEN);
        t->bEndpointAddress = st->ep_out;
        t->num_bytes = USBP_CBW_LEN;
        t->flags = 0;
        if (!(reusable = xfer(t, false, 1000, &r)) || r != ESP_OK) break;   /* often gone at once: done */
        uint32_t data_len = usbp_le32(plan.message[i] + 8);
        t->bEndpointAddress = st->ep_in;
        if (data_len && (plan.message[i][12] & 0x80)) {           /* data stage, IN */
            t->num_bytes = data_len > 448 ? 512 : (int)((data_len + 63) / 64 * 64);
            if (!(reusable = xfer(t, false, 1000, &r))) break;
        }
        t->num_bytes = 64;                                        /* status (CSW, 13 bytes) */
        reusable = xfer(t, false, 1000, &r);
    }
release:
    usb_host_interface_release(s_client, h, st->iface);
close:
    if (t && reusable) usb_host_transfer_free(t);
    if (!reusable) s_poisoned = true;
    usb_host_device_close(s_client, h);
    return err;
}

bool usb_port_next_config(const usbp_device_t *d)
{
#if CONFIG_USB_HOST_ENABLE_ENUM_FILTER_CALLBACK
    uint8_t next = usbp_next_config(d->num_configs, d->config_value);
    if (!next) return false;
    bool ok = false;
    portENTER_CRITICAL(&s_choice_mux);
    for (unsigned i = 0; i < sizeof s_choice / sizeof s_choice[0] && !ok; i++) {
        bool mine = s_choice[i].vid == d->vid && s_choice[i].pid == d->pid;
        if (!mine && (s_choice[i].vid || s_choice[i].pid)) continue;
        if (s_choice[i].tries >= USBP_MAX_CONFIGS) break;
        s_choice[i] = (typeof(s_choice[0])){d->vid, d->pid, next, (uint8_t)(s_choice[i].tries + 1)};
        ok = true;
    }
    portEXIT_CRITICAL(&s_choice_mux);
    if (!ok) return false;
    ESP_LOGI(TAG, "%04x:%04x: trying configuration %u", d->vid, d->pid, next);
    /* Re-enumerate: the device sees a port reset (its 5 V supply is external). */
    usb_host_lib_set_root_port_power(false);
    vTaskDelay(pdMS_TO_TICKS(300));
    usb_host_lib_set_root_port_power(true);
    return true;
#else
    (void)d;
    return false;
#endif
}

/* --- esp_netif glue (network sessions) --- */
typedef struct {esp_netif_driver_base_t base;} usbp_glue_t;
static usbp_glue_t s_glue;

static void out_cb(usb_transfer_t *t)
{
    if (t->status == USB_TRANSFER_STATUS_NO_DEVICE) atomic_store(&s_net.gone, true);
    else if (t->status == USB_TRANSFER_STATUS_COMPLETED) atomic_fetch_add(&s_tx_bytes, (unsigned long long)t->actual_num_bytes);
    atomic_store(&s_net.out_busy[(intptr_t)t->context], false);
    atomic_fetch_sub(&s_net.inflight, 1);
}

static esp_err_t glue_transmit(void *handle, void *buffer, size_t len)
{
    (void)handle;
    if (s_net.kind == USBP_SERIAL || !atomic_load(&s_net.running) || atomic_load(&s_net.gone) || !atomic_load(&s_net.link)) {
        atomic_fetch_add(&s_tx_dropped, 1);
        return ESP_FAIL;
    }
    for (int i = 0; i < s_net.n_out; i++) {
        if (atomic_exchange(&s_net.out_busy[i], true)) continue;
        usb_transfer_t *t = s_net.out[i];
        size_t cap = t->data_buffer_size < s_net.out_max ? t->data_buffer_size : s_net.out_max, n = 0;
        if (s_net.kind == USBP_NET_ECM) {if (len <= cap) {memcpy(t->data_buffer, buffer, len); n = len;}}
        else if (s_net.kind == USBP_NET_NCM) n = usbp_ncm_wrap(t->data_buffer, cap, buffer, len, s_net.seq++, s_net.ncm_div, s_net.ncm_rem);
        else n = usbp_rndis_wrap(t->data_buffer, cap, buffer, len);
        if (!n) {atomic_store(&s_net.out_busy[i], false); break;}
        t->num_bytes = (int)n;
        t->flags = USB_TRANSFER_FLAG_ZERO_PACK;   /* end a frame of exactly N packets */
        atomic_fetch_add(&s_net.inflight, 1);
        if (usb_host_transfer_submit(t) == ESP_OK) return ESP_OK;
        atomic_fetch_sub(&s_net.inflight, 1);
        atomic_store(&s_net.out_busy[i], false);
        break;
    }
    atomic_fetch_add(&s_tx_dropped, 1);   /* both transfers busy: never wait in TCP/IP */
    return ESP_FAIL;
}

static void glue_free_rx(void *handle, void *buffer) {(void)handle; free(buffer);}

static esp_err_t glue_post_attach(esp_netif_t *netif, void *args)
{
    usbp_glue_t *g = args;
    g->base.netif = netif;
    const esp_netif_driver_ifconfig_t ifconfig = {.handle = g, .transmit = glue_transmit, .driver_free_rx_buffer = glue_free_rx};
    return esp_netif_set_driver_config(netif, &ifconfig);
}

void *usb_port_net_glue(void)
{
    s_glue.base.post_attach = glue_post_attach;
    return &s_glue;
}

static void deliver(const uint8_t *frame, size_t len)
{
    if (len < 14 || len > 1514) {atomic_fetch_add(&s_rx_dropped, 1); return;}
    uint8_t *copy = heap_caps_malloc(len, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!copy) {atomic_fetch_add(&s_rx_dropped, 1); return;}
    memcpy(copy, frame, len);
    atomic_fetch_add(&s_rx_bytes, (unsigned long long)len);
    esp_netif_receive(s_net.netif, copy, len, NULL);   /* frees through glue_free_rx */
}

static void set_link(bool up)
{
    atomic_store(&s_net.link_known, true);
    if (atomic_exchange(&s_net.link, up) == up) return;
    if (up) esp_netif_action_connected(s_net.netif, NULL, 0, NULL);
    else esp_netif_action_disconnected(s_net.netif, NULL, 0, NULL);
    if (s_net.link_cb) s_net.link_cb(up, s_net.ctx);
}

static void resubmit(usb_transfer_t *t)
{
    if (!atomic_load(&s_net.running) || atomic_load(&s_net.gone)) return;
    t->num_bytes = (int)t->data_buffer_size;
    atomic_fetch_add(&s_net.inflight, 1);
    if (usb_host_transfer_submit(t) != ESP_OK) {atomic_fetch_sub(&s_net.inflight, 1); atomic_store(&s_net.gone, true);}
}

static void in_cb(usb_transfer_t *t)
{
    atomic_fetch_sub(&s_net.inflight, 1);
    if (t->status == USB_TRANSFER_STATUS_NO_DEVICE) {atomic_store(&s_net.gone, true); return;}
    if (!atomic_load(&s_net.running)) return;
    if (t->status == USB_TRANSFER_STATUS_COMPLETED) atomic_store(&s_rx_errors, 0);
    if (t->status == USB_TRANSFER_STATUS_COMPLETED && t->actual_num_bytes > 0) {
        size_t n = (size_t)t->actual_num_bytes;
        const uint8_t *frame;
        size_t flen;
        if (s_net.kind == USBP_SERIAL) {
            size_t sent = xStreamBufferSend(s_net.rx, t->data_buffer, n, 0);
            if (sent < n) atomic_fetch_add(&s_rx_dropped, (unsigned)(n - sent));   /* PPP/TCP recover */
        } else if (s_net.kind == USBP_NET_ECM) deliver(t->data_buffer, n);
        else if (s_net.kind == USBP_NET_NCM) {
            usbp_ncm_rx_t it = {0};
            int r;
            while ((r = usbp_ncm_next(t->data_buffer, n, &it, &frame, &flen)) == 1) deliver(frame, flen);
            if (r < 0) atomic_fetch_add(&s_rx_dropped, 1);
        } else {
            size_t off = 0;
            int r;
            while ((r = usbp_rndis_next(t->data_buffer, n, &off, &frame, &flen)) == 1) deliver(frame, flen);
            if (r < 0) atomic_fetch_add(&s_rx_dropped, 1);
        }
    } else if (t->status != USB_TRANSFER_STATUS_COMPLETED && atomic_fetch_add(&s_rx_errors, 1) > 1000) {
        atomic_store(&s_net.gone, true);   /* 1000 failures in a row: end the session */
        return;
    }
    resubmit(t);
}

static void notify_cb(usb_transfer_t *t)
{
    atomic_fetch_sub(&s_net.inflight, 1);
    if (t->status == USB_TRANSFER_STATUS_NO_DEVICE) {atomic_store(&s_net.gone, true); return;}
    if (!atomic_load(&s_net.running)) return;
    const uint8_t *n = t->data_buffer;
    /* CDC NETWORK_CONNECTION: bmRequestType 0xA1, code 0x00, wValue 1/0. */
    if (t->status == USB_TRANSFER_STATUS_COMPLETED && t->actual_num_bytes >= 8 && n[0] == 0xa1 && n[1] == 0x00
        && (s_net.kind == USBP_NET_ECM || s_net.kind == USBP_NET_NCM))
        set_link(usbp_le16(n + 2) != 0);
    resubmit(t);
}

static void free_transfers(void)
{
    usb_transfer_t **all[] = {&s_net.in[0], &s_net.in[1], &s_net.out[0], &s_net.out[1], &s_net.notify, &s_net.ctrl_xfer};
    for (unsigned i = 0; i < sizeof all / sizeof all[0]; i++) {
        if (*all[i] && !s_net.leaked) usb_host_transfer_free(*all[i]);
        *all[i] = NULL;
    }
}

static esp_err_t alloc(size_t size, usb_transfer_t **t, uint8_t ep, usb_transfer_cb_t cb, intptr_t ctx)
{
    esp_err_t err = usb_host_transfer_alloc(size, 0, t);
    if (err != ESP_OK) return err;
    (*t)->device_handle = s_net.dev;
    (*t)->bEndpointAddress = ep;
    (*t)->callback = cb;
    (*t)->context = (void *)ctx;
    return ESP_OK;
}

/* RNDIS control exchange: command, then poll the response (bounded). */
static bool rndis_exchange(const uint8_t *msg, size_t len, uint32_t type, uint32_t request_id, uint8_t *info_out, size_t info_cap, size_t *info_len)
{
    esp_err_t r;
    if (!control(s_net.ctrl_xfer, 0x21, 0x00, 0, s_net.ctrl, msg, (uint16_t)len, &r)) {s_net.leaked = true; return false;}
    if (r != ESP_OK) return false;
    for (int i = 0; i < 20; i++) {
        vTaskDelay(pdMS_TO_TICKS(i ? 50 : 10));
        if (!control(s_net.ctrl_xfer, 0xa1, 0x01, 0, s_net.ctrl, NULL, 256, &r)) {s_net.leaked = true; return false;}
        if (r != ESP_OK) continue;
        const uint8_t *info;
        size_t n = (size_t)(s_net.ctrl_xfer->actual_num_bytes > 8 ? s_net.ctrl_xfer->actual_num_bytes - 8 : 0), ilen;
        if (!usbp_rndis_cmplt(s_net.ctrl_xfer->data_buffer + 8, n, type, request_id, &info, &ilen)) continue;
        if (info_out && info && ilen <= info_cap) {memcpy(info_out, info, ilen); if (info_len) *info_len = ilen;}
        return true;
    }
    return false;
}

static bool device_mac(uint8_t mac[6])
{
    esp_err_t r;
    if (s_net.kind == USBP_NET_RNDIS) {
        uint8_t msg[32];
        size_t n = 0;
        return rndis_exchange(msg, usbp_rndis_query(msg, sizeof msg, 2, 0x01010101u), 0x00000004u, 2, mac, 6, &n) && n == 6
               && !(mac[0] & 1);
    }
    if (!s_net.mac_index) return false;
    if (!control(s_net.ctrl_xfer, 0x80, 0x06, (uint16_t)(0x0300 | s_net.mac_index), 0x0409, NULL, 64, &r)) {s_net.leaked = true; return false;}
    return r == ESP_OK && s_net.ctrl_xfer->actual_num_bytes > 8
           && usbp_mac_string(s_net.ctrl_xfer->data_buffer + 8, (size_t)s_net.ctrl_xfer->actual_num_bytes - 8, mac);
}

static esp_err_t net_init(const char **why)
{
    esp_err_t r;
    s_net.out_max = USBP_TX_SIZE;
    if (s_net.kind == USBP_NET_NCM) {
        /* NTB parameters while the data interface is at alternate setting 0. */
        if (!control(s_net.ctrl_xfer, 0xa1, 0x80, 0, s_net.ctrl, NULL, 28, &r)) {s_net.leaked = true; *why = "USB device stopped answering"; return ESP_FAIL;}
        if (r != ESP_OK || s_net.ctrl_xfer->actual_num_bytes < 8 + 28) {*why = "NCM parameters unreadable"; return ESP_FAIL;}
        const uint8_t *p = s_net.ctrl_xfer->data_buffer + 8;
        uint32_t in_max = usbp_le32(p + 4), out_max = usbp_le32(p + 16);
        s_net.ncm_div = usbp_le16(p + 20); s_net.ncm_rem = usbp_le16(p + 22);
        if (out_max && out_max < s_net.out_max) s_net.out_max = out_max;
        if (in_max > USBP_NCM_RX) {
            uint8_t size[4];
            usbp_put32(size, USBP_NCM_RX);
            if (!control(s_net.ctrl_xfer, 0x21, 0x86, 0, s_net.ctrl, size, 4, &r)) {s_net.leaked = true; *why = "USB device stopped answering"; return ESP_FAIL;}
            if (r != ESP_OK) {*why = "NCM device refused a 2 KB receive block"; return ESP_FAIL;}
        }
    }
    if (s_net.kind == USBP_NET_ECM || s_net.kind == USBP_NET_NCM) {
        /* Directed, broadcast and all multicast: optional, failures ignored. */
        if (!control(s_net.ctrl_xfer, 0x21, 0x43, 0x000e, s_net.ctrl, NULL, 0, &r)) {s_net.leaked = true; *why = "USB device stopped answering"; return ESP_FAIL;}
        return ESP_OK;
    }
    uint8_t msg[32];
    if (!rndis_exchange(msg, usbp_rndis_init(msg, sizeof msg, 1, USBP_FRAME_RX), 0x00000002u, 1, NULL, 0, NULL)) {
        *why = "RNDIS device did not initialise";
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Internal RAM the session's transfers need (buffers plus an overhead estimate). */
static size_t session_need(uint8_t kind, bool notify)
{
    size_t rx = kind == USBP_SERIAL ? USBP_SERIAL_IN : kind == USBP_NET_NCM ? USBP_NCM_RX : USBP_FRAME_RX;
    size_t need = 2 * rx + USBP_CTRL_SIZE + (kind == USBP_SERIAL ? USBP_SERIAL_OUT : 2 * USBP_TX_SIZE)
                  + (notify ? USBP_NOTIFY_SIZE : 0);
    return need + 6 * USBP_TRANSFER_OVERHEAD;
}

static esp_err_t session_open(const usbp_device_t *d, const usbp_net_t *f, esp_netif_t *netif,
                              usbp_link_cb_t link, void *ctx, const char **why)
{
    usb_port_net_close();
    *why = "USB device not ready";
    if (s_poisoned) {*why = "the USB device stopped answering: restart the gateway to retry"; return ESP_ERR_INVALID_STATE;}
    bool serial = f->kind == USBP_SERIAL, notify = !serial && f->ep_notify;
    size_t need = session_need(f->kind, notify), before = internal_free();
    if (!usbp_fits(before, need)) {
        static char text[160];
        snprintf(text, sizeof text, "not enough internal RAM for this USB device: about %u KB needed, %u KB free, 40 KB kept for the rest of the gateway; turn off unused features",
                 (unsigned)((need + 1023) / 1024), (unsigned)(before / 1024));
        *why = text;
        return ESP_ERR_NO_MEM;
    }
    s_net.kind = f->kind; s_net.ctrl = f->ctrl; s_net.data = f->data; s_net.data_alt = f->data_alt;
    s_net.ep_in = f->ep_in; s_net.ep_out = f->ep_out; s_net.ep_notify = notify ? f->ep_notify : 0; s_net.mac_index = f->mac_index;
    s_net.netif = netif;
    s_net.link_cb = link;
    s_net.ctx = ctx;
    s_net.leaked = false;
    atomic_store(&s_net.gone, false);
    atomic_store(&s_net.link, false);
    atomic_store(&s_net.link_known, false);
    atomic_store(&s_net.inflight, 0);
    esp_err_t err = usb_host_device_open(s_client, d->address, &s_net.dev);
    if (err != ESP_OK) {s_net.dev = NULL; *why = "USB device gone"; return err;}
    if ((err = alloc(USBP_CTRL_SIZE, &s_net.ctrl_xfer, 0, done_cb, 0)) != ESP_OK) goto fail;
    if (f->ctrl != f->data) {
        if ((err = usb_host_interface_claim(s_client, s_net.dev, f->ctrl, 0)) != ESP_OK) {*why = "USB control interface busy"; goto fail;}
        s_net.claimed_ctrl = true;
    }
    if (!serial && (err = net_init(why)) != ESP_OK) goto fail;
    if ((err = usb_host_interface_claim(s_client, s_net.dev, f->data, f->data_alt)) != ESP_OK) {*why = "USB data interface refused"; goto fail;}
    s_net.claimed_data = true;
    if (serial) {
        esp_err_t r;
        /* CDC-ACM: DTR and RTS on; many modems ignore data without DTR. */
        if (f->ctrl != f->data && !control(s_net.ctrl_xfer, 0x21, 0x22, 0x0003, f->ctrl, NULL, 0, &r)) s_net.leaked = true;
        if (!s_net.rx) s_net.rx = xStreamBufferCreateWithCaps(USBP_SERIAL_RX_BUFFER, 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!s_net.rx) {*why = "no memory for the USB serial buffer"; err = ESP_ERR_NO_MEM; goto fail;}
        uint8_t sink[64];
        while (xStreamBufferReceive(s_net.rx, sink, sizeof sink, 0) > 0) {}
    } else {
        uint8_t mac[6];
        if (!device_mac(mac)) {
            /* A locally administered address from this board's Ethernet MAC. */
            esp_read_mac(mac, ESP_MAC_ETH);
            mac[0] = (uint8_t)((mac[0] | 0x02) & ~0x01);
        }
        if (f->kind == USBP_NET_RNDIS && !s_net.leaked) {
            uint8_t msg[32];
            /* Directed, multicast, broadcast. */
            if (!rndis_exchange(msg, usbp_rndis_set(msg, sizeof msg, 3, 0x0001010eu, 0x0000000du), 0x00000005u, 3, NULL, 0, NULL)) {
                *why = "RNDIS device refused the packet filter";
                err = ESP_FAIL;
                goto fail;
            }
        }
        esp_netif_set_mac(netif, mac);
    }
    if (s_net.leaked) {*why = "USB device stopped answering"; err = ESP_FAIL; goto fail;}
    size_t rx = serial ? USBP_SERIAL_IN : f->kind == USBP_NET_NCM ? USBP_NCM_RX : USBP_FRAME_RX;
    s_net.n_out = serial ? 1 : 2;
    if (serial) s_net.out_max = USBP_SERIAL_OUT;
    for (int i = 0; i < 2 && err == ESP_OK; i++) err = alloc(rx, &s_net.in[i], f->ep_in, in_cb, i);
    for (int i = 0; i < s_net.n_out && err == ESP_OK; i++) err = alloc(serial ? USBP_SERIAL_OUT : USBP_TX_SIZE, &s_net.out[i], f->ep_out, out_cb, i);
    if (err == ESP_OK && notify) err = alloc(USBP_NOTIFY_SIZE, &s_net.notify, f->ep_notify, notify_cb, 0);
    if (err != ESP_OK) {*why = "no memory for the USB transfers"; goto fail;}
    atomic_store(&s_net.out_busy[0], false);
    atomic_store(&s_net.out_busy[1], false);
    s_net.opened = xTaskGetTickCount();
    atomic_store(&s_net.running, true);
    if (!serial) esp_netif_action_start(netif, NULL, 0, NULL);
    for (int i = 0; i < 2; i++) resubmit(s_net.in[i]);
    if (s_net.notify) resubmit(s_net.notify);
    if (!serial && (f->kind == USBP_NET_RNDIS || !notify)) set_link(true);
    size_t after = internal_free();
    s_mem.session_bytes = (uint32_t)(before > after ? before - after : 0);
    ESP_LOGI(TAG, "%04x:%04x %s on interface %u: %u bytes of internal RAM, %u free", d->vid, d->pid,
             serial ? "serial port" : f->kind == USBP_NET_ECM ? "CDC-ECM" : f->kind == USBP_NET_NCM ? "CDC-NCM" : "RNDIS",
             f->data, (unsigned)s_mem.session_bytes, (unsigned)after);
    return ESP_OK;
fail:
    usb_port_net_close();
    return err == ESP_OK ? ESP_FAIL : err;
}

esp_err_t usb_port_net_open(const usbp_device_t *d, const usbp_net_t *fn, esp_netif_t *netif,
                            usbp_link_cb_t link, void *ctx, const char **why)
{
    if (fn->kind != USBP_NET_ECM && fn->kind != USBP_NET_NCM && fn->kind != USBP_NET_RNDIS) {*why = "not a USB network function"; return ESP_ERR_INVALID_ARG;}
    return session_open(d, fn, netif, link, ctx, why);
}

esp_err_t usb_port_serial_open(const usbp_device_t *d, const usbp_net_t *port, const char **why)
{
    if (port->kind != USBP_SERIAL) {*why = "not a USB serial interface"; return ESP_ERR_INVALID_ARG;}
    return session_open(d, port, NULL, NULL, NULL, why);
}

int usb_port_serial_write(const void *data, size_t len, uint32_t timeout_ms)
{
    const uint8_t *p = data;
    size_t done = 0;
    TickType_t end = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while (done < len) {
        if (s_net.kind != USBP_SERIAL || !atomic_load(&s_net.running) || atomic_load(&s_net.gone)) return -1;
        if (atomic_exchange(&s_net.out_busy[0], true)) {
            if ((int32_t)(end - xTaskGetTickCount()) <= 0) {atomic_fetch_add(&s_tx_dropped, 1); return -1;}
            vTaskDelay(1);
            continue;
        }
        usb_transfer_t *t = s_net.out[0];
        size_t n = len - done < USBP_SERIAL_OUT ? len - done : USBP_SERIAL_OUT;
        memcpy(t->data_buffer, p + done, n);
        t->num_bytes = (int)n;
        t->flags = 0;
        atomic_fetch_add(&s_net.inflight, 1);
        if (usb_host_transfer_submit(t) != ESP_OK) {
            atomic_fetch_sub(&s_net.inflight, 1);
            atomic_store(&s_net.out_busy[0], false);
            return -1;
        }
        done += n;
    }
    return (int)len;
}

int usb_port_serial_read(uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    if (s_net.kind != USBP_SERIAL || !s_net.rx || !atomic_load(&s_net.running) || atomic_load(&s_net.gone)) return -1;
    return (int)xStreamBufferReceive(s_net.rx, buf, cap, pdMS_TO_TICKS(timeout_ms));
}

void usb_port_serial_flush(void)
{
    uint8_t sink[64];
    if (!s_net.rx) return;
    while (xStreamBufferReceive(s_net.rx, sink, sizeof sink, 0) > 0) {}
}

bool usb_port_net_alive(void)
{
    if (!atomic_load(&s_net.running) || atomic_load(&s_net.gone)) return false;
    /* No NETWORK_CONNECTION notice after 5 s: assume the link is up (DHCP
     * still has to succeed before the uplink is used). */
    if (s_net.kind != USBP_SERIAL && !atomic_load(&s_net.link_known) && xTaskGetTickCount() - s_net.opened > pdMS_TO_TICKS(5000))
        set_link(true);
    return true;
}

void usb_port_net_close(void)
{
    bool was_running = atomic_exchange(&s_net.running, false);
    if (!s_net.dev) {free_transfers(); return;}
    uint8_t eps[] = {s_net.ep_in, s_net.ep_out, s_net.ep_notify};
    for (unsigned i = 0; i < sizeof eps; i++) {
        if (!eps[i]) continue;
        usb_host_endpoint_halt(s_net.dev, eps[i]);
        usb_host_endpoint_flush(s_net.dev, eps[i]);
    }
    for (int i = 0; i < 100 && atomic_load(&s_net.inflight) > 0; i++) vTaskDelay(pdMS_TO_TICKS(10));
    if (atomic_load(&s_net.inflight) > 0) s_net.leaked = true;   /* never free a transfer in flight */
    for (unsigned i = 0; i < sizeof eps; i++) if (eps[i]) usb_host_endpoint_clear(s_net.dev, eps[i]);
    if (was_running && s_net.netif && s_net.kind != USBP_SERIAL) {
        if (atomic_exchange(&s_net.link, false)) {
            esp_netif_action_disconnected(s_net.netif, NULL, 0, NULL);
            if (s_net.link_cb) s_net.link_cb(false, s_net.ctx);
        }
        esp_netif_action_stop(s_net.netif, NULL, 0, NULL);
    }
    if (s_net.claimed_data) usb_host_interface_release(s_client, s_net.dev, s_net.data);
    if (s_net.claimed_ctrl) usb_host_interface_release(s_client, s_net.dev, s_net.ctrl);
    s_net.claimed_data = s_net.claimed_ctrl = false;
    if (s_net.leaked) s_poisoned = true;
    free_transfers();
    usb_host_device_close(s_client, s_net.dev);
    s_net.dev = NULL;
}

void usb_port_counters(uint32_t *rx_dropped, uint32_t *tx_dropped, uint64_t *rx_bytes, uint64_t *tx_bytes)
{
    if (rx_dropped) *rx_dropped = atomic_load(&s_rx_dropped);
    if (tx_dropped) *tx_dropped = atomic_load(&s_tx_dropped);
    if (rx_bytes) *rx_bytes = atomic_load(&s_rx_bytes);
    if (tx_bytes) *tx_bytes = atomic_load(&s_tx_bytes);
}
#endif /* CONFIG_SOC_USB_OTG_SUPPORTED */
#endif /* !USBP_HOST_TEST */
