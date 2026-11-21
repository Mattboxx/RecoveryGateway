"""Traffic per access-point device and HiLink parsing (actual cores).

main/ap_traffic.c core:
- bytes sent and received are counted per device MAC, separately;
- group (multicast/broadcast) and all-zero addresses are not devices;
- with every slot taken the device seen longest ago gives its slot up, and
  a device seen again starts from zero; unknown devices are not found.
main/cell_hilink.c core:
- XML values (first match, trimmed, bounded, absent/empty/too long refused),
  dBm text ("-73dBm", ">=-51dBm", "-105", implausible or junk -> 0),
  operator names reduced to printable ASCII; random input in bounds.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def core(path, begin, end):
    text = (ROOT / path).read_text(encoding='utf-8')
    return text[text.index(begin):text.index(end)]


PROGRAM = r'''
#define AP_TRAFFIC_HOST_TEST 1
#define HILINK_HOST_TEST 1
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ap_traffic.h"
#include "cell_hilink.h"
@@AP@@
typedef int esp_err_t,portMUX_TYPE;
#define ESP_OK 0
#define portMUX_INITIALIZER_UNLOCKED 0
#define EXT_RAM_BSS_ATTR
static bool ap_locked;
#define portENTER_CRITICAL(x) do {(void)(x); assert(!ap_locked); ap_locked=true;} while(0)
#define portEXIT_CRITICAL(x) do {(void)(x); assert(ap_locked); ap_locked=false;} while(0)
static int nvs_param_get_u8(const char *key,uint8_t *v){assert(key);*v=0;return 0;}
static int nvs_param_set_u8(const char *key,uint8_t v){assert(key&&v<=1);return 0;}
@@AP_RUNTIME@@
@@HL@@
int main(void)
{
    static ap_traffic_table_t t;
    uint8_t a[6] = {0x02, 1, 2, 3, 4, 5}, b[6] = {0x02, 1, 2, 3, 4, 6}, bc[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t mc[6] = {0x01, 0x00, 0x5e, 0, 0, 1}, zero[6] = {0};
    uint64_t s = 0, r = 0;
    uint8_t frame[14]={0};
    memcpy(frame+6,a,6);
    ap_traffic_init();ap_traffic_publish(true);assert(ap_traffic_on);
    ap_traffic_frame(frame,sizeof frame,8,true);
    assert(ap_traffic_get(a,&s,&r)&&s==8);
    ap_traffic_publish(false);
    /* Simulate a frame admitted by the outer hook before disabling. */
    ap_traffic_frame(frame,sizeof frame,10,true);
    ap_traffic_publish(true);assert(!ap_traffic_get(a,&s,&r));
    ap_traffic_frame(frame,sizeof frame,12,true);
    assert(ap_traffic_get(a,&s,&r)&&s==12);
    ap_traffic_add(&t, a, 100, true); ap_traffic_add(&t, a, 1500, false); ap_traffic_add(&t, a, 60, true);
    ap_traffic_add(&t, b, 10, false);
    assert(ap_traffic_find(&t, a, &s, &r) && s == 160 && r == 1500);
    assert(ap_traffic_find(&t, b, &s, &r) && s == 0 && r == 10);
    ap_traffic_add(&t, bc, 999, false); ap_traffic_add(&t, mc, 999, false); ap_traffic_add(&t, zero, 999, true);
    assert(!ap_traffic_find(&t, bc, &s, &r) && !ap_traffic_find(&t, mc, &s, &r) && !ap_traffic_find(&t, zero, &s, &r));
    int used = 0; for (int i = 0; i < AP_TRAFFIC_SLOTS; i++) used += t.e[i].used; assert(used == 2);
    /* fill: a is refreshed, so b is the oldest and gives its slot up */
    for (int i = 0; i < AP_TRAFFIC_SLOTS - 2; i++) {uint8_t m[6] = {0x02, 9, 9, 9, 9, (uint8_t)i}; ap_traffic_add(&t, m, 1, true);}
    ap_traffic_add(&t, a, 1, true);
    uint8_t n[6] = {0x02, 7, 7, 7, 7, 7};
    ap_traffic_add(&t, n, 5, true);
    assert(!ap_traffic_find(&t, b, &s, &r) && ap_traffic_find(&t, a, &s, &r) && s == 161);
    assert(ap_traffic_find(&t, n, &s, &r) && s == 5 && r == 0);
    ap_traffic_add(&t, b, 7, true);                                           /* back: from zero */
    assert(ap_traffic_find(&t, b, &s, &r) && s == 7 && r == 0);

    char v[64];
    const char *x = "<?xml version=\"1.0\"?><response><rssi>-73dBm</rssi><rsrp> &gt;=-95dBm </rsrp><FullName>Example Mobile\x01</FullName><e></e></response>";
    assert(hilink_xml_value(x, strlen(x), "rssi", v, sizeof v) && !strcmp(v, "-73dBm"));
    assert(hilink_xml_value(x, strlen(x), "FullName", v, sizeof v));
    char name[32]; hilink_clean_name(v, name, sizeof name); assert(!strcmp(name, "Example Mobile"));
    assert(!hilink_xml_value(x, strlen(x), "e", v, sizeof v) && !hilink_xml_value(x, strlen(x), "missing", v, sizeof v));
    assert(!hilink_xml_value(x, strlen(x), "FullName", v, 5));                  /* too long for the buffer */
    assert(!hilink_xml_value(x, 30, "rssi", v, sizeof v));                      /* the value is past the given length */
    const char *open_only = "<rssi>-70dBm";
    assert(!hilink_xml_value(open_only, strlen(open_only), "rssi", v, sizeof v));
    assert(hilink_dbm("-73dBm") == -73 && hilink_dbm(">=-51dBm") == -51 && hilink_dbm("-105") == -105);
    assert(hilink_dbm("") == 0 && hilink_dbm("abc") == 0 && hilink_dbm("-73dBmX") == 0 && hilink_dbm("-5") == 0 && hilink_dbm("-300dBm") == 0 && hilink_dbm(NULL) == 0);
    char small[4]; hilink_clean_name("Operator", small, sizeof small); assert(!strcmp(small, "Ope"));
    /* random input: bounded */
    unsigned seed = 1;
    for (int i = 0; i < 20000; i++) {
        char buf[96]; int len = 1 + (int)(seed % 95);
        for (int j = 0; j < len; j++) {seed = seed * 1103515245u + 12345u; buf[j] = "<>/rsi aFN-dBm0123456789"[(seed >> 16) % 24];}
        char *heap = malloc((size_t)len); memcpy(heap, buf, (size_t)len);
        (void)hilink_xml_value(heap, (size_t)len, "rssi", v, sizeof v);
        free(heap);
    }
    puts("ap traffic and hilink ok");
    return 0;
}
'''

source = PROGRAM.replace('@@AP@@', core('main/ap_traffic.c', '/* --- ap_traffic core (begin) --- */', '/* --- ap_traffic core (end) --- */')) \
    .replace('@@HL@@', core('main/cell_hilink.c', '/* --- hilink core (begin) --- */', '/* --- hilink core (end) --- */'))
ap_runtime = (ROOT / 'main/ap_traffic.c').read_text(encoding='utf-8').split('atomic_bool ap_traffic_on;', 1)[1].rsplit('#endif', 1)[0]
source = source.replace('@@AP_RUNTIME@@', 'atomic_bool ap_traffic_on;' + ap_runtime)
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    (tmp / 't.c').write_text(source, encoding='utf-8')
    exe = tmp / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-fsanitize=address,undefined'] if os.environ.get('AP_SANITIZE') == '1' else []
    subprocess.run(['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', *flags, '-I', str(ROOT / 'main'),
                    str(tmp / 't.c'), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and 'ap traffic and hilink ok' in out.stdout, (out.returncode, out.stdout, out.stderr)
print('ap traffic: per-device counts, group/zero addresses ignored, oldest slot reused; hilink: bounded XML, dBm, clean names')
