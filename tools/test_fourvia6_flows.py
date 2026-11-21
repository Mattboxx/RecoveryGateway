"""Host regression of the actual 4via6 flow table and header size rules."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "main/fourvia6.c").read_text(encoding="utf-8")
LIMITS = SOURCE[SOURCE.index("#define FOURVIA6_FLOW_COUNT"):SOURCE.index("static const char *TAG")]
TYPES = SOURCE[SOURCE.index("typedef struct {"):SOURCE.index("static bool s_enabled")]
FLOWS = SOURCE[SOURCE.index("static void flow_remember"):SOURCE.index("bool fourvia6_translate_wg_input")]
INPUT = SOURCE[SOURCE.index("bool fourvia6_translate_wg_input"):SOURCE.index("struct pbuf *fourvia6_translate_wg_output")]
OUTPUT = SOURCE[SOURCE.index("struct pbuf *fourvia6_translate_wg_output"):]
assert INPUT.index("payload_len < transport_header_size(protocol)") < INPUT.index("pbuf_alloc")
assert OUTPUT.index("total < ihl + transport_header_size(protocol)") < OUTPUT.index("pbuf_alloc")

PRELUDE = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int64_t clock_us;
static int64_t esp_timer_get_time(void) { return clock_us; }
#define taskENTER_CRITICAL(lock) ((void)0)
#define taskEXIT_CRITICAL(lock) ((void)0)
"""

TEST = r"""
static void remember(uint8_t protocol, uint16_t port)
{
    const uint8_t source[16] = {0xfd, 1};
    flow_remember(source, 0x64400002, 0xc0000201, protocol, port, 443);
}

static bool lookup(uint8_t protocol, uint16_t port)
{
    fourvia6_flow_t out;
    return flow_lookup(0x64400002, 0xc0000201, protocol, port, 443, &out);
}

int main(void)
{
    assert(transport_header_size(6) == 20);
    assert(transport_header_size(17) == 8);
    assert(transport_header_size(1) == 8);
    assert(transport_header_size(58) == 8);

    clock_us = 1000000;
    remember(6, 30000);
    remember(17, 30001);
    remember(1, 30002);
    clock_us += FOURVIA6_UDP_TIMEOUT_US + 1;
    remember(17, 30001);
    assert(lookup(17, 30001));
    assert(lookup(6, 30000));   /* UDP lookups cannot expire a TCP flow. */
    assert(!lookup(1, 30002));  /* ICMP keeps its shorter lifetime. */
    assert(lookup(17, 30001));

    memset(s_flows, 0, sizeof s_flows);
    for (uint16_t k = 0; k < FOURVIA6_FLOW_COUNT; ++k) {
        ++clock_us;
        remember(6, 30100 + k);
    }
    uint16_t first_slot_port = s_flows[0].client_port;
    ++clock_us;
    remember(6, first_slot_port);
    ++clock_us;
    remember(6, 31000);
    assert(lookup(6, first_slot_port));
    assert(!lookup(6, 30101));
    assert(lookup(6, 31000));

    memset(s_flows, 0, sizeof s_flows);
    for (uint16_t k = 0; k < FOURVIA6_FLOW_COUNT - 1; ++k)
        remember(6, 32000 + k);
    ++clock_us;
    remember(17, 32500);
    clock_us += FOURVIA6_UDP_TIMEOUT_US + 1;
    remember(1, 32600);
    for (uint16_t k = 0; k < FOURVIA6_FLOW_COUNT - 1; ++k)
        assert(lookup(6, 32000 + k));
    assert(!lookup(17, 32500));
    assert(lookup(1, 32600));
    puts("4via6 flow expiry, capacity and transport header rules PASS");
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix="recoverygateway-fourvia6-") as work:
    root = Path(work)
    program = root / "test.c"
    binary = root / ("test.exe" if os.name == "nt" else "test")
    program.write_text("\n".join((PRELUDE, LIMITS, TYPES,
        "static fourvia6_flow_t s_flows[FOURVIA6_FLOW_COUNT];", FLOWS, TEST)),
        encoding="utf-8")
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
    if os.environ.get("HOTLOOP_SANITIZE") == "1":
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    subprocess.run([os.environ.get("CC", "gcc"), *flags, str(program), "-o", str(binary)],
        check=True)
    subprocess.run([str(binary)], check=True)
