"""Noise upgrade answer (actual ml_coord.c upgrade_refusal()).

The upgrade succeeded when "101" appeared anywhere in the answer, so an
error page or a proxy answer containing those digits went on to fail later
with a misleading message; and every refusal was reported as "Noise
handshake failed". Now only the status line counts and the reason shown on
the Tailscale page and in the event history says what the server answered:
an unsupported client version, a wrong URL or a proxy that does not pass the
upgrade, refused access, rate limit, server error.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COORD = (ROOT / 'external/microlink/components/microlink/src/ml_coord.c').read_text(encoding='utf-8').replace('\r\n', '\n')


def function(sig):
    start = COORD.index(sig)
    return COORD[start:COORD.index('\n}\n', start) + 3]


hs = function('static int do_noise_handshake(')
assert hs.index('ml->noise_note = NULL;') < hs.index('ml->noise_note = upgrade_refusal(')
assert 'strstr((char *)resp, "101")' not in hs
assert 'note_ctrl_retry(ml, ml->noise_note ? ml->noise_note : "Noise handshake failed");' in COORD

PROGRAM = r"""
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
@@CODE@@
static void refused(const char *resp, const char *want){
    const char *n=upgrade_refusal(resp);
    if(!n||strcmp(n,want)){printf("%s -> %s (want %s)\n",resp,n?n:"NULL",want);fflush(stdout);abort();}
    assert(strlen(n)<48);   /* fits ctrl_retry_reason */
}
int main(void){
    assert(upgrade_refusal("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n")==NULL);
    assert(upgrade_refusal("HTTP/1.0 101 Switching Protocols\r\n\r\n")==NULL);
    refused("HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\nunsupported client version\n","server: client version not supported");
    refused("HTTP/1.1 400 Bad Request\r\n\r\nbad","control refused the request (HTTP 400)");
    refused("HTTP/1.1 200 OK\r\nContent-Length: 1101\r\n\r\n<html>headscale 0.101</html>","no upgrade: check the URL or proxy");
    refused("HTTP/1.1 301 Moved Permanently\r\nLocation: https://hs.example/\r\n\r\n","no upgrade: check the URL or proxy");
    refused("HTTP/1.1 404 Not Found\r\nDate: Wed, 18 Nov 2026 10:10:10 GMT\r\n\r\n","control API not found at this URL (404)");
    refused("HTTP/1.1 403 Forbidden\r\n\r\n","control refused access (HTTP 401/403)");
    refused("HTTP/1.1 401 Unauthorized\r\n\r\n","control refused access (HTTP 401/403)");
    refused("HTTP/1.1 429 Too Many Requests\r\n\r\n","control server rate limit (HTTP 429)");
    refused("HTTP/1.1 502 Bad Gateway\r\n\r\n","control server or proxy error (HTTP 5xx)");
    refused("HTTP/1.1 426 Upgrade Required\r\n\r\n","control refused the upgrade (HTTP 4xx)");
    refused("SSH-2.0-OpenSSH_9.6 101","control answer is not HTTP");
    refused("HTTP/1.1","control answer is not HTTP");
    refused("","control answer is not HTTP");
    puts("PASS: actual upgrade check: only status 101 accepts; refusals give a readable reason under 48 characters");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix='noise-upgrade-') as tmp:
    c = Path(tmp) / 't.c'
    c.write_text(PROGRAM.replace('@@CODE@@', function('static const char *upgrade_refusal(')), encoding='utf-8')
    exe = Path(tmp) / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror']
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(c), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:] or 'failed')
print('noise upgrade: exact status check, readable refusal reasons')
