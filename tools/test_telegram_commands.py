"""Telegram bot commands (main/telegram_commands.c, 3.0.12) on the host.

The pure core is compiled as is (TG_COMMANDS_HOST_TEST) with cJSON:
- only messages from the configured chat become commands (private chats and
  negative group ids); other chats are counted and skipped;
- messages older than 10 minutes are skipped when the clock is known; non-text
  updates advance the offset but run nothing;
- at most 5 commands per answer, the highest update_id is reported;
- malformed answers ("ok":false, no result array, broken JSON, a NUL escape)
  are invalid as a whole; oversized command texts are dropped;
- "/wol@MyBot nas" becomes "wol nas"; "/info" becomes "info";
- poll interval 5..300 s.
The firmware part is checked in the source: the backlog is skipped on the
first poll, the offset advances before any command runs, oversized answers
are refused, the token is wiped from the URL, the task has no internal-RAM
stack and writes no flash, and ntfy and Telegram share remote_command_run.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'main/telegram_commands.c').read_text(encoding='utf-8').replace('\r\n', '\n')
fw = SRC[SRC.index('#ifndef TG_COMMANDS_HOST_TEST'):]
assert 'offset=-1&limit=1&timeout=0' in fw and 's_have_offset = true' in fw
run_at = fw.index('run(c, u.cmd[i].text, destination,')
assert fw.rindex('if (!poll_current(generation, token, chat)) break;', 0, run_at) < run_at
assert fw.rindex('if (!destination || !poll_current(generation, token, chat)) return false;', 0, run_at) < run_at
assert fw.rindex('if (u.last_update_id > s_last_update) s_last_update = u.last_update_id;', 0, run_at) < run_at
assert 'timeout=%d' in fw and '.keep_alive_enable = true' in fw   # long polling on one connection
assert 'memset(url, 0, sizeof url);' in fw and 'memset(token, 0, sizeof token);' in fw
assert 'MALLOC_CAP_SPIRAM) == pdPASS' in fw and 'nvs_param_set' not in fw[:fw.index('esp_err_t telegram_commands_store_config')]
ntfy = (ROOT / 'main/ntfy_integration.c').read_text(encoding='utf-8')
assert 'remote_command_run(message, c->info_enabled, c->allow_direct_mac' in ntfy
assert 'remote_command_run(command, c->info_enabled, c->allow_direct_mac' in SRC

poll_current = fw[fw.index('static bool poll_current('):fw.index('static bool poll_once(')]
fetch_code = fw[fw.index('#define TG_LONG_POLL_S'):fw.index('static esp_err_t reply(')]
poll_once = fw[fw.index('static bool poll_once('):fw.index('static void task_main(')]
PROGRAM = r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "telegram_commands.h"
#define portMAX_DELAY 0
static int s_lock;
static uint32_t s_generation=4;
static telegram_commands_config_t s_cfg={.commands_enabled=true};
static bool tailscale_enabled=true,connected,target_present=true;
static void xSemaphoreTake(int lock,int timeout){(void)lock;(void)timeout;}
static void xSemaphoreGive(int lock){(void)lock;}
static bool tailscale_is_connected(void){return connected;}
static bool notify_telegram_target(char *token,size_t tc,char *chat,size_t cc){
    snprintf(token,tc,"fixture");snprintf(chat,cc,"42");return target_present;
}
''' + poll_current + r'''
typedef int esp_http_client_method_t;
typedef void *esp_http_client_handle_t;
typedef struct {const char *url;int method,timeout_ms;bool keep_alive_enable,disable_auto_redirect;void *crt_bundle_attach;} esp_http_client_config_t;
enum {HTTP_METHOD_GET,ESP_OK,MALLOC_CAP_SPIRAM,MALLOC_CAP_8BIT=4};
#define TG_ANSWER_MAX 512
static unsigned request_count,cleanups,runs;
static uint32_t s_last_update;
static bool s_have_offset;
static struct {uint32_t skipped_other_chats;char last_error[64];} s_st;
static char url_used[200],error[64];
static void *ml_tls_bundle_attach;
static int response_mode;
static size_t remaining;
static const char *current;
static bool complete;
static const char *readable="{\"ok\":true,\"result\":[{\"update_id\":12,\"message\":{\"date\":1800000000,\"chat\":{\"id\":42},\"text\":\"help\"}}]}";
static void set_error(const char *msg){snprintf(error,sizeof error,"%s",msg);}
static uint32_t wall(void){return 1800000000;}
static void *heap_caps_malloc(size_t n,int flags){assert(flags==(MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT));return malloc(n);}
static uint32_t notify_telegram_destination(const char *token,const char *chat){assert(token&&chat);return 9;}
static int esp_http_client_set_url(void *c,const char *url){assert(c);snprintf(url_used,sizeof url_used,"%s",url);return ESP_OK;}
static void *esp_http_client_init(const esp_http_client_config_t *c){assert(c->keep_alive_enable);esp_http_client_set_url(&s_lock,c->url);return &s_lock;}
static void esp_http_client_cleanup(void *c){assert(c);cleanups++;}
static int esp_http_client_open(void *c,int len){
    assert(c&&!len);request_count++;
    assert(strstr(url_used,"offset=12"));
    if(request_count==1){assert(strstr(url_used,"limit=5&timeout=25"));}
    else {assert(request_count==2&&strstr(url_used,"limit=1&timeout=0"));}
    if(response_mode==2)return -1;
    complete=request_count==2&&response_mode!=1;
    current=response_mode==3?"{\"ok\":true,\"result\":[{\"update_id\":99":readable;
    remaining=complete?strlen(current):TG_ANSWER_MAX+8;
    return ESP_OK;
}
static int esp_http_client_fetch_headers(void *c){assert(c);return 0;}
static int esp_http_client_get_status_code(void *c){assert(c);return 200;}
static int esp_http_client_read(void *c,char *out,int len){
    assert(c&&len>0);size_t take=remaining<(size_t)len?remaining:(size_t)len;
    if(complete)memcpy(out,current,take);else memset(out,'x',take);
    remaining-=take;return (int)take;
}
static bool esp_http_client_is_complete_data_received(void *c){assert(c);return complete&&!remaining;}
static void run(const telegram_commands_config_t *cfg,const char *text,uint32_t destination,bool private_chat){
    assert(cfg&&!strcmp(text,"help")&&destination==9&&private_chat&&s_last_update==12);runs++;
}
''' + fetch_code + poll_once + r'''
static void oversized_batches(void){
    for(response_mode=0;response_mode<4;response_mode++){
        esp_http_client_handle_t client=NULL;
        s_last_update=11;s_have_offset=true;request_count=cleanups=runs=0;
        bool ok=poll_once(&client,&s_cfg,"fixture","42",s_generation);
        assert(request_count==(response_mode==2?1:2));
        if(!response_mode)assert(ok&&runs==1&&s_last_update==12&&cleanups==1);
        else assert(!ok&&!runs&&s_last_update==11);
        if(response_mode==1)assert(strstr(error,"receive limit")&&cleanups==2);
    }
}
static const char *msg(char *buf, size_t cap, long long uid, long long chat, long date, const char *text) {
    snprintf(buf, cap, "{\"update_id\":%lld,\"message\":{\"message_id\":1,\"chat\":{\"id\":%lld,\"type\":\"private\"},\"date\":%ld,\"text\":\"%s\"}}", uid, chat, date, text);
    return buf;
}
int main(void) {
    char a[600], b[600], c[600], d[600], all[4096];
    tg_updates_t u;
    assert(poll_current(4,"fixture","42"));
    assert(!poll_current(3,"fixture","42"));
    assert(!poll_current(4,"previous","42"));
    assert(!poll_current(4,"fixture","1"));
    s_cfg.commands_only_when_tailscale_down=true;connected=true;
    assert(!poll_current(4,"fixture","42"));
    connected=false;assert(poll_current(4,"fixture","42"));
    tailscale_enabled=false;connected=true;assert(poll_current(4,"fixture","42"));
    oversized_batches();
    tailscale_enabled=true;connected=false;
    target_present=false;assert(!poll_current(4,"fixture","42"));
    target_present=true;s_cfg.commands_enabled=false;
    assert(!poll_current(4,"fixture","42"));
    const long now = 1800000000;
    snprintf(all, sizeof all, "{\"ok\":true,\"result\":[%s,%s,%s,%s,{\"update_id\":905,\"message\":{\"chat\":{\"id\":42},\"sticker\":{}}}]}",
             msg(a, sizeof a, 901, 42, now - 5, "/wol@MyBot nas"), msg(b, sizeof b, 902, 77, now - 5, "info"),
             msg(c, sizeof c, 903, 42, now - 700, "info"), msg(d, sizeof d, 904, 42, now - 1, "  /info  "));
    tg_updates_parse(all, strlen(all), "42", (uint32_t)now, &u);
    assert(u.valid && u.count == 2 && u.last_update_id == 905 && u.other_chats == 1 && u.stale == 1);
    assert(!strcmp(u.cmd[0].text, "wol nas") && !strcmp(u.cmd[1].text, "info  "));
    /* clock unknown: no age check */
    tg_updates_parse(all, strlen(all), "42", 0, &u);
    assert(u.count == 3 && u.stale == 0);
    /* group chat (negative id) */
    snprintf(all, sizeof all, "{\"ok\":true,\"result\":[%s]}", msg(a, sizeof a, 7, -1001234567890LL, now, "check nas"));
    tg_updates_parse(all, strlen(all), "-1001234567890", (uint32_t)now, &u);
    assert(u.count == 1 && !strcmp(u.cmd[0].text, "check nas"));
    tg_updates_parse(all, strlen(all), "1001234567890", (uint32_t)now, &u);
    assert(u.count == 0 && u.other_chats == 1 && u.last_update_id == 7);
    /* at most five commands */
    strcpy(all, "{\"ok\":true,\"result\":[");
    for (int i = 0; i < 7; i++) { msg(a, sizeof a, 100 + i, 42, now, "info"); strcat(all, a); if (i < 6) strcat(all, ","); }
    strcat(all, "]}");
    tg_updates_parse(all, strlen(all), "42", (uint32_t)now, &u);
    assert(u.count == 5 && u.last_update_id == 106);
    /* malformed answers */
    const char *bad[] = {"{\"ok\":false,\"result\":[]}", "{\"ok\":true}", "{\"ok\":true,\"result\":{}}", "{\"ok\":true,\"result\":[",
                         "{\"ok\":true,\"result\":[{\"update_id\":5,\"message\":{\"chat\":{\"id\":42},\"text\":\"a\\u0000b\"}}]}", "not json"};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) { tg_updates_parse(bad[i], strlen(bad[i]), "42", 0, &u); assert(!u.valid && u.count == 0); }
    tg_updates_parse("{\"ok\":true,\"result\":[]}", 24, "", 0, &u); assert(!u.valid);   /* no chat configured */
    /* update ids out of range are ignored */
    const char *range = "{\"ok\":true,\"result\":[{\"update_id\":-3},{\"update_id\":1e12},{\"update_id\":9}]}";
    tg_updates_parse(range, strlen(range), "42", 0, &u); assert(u.valid && u.last_update_id == 9);
    /* oversized command text */
    char long_text[200]; memset(long_text, 'x', 150); long_text[150] = 0;
    snprintf(all, sizeof all, "{\"ok\":true,\"result\":[%s]}", msg(a, sizeof a, 11, 42, now, long_text));
    tg_updates_parse(all, strlen(all), "42", (uint32_t)now, &u); assert(u.count == 0 && u.last_update_id == 11);
    /* normalize */
    char out[TG_CMD_TEXT_MAX];
    assert(tg_command_normalize("/wol@Mattboxx_bot pc studio", out, sizeof out) && !strcmp(out, "wol pc studio"));
    assert(tg_command_normalize("/info", out, sizeof out) && !strcmp(out, "info"));
    assert(tg_command_normalize("wol aa:bb:cc:dd:ee:ff", out, sizeof out) && !strcmp(out, "wol aa:bb:cc:dd:ee:ff"));
    assert(!tg_command_normalize("/", out, sizeof out) && !tg_command_normalize("@bot", out, sizeof out));
    assert(!tg_command_normalize("info", out, 4));
    /* poll interval */
    telegram_commands_config_t cfg = {0};
    cfg.poll_interval_seconds = 4; assert(!telegram_commands_config_valid(&cfg));
    cfg.poll_interval_seconds = 5; assert(telegram_commands_config_valid(&cfg));
    cfg.poll_interval_seconds = 300; assert(telegram_commands_config_valid(&cfg));
    cfg.poll_interval_seconds = 301; assert(!telegram_commands_config_valid(&cfg));
    assert(!telegram_commands_config_valid(NULL));
    puts("telegram commands ok");
    return 0;
}
'''


FETCH = fw[fw.index('#define TG_LONG_POLL_S'):fw.index('static esp_err_t reply(')]
FETCH_PROGRAM = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
typedef enum {HTTP_METHOD_GET} esp_http_client_method_t;
typedef struct {const char *url; int method, timeout_ms; bool keep_alive_enable; void *crt_bundle_attach; bool disable_auto_redirect;} esp_http_client_config_t;
typedef struct {int id; char url[200]; int timeout_ms; bool keep;} client_t;
typedef client_t *esp_http_client_handle_t;
static client_t pool[8]; static int inits, cleanups, live, opens, fail_open, status = 200, complete = 1;
static const char *body = "{}"; static int body_off;
static void *ml_tls_bundle_attach;
static esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t *c) {
    client_t *x = &pool[inits++ % 8]; x->id = inits; snprintf(x->url, sizeof x->url, "%s", c->url); x->timeout_ms = c->timeout_ms; x->keep = c->keep_alive_enable; live++; return x; }
static esp_err_t esp_http_client_set_url(esp_http_client_handle_t c, const char *u) { snprintf(c->url, sizeof c->url, "%s", u); return ESP_OK; }
static esp_err_t esp_http_client_open(esp_http_client_handle_t c, int n) { (void)c; (void)n; opens++; body_off = 0; return fail_open ? ESP_FAIL : ESP_OK; }
static int esp_http_client_fetch_headers(esp_http_client_handle_t c) { (void)c; return (int)strlen(body); }
static int esp_http_client_get_status_code(esp_http_client_handle_t c) { (void)c; return status; }
static int esp_http_client_read(esp_http_client_handle_t c, char *o, int n) {
    (void)c; int left = (int)strlen(body) - body_off; if (left <= 0) return 0; if (n > left) n = left; if (n > 7) n = 7;
    memcpy(o, body + body_off, (size_t)n); body_off += n; return n; }
static bool esp_http_client_is_complete_data_received(esp_http_client_handle_t c) { (void)c; return complete && (size_t)body_off==strlen(body); }
static esp_err_t esp_http_client_cleanup(esp_http_client_handle_t c) { (void)c; cleanups++; live--; return ESP_OK; }
@@FETCH@@
int main(void) {
    esp_http_client_handle_t cl = NULL; char a[64];
    body = "{\"ok\":true,\"result\":[]}";
    assert(fetch(&cl, "TOKEN", "offset=1&limit=5&timeout=25", a, sizeof a) == (int)strlen(body) && !strcmp(a, body));
    assert(cl && inits == 1 && cl->keep && cl->timeout_ms >= 25000 + 5000 && strstr(cl->url, "timeout=25"));
    /* the next long poll reuses the connection (no new handshake) */
    assert(fetch(&cl, "TOKEN", "offset=2&limit=5&timeout=25", a, sizeof a) > 0 && inits == 1 && strstr(cl->url, "offset=2"));
    /* a failed request drops the connection; the next one makes a new one */
    fail_open = 1; assert(fetch(&cl, "TOKEN", "q", a, sizeof a) == -1 && !cl && cleanups == 1); fail_open = 0;
    assert(fetch(&cl, "TOKEN", "q", a, sizeof a) > 0 && inits == 2);
    /* an answer larger than allowed or cut short is refused and never reused */
    body = "{\"ok\":true,\"result\":[0123456789012345678901234567890123456789012345678901234567890]}";
    assert(fetch(&cl, "TOKEN", "q", a, sizeof a) == TG_FETCH_TOO_LARGE && !cl);
    char exact[sizeof a];memset(exact,' ',sizeof exact-1);memcpy(exact,"{}",2);exact[sizeof exact-1]=0;
    body=exact;assert(fetch(&cl,"TOKEN","q",a,sizeof a)==(int)(sizeof a-1)&&cl&&!strcmp(exact,a));
    body = "{}"; complete = 0; assert(fetch(&cl, "TOKEN", "q", a, sizeof a) == -1 && !cl); complete = 1;
    status = 502; assert(fetch(&cl, "TOKEN", "q", a, sizeof a) == -1 && !cl); status = 200;
    /* a URL that does not fit is refused before any connection */
    char longtok[300]; memset(longtok, 'x', 299); longtok[299] = 0; int before = opens;
    assert(fetch(&cl, longtok, "q", a, sizeof a) == -1 && opens == before);
    if (cl) esp_http_client_cleanup(cl);
    assert(live == 0);
    puts("fetch ok");
    return 0;
}
"""


def fetch_behaviour(path):
    (path / 'fetch.c').write_text(FETCH_PROGRAM.replace('@@FETCH@@', FETCH), encoding='utf-8')
    exe = path / ('fetch.exe' if os.name == 'nt' else 'fetch')
    subprocess.run([os.environ.get('CC', 'gcc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    str(path / 'fetch.c'), '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0 and 'fetch ok' in out.stdout, (out.stdout, out.stderr)


def main():
    with tempfile.TemporaryDirectory(prefix='tg-fetch-') as folder:
        fetch_behaviour(Path(folder))
    with tempfile.TemporaryDirectory(prefix='tg-cmd-') as folder:
        path = Path(folder)
        (path / 'esp_err.h').write_text('#pragma once\ntypedef int esp_err_t;\n', encoding='utf-8')
        (path / 'test.c').write_text(PROGRAM, encoding='utf-8')
        exe = path / ('test.exe' if os.name == 'nt' else 'test')
        flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-DTG_COMMANDS_HOST_TEST', '-I', str(path), '-I', str(ROOT / 'main')]
        libs = []
        dep = os.environ.get('CJSON_SOURCE', str(Path.home() / '.platformio/packages/framework-espidf@3.50503.0/components/json/cJSON/cJSON.c'))
        if Path(dep).exists():
            flags += ['-I', str(Path(dep).parent)]
            sources = [dep]
        else:
            flags += subprocess.check_output(['pkg-config', '--cflags', 'libcjson'], text=True).split()
            libs += subprocess.check_output(['pkg-config', '--libs', 'libcjson'], text=True).split()
            sources = []
        if os.name != 'nt' and os.environ.get('HOTLOOP_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        cc = os.environ.get('CC', 'gcc')
        objs = []
        for i, s in enumerate(sources):
            o = path / f'dep{i}.o'
            subprocess.run([cc, '-std=gnu11', '-O1', '-w', '-c', s, '-o', str(o)], check=True)
            objs.append(str(o))
        subprocess.run([cc, *flags, str(path / 'test.c'), str(ROOT / 'main/telegram_commands.c'), *objs, '-o', str(exe), *libs], check=True)
        out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        assert out.returncode == 0 and 'telegram commands ok' in out.stdout, (out.returncode, out.stdout, out.stderr)
    print('telegram commands: chat authorization, age limit, batch cap, malformed answers, /cmd@Bot forms; '
          'backlog skipped, offset before running, no flash writes, shared command engine with ntfy; '
          'long polling on one reused connection, dropped after a failure, oversized or cut answers refused')


if __name__ == '__main__':
    main()
