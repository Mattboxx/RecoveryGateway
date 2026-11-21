"""Actual profile core and transaction coordinator with injected faults.

Compiles main/config_profiles.c's core and coordinator with fixture setting
owners and transaction storage. The flash journal has separate power-cut tests.
Set PROFILE_SANITIZE=1 on Linux to add ASan/UBSan.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/config_profiles.c').read_text(encoding='utf-8')
start = '#define PROFILE_MAGIC'
core = start + source.split(start, 1)[1].split('/* --- profile core (end) --- */', 1)[0]


def function(signature, text=source):
    at = text.index(signature)
    return text[at:text.index('\n}', at) + 2] + '\n'


coordinator = source[source.index('static esp_err_t commit_profile(', source.index('/* --- profile core (end) --- */')):
                     source.index('static esp_err_t record_save(', source.index('/* --- profile core (end) --- */'))]

STUBS = {
    'esp_err.h': '#pragma once\ntypedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_FAIL -1\n'
                 '#define ESP_ERR_NO_MEM 0x101\n#define ESP_ERR_INVALID_ARG 0x102\n'
                 '#define ESP_ERR_INVALID_STATE 0x103\n#define ESP_ERR_NOT_FOUND 0x105\n',
    'esp_http_server.h': '#pragma once\ntypedef void *httpd_handle_t;\n',
}

PROGRAM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "config_profiles.h"
static profile_values_t settings, persisted_values, before_values, before_runtime;
static int fail_write_at=-1, fail_save_at=-1, writes, saves, reads_fail;
static bool fail_begin,fail_end,health_conflict,in_txn,history_locked,health_locked,lan_enabled;
static char trace[64]; static unsigned trace_len;
static unsigned char stored[64],before_record[64];
''' + core.replace('/* --- profile core (begin) --- */', '') + r'''
static bool values_read(profile_values_t *out){if(reads_fail)return false;*out=settings;return true;}
static esp_err_t stage_value(profile_key_t key,uint8_t value){
    assert(in_txn && !memcmp(&settings,&before_runtime,sizeof settings));
    assert(key<PK_COUNT&&value<=1);
    int n=writes++; trace[trace_len++]='w';
    if(n==fail_write_at)return ESP_ERR_NO_MEM;
    persisted_values.value[key]=value;return ESP_OK;
}
static esp_err_t record_save(const profile_record_t *r){
    assert(in_txn && !memcmp(&settings,&before_runtime,sizeof settings));
    int n=saves++; trace[trace_len++]='s';
    if(n==fail_save_at)return ESP_FAIL;
    assert(record_valid(r));memcpy(stored,r,sizeof *r);return ESP_OK;
}
static esp_err_t nvs_param_txn_begin(void){
    assert(!in_txn);
    if(fail_begin)return ESP_ERR_NO_MEM;
    in_txn=true;before_values=persisted_values;before_runtime=settings;
    memcpy(before_record,stored,sizeof stored);
    return ESP_OK;
}
static esp_err_t nvs_param_txn_end(bool keep){
    assert(in_txn&&!memcmp(&settings,&before_runtime,sizeof settings));
    in_txn=false;trace[trace_len++]='e';
    if(keep&&!fail_end)return ESP_OK;
    persisted_values=before_values;memcpy(stored,before_record,sizeof stored);
    return ESP_ERR_INVALID_STATE;
}
typedef struct {uint8_t monitoring,lease_notifications;} ops_settings_t;
static void homelab_ops_settings(ops_settings_t *s){
    *s=(ops_settings_t){settings.value[PK_OPS_MONITORING],settings.value[PK_LEASE_NOTIFY]};
}
static esp_err_t homelab_ops_stage_settings(const ops_settings_t *s){
    esp_err_t err=ESP_OK;
    if(s->monitoring!=settings.value[PK_OPS_MONITORING])err=stage_value(PK_OPS_MONITORING,s->monitoring);
    if(err==ESP_OK&&s->lease_notifications!=settings.value[PK_LEASE_NOTIFY])err=stage_value(PK_LEASE_NOTIFY,s->lease_notifications);
    return err;
}
static void publish_value(profile_key_t key,uint8_t value){
    assert(!in_txn);
    settings.value[key]=value;
}
static void homelab_ops_publish_settings(const ops_settings_t *s){
    publish_value(PK_OPS_MONITORING,s->monitoring);publish_value(PK_LEASE_NOTIFY,s->lease_notifications);
}
static const int tailnet_names_flags=0;
static void tailnet_names_get(bool *names,bool *lan){*names=settings.value[PK_TAILNET_NAMES];*lan=lan_enabled;}
static esp_err_t nvs_flags_save(const int *flags,uint8_t v){
    assert(flags==&tailnet_names_flags && (v>>1)==lan_enabled);return stage_value(PK_TAILNET_NAMES,v&1);
}
static void tailnet_names_publish(bool names,bool lan){assert(lan==lan_enabled);publish_value(PK_TAILNET_NAMES,names);}
static esp_err_t ap_traffic_stage(bool enabled){return stage_value(PK_AP_TRAFFIC,enabled);}
static void ap_traffic_publish(bool enabled){publish_value(PK_AP_TRAFFIC,enabled);}
static esp_err_t history_stage_config(bool ev,bool metrics,bool snaps){
    assert(!history_locked);
    bool v[]={ev,metrics,snaps};
    for(unsigned i=0;i<3;i++)if(v[i]!=settings.value[PK_HIST_EVENTS+i]){
        esp_err_t err=stage_value(PK_HIST_EVENTS+i,v[i]);
        if(err)return err;
    }
    history_locked=true;return ESP_OK;
}
static void history_finish_staged(bool ev,bool metrics,bool snaps,bool commit){
    assert(!in_txn&&history_locked);
    history_locked=false;
    if(commit){publish_value(PK_HIST_EVENTS,ev);publish_value(PK_HIST_TRENDS,metrics);publish_value(PK_SNAPSHOTS,snaps);}
}
static esp_err_t health_monitor_stage_enabled(bool expected,bool enabled){
    assert(!health_locked&&expected==settings.value[PK_HEALTH]);
    if(health_conflict)return ESP_ERR_INVALID_STATE;
    esp_err_t err=stage_value(PK_HEALTH,enabled);
    health_locked=err==ESP_OK;
    return err;
}
static void health_monitor_finish_staged(bool enabled,bool commit){
    assert(!in_txn&&health_locked);
    health_locked=false;
    if(commit)publish_value(PK_HEALTH,enabled);
}
''' + coordinator + r'''
static void reset(void){
    memset(&settings,0,sizeof settings);record_defaults(&record);
    persisted_values=settings;memset(stored,0,sizeof stored);
    fail_begin=fail_end=health_conflict=history_locked=health_locked=in_txn=lan_enabled=false;
    fail_write_at=fail_save_at=-1;writes=saves=reads_fail=0;trace_len=0;memset(trace,0,sizeof trace);
}
#define MON_MASK (1u<<PK_OPS_MONITORING|1u<<PK_HEALTH|1u<<PK_HIST_EVENTS|1u<<PK_HIST_TRENDS)
static uint32_t token_for(profile_id_t p){profile_plan_t plan;assert(preview_locked(p,&plan)==ESP_OK);return plan.token;}
int main(void){
    profile_plan_t plan; profile_result_t r; profile_id_t id;
    reset();
    assert(config_profile_parse("monitoring",&id)&&id==PROFILE_MONITORING);
    assert(!config_profile_parse("none",&id)&&!config_profile_parse("Monitoring",&id)&&!config_profile_parse(NULL,&id));
    assert(!strcmp(config_profile_name(PROFILE_COUNT),"unknown"));
    assert(preview_locked(PROFILE_NONE,&plan)==ESP_ERR_INVALID_ARG&&preview_locked(PROFILE_COUNT,&plan)==ESP_ERR_INVALID_ARG);
    assert(preview_locked(PROFILE_MONITORING,&plan)==ESP_OK);
    assert(plan.change_mask==MON_MASK&&plan.token);
    assert(preview_locked(PROFILE_GATEWAY,&plan)==ESP_OK&&plan.change_mask==(1u<<PK_LEASE_NOTIFY|1u<<PK_SNAPSHOTS|1u<<PK_HIST_EVENTS));
    assert(preview_locked(PROFILE_RECOVERY,&plan)==ESP_OK&&plan.change_mask==(1u<<PK_OPS_MONITORING|1u<<PK_HIST_EVENTS));
    #define IOT_MASK (1u<<PK_TAILNET_NAMES|1u<<PK_AP_TRAFFIC|1u<<PK_HIST_EVENTS)
    assert(preview_locked(PROFILE_IOT,&plan)==ESP_OK&&plan.change_mask==IOT_MASK&&plan.proposed_mask==plan.change_mask);
    settings.value[PK_TAILNET_NAMES]=1;assert(preview_locked(PROFILE_IOT,&plan)==ESP_OK&&plan.change_mask==(IOT_MASK&~(1u<<PK_TAILNET_NAMES)));
    settings.value[PK_AP_TRAFFIC]=1;settings.value[PK_HIST_EVENTS]=1;
    assert(preview_locked(PROFILE_IOT,&plan)==ESP_OK&&!plan.change_mask&&plan.proposed_mask==IOT_MASK);   /* already on */
    settings.value[PK_TAILNET_NAMES]=settings.value[PK_AP_TRAFFIC]=settings.value[PK_HIST_EVENTS]=0;
    /* 3.0.26: a profile for every first-boot goal. */
    assert(preview_locked(PROFILE_LAN_TAILNET,&plan)==ESP_OK&&plan.change_mask==(1u<<PK_LEASE_NOTIFY|1u<<PK_SNAPSHOTS|1u<<PK_HIST_EVENTS));
    assert(preview_locked(PROFILE_HOME_ASSISTANT,&plan)==ESP_OK&&plan.change_mask==(1u<<PK_OPS_MONITORING|1u<<PK_HIST_EVENTS|1u<<PK_SNAPSHOTS));
    assert(config_profile_parse("lan-tailnet",&id)&&id==PROFILE_LAN_TAILNET&&config_profile_parse("home-assistant",&id)&&id==PROFILE_HOME_ASSISTANT);
    {
        const char *roles[]={"lan-tailnet","subnet-router","iot-ap","wol","home-assistant","monitoring","advanced"};
        const profile_id_t want[]={PROFILE_LAN_TAILNET,PROFILE_GATEWAY,PROFILE_IOT,PROFILE_RECOVERY,PROFILE_HOME_ASSISTANT,PROFILE_MONITORING,PROFILE_ADVANCED};
        unsigned seen=0;
        for(unsigned i=0;i<7;i++){assert(config_profile_for_setup_role(roles[i])==want[i]);seen|=1u<<want[i];}
        assert(seen==((1u<<PROFILE_COUNT)-2));   /* every profile but "none" matches a goal */
        assert(config_profile_for_setup_role("first-boot")==PROFILE_NONE&&config_profile_for_setup_role("")==PROFILE_NONE&&config_profile_for_setup_role(NULL)==PROFILE_NONE);
    }
    /* No profile ever asks for more than the local switches it may turn on. */
    for(unsigned p=0;p<PROFILE_COUNT;p++)assert(!(profile_wants[p]&~((1u<<PK_COUNT)-1)));
    assert(preview_locked(PROFILE_ADVANCED,&plan)==ESP_OK&&!plan.change_mask);
    for(unsigned p=0;p<PROFILE_COUNT;p++)assert(!(profile_wants[p]>>PK_COUNT));
    for(unsigned k=0;k<PK_COUNT;k++)assert(key_names[k]&&key_names[k][0]);
    reads_fail=1;assert(preview_locked(PROFILE_MONITORING,&plan)==ESP_FAIL);
    assert(apply_locked(PROFILE_MONITORING,1,&r)==ESP_FAIL&&!saves&&!writes);reads_fail=0;

    /* Token binds profile and state; mismatch changes nothing. */
    uint32_t mon=token_for(PROFILE_MONITORING),gw=token_for(PROFILE_GATEWAY);
    assert(mon!=gw);
    assert(apply_locked(PROFILE_RECOVERY,mon,&r)==ESP_ERR_INVALID_STATE&&!saves&&!writes);
    assert(apply_locked(PROFILE_MONITORING,0,&r)==ESP_ERR_INVALID_STATE);
    assert(apply_locked(PROFILE_NONE,mon,&r)==ESP_ERR_INVALID_ARG);
    settings.value[PK_LEASE_NOTIFY]=1;assert(apply_locked(PROFILE_MONITORING,mon,&r)==ESP_ERR_INVALID_STATE&&!writes);
    settings.value[PK_LEASE_NOTIFY]=0;

    /* Apply: stages remain private until the profile and journal commit. */
    assert(apply_locked(PROFILE_MONITORING,mon,&r)==ESP_OK&&r.applied&&!r.rolled_back);
    assert(!strcmp(trace,"wwwwse")&&settings.value[PK_OPS_MONITORING]&&settings.value[PK_HEALTH]&&!settings.value[PK_LEASE_NOTIFY]);
    assert(settings.value[PK_HIST_EVENTS]&&settings.value[PK_HIST_TRENDS]&&!settings.value[PK_SNAPSHOTS]&&!settings.value[PK_TAILNET_NAMES]);
    assert(record.active==PROFILE_MONITORING&&record.has_backup&&record.applied_mask==r.changed_mask);
    assert(!memcmp(stored,&record,sizeof record));
    assert(apply_locked(PROFILE_MONITORING,mon,&r)==ESP_ERR_INVALID_STATE); /* replay refused */
    assert(token_for(PROFILE_MONITORING)!=mon);

    /* Operator turned health off since; rollback keeps that, restores the rest. */
    settings.value[PK_HEALTH]=0;trace_len=0;memset(trace,0,sizeof trace);
    assert(rollback_locked(&r)==ESP_OK&&r.rolled_back&&r.changed_mask==(MON_MASK&~(1u<<PK_HEALTH))&&r.kept_mask==1u<<PK_HEALTH);
    assert(!strcmp(trace,"wwwse")&&!settings.value[PK_OPS_MONITORING]&&!settings.value[PK_HIST_EVENTS]&&!settings.value[PK_HIST_TRENDS]);
    assert(!record.has_backup&&record.active==PROFILE_NONE);
    assert(rollback_locked(&r)==ESP_ERR_NOT_FOUND);

    /* Never disables something already on, even on rollback. */
    reset();settings.value[PK_OPS_MONITORING]=1;
    assert(apply_locked(PROFILE_MONITORING,token_for(PROFILE_MONITORING),&r)==ESP_OK&&r.changed_mask==(MON_MASK&~(1u<<PK_OPS_MONITORING)));
    assert(rollback_locked(&r)==ESP_OK&&settings.value[PK_OPS_MONITORING]==1&&!settings.value[PK_HEALTH]);
    reset();assert(apply_locked(PROFILE_ADVANCED,token_for(PROFILE_ADVANCED),&r)==ESP_OK&&!writes&&record.active==PROFILE_ADVANCED);
    assert(rollback_locked(&r)==ESP_OK&&record.active==PROFILE_NONE&&!writes);

    /* Fail opening the transaction, every setting stage, the record, and
     * final commit in both directions. Nothing leaks into the running state. */
    for (unsigned rollback=0;rollback<=1;rollback++) for(unsigned fault=0;fault<8;fault++){
        reset();
        if(rollback)assert(apply_locked(PROFILE_MONITORING,token_for(PROFILE_MONITORING),&r)==ESP_OK);
        profile_record_t before=record;
        profile_values_t before_settings=settings;
        fail_begin=fault==0;fail_end=fault==6;health_conflict=fault==7;
        if(fault>=1&&fault<=4)fail_write_at=writes+(int)fault-1;
        if(fault==5)fail_save_at=saves;
        esp_err_t err=rollback?rollback_locked(&r):apply_locked(PROFILE_MONITORING,token_for(PROFILE_MONITORING),&r);
        assert(err!=ESP_OK&&!r.applied&&!r.rolled_back&&!r.partial&&!r.changed_mask);
        assert(!memcmp(&before,&record,sizeof record)&&!memcmp(&before_settings,&settings,sizeof settings));
        assert(!memcmp(&persisted_values,&settings,sizeof settings)&&!in_txn&&!history_locked&&!health_locked);
        if(rollback)assert(!memcmp(stored,&record,sizeof record));
        fail_begin=fail_end=health_conflict=false;fail_write_at=fail_save_at=-1;
        if(rollback)assert(rollback_locked(&r)==ESP_OK&&r.changed_mask==MON_MASK&&!r.kept_mask);
    }

    reset();lan_enabled=true;
    assert(apply_locked(PROFILE_IOT,token_for(PROFILE_IOT),&r)==ESP_OK&&lan_enabled);
    assert(settings.value[PK_TAILNET_NAMES]&&settings.value[PK_AP_TRAFFIC]);
    assert(rollback_locked(&r)==ESP_OK&&lan_enabled&&!settings.value[PK_TAILNET_NAMES]&&!settings.value[PK_AP_TRAFFIC]);

    /* Single-level history: rollback returns to the previous profile only. */
    reset();assert(apply_locked(PROFILE_GATEWAY,token_for(PROFILE_GATEWAY),&r)==ESP_OK);
    assert(apply_locked(PROFILE_MONITORING,token_for(PROFILE_MONITORING),&r)==ESP_OK&&record.previous==PROFILE_GATEWAY);
    assert(rollback_locked(&r)==ESP_OK&&record.active==PROFILE_GATEWAY&&settings.value[PK_LEASE_NOTIFY]);
    assert(!settings.value[PK_OPS_MONITORING]&&!settings.value[PK_HEALTH]&&settings.value[PK_SNAPSHOTS]);

    /* A record saved by 3.0.0 (three keys, zeros after them) is still valid. */
    {profile_record_t old;record_defaults(&old);old.active=PROFILE_MONITORING;old.previous_values[0]=1;old.applied_mask=1u<<PK_HEALTH;
     old.has_backup=1;old.checksum=record_checksum(&old);assert(record_valid(&old));}

    /* Record validation rejects every malformed field. */
    profile_record_t v=record;v.checksum=record_checksum(&v);assert(record_valid(&v));
    profile_record_t bad=v;bad.checksum^=1;assert(!record_valid(&bad));
    bad=v;bad.active=PROFILE_COUNT;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    bad=v;bad.previous=200;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    /* applied_mask: all 8 bits are keys now (PK_COUNT == 8), none can be out of range. */
    bad=v;bad.previous_values[0]=2;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    bad=v;bad.previous_values[PK_COUNT-1]=2;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    /* A record of 3.0.25 (7 keys, a reserved zero byte after them) keeps its meaning. */
    {profile_record_t old;record_defaults(&old);old.active=PROFILE_IOT;old.has_backup=1;old.applied_mask=1u<<PK_TAILNET_NAMES;
     old.previous_values[PK_SNAPSHOTS]=1;old.checksum=record_checksum(&old);assert(record_valid(&old)&&sizeof old.previous_values==8);}
    bad=v;bad.has_backup=2;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    bad=v;bad.version=2;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    bad=v;bad.magic=0;bad.checksum=record_checksum(&bad);assert(!record_valid(&bad));
    puts("PASS: profile preview, staged settings and record, commit faults, concurrent health edit, rollback and legacy record validation (fixtures)");
}
'''

with tempfile.TemporaryDirectory(prefix='config-profiles-') as folder:
    path = Path(folder)
    for name, text in STUBS.items():
        (path / name).write_text(text, encoding='utf-8')
    (path / 'test.c').write_text(PROGRAM, encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', str(path), '-I', str(ROOT / 'main')]
    if os.environ.get('PROFILE_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'test.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)

# Exercise actual History resource reservation and the deferred publication.
history = (ROOT / 'main/history.c').read_text(encoding='utf-8')
HISTORY = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "esp_err.h"
#define QUEUE_LEN 4
#define LIVE_SAMPLES 8
#define MALLOC_CAP_SPIRAM 1
#define portMAX_DELAY 0
#define pdPASS 1
#define HIST_EV_SETTINGS 1
#define HIST_INFO 0
typedef struct {bool events,metrics,snapshots;} hist_config_t;
typedef int queued_t, StaticQueue_t;
static hist_config_t s_cfg;
static int s_merge,s_live_head,s_live_count,s_lock=1,history_flags,reserved_task;
static void *s_task;
static int *s_live;
static bool s_sink,s_persist,s_queue,s_have_traffic,held,task_fails,save_fails;
static unsigned writes,events_sent;
static atomic_bool s_events_on;
static void open_rings(void){assert(held);s_persist=true;}
static void number_boot(void){assert(held);}
static void history_task(void *p){(void)p;}
static void xSemaphoreTake(int lock,int timeout){assert(lock&&!timeout&&!held);held=true;}
static void xSemaphoreGive(int lock){assert(lock&&held);held=false;}
static void history_event(int kind,int level,const char *text){
    assert(!held&&kind==HIST_EV_SETTINGS&&level==HIST_INFO&&text);events_sent++;
}
static void *heap_caps_malloc(size_t size,int caps){assert(caps==MALLOC_CAP_SPIRAM);return malloc(size);}
static void *heap_caps_calloc(size_t n,size_t size,int caps){assert(caps==MALLOC_CAP_SPIRAM);return calloc(n,size);}
static void *queue_area;
static bool xQueueCreateStatic(int entries,size_t size,uint8_t *area,StaticQueue_t *storage){
    assert(entries==QUEUE_LEN&&size==sizeof(queued_t)&&area&&storage);queue_area=area;return true;
}
static int xTaskCreate(void (*fn)(void *),const char *name,int stack,void *arg,int prio,void **task){
    assert(held&&fn==history_task&&name&&stack&&arg==NULL&&prio==2);
    if(task_fails)return 0;
    *task=&reserved_task;return pdPASS;
}
static esp_err_t nvs_flags_save(int *flags,uint8_t bits){
    assert(held&&flags==&history_flags&&bits==3);
    writes++;return save_fails?ESP_FAIL:ESP_OK;
}
void history_finish_staged(bool events,bool metrics,bool snapshots,bool committed);
''' + ''.join(function(s, history) for s in (
    'static esp_err_t prepare_config(', 'static void publish_acceptance(',
    'esp_err_t history_stage_config(', 'void history_finish_staged(')) + r'''
int main(void){
    task_fails=true;
    assert(history_stage_config(true,true,false)==ESP_ERR_NO_MEM);
    assert(!held&&!s_cfg.events&&!s_cfg.metrics&&!s_task&&!s_live&&!s_events_on&&!writes);
    task_fails=false;save_fails=true;
    assert(history_stage_config(true,true,false)==ESP_FAIL&&writes==1);
    assert(!held&&!s_cfg.events&&!s_cfg.metrics&&!s_events_on&&!events_sent);
    save_fails=false;
    assert(history_stage_config(true,true,false)==ESP_OK&&held&&writes==2);
    assert(!s_cfg.events&&!s_cfg.metrics&&!s_events_on&&!events_sent);
    history_finish_staged(true,true,false,false);
    assert(!held&&!s_cfg.events&&!s_cfg.metrics&&!s_events_on&&!events_sent);
    assert(history_stage_config(true,true,false)==ESP_OK&&held&&writes==3);
    history_finish_staged(true,true,false,true);
    assert(!held&&s_cfg.events&&s_cfg.metrics&&s_events_on&&events_sent==1);
    free(s_live);free(queue_area);
}
'''
with tempfile.TemporaryDirectory(prefix='config-profiles-history-') as folder:
    path = Path(folder)
    (path / 'esp_err.h').write_text(STUBS['esp_err.h'], encoding='utf-8')
    (path / 'history.c').write_text(HISTORY, encoding='utf-8')
    binary = path / ('history.exe' if os.name == 'nt' else 'history')
    subprocess.run([os.environ.get('CC', 'gcc'), '-I', str(path), *flags, str(path / 'history.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
    print("PASS: actual History task-allocation and storage faults, aborted preparation and committed publication (fixtures)")

# Second program: actual POST /api/profiles parser and error mapping.
web = (ROOT / 'main/web_ui.c').read_text(encoding='utf-8')
save_response = function('static void nvs_save_errors_attach(', web) + function(
    'static esp_err_t send_save_response(httpd_req_t *req)\n{', web)
secrets_post = function('static esp_err_t system_secrets_post_handler(', web)
assert secrets_post.rstrip().endswith('return send_save_response(req);\n}')
HTTP = r'''
#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "json_guard.h"
#include "config_profiles.h"
#include "wifi_networks.h"
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_NOT_FOUND 0x105
struct httpd_req {int content_len,offset,status;const char *body;bool authorized;char reply[300];};
static const char *const key_names[PK_COUNT]={"device_monitoring","service_expiry_notifications","health_monitor","event_history","trends","settings_copy_before_update","tailnet_names","ap_client_traffic"};
static const char *const profile_names[PROFILE_COUNT]={"none","gateway","recovery","iot","monitoring","advanced","lan-tailnet","home-assistant"};
const char *config_profile_name(profile_id_t p){return p<PROFILE_COUNT?profile_names[p]:"unknown";}
bool config_profile_parse(const char *n,profile_id_t *o){for(unsigned i=1;n&&i<PROFILE_COUNT;i++)if(!strcmp(n,profile_names[i])){*o=(profile_id_t)i;return true;}return false;}
static int applies,rollbacks;static uint32_t last_token;static profile_id_t last_profile;static esp_err_t apply_result,rollback_result;static profile_result_t canned;
esp_err_t config_profiles_apply(profile_id_t p,uint32_t t,profile_result_t *o){applies++;last_profile=p;last_token=t;*o=canned;return apply_result;}
esp_err_t config_profiles_rollback(profile_result_t *o){rollbacks++;*o=canned;return rollback_result;}
static const char *esp_err_to_name(esp_err_t e){(void)e;return "ERR";}
static struct {unsigned count;char first_key[16];esp_err_t first_err;} s_save_err;
static int web_ui_require_auth(httpd_req_t *r){if(r->authorized)return ESP_OK;r->status=401;return ESP_FAIL;}
static void httpd_resp_set_status(httpd_req_t *r,const char *s){r->status=atoi(s);}
static void httpd_resp_set_type(httpd_req_t *r,const char *s){(void)r;(void)s;}
static void httpd_resp_set_hdr(httpd_req_t *r,const char *k,const char *v){(void)r;(void)k;(void)v;}
static void httpd_resp_send_500(httpd_req_t *r){r->status=500;}
static int httpd_resp_sendstr(httpd_req_t *r,const char *s){snprintf(r->reply,sizeof r->reply,"%s",s);if(!r->status)r->status=200;return ESP_OK;}
static int httpd_req_recv(httpd_req_t *r,char *out,int n){memcpy(out,r->body+r->offset,n);r->offset+=n;return n;}
static const wifi_network_t saved_networks[] = {
    {.ssid="static-lan", .static_ip="192.0.2.11", .subnet="255.255.255.0", .gateway="192.0.2.1", .dns="192.0.2.2"},
    {.ssid="dhcp-lan"},
    {.ssid="static-lan", .static_ip="192.0.2.21", .subnet="255.255.255.0", .gateway="192.0.2.1"},
};
int wifi_networks_count(void){return sizeof saved_networks / sizeof saved_networks[0];}
bool wifi_networks_get(int index,wifi_network_t *out){
    if(index<0||index>=wifi_networks_count())return false;
    *out=saved_networks[index];return true;
}
#define strlcpy(dst,src,size) ((void)snprintf(dst,size,"%s",src))
''' + save_response + function('static void restore_network_base(', web) + ''.join(function(s) for s in ('static esp_err_t send_json(', 'static bool add_keys(', 'static esp_err_t send_error(', 'static esp_err_t post_profiles(')) + r'''
static unsigned allocations,fail_allocation,live_allocations;
static void *fail_malloc(size_t size){
    if(++allocations==fail_allocation)return NULL;
    void *p=malloc(size);assert(p);live_allocations++;return p;
}
static void fail_free(void *p){if(p){assert(live_allocations);live_allocations--;}free(p);}
static void check_save_response(void){
    cJSON_Hooks hooks={.malloc_fn=fail_malloc,.free_fn=fail_free};
    for (unsigned failed=0;failed<2;failed++) for (unsigned fault=1;fault<=15;fault++) {
        s_save_err.count=failed;
        allocations=0;fail_allocation=fault;
        httpd_req_t request={0};
        cJSON_InitHooks(&hooks);
        assert(send_save_response(&request)==ESP_OK);
        assert(!live_allocations);
        cJSON_InitHooks(NULL);
        cJSON *reply=cJSON_Parse(request.reply);
        const cJSON *ok=cJSON_GetObjectItemCaseSensitive(reply,"ok");
        assert(request.status==200&&cJSON_IsBool(ok)&&cJSON_IsTrue(ok)==!failed);
        cJSON_Delete(reply);
    }
}
static httpd_req_t post(const char *body){httpd_req_t r={.content_len=(int)strlen(body),.body=body,.authorized=true};post_profiles(&r);return r;}
int main(void){
    check_save_response();
    wifi_network_t restored;
    restore_network_base(&restored,1,"static-lan");
    assert(!strcmp(restored.static_ip,"192.0.2.11") && !strcmp(restored.subnet,"255.255.255.0")
           && !strcmp(restored.gateway,"192.0.2.1") && !strcmp(restored.dns,"192.0.2.2"));
    restore_network_base(&restored,2,"static-lan");
    assert(!strcmp(restored.static_ip,"192.0.2.21"));
    restore_network_base(&restored,0,"new-lan");
    assert(!strcmp(restored.ssid,"new-lan") && !restored.static_ip[0]);
    canned=(profile_result_t){.applied=true,.changed_mask=1u<<PK_HEALTH};
    httpd_req_t r=post("{\"action\":\"apply\",\"profile\":\"monitoring\",\"token\":4294967295}");
    assert(r.status==200&&applies==1&&last_profile==PROFILE_MONITORING&&last_token==4294967295u&&strstr(r.reply,"\"changed\":[\"health_monitor\"]"));
    const char *bad[]={"{\"action\":\"apply\",\"profile\":\"none\",\"token\":5}","{\"action\":\"apply\",\"profile\":\"monitoring\",\"token\":0}",
        "{\"action\":\"apply\",\"profile\":\"monitoring\",\"token\":4294967296}","{\"action\":\"apply\",\"profile\":\"monitoring\",\"token\":1.5}",
        "{\"action\":\"apply\",\"profile\":\"monitoring\",\"token\":\"5\"}","{\"action\":\"apply\",\"profile\":\"monitoring\"}",
        "{\"action\":\"apply\",\"profile\":\"monitoring\",\"token\":5,\"x\":1}","{\"action\":\"rollback\",\"profile\":\"gateway\"}",
        "{\"action\":\"delete\"}","{\"action\":\"apply\",\"action\":\"rollback\"}","[]","{"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){r=post(bad[i]);assert(r.status==400);}
    assert(applies==1&&!rollbacks);
    char big[200];memset(big,' ',sizeof big-1);big[sizeof big-1]=0;r=post(big);assert(r.status==400);
    apply_result=ESP_ERR_INVALID_STATE;r=post("{\"action\":\"apply\",\"profile\":\"gateway\",\"token\":7}");assert(r.status==409&&strstr(r.reply,"preview again"));
    canned=(profile_result_t){.rolled_back=true,.partial=true,.changed_mask=1u<<PK_OPS_MONITORING};apply_result=ESP_ERR_NO_MEM;
    r=post("{\"action\":\"apply\",\"profile\":\"gateway\",\"token\":7}");assert(r.status==503&&strstr(r.reply,"\"partial\":true")&&strstr(r.reply,"device_monitoring"));
    rollback_result=ESP_ERR_NOT_FOUND;r=post("{\"action\":\"rollback\"}");assert(r.status==404&&rollbacks==1);
    rollback_result=ESP_OK;canned=(profile_result_t){.rolled_back=true,.kept_mask=1u<<PK_HEALTH};r=post("{\"action\":\"rollback\"}");assert(r.status==200&&strstr(r.reply,"\"kept\":[\"health_monitor\"]"));
    httpd_req_t denied={.content_len=2,.body="{}",.authorized=false};int before=applies;post_profiles(&denied);assert(denied.status==401&&applies==before);
    puts("PASS: profile POST validation and auth, and truthful save acknowledgement with cJSON allocation failures (fixtures)");
}
'''
STUBS2 = {'esp_err.h': STUBS['esp_err.h'], 'esp_http_server.h': '#pragma once\ntypedef struct httpd_req httpd_req_t;\ntypedef void *httpd_handle_t;\n'}
with tempfile.TemporaryDirectory(prefix='config-profiles-http-') as folder:
    path = Path(folder)
    for name, text in STUBS2.items(): (path / name).write_text(text, encoding='utf-8')
    (path / 'http.c').write_text(HTTP, encoding='utf-8')
    binary = path / ('http.exe' if os.name == 'nt' else 'http')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', str(path), '-I', str(ROOT / 'main')]
    libs = ['-lm']; dep = os.environ.get('CJSON_SOURCE')
    if dep: flags += ['-I', str(Path(dep).parent), dep]
    else:
        flags += subprocess.check_output(['pkg-config', '--cflags', 'libcjson'], text=True).split()
        libs += subprocess.check_output(['pkg-config', '--libs', 'libcjson'], text=True).split()
    if os.environ.get('PROFILE_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'http.c'), '-o', str(binary), *libs], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
