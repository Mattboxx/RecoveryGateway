"""Actual entity serializer and batch cursor. MQTT acceptance is mocked, not HA."""
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'main/mqtt_integration.c').read_text()
src='static bool add_device'+source.split('static bool add_device',1)[1].split('/* QoS1 retained state',1)[0]
clear=source[source.index('static void discovery_clear_topic('):source.index('static bool add_device(')]
PROGRAM=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "discovery_budget.h"
typedef struct {char discovery_prefix[48],base_topic[96],uri[160];bool home_assistant_discovery;} mqtt_integration_config_t;
static const char *s_catalog_prefix="homeassistant", *s_retiring_prefix;
static uint8_t s_client_broker[32];
static discovery_budget_t s_discovery;
static char s_device_id[24]="fixture",s_availability_topic[128]="fixture/availability",s_state_topic[64]="fixture/state";
static unsigned accepted,allocations,fail_at,live;
static int publish_result=1;
static int publish(const char *t,const char *j,int retain){assert(t&&j&&retain);if(strstr(t,"/event/")){assert(strstr(j,"\"event_types\":[\"possible_blackout\"]"));assert(strstr(j,"\"qos\":1"));}if(publish_result>=0)accepted++;return publish_result;}
static void *allocate(size_t n){if(++allocations==fail_at)return NULL;void *p=malloc(n);if(p)live++;return p;}
static void release(void *p){if(p)live--;free(p);}
typedef int esp_err_t;
typedef int mbedtls_md_info_t;
#define MBEDTLS_MD_SHA256 1
#define ESP_OK 0
#define ESP_ERR_NVS_NOT_FOUND 1
#define ESP_ERR_INVALID_SIZE 2
#define ESP_ERR_INVALID_ARG 3
#define EXT_RAM_BSS_ATTR
#define ESP_LOGI(...) ((void)0)
#define WOL_MAX_DEVICES 12
#define TAILNET_FORWARD_MAX 8
typedef struct {uint8_t mac[6];char name[32];} wol_device_t;
typedef struct {char name[32],destination[96];} tailnet_forward_rule_t;
static bool have_device;
static const uint8_t fixture_mac[6]={2,0,0,0,0,1};
static int wol_count(void){return have_device;}
static bool wol_get(int i,wol_device_t *out){
    if(i || !have_device)return false;
    memcpy(out->mac,fixture_mac,6);strcpy(out->name,"Fixture");return true;
}
static int tailnet_forward_count(void){return 0;}
static bool tailnet_forward_get(int i,tailnet_forward_rule_t *r,void *out){(void)i;(void)r;(void)out;return false;}
static uint32_t service_lease_token(const tailnet_forward_rule_t *r){(void)r;return 1;}
static const mbedtls_md_info_t *mbedtls_md_info_from_type(int type){static int h;assert(type==MBEDTLS_MD_SHA256);return &h;}
static int mbedtls_md(const mbedtls_md_info_t *m,const unsigned char *bytes,size_t n,uint8_t *out){
    assert(m && n);memset(out,bytes[n-1],32);return 0;
}
static size_t strlcpy_fixture(char *out,const char *in,size_t cap){snprintf(out,cap,"%s",in);return strlen(in);}
#define strlcpy strlcpy_fixture
static unsigned char disk[1024];
static size_t saved;
static unsigned commits, deletes, changed_wol;
static bool fail_commit, fail_ack;
static const char *expected_retired_prefix;
static bool delete_retained_topic(const char *topic){
    assert(expected_retired_prefix && !strncmp(topic,expected_retired_prefix,strlen(expected_retired_prefix)));
    assert(strstr(topic,"/fixture/") && strstr(topic,"/config"));
    if (fail_ack)return false;
    deletes++;
    if(strstr(topic,"_020000000001/config"))changed_wol++;
    return true;
}
static int history_run_job(esp_err_t (*fn)(void *),void *arg){return fn(arg);}
static int nvs_param_get_blob(const char *key,void *out,size_t *cap){
    assert(!strcmp(key,"mqtt_ha_idx1"));
    if(!saved)return ESP_ERR_NVS_NOT_FOUND;
    assert(*cap>=saved);memcpy(out,disk,saved);*cap=saved;return ESP_OK;
}
static int nvs_param_set_blob(const char *key,const void *bytes,size_t n){
    assert(!strcmp(key,"mqtt_ha_idx1") && n<=sizeof disk);
    if(fail_commit)return -1;
    memcpy(disk,bytes,n);saved=n;commits++;return ESP_OK;
}
'''
TAIL=r'''
static void one(void){discovery_publish_entity("sensor","one","Fixture","fixture/state","{{ value_json.one }}",NULL,NULL,"B");}
static void reconcile(mqtt_integration_config_t *cfg){
    for(int i=0;i<100;i++){discovery_begin(&s_discovery);publish_discovery(cfg);if(discovery_finished(&s_discovery))return;}
    assert(0);
}
int main(void){
    cJSON_Hooks hooks={allocate,release};cJSON_InitHooks(&hooks);
    discovery_begin(&s_discovery);one();assert(accepted==1&&s_discovery.cursor==1&&discovery_finished(&s_discovery));assert(!live);
    unsigned total=allocations;
    for(unsigned i=1;i<=total;i++){discovery_reset(&s_discovery);discovery_begin(&s_discovery);allocations=0;fail_at=i;accepted=0;one();assert(!accepted&&s_discovery.failed&&!s_discovery.cursor&&!live);}
    fail_at=0;allocations=0;accepted=0;discovery_reset(&s_discovery);discovery_begin(&s_discovery);
    discovery_publish_entity("event","power","Power","fixture/event/power",NULL,NULL,NULL,NULL);
    assert(accepted==1&&s_discovery.cursor==1&&!live);total=allocations;
    for(unsigned i=1;i<=total;i++){
      discovery_reset(&s_discovery);discovery_begin(&s_discovery);allocations=0;fail_at=i;accepted=0;
      discovery_publish_entity("event","power","Power","fixture/event/power",NULL,NULL,NULL,NULL);
      assert(!accepted&&s_discovery.failed&&!s_discovery.cursor&&!live);
    }
    fail_at=0;accepted=0;discovery_reset(&s_discovery);
    unsigned passes=0;
    while(s_discovery.cursor<100){
        discovery_begin(&s_discovery);unsigned before=accepted;
        for(unsigned i=0;i<100;i++)if(discovery_visit(&s_discovery)){accepted++;discovery_result(&s_discovery,true);}
        assert(accepted-before<=4);passes++;
    }
    assert(passes==25&&accepted==100&&discovery_finished(&s_discovery));
    discovery_reset(&s_discovery);discovery_begin(&s_discovery);publish_result=-2;one();assert(!s_discovery.cursor&&s_discovery.failed);
    discovery_begin(&s_discovery);publish_result=1;one();assert(s_discovery.cursor==1&&!s_discovery.failed);
    assert(!live);cJSON_InitHooks(NULL);
    mqtt_integration_config_t cfg={.uri="mqtt://broker1",.base_topic="fixture",.discovery_prefix="homeassistant",
                                   .home_assistant_discovery=true};
    assert(ha_broker_hash(cfg.uri,s_client_broker));
    discovery_reset(&s_discovery);have_device=true;fail_commit=true;
    unsigned before=accepted;
    discovery_begin(&s_discovery);publish_discovery(&cfg);
    assert(s_discovery.failed && !saved && accepted==before);
    fail_commit=false;reconcile(&cfg);
    assert(commits==1 && saved && accepted>before);
    /* Reboot with device removed while disconnected. Failed deletion must
     * leave the previous inventory intact until both PUBACKs arrive. */
    discovery_reset(&s_discovery);s_ha_loaded=false;have_device=false;fail_ack=true;
    expected_retired_prefix="homeassistant/";
    discovery_begin(&s_discovery);publish_discovery(&cfg);
    assert(s_discovery.failed && commits==1 && !deletes);
    fail_ack=false;reconcile(&cfg);
    assert(commits==2 && deletes==2 && changed_wol==2);
    /* Old prefixes are retired only when the matching broker is connected. */
    discovery_reset(&s_discovery);strcpy(cfg.discovery_prefix,"newprefix");strcpy(cfg.uri,"mqtt://broker2");
    assert(ha_broker_hash(cfg.uri,s_client_broker));
    reconcile(&cfg);assert(commits==3 && deletes==2);
    discovery_reset(&s_discovery);strcpy(cfg.uri,"mqtt://broker1");
    assert(ha_broker_hash(cfg.uri,s_client_broker));
    reconcile(&cfg);assert(commits==5 && deletes>50);
    unsigned retired=deletes;
    discovery_reset(&s_discovery);cfg.home_assistant_discovery=false;
    expected_retired_prefix="newprefix/";reconcile(&cfg);
    assert(commits==6 && deletes>retired && !s_retiring_prefix);
    /* Corruption in a vacant slot must not be interpreted as a MAC list. */
    ha_scope_t broken[HA_INVENTORY_SLOTS]={0};
    broken[0].count=255;memcpy(disk,broken,sizeof broken);saved=sizeof broken;
    assert(ha_inventory_load(NULL)==ESP_ERR_INVALID_ARG);
    puts("PASS: actual HA entity serializer every-allocation refusal, bounded four-entity batches, cursor retention on full outbox (mock MQTT)");
    puts("PASS: tracked WoL retirement across reboot, failed PUBACK, scoped prefix migration and disable");
}
'''
with tempfile.TemporaryDirectory(prefix='mqtt-discovery-') as folder:
    p=Path(folder);(p/'test.c').write_text(PROGRAM+clear+src+TAIL);binary=p/('test.exe' if os.name=='nt' else 'test')
    flags=['-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT/'main')];libs=[]
    cjson=os.environ.get('CJSON_SOURCE')
    if cjson:flags+=['-I',str(Path(cjson).parent),cjson]
    else:
        flags+=subprocess.check_output(['pkg-config','--cflags','libcjson'],text=True).split()
        libs+=subprocess.check_output(['pkg-config','--libs','libcjson'],text=True).split()
    if os.environ.get('DISCOVERY_SANITIZE')=='1':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC','gcc'),*flags,str(p/'test.c'),'-o',str(binary),*libs],check=True)
    subprocess.run([str(binary)],check=True,timeout=30)
