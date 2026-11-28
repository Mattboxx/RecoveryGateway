/* Gateway/DNS/configured Internet/Tailnet-service evidence. No default external
 * target. One check at a time on the existing optional worker, no power action.
 * SPDX-License-Identifier: GPL-3.0-only */
#include "health_monitor.h"
#include "uplink_services.h"
#include "homelab_ops.h"
#include "tailscale_config.h"
#include "mqtt_integration.h"
#include "ntfy_integration.h"
#include "nvs_params.h"
#include "nvs.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "microlink.h"
#include "ml_policy.h"
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#define HEALTH_MAGIC 0x484c5431u
typedef struct {uint32_t magic,version;health_config_t config;uint32_t checksum;} health_store_t;
typedef enum {H_UNVERIFIED,H_OK,H_DEGRADED,H_DOWN,H_UNKNOWN,H_RESOURCE} health_state;
static const char *const health_states[]={"not-verified","operational","degraded","down","inconclusive","resource-deferred"};
static const char *const health_roles[]={"gateway-tcp","dns-lookup","internet-target-tcp","tailnet-service-tcp"};
typedef struct {health_state state;int outcome;unsigned failures;uint32_t latency;uint64_t observed,due;} health_result;
static health_config_t configuration;
static health_result observations[4];
static SemaphoreHandle_t health_lock;
static StaticSemaphore_t health_lock_storage;
static portMUX_TYPE health_init_lock=portMUX_INITIALIZER_UNLOCKED;
static bool health_loaded;
static uint32_t health_generation;
static unsigned health_cursor;
static uint64_t health_next;
#define HLOCK() xSemaphoreTake(health_lock,portMAX_DELAY)
#define HUNLOCK() xSemaphoreGive(health_lock)
static uint64_t health_now(void){return (uint64_t)esp_timer_get_time()/1000;}
static uint32_t health_checksum(const health_store_t *s){
    uint32_t h=2166136261u;const uint8_t *p=(const uint8_t*)s;
    for(size_t i=0;i<offsetof(health_store_t,checksum);i++)h=(h^p[i])*16777619u;
    return h;
}
static bool health_name(const char *s,size_t size){
    if(!memchr(s,0,size))return false;
    for(const unsigned char *p=(const unsigned char*)s;*p;p++)
        if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='-'||*p=='.'))return false;
    return !*s || (*s!='.'&&s[strlen(s)-1]!='.');
}
static bool health_public(uint32_t ip){
    unsigned a=ip>>24,b=(ip>>16)&255;
    return a && a!=10 && a!=127 && a<224 && a!=0 && a!=255
        && !(a==100&&b>=64&&b<=127) && !(a==169&&b==254)
        && !(a==172&&b>=16&&b<=31) && !(a==192&&(b==168||b==0))
        && !(a==198&&(b==18||b==19));
}
static bool health_valid(const health_config_t *c){
    if(!c||c->enabled>1||c->notify>1||c->failure_threshold<1||c->failure_threshold>5
       ||c->interval_s<30||c->interval_s>3600||!health_name(c->dns_name,sizeof c->dns_name)
       ||!health_name(c->tailnet_target,sizeof c->tailnet_target)||!memchr(c->internet_ip,0,sizeof c->internet_ip))return false;
    struct in_addr a;
    if(c->internet_ip[0]&&(!c->internet_port||inet_pton(AF_INET,c->internet_ip,&a)!=1||!health_public(ntohl(a.s_addr))))return false;
    if(c->tailnet_target[0]&&!c->tailnet_port)return false;
    if(c->tailnet_target[0]&&inet_pton(AF_INET,c->tailnet_target,&a)==1 && (ntohl(a.s_addr)&0xffc00000u)!=0x64400000u)return false;
    return true;
}
EXT_RAM_BSS_ATTR static saved_tcp_target_t saved_targets[SAVED_TCP_MAX];
EXT_RAM_BSS_ATTR static health_result saved_results[SAVED_TCP_MAX];
static uint32_t saved_generation;
static uint64_t saved_next, saved_manual_after;
static int saved_pending = -1;
static ops_recovery_origin_t saved_origin;
static uint32_t saved_destination;
static unsigned saved_cursor;
static bool saved_running;

static bool saved_valid(const saved_tcp_target_t targets[SAVED_TCP_MAX])
{
    if (!targets) return false;
    for (unsigned i=0; i<SAVED_TCP_MAX; ++i) {
        const saved_tcp_target_t *t=&targets[i];
        if (!memchr(t->name,0,sizeof t->name) || !memchr(t->address,0,sizeof t->address)) return false;
        if (!t->name[0]) {
            if (t->address[0] || t->port || t->interval_s || t->notify) return false;
            continue;
        }
        struct in_addr addr;
        if (!t->port || t->notify>1 || (t->interval_s && (t->interval_s<30 || t->interval_s>3600))
                || inet_pton(AF_INET,t->address,&addr)!=1) return false;
        uint32_t ip=ntohl(addr.s_addr);
        unsigned octet=ip>>24;
        if (!octet || octet==127 || octet>=224 || (ip&0xffff0000u)==0xa9fe0000u) return false;
        for (const char *c=t->name;*c;++c)
            if (!((*c>='a'&&*c<='z')||(*c>='A'&&*c<='Z')||(*c>='0'&&*c<='9')||*c=='-'||*c=='_')) return false;
        for (unsigned j=0;j<i;++j)
            if (!strcasecmp(t->name,targets[j].name)) return false;
    }
    return true;
}

void health_monitor_init(void){
    portENTER_CRITICAL(&health_init_lock);
    if(!health_lock)health_lock=xSemaphoreCreateMutexStatic(&health_lock_storage);
    portEXIT_CRITICAL(&health_init_lock);
    HLOCK();if(health_loaded){HUNLOCK();return;}
    configuration=(health_config_t){.interval_s=60,.failure_threshold=3};
    health_store_t s={0};size_t size=sizeof s;nvs_handle_t nvs;
    if(nvs_open(NVS_NAMESPACE,NVS_READONLY,&nvs)==ESP_OK){
        if(nvs_get_blob(nvs,"ops_health",&s,&size)==ESP_OK&&size==sizeof s&&s.magic==HEALTH_MAGIC
           &&s.version==1&&s.checksum==health_checksum(&s)&&health_valid(&s.config))configuration=s.config;
        size=sizeof saved_targets;
        if(nvs_get_blob(nvs,"ops_tcp_v1",saved_targets,&size)!=ESP_OK || size!=sizeof saved_targets || !saved_valid(saved_targets))
            memset(saved_targets,0,sizeof saved_targets);
        nvs_close(nvs);
    }
    health_loaded=true;HUNLOCK();
}
bool health_monitor_enabled(void){health_monitor_init();HLOCK();bool enabled=configuration.enabled;HUNLOCK();return enabled;}
bool saved_tcp_schedule_enabled(void)
{
    health_monitor_init();
    HLOCK();
    bool enabled=false;
    for (unsigned i=0;i<SAVED_TCP_MAX;++i) enabled=enabled || saved_targets[i].interval_s;
    HUNLOCK();
    return enabled;
}
static esp_err_t health_store_locked(const health_config_t *config){
    health_store_t s={.magic=HEALTH_MAGIC,.version=1,.config=*config};s.checksum=health_checksum(&s);
    return nvs_param_set_blob("ops_health",&s,sizeof s);
}
static void health_publish_locked(const health_config_t *config){
    configuration=*config;memset(observations,0,sizeof observations);health_next=0;health_generation++;
}
static esp_err_t health_save_locked(const health_config_t *config){
    esp_err_t err=health_store_locked(config);
    if(err==ESP_OK)health_publish_locked(config);
    return err;
}
esp_err_t health_monitor_set(const health_config_t *config){
    if(!health_valid(config))return ESP_ERR_INVALID_ARG;
    health_monitor_init();
    if(config->enabled){esp_err_t e=homelab_ops_start_optional_worker();if(e!=ESP_OK)return e;}
    HLOCK();esp_err_t err=health_save_locked(config);HUNLOCK();return err;
}
esp_err_t health_monitor_set_enabled(bool enabled){
    health_monitor_init();
    if(enabled){esp_err_t e=homelab_ops_start_optional_worker();if(e!=ESP_OK)return e;}
    HLOCK();health_config_t c=configuration;c.enabled=enabled;
    esp_err_t err=health_save_locked(&c);HUNLOCK();return err;
}
esp_err_t health_monitor_stage_enabled(bool expected, bool enabled){
    health_monitor_init();
    if(enabled){esp_err_t e=homelab_ops_start_optional_worker();if(e!=ESP_OK)return e;}
    HLOCK();
    if ((configuration.enabled != 0) != expected) { HUNLOCK(); return ESP_ERR_INVALID_STATE; }
    health_config_t next=configuration;
    next.enabled=enabled;
    esp_err_t err=health_store_locked(&next);
    if (err!=ESP_OK) HUNLOCK();
    return err;
}
void health_monitor_finish_staged(bool enabled, bool committed){
    if (committed) {
        health_config_t next=configuration;
        next.enabled=enabled;
        health_publish_locked(&next);
    }
    HUNLOCK();
}
esp_err_t saved_tcp_set(const saved_tcp_target_t targets[SAVED_TCP_MAX])
{
    if (!saved_valid(targets)) return ESP_ERR_INVALID_ARG;
    health_monitor_init();
    for (unsigned i=0;i<SAVED_TCP_MAX;++i) {
        if (!targets[i].interval_s) continue;
        esp_err_t err=homelab_ops_start_optional_worker();
        if (err!=ESP_OK) return err;
        break;
    }
    HLOCK();
    nvs_handle_t nvs;
    esp_err_t err=nvs_open(NVS_NAMESPACE,NVS_READWRITE,&nvs);
    if (err==ESP_OK) {
        err=nvs_set_blob(nvs,"ops_tcp_v1",targets,sizeof saved_targets);
        if (err==ESP_OK) err=nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (err==ESP_OK) {
        memcpy(saved_targets,targets,sizeof saved_targets);
        memset(saved_results,0,sizeof saved_results);
        saved_pending=-1;
        saved_next=0;
        saved_generation++;
    }
    HUNLOCK();
    return err;
}

esp_err_t saved_tcp_remote_request(const char *name, ops_recovery_origin_t origin, uint32_t destination)
{
    if (!name || !*name || strlen(name)>=sizeof saved_targets[0].name) return ESP_ERR_INVALID_ARG;
    if (!remote_command_active(origin,destination) || !homelab_ops_recovery_allowed(origin)) return ESP_ERR_NOT_SUPPORTED;
    health_monitor_init();
    HLOCK();
    bool exists=false;
    for (unsigned i=0;i<SAVED_TCP_MAX;++i)
        if (saved_targets[i].name[0] && !strcasecmp(name,saved_targets[i].name)) {exists=true;break;}
    HUNLOCK();
    if (!exists) return ESP_ERR_NOT_FOUND;
    esp_err_t err=homelab_ops_start_optional_worker();
    if (err!=ESP_OK) return err;
    HLOCK();
    if (saved_pending>=0 || saved_running) err=ESP_ERR_INVALID_STATE;
    else if (health_now()<saved_manual_after) err=ESP_ERR_TIMEOUT;
    else {
        err=ESP_ERR_NOT_FOUND;
        for (unsigned i=0;i<SAVED_TCP_MAX;++i) {
            if (!saved_targets[i].name[0] || strcasecmp(name,saved_targets[i].name)) continue;
            saved_pending=(int)i;
            saved_origin=origin;
            saved_destination=destination;
            saved_manual_after=health_now()+5000;
            err=ESP_OK;
            break;
        }
    }
    HUNLOCK();
    return err;
}

esp_err_t saved_tcp_request(const char *name, ops_recovery_origin_t origin)
{
    return saved_tcp_remote_request(name, origin, 0);
}

static const char *saved_state(const health_result *r)
{
    if (!r->observed) return "not checked";
    return r->outcome>0 ? "reachable" : r->outcome==0 ? "not reachable" : "inconclusive";
}

void saved_tcp_summary(char *out,size_t capacity)
{
    if (!out || !capacity) return;
    health_monitor_init();
    HLOCK();
    size_t used=0;
    out[0]='\0';
    for (unsigned i=0;i<SAVED_TCP_MAX;++i) {
        if (!saved_targets[i].name[0]) continue;
        int n=snprintf(out+used,capacity-used,"%s%s: %s",used?"\n":"Saved TCP checks (last result)\n\n",saved_targets[i].name,saved_state(&saved_results[i]));
        if (n<0 || (size_t)n>=capacity-used) break;
        used+=(size_t)n;
    }
    if (!out[0]) snprintf(out,capacity,"No saved TCP checks. Add one in Health & Resources.");
    HUNLOCK();
}

static bool health_configured(const health_config_t *c,unsigned role){
    return role==0?c->gateway_port!=0:role==1?c->dns_name[0]!=0:role==2?c->internet_ip[0]!=0:c->tailnet_target[0]!=0;
}
static bool health_uplink(esp_netif_ip_info_t *info){
    return uplink_address(uplink_internet_netif(), info);
}
static int health_tcp(uint32_t nbo,uint16_t port){
    int fd=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(fd<0)return -1;
    int flags=fcntl(fd,F_GETFL,0);if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0){close(fd);return -1;}
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr={.s_addr=nbo}};
    int result=connect(fd,(struct sockaddr*)&a,sizeof a);
    if(result==0){close(fd);return 1;}
    if(errno!=EINPROGRESS){int err=errno;close(fd);return err==ECONNREFUSED||err==ETIMEDOUT?0:-1;}
    fd_set writable;FD_ZERO(&writable);FD_SET(fd,&writable);struct timeval timeout={.tv_sec=1};
    int ready=select(fd+1,NULL,&writable,NULL,&timeout),error=0;socklen_t size=sizeof error;
    int outcome=ready==0 ? 0 : -1;
    if (ready>0 && getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)==0)
        outcome=!error ? 1 : error==ECONNREFUSED || error==ETIMEDOUT ? 0 : -1;
    close(fd);
    return outcome;
}
/* The shared ops worker executes at most one extra TCP check per turn. */
static void saved_tcp_poll(void)
{
    uint64_t now=health_now();
    HLOCK();
    int index=saved_pending;
    bool manual=index>=0;
    if (!manual && now>=saved_next) {
        for (unsigned i=0;i<SAVED_TCP_MAX;++i) {
            unsigned candidate=(saved_cursor+i)%SAVED_TCP_MAX;
            if (saved_targets[candidate].interval_s && now>=saved_results[candidate].due) {
                index=(int)candidate;
                saved_cursor=(candidate+1)%SAVED_TCP_MAX;
                break;
            }
        }
    }
    if (index<0) { HUNLOCK(); return; }
    ops_recovery_origin_t origin=saved_origin;
    uint32_t destination=manual ? saved_destination : 0;
    saved_pending=-1;
    saved_running=true;
    saved_next=now+5000;
    saved_tcp_target_t t=saved_targets[index];
    uint32_t generation=saved_generation;
    HUNLOCK();

    struct in_addr a;
    esp_netif_ip_info_t uplink={0};
    int result=-1;
    if ((!manual || (remote_command_active(origin,destination) && homelab_ops_recovery_allowed(origin))) &&
        inet_pton(AF_INET,t.address,&a)==1 && homelab_ops_admit()) {
        uint32_t ip=ntohl(a.s_addr);
        bool tailnet=(ip&0xffc00000u)==0x64400000u;
        if (tailnet) {
            ml_policy_status_t policy;
            ml_policy_get_status(&policy);
            if (tailscale_is_connected() && policy.authority_ready)
                result=health_tcp(a.s_addr,t.port);
        } else if (uplink_address(uplink_internet_netif(),&uplink) ||
                   (uplink_address(uplink_local_netif(),&uplink) && uplink.netmask.addr &&
                    (a.s_addr & uplink.netmask.addr) == (uplink.ip.addr & uplink.netmask.addr))) {
            result=health_tcp(a.s_addr,t.port);
        }
    }
    uint64_t finished=health_now();
    bool allowed=!manual || (remote_command_active(origin,destination) && homelab_ops_recovery_allowed(origin));
    bool notify=false;
    HLOCK();
    saved_running=false;
    if (allowed && generation==saved_generation) {
        health_result *r=&saved_results[index];
        bool new_failure=!manual && r->state==H_OK && result==0;
        r->outcome=result;
        r->observed=finished;
        r->latency=(uint32_t)(finished-now);
        if (!manual) {
            if (result>=0) r->state=result>0?H_OK:H_DOWN;
            r->due=finished+(uint64_t)t.interval_s*1000;
        }
        notify=(manual && origin!=OPS_RECOVERY_LOCAL) || (t.notify && (manual || new_failure));
    }
    HUNLOCK();
    if (notify) {
        char message[100];
        snprintf(message,sizeof message,"Service: %s\nTCP check: %s.",t.name,result>0?"reachable":result==0?"not reachable":"inconclusive");
        if (destination) (void)remote_command_reply(origin,destination,message);
        else (void)ntfy_integration_queue_event(message);
    }
}

/* Positive is a specific check, negative infrastructure/unknown is not a
 * definitive service failure. NXDOMAIN is inconclusive, not "Internet down". */
static int health_probe(const health_config_t *c,unsigned role){
    esp_netif_ip_info_t info={0};if(!health_uplink(&info))return -3;
    if(role==0)return info.gw.addr?health_tcp(info.gw.addr,c->gateway_port):-4;
    if(role==1){
        struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM},*answer=NULL;
        int result=getaddrinfo(c->dns_name,NULL,&hints,&answer);bool ok=result==0&&answer;
        if(answer)freeaddrinfo(answer);
        return ok?1:-5;
    }
    if(role==2){struct in_addr a;if(inet_pton(AF_INET,c->internet_ip,&a)!=1)return -1;return health_tcp(a.s_addr,c->internet_port);}
    ml_policy_status_t policy;ml_policy_get_status(&policy);microlink_t *ml=tailscale_get_microlink();
    if(!tailscale_is_connected()||!ml)return -7;
    if(!policy.authority_ready)return -6;
    struct in_addr a;uint32_t ip=inet_pton(AF_INET,c->tailnet_target,&a)==1?ntohl(a.s_addr):microlink_resolve(ml,c->tailnet_target);
    return (ip&0xffc00000u)==0x64400000u?health_tcp(htonl(ip),c->tailnet_port):-8;
}
static void health_observe(health_result *r,int outcome,unsigned threshold,uint64_t now,uint32_t latency,unsigned interval){
    r->observed=now;r->latency=latency;r->outcome=outcome;
    if(outcome>0){r->state=H_OK;r->failures=0;}
    else if(outcome==0){if(r->failures<5)r->failures++;r->state=r->failures>=threshold?H_DOWN:H_DEGRADED;}
    else {r->state=outcome==-2?H_RESOURCE:H_UNKNOWN;r->failures=0;}
    unsigned shift=r->failures>4?4:r->failures;
    r->due=now+((uint64_t)interval*1000<<shift);
}
static const char *health_reason(const health_result *r){
    if(!r->observed)return "No check completed in this boot";
    switch(r->outcome){
    case 1:return "Configured check succeeded; not proof of application or whole-network health";
    case 0:return "TCP connection did not succeed; timeout, refusal and filtering are not distinguished";
    case -2:return "Optional-work admission deferred the check";
    case -3:return "Selected uplink (WiFi, or Ethernet while selected) has no usable local IPv4 address";
    case -4:return "Uplink did not provide a gateway address";
    case -5:return "SDK name lookup did not yield an IPv4 result; this alone does not prove a DNS outage";
    case -6:return "Current Tailnet policy authority is incomplete or suspended";
    case -7:return "Tailnet control connection is not available";
    case -8:return "Tailnet target did not resolve from a literal or the local peer cache";
    default:return "Local probe setup failed or check is inconclusive";
    }
}
static const char *health_next_step(const health_result *r){
    if(!r->observed)return "Enable and configure the desired check, then wait for its scheduled turn";
    switch(r->outcome){
    case 1:return "Use an application-level client if application readiness matters";
    case 0:return "Verify the configured service/port and its firewall; a closed gateway port is not router failure";
    case -2:return "Inspect internal heap, largest block and socket headroom before increasing optional load";
    case -3:case -4:return "Inspect WiFi association, DHCP/static address and gateway settings";
    case -5:return "Verify the lookup name and configured resolver; cached answers do not test fresh DNS traffic";
    case -6:return "Inspect control-map/reset diagnostics; do not bypass the policy gate";
    case -7:return "Inspect Tailscale login/control status and local uplink; authentication failure is only a hypothesis";
    case -8:return "Verify a current Tailnet IPv4 or cached peer hostname; do not infer that the peer is offline";
    default:return "Inspect local resources and retry at the bounded cadence";
    }
}
void health_monitor_poll(void){
    health_monitor_init();uint64_t now=health_now();int role=-1;
    HLOCK();health_config_t c=configuration;uint32_t generation=health_generation;
    if(c.enabled&&now>=health_next){
        for(unsigned i=0;i<4;i++){unsigned r=(health_cursor+i)%4;
            if(health_configured(&c,r)&&now>=observations[r].due){role=(int)r;health_cursor=(r+1)%4;break;}}
        health_next=now+(uint64_t)c.interval_s*1000;
    }
    HUNLOCK();if(role<0){saved_tcp_poll();return;}
    int result=homelab_ops_admit()?health_probe(&c,(unsigned)role):-2;uint64_t finished=health_now();bool notify=false,changed=false;
    HLOCK();if(configuration.enabled&&health_generation==generation){
        health_state previous=observations[role].state;
        health_observe(&observations[role],result,c.failure_threshold,finished,(uint32_t)(finished-now),c.interval_s);
        changed=observations[role].state!=previous;notify=c.notify&&changed&&observations[role].state==H_DOWN;
    }HUNLOCK();
    if(notify){char message[160];snprintf(message,sizeof message,"Configured %s check is down after repeated failures. This is not proof of a whole-network outage.",health_roles[role]);(void)ntfy_integration_queue_event(message);}
    if(changed)mqtt_integration_publish_now();
    saved_tcp_poll();
}
void health_monitor_codes(uint8_t out[4]){
    health_monitor_init();HLOCK();health_config_t c=configuration;health_result r[4];memcpy(r,observations,sizeof r);HUNLOCK();
    uint64_t now=health_now();
    for(unsigned i=0;i<4;i++){
        if(!c.enabled)out[i]=0;else if(!health_configured(&c,i))out[i]=1;
        else if(r[i].observed&&now-r[i].observed>((uint64_t)c.interval_s*16+30)*1000)out[i]=8;
        else out[i]=(uint8_t)(2+r[i].state);
    }
}
cJSON *health_monitor_snapshot(bool detailed){
    health_monitor_init();HLOCK();health_config_t c=configuration;health_result r[4];memcpy(r,observations,sizeof r);HUNLOCK();
    cJSON *root=cJSON_CreateObject();if(!root)return NULL;
    cJSON_AddBoolToObject(root,"enabled",c.enabled);cJSON_AddBoolToObject(root,"notify",c.notify);
    cJSON_AddNumberToObject(root,"interval_s",c.interval_s);cJSON_AddNumberToObject(root,"failure_threshold",c.failure_threshold);
    if(detailed){cJSON_AddNumberToObject(root,"gateway_port",c.gateway_port);cJSON_AddStringToObject(root,"dns_name",c.dns_name);
        cJSON_AddStringToObject(root,"internet_ip",c.internet_ip);cJSON_AddNumberToObject(root,"internet_port",c.internet_port);
        cJSON_AddStringToObject(root,"tailnet_target",c.tailnet_target);cJSON_AddNumberToObject(root,"tailnet_port",c.tailnet_port);}
    wifi_ap_record_t ap;esp_netif_ip_info_t info={0};ml_policy_status_t policy;ml_policy_get_status(&policy);
    cJSON_AddBoolToObject(root,"wifi_associated",esp_wifi_sta_get_ap_info(&ap)==ESP_OK);
    cJSON_AddBoolToObject(root,"uplink_address_available",health_uplink(&info));
    cJSON_AddBoolToObject(root,"control_connected",tailscale_is_connected());cJSON_AddBoolToObject(root,"policy_authority_ready",policy.authority_ready);
    cJSON_AddStringToObject(root,"global_data_plane","not-verified");
    cJSON_AddStringToObject(root,"route_approval","unknown");
    cJSON *checks=cJSON_AddArrayToObject(root,"checks");uint64_t now=health_now();
    for(unsigned i=0;checks&&i<4;i++){
        cJSON *item=cJSON_CreateObject();if(!item)break;
        bool configured=health_configured(&c,i);const char *state=!c.enabled?"disabled":!configured?"not-configured":health_states[r[i].state];
        if(c.enabled&&configured&&r[i].observed&&now-r[i].observed>((uint64_t)c.interval_s*16+30)*1000)state="stale";
        cJSON_AddStringToObject(item,"role",health_roles[i]);cJSON_AddStringToObject(item,"state",state);
        cJSON_AddNumberToObject(item,"observed_uptime_ms",r[i].observed);cJSON_AddNumberToObject(item,"latency_ms",r[i].latency);
        cJSON_AddNumberToObject(item,"consecutive_failures",r[i].failures);cJSON_AddBoolToObject(item,"configured",configured);
        cJSON_AddStringToObject(item,"evidence",i==1?"SDK IPv4 name lookup (may be cached)":"TCP connect to one configured service, not application health");
        cJSON_AddStringToObject(item,"reason",!c.enabled?"Active checks are disabled":!configured?"No target/service is configured":health_reason(&r[i]));
        cJSON_AddStringToObject(item,"next_step",health_next_step(&r[i]));
        cJSON_AddItemToArray(checks,item);
    }
    if (detailed) {
        cJSON *saved=cJSON_AddArrayToObject(root,"saved_tcp");
        HLOCK();
        for (unsigned i=0;saved && i<SAVED_TCP_MAX;++i) {
            const saved_tcp_target_t *target=&saved_targets[i];
            if (!target->name[0]) continue;
            cJSON *item=cJSON_CreateObject();
            if (!item) break;
            cJSON_AddStringToObject(item,"name",target->name);
            cJSON_AddStringToObject(item,"address",target->address);
            cJSON_AddNumberToObject(item,"port",target->port);
            cJSON_AddNumberToObject(item,"interval_s",target->interval_s);
            cJSON_AddBoolToObject(item,"notify",target->notify);
            cJSON_AddStringToObject(item,"state",saved_state(&saved_results[i]));
            cJSON_AddNumberToObject(item,"observed_ms",saved_results[i].observed);
            cJSON_AddItemToArray(saved,item);
        }
        HUNLOCK();
    }
    return root;
}
