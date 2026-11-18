"""Actual cellular uplink core and HTTP API, no modem.

Compiles the real core, record loader and /api/cellular handlers of
main/cell_uplink.c with fixture NVS/HTTP: config validation per transport
(UART pins or USB), AT response parsers and line classifier, the USB serial
interface plan from synthetic configuration descriptors (known modems,
CDC-ACM, vendor probe order, RNDIS/ECM refusal, manual choice, malformed and
fuzzed input), primary/failover selection, fail-closed record load with the
version 1 -> 2 migration, write-only SIM PIN and password. UART, USB host,
PPP and any physical modem/SIM/carrier behavior are NOT covered.
CELL_SANITIZE=1 adds ASan/UBSan on Linux.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / 'main/cell_uplink.c').read_text(encoding='utf-8')
header = (ROOT / 'main/cell_uplink.h').read_text(encoding='utf-8')
types = 'enum {CELL_MODE_FAILOVER' + header.split('enum {CELL_MODE_FAILOVER', 1)[1].split('/* Core (pure, host-tested). */', 1)[0]
types += 'typedef struct {uint8_t streak;} cell_selector_t;\n#define CELL_STABLE_SAMPLES 3\n'
types += '#define CELL_CARRY_SETTLE_S' + header.split('#define CELL_CARRY_SETTLE_S', 1)[1].split('int cell_carry_update(', 1)[0]
core = source.split('/* --- cell core (begin) --- */', 1)[1].split('/* --- cell core (end) --- */', 1)[0]
records = '#define CELL_MAGIC' + source.split('#define CELL_MAGIC', 1)[1].split('\nstatic SemaphoreHandle_t s_lock;', 1)[0] + '\n'


def function(text, signature):
    at = text.index(signature)
    return text[at:text.index('\n}', at) + 2] + '\n'


COMMON = r'''
#include <assert.h>
#include <ctype.h>
#include <math.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define EXT_RAM_BSS_ATTR   /* PSRAM placement: no effect on the host */
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG 0x102
'''

PROGRAM = COMMON + r'''
#define NVS_READONLY 0
#define NVS_NAMESPACE "tsr"
typedef int nvs_handle_t;
''' + types + core + r'''
static unsigned char blob[512];static size_t blob_size;static int open_fail;
static esp_err_t nvs_open(const char *ns,int mode,nvs_handle_t *h){(void)ns;(void)mode;*h=1;return open_fail?ESP_FAIL:ESP_OK;}
static esp_err_t nvs_get_blob(nvs_handle_t h,const char *k,void *out,size_t *n){(void)h;assert(!strcmp(k,"cell_cfg"));if(!blob_size)return ESP_FAIL;if(*n<blob_size){*n=blob_size;return ESP_FAIL;}memcpy(out,blob,blob_size);*n=blob_size;return ESP_OK;}
static void nvs_close(nvs_handle_t h){(void)h;}
''' + records + ''.join(function(source, s) for s in ('static void defaults(', 'static uint32_t cell_fnv(', 'static uint32_t record_checksum(',
                                                    'static void migrate_v1(', 'static size_t record_encode(', 'static void load(', 'bool cell_uplink_usb_configured(')) + r'''
static cell_config_t good(void){cell_config_t c;defaults(&c);c.enabled=1;c.data_ack=1;strcpy(c.apn,"internet.example");return c;}
/* Synthetic USB configuration descriptors. */
static uint8_t D[1200];static size_t DL;
static void begin(void){memset(D,0,sizeof D);D[0]=9;D[1]=2;DL=9;}
static void put(const uint8_t *d,size_t n){memcpy(D+DL,d,n);DL+=n;}
static void iface(uint8_t num,uint8_t alt,uint8_t cls,uint8_t sub,uint8_t proto,uint8_t eps){uint8_t d[9]={9,4,num,alt,eps,cls,sub,proto,0};put(d,9);}
static void ep(uint8_t addr,uint8_t attr){uint8_t d[7]={7,5,addr,attr,64,0,0};put(d,7);}
static size_t end(void){D[2]=(uint8_t)(DL&255);D[3]=(uint8_t)(DL>>8);return DL;}
static void serial(uint8_t num,bool status){iface(num,0,0xff,0xff,0xff,status?3:2);if(status)ep((uint8_t)(0x81+num),3);ep((uint8_t)(0x81+num),2);ep((uint8_t)(1+num),2);}
static void acm(uint8_t ctrl){uint8_t iad[8]={8,0x0b,ctrl,2,2,2,1,0},hdr[5]={5,0x24,0,0x10,1},uni[5]={5,0x24,6,ctrl,(uint8_t)(ctrl+1)};
    put(iad,8);iface(ctrl,0,2,2,1,1);put(hdr,5);put(uni,5);ep((uint8_t)(0x81+ctrl),3);iface((uint8_t)(ctrl+1),0,0x0a,0,0,2);ep((uint8_t)(0x82+ctrl),2);ep((uint8_t)(2+ctrl),2);}
static void rndis(void){iface(0,0,2,2,0xff,1);ep(0x81,3);iface(1,0,0x0a,0,0,2);ep(0x82,2);ep(0x02,2);}
static int plan(uint16_t vid,uint16_t pid,uint8_t override,cell_usb_plan_t *p){size_t n=end();return cell_usb_plan(vid,pid,D,n,override,p);}
static bool order(const cell_usb_plan_t *p,int n,const uint8_t *want){if(p->count!=n)return false;for(int i=0;i<n;i++)if(p->iface[i]!=want[i])return false;return true;}
static bool valid(cell_config_t c){char why[96]="";bool ok=cell_config_valid(&c,why,sizeof why);assert(ok||why[0]);return ok;}
int main(void){
    cell_config_t d;defaults(&d);assert(!d.enabled&&valid(d)); /* the default record: off, no APN, no secrets */
    cell_config_t c=good();assert(valid(c));
    c.data_ack=0;assert(!valid(c));                                       /* never dial without the data notice */
    c=good();c.apn[0]=0;assert(!valid(c));c.enabled=0;assert(valid(c));
    c=good();strcpy(c.apn,"bad\"apn");assert(!valid(c));strcpy(c.apn,"bad\\apn");assert(!valid(c));strcpy(c.apn,"tab\tapn");assert(!valid(c));
    c=good();strcpy(c.user,"user\"x");assert(!valid(c));c=good();strcpy(c.password,"p\r\nATD");assert(!valid(c));
    c=good();strcpy(c.pin,"1234");assert(valid(c));strcpy(c.pin,"12345678");assert(valid(c));
    strcpy(c.pin,"123");assert(!valid(c));strcpy(c.pin,"12a4");assert(!valid(c));memset(c.pin,'1',sizeof c.pin);assert(!valid(c));
    int forbidden[]={0,3,19,20,26,33,37,38,39,40,43,44,45,46,49,-5};
    for(unsigned i=0;i<sizeof forbidden/sizeof *forbidden;i++){c=good();c.tx=(int8_t)forbidden[i];assert(!valid(c));}
    c=good();c.rx=-1;assert(!valid(c));c=good();c.rx=c.tx;assert(!valid(c));
    c=good();c.rts=5;assert(!valid(c));c.cts=6;assert(valid(c));c.cts=c.rts;assert(!valid(c));   /* RTS needs CTS */
    c=good();c.pwrkey=7;assert(valid(c));c.pwrkey=c.tx;assert(!valid(c));
    c=good();c.uart=0;assert(!valid(c));c.uart=3;assert(!valid(c));c.uart=2;assert(valid(c));
    c=good();c.baud=12345;assert(!valid(c));c.baud=921600;assert(valid(c));
    c=good();c.mode=2;assert(!valid(c));c=good();c.enabled=2;assert(!valid(c));c=good();c.roaming=2;assert(!valid(c));
    assert(!cell_config_valid(NULL,NULL,0));

    /* AT responses. */
    assert(cell_csq_to_dbm(0)==-113&&cell_csq_to_dbm(31)==-51&&!cell_csq_to_dbm(99)&&!cell_csq_to_dbm(32)&&!cell_csq_to_dbm(-1));
    assert(cell_parse_csq("+CSQ: 18,99\nOK\n")==18&&cell_parse_csq("+CSQ: 99,99\n")==99&&cell_parse_csq("+CSQ: x\n")==-1&&cell_parse_csq("OK\n")==-1&&cell_parse_csq(NULL)==-1);
    assert(cell_parse_reg("+CEREG: 0,1\nOK\n","+CEREG")==1&&cell_parse_reg("+CREG: 0,5\n","+CREG")==5);
    assert(cell_parse_reg("+CGREG: 2,1,\"1A2B\",\"01C2D3E4\",7\n","+CGREG")==1);
    assert(cell_parse_reg("+CEREG: 2\n","+CEREG")==2);                     /* URC form */
    assert(cell_parse_reg("+CEREG: 0,1\n","+CREG")==-1&&cell_parse_reg("+CGREG: 0,1\n","+CREG")==-1);   /* no prefix confusion */
    assert(cell_parse_reg("+CREG: 0,\n","+CREG")==-1&&cell_parse_reg("+CREG: 0,99\n","+CREG")==-1&&cell_parse_reg("ERROR\n","+CREG")==-1);
    assert(cell_parse_cpin("+CPIN: READY\nOK\n")==CELL_SIM_READY&&cell_parse_cpin("+CPIN: SIM PIN\n")==CELL_SIM_PIN);
    assert(cell_parse_cpin("+CPIN: SIM PUK\n")==CELL_SIM_PUK&&cell_parse_cpin("+CPIN: SIM PIN2\n")==CELL_SIM_OTHER);
    assert(cell_parse_cpin("+CPIN: SIM PUK2\n")==CELL_SIM_OTHER&&cell_parse_cpin("+CME ERROR: SIM not inserted\n")==CELL_SIM_OTHER);
    char name[12];
    assert(cell_parse_cops("+COPS: 0,0,\"vodafone IT\",7\n",name,sizeof name)&&!strcmp(name,"vodafone IT"));
    assert(cell_parse_cops("+COPS: 0,0,\"A very long operator\",7\n",name,sizeof name)&&strlen(name)==sizeof name-1);
    assert(!cell_parse_cops("+COPS: 0\n",name,sizeof name)&&!cell_parse_cops("+COPS: 0,0,\"\",7\n",name,sizeof name));
    assert(cell_parse_cops("+COPS: 0,0,\"x\x01y\",7\n",name,sizeof name)&&!strcmp(name,"x?y"));
    assert(cell_registered(1,false)&&!cell_registered(5,false)&&cell_registered(5,true)&&!cell_registered(2,true)&&!cell_registered(-1,true));

    /* Selection: failover only while the other uplink is down; primary after a stable window. */
    cell_selector_t s={0};
    assert(!cell_uplink_choose(&s,CELL_MODE_FAILOVER,true,true));
    assert(cell_uplink_choose(&s,CELL_MODE_FAILOVER,false,true));
    assert(!cell_uplink_choose(&s,CELL_MODE_FAILOVER,false,false)&&!s.streak);
    assert(!cell_uplink_choose(&s,CELL_MODE_FAILOVER,true,true));          /* back to WiFi/Ethernet at once */
    s=(cell_selector_t){0};
    for(int i=1;i<CELL_STABLE_SAMPLES;i++)assert(!cell_uplink_choose(&s,CELL_MODE_PRIMARY,true,true));
    assert(cell_uplink_choose(&s,CELL_MODE_PRIMARY,true,true));
    assert(!cell_uplink_choose(&s,CELL_MODE_PRIMARY,true,false)&&!s.streak);
    assert(cell_uplink_choose(&s,CELL_MODE_PRIMARY,false,true));           /* nothing else: cellular now */
    for(int i=0;i<300;i++)cell_uplink_choose(&s,CELL_MODE_PRIMARY,true,true);
    assert(s.streak==CELL_STABLE_SAMPLES);

    /* Transport: USB ignores the UART pins and flow control, keeps PWRKEY checks. */
    c=good();c.transport=CELL_TRANSPORT_USB;assert(valid(c));
    c.tx=33;c.rx=19;c.rts=5;assert(valid(c));                              /* unused UART fields */
    c.pwrkey=19;assert(!valid(c));c.pwrkey=7;assert(valid(c));c.pwrkey=-1;assert(valid(c));
    c.usb_iface=0;assert(valid(c));c.usb_iface=15;assert(valid(c));c.usb_iface=16;assert(!valid(c));c.usb_iface=CELL_USB_IFACE_AUTO;assert(valid(c));
    c.transport=2;assert(!valid(c));
    c=good();c.transport=CELL_TRANSPORT_USB;c.data_ack=0;assert(!valid(c));    /* data notice for USB too */
    /* USB may leave the APN empty (the modem's default context; a network
     * stick has its own); UART keeps requiring it. Quoting rules stay. */
    c=good();c.transport=CELL_TRANSPORT_USB;c.apn[0]=0;assert(valid(c));strcpy(c.apn,"a\"b");assert(!valid(c));
    c=good();c.apn[0]=0;assert(!valid(c));
    c=good();c.transport=CELL_TRANSPORT_USB;for(uint8_t m=0;m<3;m++){c.usb_mode=m;assert(valid(c));}c.usb_mode=3;assert(!valid(c));
    c=good();c.tx=33;assert(!valid(c));c.transport=CELL_TRANSPORT_UART;assert(!valid(c));   /* UART still checks pins */
    assert(d.transport==CELL_TRANSPORT_UART&&d.usb_iface==CELL_USB_IFACE_AUTO);

    /* AT line classifier shared by both transports. */
    assert(cell_at_line("OK",NULL)==1&&cell_at_line("ERROR",NULL)==0&&cell_at_line("+CME ERROR: 10",NULL)==0);
    assert(cell_at_line("NO CARRIER",NULL)==0&&cell_at_line("BUSY",NULL)==0&&cell_at_line("NO DIALTONE",NULL)==0);
    assert(cell_at_line("CONNECT 150000000","CONNECT")==1&&cell_at_line("+CPIN: READY","+CPIN")==1);
    assert(cell_at_line("+CSQ: 18,99",NULL)==-1&&cell_at_line("OK ",NULL)==-1&&cell_at_line("",NULL)==-1&&cell_at_line("RING","CONNECT")==-1);

    /* USB plan. Quectel EC25 layout: DM, NMEA, AT, modem, QMI. */
    cell_usb_plan_t p;
    begin();serial(0,false);serial(1,true);serial(2,true);serial(3,true);serial(4,true);
    assert(plan(0x2c7c,0x0125,CELL_USB_IFACE_AUTO,&p)==2&&p.how==CELL_USB_HOW_KNOWN&&order(&p,2,(const uint8_t[]){3,2}));
    /* Same layout, unknown ids: status-endpoint ports first, diagnostics last. */
    assert(plan(0x1234,0x5678,CELL_USB_IFACE_AUTO,&p)==5&&p.how==CELL_USB_HOW_PROBE&&order(&p,5,(const uint8_t[]){1,2,3,4,0}));
    /* Manual choice: only that interface, only if it is a serial interface. */
    assert(plan(0x2c7c,0x0125,2,&p)==1&&p.how==CELL_USB_HOW_MANUAL&&p.iface[0]==2);
    assert(plan(0x2c7c,0x0125,7,&p)==0&&p.how==CELL_USB_HOW_MANUAL&&!p.network_only);
    /* SIMCom SIM7600: diag, NMEA, AT, modem, audio, rmnet. */
    begin();for(uint8_t i=0;i<6;i++)serial(i,i!=0);
    assert(plan(0x1e0e,0x9001,CELL_USB_IFACE_AUTO,&p)==2&&p.how==CELL_USB_HOW_KNOWN&&order(&p,2,(const uint8_t[]){3,2}));
    /* Known ids in another composition (no interface 3): the generic order. */
    begin();serial(0,false);serial(1,true);serial(2,true);
    assert(plan(0x2c7c,0x0125,CELL_USB_IFACE_AUTO,&p)==1&&p.how==CELL_USB_HOW_KNOWN&&p.iface[0]==2);
    begin();serial(0,false);serial(1,true);
    assert(plan(0x2c7c,0x0125,CELL_USB_IFACE_AUTO,&p)==2&&p.how==CELL_USB_HOW_PROBE&&order(&p,2,(const uint8_t[]){1,0}));
    /* Standard CDC-ACM (IAD, functional descriptors): the control interface. */
    begin();acm(0);
    assert(plan(0x0403,0x6015,CELL_USB_IFACE_AUTO,&p)==1&&p.how==CELL_USB_HOW_ACM&&p.iface[0]==0);
    assert(plan(0x0403,0x6015,0,&p)==1&&plan(0x0403,0x6015,1,&p)==0);    /* the data interface is not a choice */
    begin();acm(0);acm(2);
    assert(plan(0x1111,0x2222,CELL_USB_IFACE_AUTO,&p)==2&&order(&p,2,(const uint8_t[]){0,2}));
    /* Network-only modems (RNDIS, ECM, NCM, MBIM, wireless RNDIS): refused with a reason. */
    begin();rndis();assert(plan(0x1e0e,0x9011,CELL_USB_IFACE_AUTO,&p)==0&&p.network_only);
    begin();iface(0,0,2,6,0,1);ep(0x81,3);iface(1,0,0x0a,0,0,0);iface(1,1,0x0a,0,0,2);ep(0x82,2);ep(0x02,2);
    assert(plan(0x1111,0x2222,CELL_USB_IFACE_AUTO,&p)==0&&p.network_only);
    begin();iface(0,0,2,0x0d,0,1);ep(0x81,3);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0&&p.network_only);
    begin();iface(0,0,2,0x0e,0,1);ep(0x81,3);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0&&p.network_only);
    begin();iface(0,0,0xe0,1,3,1);ep(0x81,3);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0&&p.network_only);
    /* RNDIS plus vendor serial ports (A7670-style): the serial ports, never RNDIS as ACM. */
    begin();rndis();serial(2,false);serial(3,true);serial(4,true);
    assert(plan(0x1e0e,0x9011,CELL_USB_IFACE_AUTO,&p)==3&&p.how==CELL_USB_HOW_PROBE&&!p.network_only&&order(&p,3,(const uint8_t[]){3,4,2}));
    /* Nothing serial at all, nothing network: no candidates, no network flag. */
    begin();iface(0,0,8,6,0x50,2);ep(0x81,2);ep(0x02,2);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0&&!p.network_only);
    /* Only alternate setting 0 counts; endpoints of alt 1 are not a serial port. */
    begin();iface(0,0,0xff,0,0,0);iface(0,1,0xff,0,0,2);ep(0x81,2);ep(0x01,2);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0);
    /* One direction only is not a serial port. */
    begin();iface(0,0,0xff,0,0,1);ep(0x81,2);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0);
    /* Bounded: at most CELL_USB_MAX_CANDIDATES; interface numbers >= 32 ignored. */
    begin();for(uint8_t i=0;i<12;i++)serial(i,true);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==CELL_USB_MAX_CANDIDATES);
    begin();serial(40,true);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==0);assert(plan(1,2,15,&p)==0);
    /* Malformed descriptors: refused, never guessed. */
    begin();serial(2,true);size_t n=end();
    assert(cell_usb_plan(1,2,NULL,n,CELL_USB_IFACE_AUTO,&p)==-1&&cell_usb_plan(1,2,D,n,CELL_USB_IFACE_AUTO,NULL)==-1);
    assert(cell_usb_plan(1,2,D,8,CELL_USB_IFACE_AUTO,&p)==-1);              /* shorter than a config descriptor */
    assert(cell_usb_plan(1,2,D,n-1,CELL_USB_IFACE_AUTO,&p)==-1);            /* truncated copy (wTotalLength > len) */
    assert(cell_usb_plan(1,2,D,n+50,CELL_USB_IFACE_AUTO,&p)==1);            /* trailing bytes beyond wTotalLength ignored */
    D[1]=4;assert(cell_usb_plan(1,2,D,n,CELL_USB_IFACE_AUTO,&p)==-1);D[1]=2;
    D[0]=8;assert(cell_usb_plan(1,2,D,n,CELL_USB_IFACE_AUTO,&p)==-1);D[0]=9;
    D[2]=8;D[3]=0;assert(cell_usb_plan(1,2,D,n,CELL_USB_IFACE_AUTO,&p)==-1);
    begin();uint8_t zero[2]={0,4};put(zero,2);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==-1);           /* bLength 0: no endless loop */
    begin();uint8_t over[3]={40,4,0};put(over,3);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==-1);        /* runs past the end */
    begin();uint8_t shorti[5]={5,4,0,0,2};put(shorti,5);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==-1);  /* short interface */
    begin();iface(0,0,0xff,0,0,1);uint8_t shorte[4]={4,5,0x81,2};put(shorte,4);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==-1);
    begin();uint8_t one[1]={1};put(one,1);assert(plan(1,2,CELL_USB_IFACE_AUTO,&p)==-1);
    /* Deterministic fuzz: bounded result, candidates always real interface numbers. */
    uint32_t seed=12345;
    for(int round=0;round<20000;round++){
        size_t len=9+(size_t)((seed=seed*1103515245u+12345u)>>16)%300;
        for(size_t i=0;i<len;i++){seed=seed*1103515245u+12345u;D[i]=(uint8_t)(seed>>16);}
        if(round%3){for(size_t i=9;i+2<len;i+=1+((seed>>8)%9)){D[i]=(uint8_t)(2+((seed=seed*1103515245u+12345u)>>16)%12);D[i+1]=(uint8_t)(4+((seed>>20)&1));}}
        D[0]=9;D[1]=2;size_t total=round%5?len:len+9;D[2]=(uint8_t)(total&255);D[3]=(uint8_t)(total>>8);
        uint8_t ov=round%7==0?(uint8_t)(seed%20):CELL_USB_IFACE_AUTO;
        int r=cell_usb_plan((uint16_t)seed,(uint16_t)(seed>>16),D,len,ov,&p);
        assert(r>=-1&&r<=CELL_USB_MAX_CANDIDATES);
        if(r>0){assert(p.count==r);for(int i=0;i<r;i++)assert(p.iface[i]<32);}
    }

    /* Record load: a checksummed, valid v2 record, or a v1 record migrated
     * as a UART modem; anything else is OFF. */
    cell_config_t g=good(),out;strcpy(g.pin,"4321");
    cell_record_t r;memset(&r,0,sizeof r);r.magic=CELL_MAGIC;r.version=2;memcpy(&r.config,&g,sizeof g);r.checksum=record_checksum(&r);
    memcpy(blob,&r,sizeof r);blob_size=sizeof r;load(&out);assert(!memcmp(&out,&g,sizeof g));
    cell_record_t u=r;u.config.transport=CELL_TRANSPORT_USB;u.config.usb_iface=3;u.config.tx=33;u.checksum=record_checksum(&u);
    memcpy(blob,&u,sizeof u);load(&out);assert(out.enabled&&out.transport==CELL_TRANSPORT_USB&&out.usb_iface==3);
    u.config.usb_iface=20;u.checksum=record_checksum(&u);memcpy(blob,&u,sizeof u);load(&out);assert(!out.enabled&&out.transport==CELL_TRANSPORT_UART);
    cell_record_t bad=r;bad.checksum^=1;memcpy(blob,&bad,sizeof bad);load(&out);assert(!out.enabled);
    bad=r;bad.version=3;bad.checksum=record_checksum(&bad);memcpy(blob,&bad,sizeof bad);load(&out);assert(!out.enabled);
    bad=r;bad.version=1;bad.checksum=record_checksum(&bad);memcpy(blob,&bad,sizeof bad);load(&out);assert(!out.enabled);   /* v1 tag, v2 size */
    bad=r;bad.magic^=1;bad.checksum=record_checksum(&bad);memcpy(blob,&bad,sizeof bad);load(&out);assert(!out.enabled);
    /* Version 1 (3.0.24 and earlier) migrates: same fields, UART, automatic USB. */
    cell_record_v1_t v1;memset(&v1,0,sizeof v1);v1.magic=CELL_MAGIC;v1.version=1;
    v1.config=(cell_config_v1_t){.enabled=1,.uart=2,.mode=CELL_MODE_PRIMARY,.roaming=1,.data_ack=1,.pwrkey_active_high=1,.tx=4,.rx=5,.rts=6,.cts=7,.pwrkey=8,.baud=921600};
    strcpy(v1.config.apn,"apn.v1");strcpy(v1.config.user,"u1");strcpy(v1.config.password,"pw1");strcpy(v1.config.pin,"2468");
    v1.checksum=cell_fnv(&v1,offsetof(cell_record_v1_t,checksum));
    memcpy(blob,&v1,sizeof v1);blob_size=sizeof v1;load(&out);
    assert(out.enabled&&out.uart==2&&out.mode==CELL_MODE_PRIMARY&&out.roaming&&out.data_ack&&out.pwrkey_active_high);
    assert(out.tx==4&&out.rx==5&&out.rts==6&&out.cts==7&&out.pwrkey==8&&out.baud==921600);
    assert(!strcmp(out.apn,"apn.v1")&&!strcmp(out.user,"u1")&&!strcmp(out.password,"pw1")&&!strcmp(out.pin,"2468"));
    assert(out.transport==CELL_TRANSPORT_UART&&out.usb_iface==CELL_USB_IFACE_AUTO);
    cell_record_v1_t v1b=v1;v1b.checksum^=1;memcpy(blob,&v1b,sizeof v1b);load(&out);assert(!out.enabled);
    v1b=v1;v1b.version=2;v1b.checksum=cell_fnv(&v1b,offsetof(cell_record_v1_t,checksum));memcpy(blob,&v1b,sizeof v1b);load(&out);assert(!out.enabled);
    v1b=v1;v1b.config.tx=33;v1b.checksum=cell_fnv(&v1b,offsetof(cell_record_v1_t,checksum));memcpy(blob,&v1b,sizeof v1b);load(&out);assert(!out.enabled);
    blob_size=sizeof v1-1;memcpy(blob,&v1,sizeof v1);load(&out);assert(!out.enabled);
    /* Saving: a UART modem with default USB settings is written as version 1
     * (what 3.0.24 reads, so a rollback keeps it); anything USB as version 2. */
    union {cell_record_t v2; cell_record_v1_t v1;} enc;
    cell_config_t u1=good();strcpy(u1.pin,"2468");strcpy(u1.password,"pw");u1.tx=4;u1.rx=5;u1.baud=921600;
    size_t es=record_encode(&u1,&enc);
    assert(es==sizeof(cell_record_v1_t)&&enc.v1.version==1&&enc.v1.magic==CELL_MAGIC);
    assert(enc.v1.checksum==cell_fnv(&enc.v1,offsetof(cell_record_v1_t,checksum)));
    assert(enc.v1.config.enabled==1&&enc.v1.config.tx==4&&enc.v1.config.rx==5&&enc.v1.config.baud==921600&&!strcmp(enc.v1.config.pin,"2468")&&!strcmp(enc.v1.config.apn,"internet.example"));
    memcpy(blob,&enc,es);blob_size=es;load(&out);assert(!memcmp(&out,&u1,sizeof u1));      /* round trip */
    cell_config_t u2=u1;u2.transport=CELL_TRANSPORT_USB;
    es=record_encode(&u2,&enc);assert(es==sizeof(cell_record_t)&&enc.v2.version==2);
    memcpy(blob,&enc,es);blob_size=es;load(&out);assert(!memcmp(&out,&u2,sizeof u2));
    u2=u1;u2.usb_mode=2;es=record_encode(&u2,&enc);assert(es==sizeof(cell_record_t));   /* a USB choice kept even on UART */
    memcpy(blob,&enc,es);load(&out);assert(out.usb_mode==2&&out.transport==CELL_TRANSPORT_UART);
    u2=u1;u2.usb_iface=3;assert(record_encode(&u2,&enc)==sizeof(cell_record_t));
    /* Before Wi-Fi starts: only an enabled USB connection counts. */
    u2=u1;u2.transport=CELL_TRANSPORT_USB;es=record_encode(&u2,&enc);memcpy(blob,&enc,es);blob_size=es;assert(cell_uplink_usb_configured());
    u2.enabled=0;es=record_encode(&u2,&enc);memcpy(blob,&enc,es);blob_size=es;assert(!cell_uplink_usb_configured());
    es=record_encode(&u1,&enc);memcpy(blob,&enc,es);blob_size=es;assert(!cell_uplink_usb_configured());   /* UART */
    blob_size=0;assert(!cell_uplink_usb_configured());
    blob_size=sizeof r;
    bad=r;bad.config.data_ack=0;bad.checksum=record_checksum(&bad);memcpy(blob,&bad,sizeof bad);load(&out);assert(!out.enabled);
    bad=r;bad.config.tx=33;bad.checksum=record_checksum(&bad);memcpy(blob,&bad,sizeof bad);load(&out);assert(!out.enabled);
    blob_size=sizeof r-1;memcpy(blob,&r,sizeof r);load(&out);assert(!out.enabled);
    blob_size=0;load(&out);assert(!out.enabled);open_fail=1;blob_size=sizeof r;load(&out);assert(!out.enabled);
    /* Mobile data carrying the traffic: reported once a change has lasted 30 s. */
    cell_carry_t cc={0};
    assert(cell_carry_update(&cc,true,100)==CELL_CARRY_NONE&&cell_carry_update(&cc,true,129)==CELL_CARRY_NONE);
    assert(cell_carry_update(&cc,true,130)==CELL_CARRY_STARTED&&cell_carry_update(&cc,true,500)==CELL_CARRY_NONE);
    assert(cell_carry_update(&cc,false,600)==CELL_CARRY_NONE&&cell_carry_update(&cc,true,610)==CELL_CARRY_NONE);   /* a short flip */
    assert(cell_carry_update(&cc,false,700)==CELL_CARRY_NONE&&cell_carry_update(&cc,false,740)==CELL_CARRY_ENDED);
    assert(cell_carry_update(&cc,false,9999)==CELL_CARRY_NONE);
    puts("PASS: actual cellular validation per transport (UART pins, USB), AT parsers and line classifier, USB interface plan (known, ACM, probe, manual, RNDIS/ECM refusal, malformed, fuzz), failover/primary selection, mobile data use reported after 30 s (short flips quiet), fail-closed record load and v1 migration (no modem)");
}
'''

HTTP = COMMON + r'''
#include "cJSON.h"
#include "json_guard.h"
#define HTTPD_400_BAD_REQUEST 400
typedef struct {int content_len,offset,status;const char *body;bool authorized;char reply[2048];} httpd_req_t;
struct in_addr {uint32_t s_addr;};
static char *inet_ntoa_r(struct in_addr a,char *b,size_t n){uint32_t x=a.s_addr;snprintf(b,n,"%u.%u.%u.%u",x&255,(x>>8)&255,(x>>16)&255,x>>24);return b;}
static const char *esp_err_to_name(esp_err_t e){(void)e;return "ESP_FAIL";}
static int web_ui_require_auth(httpd_req_t *r){if(r->authorized)return ESP_OK;r->status=401;return ESP_FAIL;}
static void httpd_resp_set_status(httpd_req_t *r,const char *s){r->status=atoi(s);}
static void httpd_resp_send_err(httpd_req_t *r,int s,const char *m){(void)m;r->status=s;}
static void httpd_resp_send_408(httpd_req_t *r){r->status=408;}
static void httpd_resp_send_500(httpd_req_t *r){r->status=500;}
static void httpd_resp_set_type(httpd_req_t *r,const char *s){(void)r;(void)s;}
static void httpd_resp_set_hdr(httpd_req_t *r,const char *k,const char *v){(void)r;(void)k;(void)v;}
static int httpd_resp_sendstr(httpd_req_t *r,const char *s){snprintf(r->reply,sizeof r->reply,"%s",s);if(!r->status)r->status=200;return ESP_OK;}
static int httpd_req_recv(httpd_req_t *r,char *out,int n){memcpy(out,r->body+r->offset,n);r->offset+=n;return n;}
''' + types + 'bool cell_config_valid(const cell_config_t *c, char *why, size_t why_size);\n' + core + r'''
static cell_config_t stored;static cell_status_t status;static int saves;static esp_err_t save_result;
static void cell_uplink_get_config(cell_config_t *out){*out=stored;}
static void cell_uplink_get_status(cell_status_t *out){*out=status;}
static esp_err_t cell_uplink_set_config(const cell_config_t *c,char *why,size_t n){if(!cell_config_valid(c,why,n))return ESP_ERR_INVALID_ARG;saves++;if(save_result)return save_result;stored=*c;return ESP_OK;}
#define CELL_QUOTA_HOST_TEST 1
#include "cell_quota.h"
static cell_quota_config_t quota;static bool quota_reset;static int quota_saves;static esp_err_t quota_result;
static esp_err_t cell_quota_set(const cell_quota_config_t *c,bool reset,char *why,size_t n){
    if(c->reset_day<1||c->reset_day>28){snprintf(why,n,"bad day");return ESP_ERR_INVALID_ARG;}
    quota_saves++;if(quota_result){snprintf(why,n,"settings not saved");return quota_result;}quota=*c;quota_reset=reset;return ESP_OK;}
static void cell_quota_json(cJSON *parent){cJSON *o=cJSON_AddObjectToObject(parent,"data_limit");cJSON_AddNumberToObject(o,"limit_mb",quota.limit_mb);}
''' + 'static const char *const STATE_NAMES' + source.split('static const char *const STATE_NAMES', 1)[1].split('\nstatic esp_err_t send_json(', 1)[0] + '\n' \
    + ''.join(function(source, s) for s in ('static esp_err_t send_json(', 'static esp_err_t get_cellular(', 'static bool json_int(',
                                             'static bool json_text(', 'static bool json_secret(', 'static esp_err_t post_data_limit(',
                                             'static esp_err_t post_cellular(')) + r'''
static httpd_req_t post(const char *body){httpd_req_t r={.content_len=(int)strlen(body),.body=body,.authorized=true};post_cellular(&r);return r;}
static httpd_req_t get(void){httpd_req_t r={.authorized=true};get_cellular(&r);return r;}
#define PINS "\"uart\":1,\"baud\":115200,\"tx\":17,\"rx\":18,\"rts\":-1,\"cts\":-1,\"pwrkey\":-1,\"pwrkey_active_high\":false"
#define ON "{\"enabled\":true,\"data_ack\":true,\"roaming\":false,\"mode\":\"failover\"," PINS ",\"apn\":\"internet.example\",\"user\":\"\""
int main(void){
    stored.usb_iface=CELL_USB_IFACE_AUTO;   /* the loaded defaults */
    httpd_req_t r=post(ON ",\"pin\":\"1234\",\"password\":\"s3cret-pw\"}");
    assert(r.status==200&&strstr(r.reply,"restart_required")&&stored.enabled&&!strcmp(stored.pin,"1234")&&!strcmp(stored.password,"s3cret-pw"));
    /* GET never returns the secrets, only their presence. */
    r=get();assert(r.status==200&&!strstr(r.reply,"1234")&&!strstr(r.reply,"s3cret")&&strstr(r.reply,"\"has_pin\":true")&&strstr(r.reply,"\"has_password\":true"));
    assert(strstr(r.reply,"\"apn\":\"internet.example\"")&&strstr(r.reply,"\"rssi_dbm\":null")&&strstr(r.reply,"experimental"));
    /* Omitted or empty secrets keep the saved value; clear_* removes it. */
    r=post(ON "}");assert(r.status==200&&!strcmp(stored.pin,"1234")&&!strcmp(stored.password,"s3cret-pw"));
    r=post(ON ",\"pin\":\"\",\"password\":\"\"}");assert(r.status==200&&!strcmp(stored.pin,"1234"));
    r=post(ON ",\"clear_pin\":true,\"clear_password\":true}");assert(r.status==200&&!stored.pin[0]&&!stored.password[0]);
    r=post(ON ",\"pin\":\"9876\",\"mode\":\"primary\"}");assert(r.status==400);      /* duplicate key refused by json_guard */
    /* Transport: absent keeps the saved choice (older clients), "usb" selects
     * the USB port, usb_interface -1 is automatic. */
    r=get();assert(strstr(r.reply,"\"transport\":\"uart\"")&&strstr(r.reply,"\"usb_interface\":-1")&&strstr(r.reply,"\"usb\":null"));
    r=post(ON ",\"transport\":\"usb\",\"usb_interface\":3}");assert(r.status==200&&stored.transport==CELL_TRANSPORT_USB&&stored.usb_iface==3);
    r=post(ON "}");assert(r.status==200&&stored.transport==CELL_TRANSPORT_USB&&stored.usb_iface==3);
    r=get();assert(strstr(r.reply,"\"transport\":\"usb\"")&&strstr(r.reply,"\"usb_interface\":3"));
    r=post(ON ",\"usb_interface\":-1}");assert(r.status==200&&stored.usb_iface==CELL_USB_IFACE_AUTO);
    /* usb_mode: auto (default), serial, network; absent keeps it. */
    r=get();assert(strstr(r.reply,"\"usb_mode\":\"auto\""));
    r=post(ON ",\"usb_mode\":\"network\"}");assert(r.status==200&&stored.usb_mode==2);
    r=post(ON "}");assert(r.status==200&&stored.usb_mode==2);
    r=get();assert(strstr(r.reply,"\"usb_mode\":\"network\""));
    r=post(ON ",\"usb_mode\":\"serial\"}");assert(r.status==200&&stored.usb_mode==1);
    r=post(ON ",\"usb_mode\":\"auto\"}");assert(r.status==200&&stored.usb_mode==0);
    /* USB ignores the UART pins, but the stored ones stay valid numbers. */
    r=post("{\"enabled\":true,\"data_ack\":true,\"roaming\":false,\"mode\":\"failover\",\"transport\":\"usb\",\"uart\":1,\"baud\":115200,\"tx\":19,\"rx\":20,\"rts\":-1,\"cts\":-1,\"pwrkey\":-1,\"pwrkey_active_high\":false,\"apn\":\"x\",\"user\":\"\"}");
    assert(r.status==200&&stored.tx==19);
    r=post(ON ",\"transport\":\"uart\"}");assert(r.status==200&&stored.transport==CELL_TRANSPORT_UART&&stored.tx==17);
    cell_config_t before_usb=stored;
    const char *bad_usb[]={ON ",\"transport\":\"bluetooth\"}",ON ",\"transport\":1}",ON ",\"transport\":null}",ON ",\"usb_interface\":16}",
        ON ",\"usb_interface\":-2}",ON ",\"usb_interface\":1.5}",ON ",\"usb_interface\":\"2\"}",
        ON ",\"usb_mode\":\"qmi\"}",ON ",\"usb_mode\":2}",ON ",\"usb_mode\":\"\"}",
        "{\"enabled\":true,\"data_ack\":true,\"roaming\":false,\"mode\":\"failover\",\"transport\":\"usb\",\"uart\":1,\"baud\":115200,\"tx\":17,\"rx\":18,\"rts\":-1,\"cts\":-1,\"pwrkey\":20,\"pwrkey_active_high\":false,\"apn\":\"x\",\"user\":\"\"}"};
    for(unsigned i=0;i<sizeof bad_usb/sizeof *bad_usb;i++){r=post(bad_usb[i]);assert(r.status==400&&!memcmp(&stored,&before_usb,sizeof stored));}
    /* USB status: device id, chosen interface and how, drops. */
    status.enabled_at_boot=true;status.transport=CELL_TRANSPORT_USB;status.usb_present=true;status.usb_vid=0x2c7c;status.usb_pid=0x125;
    status.usb_iface=3;status.usb_how=CELL_USB_HOW_KNOWN;status.usb_rx_dropped=7;
    status.usb_action=1;status.usb_switches=2;
    r=get();assert(strstr(r.reply,"\"id\":\"2c7c:0125\"")&&strstr(r.reply,"\"interface\":3")&&strstr(r.reply,"\"chosen_by\":\"known\"")&&strstr(r.reply,"\"rx_dropped\":7"));
    assert(strstr(r.reply,"\"mode\":\"serial\"")&&strstr(r.reply,"\"network\":\"none\"")&&strstr(r.reply,"\"switches\":2"));
    status.usb_action=2;status.usb_net=2;r=get();assert(strstr(r.reply,"\"mode\":\"network\"")&&strstr(r.reply,"\"network\":\"ncm\""));
    status.usb_action=7;status.usb_net=9;r=get();assert(strstr(r.reply,"\"mode\":\"none\"")&&strstr(r.reply,"\"network\":\"none\""));
    status.usb_present=false;status.usb_iface=0xff;status.usb_how=9;
    r=get();assert(strstr(r.reply,"\"present\":false")&&strstr(r.reply,"\"id\":\"\"")&&strstr(r.reply,"\"interface\":-1")&&strstr(r.reply,"\"chosen_by\":\"none\""));
    status=(cell_status_t){0};
    cell_config_t keep=stored;
    const char *bad[]={
        "{\"enabled\":true,\"data_ack\":false,\"roaming\":false,\"mode\":\"failover\"," PINS ",\"apn\":\"internet.example\",\"user\":\"\"}",
        ON ",\"pin\":\"12\"}", ON ",\"pin\":\"12345678901\"}", ON ",\"clear_pin\":1}", ON ",\"password\":7}",
        "{\"enabled\":true,\"data_ack\":true,\"roaming\":false,\"mode\":\"fastest\"," PINS ",\"apn\":\"x\",\"user\":\"\"}",
        "{\"enabled\":true,\"data_ack\":true,\"roaming\":false,\"mode\":\"failover\",\"uart\":1,\"baud\":115200,\"tx\":33,\"rx\":18,\"rts\":-1,\"cts\":-1,\"pwrkey\":-1,\"pwrkey_active_high\":false,\"apn\":\"x\",\"user\":\"\"}",
        "{\"enabled\":true,\"data_ack\":true,\"roaming\":false,\"mode\":\"failover\"," PINS ",\"apn\":\"a\\\"b\",\"user\":\"\"}",
        "{\"enabled\":1}", "[]", "{"};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;i++){r=post(bad[i]);assert(r.status==400&&!memcmp(&stored,&keep,sizeof keep));}
    save_result=ESP_FAIL;r=post(ON ",\"pin\":\"5555\"}");assert(r.status==500&&!memcmp(&stored,&keep,sizeof keep));save_result=ESP_OK;
    httpd_req_t denied={.content_len=2,.body="{}",.authorized=false};int before=saves;post_cellular(&denied);assert(denied.status==401&&saves==before);
    char big[900];memset(big,' ',sizeof big-1);big[sizeof big-1]=0;r=post(big);assert(r.status==400);
    /* Monthly data limit: applied on its own, no restart, modem settings untouched. */
    keep=stored;int modem_saves=saves;
    r=post("{\"data_limit\":{\"limit_mb\":2048,\"warn_percent\":75,\"reset_day\":5,\"pause\":true}}");
    assert(r.status==200&&strstr(r.reply,"\"restart_required\":false")&&quota.limit_mb==2048&&quota.warn_pct==75&&quota.reset_day==5&&quota.pause&&!quota_reset);
    assert(saves==modem_saves&&!memcmp(&stored,&keep,sizeof keep));
    r=post("{\"data_limit\":{\"limit_mb\":2048,\"warn_percent\":75,\"reset_day\":5,\"pause\":false,\"reset_usage\":true}}");
    assert(r.status==200&&quota_reset&&!quota.pause);
    r=get();assert(strstr(r.reply,"\"data_limit\":{\"limit_mb\":2048}"));
    const char *bad_limit[]={"{\"data_limit\":{\"limit_mb\":-1,\"warn_percent\":75,\"reset_day\":5,\"pause\":true}}",
        "{\"data_limit\":{\"limit_mb\":1000001,\"warn_percent\":75,\"reset_day\":5,\"pause\":true}}",
        "{\"data_limit\":{\"limit_mb\":10,\"warn_percent\":100,\"reset_day\":5,\"pause\":true}}",
        "{\"data_limit\":{\"limit_mb\":10,\"warn_percent\":50,\"reset_day\":29,\"pause\":true}}",
        "{\"data_limit\":{\"limit_mb\":10,\"warn_percent\":50,\"reset_day\":1,\"pause\":1}}",
        "{\"data_limit\":{\"limit_mb\":10,\"warn_percent\":50,\"reset_day\":1}}",
        "{\"data_limit\":{\"limit_mb\":10,\"warn_percent\":50,\"reset_day\":1,\"pause\":true,\"reset_usage\":\"yes\"}}",
        "{\"data_limit\":[]}"};
    cell_quota_config_t qkeep=quota;int qs=quota_saves;
    for(unsigned i=0;i<sizeof bad_limit/sizeof *bad_limit;i++){r=post(bad_limit[i]);assert(r.status==400&&!memcmp(&quota,&qkeep,sizeof qkeep));}
    assert(quota_saves==qs);
    quota_result=ESP_FAIL;r=post("{\"data_limit\":{\"limit_mb\":1,\"warn_percent\":0,\"reset_day\":1,\"pause\":false}}");
    assert(r.status==500&&!memcmp(&quota,&qkeep,sizeof qkeep));quota_result=ESP_OK;
    /* With the modem fields present the request is a modem save: data_limit is not applied. */
    r=post(ON ",\"data_limit\":{\"limit_mb\":7,\"warn_percent\":0,\"reset_day\":1,\"pause\":false}}");
    assert(r.status==200&&quota.limit_mb==2048&&strstr(r.reply,"\"restart_required\":true"));
    httpd_req_t denied2={.content_len=60,.body="{\"data_limit\":{\"limit_mb\":1,\"warn_percent\":0,\"reset_day\":1,\"pause\":false}}",.authorized=false};
    denied2.content_len=(int)strlen(denied2.body);qs=quota_saves;post_cellular(&denied2);assert(denied2.status==401&&quota_saves==qs);
    puts("PASS: actual cellular API: typed fields, UART/USB transport and USB interface (optional, kept, validated), USB status, real validation, write-only SIM PIN/password (kept, replaced, cleared, never returned), monthly data limit applied alone without restart or modem change (bounds, 400/500/401), 400/500/401 without saved-state change (fixtures)");
}
'''


def build_and_run(name, program, extra=()):
    with tempfile.TemporaryDirectory(prefix='cell-') as folder:
        path = Path(folder); (path / f'{name}.c').write_text(program, encoding='utf-8')
        binary = path / (f'{name}.exe' if os.name == 'nt' else name)
        flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-unused-variable', '-I', str(ROOT / 'main')]
        if os.name != 'nt':
            # glibc hides POSIX strnlen in strict C11 unless requested.
            flags += ['-D_POSIX_C_SOURCE=200809L']
        libs = ['-lm']
        if extra:
            dep = os.environ.get('CJSON_SOURCE')
            if dep: flags += ['-I', str(Path(dep).parent), dep]
            else:
                flags += subprocess.check_output(['pkg-config', '--cflags', 'libcjson'], text=True).split()
                libs += subprocess.check_output(['pkg-config', '--libs', 'libcjson'], text=True).split()
        if os.environ.get('CELL_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / f'{name}.c'), '-o', str(binary), *libs], check=True)
        subprocess.run([str(binary)], check=True, timeout=30)


build_and_run('core', PROGRAM)
build_and_run('http', HTTP, extra=('cjson',))

main_source = (ROOT / 'main/main.c').read_text(encoding='utf-8')
services = function(main_source, 'esp_netif_t *uplink_internet_netif(void)')
services += function(main_source, 'void uplink_services_refresh(bool lost_link)')
policy = function(source, 'esp_netif_t *cell_uplink_preferred_netif(')

build_and_run('services', COMMON + types + core + r'''
typedef struct { struct {uint32_t addr;} ip; } esp_netif_ip_info_t;
typedef struct {uint32_t ip; bool up;} esp_netif_t;
static esp_netif_t wifi, eth, ppp, *lan = &wifi, *s_netif = &ppp, *default_netif;
static cell_config_t s_running = {.mode = CELL_MODE_FAILOVER};
static atomic_bool s_has_ip;
static bool first_boot, shutdown, s_ap_auto_off = true, ap_requested;
static unsigned ap_delay, starts, uplink_up, uplink_down;
static uint32_t name_ip, tailscale_exit_node_ip;
static bool tailscale_enabled = true;
#define AP_FALLBACK_DELAY_MS 60000u
enum {HIST_EV_UPLINK, HIST_INFO, HIST_WARN, BOOT_TL_IP};
static bool uplink_address(esp_netif_t *n, esp_netif_ip_info_t *out) {
    if (!n || !n->up) return false;
    out->ip.addr = n->ip;
    return out->ip.addr != 0;
}
static esp_netif_t *eth_uplink_service_netif(void) { return lan; }
static bool quota_paused;
static bool cell_quota_paused(void) { return quota_paused; }
static esp_netif_t *esp_netif_get_default_netif(void) { return default_netif; }
static void esp_netif_set_default_netif(esp_netif_t *n) { default_netif = n; }
static bool first_boot_active(void) { return first_boot; }
static bool ap_policy_is_shutdown(void) { return shutdown; }
static void ap_policy_request_after(bool on, unsigned delay) { ap_requested = on; ap_delay = delay; }
static void ap_policy_request(bool on) { ap_policy_request_after(on, 0); }
static void boot_timeline_mark(int mark) { assert(mark == BOOT_TL_IP); }
static int tailscale_request_connect(void) { ++starts; return 0; }
static void tailnet_names_uplink(uint32_t ip) { name_ip = ip; }
static void lan_name_uplink_up(void) {}
static void refresh_ap_dns(void) {}
static void history_event(int kind, int level, const char *text) {
    assert(kind == HIST_EV_UPLINK);
    if (level == HIST_INFO) { assert(!strcmp(text, "Internet uplink connected")); ++uplink_up; }
    else { assert(level == HIST_WARN && !strcmp(text, "Internet uplink lost")); ++uplink_down; }
}
''' + policy + services + r'''
int main(void) {
    ppp = (esp_netif_t){1, true}; atomic_store(&s_has_ip, true);
    first_boot = true;
    uplink_services_refresh(false);
    assert(!starts && !default_netif);
    first_boot = false;
    uplink_services_refresh(false);
    assert(default_netif == &ppp && ap_requested && !name_ip && starts == 1);
    assert(uplink_up == 1 && uplink_down == 0);
    eth = (esp_netif_t){2, true}; lan = &eth;
    uplink_services_refresh(false);
    assert(default_netif == &eth && !ap_requested && name_ip == 2);
    s_running.mode = CELL_MODE_PRIMARY;
    uplink_services_refresh(false);
    assert(default_netif == &ppp && !ap_requested && name_ip == 2);
    eth.up = false; lan = &wifi;
    uplink_services_refresh(true);
    assert(default_netif == &ppp && ap_requested && ap_delay == 60000 && !name_ip);
    assert(uplink_up == 1 && uplink_down == 0); /* failover still has an Internet uplink */
    ppp.up = false; atomic_store(&s_has_ip, false);
    uplink_services_refresh(true);
    assert(uplink_down == 1 && ap_requested && !name_ip);
    wifi = (esp_netif_t){3, true};
    tailscale_exit_node_ip = 4;
    uplink_services_refresh(false);
    assert(default_netif == &ppp && !ap_requested && name_ip == 3 && uplink_up == 2);
    /* Mobile data paused at the monthly limit: primary mode no longer prefers it. */
    ppp.up = true; atomic_store(&s_has_ip, true); s_running.mode = CELL_MODE_PRIMARY;
    assert(cell_uplink_preferred_netif(&wifi) == &ppp);
    quota_paused = true;
    assert(cell_uplink_preferred_netif(&wifi) == &wifi);
    quota_paused = false;
    puts("PASS: Ethernet and PPP cold boot, primary/failover, LAN DNS binding, AP recovery and exit route preservation, mobile data paused at the limit");
}
''')
