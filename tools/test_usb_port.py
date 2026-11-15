"""Actual USB port core, no USB device.

Compiles the real core of main/usb_port.c (USBP_HOST_TEST) and checks it
with synthetic configuration descriptors and messages: CDC-ECM, CDC-NCM and
RNDIS (three class codes) network functions with union and Ethernet
functional descriptors, MBIM and vendor-only devices, mass-storage
detection, the serial/network/switch/next-configuration decision for the
cellular and Ethernet uplinks, mode-switch messages against the
usb_modeswitch constants, RNDIS control/data framing, NCM NTB16 framing
(alignment, several datagrams, chained NDPs, loops), iMACAddress strings,
malformed input and a deterministic fuzz. USB host transfers, real modems,
sticks, adapters and phones are NOT covered.
USBP_SANITIZE=1 adds ASan/UBSan on Linux.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

PROGRAM = r'''
#define USBP_HOST_TEST 1
#include <assert.h>
#include "usb_port.c"

static uint8_t D[1600];static size_t DL;
static void begin(void){memset(D,0,sizeof D);D[0]=9;D[1]=2;DL=9;}
static void put(const uint8_t *d,size_t n){memcpy(D+DL,d,n);DL+=n;}
static void iface(uint8_t num,uint8_t alt,uint8_t cls,uint8_t sub,uint8_t proto,uint8_t eps){uint8_t d[9]={9,4,num,alt,eps,cls,sub,proto,0};put(d,9);}
static void ep(uint8_t addr,uint8_t attr,uint16_t mps){uint8_t d[7]={7,5,addr,attr,(uint8_t)mps,(uint8_t)(mps>>8),0};put(d,7);}
static void cs_union(uint8_t ctrl,uint8_t data){uint8_t d[5]={5,0x24,0x06,ctrl,data};put(d,5);}
static void cs_ether(uint8_t mac){uint8_t d[13]={13,0x24,0x0f,mac,0,0,0,0,0xea,0x05,0,0,0};put(d,13);}
static size_t end(void){D[2]=(uint8_t)(DL&255);D[3]=(uint8_t)(DL>>8);return DL;}
/* ECM/NCM function: comm (with notify), data alt 0 empty, alt 1 bulk pair. */
static void cdc_net(uint8_t sub,uint8_t ctrl,uint8_t data,uint8_t mac){
    iface(ctrl,0,2,sub,0,1);uint8_t hdr[5]={5,0x24,0,0x10,1};put(hdr,5);cs_union(ctrl,data);cs_ether(mac);ep((uint8_t)(0x81+ctrl),3,16);
    iface(data,0,0x0a,0,sub==0x0d?1:0,0);iface(data,1,0x0a,0,sub==0x0d?1:0,2);ep((uint8_t)(0x82+data),2,64);ep((uint8_t)(0x02+data),2,64);}
static void rndis(uint8_t cls,uint8_t sub,uint8_t proto){
    iface(0,0,cls,sub,proto,1);cs_union(0,1);ep(0x81,3,8);iface(1,0,0x0a,0,0,2);ep(0x82,2,64);ep(0x02,2,64);}
static void storage(uint8_t num){iface(num,0,8,6,0x50,2);ep((uint8_t)(0x81+num),2,64);ep((uint8_t)(0x01+num),2,64);}
static int scan(usbp_net_t *n,usbp_storage_t *s){size_t len=end();return usbp_scan(D,len,n,s);}
static bool hexeq(const uint8_t *m,const char *hex){uint8_t b[31];assert(usbp_hex(hex,b));return !memcmp(m,b,31);}
static void le32(uint8_t *p,uint32_t v){for(int i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void le16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}

int main(void){
    usbp_net_t n;usbp_storage_t s;
    /* CDC-ECM (USB Ethernet adapters in ECM mode, HiLink sticks). */
    begin();cdc_net(0x06,0,1,3);
    assert(scan(&n,&s)==0&&n.kind==USBP_NET_ECM&&n.ctrl==0&&n.data==1&&n.data_alt==1&&n.ep_in==0x83&&n.ep_out==0x03);
    assert(n.ep_notify==0x81&&n.mac_index==3&&n.mps_in==64&&n.mps_out==64&&!s.present);
    /* CDC-NCM (USB 3 adapters, recent phones), preferred over ECM in one configuration. */
    begin();cdc_net(0x0d,0,1,4);assert(scan(&n,&s)==0&&n.kind==USBP_NET_NCM&&n.data_alt==1&&n.mac_index==4);
    begin();cdc_net(0x06,0,1,3);cdc_net(0x0d,2,3,5);assert(scan(&n,&s)==0&&n.kind==USBP_NET_NCM&&n.ctrl==2&&n.data==3&&n.ep_in==0x85);
    /* Union descriptor wins over "control + 1". */
    begin();iface(0,0,2,6,0,1);cs_union(0,4);ep(0x81,3,16);iface(1,0,0xff,0,0,0);iface(4,1,0x0a,0,0,2);ep(0x84,2,64);ep(0x04,2,64);
    assert(scan(&n,&s)==0&&n.kind==USBP_NET_ECM&&n.data==4&&n.data_alt==1&&!n.mac_index);
    /* RNDIS: Windows class 02/02/ff, wireless e0/01/03 (Android), misc ef/04/01. */
    uint8_t rcodes[3][3]={{2,2,0xff},{0xe0,1,3},{0xef,4,1}};
    for(int i=0;i<3;i++){begin();rndis(rcodes[i][0],rcodes[i][1],rcodes[i][2]);
        assert(scan(&n,&s)==0&&n.kind==USBP_NET_RNDIS&&n.ctrl==0&&n.data==1&&n.data_alt==0&&n.ep_in==0x82&&n.ep_out==0x02&&n.ep_notify==0x81);}
    /* RNDIS next to ECM: ECM preferred. */
    begin();rndis(0xe0,1,3);cdc_net(0x06,2,3,0);assert(scan(&n,&s)==0&&n.kind==USBP_NET_ECM&&n.ctrl==2);
    /* MBIM alone, or a network function without a data path: unsupported. */
    begin();iface(0,0,2,0x0e,0,1);ep(0x81,3,16);iface(1,1,0x0a,0,2,2);ep(0x82,2,64);ep(0x02,2,64);assert(scan(&n,&s)==0&&n.kind==USBP_NET_UNSUPPORTED);
    begin();iface(0,0,2,6,0,1);ep(0x81,3,16);assert(scan(&n,&s)==0&&n.kind==USBP_NET_UNSUPPORTED);
    begin();iface(0,0,2,6,0,1);iface(1,1,0x0a,0,0,1);ep(0x82,2,64);assert(scan(&n,&s)==0&&n.kind==USBP_NET_UNSUPPORTED);   /* one direction */
    /* Vendor-only Ethernet chip (e.g. ASIX AX88179): nothing usable. */
    begin();iface(0,0,0xff,0xff,0,3);ep(0x81,3,8);ep(0x82,2,64);ep(0x03,2,64);assert(scan(&n,&s)==0&&n.kind==USBP_NET_NONE&&!s.present);
    /* Mass storage (a stick in CD-ROM mode), alone or with modem functions. */
    begin();storage(0);assert(scan(&n,&s)==0&&s.present&&s.iface==0&&s.ep_in==0x81&&s.ep_out==0x01&&s.mps_out==64&&n.kind==USBP_NET_NONE);
    begin();iface(0,0,8,6,0x62,2);ep(0x81,2,64);ep(0x01,2,64);assert(scan(&n,&s)==0&&!s.present);   /* UAS, not bulk-only */
    begin();storage(3);rndis(0xe0,1,3);assert(scan(&n,&s)==0&&s.present&&s.iface==3&&n.kind==USBP_NET_RNDIS);
    /* Bounded: more functions and data alternates than the tables hold. */
    begin();for(uint8_t i=0;i<10;i++){iface(i,0,2,6,0,0);}for(uint8_t i=0;i<20;i++){iface(10,i,0x0a,0,0,0);}
    assert(scan(&n,&s)==0&&n.kind==USBP_NET_UNSUPPORTED);
    /* Malformed. */
    begin();cdc_net(0x06,0,1,3);size_t len=end();
    assert(usbp_scan(NULL,len,&n,&s)==-1&&usbp_scan(D,len,NULL,&s)==-1&&usbp_scan(D,len,&n,NULL)==-1);
    assert(usbp_scan(D,8,&n,&s)==-1&&usbp_scan(D,len-1,&n,&s)==-1&&usbp_scan(D,len+40,&n,&s)==0);
    D[1]=4;assert(usbp_scan(D,len,&n,&s)==-1);D[1]=2;D[2]=8;D[3]=0;assert(usbp_scan(D,len,&n,&s)==-1);
    begin();uint8_t z[2]={0,4};put(z,2);assert(scan(&n,&s)==-1);
    begin();uint8_t over[3]={60,4,0};put(over,3);assert(scan(&n,&s)==-1);
    begin();uint8_t si[6]={6,4,0,0,1,2};put(si,6);assert(scan(&n,&s)==-1);
    begin();iface(0,0,0xff,0,0,1);uint8_t se[5]={5,5,0x81,2,64};put(se,5);assert(scan(&n,&s)==-1);
    begin();iface(0,0,2,6,0,0);uint8_t cu[3]={3,0x24,0x06};put(cu,3);assert(scan(&n,&s)==0);   /* short functional descriptor ignored */

    /* Decisions. */
    usbp_net_t ecm={.kind=USBP_NET_ECM},none={0},bad={.kind=USBP_NET_UNSUPPORTED};
    usbp_storage_t st={.present=true},nost={0};
    assert(usbp_action(true,USBP_MODE_AUTO,2,&ecm,&nost,1,1)==USBP_ACT_SERIAL);       /* serial keeps SIM/APN control */
    assert(usbp_action(true,USBP_MODE_AUTO,0,&ecm,&nost,1,1)==USBP_ACT_NETWORK);
    assert(usbp_action(true,USBP_MODE_NETWORK,2,&ecm,&nost,1,1)==USBP_ACT_NETWORK);
    assert(usbp_action(true,USBP_MODE_NETWORK,2,&none,&nost,1,1)==USBP_ACT_NONE);
    assert(usbp_action(true,USBP_MODE_SERIAL,0,&ecm,&nost,1,1)==USBP_ACT_NONE);
    assert(usbp_action(true,USBP_MODE_SERIAL,0,&ecm,&nost,2,1)==USBP_ACT_NEXT_CONFIG);
    assert(usbp_action(true,USBP_MODE_AUTO,0,&none,&st,1,1)==USBP_ACT_SWITCH);
    assert(usbp_action(true,USBP_MODE_AUTO,1,&none,&st,1,1)==USBP_ACT_SERIAL);        /* driver disk next to a modem */
    assert(usbp_action(true,USBP_MODE_NETWORK,1,&none,&st,1,1)==USBP_ACT_NONE);       /* never eject a working modem */
    assert(usbp_action(true,USBP_MODE_AUTO,0,&bad,&st,1,1)==USBP_ACT_NONE);
    assert(usbp_action(false,0,0,&ecm,&st,1,1)==USBP_ACT_NETWORK);
    assert(usbp_action(false,0,0,&none,&st,1,1)==USBP_ACT_SWITCH);
    assert(usbp_action(false,0,0,&none,&nost,2,1)==USBP_ACT_NEXT_CONFIG);             /* e.g. RTL8153: ECM in configuration 2 */
    assert(usbp_action(false,0,0,&none,&nost,2,2)==USBP_ACT_NONE);
    assert(usbp_action(false,0,0,&bad,&nost,1,1)==USBP_ACT_NONE);
    assert(usbp_action(true,0,0,NULL,NULL,1,1)==USBP_ACT_NONE);
    assert(usbp_next_config(1,1)==0&&usbp_next_config(2,1)==2&&usbp_next_config(3,2)==3&&usbp_next_config(3,3)==0);
    assert(usbp_next_config(6,4)==0&&usbp_next_config(3,0)==0&&usbp_next_config(0,0)==0);

    /* Mode switch: usb_modeswitch reference messages, byte for byte. */
    usbp_msw_t m;
    static const uint8_t huawei[31]={0x55,0x53,0x42,0x43,0x12,0x34,0x56,0x78,0,0,0,0,0,0,0,0x11,0x06,0x20,0,0,0x01,0x01,0,0x01,0,0,0,0,0,0,0};   /* bCBWCBLength 0, as in the reference */
    usbp_msw_plan(0x12d1,0x1f01,&m);assert(m.count==1&&!memcmp(m.message[0],huawei,31));
    usbp_msw_plan(0x12d1,0x7777,&m);assert(m.count==1&&!memcmp(m.message[0],huawei,31));   /* other Huawei */
    static const uint8_t eject0[31]={0x55,0x53,0x42,0x43,0x87,0x65,0x43,0x21,0,0,0,0,0,0,0x06,0x1e};
    static const uint8_t eject1[31]={0x55,0x53,0x42,0x43,0x97,0x65,0x43,0x21,0,0,0,0,0,0,0x06,0x1b,0,0,0,0x02};
    usbp_msw_plan(0x19d2,0x1225,&m);assert(m.count==4&&!memcmp(m.message[0],eject0,31)&&!memcmp(m.message[1],eject1,31));
    assert(m.message[2][13]==1&&m.message[3][13]==1&&m.message[3][15]==0x1b);              /* LUN 1 */
    usbp_msw_plan(0x1234,0x5678,&m);assert(m.count==4&&!memcmp(m.message[0],eject0,31));    /* unknown: standard eject */
    usbp_msw_plan(0x19d2,0x1588,&m);assert(m.count==5&&hexeq(m.message[4],"55534243123456702000000080000c85010101180101010101000000000000"));
    usbp_msw_plan(0x1bbb,0xf000,&m);assert(m.count==1&&hexeq(m.message[0],"55534243123456788000000080000606f50402527000000000000000000000"));
    usbp_msw_plan(0x19d2,0x0166,&m);assert(m.count==1&&m.message[0][8]==0x24&&m.message[0][12]==0x80);   /* IN data stage */
    usbp_msw_plan(0x05c6,0xf000,&m);assert(m.count==5);
    usbp_msw_plan(0x1c9e,0xf000,&m);assert(m.count==1&&m.message[0][15]==0xff);
    for(size_t i=0;i<sizeof USBP_MSW/sizeof USBP_MSW[0];i++){
        usbp_msw_plan(USBP_MSW[i].vid,USBP_MSW[i].pid,&m);assert(m.count>=1&&m.count<=USBP_MSW_MAX);
        for(unsigned k=0;k<m.count;k++)assert(!memcmp(m.message[k],"USBC",4)&&m.message[k][14]<=16);
        if(USBP_MSW[i].message)assert(strlen(USBP_MSW[i].message)==62);
    }
    uint8_t hb[31];assert(!usbp_hex("55",hb)&&!usbp_hex("5553424312345678000000000000001106200000010100010000000000000G",hb));

    /* RNDIS control. */
    uint8_t buf[2200];
    assert(usbp_rndis_init(buf,sizeof buf,7,2048)==24&&buf[0]==2&&buf[4]==24&&buf[8]==7&&buf[12]==1&&buf[16]==0&&buf[20]==0&&buf[21]==8);
    assert(usbp_rndis_init(buf,23,1,2048)==0&&usbp_rndis_query(buf,27,1,1)==0&&usbp_rndis_set(buf,31,1,1,1)==0);
    assert(usbp_rndis_query(buf,sizeof buf,2,0x01010101u)==28&&buf[0]==4&&buf[12]==1&&buf[15]==1&&buf[16]==0&&buf[20]==20);
    assert(usbp_rndis_set(buf,sizeof buf,3,0x0001010eu,0x0d)==32&&buf[0]==5&&buf[4]==32&&buf[16]==4&&buf[20]==20&&buf[28]==0x0d);
    uint8_t c[64];memset(c,0,sizeof c);le32(c,0x80000002u);le32(c+4,52);le32(c+8,1);
    const uint8_t *info;size_t ilen;
    assert(usbp_rndis_cmplt(c,52,2,1,&info,&ilen)&&!info);
    assert(!usbp_rndis_cmplt(c,51,2,1,NULL,NULL)&&!usbp_rndis_cmplt(c,52,2,2,NULL,NULL)&&!usbp_rndis_cmplt(c,52,4,1,NULL,NULL));
    le32(c+12,0xc0000001u);assert(!usbp_rndis_cmplt(c,52,2,1,NULL,NULL));le32(c+12,0);
    le32(c+4,40);assert(!usbp_rndis_cmplt(c,64,2,1,NULL,NULL));                            /* INIT_CMPLT too short */
    memset(c,0,sizeof c);le32(c,0x80000004u);le32(c+4,30);le32(c+8,2);le32(c+16,6);le32(c+20,16);
    static const uint8_t mac[6]={0x02,0x11,0x22,0x33,0x44,0x55};memcpy(c+24,mac,6);
    assert(usbp_rndis_cmplt(c,30,4,2,&info,&ilen)&&ilen==6&&!memcmp(info,mac,6));
    le32(c+16,7);assert(!usbp_rndis_cmplt(c,30,4,2,&info,&ilen));le32(c+16,6);
    le32(c+20,0xfffffff0u);assert(!usbp_rndis_cmplt(c,30,4,2,&info,&ilen));                /* offset overflow */
    le32(c+20,16);le32(c+16,0xffffffffu);assert(!usbp_rndis_cmplt(c,30,4,2,&info,&ilen));
    assert(!usbp_rndis_cmplt(NULL,30,4,2,&info,&ilen)&&!usbp_rndis_cmplt(c,15,4,2,&info,&ilen));
    /* RNDIS data: wrap, several packets per transfer, other messages, padding. */
    uint8_t frame[1700];for(size_t i=0;i<sizeof frame;i++)frame[i]=(uint8_t)(i*7+1);
    size_t a=usbp_rndis_wrap(buf,sizeof buf,frame,60);assert(a==104&&buf[0]==1&&buf[4]==104&&buf[8]==36&&buf[12]==60);
    assert(usbp_rndis_wrap(buf,103,frame,60)==0&&usbp_rndis_wrap(buf,sizeof buf,frame,1515)==0&&usbp_rndis_wrap(buf,sizeof buf,frame,0)==0);
    uint8_t ind[20]={0};le32(ind,7);le32(ind+4,20);memcpy(buf+a,ind,20);
    size_t b=usbp_rndis_wrap(buf+a+20,sizeof buf-a-20,frame+100,1514);assert(b==1558);
    size_t total=a+20+b;memset(buf+total,0,12);
    size_t off=0;const uint8_t *f;size_t fl;
    assert(usbp_rndis_next(buf,total+12,&off,&f,&fl)==1&&fl==60&&!memcmp(f,frame,60));
    assert(usbp_rndis_next(buf,total+12,&off,&f,&fl)==1&&fl==1514&&!memcmp(f,frame+100,1514));
    assert(usbp_rndis_next(buf,total+12,&off,&f,&fl)==0);
    off=0;assert(usbp_rndis_next(buf,total+5,&off,&f,&fl)==1);
    le32(buf+4,4);off=0;assert(usbp_rndis_next(buf,total,&off,&f,&fl)==-1);le32(buf+4,104);
    le32(buf+4,9999);off=0;assert(usbp_rndis_next(buf,total,&off,&f,&fl)==-1);le32(buf+4,104);
    le32(buf+12,61);off=0;assert(usbp_rndis_next(buf,total,&off,&f,&fl)==-1);le32(buf+12,60);
    le32(buf+12,13);off=0;assert(usbp_rndis_next(buf,total,&off,&f,&fl)==-1);le32(buf+12,60);
    le32(buf+8,0xfffffff8u);off=0;assert(usbp_rndis_next(buf,total,&off,&f,&fl)==-1);le32(buf+8,36);
    le32(buf+4,40);off=0;assert(usbp_rndis_next(buf,total,&off,&f,&fl)==-1);le32(buf+4,104);
    off=0;assert(usbp_rndis_next(buf,7,&off,&f,&fl)==0);

    /* NCM: one datagram per NTB, aligned as the device asks. */
    uint16_t divs[][2]={{0,0},{4,0},{4,2},{8,0},{32,14}};
    for(unsigned i=0;i<5;i++){
        size_t w=usbp_ncm_wrap(buf,sizeof buf,frame,1500,(uint16_t)i,divs[i][0],divs[i][1]);
        size_t at=buf[20]|buf[21]<<8;
        assert(w==at+1500&&(size_t)(buf[8]|buf[9]<<8)==w&&(unsigned)(buf[6]|buf[7]<<8)==i&&at>=28);
        if(divs[i][0]>1)assert(at%divs[i][0]==divs[i][1]%divs[i][0]);
        usbp_ncm_rx_t it={0};assert(usbp_ncm_next(buf,w,&it,&f,&fl)==1&&fl==1500&&!memcmp(f,frame,1500));
        assert(usbp_ncm_next(buf,w,&it,&f,&fl)==0);
    }
    assert(usbp_ncm_wrap(buf,1527,frame,1500,0,0,0)==0&&usbp_ncm_wrap(buf,sizeof buf,frame,1515,0,0,0)==0&&usbp_ncm_wrap(buf,sizeof buf,NULL,60,0,0,0)==0);
    /* NTB with three datagrams over two chained NDPs (one NCM1). */
    memset(buf,0,sizeof buf);le32(buf,USBP_NTH16);le16(buf+4,12);le16(buf+10,12);
    le32(buf+12,USBP_NDP16);le16(buf+16,20);le16(buf+18,32);le16(buf+20,100);le16(buf+22,64);le16(buf+24,200);le16(buf+26,70);
    le32(buf+32,USBP_NDP16_CRC);le16(buf+36,16);le16(buf+40,300);le16(buf+42,80);
    memcpy(buf+100,frame,64);memcpy(buf+200,frame+1,70);memcpy(buf+300,frame+2,80);le16(buf+8,380);
    usbp_ncm_rx_t it={0};
    assert(usbp_ncm_next(buf,400,&it,&f,&fl)==1&&fl==64&&!memcmp(f,frame,64));
    assert(usbp_ncm_next(buf,400,&it,&f,&fl)==1&&fl==70&&!memcmp(f,frame+1,70));
    assert(usbp_ncm_next(buf,400,&it,&f,&fl)==1&&fl==80&&!memcmp(f,frame+2,80));
    assert(usbp_ncm_next(buf,400,&it,&f,&fl)==0);
    /* Malformed NTBs. */
    #define NCM_BAD(stmt, restore) do{stmt;usbp_ncm_rx_t j={0};int r;while((r=usbp_ncm_next(buf,400,&j,&f,&fl))==1){}assert(r==-1);restore;}while(0)
    NCM_BAD(buf[0]^=1,buf[0]^=1);
    NCM_BAD(le16(buf+4,16),le16(buf+4,12));
    NCM_BAD(le16(buf+8,401),le16(buf+8,380));
    NCM_BAD(le16(buf+10,14),le16(buf+10,12));
    NCM_BAD(le16(buf+10,380),le16(buf+10,12));
    NCM_BAD(buf[12]^=1,buf[12]^=1);
    NCM_BAD(le16(buf+16,12),le16(buf+16,20));
    NCM_BAD(le16(buf+16,18),le16(buf+16,20));
    NCM_BAD(le16(buf+22,300),le16(buf+22,64));                     /* datagram past the block */
    NCM_BAD(le16(buf+22,13),le16(buf+22,64));
    NCM_BAD(le16(buf+22,1515),le16(buf+22,64));
    NCM_BAD(le16(buf+18,34),le16(buf+18,32));                      /* unaligned next NDP */
    NCM_BAD(le16(buf+38,32),le16(buf+38,0));                       /* NDP chain loop: bounded */
    NCM_BAD(le16(buf+38,12),le16(buf+38,0));
    it=(usbp_ncm_rx_t){0};assert(usbp_ncm_next(buf,11,&it,&f,&fl)==-1);
    /* More than 64 datagrams in one NTB: refused. */
    memset(buf,0,sizeof buf);le32(buf,USBP_NTH16);le16(buf+4,12);le16(buf+10,12);
    le32(buf+12,USBP_NDP16);le16(buf+16,8+4*70);
    for(int i=0;i<69;i++){le16(buf+20+4*i,400);le16(buf+22+4*i,14);}
    memcpy(buf+400,frame,14);le16(buf+8,414);
    {usbp_ncm_rx_t j={0};int r,k=0;while((r=usbp_ncm_next(buf,414,&j,&f,&fl))==1)k++;assert(r==-1&&k==64);}

    /* iMACAddress. */
    uint8_t sd[26]={26,3},mac6[6];const char *hex="0A1b2C3d4E5F";
    for(int i=0;i<12;i++)sd[2+2*i]=(uint8_t)hex[i];
    assert(usbp_mac_string(sd,26,mac6)&&mac6[0]==0x0a&&mac6[1]==0x1b&&mac6[5]==0x5f);
    assert(!usbp_mac_string(sd,25,mac6)&&!usbp_mac_string(NULL,26,mac6));
    sd[1]=2;assert(!usbp_mac_string(sd,26,mac6));sd[1]=3;
    sd[3]=1;assert(!usbp_mac_string(sd,26,mac6));sd[3]=0;
    sd[4]='g';assert(!usbp_mac_string(sd,26,mac6));sd[4]='1';
    sd[2]='0';sd[3]=0;sd[4]='1';assert(!usbp_mac_string(sd,26,mac6));sd[4]='a';   /* 01: multicast */
    uint8_t zeros[26]={26,3};for(int i=0;i<12;i++)zeros[2+2*i]='0';assert(!usbp_mac_string(zeros,26,mac6));
    sd[0]=40;assert(!usbp_mac_string(sd,26,mac6));

    /* Deterministic fuzz: bounded results on arbitrary input. */
    uint32_t seed=99;
    for(int round=0;round<20000;round++){
        size_t l=9+(size_t)((seed=seed*1103515245u+12345u)>>16)%400;
        for(size_t i=0;i<l;i++){seed=seed*1103515245u+12345u;D[i]=(uint8_t)(seed>>16);}
        if(round%2)for(size_t i=9;i+2<l;i+=2+((seed>>9)%10)){seed=seed*1103515245u+12345u;D[i]=(uint8_t)(2+(seed>>16)%14);D[i+1]=(uint8_t)(4+((seed>>21)%3==0?0x20:(seed>>21)&1));}
        D[0]=9;D[1]=2;D[2]=(uint8_t)l;D[3]=(uint8_t)(l>>8);
        int r=usbp_scan(D,l,&n,&s);assert(r==0||r==-1);
        if(!r&&n.kind>=USBP_NET_ECM&&n.kind<=USBP_NET_RNDIS)assert(n.ep_in&0x80&&!(n.ep_out&0x80)&&n.mps_in&&n.mps_out);
        size_t o=0;int k=0;while((r=usbp_rndis_next(D,l,&o,&f,&fl))==1){assert(f>=D&&f+fl<=D+l&&fl>=14&&fl<=1514);k++;assert(k<100);}
        memcpy(buf,D,l);le32(buf,USBP_NTH16);le16(buf+4,12);if(round%3)le16(buf+8,(uint16_t)l);if(round%5)le16(buf+10,12);
        usbp_ncm_rx_t j={0};k=0;while((r=usbp_ncm_next(buf,l,&j,&f,&fl))==1){assert(f>=buf&&f+fl<=buf+l&&fl>=14);k++;assert(k<=64);}
    }
    puts("PASS: actual USB port core: ECM/NCM/RNDIS/MBIM/vendor/storage scan, serial/network/switch/next-configuration decisions, usb_modeswitch messages byte for byte, RNDIS and NCM framing (alignment, chains, loops, malformed), iMACAddress, fuzz (no USB device)");
}
'''

with tempfile.TemporaryDirectory(prefix='usb-port-') as folder:
    path = Path(folder)
    (path / 'test.c').write_text(PROGRAM, encoding='utf-8')
    binary = path / ('test.exe' if os.name == 'nt' else 'test')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-I', str(ROOT / 'main')]
    if os.environ.get('USBP_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(path / 'test.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=60)
