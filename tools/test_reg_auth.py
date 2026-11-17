"""When registration presents the auth key (actual MicroLink ml_reg_auth.c).

Field report on 3.0.24 (official Tailscale, default single-use auth key): the
device appeared in the admin console, then stayed offline with
"RegisterResponse.Error: invalid key: API key ... not valid". MicroLink sent
the key in every RegisterRequest, and it registers on every control
reconnect; the control server refuses a used key even for a registered node
(tailscale/tailscale#19501). The reference client presents the key only to
log in.

A simulated control server (single-use keys, node registry, deletion,
expiry) drives the real decision/result code through registration, 20
reconnects and 3 restarts (the persisted record survives them), and checks:
- a single-use key is presented once; no "invalid key" after it;
- lost response to the consuming registration: one retry without the key;
- device deleted in the console with a used key: bounded retries, then a
  clear "enter a new auth key" refusal (no endless loop);
- a new key entered for a registered device is presented once; an invalid
  new key does not take the registered device offline;
- no key: the server's authorization request is a refusal, not "connected";
- the persisted record binds node key and auth key, never holds the key.
Also checks the wiring in ml_coord.c/microlink.c structurally.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ML = ROOT / 'external/microlink/components/microlink'
BLAKE = next(ML.glob('components/wireguard_lwip/src/crypto/refc/blake2s.c'))

coord = (ML / 'src/ml_coord.c').read_text(encoding='utf-8')
main = (ML / 'src/microlink.c').read_text(encoding='utf-8')
reg = coord[coord.index('static int do_register('):coord.index('State: FETCH_PEERS')]
assert 'bool sent_key = ml_reg_auth_send_key(&ml->reg_auth, have_key);' in reg
assert 'if (sent_key) {' in reg and reg.count('"AuthKey"') == 1, 'the key is added only when sent_key'
assert reg.index('ml_reg_auth_result(') < reg.index('ml_identity_mark_registered(ml);'), 'record only after acceptance'
assert 'return outcome == ML_REG_RETRY ? -2 : -1;' in reg
assert 'state = reg == -2 ? COORD_TCP_CONNECT : COORD_RECONNECTING;' in coord
assert 'ml->reg_auth.registered = ml_identity_registered(ml);' in reg, 'record read after the NVS key override'
assert 'NVS_KEY_REG_MARKER' in main and 'nvs_commit' in main[main.index('void ml_identity_mark_registered('):]

PROGRAM = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ml_reg_auth.h"

/* --- simulated control server ---------------------------------------- */
typedef struct {char key[40];bool single_use,used,revoked;} srv_key;
static srv_key keys[4];
static uint8_t registered_node[4][32];static int nodes;
static bool node_known(const uint8_t n[32]){for(int i=0;i<nodes;i++)if(!memcmp(registered_node[i],n,32))return true;return false;}
static void forget_node(const uint8_t n[32]){for(int i=0;i<nodes;i++)if(!memcmp(registered_node[i],n,32)){memset(registered_node[i],0,32);}}
typedef struct {bool error,needs_auth;} srv_resp;
static int invalid_key_errors;
static srv_resp server_register(const uint8_t node[32],const char *key){
    srv_resp r={0};
    if(key){   /* Tailscale refuses an invalid key also for a known node (#19501) */
        srv_key *k=NULL;for(int i=0;i<4;i++)if(!strcmp(keys[i].key,key))k=&keys[i];
        if(!k||k->revoked||(k->single_use&&k->used)){r.error=true;invalid_key_errors++;return r;}
        k->used=true;if(!node_known(node)){memcpy(registered_node[nodes++],node,32);}
        return r;
    }
    if(!node_known(node))r.needs_auth=true;
    return r;
}
/* --- device: the coordinator's use of the real code -------------------- */
typedef struct {uint8_t node[32];const char *key;uint8_t nvs_marker[ML_REG_MARKER_LEN];bool has_marker;ml_reg_auth_t s;} device;
static bool lose_next_response;
static void boot(device *d){
    uint8_t want[ML_REG_MARKER_LEN];ml_reg_marker(want,d->node,d->key);
    memset(&d->s,0,sizeof d->s);d->s.registered=d->has_marker&&!memcmp(want,d->nvs_marker,sizeof want);
}
/* One connection: returns 1 connected, 0 refused (backoff), counts retries. */
static int connect_once(device *d,int *immediate_retries,const char **why){
    for(int attempt=0;attempt<8;attempt++){
        bool have=d->key&&d->key[0];bool sent=ml_reg_auth_send_key(&d->s,have);
        srv_resp r=server_register(d->node,sent?d->key:NULL);
        if(lose_next_response){lose_next_response=false;return 0;}   /* transport loss after the server acted */
        ml_reg_outcome_t o=ml_reg_auth_result(&d->s,have,sent,r.error,r.needs_auth,why);
        if(o==ML_REG_ACCEPTED){ml_reg_marker(d->nvs_marker,d->node,d->key);d->has_marker=true;return 1;}
        if(o==ML_REG_REFUSED)return 0;
        (*immediate_retries)++;
    }
    assert(!"unbounded immediate retries");return 0;
}
int main(void){
    const char *why=NULL;int retries=0;
    device d;memset(&d,0,sizeof d);d.node[0]=7;
    strcpy(keys[0].key,"synthetic-key-one");keys[0].single_use=true;
    d.key=keys[0].key;boot(&d);
    /* 1. Single-use key: registered once, then 20 reconnects and 3 restarts. */
    assert(connect_once(&d,&retries,&why)==1&&keys[0].used&&retries==0);
    for(int i=0;i<20;i++)assert(connect_once(&d,&retries,&why)==1);
    for(int b=0;b<3;b++){boot(&d);assert(d.s.registered);assert(connect_once(&d,&retries,&why)==1);}
    assert(invalid_key_errors==0&&retries==0);
    /* 2. Lost response to the consuming registration (fresh device). */
    device e;memset(&e,0,sizeof e);e.node[0]=8;strcpy(keys[1].key,"synthetic-key-two");keys[1].single_use=true;
    e.key=keys[1].key;boot(&e);lose_next_response=true;
    assert(connect_once(&e,&retries,&why)==0&&keys[1].used&&!e.has_marker);
    retries=0;assert(connect_once(&e,&retries,&why)==1&&retries==1&&invalid_key_errors==1);
    boot(&e);assert(e.s.registered);assert(connect_once(&e,&retries,&why)==1&&invalid_key_errors==1);
    /* 3. Device deleted in the console, key used: bounded, clear refusal. */
    forget_node(e.node);retries=0;
    assert(connect_once(&e,&retries,&why)==0&&retries==2);
    assert(why&&strstr(why,"enter a new auth key"));
    int before=invalid_key_errors;assert(connect_once(&e,&retries,&why)==0&&invalid_key_errors==before);  /* key not resent this boot */
    /* ... a new key entered (restart with it) registers it again. */
    strcpy(keys[2].key,"synthetic-key-three");keys[2].single_use=true;e.key=keys[2].key;boot(&e);
    assert(!e.s.registered&&connect_once(&e,&retries,&why)==1&&keys[2].used);
    /* 4. An invalid new key for a registered device does not take it offline. */
    d.key="synthetic-key-mistyped";boot(&d);assert(!d.s.registered);retries=0;
    assert(connect_once(&d,&retries,&why)==1&&retries==1);
    boot(&d);assert(d.s.registered);before=invalid_key_errors;
    assert(connect_once(&d,&retries,&why)==1&&invalid_key_errors==before);
    /* 5. No key: authorization request is a refusal, not a connection. */
    device f;memset(&f,0,sizeof f);f.node[0]=9;f.key="";boot(&f);
    assert(connect_once(&f,&retries,&why)==0&&why&&strstr(why,"enter an auth key"));
    /* 6. Error without the key: refused. */
    ml_reg_auth_t s={.registered=true};assert(ml_reg_auth_result(&s,true,false,true,false,&why)==ML_REG_REFUSED);
    /* 7. Record: binds node and key, never contains the key. */
    uint8_t a[ML_REG_MARKER_LEN],b[ML_REG_MARKER_LEN],c[ML_REG_MARKER_LEN],z[ML_REG_MARKER_LEN];
    uint8_t n1[32]={1},n2[32]={2};static const uint8_t zero[32];
    ml_reg_marker(a,n1,"synthetic-key-abc");ml_reg_marker(b,n1,"synthetic-key-abd");ml_reg_marker(c,n2,"synthetic-key-abc");ml_reg_marker(z,n1,"");
    assert(memcmp(a,b,sizeof a)&&memcmp(a+32,c+32,32)&&!memcmp(z+32,zero,32)&&memcmp(a+32,zero,32));
    ml_reg_marker(b,n1,"synthetic-key-abc");assert(!memcmp(a,b,sizeof a));
    for(unsigned i=0;i+4<=sizeof a;i++)assert(memcmp(a+i,"synt",4)&&memcmp(a+i,"-abc",4));
    puts("PASS: actual registration auth: single-use key presented once (20 reconnects, 3 restarts, no invalid key), lost response, deleted device bounded refusal, new/mistyped key, no key, private record");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='reg-auth-') as tmp:
    t = Path(tmp)
    (t / 't.c').write_text(PROGRAM, encoding='utf-8')
    exe = t / ('t.exe' if os.name == 'nt' else 't')
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(ML / 'src'), '-I', str(BLAKE.parent)]
    if os.environ.get('POLICY_SANITIZE') == '1':
        flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([os.environ.get('CC', 'gcc'), *flags, str(t / 't.c'), str(ML / 'src/ml_reg_auth.c'), str(BLAKE),
                    '-o', str(exe)], check=True)
    out = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    print(out.stdout.strip())
    if out.returncode:
        raise SystemExit(out.stderr[-2000:])
    # Mutant: the 3.0.24 rule (always present a configured key) must fail.
    src = (ML / 'src/ml_reg_auth.c').read_text(encoding='utf-8')
    mutant = src.replace('return have_key && !s->refused && (s->needed || !s->registered);', 'return have_key;')
    assert mutant != src
    (t / 'm.c').write_text(mutant, encoding='utf-8')
    subprocess.run([os.environ.get('CC', 'gcc'), '-std=gnu11', '-w', '-I', str(ML / 'src'), '-I', str(BLAKE.parent),
                    str(t / 't.c'), str(t / 'm.c'), str(BLAKE), '-o', str(exe)], check=True)
    assert subprocess.run([str(exe)], capture_output=True, timeout=60).returncode != 0, '3.0.24 rule must fail'
print('reg auth: the auth key is presented only to log in')
