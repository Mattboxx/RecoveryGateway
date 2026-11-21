"""Generate the project's NAPT and owned timeout changes from pinned ESP-IDF sources."""
# SPDX-License-Identifier: GPL-3.0-only
import argparse
import hashlib
from pathlib import Path

NAPT_FILE = 'src/core/ipv4/ip4_napt.c'
TIMEOUTS_FILE = 'src/core/timeouts.c'
SDK_HASHES = {
    NAPT_FILE: '35662ff7531d0a93b0609495a9452c40ba375cd26cc9427ec233a57d16716f33',
    TIMEOUTS_FILE: '373d44f83a092e02c2da112355fe4c783a1e56d019859178e8f48d9acd154f17',
}

# The generated files retain the existing copyright and license notices.
NOTICE = '/* RecoveryGateway changes: see tools/prepare_lwip_napt.py. */\n'


def pinned_source(root, path):
    data = (root / path).read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(data).hexdigest() != SDK_HASHES[path]:
        raise ValueError(f'Unreviewed lwIP input: {path}. Review the NAPT patch for the new SDK.')
    return data.decode('utf-8')


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError(f'Unexpected lwIP patch context: {old!r}')
    return source.replace(old, new, 1)


def patch_napt(source):
    source = replace_once(source, 'static void ip_napt_tmr(void *arg);',
                          'static void ip_napt_tmr(void *arg);\nstatic lwip_owned_timeout_t napt_timeout;')
    source = replace_once(source, '#include "lwip/timeouts.h"', '#include "lwip_owned_timeout.h"')
    source = replace_once(source, '  sys_untimeout(ip_napt_tmr, NULL);',
                          '  lwip_owned_timeout_cancel(&napt_timeout);')
    start = source.index('/**\n * Allocates and initializes the NAPT tables.')
    end = source.index('/* adjusts checksum in a packet', start)
    code = r'''/* Publish both tables only after all allocations succeed. */
static int
ip_napt_init(void)
{
  u16_t i;
  struct ip_napt_entry *nat;
#if IP_NAPT_PORTMAP
  struct ip_portmap_entry *portmap;
#endif

  if (ip_napt_table != NULL) {
    return 1;
  }
  nat = (struct ip_napt_entry *)mem_calloc(IP_NAPT_MAX, sizeof(*nat));
  if (nat == NULL) {
    return 0;
  }
#if IP_NAPT_PORTMAP
  portmap = (struct ip_portmap_entry *)mem_calloc(IP_PORTMAP_MAX, sizeof(*portmap));
  if (portmap == NULL) {
    mem_free(nat);
    return 0;
  }
#endif
  for (i = 0; i < IP_NAPT_MAX - 1; i++) {
    nat[i].next = i + 1;
  }
  nat[i].next = NO_IDX;
  ip_napt_table = nat;
  ip_napt_max = IP_NAPT_MAX;
#if IP_NAPT_PORTMAP
  ip_portmap_table = portmap;
  ip_portmap_max = IP_PORTMAP_MAX;
#endif
  lwip_owned_timeout_schedule(&napt_timeout, NAPT_TMR_INTERVAL, ip_napt_tmr, NULL, "ip_napt_tmr");
  return 1;
}

static int
ip_napt_set_netif(struct netif *netif, int enable)
{
  struct netif *other;
  if (enable) {
    if (!ip_napt_init()) {
      return 0;
    }
    netif->napt = 1;
  } else if (netif->napt) {
    netif->napt = 0;
    NETIF_FOREACH(other) {
      if (other->napt) {
        return 1;
      }
    }
    ip_napt_deinit();
  }
  return 1;
}

void
ip_napt_enable(u32_t addr, int enable)
{
  struct netif *netif;
  NETIF_FOREACH(netif) {
    if (netif_is_up(netif) && !ip_addr_isany(&netif->ip_addr) &&
        ip_2_ip4(&netif->ip_addr)->addr == addr) {
      if (!ip_napt_set_netif(netif, enable)) {
        return;
      }
    }
  }
}

void
ip_napt_enable_no(u8_t number, int enable)
{
  struct netif *netif;
  NETIF_FOREACH(netif) {
    if (netif->num == number) {
      ip_napt_set_netif(netif, enable);
      return;
    }
  }
}

int
ip_napt_enable_netif(struct netif *netif, int enable)
{
  return netif_is_up(netif) && ip_napt_set_netif(netif, enable);
}

'''
    updated = source[:start] + code + source[end:]
    updated = replace_once(updated, '  sys_timeout(NAPT_TMR_INTERVAL, ip_napt_tmr, arg);',
                           '  lwip_owned_timeout_schedule(&napt_timeout, NAPT_TMR_INTERVAL, ip_napt_tmr, arg, "ip_napt_tmr");')
    return NOTICE + updated


def patch_timeouts(source):
    source = replace_once(source, '#include "lwip/timeouts.h"', '#include "lwip_owned_timeout.h"')
    source = replace_once(source, 'static struct sys_timeo *next_timeout;',
                          '''static struct sys_timeo *next_timeout;

static void
dispatch_owned_timeout(void *arg)
{
  lwip_owned_timeout_t *timer = arg;
  timer->handler(timer->arg);
}

static void
release_timeout(struct sys_timeo *timeout)
{
  if (timeout->h == dispatch_owned_timeout) {
    lwip_owned_timeout_t *timer = timeout->arg;
    timer->pending = 0;
  } else {
    memp_free(MEMP_SYS_TIMEOUT, timeout);
  }
}''')
    start = source.index('static void\n#if LWIP_DEBUG_TIMERNAMES\nsys_timeout_abs(')
    body = source.index('  timeout->next = NULL;', start)
    tail = source.index('\n}\n', body) + 3
    insertion = '''static void
#if LWIP_DEBUG_TIMERNAMES
insert_timeout(struct sys_timeo *timeout, u32_t abs_time, sys_timeout_handler handler,
               void *arg, const char *handler_name)
#else
insert_timeout(struct sys_timeo *timeout, u32_t abs_time, sys_timeout_handler handler, void *arg)
#endif
{
  struct sys_timeo *t;

'''
    allocation = source[start:body].replace('struct sys_timeo *timeout, *t;', 'struct sys_timeo *timeout;')
    output = source[:start] + insertion + source[body:tail] + '\n' + allocation + '''#if LWIP_DEBUG_TIMERNAMES
  insert_timeout(timeout, abs_time, handler, arg, handler_name);
#else
  insert_timeout(timeout, abs_time, handler, arg);
#endif
}

void
lwip_owned_timeout_cancel(lwip_owned_timeout_t *timer)
{
  LWIP_ASSERT_CORE_LOCKED();
  if (timer->pending) {
    sys_untimeout(dispatch_owned_timeout, timer);
  }
}

/* Preserve tick ordering and wrap handling without allocating timer nodes. */
void
lwip_owned_timeout_schedule(lwip_owned_timeout_t *timer, u32_t delay_ms,
                           sys_timeout_handler handler, void *arg, const char *name)
{
  LWIP_ASSERT_CORE_LOCKED();
  LWIP_ASSERT("Timeout time too long", delay_ms <= (LWIP_UINT32_MAX / 4));
  lwip_owned_timeout_cancel(timer);
  timer->handler = handler;
  timer->arg = arg;
  timer->pending = 1;
#if LWIP_DEBUG_TIMERNAMES
  insert_timeout(&timer->node, (u32_t)(sys_now() + delay_ms), dispatch_owned_timeout, timer, name);
#else
  LWIP_UNUSED_ARG(name);
  insert_timeout(&timer->node, (u32_t)(sys_now() + delay_ms), dispatch_owned_timeout, timer);
#endif
}
''' + source[tail:]
    for pointer in ('t', 'tmptimeout'):
        output = replace_once(output, f'memp_free(MEMP_SYS_TIMEOUT, {pointer});', f'release_timeout({pointer});')
    return NOTICE + output


def prepare(lwip, destination):
    sources = {
        NAPT_FILE: patch_napt(pinned_source(lwip, NAPT_FILE)),
        TIMEOUTS_FILE: patch_timeouts(pinned_source(lwip, TIMEOUTS_FILE)),
    }
    destination.mkdir(parents=True, exist_ok=True)
    for source_path, text in sources.items():
        path = destination / Path(source_path).name
        # LWIP_ASSERT uses __FILE__. Keep its diagnostic independent of the
        # generated file's absolute location, including on Windows builds.
        data = (f'#line 1 "esp-lwip/{source_path}"\n' + text).encode('utf-8')
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('lwip', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    try:
        prepare(args.lwip, args.destination)
    except (OSError, ValueError) as error:
        parser.exit(1, f'{error}\n')
