# Selective Tailnet Service Gateway

The primary feature of ESP32 Tailnet Gateway — Mattboxx Edition: let ordinary
devices on your existing LAN use **specific** services on your Tailscale or
Headscale tailnet, without a Tailscale client on those devices, without joining
them to the ESP32 access point and without changing your router or default
gateway. The underlying VPN (Tailscale/WireGuard/DERP/MagicDNS) is not a
Mattboxx invention; the value here is making a selective, verifiable and
time-bounded service path easy to set up on a small independent board.

## When to use it — and when not

| Need | Use |
|---|---|
| A few LAN devices must reach one or two remote tailnet services | **Service Gateway rules** (this guide) |
| Tailnet clients must reach your LAN | Subnet router (Tailscale page), approved in your admin console |
| Devices can run a Tailscale client | Install the client on them |
| Isolated IoT devices on their own WiFi | AP gateway, with its separate AP-side forwarding |
| Site-wide routing, bulk transfer, video | A router/server-class Tailscale node, not an ESP32 |

## Five-minute example

Goal: an MQTT sensor hub at `192.168.1.20` (no VPN client) publishes to a
broker on another site, `broker.your-tailnet.ts.net:1883`.

1. Give the ESP32 a fixed LAN address, e.g. `192.168.1.50`, and join it to
   your tailnet. Allow its identity to reach the broker in your tailnet ACL.
2. Status → **What do you want to do?** → **Connect a LAN device to a Tailnet
   service** (or Network → **LAN → Tailnet service gateway**). While a rule is
   enabled, the Status page also shows a Service Gateway card. The guide checks
   uplink, control connection, web password and a free slot, lists the risks
   and asks you to acknowledge the exposure once per browser.
3. Add a rule: TCP, listen `18830`, destination `broker.your-tailnet.ts.net`,
   port `1883`, source `192.168.1.20/32`. It is saved **disabled**.
4. Press **Test destination**. The ESP32 itself makes one bounded TCP
   handshake (2 s limit) with the broker through the tunnel — the same remote
   leg forwarded clients use — while the rule is still disabled.
5. Enable the rule, optionally arm an expiry, and set the hub's broker to
   `192.168.1.50:18830`. Watch installed state and accepted/rejected counters.

## Destination test results (development line)

| State | Meaning | Not a claim of |
|---|---|---|
| `reachable` | TCP handshake completed from the ESP32 | application health, LAN client path |
| `no_tcp_answer` | No handshake in 2 s | which of refusal, filtering or timeout |
| `udp_unverifiable` | UDP has no handshake | either success or failure |
| `control_offline` / `policy_not_ready` | Tunnel prerequisites missing | a remote fault |
| `unresolved` | Not a Tailnet IPv4 from literal/peer cache | the peer being offline |
| `resource_deferred` / `local_error` | Local admission or socket problem | a network fault |
| `rule_changed` | Rule edited before the test ran | anything about the service |

Tests run only on request, one at a time, with a 5 s per-rule cooldown, in
the existing optional operations worker (one socket); the routing core never
waits for them. A result belongs to the rule's exact settings: editing the
destination, port, protocol or source hides it. Requires a board with PSRAM
for the optional worker.

## Service watch (development line, optional)

Network → LAN → Tailnet → **Service watch** periodically repeats the destination
test for enabled TCP rules, one rule per interval (60–86400 s, default 900),
round-robin, in the same single bounded slot as manual tests (a manual test is
never displaced). Two consecutive "no TCP answer" results send one ntfy notice
(and refresh MQTT); the next answer sends one recovery notice. Tunnel, policy
or resource states are not counted as service evidence. OFF by default; it
never enables, disables or edits rules. UDP rules are not watched.

## Activity and reply evidence (development line)

Each rule shows when the gateway last **accepted** and last **rejected** a LAN
packet for it (uptime-based, "never this boot" after a restart), and when the
Tailnet service last **replied**: the newest reply the policy gate admitted on
a flow this gateway sent to that destination IP and port. For UDP that reply is
the only evidence the service answers. Reply evidence belongs to the remote
service tuple, so rules sharing a destination share it; it is not per LAN
client, and it disappears while authority is suspended or after revocation.
The activity line also shows the destination peer's path from the current
peer list: direct, relayed via DERP (slower) or offline. It is a snapshot, not
a reachability test.

## Templates and export (development line)

Templates (MQTT over TLS, unencrypted MQTT, HTTPS, NAS web UI, Home Assistant,
Grafana, SSH, syslog over UDP, Remote Desktop) prefill name, protocol and ports,
pick the first free listen port and show the main risk. Destination and source
are never guessed and the rule starts disabled. The Status card lists open
temporary rules and the soonest closure. The local diagnostic export includes
per-rule state, diagnosis, test state, counters and ages, never names,
destinations, ports, source networks or runtime error text.

## MQTT and Home Assistant (development line)

The MQTT state lists each rule's `status` (the same diagnosis code as the Web
UI), `destination_check` and `service_reply_age_s` (null when no reply was
seen). Home Assistant Discovery adds a "Tailnet rule status" sensor next to
each rule's switch and expiry sensor; unused slots are cleared. The switch
topic still requires the rule binding token. Real Home Assistant behavior and
the state payload size budget are not yet qualified.

SNMP (read-only, private tree `1.3.6.1.4.1.99999.2`): `.17.0`/`.18.0` accepted
and blocked packets, `.22.0` rules whose current destination test was
reachable, `.23.0` rules with an admitted reply from their service.

## Performance and limits

IPv4 TCP/UDP, up to 8 rules, destination in `100.64.0.0/10`. Clients connect to
the ESP32 address and listen port (port forwarding, not transparent routing).
WiFi plus software WireGuard on a microcontroller suits control, telemetry,
dashboards and SSH; throughput is not measured for the current candidate.

## Time limits

Each rule has a **Stays open** choice: *No time limit* (it forwards while it
is switched on) or 15 minutes, 1 hour, 8 hours, 1 day or 7 days, optionally
with *Delete the rule when the time is up*. Save applies the rules and then
the time limit of each rule. A rule closed by its time limit says so on the
rule ("Time is up" or "Not forwarding: choose how long it stays open"); choose
a new time limit and Save to open it again. A time limit needs the clock to be
set; it never switches on a rule that is off.

How it is enforced: once a time limit has been used, every new or edited rule
must have its choice confirmed (Save does this for you); until then the rule
is closed, so an edited rule can neither lose nor silently gain a time limit.
Rule tokens are change detectors, not authentication. Unknown clock or store,
expiry or an unconfirmed rule means denied forwarding; expiry survives a
restart and a clock rollback closes the rule. Expired rules keep their ports
unless *Delete the rule when the time is up* was chosen. Notices when a time
limit closes a rule (ntfy) are under *More options*, off by default.

## Example: IoT at a second home, broker at the first

The IoT device stays on its normal WiFi and does not install a VPN client.
Configure the broker endpoint it uses as the ESP's uplink-LAN IP and a local
forwarding port. The broker at the other site must be a reachable Tailnet peer;
Home Assistant then uses that broker normally.

| Rule field | Example |
|---|---|
| Name | Remote MQTT |
| Enabled | OFF while preparing; enable and Save deliberately |
| Protocol | TCP |
| Listen port | 18830 |
| Tailnet destination | 100.64.0.2 (example peer address) |
| Destination port | 1883 |
| Allowed source subnet | 192.168.50.42/32 (example local client) |

The device connects to `ESP-LAN-IP:18830`. The forwarder sends to
`100.64.0.2:1883`. If your service uses TLS, retain its certificate/hostname
requirements; pointing a TLS client at a different IP may require correct
SNI/server-name support. Do not disable verification just to make a template
work. Tailnet transport encryption does not encrypt the ordinary LAN hop.

No static route on the home router is needed **for this selected-port path**.
That does not apply to arbitrary site-to-site routing. AP SSID, DHCP, client
membership and AP-side port mappings are independent.

## Explain status and LAN exposure

In development source 1.14, expand a rule's **Explain status & LAN exposure**.
It shows the saved local/remote path, source restriction, passive diagnosis,
runtime report, historical accepted/rejected counts and next step.

- Disabled: explicitly not enabled; not a network fault.
- Uplink has no IPv4: cannot bind the configured STA path. Not proof the router
  itself is broken.
- Control session not ready: inspect authentication/startup state. Existing
  data sessions may still work; control and data are not the same observation.
- Destination unresolved: check the saved Tailnet address/name. Not proof
  the peer is powered off.
- Mapping not installed: review runtime error/listener conflicts and reload
  after the existing manager refreshes.
- Mapping installed: the local mapping exists; the remote service is **not
  tested**. Try from the permitted client, then check remote service/listener,
  authentication, firewall and applicable tailnet policy if it fails.

Development line: evidence refines these states without hiding a passive
fault (an uplink or control problem always wins):

- Ready to enable: rule disabled, destination test reachable.
- Service replied recently: the policy gate admitted a reply from that
  destination on a flow this gateway sent. Not per LAN client.
- Destination test got no TCP answer: check the peer, its listener and the
  Tailnet ACL for this gateway.
- Only rejected LAN packets seen: traffic reaches the listener but not from the
  allowed source (or the expiry closed it). Compare the client with the CIDR.
- Destination test reachable: try from the allowed client.

There is no background probing and no automatic refresh added by this panel;
the destination test runs only when requested.
Save applies edits; an unsaved draft does not inherit an old “working” label.
A failed read retains fields and reports unavailable; retry Reload before Save.

## Security and protocol boundaries

Use `/32` for a single client where practical. `/0` is an explicitly broad
source policy and is warned about. A source CIDR is not authenticated identity:
another host on the local segment may spoof addresses. Authenticate the service
and isolate untrusted LAN clients. Rule enablement is a real exposure decision.

This is an IPv4 TCP/UDP service mapping to a peer in 100.64.0.0/10, not a
transparent LAN bridge or arbitrary remote subnet destination selector. It
does not relay mDNS/SSDP discovery or automatically fix multiport/callback/
embedded-address protocols. Home Assistant compatibility depends on each
integration. The firmware itself is a third-party Tailscale-compatible client;
read the [policy limitation](../SECURITY.md#tailnet-policy-compatibility-boundary)
before relying on fine-grained tailnet authorization.
