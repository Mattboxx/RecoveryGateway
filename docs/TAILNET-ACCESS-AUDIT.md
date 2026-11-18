# Tailnet access audit

Origin: a user report on official Tailscale with 3.0.24 (device visible in the
admin console, then offline; "invalid key"; "reason=peer-update" with 18
devices). Each item: what blocks access, status, where.

### Fixed

| Item | Effect before | Fix (version) |
|---|---|---|
| Auth key sent at every reconnect | single-use key refused ("invalid key"), device offline after the first reconnect or restart | key only to log in, registration record in NVS (beta.16) |
| 16-peer map limit | map with >16 peers refused whole, tunnel blocked | map, ACL rules and peer table sized by the tailnet; 20 tunnel slots with rotation (beta.16/17) |
| One route per peer in WireGuard | second subnet or subnet + exit route unreachable | 31 extra allowed IPs per peer in PSRAM (beta.17) |
| 128 ACL rules | larger policy refused whole | rule table sized by the policy (beta.17) |
| Node key expiry | factory reset needed | 14-day warning, renewal with OldNodeKey at the next start (beta.17) |
| First map without Peers (empty tailnet, omitempty) | lone gateway: no peer authority, tunnel blocked, reconnect loop | first map of a session is complete (beta.18) |
| "cap:" ACL sources | whole policy refused, all traffic blocked | such a source admits nobody, other rules apply (beta.18) |
| Control only on port 80 | no registration where 80 is blocked/proxied | TLS 443 fallback after two failures, and back (beta.18) |
| Clock only from pool.ntp.org (audit item 1) | NTP blocked: key expiry checks fail, policy "pending" | clock from MapResponse.ControlTime while unset (beta.18). NTP fallback servers: not added (CONFIG_LWIP_SNTP_MAX_SERVERS=1) |
| DERP fixed on the first node, DNS only | relay down if that node or DNS fails (mobile/CGNAT: no access) | next node of the region after a failure; DERPMap IPv4 when DNS fails (beta.18) |
| Pasted auth key with spaces | "invalid key" | trimmed in the page, on save and on load (beta.18) |
| Address item 0 assumed IPv4 | empty address for IPv6-first lists | first IPv4 of the list (beta.18) |
| Start refused without a saved key | key could not be removed after registering | registered identity starts without it (beta.18) |
| "Waiting for approval" stuck | state not cleared (reconnects skip registration) | follows MachineAuthorized in the map (beta.18) |
| Node key expired seen in the map | reconnect loop every 60 s without registering (reconnects skip registration) | forces a registration, records the expiry for the renewal, shows it (beta.20) |
| Built-in Tailscale control Noise key | a key rotation would stop every device | after a failed handshake the current key is fetched over verified HTTPS (beta.20) |
| Peer key rotation in a patch | refused, full map refresh, short interruption | applied, old key revoked, tunnel replaced at once (beta.21) |
| Peer without a tunnel slot reaching out | its DISCO dropped until the 30 s refill | gets a slot at once (rate-limited lookup) (beta.21) |
| DNS failure for the control host | no connection | last working address (NVS, written on change) (beta.21) |
| DNS failure: Headscale key fetch and HTTPS (443) | still resolved by name: no access after a restart | same last working address; TLS still verifies the name (beta.22) |
| Custom server Noise key changed | every handshake failed until a restart | fetched again after a failed handshake (beta.22) |
| Peer cache flash writes | 7.7 KB rewritten per peer per map (about 140 KB per reconnect with 18 peers) | written only when a peer changes; wrap-safe LRU (beta.22) |
| Control server refuses the Noise upgrade | "101" anywhere passed; every refusal shown as "Noise handshake failed" | status 101 only; the server's answer named (version, URL/proxy, access, rate limit, 5xx) (beta.23) |
| Peer homed on another DERP region, no direct path | traffic the gateway starts toward it lost (relays deliver only to their own clients) | after the home relay's PeerGone "not here", one on-demand relay connection to the peer's region, closed after 60 s idle (beta.24) |
| WireGuard handshakes/keepalives sent off the network thread | race in lwIP's ARP table (upstream field reboot) | posted to the TCPIP thread as a copy (upstream 0.1.39) (beta.25) |
| Kept direct endpoint, quiet peer | never re-checked, packets lost | re-checked every tick, relay after 30 s without direct traffic (upstream 0.1.39) (beta.25) |
| LAN → Tailnet rule edited after a timer was used | silently stopped forwarding until confirmed in a separate timer section | time limit chosen on the rule and confirmed on Save; a closed rule says why (beta.24) |

### Audit items 2-6

2. **Map response size.** One response must fit one buffer: 512 KB through
   beta.17, 768 KB in beta.18 (about 250-500 peers in an official map at
   1.5-3 KB per peer). Beyond it the accumulator overflows, the policy is
   reset and the gateway reconnects. Compression (zstd, which Tailscale
   supports; the firmware sends "Compress": "") would cut the bytes on the
   wire but not this limit: the decompressed map is still held and parsed
   whole (cJSON needs several times its size). The fix is a streaming parser
   that reads the Peers list one peer at a time.
3. **PingRequest.** Liveness requests over Noise are answered with a HEAD
   to their URL since beta.19 (as the reference client); other types
   (disco, TSMP, c2n) and plain-TLS URLs are logged, not answered.
4. **Capability version 131 claims more than implemented.** Seamless key
   renewal (126) and C2N debug requests (127-128) are not implemented; the
   one blocking consequence found ("cap:" sources, 109) is fixed. Align the
   version or implement.
5. **DisplayMessages** (capver 117): shown on the Tailscale page since
   beta.19 (at most 4, plain text).
6. **IPv6 in the tailnet.** Tunnels route IPv4 only (4via6 inbound
   excepted); reaching a peer's fd7a:... address from the gateway does not
   work. Documented in CONFIGURATION.md; IPv6 allowed IPs and routing would
   be the fix.

Also open: HTTPS login servers and custom DERP relays must have a certificate
from a public CA (a private CA or self-signed certificate is refused; use
http:// for a LAN-only Headscale, or a public certificate). The DERP map keeps
32 regions of 4 nodes (Tailscale's public map has 28 regions; extra nodes of
a region are only redundancy). One auxiliary relay at a time: two peers in two
other regions, both without a direct path and both busy, share it in turns
(a busy relay keeps its region for 10 s).

Also open: on the very first connection with DNS failing there is no known
control address yet (official clients have baked bootstrap addresses and
DERP bootstrap DNS).
In keep mode a lone gateway can need one extra reconnect when a stream starts
with OmitPeers.
