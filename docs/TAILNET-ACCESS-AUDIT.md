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

Also open: no DNS fallback for the control host (official clients have baked
bootstrap addresses); an explicit "controlplane.tailscale.com" login server is
treated as custom (no port fallback); in keep mode a lone gateway can need one
extra reconnect when a stream starts with OmitPeers.
