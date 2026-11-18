# Backup and restore

System → Backup & reset → **Backup file** (*Download backup*) downloads a JSON file generated in your
browser from the device's own settings APIs. Nothing is uploaded anywhere.

## What is included

Network and AP settings, system settings (name, time zone, TX power, Web port,
WiFi power save), DHCP reservations, AP-side port forwards, Tailscale settings
(without the auth key), firewall lists, Wake-on-LAN devices, MQTT and ntfy
settings (without passwords/tokens) and LAN → Tailnet rules.

**Secrets** (WiFi passwords, auth key, MQTT password, ntfy token, ...) are
included only if you choose *include secrets* and give a passphrase; they are
encrypted in the browser. Without the passphrase they cannot be restored.

Not included: the web password, Tailscale node identity, NVS internals,
service-rule expiry timers, profile history, Ethernet and Service watch
settings, logs.

## Restore

System → Backup & reset → **Restore…** applies the sections in order through the same validated
endpoints as the forms. Firewall lists are cleared and re-added in their
original order. Encrypted secrets are decrypted first, so a wrong passphrase
stops the restore before anything changes. A failing section stops with its
name; earlier sections stay applied, so review the result and fix the reported step before retrying.
An encrypted access-point password is restored together with protected mode.
To restore a protected setting onto an open AP, include the encrypted password
or set a new AP password first. When every section succeeds, the device restarts.

Restored LAN → Tailnet rules keep their saved enabled state; review them,
because a rule's exposure depends on today's network.

## Related

- Service rules alone: Network → LAN → Tailnet **export/import** (preview,
  confirmation, imported rules forced OFF) — see
  [SERVICE-GATEWAY.md](SERVICE-GATEWAY.md).
- Guided setups snapshot the settings they touch and offer *Restore previous
  settings* without reading secrets.
- Profiles keep one rollback level (System → General → Configuration profile).
  Since 3.0.26 there is one profile per first-boot goal (LAN → Tailnet
  services, subnet router and remote access, IoT Wi-Fi gateway, Wake-on-LAN
  and recovery, Home Assistant, monitoring, advanced); the goals chosen at
  first boot are marked "chosen at setup" and never applied by themselves.
  A profile only switches on local settings after a preview (now also the
  traffic count per access point device); access, uplinks, routes and
  notification channels stay guided steps. A record saved by a newer version
  with one of the new profiles reads as "no profile" on older firmware.
- Settings copies (System → Backup & reset) keep up to three full copies on
  the gateway itself, by hand or before each update; see [CHANGELOG](../CHANGELOG.md).
- Physical NVS power-loss behavior during restore is not qualified.
