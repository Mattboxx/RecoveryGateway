# Repository rename and OTA migration

## RecoveryGateway (3.0.28)

From 3.0.28 the product is **RecoveryGateway — Mattboxx Edition** (formerly ESP32
Tailnet Gateway). Same firmware, same settings: the internal identity
(`esp32_tsr`, saved settings, the updater's checks) does not change, and the
first-boot Wi-Fi is now `RecoveryGateway-Setup-XXXX`.

With 3.0.28 the repository was renamed to `Mattboxx/RecoveryGateway` and the
website moved to `mattboxx.github.io/RecoveryGateway`.

- **Updater.** 3.0.28 asks `Mattboxx/RecoveryGateway` first, then
  `Mattboxx/esp32-tailnet-gateway` only if that answers 404, then the older
  name, and accepts downloads from any of the three release paths.
- **Redirect repository.** Firmware 3.0.27 and older asks only
  `Mattboxx/esp32-tailnet-gateway`, with redirects disabled, so it cannot follow
  GitHub's rename redirect. A small repository therefore keeps that name: it
  holds no source, only the 3.0.28 **transition release** (the same files as
  the 3.0.28 release here, including `firmware.bin`) and redirect pages. Those
  gateways find 3.0.28 with a normal update check; from then on they use this
  repository. Give it a new release only when a newer transition image is
  needed, and never delete or rename it.
- **Website.** GitHub Pages does not follow a rename. The redirect repository
  publishes `mattboxx.github.io/esp32-tailnet-gateway/`, whose pages (including
  its 404 page for every deep link) send visitors to the same path under
  `mattboxx.github.io/RecoveryGateway/`.
- **Code links.** Because the old name is taken by the redirect repository,
  GitHub no longer redirects `github.com/Mattboxx/esp32-tailnet-gateway/...`:
  its front page points here, but old deep links (a file, a tag, an issue)
  answer 404 there. Maintained documents link the new name. Firmware 3.0.28
  still links the old repository from System → About (the next firmware links
  the new one) and hides the release-notes link for releases of the new name.
- **Git remotes.** Point clones to `https://github.com/Mattboxx/RecoveryGateway.git`:
  the old URL now reaches the redirect repository, not this one.
- The oldest name, `Mattboxx/esp32-tailscale-gateway-NAS-recovery`, still
  redirects here.

## Earlier rename

The project was **ESP32 Tailnet Gateway — Mattboxx Edition**.
The existing repository has moved from
`Mattboxx/esp32-tailscale-gateway-NAS-recovery` to
`Mattboxx/esp32-tailnet-gateway` (now [`Mattboxx/RecoveryGateway`](https://github.com/Mattboxx/RecoveryGateway)).
Its history, fork relationship, issues, tags and historical releases remain.
Do not create another repository at the old name: it would break redirects.

## Bridge release

The bridge **0.1.38-Mattboxx-1.100** was published under the previous repository
name before the rename. Its legacy version can be selected by 1.10–1.13
updaters, while the bridge's updater also understands **Firmware v2.0.0**.
The repository was renamed immediately afterward, without a migration window.

## Devices still running 1.13 or earlier

Older updaters require HTTP 200 from the fixed previous GitHub API endpoint.
GitHub's repository rename returns a redirect, which those versions refuse.
Their updater can therefore report **GitHub check failed** after the rename.
The installed firmware keeps running; this does not erase settings or partially
install an image. Releases before 1.10 have no GitHub updater.

The current 3.x application does not fit these old OTA slots. Do not upload
its `firmware.bin` directly to a 1.x/2.x layout.

1. Back up your configuration and check the [3.x hardware requirements](HARDWARE.md).
2. For a cable-based upgrade, use the current [Easy Install keep-settings
   option](https://mattboxx.github.io/RecoveryGateway/easy-install/).
3. For the staged network route, first upload `firmware.bin` from the
   [legacy 1.100 bridge](https://github.com/Mattboxx/RecoveryGateway/releases/tag/v0.1.38-Mattboxx-1.100)
   in **System → Firmware**. This is the old-layout bridge, not the latest 3.x image.
4. Continue through the **2.1.0 bridge** and its **Move to the 3.0 flash layout**
   action as described in [Moving to 3.0](MIGRATION-3.0.md).

Do not upload a factory image in the Web UI. New-device/erase installation
deletes settings. USB keep-settings installation writes the first app slot
and initial OTA selection; it is not an inactive-slot OTA operation and must
not overwrite a deliberately protected recovery image.

## New update behavior

- The bridge and 2.x updater check the new repository first and fall back to
  the previous name only on HTTP 404. Rate limits, 5xx and transport failures
  do not silently select another repository.
- Release downloads accept the fixed old and new repository paths and the
  approved GitHub asset CDN, retaining TLS verification and SHA-256 checks.
- Application identity `esp32_tsr` and the NVS namespace remain stable.
  Ordinary application updates within a compatible layout preserve settings;
  moving to the 3.x layout requires the separate migration procedure above.
- Periodic checks, automatic installation and beta participation remain
  explicit opt-ins. **Check now** and **Install latest update** are on demand.

Historical 1.13 downloads remain available for recovery. Firmware rollback
depends on the valid previous OTA slot; serial recovery can use an appropriate
saved image. See [Updates](UPDATES.md) and [Backup and restore](BACKUP-RESTORE.md).
