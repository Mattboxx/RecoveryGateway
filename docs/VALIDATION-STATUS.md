# Validation records

3.0.25-beta.4 (release source `3e142f1`, pre-release `v3.0.25-beta.4`, not Latest): lean USB sessions under internal RAM pressure, translated card states and firmware messages, a Waiting badge. `validate_all.py --browser` 147/147 PASS; clean build, provenance PASS, BIN b24591fc189268218389056801bb1f9f200fcd01de999c05bbe4d98082e3b11d; history scan 0 findings; board B (MAC verified, ota_0) boot, exact UI, protected APIs, 15 LAN checks; assets re-downloaded and matched. Afterwards (for the next candidate, not in beta.4): the simple-mode note ("N advanced sections are hidden") is translated with its number; browser 111 scenarios PASS.

Board A measurement with 3.0.25-beta.3 (owner-installed through the beta channel; owner-authorized changes, then restored): Cellular set to USB and enabled with no device, restart. `/api/cellular` reported state `backoff`, "no USB device on the USB port", `usb.internal_ram`: host 3344 B, free 44331 B, minimum since boot 39828 B (48723 B free with USB off at the same uptime). Tailnet connected, Wi-Fi up, CPU 3 %. Settings restored to off/UART (record identical to before) and the board restarted without the USB host. UI findings fixed in beta.4: English state/error texts and a "Connecting…" badge while waiting for a device; an untranslated runtime string "2 advanced sections are hidden in simple mode" on the System page predates this work and is listed as a follow-up.

3.0.25-beta.3 (release source `a93ffdd`, published 2026-11-15 as the pre-release `v3.0.25-beta.3`, not Latest). Found on the owner's board A running beta.2 (read-only checks through the owner's authenticated browser session): 46 KB of internal RAM free with its features on, below the beta.2 USB guards (56/64 KB), so the USB connection could never start there. Beta.3 drops the CDC-ACM host driver (4 KB internal task stack), runs serial ports through the usb_port session with smaller transfers, and refuses a USB start or session only when less than 40 KB would stay free, reporting the measured use (`usb.internal_ram`). `validate_all.py --browser` 147/147 PASS; clean build, `check_image_provenance.py` PASS, BIN 2a5a117a93041646ebe9de2b79ad5e7e5e5ff0a81b5dbac540c63ade65d3cd80; history scan 0 findings; board B (MAC verified, ota_0) boot, exact UI, protected APIs, 15 LAN checks; release assets re-downloaded and matched. Board A found v3.0.25-beta.3 through its beta channel; its installation and the measurement of the USB host cost there wait for the owner (installing firmware on the daily board needs the owner's own click).

3.0.25-beta.2 (release source `6af276d`, published 2026-11-15 as the GitHub pre-release `v3.0.25-beta.2`, not Latest): pins/USB choice in first-boot setup, clearer USB guidance with device lists, UART/SPI settings saved again in the 3.0.24 record format. `validate_all.py --browser` with the pinned IDF 6.1 tree: 145 of 146 checks passed; `test_automation_ui.cjs` failed on a stale selector of the new USB hint block, fixed in `6af276d` and passed 109/109 alone. `test_first_boot_ui.cjs` 20 runs PASS (USB flows included). Clean build of `6af276d`, `check_image_provenance.py` PASS, BIN 2859d1fec0735b7afc4951ead394187d75a58448ae27844f6659a7296acb883d. Sensitive-data scan of the tree and history: 0 findings. Owner-authorized install of that exact image on test board B (MAC verified, ota_0 only): boot without panic, exact UI, protected APIs, 15 LAN checks. Release assets re-downloaded and matched `SHA256SUMS.txt`. USB devices themselves are still untested.

3.0.25-beta.1 (source `9ff75d3`, branch `feat/usb-cellular-20261115` from 3.0.24): USB modems, 4G sticks, USB Ethernet adapters and phone tethering (ADR-036). Host: `test_usb_port.py` (new: ECM/NCM/RNDIS/MBIM/vendor/storage scan, decisions, usb_modeswitch messages byte for byte, RNDIS/NCM framing with malformed input and a 20000-case fuzz), `test_cell_uplink.py` (transport/USB validation, AT line classifier, USB interface plan with synthetic descriptors and fuzz, v1->v2 migration, API), `test_eth_uplink.py` (SPI/USB, v1->v2, API), `test_netif_hooks.py` (USB network netif hooked on add) PASS. `test_automation_ui.cjs` 109 scenarios PASS (3 new). `i18n_extract.py --check 100` PASS in it/de/fr/es/zh. `test_index_variants.py` PASS at 174355 gzip bytes under the budget raised to 175000. Targeted `validate_all.py --only` (20 drivers incl. license_compliance, feature_preservation, task_memory, first_boot, tailnet_sdk) PASS. Clean ESP32-S3 build (IDF 6.1, 69.5 %, static RAM 57592 B; image internal RAM +2.5 KB against 3.0.24); BIN e220015c2fbee129227ed4ef17fc912b8301424e15700c934386019007932618 in ignored `build/development-3.0.25-beta.1/9ff75d3/`. Owner-authorized install on test board B (MAC verified, ota_0 only, settings kept): serial boot without panic, the exact generated UI served, `/api/network`, `/api/cellular`, `/api/ethernet` protected, 15 LAN checks with unchanged state; USB connection left off. Pending: everything with a real USB device (board B reaches the PC through its native USB port, so enabling the USB host there cuts its serial link), unplug/replug, power, throughput, internal heap while enabled, full `validate_all.py`.

3.0.23 (source `4032840`): the Network page opens and closes the gateway Wi-Fi like first boot. `tools/test_network_ap_ui.cjs` (new), `tools/test_first_boot.py` (`fb_check_ap_change`), `tools/test_first_boot_ui.cjs` (20 runs) and `tools/test_automation_ui.cjs` (106 scenarios) passed; `tools/test_index_variants.py` passed at 172995 gzip bytes under the 173000 budget. Clean build with provenance PASS (BIN 9f2de869e1de47966933bfc1c3531e152ca0d2bad7e5eab93a7d52f8b5af6b3a). Owner-authorized install on test board B (MAC verified, settings kept, otadata erased): it started with its saved settings, joined the uplink and turned its recovery AP off, no panic. Full `validate_all.py` and the open/close switch on hardware are pending.

3.0.22 (release source `ecd06a0`, web installer staged in `4f96f72`): clean ESP32-S3 build with image provenance PASS (BIN 6cea151c915f6e9f04981980c31be647440ea5ad9eb89ce77efb60d544860119). `tools/validate_all.py --browser` with the pinned IDF 6.1 tree: 143 of 144 checks passed; `test_automation_ui.cjs` timed out once waiting for the ntfy save button and passed 106/106 scenarios in two separate reruns. Firmware build and provenance were run separately on the release source. Hardware: the owner completed first boot of the equivalent 3.0.22-beta.2 on test board B; board A was not updated.

3.0.22-beta.2 (source `f2daa14`): `tools/test_first_boot_ui.cjs` passed 20 runs, including the Tailscale choice, no page scrolling behind the wizard, `.local` name, mode-named gateway Wi-Fi and the explicit open AP. `tools/test_first_boot.py` passed with the new `fb_check_lan_name` and `fb_check_ap_settings` rules (host crypto built from the pinned IDF 6.1 tree). `tools/test_index_variants.py` passed at 172755 gzip bytes under the 173000 budget. ESP32-S3 build succeeded (66.9 %). Board B (test-only) runs it and booted into first-boot setup mode without a panic; the owner then completed the wizard on board B and reported that everything works (2026-11-14, owner report; no captured logs of that walk-through). The full `validate_all.py` campaign is pending.

First-boot choices by goal (3.0.22-beta.1, source `60cc662`): `tools/test_first_boot_ui.cjs` passed 20 viewport/language runs, including the new step-4 flow (focus on the title, no section opened or page moved by a choice, preset undo, summaries, language change, firmware role order). `tools/test_index_variants.py` passed at 171828 gzip bytes under the raised 172000 budget; `tools/i18n_extract.py --check 90` passed. The ESP32-S3 build succeeded (66.7 % of the app slot). Board B (test-only) was flashed with the image and booted into first-boot setup mode without a panic; the wizard walk-through on hardware and full `validate_all.py` are pending.

Per-integration recovery controls: ESP32-S3 build, five host command/operations
drivers, Telegram UI and 105 Chromium automation scenarios passed. Host tests
cover legacy inheritance, channel isolation, revocation and a failed permission
write with synthetic NVS. Real NVS upgrade and remote command checks are pending.

Health & Resources layout (post-3.0.15): 104 Chromium scenarios passed on
the generated Web UI with synthetic APIs, including 390 px placement,
independent saves and the per-device pause indicator. The settings-search
regression passed, including opening the collapsed guard controls. All language tables
pass `python tools/i18n_extract.py --check 100`. Hardware verification pending.

2026-10-29: [Performance/load exploration](PERFORMANCE-EXPLORATION-ROADMAP.md)
is active. Twelve harness host tests, actual RX ownership tests, real SDK pbuf
lifetime tests and existing authorization/SDK-forwarding targeted checks pass
on Windows. Six real 32 MB transfers passed hashes and preserved original
rule/lease/log settings, with no ESP reboot; INFO/WARN differences did not
justify a default change. The owning-pbuf RX prototype is not hardware-qualified.
Linux runner fixes and current sanitizer/build results are tracked in the
[performance checkpoint](CODEX-TO-CLAUDE-PERFORMANCE-CHECKPOINT.md); do not infer
their completion. Broader concurrent-load, remote/direct/DERP and uninterrupted
500 MB candidate gates remain pending. RAM tradeoffs require measured reserves.

The 3.0.6 update-transfer fix has separate actual-handler regression and
private transport evidence in `build/notification-ui/`. It does not replace
the released 3.0.5 qualification or imply a new physical install.

MQTT power-return work for firmware 3.0.5 has its own evidence under
`build/notification-ui/`. Preserve the qualified 3.0.4 image and separate actual
host/broker/HA/power-cycle outcomes; no new device result follows from unit tests.

The 3.0.4 ntfy wording increment has its own evidence under
`build/notification-ui/`; the published 3.0.3 image and its qualification
remain unchanged. Inspect that private checkpoint before device operations.

Detailed execution summaries, device captures, remaining test cases, resource
measurements and maintainer handovers are stored locally under ignored
`build/private-device/` and `build/validation-*/` directories. They are not
firmware downloads or public release notes. Preserve their original outcomes;
do not overwrite a failed run to make a later corrective rerun appear cleaner.

Public automated workflow logs are available in GitHub Actions. The supported
hardware and operational boundaries are documented in [Hardware](HARDWARE.md),
[Tailnet authorization](TAILNET-AUTHORIZATION.md) and the release instructions.

Maintainers follow [Quality policy](QUALITY-GATE.md), [Testing](TESTING.md),
the full [feature matrix](FEATURE-IMPLEMENTATION-MATRIX.md) and
[architecture decisions](ARCHITECTURE-DECISIONS.md). A source check, simulated
packet path, browser fixture and physical-device experiment are distinct kinds
of evidence and must never be presented as interchangeable.
