# Validation records

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
