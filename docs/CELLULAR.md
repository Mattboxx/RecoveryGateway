# Cellular uplink (GSM/LTE with a SIM)

Firmware 3.0 can use an external cellular modem as its Internet uplink: as the
main uplink, or only while WiFi and Ethernet are down (failover). The modem
can be **wired to UART pins** or, from 3.0.25, **plugged into the board's
native USB port** (USB LTE modems and 4G sticks); see [USB modems and
sticks](#usb-modems-and-sticks). It is **off
by default**, never dials until you enable it and acknowledge the data-use
notice, and it has **not yet been validated with a real modem**. Report what
works and what does not with your modem model.

## What you need

- An ESP32-S3 N8R8 or N16R8 running firmware 3.0 or later.
- A modem with a UART AT interface and PPP data calls, for example SIMCom
  SIM7600/SIM7670/A7670 or Quectel EC2x/EG91 boards. Modems without PPP
  (AT-socket-only) are not supported.
- A data SIM and its **APN** (from your operator, for example `internet`).
- A power supply for the modem able to deliver **2 A peaks** at its own
  voltage. Never power an LTE modem from the ESP32's 3.3 V pin.
- Logic levels that match: the ESP32-S3 uses 3.3 V. Many modem boards have a
  level shifter; bare modules running at 1.8 V need one.

## Wiring (UART)

| ESP32-S3 | Modem |
|---|---|
| TX GPIO (default 17) | RXD |
| RX GPIO (default 18) | TXD |
| GND | GND (common ground is required) |
| PWRKEY GPIO (optional) | PWRKEY, directly or through the board's transistor |
| RTS / CTS GPIO (optional, both or none) | CTS / RTS |

Usable pins on N8R8/N16R8: 1, 2, 4–18, 21, 41, 42, 47, 48. The firmware refuses
flash/PSRAM, USB, console, strapping and microSD pins, and any pin already used
by an enabled Ethernet module.

## Settings (Network → Cellular uplink)

- **I understand that mobile data may cost money** — required to enable.
- **Use**: *Only when WiFi and Ethernet are down* (failover) or *As the main
  Internet uplink*. LAN services (the LAN → Tailnet service gateway, health
  checks of the home network) stay on WiFi or Ethernet.
- **Allow roaming** — off by default: on a foreign network the modem waits.
- **APN**, optional **user name** and **password** (sent with PPP PAP).
- **SIM PIN** — optional. It is sent **once per start**: a wrong PIN stops the
  modem with a message instead of retrying towards a PUK lock. The password and
  PIN are write-only: the page shows only that they are saved.
- **UART**, **baud rate** (115200 for most modems), **TX/RX** pins, optional
  **RTS/CTS** and **PWRKEY** (pulsed at start and when the modem stops
  answering AT; *active high* for boards with a transistor driver).

Settings apply after a restart.

## USB modems and sticks

Choose **Connection → USB port** on the Cellular card. Nothing USB-related is
installed while the cellular uplink is off or set to UART: no USB host stack,
task or memory, and the native USB port keeps working as USB-Serial-JTAG.

### The board's USB ports

ESP32-S3 N8R8/N16R8 development boards usually have two USB-C connectors:

- **COM / UART** (through a USB-serial chip to GPIO43/44): flashing, the
  console and the browser installer. It is not affected by this feature.
- **USB** (the chip's own USB on GPIO19/20): normally USB-Serial-JTAG. When a
  USB connection is enabled, the firmware turns this port into a **USB host**
  at boot and keeps it that way until the next restart. Flash and read logs
  over the COM port while a USB device is in use.

The ESP32-S3 USB host is **full speed (12 Mbit/s)**: expect about 10 Mbit/s
at most through any USB device. There is **one device at a time and no USB
hub support**. Unplugging and plugging back is handled (the device is detected
again and the connection restarts), but it is **not qualified on hardware**:
restart the gateway if a device does not come back.

**Power:** the board does not supply 5 V on its USB port by default. The
device needs 5 V on its USB connector: a powered OTG Y-cable, a separate
supply for the device, or the board's "USB-OTG" solder pad with a strong
enough supply. **[USB devices](USB-DEVICES.md)** explains ports, adapters,
cables and each power option step by step.

**LTE modems draw up to 2 A in bursts.** Never feed one from the board's 3.3 V
or 5 V pins; brownouts reset the gateway (the reset reason shows `BROWNOUT`).

### How the device is handled

When a USB device appears, the gateway reads its descriptors and decides:

1. **Serial AT port → PPP** (preferred in automatic mode, because the gateway
   then controls the SIM PIN, APN, registration and signal). The AT/modem
   interface is chosen from a table of known modules, then any standard
   CDC-ACM interface, then the vendor serial interfaces in a likely order;
   each candidate must answer `AT` (at most 6 candidates, 3 s each). The
   *USB interface* setting (advanced) forces one interface number.
2. **USB network (RNDIS, CDC-ECM or CDC-NCM)**, for sticks without an AT port
   (for example "HiLink" sticks). The stick dials by itself: set its APN and
   PIN in the stick (its own web page or phone app) and the gateway gets an
   address from it by DHCP. Signal, operator and SIM state are not available
   in this mode.
3. **CD-ROM / storage mode** (many sticks start like this): the gateway sends
   the USB mode-switch message for that stick, at most once per boot, and
   waits for it to come back as a modem. Messages come from the
   [usb_modeswitch](https://www.draisberghof.de/usb_modeswitch/) reference
   data; sticks not in the table get Huawei's switch (Huawei) or a standard
   SCSI eject (others).
4. **Another USB configuration**, when the first one offers nothing usable
   (bounded to four configurations).

*USB mode* forces serial or network. With USB the APN may stay empty: the
modem's own default context (or the stick's settings) is used.

### Compatibility

Tested with real hardware: a **TCL LinkKey IK41 4G USB stick** (`1bbb:0195`, USB
network mode) as the main Internet uplink. Nothing else below has been tested
with real hardware yet. "Expected" means the
device exposes interfaces this firmware drives; firmware variants of the same
model can differ.

| Group | Examples | Path | Expectation |
|---|---|---|---|
| Known serial layouts | SIMCom SIM7600 series (1e0e:9001); Quectel EC25/EG25-G, EC21, EG91/EG95, BG96 (2c7c:0125/0121/0195/0296) | AT + PPP on the modem port | expected |
| CDC-ACM modems | Many Cat-1/Cat-4 modules that enumerate as standard CDC-ACM (for example Air780E/Air724 in their ACM mode, u-blox and Telit modules set to ACM) | AT + PPP | expected |
| Other vendor serial ports | SIMCom A7670/A7600/SIM7070/SIM7080, Quectel EC200/EG800, Fibocom, Neoway, MeiG modules | AT probe on vendor ports | likely, not verified |
| RNDIS / ECM / NCM sticks | Huawei E3372h/E8372h HiLink, ZTE MF79U/MF833-type sticks, Alcatel Link Key, generic "4G UFI" RNDIS sticks | DHCP over USB network | likely, not verified |
| Sticks starting as CD-ROM | Huawei E353/E352/E173s and newer Huawei (12d1:1f01/14fe/1446), ZTE MF668/MF70/MF820/MF710M, Alcatel X200/L100V/OT-X220D, Qualcomm-based 05c6:f000, SpeedUp SU-8000, Longcheer | mode switch, then one of the paths above | reference messages; others get a generic switch |
| Not supported | MBIM- or QMI-only modems without an AT port, modems needing an unknown vendor switch, USB hubs | — | reported in the status |

## Status

The card shows the modem state (starting, SIM, looking for the network, data
call, connected), operator, signal in dBm, the cellular IP address, whether it
carries the Internet traffic now and the data used since boot. After a failure
it retries after 30 s, doubling up to 10 minutes. A SIM that needs a PIN or is
PUK-locked stops until you fix it and restart.

With USB the status also shows the USB device (vendor:product), whether a
serial interface (and how it was chosen) or a USB network function (RNDIS,
CDC-ECM, CDC-NCM) is in use, mode switches this boot and dropped data, with a
reason when nothing usable is found.

## Monthly data limit

Under the cellular settings, **Monthly data limit** counts mobile data in both
directions (most carriers count both), for a UART or USB modem and for a USB
network stick.

- **Monthly limit (MB)**: 0 turns the counter off (the default). While off,
  nothing is counted, stored or written to flash.
- **Warn at (%)**: one warning in the event history and through the
  notification channels when that share is used; 0 warns only at the limit.
  The limit itself is reported once per month.
- **The month starts on day**: 1 to 28, the day the carrier's month restarts.
  The counter restarts then; this needs the clock (SNTP). Until the clock is
  set, use is added to the last known month.
- **Stop using mobile data when the limit is reached**: the modem stays
  connected but carries no traffic until the next month; Wi-Fi or Ethernet,
  when present, keep working. Off by default.
- Usage is saved at warnings and period changes. A regular checkpoint needs
  at least 1 MiB of new data and 10 minutes since the last successful write.
  A power cut can lose the usage since that checkpoint, which can exceed
  1 MiB. Carrier counters may include different overhead. **Reset the counter**
  starts the month over.

## Security and costs

- Cellular PPP provides Internet and Tailnet transport. On cellular-only
  setups the access point provides local administration and the existing
  AP-to-Tailnet gateway. With a physical LAN connected, LAN-to-Tailnet rules
  continue to listen on its Ethernet or WiFi address.
- The modem address is never used as a LAN-to-Tailnet listener or LAN DNS
  listener. Operator firewall and local access policies apply as usual.

- The ESP-bound firewall lists (ACL *to ESP* / *from ESP*) apply to the
  cellular link too, including a USB network stick; the link does not start
  if those hooks cannot be installed.
- Data from a USB device is parsed with bounded checks (descriptors, RNDIS and
  NCM framing); malformed input is dropped, never trusted. A device that stops
  answering ends the USB session until restart instead of leaking memory on
  every retry.
- Tailscale over mobile networks usually runs through DERP relays because of
  carrier NAT: it works, with higher latency.
- A UART modem is saved as before, so an older firmware keeps using it after
  a downgrade. A USB setting is saved in a new format that older firmware
  ignores: there the cellular uplink stays off.
- First-boot setup asks the same question (*Modem wired to the pins* or *USB
  modem or 4G stick*); over USB the APN may stay empty.
- Everything that uses the Internet uses mobile data while cellular carries the
  traffic: Tailscale, GitHub update checks, MQTT/ntfy, and Internet traffic of
  access-point clients. Use failover mode on limited plans.
