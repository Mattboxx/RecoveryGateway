# Connecting USB devices: modems, 4G sticks, Ethernet adapters, phones

From firmware 3.0.25 the gateway can use one USB device on the board's own
USB port: a USB LTE modem or 4G stick for the **Cellular uplink**, or a USB
Ethernet adapter or phone USB tethering for the **Ethernet uplink**. This page
explains which port to use, how to wire it and, above all, **how to power the
device**. Which devices are expected to work is listed in
[CELLULAR.md](CELLULAR.md#compatibility) and [ETHERNET.md](ETHERNET.md#usb-adapters-and-tethering).

> Tested: a TCL LinkKey IK41 4G USB stick (USB ID `1bbb:0195`, network mode) as the
> main Internet uplink, with Tailscale over mobile data. USB modems in serial
> mode, USB Ethernet adapters and tethering are not yet tested with real
> devices: report your board, cable and device (the card shows its `vendor:product`).

## 1. Which port

Most ESP32-S3 N8R8/N16R8 boards have **two USB-C connectors**:

| Label (varies) | What it is | Use it for |
|---|---|---|
| **COM**, UART, "CH343"/"CP2102" | a USB-serial chip wired to GPIO43/44 | flashing, logs, the browser installer, powering the board |
| **USB**, OTG, "ESP32-S3" | the chip's own USB (GPIO19/20) | **the USB device** |

When a USB connection is enabled, the firmware turns the **USB** port into a
USB *host* at boot, until the next restart. From then on, flash, read logs and
power the board through the **COM** port (or the 5V/GND pins). If you plug the
board into a computer through the USB port, the computer no longer sees it.

Order: save the setting (Network page or first-boot setup), restart, then plug
the device. Plugging it before or after the restart both work.

## 2. Connectors and adapters

The board's USB port is a USB-C socket that behaves as a *device* socket
electrically: it does not tell a phone or a USB-C device "I am a host".

- **USB-A devices (most 4G sticks, many Ethernet adapters):** use a short
  **USB-C (male) to USB-A (female) OTG adapter** on the board's USB port.
- **USB-C devices:** use the same OTG adapter plus the device's own USB-A to
  USB-C cable. A plain USB-C to USB-C cable usually does not work, because
  neither side offers to be the host.
- **Modem boards** (SIM7600/EC25 boards with a USB socket, mPCIe/M.2 modem
  carriers): connect their USB socket the same way, or wire D+, D−, GND and
  VBUS directly (see 4).
- **Phones:** OTG adapter plus the phone's usual charging cable; then turn on
  *USB tethering* on the phone.

**No USB hubs.** The firmware talks to exactly one device directly on the
port; a hub (powered or not) is not supported.

## 3. Power: the device needs 5 V on its USB connector

> **Get this right before plugging anything in.** A modem without enough
> current resets in a loop or restarts the gateway; two 5 V sources connected
> together can damage the board, the computer or the charger.

A USB device only starts when it sees 5 V on the VBUS pin of its connector.
**The board does not supply 5 V on its USB port by default**, so you must
provide it. How much current the device needs:

| Device | Typical current | Notes |
|---|---|---|
| USB Ethernet adapter | 150–350 mA | |
| Phone (USB tethering) | 0–500 mA or more | the phone may try to charge from the port |
| 4G stick (Huawei, ZTE, …) | 300–800 mA, peaks above 1 A | |
| LTE modem module (SIM7600, EC25, …) | **peaks up to 2 A** | during transmission bursts |

A computer's USB port gives 500–900 mA: **not enough for a modem or 4G stick**.
Too little current shows up as random modem resets, failed data calls or the
gateway restarting with reset reason `BROWNOUT` (System page).

Choose one of these solutions.

### A. Powered OTG Y-cable (recommended, no soldering)

An **OTG Y-cable** (also sold as "OTG cable with power", "USB-C OTG adapter
with charging port") has three ends: one to the board's USB port, one USB-A
socket for the device, and one power input for a USB charger.

```
5 V charger (≥ 2.5 A for a modem, ≥ 1 A otherwise)
        │ power input
        ▼
 ┌─ Y-cable ─┐── USB-C plug ──▶ board's USB port (data + 5 V)
 └───────────┘── USB-A socket ◀── modem / stick / adapter / phone cable
```

- The charger powers the device and, through the cable, usually the board too.
  **Tested** on an ESP32-S3-DevKitC-1 N16R8 with a TCL LinkKey IK41 stick: one
  charger on the power input runs both the board and the stick, with nothing
  connected to the COM port.
- Check the cable's description: it must pass **data** to the USB-C plug and
  **power** to the USB-A socket. Charge-only splitters do not work.
- Keep the COM port free or connected to a computer only for logs; both can be
  plugged at the same time.

### B. Separate supply for the device, data through the board

Modem boards and carrier boards often have their **own 5 V input** (DC jack,
screw terminals or a "5V/VIN" pin). Then:

- power the modem board from a **5 V supply able to deliver 2 A peaks**;
- connect its USB **D+, D− and GND** to the board's USB port (through an OTG
  adapter or a cut USB cable);
- make sure the modem's USB **VBUS sense** sees 5 V: on most boards the USB
  socket's VBUS must carry 5 V from the same supply, or the module never shows
  up on USB. Connect the supply's 5 V to VBUS on the device side;
- **always connect the grounds** of the supply, the modem and the ESP32 board.

### C. Bridge the board's "USB-OTG" pad (soldering)

Many N8R8/N16R8 boards (for example the common "YD-ESP32-S3" style) have a
solder jumper labelled **USB-OTG** (sometimes next to an **IN-OUT** jumper).
Bridging **USB-OTG** connects the board's 5 V rail to VBUS of the USB port, so
the board itself feeds the device.

Only do this if all of the following hold:

- your board's documentation or schematic says that the pad connects 5 V to
  the USB port's VBUS (labels and meanings differ between makers);
- the board is powered from a **5 V supply strong enough for board and device**
  together, through the 5V pin or the COM port with a charger: a computer's
  USB port on COM is enough for an Ethernet adapter, **not for a modem or 4G
  stick**;
- you will **never connect the board's USB port to a computer or a charger
  while the pad is bridged**: two 5 V sources would push current into each
  other. Remove the bridge before using that port with a computer again.

The **IN-OUT** jumper, where present, changes how the 5 V pin and the USB
sockets share power; leave it as it is unless the board's documentation says
otherwise.

### Not recommended

- Powering an LTE modem from the board's **3.3 V** pin: never.
- A **powered USB hub** to inject power: hubs are not supported.
- Long, thin USB cables for modems: they drop voltage at 2 A; keep the modem
  cable short.

## Wi-Fi while a USB connection is on

The USB port's transfers must use the chip's **internal RAM** (the ESP32-S3
USB controller cannot reach PSRAM), the same RAM where the Wi-Fi keeps its
receive buffers. So, **only while the Cellular or Ethernet uplink is set to the
USB port**, the gateway starts its Wi-Fi with **16 receive buffers instead of
24**. That frees about 12.8 KB of internal RAM for the USB device. The System
page and `/api/status` show it as `wifi_rx_lean_for_usb: true`.

What it can change:

- **Bursts of incoming Wi-Fi traffic** fill 16 buffers sooner. When they are
  full, further frames are dropped and TCP has to resend them: a short drop in
  speed, slightly higher latency peaks.
- It shows most with **speed tests or large uploads from phones or laptops
  connected to the gateway's own access point**, with several devices sending
  at once on that access point, and with a weak Wi-Fi signal (more resent
  frames).
- Ordinary use (Web UI, MQTT, notifications, Tailnet, ping) was unchanged in
  the measurements on a fully configured gateway.
- Over USB the uplink itself is limited to about 10 Mbit/s (USB full speed), so
  on a USB uplink the Wi-Fi buffers are rarely the narrowest point.

With the pins (W5500, UART modem), or with both uplinks off, the Wi-Fi keeps
24 buffers exactly as before. Setting the uplink back to the pins and
restarting restores them.

## Suggested devices for a first test

These match the firmware's tables and are easy to find. They are suggestions
for testing, not tested results yet:

| Use | Device | Why |
|---|---|---|
| Ethernet over USB | **TP-Link UE300** or another USB-A adapter with a **Realtek RTL8153** chip | its standard CDC-ECM configuration is selected automatically |
| Ethernet over USB, also for a computer | a **USB-C 2.5 Gbit/s** adapter with a **Realtek RTL8156BG** chip (for example Cudy UE25C), plus a passive **USB-A (male) to USB-C (female)** adapter for the Y-cable | 2.5 Gbit/s on a computer; on the gateway about 10 Mbit/s. Whether a USB 3 adapter works on the full-speed port is part of the test |
| Mobile network, 4G stick | **Huawei E3372h-320** (HiLink) | starts as a CD-ROM, is switched to network mode automatically, then connects by itself |
| Mobile network, AT modem | **SIMCom SIM7600E-H / SIM7600G-H USB dongle** | uses the gateway's AT/PPP path with SIM PIN and APN |
| Power | **USB-C OTG Y-cable with a power input** and a **5 V 3 A charger** | the board does not supply 5 V on its USB port |

Avoid adapters with **ASIX AX88179/AX88772** or **Microchip LAN78xx** chips and
modems that offer only MBIM or QMI. Listings often hide the chip: look for
"RTL8153" in the description.

## 4. Wiring a bare module directly (advanced)

For a modem module without a USB socket, wire its USB pins to a USB-A socket
or to the board's USB data lines:

| ESP32-S3 | Module |
|---|---|
| GPIO20 (USB D+) | USB_DP |
| GPIO19 (USB D−) | USB_DM |
| GND | GND |
| — (5 V supply) | USB_VBUS (sense) and the module's own supply input |

Keep D+/D− short and twisted together. Many modules run their USB at their own
I/O voltage; the ESP32-S3 USB is a standard USB 2.0 full-speed port and needs
no level shifter on D+/D−.

## 5. Setting it up

1. **Network → Cellular uplink** (modem or 4G stick) or **Network → Ethernet
   uplink** (adapter or phone): choose *USB port* under *How … is connected*,
   enable it and save. First-boot setup asks the same question.
2. Restart the gateway.
3. Plug the device as above. The card shows the device (`vendor:product`) and
   what the gateway is doing with it: the serial interface in use, the USB
   network type (RNDIS, CDC-ECM, CDC-NCM), a mode switch of a stick that started
   as a CD-ROM, or the reason it cannot be used.
4. Only one of the two uplinks can use the USB port at a time.

To go back to the pins (or to use the USB port with a computer again), choose
the pins option, save and restart.

## 6. Troubleshooting

| What you see | Try |
|---|---|
| "No USB device on the USB port" | the device has no 5 V (see 3), it is on the COM port, or a charge-only cable/adapter is in the way |
| The device appears, disappears, appears | not enough current: use a stronger supply, a shorter cable or solution B |
| Gateway restarts, reset reason BROWNOUT | the modem is drawing from the board's supply: power it separately (A or B) |
| "stays in storage mode" | the stick needs a switch this firmware does not know: switch it once to modem mode on a computer (its maker's tool or usb_modeswitch) and report its `vendor:product` |
| "not supported (vendor-only chip …)" | that Ethernet adapter uses a vendor protocol (ASIX, Microchip): use an RTL8152/RTL8153 or CDC-ECM/NCM adapter |
| A phone is not seen | use an OTG adapter, enable USB tethering after plugging, unlock the phone |
| About 10 Mbit/s at most | expected: the ESP32-S3 USB port is full speed (12 Mbit/s) |
| Wi-Fi speed tests through the access point slower than before | expected while USB is on: fewer Wi-Fi receive buffers (see *Wi-Fi while a USB connection is on*) |
| The stick uses the same addresses as the home network (e.g. 192.168.1.x on both) | handled from 3.0.29: home addresses go through Wi-Fi/Ethernet. While the stick carries the Internet traffic, its gateway address (often .1) means the stick, so a home device with that same address is unreachable then; change the stick's or the router's range if you can |
