# Ethernet uplink (optional: W5500 over SPI, or USB)

Most ESP32-S3 boards, including the N8R8 and N16R8 boards this firmware
targets, have **no Ethernet**. Two ways to add it:

- an explicitly wired **W5500 SPI module** (the driver is in the standard
  image from 3.0);
- from 3.0.25, a **USB Ethernet adapter or phone USB tethering** on the
  board's native USB port; see [USB adapters and tethering](#usb-adapters-and-tethering).

Both are implemented and host-tested, but **not physically validated** on the
current candidate.

## Builds

| Build | Ethernet | Notes |
|---|---|---|
| `esp32-s3` (3.x, releases) | W5500 driver compiled, OFF until configured | One image for every board and language |
| 2.x `esp32-s3-eth` (historical) | W5500 driver compiled | Separate English-only image of the 2.x line |

## Boards with built-in Ethernet

An ESP32-S3 board with a built-in W5500 and a PoE module needs no wiring:
enter its W5500 pins (from the board's documentation) under Network →
Ethernet. It must have 8 MB octal PSRAM (R8) and at least 8 MB of flash. Not
yet validated on real hardware. The one considered for this project:
[Amazon link](https://link.amazon/B02rb02fJ) (*affiliate link: buying through it supports
the project at no extra cost to you. As an Amazon Associate I earn from qualifying purchases.*)

## Wiring and settings

Network → **Ethernet uplink**, *Connection*: *W5500 module on SPI pins* or
*USB adapter or phone tethering*. For the W5500: SPI host (SPI2/SPI3), SPI clock (1–40 MHz),
SCLK/MOSI/MISO/CS, INT (or -1 to poll every 10 ms) and RST (or -1). Pins
reserved on N8R8/N16R8 boards are refused: GPIO0/3/45/46 (straps), 19/20 (USB),
26–37 (flash/octal PSRAM), 38–40 (microSD log), 43/44 (console UART). Use
DHCP or a static IPv4 address, mask, gateway and optional DNS. Settings are
validated, saved and **applied after a restart**; an invalid or damaged saved
record means "Ethernet off".

## USB adapters and tethering

Nothing USB-related is installed while Ethernet is off or set to SPI. With the
USB connection the adapter becomes the standard Ethernet interface: the same
preference, static or DHCP address, firewall hooks, LAN listeners and status
as the W5500. The cellular uplink and the Ethernet uplink cannot both use the
USB port.

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

Supported device classes: **CDC-ECM**, **CDC-NCM** and **RNDIS**. A device
whose first USB configuration is vendor-specific is re-enumerated with its next
configuration (bounded); this is how Realtek RTL8152/RTL8153 adapters normally
reach their standard ECM configuration. The cable state comes from the
adapter's CDC notifications when it sends them.

| Device | Expectation |
|---|---|
| Realtek RTL8152/RTL8153/RTL8156 adapters, and USB-C hubs built on them | expected through their ECM/NCM configuration, not verified |
| Adapters and docks that enumerate as CDC-ECM or CDC-NCM | expected, not verified |
| Android USB tethering (RNDIS; NCM on some recent phones) | likely, not verified; the phone needs 5 V on the port to see a host |
| 4G sticks in RNDIS/ECM mode used as a LAN | possible; the cellular card is the intended place |
| ASIX AX88179/AX88772, Microchip LAN78xx/LAN95xx (vendor-only protocols) | not supported (status says so) |
| iPhone USB tethering (Apple protocol) | not supported |

## Uplink preference

- **WiFi first** (default): Ethernet is used only while WiFi has no address.
- **Ethernet first**: Ethernet becomes the uplink after it has been up with an
  address for three consecutive route-supervisor checks; losing it falls back
  to WiFi immediately.

The selected uplink carries the default route, so Tailscale control/DERP and
WireGuard traffic and AP-client NAT follow it; in exit-node mode the tunnel is
pinned to the selected uplink. With Ethernet disabled the route logic is
exactly the previous WiFi behavior.

## Security

The Ethernet interface gets the same ESP-bound firewall chains as WiFi
(`to_esp`/`from_esp`). The driver is installed first and **started only after
those hooks are in place**; if they cannot be installed, Ethernet stays
stopped and reports why. Administration rules (password, Host/Origin
screening) are unchanged.

## Local services and validation

- Only W5500. DM9051/KSZ8851SNL drivers exist in ESP-IDF but are not wired.
- LAN → Tailnet rules (and AP-side port forwards) listen on the **selected**
  uplink: the Ethernet address while Ethernet is the uplink, otherwise WiFi.
  Bindings are reinstalled when the selection changes, so clients must use the
  address of the current LAN uplink. Wake-on-LAN's automatic broadcast and
  the local `.local` name also follow that interface.
- Tailscale starts when the Internet uplink has an IPv4 address. Health
  checks, remote update checks, and DNS forwarding use the Internet uplink.
  The access point can stay enabled while the cable carries Internet traffic.
- SNMP exposes the Ethernet, WiFi and tunnel interfaces separately.
- DNS servers are global in lwIP: the last interface to obtain DHCP DNS wins.
- No measurements of throughput, link-flap behavior or power on real hardware.
- A W5500 is saved as before, so an older firmware keeps using it after a
  downgrade. A USB setting is saved in a new format that older firmware
  ignores: there Ethernet stays off.
- First-boot setup asks the same question (*W5500 module wired to the pins* or
  *USB Ethernet adapter or phone*).
