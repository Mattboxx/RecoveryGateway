# ntfy and Telegram commands

Optional push notifications and a few commands through an
[ntfy](https://ntfy.sh) server (public or self-hosted). Technical transport
notes are in [NTFY-TRANSPORT.md](NTFY-TRANSPORT.md).

## Setup

Automation → **ntfy**: server URL, topic and, recommended, an access token.
**Send test** confirms delivery to the server only.

## Messages (each opt-in)

- Tailscale stays disconnected while the uplink works (after the delay).
- System events: gateway started (firmware, reset reason), Tailscale restored
  after a delivered alert, firmware update available (never installed).
- Health Monitor check down after repeated failures.
- Smart Recovery results; temporary service access closed; Service watch
  "no TCP answer" and recovery.

## Commands

Enable commands under **Automation** for each channel you use. Send a plain
topic message in ntfy or a message to your configured Telegram bot. Both accept
a leading slash. In a private Telegram chat, `/help` also opens a compact
keyboard with shortcuts allowed by the channel settings.

**Allowed commands → Disabled** ignores all incoming commands for that
channel, including `help`, and revokes scheduled work and pending replies
from those commands. Automatic alerts use their own settings. After
re-enabling commands, allow the first poll to establish a fresh cursor before
sending a command. Telegram skips the cached backlog. With a cleared
cursor, ntfy uses the server's [latest-message request](https://docs.ntfy.sh/subscribe/api/#fetch-latest-message)
to establish the starting point without dispatching cached commands.
Older servers can return cached messages in multiple batches. The gateway
advances through those batches before accepting new commands.

| Message | Effect |
|---|---|
| `help` / `start` | Show commands available for this channel |
| `devices` | List saved devices with their last known check results |
| `info` / `status` | Show gateway status if enabled. Private network details follow the channel setting |
| `wol <saved device name or MAC>` | WoL to a saved device (direct MAC only if allowed) |
| `recover <name>` / `check <name>` | Smart Recovery / check, when Remote commands is set to *Info, Wake-on-LAN and verified recovery* |
| `checks` / `probe <name>` | List past TCP results or run a saved TCP check. Requires verified recovery |

Set a verification address, answering TCP port and timeout (5–600 seconds) in
the device profile. Use `recover NAME` for a verified wake and `check NAME`
for a reachability check without waking the device. The acknowledgement
confirms the job was accepted. Its result goes to the chat or topic that
requested it. The device notification setting controls scheduled outage alerts
and notifications for manual checks started from the web UI. The
Tailscale-down-only switch pauses command polling while Tailscale is connected.
Standalone setups accept enabled commands with either switch setting. The
gateway still needs network access to its notification provider and local device.

For ntfy use an access-controlled topic with write access restricted to you.
For Telegram use your numeric user ID and a private bot chat. A numeric group
chat ID authorizes the configured group, including other members who can
send messages there. Telegram skips the existing backlog on the first poll
after a restart. ntfy persists its cursor across a restart when command
permissions and the destination stay the same.
