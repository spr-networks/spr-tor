# spr-tor

A [Tor](https://www.torproject.org/) client plugin for [SPR](https://github.com/spr-networks/super)
(Secure Programmable Router). It runs the `tor` daemon as an **outbound-only client** in an
isolated container and exposes a SOCKS5 proxy — plus optional transparent-proxy and
DNS-over-Tor ports — to SPR devices, gated by SPR's microsegmentation.

Wishlist item from [spr-networks/super#341](https://github.com/spr-networks/super/issues/341).

## About

The plugin container sits on its own docker bridge network (`spr-tor`). The Tor SOCKS port is
bound to the container's IP on that bridge — never to the host — so only devices that SPR's
firewall explicitly allows (the `tor` group) can reach it. The plugin's Go backend supervises
the tor daemon, generates a hardened `torrc` from a validated JSON config, and talks to tor
over its control channel (unix socket + cookie auth) to report status, list circuits, and
request new identities.

The UI is embedded in the SPR interface under Plugins (iframe): a status card with bootstrap
progress and circuit state, a config form, a circuits list, and a New Identity button.

## Features

- Tor SOCKS5 proxy for SPR devices in the `tor` group (container-IP:9050)
- Optional transparent proxy port (9040) and DNS-over-Tor port (9053), off by default,
  for routing devices/groups through Tor
- Exit-relay country selection (`ExitNodes {cc}` + `StrictNodes`)
- Bridge support: vanilla and obfs4 bridges (obfs4proxy included), strictly format-validated
- New Identity (NEWNYM) button and circuit list in the UI
- Contributes to SPR's topology view (`HasTopology`): built circuits are shown as relay
  chains (guard → middle → exit) hanging off the router node
- Client-only hardening baked in: no relay, no exit, no ORPort/DirPort, control channel on a
  unix socket with cookie auth only (no TCP ControlPort)

## UI Setup

1. In the SPR UI, under Plugins, choose `+ New Plugin` and add
   `https://github.com/spr-networks/spr-tor`.
2. After installation, open **spr-tor** at the bottom of the left-hand menu.
3. Add SPR devices to the `tor` group to let them reach the proxy ports.
4. Point apps at the SOCKS5 proxy shown on the status card (e.g. `172.x.y.z:9050`).

## Command Line Setup

```bash
cd /home/spr/super/plugins/
git clone https://github.com/spr-networks/spr-tor
cd spr-tor
./install.sh   # prompts for the SUPER directory and an SPR API token
```

The script writes the plugin config, builds and starts the container, and registers the
`spr-tor` bridge interface with the SPR firewall (policies `wan`, `dns`; group `tor`).

## API

All endpoints are served over the plugin's unix socket and proxied by the SPR API at
`/plugins/spr-tor/...` (authenticated by SPR).

| Method | Path        | Description                                                       |
| ------ | ----------- | ----------------------------------------------------------------- |
| GET    | `/status`   | Daemon state: bootstrap %, version, circuit established, traffic, bound ports |
| GET    | `/config`   | Current plugin configuration                                      |
| PUT    | `/config`   | Validate + save configuration, regenerate torrc, reload tor       |
| POST   | `/newnym`   | Signal NEWNYM (new identity / fresh circuits)                     |
| GET    | `/circuits` | Open circuits: id, status, relay path, purpose, created time      |
| GET    | `/topology` | Live circuit graph (`{Nodes, Edges}`) for SPR's topology view: a root anchor plus a `root → guard → middle → exit` relay chain per built circuit; root-only when tor is down |

## Configuration reference

`/configs/plugins/spr-tor/config.json` (edit via the UI or `PUT /config` — the file is
regenerated with validated values):

| Field              | Type     | Default | Meaning                                                       |
| ------------------ | -------- | ------- | ------------------------------------------------------------- |
| `TransPortEnabled` | bool     | false   | Open `TransPort <container-ip>:9040` (transparent proxying)   |
| `DNSPortEnabled`   | bool     | false   | Open `DNSPort <container-ip>:9053` (DNS through Tor)          |
| `ExitCountry`      | string   | ""      | 2-letter country code; emits `ExitNodes {cc}` + `StrictNodes 1` (with `StrictNodes`, no exits in that country means no exit circuits) |
| `UseBridges`       | bool     | false   | Enable the bridge lines below                                 |
| `Bridges`          | []string | []      | Bridge lines: `ip:port [fingerprint]` or `obfs4 ip:port fingerprint cert=… iat-mode=N` |
| `SocksPolicy`      | []string | []      | `accept`/`reject` entries (`*`, IP, or CIDR) for the SocksPort |
| `SafeSocks`        | bool     | false   | Reject SOCKS requests that resolve DNS locally (prevents DNS leaks from misconfigured apps, but breaks clients that connect by hostname-resolved IP — off by default) |

The backend generates the entire `torrc` from these validated fields; arbitrary torrc lines
cannot be injected. Bridge lines only allow IP-literal addresses, 40-hex fingerprints and
allow-listed `k=v` transport arguments (transports: `obfs4`).

## Security model

- **No published host ports.** `ports:` is absent; the only host-facing endpoint is the
  plugin unix socket `/state/plugins/spr-tor/socket`, which SPR proxies and authenticates.
- **Proxy ports bind to the container IP** on the plugin's dedicated bridge (`spr-tor`).
  Reachability is granted through SPR policies/groups: devices must be in the `tor` group.
- **Client only.** The generated torrc pins `ClientOnly 1`, `ORPort 0`, `DirPort 0`,
  `ExitRelay 0` — the container never relays or exits traffic for the Tor network, it only
  makes outbound connections (`wan` + `dns` policies).
- **Control channel** is `ControlSocket` (unix) with `CookieAuthentication 1`, `ControlPort 0`
  (never TCP). Socket and cookie live in `/run/tor` inside the container, not on a host mount.
- **No extra privileges.** No `cap_add`, no devices, no tun, `no-new-privileges:true`;
  tor itself drops from root to the `debian-tor` user at startup (torrc `User`).
- **Mounts** are the minimal SPR plugin set: plugin state (rw), plugin config (rw),
  `configs/base/config.sh` (ro). The backend does not call the SPR API in this version
  (`ScopedPaths` omitted).
- The UI runs inside the SPR app and calls only the plugin's own endpoints; there are no
  external CDN/fonts/scripts and no "check my IP" callouts (offline-safe).

## Upstream

- [Tor](https://www.torproject.org/) — BSD-3-Clause. Installed as the Ubuntu 24.04 (noble)
  `tor` package, version **0.4.8.10-1build2**, plus `tor-geoipdb` 0.4.8.10-1build2 (country
  selection) and `obfs4proxy` 0.0.14-1build1 (obfs4 bridges), all from the pinned Ubuntu
  snapshot archive for reproducibility.
- This plugin is MIT licensed (see LICENSE).

## Reproducible builds

All build inputs are pinned in `reproducible.env` (base image digests, Go toolchain version +
sha256, Ubuntu snapshot timestamp, tor/obfs4proxy package versions). Build with:

```bash
./build_docker_compose.sh
```

which resolves pins, normalizes timestamps (`SOURCE_DATE_EPOCH=0`, `rewrite-timestamp=true`)
and builds via buildx for bit-for-bit reproducible images. Refresh pins with
`./update-pins.sh` (re-resolves image digests, the latest Go 1.25.x + checksums from go.dev,
and the tor/obfs4proxy versions from the pinned snapshot) and review with `git diff`.
