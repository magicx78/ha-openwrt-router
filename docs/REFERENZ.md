# OpenWrt Router – Technische Referenz

> Diese Seite bewahrt die ausführliche Dokumentation der bisherigen README. Sie entspricht dem Stand zum Zeitpunkt der Umgestaltung und wird möglicherweise nicht laufend aktualisiert. Für aktuelle Informationen siehe [README](../README.md), [TODO](../TODO.md) und [Changelog](../CHANGELOG.md).

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/github/v/release/magicx78/ha-openwrt-router?label=version&color=blue)](https://github.com/magicx78/ha-openwrt-router/releases/latest)
[![Tests](https://img.shields.io/github/actions/workflow/status/magicx78/ha-openwrt-router/tests.yaml?branch=main&label=tests)](https://github.com/magicx78/ha-openwrt-router/actions/workflows/tests.yaml)

A Home Assistant custom integration in active development for [OpenWrt](https://openwrt.org/) routers, communicating via the built-in **ubus / rpcd JSON-RPC API**. Supports multi-AP mesh networks with a live topology panel.

---

## Installation

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=magicx78&repository=ha-openwrt-router&category=integration)

**Via HACS (Recommended)**
1. Click the button above — or open HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/magicx78/ha-openwrt-router` as **Integration**
3. Search for and install **OpenWrt Router**
4. Restart Home Assistant

**Manual**
1. Copy `custom_components/openwrt_router/` into your HA config directory
2. Restart Home Assistant

---

## Topology Panel

A built-in network map panel is automatically registered when the integration is set up. It shows your entire mesh network — gateway, APs, wired uplinks, WiFi backhaul, and all connected clients — in a live, interactive view.

The panel and its snapshot API contain DHCP leases, ARP/switch tables, the WAN IP and DDNS details, so they are **available to administrators only** by default (other users get HTTP 403 from the API). To show the panel to every Home Assistant user, enable **“Show topology panel to all users”** in the integration options (**Configure**). There is one panel for all routers: it is open to all users as soon as one loaded router entry has the option enabled. Changes apply immediately, without a restart. This restriction covers only the topology panel and its snapshot API: entity states (for example device trackers with IP and hostname, or sensors) stay visible to all Home Assistant users, as usual in Home Assistant.

### Sidebar views

| Tab | Description |
|-----|-------------|
| **Topology** | Zoom/pan network map with animated edges, traffic overlay, and focus mode |
| **Devices** | Gateway + APs as list rows — status, uplink type, backhaul signal, client count |
| **Clients** | All WiFi clients with search (name / IP / MAC / vendor), band filter, status filter |
| **Alarms** | Only offline or warning devices and clients, grouped |
| **Diagnose** | Network Intelligence: overview, incidents, timeline, Wi-Fi, infrastructure, settings — see [Network Intelligence](#network-intelligence) |
| **Settings** | HA links, polling interval, GitHub link, about |

### Topology interactions

| Action | Result |
|--------|--------|
| **Click** node | Select — dim others, open Inspector panel on the right |
| **Double-click** node | Zoom to 2× centered on node; double-click again to reset |
| **Right-click** node | Context menu: Focus, Zoom, Clients, VLAN-Overlay, Alerts |
| **Hover** node | Quick-info tooltip — IP, uptime, CPU/RAM, firmware, SSIDs, VLANs |
| **Hover** edge | Link type, signal strength, WAN traffic |
| **Hover** port chip | Link speed, VLANs, and the devices mapped to that port (with confidence) |
| **Click** port chip / port device dot | Port detail panel — devices with name, MAC, clickable `http://<ip>` link, mapping source + confidence |
| **Click** AP client count | Inline client list with signal bars and band |
| **Minimap** (bottom-right) | Click to pan canvas; shows all nodes as coloured dots |

### Topology modes (toolbar)

| Toggle | Description |
|--------|-------------|
| ♥ Health | Colour nodes by CPU / RAM / signal — green → amber → red |
| ≋ Heatmap | Signal-strength glow on each AP |
| 👻 Ghost | Show recently-offline devices greyed out |
| VLAN | Highlight edges and nodes by VLAN subnet membership |
| Traffic | Animated flow arrows on links |
| **Group** selector | Organise APs into visual groups: by type, VLAN, or online status |

### Inspector panel (right sidebar)

Opens when a node is clicked. Shows:
- **Gateway**: model, firmware, LAN/WAN IP, uptime, ping, CPU/RAM bars + 1 h chart, WAN traffic bars, SSIDs, ports, VLANs, DDNS status, event timeline
- **Access Point**: model, firmware, IP, uplink type + backhaul signal, CPU/RAM bars, SSIDs, client list, event timeline
- **Client**: name, hostname, IP, MAC, vendor, model, band, signal, connected since, DHCP expiry, session traffic, HA device-tracker link

### Footer and client names

The bar below the map (its layout follows the panel width, so it adapts when HA's sidebar is expanded) shows the network status, the **WAN traffic** of the gateway in bit/s (averaged between two router polls; the averaging window and the sample time are shown underneath), the **top talkers** by bytes since they joined their access point (click one to select it on the map) and the clients by band.

Clients are named everywhere in the panel by the best source available: a name you gave the device or its tracker in Home Assistant, the name another integration registered for the MAC (ESPHome, Shelly, …), the DHCP hostname, the manufacturer plus the end of the MAC, or "Privat-MAC …" for a randomised address.

The **Internet** node takes the colour of the Internet latency Home Assistant measures (a TCP connect to 8.8.8.8:53 from the HA host: green < 50 ms, amber < 100 ms, orange above, red when it fails) and pulses while the Internet is reachable; right after a restart it shows "not measured yet" until the second poll. With "reduce motion" enabled in the OS it stays still.

### Router-to-router wiring (LLDP)

Which AP hangs on which router — and on which physical port — is read from
**LLDP** when the routers run `lldpd`. LLDP reports real link-layer neighbours
plus the local and remote port, so the panel no longer has to infer the
backbone from DHCP leases, ARP and bridge FDB. LLDP runs as the first detection
pass and wins over all heuristics for the same router pair; a conflicting
FDB port is recorded in diagnostics rather than silently preferred.

LLDP is **optional**. Without `lldpd` everything keeps working exactly as
before, only with lower confidence and a corresponding marker in the UI. It is
read over SSH (`lldpcli -f json show neighbors`) because stock OpenWrt exposes
no ubus object for it — that read deliberately does **not** trip the
“SSH fallback / degraded” warning, and it is refreshed every 10 minutes rather
than on every poll.

Install it on **all** routers for reliable detection:

```sh
# OpenWrt 25.x (apk)
apk add lldpd

# OpenWrt 24.x and older (opkg)
opkg update && opkg install lldpd

/etc/init.d/lldpd enable && /etc/init.d/lldpd start
```

The medium is taken from the LLDP interface names, so a WLAN repeater running
`lldpd` is still shown as *WLAN Repeater* while an LLDP-verified copper link
outranks the STA-interface heuristic. Two APs reported on the same gateway port
still produce an inferred unmanaged-switch node.

Installing `lldpd` later takes effect on its own — no reload of the config
entry required.

### Port-to-device mapping

Every physical port tile (WAN, LAN1, …) shows what is plugged in: a badge with
the device name (or IP), `n Geräte` when several devices sit behind the port,
`Switch/AP` for mesh trunk ports, and `Unbekannt` when the link is up but no
device could be identified. Wired devices additionally appear as grouped icon
dots below the port strip.

The mapping is derived from real router data — bridge FDB (`brforward`),
DHCP leases and the ARP table — and carries an explicit confidence level:

| Confidence | Meaning |
|------------|---------|
| `high` | MAC seen in the bridge FDB on that port **and** full identity (IP + hostname) from DHCP/ARP |
| `medium` | FDB port match, but only partial identity (IP-only, hostname-only, bare MAC, or DHCP/ARP conflict) |
| `low` | Identity known, but no reliable port — listed as *unassigned*, never pinned to a port |
| `none` | Nothing known |

WiFi clients are never attributed to LAN ports, router-own MACs are filtered,
and the WAN port never claims devices (the FDB cannot see the WAN side).
Devices behind a mesh AP belong to that AP, not to the gateway trunk port.

For troubleshooting, enable **“Port mapping debug data in topology snapshot”**
in the integration options: the auth-protected snapshot endpoint
(`/api/openwrt_topology/snapshot`) then includes a per-port trace (FDB MACs,
DHCP/ARP matches, filtered MACs, final assignment, reason). HA diagnostics
always contain only a PII-free summary (counts, confidence, sources).

### Event timeline

The Inspector panel shows a per-device event timeline — status changes recorded in memory since the last HA restart:

- WAN connected / disconnected
- CPU spike ≥ 80% / recovery
- RAM spike ≥ 90% / recovery

### Animations

- Nodes animate in/out when filters change (layout transition)
- Status-change flash on online ↔ offline ↔ warning transitions
- Programmatic zoom uses smooth cubic-bezier transition

---

## Network Intelligence

Network Intelligence turns the data the integration already polls into **events**,
**incidents with a root cause** and a **health score** per router and for the fleet. It adds
no router calls (no extra ubus requests, no SSH commands, no ACL change). Full details:
[docs/network-intelligence.md](network-intelligence.md).

### What it detects

- **Wi-Fi** (from the router log and the client lists): reconnect storms, failed
  authentications per client and as a fleet-wide wave, mass disconnects of one AP, clients
  without IP address, DHCP failures after connecting, band and roam flapping, weak clients,
  radio channel changes (DFS).
- **Infrastructure:** router unreachable, all routers unreachable (`lan_unreachable`),
  reboot, CPU and memory pressure, service restarts, clock skew, conntrack jumps, port flaps,
  speed drops, port errors and load, uplink down, LLDP neighbour changes, WAN down / unstable /
  IP changed, DHCP pool full and address conflicts.

Every threshold has a default and can be changed by an admin in the Diagnose tab.

### Root cause and correlation

Follow-up problems are linked to a **root** (router outage, all routers away, reboot, WAN
down, radio change, uplink down, mass disconnect) using the router tree from LLDP and the
topology panel's port mapping. Children fire no event, are not counted and do not lower the
score. Example: an access point fails → one `router_unreachable` incident; its clients'
disconnects just before are its children.

- **Observed vs. inferred:** a cause is `confirmed` only when it rests on measured data (same
  router, or a path seen by LLDP). Otherwise it is a `hypothesis` with a confidence value; a
  link over an inferred topology edge has a confidence of **at most 0.6**.
- **Cause level** (since 1.41.0): *confirmed*, *likely* (confidence ≥ 0.7 **and** at least two
  independent sources such as log, poll, usteer, LLDP or the other clients on the radio),
  *possible* (≥ 0.4) or *unknown*. One source alone is at most *possible*. The level is in the
  panel, the `incidents` API and the bus event (`cause_level`).
- A flapping uplink port (`lan_port_flap`) is a root too (since 1.41.0): drops of the access
  points behind it (mass disconnects, reconnect storms, missing DHCP) become its children;
  failed authentication and band or roam flapping stay incidents of their own.
- A client with reconnects is compared with the other clients on its radio: with at least three
  quiet peers the top cause is the device itself (`client_side`).
- Every cause comes with a recommendation (text only; German in the panel, English in
  [docs/realtime-rca.md](realtime-rca.md#recommendations-per-cause)).

### Near-realtime Wi-Fi events (since 1.41.0)

The router log is read on **every poll**, so Wi-Fi events (disconnects with their reason,
failed authentication, roaming, DFS) reach the engine at most one poll interval late (60 s by
default). There is no push stream, no new kind of router call and no ACL change; `log read`
(ACL v6) is enough, it just runs on every poll instead of every second one. Each Wi-Fi
event carries the category of its 802.11 reason (`radio`, `security`, `ap`, `inactivity`,
`client`). The Diagnose tab shows how old the last log read of each router is. Details, limits
and the test scenarios: [docs/realtime-rca.md](realtime-rca.md).

### Health score

0–100 per router over five weighted areas (Wi-Fi 30, system 25, LAN 15, WAN 20, DHCP/DNS 10).
Open root incidents lower their area (critical 40, warning 15, info 3, times confidence;
acknowledged half). The score is **unknown, never 100,** while less than 50 % of it rests on
fresh data; the Wi-Fi area needs a readable router log. The fleet score weights the routers by
their coverage.

### Entities

| Entity | `unique_id` | Notes |
|--------|-------------|-------|
| Sensor *Network health* | `{entry_id}_net_health` | 0–100 or unknown; attributes `areas`, `coverage`, `maintenance` |
| Sensor *Active incidents* | `{entry_id}_incidents_active` | Open root incidents of the router |
| Sensor *Wi-Fi reconnects (1 h)* | `{entry_id}_wifi_reconnects_1h` | Routers with AP interfaces only |
| Sensor *Wi-Fi authentication errors (1 h)* | `{entry_id}_wifi_auth_errors_1h` | Routers with AP interfaces only |
| Sensor *WAN reconnects (24 h)* | `{entry_id}_wan_stability` | Disabled by default without WAN |
| Binary sensor *Critical incident* | `{entry_id}_incident_critical` | Problem; on while a critical root incident is open |
| Switch *Maintenance mode* | `{entry_id}_maintenance_mode` | Configuration entity |
| Sensor *Fleet network health* | `openwrt_router_fleet_net_health` | One per HA instance, no device |
| Sensor *Fleet active incidents* | `openwrt_router_fleet_incidents_active` | One per HA instance, no device |
| Binary sensor *Fleet critical incident* | `openwrt_router_fleet_incident_critical` | One per HA instance, no device |

`{entry_id}` is the router's config entry ID. The fleet entities move to another router entry
when theirs is removed or reloaded and keep their entity IDs.

### Bus event `openwrt_router_incident_event`

Fired once per root incident with `state` `opened` (after a 90 s settle time), `reopened` or
`resolved`, from severity `warning` upwards (setting `notify_min_severity`). Never for
children or routers in maintenance mode. Ignoring an announced incident fires `resolved` with
`reason: ignored`.

Fields: `state`, `incident_id`, `type`, `severity`, `confidence`, `cause`, `cause_status`,
`cause_level` (since 1.41.0), `scope`, `routers` (names), `entry_ids`, `device_id` (one
router only, else `null`), `reason` (`ignored` or `null`) and, for client incidents, `mac`.

```yaml
automation:
  - alias: "Notify on critical network incident"
    triggers:
      - trigger: event
        event_type: openwrt_router_incident_event
        event_data:
          state: opened
          severity: critical
    actions:
      - action: notify.notify
        data:
          title: "Network incident"
          message: >-
            {{ trigger.event.data.type }} on
            {{ trigger.event.data.routers | join(', ') }}
            (cause: {{ trigger.event.data.cause or 'unknown' }})
```

### Maintenance mode

Per router with the switch *Maintenance mode*; for the whole fleet for 1, 4 or 24 h in the
Diagnose tab. Events are still stored (marked), but no incidents open, no bus events fire and
the router leaves the fleet score. No late alarms after it ends.

### Diagnose tab

A **Diagnose** tab in the topology panel (labels in German): *Übersicht* (scores, open
incidents, events of the last 24 h), *Incidents* (with children, evidence, cause and
recommendation), *Timeline* (filters: router, category, severity, period), *WLAN*,
*Stabilität* (client stability, since 1.42.0), *Infrastruktur* and *Einstellungen*. Router nodes in the topology carry a warning badge that
opens the Diagnose view of that router. Access follows the topology panel (admins, or all
users with the option enabled).

### Settings

Retention (30 days), maximum events (3000), `notify_min_severity`, score weights and
penalties, every threshold, exclusions (MACs, SSIDs, routers, incident types) and fleet
maintenance. Everyone who can open the panel can read them; **only admins can change them**
(also acknowledge / ignore / re-activate incidents). Changes are checked strictly and apply at
once.

### Storage

One file for all routers: `.storage/openwrt_router.intelligence`, written at most every
300 s, capped at **1.5 MB** (oldest events are dropped first). An unreadable file is copied to
`openwrt_router.intelligence.bak` before the engine starts empty. Incidents and events
survive HA restarts; removing a router entry deletes its data from the file.

### Privacy

Everything stays local. The store, the panel and the bus event can contain client MAC
addresses, the WAN IP and router names; the panel is admin-only by default. The diagnostics
download contains only counts, types, times and the score from this feature.

### Limits / FAQ

- **Not measurable** without new router calls: packet loss, router-side latency, DNS
  resolution, network loops, foreign Wi-Fi interference / channel utilisation, fluctuating
  client data rates, conntrack usage in percent.
- Detection follows the poll interval (slower in SSH fallback mode); log events arrive with
  the next poll.
- *Score unknown?* Too little fresh data (right after start, router unreachable, log not
  readable).
- *No event for a client storm?* It was a child of a root (e.g. the AP went down), below
  `notify_min_severity`, or the router was in maintenance.
- Authentication errors are not counted as an outage.

### Client stability (since 1.42.0)

A long-term history per Wi-Fi client: how stable is this device, since when, at which access
point, and is the device or the network to blame? It adds **no router calls** (no ubus
request, no SSH, no file read or exec, no ACL change); it reuses the client lists and log lines
that Network Intelligence already evaluates. Full details:
[docs/client-stability.md](client-stability.md).

- **Tolerant state per MAC:** roaming and a short absence are no disconnect (offline only
  after 2 polls and at least 150 s in no list); an access point outage is a measurement gap,
  never offline. Disconnects are classed by their log reason (`error`, `inactivity`, `leave`,
  `unknown`, `infra`); those during a Network Intelligence root of the client's router count
  as `infra` and raise no alarm of their own (port roots only behind the port, never for a
  gateway's WAN port flap).
- **Stability score** 0–100 from disconnects 30, reconnects 15, session length 15, signal 20,
  authentication 10, roaming 5 and recurring patterns 5; *unknown*, never 100, without enough
  data. Classes *very stable* … *critical*; devices can be marked *sleepy*.
- **Patterns and recommendations:** disconnects at the same time of day, signal getting worse,
  problems at one access point only; every recommendation is an observation, a hypothesis or
  confirmed and comes with its numbers.
- **AP comparison** per router and band over 24 h / 7 d / 30 d, per 100 client hours.
- **Panel:** sub-tab *Stabilität* in *Diagnose* (table, detail with timeline and charts from
  1 h to 30 d, AP comparison, settings).
- **Entities only for picked clients** (up to 25): *stability score* and *connection quality*
  (enabled), *reconnects (24 h)*, *connection uptime* and *last disconnect* (disabled).
- **Storage:** `.storage/openwrt_router.client_history`, at most every 300 s, cap 3 MB
  (1–8 MB); hour buckets 7 days, day buckets 30 days (up to 90).
- **Since 1.43.0:** every window figure in the detail (observed time and gaps, disconnects
  per class, signal min/max, TX/RX rates, failures one by one, mean session length, notable
  events, share of samples with a known IP), the real last 60 minutes, a coarse 7 d / 30 d
  strip, disconnect/reconnect bars, an AP/band roaming strip, sorting by AP, 7-day
  availability and trend, and score weights and class limits in the panel (admins).
- **Load:** one pass per poll over the client list (below 20 ms at 1000 clients); 150 clients
  × 30 days take 2.5 MB. The panel costs only while the tab is open; at 1000 clients its first
  table request per hour blocks HA for about 1.4 s. Turn it off with `enabled: false` in the
  tab's settings.

---

## Enterprise Core (since 1.44.0)

An internal foundation for later modules (configuration backup, Security Center, network
diagnostics, Wi-Fi RF). No new entity, no changed `unique_id`, device or entity id, no
config-entry migration, and **no extra router call per poll**. **What you will see:** core
events (`openwrt_router_core_event`) appear in the logbook, once `router.registered` per
router at first start, and in the recorder. An error in the core never fails a poll or a router's setup; it is
logged. Details (German): [docs/enterprise-core.md](enterprise-core.md).

- **Stable router id** per config entry that survives IP and hostname changes and a
  factory reset; duplicates are flagged, never merged; a replaced router is taken over only
  by an explicit admin action.
- **Capabilities** per router from the poll data, plus `rf.*` from the deployed rpcd ACL.
- **Configuration API v1** for modules. Since 1.45.0 the
  [Configuration Manager](#configuration-manager-since-1450) is the provider; option
  `config_backup_enabled` (default off) switches it on per router.
- **Approvals** for critical actions (admin users only, single use, bound to router and
  checksum) and an **audit log** with a separate security ring.
- **Tiered rpcd ACL v9 as an offer only** (written only after an admin approval, with
  backup and rollback command) and **pinned SSH** for that path: a first-seen host key
  waits for an admin confirmation; a changed key is always refused.

---

## Configuration Manager (since 1.45.0)

Backs up the configuration of your OpenWrt routers in Home Assistant, keeps versions, shows
differences and detects configuration drift. **Off by default** (option
`config_backup_enabled` per router, *Settings → Devices & services → OpenWrt Router →
Configure*); while it is off there are **0 extra router calls**. Full guide (German):
[docs/configuration-manager.md](configuration-manager.md).

- **Three artifacts per version:** the restorable archive (`sysupgrade -b` format, fetched
  through LuCI's `cgi-backup` endpoint, otherwise over SSH as root), a normalised UCI snapshot
  for comparison, and a package and system inventory. Routers without an archive path get the
  snapshot only.
- **Triggers:** a daily run (option `config_backup_time`, default 03:30, a fixed per-router
  offset of up to one hour, one run at a time), a manual run from the panel or the action
  `openwrt_router.create_config_backup`, a run after a detected release change, and drift
  checks when the polled data changes (debounced, at most one per hour). The integration has
  no update path of its own: call the action before a firmware update.
- **Versions:** deduplicated, kept 7 daily / 4 weekly / 6 monthly, protectable; **drift**
  with areas and risk levels (critical: management IP, VLAN, firewall, SSH access, uplink,
  web admin), acknowledge or mark as known, never an automatic reset; a diff view that shows
  secrets only as "changed".
- **Panel:** *Enterprise → Konfiguration* (administrators only): overview, router detail,
  export with approval, restore check. Entities per router: `config_last_backup`,
  `config_backup_status`, `config_versions`, `config_drift`.
- **No automatic restore.** The integration restores nothing; the restore check only tells
  you what a manual restore (LuCI or `sysupgrade -r`) would do, and a restore cannot be undone
  automatically.
- **Security:** archives contain Wi-Fi passwords, keys and password hashes in clear text and
  are not encrypted by the integration (stored under `openwrt_router/config_backups/` in the
  HA config folder with restrictive file modes: encrypt your HA backups). The router right it
  needs (`cgi-io: backup`, `uci` and `rpc-sys packagelist`, read-only) gives Home Assistant
  read access to **all** router secrets; it is only offered, and written to the router only
  after an explicit admin approval.

---

## Security Center (since 1.46.0)

Turns data the integration already reads (Wi-Fi events, device list, configuration changes)
into **hints** about unusual activity, and can optionally evaluate syslog lines your routers
send to Home Assistant. **It only observes:** no blocking, no quarantine, no scans and no
change to any router or firewall. **Off by default**; switch it on as an administrator under
*Panel → Enterprise → Security Center*. While it is off there is no listener, no socket and
nothing is written. Full guide (German): [docs/security-center.md](security-center.md).

- **Hints, not verdicts:** Wi-Fi authentication failures (also across access points), bursts
  of association attempts, clustered deauthentications, new devices and unusual IP or host name
  changes, configuration changes in VLAN, firewall or interface areas (needs the Configuration
  Manager), and, with remote logging, blocked firewall connections and DNS patterns. Findings
  already covered by Network Intelligence are linked, never duplicated. Each detection shows
  whether its data source is available; firewall and DNS log formats are marked
  "format unconfirmed" because they were not seen on real devices.
- **No extra router calls per poll.** Remote logging is optional: *log path* `syslog` makes
  Home Assistant listen on UDP port 5514 (IPv4, only for the routers' management addresses; UDP
  senders can be forged, so the sender list filters noise and does not authenticate). You set
  up the router side yourself, the integration changes nothing on a router. The collector path
  is not available yet.
- **Entities and panel:** seven fleet sensors (security score, active and critical hints,
  unconfirmed devices, firewall log entries and Wi-Fi authentication failures of the last hour,
  detection coverage), only while the center is on; unknown is `None`, never 0. The panel tab
  shows overview, timeline, devices, detections and settings.
- **Privacy:** only administrators see MAC, IP and host name in clear text, everyone else
  pseudonyms; DNS names are off by default; raw log lines are never stored; diagnostics carry
  counters only. No new router rights (no ACL change).
- **Not tested** against real routers or a real Home Assistant instance yet.

---

## Features

### System Monitoring
- **System Info**: Platform architecture, OpenWrt version, hostname, model
- **CPU**: 1/5/15-minute load averages as percentage of total CPU capacity (load average divided by the core count from `/proc/cpuinfo`, rpcd ACL v7; a load average of 1.22 on two cores is 61%)
- **Memory**: Total, used, free, cached, shared, buffered (MB)
- **Disk**: Total, used, free capacity and usage percentage
- **tmpfs**: Monitoring for /tmp, /run, /dev/shm
- **Connections**: Active network connection count (nf_conntrack)
- **TCP Ping**: Round-trip latency to 8.8.8.8:53 in ms

### Network & Traffic
- **Per-Interface Bandwidth**: Dynamic RX/TX byte sensors per network interface (wan, lan, loopback, …)
- **Bandwidth Rate**: RX/TX in bytes/s for real-time monitoring
- **Per-Port Sensors**: Link state, speed, RX/TX bytes per physical Ethernet port
- **WAN Statistics**: WAN download/upload bytes, WAN IP, WAN status
- **WAN detection**: the WAN is the interface named `wan*`, `wwan*` or `pppoe-wan`, else one with an upstream-only protocol (PPPoE/PPPoA, cellular `qmi`, `mbim`, `ncm`, `modemmanager`, `3g`, `wwan`), else a cellular name (`lte*`, `modem*`, `umts*`, `3g`/`4g`/`5g`); an interface that is up wins over one that is down. A router without any of these (dumb AP) reports no WAN: its WAN entities are created disabled and DDNS is not polled. Uplinks named differently (`tethering`, `sta`, `repeater`) are not detected yet
- **Radio Signal/Noise**: dBm sensors per WiFi radio (iwinfo-capable routers)
- **LLDP Neighbours**: router-to-router wiring incl. physical ports read from `lldpd` when installed — optional, falls back to the DHCP/ARP/FDB heuristics

### DDNS / DynDNS
- **DDNS Service Status**: Reads `/etc/config/ddns` — service name, domain, last update, current IP
- **Status**: `ok` / `error` / `unknown` per configured DDNS service

### WiFi & Clients
- **WiFi Switches**: Toggle per SSID with correct SSID + Band label (`OpenWrt (2.4 GHz)`, `Guest (5 GHz)`, …)
- **WiFi Switch Client List**: Each switch exposes a `clients` attribute with all connected clients (name, MAC, IP, signal, online time, DHCP expiry)
- **AP Interface Sensors**: Per-radio channel, frequency, TX power, HT mode, HW mode, client count
- **Device Tracker**: Track WiFi clients by MAC — `home` / `not_home` with IP, hostname, signal, `connected_since`

### Management & Control
- **Service Management**: Start/stop/restart procd system services (dnsmasq, dropbear, firewall, network, uhttpd, wpad)
- **Update Management**: Check for and perform system/package updates
- **Buttons**: Reload WiFi, Check Updates, Perform Updates, Restart Service
- **SSL/HTTPS**: Secure connections with self-signed certificate support
- **Auto-ACL Provisioning**: Automatically deploys the rpcd ACL file via ubus (pure-Python asyncssh fallback when the router blocks ubus file access — no `sshpass` on the HA host required) — on first add and re-validated on every startup

### Resilience
- **Session renewal**: rpcd sessions request a 24-hour TTL; auto re-login on expiry
- **Retry logic**: exponential backoff on repeated auth failures
- **ACL fallback chain**: automatic fallbacks for every blocked rpcd call

---

## ACL Fallback Support

Works on **ACL-restricted routers** (e.g. Cudy WR3000 on OpenWrt 25) where standard rpcd calls are blocked. All fallback chains are automatic — no manual router configuration required.

| Blocked Call | Fallback |
|---|---|
| `uci/commit` | → `uci/apply` → SSH `uci set + commit + wifi reload` |
| `hostapd.*/get_clients` | → SSH `ubus call` → SSH `iw station dump` (kernel, read-only) |
| `file/read /tmp/dhcp.leases` | → `luci-rpc/getDHCPLeases` |
| `hostapd.*/get_status` (SSID) | → `iwinfo/info` → `luci-rpc/getWirelessDevices` |
| `network.wireless/status` | → `iwinfo/info` → UCI wireless config |
| `file/write` (ACL deploy) | → SSH `printf > acl.d/…` + `rpcd restart` (setup checklist reports the outcome) |

---

## Configuration

Add via **Settings → Devices & Services → Add Integration → OpenWrt Router**.

| Field | Default | Description |
|-------|---------|-------------|
| Host | – | Router IP address or hostname |
| Protocol | HTTP | HTTP, HTTPS, or HTTPS Self-Signed |
| Port | 80* | Auto-adjusts to 443 for HTTPS |
| Username | root | rpcd/ubus username |
| Password | – | rpcd/ubus password |
| SSH Username | – | Optional: for SSH fallback (client counting, WiFi toggle) |
| SSH Password | – | Optional: SSH password |

---

## Requirements

- Home Assistant **2026.2.0** or newer
- OpenWrt **19.07** or newer (tested on 25.12.1)
- `rpcd` with `rpcd-mod-rpcsys` installed on the router
- *Optional:* `lldpd` on every router for exact router-to-router wiring
  (see [Router-to-router wiring (LLDP)](#router-to-router-wiring-lldp))

### Enable rpcd on OpenWrt

```sh
# OpenWrt 25.x (apk)
apk add rpcd rpcd-mod-rpcsys

# OpenWrt 24.x and older (opkg)
opkg update && opkg install rpcd rpcd-mod-rpcsys

uci set rpcd.@rpcd[0].socket='/var/run/ubus/ubus.sock'
uci set rpcd.@rpcd[0].timeout=30
uci commit rpcd
service rpcd restart
```

---

## Entities

### Sensors (Static)
| Entity | Description |
|--------|-------------|
| `sensor.{name}_uptime` | Router uptime |
| `sensor.{name}_wan_status` | WAN connection state |
| `sensor.{name}_connected_clients` | Total WiFi client count |
| `sensor.{name}_cpu_load` | 1-min CPU load in % of all cores, attributes `cpu_cores` (empty if unknown, then not divided), `load_average_1min/5min/15min` |
| `sensor.{name}_cpu_load_5_minute` | 5-min CPU load in % of all cores |
| `sensor.{name}_cpu_load_15_minute` | 15-min CPU load in % of all cores |
| `sensor.{name}_memory_*` | RAM details (MB / %) |
| `sensor.{name}_disk_*` | Disk details (GB / %) |
| `sensor.{name}_temporary_storage_*` | tmpfs usage |
| `sensor.{name}_wan_ip_address` | WAN IP |
| `sensor.{name}_wan_download/upload` | WAN RX/TX bytes |
| `sensor.{name}_firmware_version` | OpenWrt version |
| `sensor.{name}_ping_ms` | TCP latency to 8.8.8.8:53 |
| `sensor.{name}_update_status` | Update availability |
| `sensor.{name}_active_network_connections` | nf_conntrack count |
| `sensor.{name}_ddns_*` | DDNS service status and last IP |
| `sensor.{name}_router_log` | Diagnostic: log ingest status (`ok`, `pending`, `not_permitted`, `error`); attributes `counts_24h` per event type, processed/missed lines |
| `sensor.{name}_dfs_events_24_h` | Diagnostic: DFS log events and channel changes in the last 24 h; attributes `by_type`, `last_event` |
| `sensor.{name}_unstable_wi_fi_clients` | Diagnostic: clients with >= 3 reconnects (same router, within 5 min) in 24 h; attribute `top` (10 clients) |
| `sensor.{name}_channel_plan_findings` | Diagnostic: Wi-Fi channel plan findings of this router across all routers (`same_channel`, `overlap`, `non_standard_24`, `dfs`); attributes `findings`, `radios` |

### Sensors (Dynamic)
| Entity | Description |
|--------|-------------|
| `sensor.{name}_{iface}_rx/tx` | RX/TX bytes per interface |
| `sensor.{name}_{iface}_rx_rate/tx_rate` | RX/TX bytes/s |
| `sensor.{name}_{iface}_signal/noise` | WiFi signal/noise dBm |
| `sensor.{name}_{iface}_channel` | WiFi channel |
| `sensor.{name}_{iface}_ap_clients` | Clients per radio |
| `sensor.{name}_{port}_link/speed/rx/tx` | Per-port Ethernet stats |
| `sensor.{name}_dhcp_pool_{pool}` | Share of an active DHCP pool's range covered by leases (%), attributes `interface`, `leases`, `size`. Needs read access to the uci config `dhcp` (granted to `root` through the LuCI ACLs) |

> **Traffic Charts**: RX/TX byte sensors use `state_class: total_increasing` — add to a **Statistics card** or **Energy Dashboard** for traffic history graphs.

### Binary Sensors
| Entity | Description |
|--------|-------------|
| `binary_sensor.{name}_connectivity` | Router reachable |
| `binary_sensor.{name}_wan_connectivity` | WAN up |
| `binary_sensor.{name}_sticky_wi_fi_clients` | Diagnostic: clients stay on this router although another one is better — with usteer: heard >= 8 dB stronger elsewhere for 10 min; without: <= -75 dBm for 10 min and another router offers the band. Attributes `method`, `clients` |

### Switches
- **WiFi Switches**: one per SSID — `switch.{ssid}_2_4_ghz`, `switch.{ssid}_5_ghz`, `switch.{ssid}_6_ghz`
- **Service Switches**: `switch.service_{name}` for dnsmasq, dropbear, firewall, network, uhttpd, wpad

### Buttons
| Entity | Description |
|--------|-------------|
| `button.{name}_reload_wifi` | Reload WiFi configuration |
| `button.{name}_check_for_updates` | List upgradable packages (apk or opkg, via SSH) in `sensor.{name}_update_status` |
| `button.restart_{service}` | Restart system service |

### Events
| Event | When |
|-------|------|
| `openwrt_router_outage_event` | A router (or all routers at once) became unreachable / reachable again |
| `openwrt_router_wifi_event` | Router log: `psk_mismatch`, `handshake_failed`, `inactivity_timeout` (fields `mac`, `hostname`, `interface`, `router`, `time`) |
| `openwrt_router_dhcp_event` | Router log: dnsmasq `nak`, `decline`, `no_address` (pool exhausted), with `ip` |
| `openwrt_router_incident_event` | Network Intelligence: a root incident was `opened`, `reopened` or `resolved` — see [Network Intelligence](#network-intelligence) |
| `openwrt_router_dfs_event` | Router log: hostapd `radar_detected`, `cac_*`, `nop_finished`, `new_channel`; or `channel_change` of a radio between two polls. `dfs_related` is only true with a DFS log line (`radar_detected`, `new_channel`, `cac_failed`) of the same 5 GHz radio within 15 min |

Log events are limited to 10 per fetch and one per type and client (DFS lines: per interface and frequency) in 5 minutes; channel changes are not limited. They need rpcd ACL v6 or newer (`log read`), which the integration deploys on start.

### Device Tracker
One entity per WiFi client — `home` / `not_home` with attributes: `mac`, `ip_address`, `hostname`, `ssid`, `radio`, `signal`, `connected_since`, `random_mac` (locally administered "private" MAC, no vendor lookup), `associations_24h`, `reconnects_24h` (from the router logs of all routers), `dhcp_status` (`ok`, `pending`, `dhcp_missing` = associated for 180 s without lease or ARP entry on any router, `static_no_lease`; empty while no router reports leases or a DHCP server is unreachable). Note: a device with a manually set IP that only talks locally, or clients right after a gateway reboot (empty lease file until they renew), can show `dhcp_missing`.

Trackers are restored from the entity registry after a restart, so absent clients show `not_home`; to remove a stale tracker for good, disable it first, then delete it.

---

## Architecture

```
Config Flow → Config Entry → OpenWrtRuntimeData
                                 ├── api: OpenWrtAPI       ← ALL HTTP/SSH calls
                                 └── coordinator: OpenWrtCoordinator (30 s poll)
                                           ↕
                                   OpenWrt Router (ubus JSON-RPC POST /ubus)

Topology Panel (sidebar)
  └── /api/openwrt_topology/snapshot  ← aggregates all coordinator data
        └── topology_mesh.py          ← multi-router mesh view
```

**Rule:** Entities never call the API directly. All network calls go through `api.py`.

---

## Version History

| Version | Date | Key Features |
|---------|------|---|
| **1.28.0** | 2026-09 | LLDP-basierte Router-zu-Router-Verkabelung inkl. physischer Ports, reicheres Client-Datenmodell (Vendor/Quelle/Confidence) — siehe [CHANGELOG.md](../CHANGELOG.md) |
| **1.27.0** | 2026-09 | Reboot-Button pro Router (ubus `system/reboot` mit SSH-Fallback) — siehe [CHANGELOG.md](../CHANGELOG.md) |
| **1.24.0 – 1.26.6** | 2026-08 | Log-Hygiene im Multi-Router-Betrieb, ScannerEntity-Dedup über APs hinweg, rpcd-ACL v5 mit Redeploy, SSL-Kontext ausserhalb des Event-Loops — siehe [CHANGELOG.md](../CHANGELOG.md) |
| **1.23.0** | 2026-07 | Setup-Checklist: Datei-Lesezugriff via ubus (erweiterte rpcd-ACL), WLAN-Status via iwinfo, reparierte manuelle Deploy-Anleitung — siehe [CHANGELOG.md](../CHANGELOG.md) |
| **1.22.0** | 2026-07 | SSH-Fallback pure-Python (asyncssh) statt `sshpass` — funktioniert jetzt auch auf HAOS/Containern — siehe [CHANGELOG.md](../CHANGELOG.md) |
| **1.20.0 – 1.21.0** | 2026-07 | HA-2026.8-Kompatibilität (`config_entry=` im Coordinator), de.json, CI-Modernisierung; Checklist-Deploy-Feedback + SSH-Fallback fürs ACL-Deploy; Topology-Port-Mapping — siehe [CHANGELOG.md](../CHANGELOG.md) |
| **1.16.0 – 1.19.0** | 2026-04 → 2026-05 | HTTPS support, error sensor + outage notifications, sshpass security fix, subprocess/panel lifecycle hardening, rpcd session-leak fix — see [CHANGELOG.md](../CHANGELOG.md) |
| **1.15.6** | 2026-04-22 | **rpcd Memory Leak Fix (CRITICAL)** — `file/exec` removed from ACL; Bridge FDB now via `file/read` on `/sys/class/net/br-lan/brforward` (136 MB → <5 MB) |
| **1.15.5** | 2026-04-22 | **Topology Polling Fix** — stops on HTTP 401 (session expired); shows HA notification instead of continuous retries |
| **1.15.4** | 2026-04-21 | **Config-Flow Capability Checklist** — verifies ubus permissions during setup; red warnings for critical caps missing |
| **1.15.3** | 2026-04-21 | **SSH Fallback Detection** — persistent HA notification when ACL forces SSH; poll interval drops to 5m during remediation |
| **1.15.2** | 2026-04-21 | **Staggered & Adaptive Polling** — multiple coordinators distribute 60s interval evenly (0/15/30/45s offset); auto-doubles to 120s on CPU >100% |
| **1.15.1** | 2026-04-21 | **Topology Memory Leak & CPU Spike Fixes** — nodeRefs cleanup; stabilized recomputeEdges dependency |
| **1.13.0** | 2026-04-19 | **VLAN Badge Caching** — offline routers show stale VLAN badges (not empty) |
| **1.12.3** | 2026-04-19 | **VLAN Badge SSH Fallback** — OpenWrtAuthError correctly caught in get_network_interfaces() |
| **1.12.2** | 2026-04-19 | **VLAN Badge Support** — SSH fallback reads VLANs via `ip -o addr show` |
| **1.12.1** | 2026-04-19 | **SSID/VLAN Badge UI** — SSID badges compact to count only; VLAN badges added to AP nodes; WiFi-client uplink detection fixed |
| **1.12.0** | 2026-04-19 | Full topology UI/UX spec: minimap, context menus, health mode, event timeline, group mode, inspector mini-charts, firmware version, zoom-to-node, status animations |
| **1.11.1** | 2026-04-16 | 24h rpcd session timeout; DDNS skip for devices without DDNS; ruff CI fix |
| **1.11.0** | 2026-04-15 | Client Detail Panel (IP, band, connected since, lease expiry, HA link) |
| **1.10.1** | 2026-04-14 | Topology panel 5 views; edge tooltip; Phase 2 UI; Fritz!Box TR-064 fix |
| **1.9.2** | 2026-04-07 | WiFi switch `clients` attribute — per-client name, MAC, IP, signal, DHCP expiry |
| **1.9.0** | 2026-04-06 | Full ACL fallback chain; WiFi switch SSID+Band label |
| **1.8.0** | 2026-04-06 | AP interface sensors (channel, mode, htmode, ap_clients) |
| **1.7.0** | 2026-04-06 | Service management (start/stop/restart) |
| **1.6.0** | 2026-04-06 | Bandwidth rate sensors (bytes/s) |
| **1.4.0** | 2026-04-06 | Per-interface bandwidth; per-client online time; radio signal/noise |
| **1.2.0** | 2026-03-24 | Full test suite (247 tests); CI/CD pipelines; HACS icon |
| **1.0.0** | 2026-03-11 | Initial release |

**Tested on:** OpenWrt 25.12.1 (MediaTek Filogic, Cudy WR3000 v1) | Compatible with OpenWrt 19.07+

---

## Roadmap

- [ ] HACS Default Store submission
- [ ] Parental control support
- [ ] Shift+click multi-device compare in topology
- [x] Persistent event history (survive HA restarts) — Network Intelligence
- [ ] Per-client traffic history chart

---

## Contributing

PRs welcome! Please open an issue first for major changes.

## License

MIT
