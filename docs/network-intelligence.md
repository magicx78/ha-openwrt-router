# Network Intelligence

Network Intelligence turns the data the integration already polls from your OpenWrt routers
into **events**, **incidents** with a root cause, and a **health score** per router and for the
whole fleet. It ships with entities, a Home Assistant bus event and a **Diagnose** tab in the
topology panel.

It adds **no router calls**: no extra ubus requests, no SSH commands and no ACL change. It only
reads fields of answers the coordinator already fetches (system info, ports, WAN status, DHCP,
Wi-Fi clients, LLDP and the router log via `log read`, rpcd ACL v6 or newer).

A short overview lives in the [technical reference](REFERENZ.md#network-intelligence); this page has the
details.

---

## Contents

- [How it works](#how-it-works)
- [What it detects](#what-it-detects)
- [Root cause and correlation](#root-cause-and-correlation)
- [Health score](#health-score)
- [Entities](#entities)
- [Bus event `openwrt_router_incident_event`](#bus-event-openwrt_router_incident_event)
- [Maintenance mode](#maintenance-mode)
- [Diagnose tab](#diagnose-tab)
- [Settings](#settings)
- [Storage](#storage)
- [Privacy](#privacy)
- [Limits and FAQ](#limits-and-faq)

---

## How it works

1. **Events.** After every poll, new log lines (Wi-Fi, DHCP, DFS, system) and changes between
   two polls (port link, WAN, reboot, CPU, …) become events. Each event has a category
   (`wifi`, `dhcp`, `system`, `lan`, `wan`, `dns`, `mesh`), a severity (`info`, `warning`,
   `critical`) and an origin: `observed` (measured) or `inferred` (derived).
2. **Incidents.** A rule per incident type (see [What it detects](#what-it-detects)) turns
   events and measurements into an incident with a life cycle:
   `active` → `resolved`, plus `acknowledged` and `ignored` set by an admin. Repeats only raise
   the occurrence count. A new trigger within the rule's cooldown after a resolve **reopens**
   the same incident.
3. **Correlation.** Incidents and events that follow from another problem are linked to it as
   children (see [Root cause and correlation](#root-cause-and-correlation)).
4. **Score, entities, bus event.** Root incidents lower the health score, are counted by the
   entities and are announced once on the HA bus.

One engine runs per Home Assistant instance and serves all routers of the integration.

---

## What it detects

The defaults below are taken from the built-in settings. All thresholds can be changed in
**Diagnose → Einstellungen** (admin only). "Window" rules open at *count* hits within *window*
seconds; "level" rules open after *debounce* polls at or above *raise* and resolve below
*clear*.

### Wi-Fi

| Incident type | Default trigger | Severity |
|---|---|---|
| `wifi_reconnect_storm` | One client reconnects 5× in 600 s (down → up within 30 s) | warning |
| `wifi_auth_failures` | 3 failed authentications in 600 s | warning |
| `wifi_auth_wave` | 5 different clients fail to authenticate in 600 s (fleet-wide) | warning |
| `wifi_mass_disconnect` | Many clients of one AP disconnect within 5 s (`min_clients` 5, `min_ratio` 0.5) | warning |
| `wifi_no_ip` | Client connected but without an IP address (`dhcp_missing` after 180 s) | info |
| `wifi_dhcp_after_connect` | DHCP failure right after connecting (a NAK followed by an ACK within 30 s is not counted) | warning |
| `wifi_band_flapping` | 4 band changes in 600 s | info |
| `wifi_roam_flapping` | 4 roams in 600 s | info |
| `wifi_weak_clients` | 3 or more clients below −75 dBm for 600 s (clears above −70 dBm) | info |
| `wifi_radio_change` | A radio left its channel (DFS radar, new channel, failed CAC) | info |

### Infrastructure

| Incident type | Default trigger | Severity |
|---|---|---|
| `router_unreachable` | The router's outage is reported by the integration's outage tracker (authentication errors are not an outage) | warning |
| `lan_unreachable` | All routers are unreachable at the same time (fleet-wide) | critical |
| `system_reboot` | The router rebooted | warning |
| `system_cpu_high` | CPU load ≥ 80 % for 3 polls, clears below 65 % | warning |
| `system_ram_high` | Memory pressure ≥ 85 % held for 900 s, clears below 80 % | warning |
| `system_service_restart` | `dnsmasq`, `odhcpd`, `wpad`, `hostapd` or `network` restarted; critical at 3 in 3600 s | warning |
| `system_clock_skew` | Router clock off by ≥ 120 s for 3 polls | warning |
| `system_conntrack_jump` | Conntrack count ≥ 3× the median of the last hour (at least 5000 entries) | info |
| `lan_port_flap` | 3 link changes of a port in 600 s | warning |
| `lan_port_speed_drop` | Port speed below the highest speed of the last 24 h, 2 polls | warning |
| `lan_port_errors` | Port error ratio ≥ 0.1 % (at least 1000 packets) | warning |
| `lan_port_load` | Port load ≥ 90 % for 5 polls | info |
| `lan_uplink_down` | The uplink port of a router is down (warning, confidence ≤ 0.6, when the uplink is only inferred) | critical |
| `lan_lldp_change` | LLDP neighbour of a port changed | info |
| `wan_down` | WAN is down (only on the router that is the WAN gateway) | critical |
| `wan_unstable` | 3 WAN reconnects in 3600 s (WAN gateway only) | warning |
| `wan_ip_changed` | The WAN IP address changed | info |
| `dhcp_pool_full` | DHCP pool ≥ 90 % used, critical at 98 % | warning |
| `dhcp_conflict` | A client declined its offered address (dnsmasq `DHCPDECLINE`, address in use) | warning |

`wifi_channel_busy` exists in the settings, but its data source (`optional_sources.hostapd_status`)
is off and not read in this version, so it does not trigger.

An incident without new evidence resolves after `auto_resolve` (default 1800 s). Router and
fleet outages stay open until the router is back (they are never resolved for lack of data).

---

## Root cause and correlation

After every step the engine builds the router tree from **LLDP** and the trunk port mapping of
the topology panel, and links follow-up problems to a **root**. Roots, from strongest to
weakest:

| Root | Cause given to children | Window before / after (s) |
|---|---|---|
| `lan_unreachable` | `lan_unreachable` | 120 / 0 |
| `router_unreachable` | `router_unreachable` | 120 / 180 |
| `system_reboot` | `router_reboot` | 120 / 180 |
| `wan_down` | `wan_down` | 60 / 120 |
| `wifi_radio_change` | `radio_change` | 60 / 60 |
| `lan_uplink_down` | `uplink_down` | 60 / 60 |
| `wifi_mass_disconnect` | `mass_disconnect` | 30 / 30 |

Examples: when an access point goes down, the disconnects of its clients just before become
children of its `router_unreachable`. When all routers are away, the single router outages
become children of `lan_unreachable`.

**Observed vs. inferred.** Every cause carries `cause_status`:

- `confirmed` only when the link rests on measured data: the same router, or a path seen by
  LLDP.
- `hypothesis` otherwise, for example when the link rests on an edge derived from MAC tables
  (inferred). Such a cause has a **confidence of at most 0.6**.

The panel shows the cause as one of four levels:

| `cause_status` | Confidence | Shown as |
|---|---|---|
| `confirmed` | any | confirmed (bestätigt) |
| `hypothesis` | ≥ 0.7 and two independent sources | likely (wahrscheinlich) |
| `hypothesis` | ≥ 0.4 | possible (möglich) |
| otherwise / no cause | – | unknown (unbekannt) |

Since 1.41.0 *likely* needs at least two independent source families behind the evidence;
see [realtime-rca.md](realtime-rca.md#cause-levels).

Children stay silent: they do not lower the score, are not counted by the entities and fire no
bus event. When the root has resolved and its "after" window has passed, a child that is
still open counts as a problem of its own only if it shows new evidence after that window
(for example a router that is still down, or new reconnects); it keeps the link for the
history. Without new evidence it stays silent until it resolves itself. A child still open one
hour after the window is released from its root. When a router's outage ended only because
its entry was unloaded or reloaded, its children get no "after" window: they stay silent until
that release.

---

## Health score

Each router gets a score from 0 to 100 over five areas:

| Area | Weight | Lowered by |
|---|---|---|
| `wifi` | 30 | `wifi_*` incidents |
| `system` | 25 | `system_*`, `router_unreachable` |
| `lan` | 15 | `lan_*` incidents |
| `wan` | 20 | `wan_*` incidents |
| `dhcp_dns` | 10 | `dhcp_*` incidents |

- Each open root incident of that router lowers its area by a penalty: critical 40,
  warning 15, info 3, multiplied by the incident's confidence. Acknowledged incidents count
  half; ignored and resolved ones do not count.
- **Coverage** says how much of the score rests on fresh data: each area has indicators (for
  example CPU, memory, uptime for `system`; client list and a readable log for `wifi`). Data
  older than three poll intervals does not count. An area below 30 % coverage
  (`min_area_coverage`) drops out.
- The score is **unknown** (not 100) while the coverage is below 50 % (`min_coverage`), for
  example right after an HA start. The Wi-Fi area needs a readable router log.
- Areas that do not exist on a router (no AP, no WAN, no DHCP server) count neither way.
- An unreachable router has a `system` area score of 0 and no other fresh data, so its own
  score is usually unknown; in the fleet score it counts as 0.
- The **fleet score** is the router scores weighted with their coverage. Routers in
  maintenance mode or excluded in the settings are left out.

Fleet incidents (`lan_unreachable`, `wifi_auth_wave`) count only for the fleet entities, not
for a single router. They lower the fleet score by their penalty times their confidence (half
when acknowledged), scaled with the weight of their area; for example a critical
`wifi_auth_wave` lowers it by 40 × 30 / 100 = 12 points. A fleet incident whose routers are
all in maintenance mode or excluded does not lower it.

---

## Entities

Per router (on the router's device; `unique_id` = `{entry_id}_{suffix}`):

| Entity | Suffix | Notes |
|---|---|---|
| Sensor **Network health** | `net_health` | 0–100 or unknown; attributes `areas`, `coverage`, `maintenance` |
| Sensor **Active incidents** | `incidents_active` | Open root incidents of the router |
| Sensor **Wi-Fi reconnects (1 h)** | `wifi_reconnects_1h` | Only on routers with AP interfaces |
| Sensor **Wi-Fi authentication errors (1 h)** | `wifi_auth_errors_1h` | Only on routers with AP interfaces |
| Sensor **WAN reconnects (24 h)** | `wan_stability` | Disabled by default on routers without WAN |
| Binary sensor **Critical incident** | `incident_critical` | Problem class; on while a critical root incident is open |
| Switch **Maintenance mode** | `maintenance_mode` | Configuration entity, see [Maintenance mode](#maintenance-mode) |

Fleet (no device, one set per Home Assistant instance):

| Entity | `unique_id` |
|---|---|
| Sensor **Fleet network health** (attributes `coverage`, `routers`, `maintenance`) | `openwrt_router_fleet_net_health` |
| Sensor **Fleet active incidents** | `openwrt_router_fleet_incidents_active` |
| Binary sensor **Fleet critical incident** | `openwrt_router_fleet_incident_critical` |

The fleet entities belong to one router entry (the first one set up). When that entry is
removed or reloaded, they move to the next entry and keep their entity IDs and history. The
entities are updated by the engine (no polling of their own). The attributes `areas`,
`coverage`, `routers` and `maintenance` are not stored in the recorder.

---

## Bus event `openwrt_router_incident_event`

Fired **once** per root incident and state:

| `state` | When |
|---|---|
| `opened` | A new root incident, after a settle time of 90 s (longer when a router polls more slowly) |
| `reopened` | An incident that fired `opened` came back within its cooldown |
| `resolved` | An announced incident resolved, or was ignored (`reason: ignored`) |

Rules:

- Only from severity `warning` upwards by default (`notify_min_severity`).
- No event for children, for routers in maintenance mode, or for incidents that were
  acknowledged before they were announced (then no `resolved` either).
- Ignoring an announced incident fires `resolved` with `reason: ignored`, so an automation
  waiting for the end does not hang; after that it fires nothing while it is ignored. When it
  is re-activated and still present, it fires `reopened` (or `opened` if it was never
  announced).
- While a router has missed its poll and its outage may still be coming, announcements wait,
  at most 900 s.
- Unloading or reloading a router entry ends its open outage silently (no event).

Fields:

| Field | Content |
|---|---|
| `state` | `opened`, `reopened` or `resolved` |
| `incident_id` | Stable ID of the incident |
| `type` | Incident type, e.g. `wan_down` |
| `severity` | `info`, `warning`, `critical` |
| `confidence` | 0–1, two decimals |
| `cause` | Cause from the root (e.g. `router_unreachable`) or `null` |
| `cause_status` | `confirmed`, `hypothesis` or `null` |
| `scope` | `client`, `radio`, `port`, `router`, `segment` or `fleet` |
| `routers` | Router names (config entry titles) |
| `entry_ids` | Config entry IDs of those routers |
| `device_id` | Device ID when exactly one router is involved, else `null` |
| `mac` | Only for client incidents: the client's MAC address |
| `reason` | `ignored` on the `resolved` of an ignored incident, else `null` |

The logbook shows these events, for example "incident opened: wan_down (critical)".

Example automation:

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

---

## Maintenance mode

- **Per router:** the switch **Maintenance mode** of the router. Its state is stored and
  restored after a restart.
- **Whole fleet:** in **Diagnose → Einstellungen** for 1, 4 or 24 hours (admin only).

While maintenance is on, events are still stored but marked, no incidents are opened or
reopened, no bus events fire and the router stays out of the fleet score. Open incidents can
still resolve. When maintenance ends, no late alarms arrive for what happened during it.

---

## Diagnose tab

The topology panel has a **Diagnose** tab (labels in German) with these views:

| View | Content |
|---|---|
| Übersicht | Score and coverage per router and for the fleet, open incidents by severity, events of the last 24 h |
| Incidents | Incident list, open first; children folded under their root; detail with evidence, cause level, parent, children and recommendation |
| Timeline | Events with filters: router, category, severity, period (1 h, 24 h, 7 days, 30 days, all) |
| WLAN | Wi-Fi incidents with Wi-Fi figures from the overview |
| Infrastruktur | System, LAN, WAN and DHCP incidents with figures from the overview |
| Einstellungen | Settings, see [Settings](#settings) |

Router nodes in the topology show a warning badge with the counted incidents; clicking it opens
the Diagnose view of that router (on phones this is the way in, with a back button).
Acknowledge, ignore (with an optional number of days) and re-activate are admin only.

The panel reads from these authenticated routes (`/api/openwrt_topology/intelligence/…`):

| Method | Route | Purpose |
|---|---|---|
| GET | `summary` | Overview |
| GET | `events` | Filters `router`, `category`, `severity`, `kind`, `since`, `until`, `mac`; `limit` 1–500 (default 100); cursor `before` |
| GET | `incidents` | Filters `status` (comma-separated), `router`, `severity`; `limit` 1–200 (default 100) |
| GET | `incidents/{incident_id}` | Detail |
| POST | `incidents/{incident_id}` | Body `{"status": "acknowledged" \| "ignored" \| "active", "ignore_days": 1–365}` (admin) |
| GET / POST | `settings` | Read / change settings (POST admin) |

Reading follows the topology panel rule: admins, or every user while the option
"Show topology panel to all users" is on. Answers: 403 without permission, 400 for invalid
input, 404 for an unknown incident, 409 for an impossible status change, 503 while the engine
is not loaded yet, 410 after the integration is unloaded.

---

## Settings

**Diagnose → Einstellungen** shows the settings to every reader; **only admins can change
them**. Changes are checked strictly (unknown keys, values out of range, lists longer than 200
entries or entries longer than 64 characters are rejected) and apply at once.

| Setting | Default |
|---|---|
| `retention_days` | 30 (1–365) |
| `max_events` | 3000 (1–10000) |
| `notify_min_severity` | `warning` |
| `score.weights` | wifi 30, system 25, lan 15, wan 20, dhcp_dns 10 |
| `score.penalty` | critical 40, warning 15, info 3 |
| `score.min_coverage` / `min_area_coverage` | 0.5 / 0.3 |
| `thresholds.*` | Per incident type, see [What it detects](#what-it-detects) |
| `thresholds.auto_resolve.clear` | 1800 s |
| `thresholds.ignored.duration` | 7 days (default for "ignore") |
| `exclusions` | `macs`, `ssids`, `routers`, `incident_types` (all empty); MACs with `:` or `-`, stored as `AA:BB:CC:DD:EE:FF` |
| `maintenance.fleet_until` | none |

Exclusions keep evidence away from the incident logic: an excluded router also leaves the fleet
score; an excluded SSID excludes its clients. Open incidents of a newly excluded type end by
`auto_resolve`.

---

## Storage

- One file for all routers: `.storage/openwrt_router.intelligence` (Home Assistant `Store`).
- Holds events, incidents, counters, settings, maintenance state and log positions; written
  at most every 300 s and when the last router unloads.
- Capped at **1.5 MB**: the oldest events are dropped first before a save.
- Events older than `retention_days` and beyond `max_events` are pruned; at most 500
  incidents are kept.
- An unreadable or damaged file is copied to `openwrt_router.intelligence.bak` first, then the
  engine starts empty with a warning.
- Removing a router entry deletes its events, counters and incidents from the file.
- After a restart, incidents and events of the last 30 days (default) are back in the panel.
  The first log read after a restart only takes lines newer than the stored position; if lines
  may have been lost in between, a `system.log_gap` event records it.

---

## Privacy

- Everything stays in Home Assistant. Nothing is sent anywhere.
- The store file and the panel can contain client MAC addresses, IP addresses (for example the
  WAN IP in `wan_ip_changed`), interface names and port names. The panel and its API are
  admin-only unless you open the topology panel to all users.
- The bus event carries router names, entry IDs and, for client incidents, the MAC address.
  Automations and the logbook can see it.
- The diagnostics download contains only counts, types, times, score and coverage from the
  engine; no MAC, IP, hostname, SSID or router name.

---

## Limits and FAQ

**What can it not see?** Some things are not reliably measurable without new router calls or
an ACL change, which this feature avoids:

- Packet loss and router-side latency (there is no ping from the router; the existing latency
  sensor measures from the HA host).
- DNS resolution (no resolution probe; dnsmasq log lines give a hypothesis at most).
- Network loops (no STP state or per-port broadcast counters).
- Foreign Wi-Fi interference and channel utilisation (no survey/scan; `wifi_channel_busy` is
  inactive).
- Fluctuating client data rates (only snapshot values every poll).
- Conntrack usage in percent (only the count is readable; jumps are detected instead).
- Instant reactions: everything is poll-based, so detection follows the poll interval
  (slower in SSH fallback mode).

**Why is the score "unknown"?** Too little fresh data, for example right after a start, while
a router is unreachable for a while, or when the log cannot be read (the Wi-Fi area then
drops out).

**Why did my automation not fire for a client storm?** Most likely it was a child of a root
(for example the AP went down), it was below `notify_min_severity` (Wi-Fi storms are
`warning`, many Wi-Fi types are `info`), or the router was in maintenance mode.

**Is "router_unreachable" fired on authentication errors?** No. Wrong credentials are no
outage.

**Clients with random (private) MAC addresses** look like new clients after a MAC change;
per-client counts start over.

**How do I go back?** Downgrading to 1.39.x removes the feature; the store file
`.storage/openwrt_router.intelligence` is then unused and can be deleted while Home Assistant
is stopped. The new entities can be removed from the entity registry.
