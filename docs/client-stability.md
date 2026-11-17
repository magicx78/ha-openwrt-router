# Client Stability (1.42.0)

This builds on [Network Intelligence](network-intelligence.md). It keeps a long-term history
per Wi-Fi client and answers: *how stable is this device, since when, at which access point,
and is the device or the network to blame?* It adds **no router calls**: no new ubus request,
no SSH command, no file read or exec and no ACL change. Everything comes from the client lists
and log lines the integration already polls, handed over by the Network Intelligence engine
after each poll.

## Contents

- [What it adds to the load](#what-it-adds-to-the-load)
- [How a client is tracked](#how-a-client-is-tracked)
- [Windows and figures](#windows-and-figures)
- [Stability score](#stability-score)
- [Recurring patterns](#recurring-patterns)
- [AP comparison](#ap-comparison)
- [Recommendations](#recommendations)
- [Panel tab *Stabilität*](#panel-tab-stabilität)
- [Entities](#entities)
- [API routes](#api-routes)
- [Settings](#settings)
- [Storage](#storage)
- [Privacy](#privacy)
- [Limits and FAQ](#limits-and-faq)
- [Turning it off and rolling back](#turning-it-off-and-rolling-back)

## What it adds to the load

| Where | Cost | Measured (dev PC, Python 3.13) |
|---|---|---|
| Router | **nothing**: 0 ubus calls, 0 SSH sessions, 0 file reads, no ACL change | call-counter test |
| HA, per poll and router | one pass over the client list and the new log lines | 1000 clients: ≤ 20 ms (test budget), best run 9 ms |
| HA, store write | at most every 300 s; builds the payload from packed strings | 150 clients × 30 d: ~22 ms; 1000 clients: ~100 ms, the first save that has to trim ~0.5 s |
| Disk | one extra file `.storage/openwrt_router.client_history`, default cap 3 MB (1–8 MB) | 150 clients × 30 d, all always online: 2.5 MB |
| HA, panel request | only while the *Stabilität* tab is open, at most every 60 s | 150 clients × 30 d: table 262 ms first / 107 ms after, AP view 114 ms, detail ≤ 9 ms |
| Browser | panel bundle +28.9 kB | – |

At the client limit (1000 clients × 30 days) the first table request of each hour takes about
1.4 s (it computes the hourly patterns of every client; later requests in that hour take about
0.35 s) and the AP view about 0.65–0.85 s. These requests run in the HA event loop.

## How a client is tracked

Key: the MAC address. A locally administered MAC (private / random MAC) is marked
`private_mac`. Hostname and IP are kept as the last value only.

Every client has a state:

| State | Meaning |
|---|---|
| `online` | in a fresh client list of an access point |
| `grace` | missing, decision still open (no disconnect yet) |
| `offline` | missing from **all** fresh lists for 2 polls and at least 150 s; the disconnect is dated back to the start of `grace` |
| `unknown` | no statement possible: the access point is unreachable or its list is stale (older than 1.25 poll intervals), or HA was restarted |

- **Roaming is not a disconnect.** A client that shows up at another access point within the
  roam grace time (`max(2 × poll interval, 150 s)`) roams. Only ping-pong (two or more changes
  A↔B within 600 s) counts as a roam flap.
- **Blips** (missing for one poll, back before the offline rule) are no disconnect.
- **Access point outage** or a poll gap is a **measurement gap**, never offline time. If the
  client is missing when the access point comes back, the disconnect is counted with an
  unknown time.
- Each disconnect gets a **class** from the reason in the router log: `error` (timeout,
  handshake, MIC, wrong PSK, missing ACKs, AP full, other), `inactivity`, `leave` (the client
  left on its own), `unknown` (no log line, only the poll) or `infra` (during an open Network
  Intelligence root of the client's router: router or fleet outage, uplink down, or up to 300 s
  after a reboot, radio change, port flap or mass disconnect; WAN down does not count). An
  `infra` disconnect carries the root's incident ID.
- **Reconnects** come only from the Network Intelligence `wifi.reconnect` events (router log).
- **IP visible** (DHCP lease or ARP entry) is counted separately and never mixed with
  availability.
- Tracking stops for clients that are unknown for more than 1 day or offline for more than
  7 days; their time is then neither online nor offline.

## Windows and figures

| Window | Source |
|---|---|
| 1 h | per-poll ring in memory (empty after an HA restart) and the transitions |
| 24 h | hour buckets, the running hour and the transitions |
| 7 d | hour buckets (kept 168 h) |
| 30 d | day buckets (kept `retention_days`, default 30, max. 90) |

For each window: observed time, **coverage** (observed time / window length since first
seen), **availability** = online time / observed time (`unknown`, never 100 %, while nothing
was observed), disconnects per class, reconnects, sessions and the longest stable session,
RSSI mean / min / max, share of weak signal (≤ −75 dBm), roams, band changes, failed
authentication, association and DHCP, measurement gaps and the IP-visible share.

## Stability score

0–100 per client from seven parts. Each part has a value `s` (0–100), a coverage `c` (0–1) and
a weight `w`:

| Part | Weight | Figure x (per 24 observed online hours) | Value | Coverage |
|---|---|---|---|---|
| Disconnects | 30 | `1.0·error + 0.75·unknown + 0.5·inactivity + 0.25·leave` (`infra` 0) | `100·e^(−x/4)` | observed share |
| Reconnects | 15 | reconnect events | `100·e^(−x/3)` | log coverage of the client's router |
| Session length | 15 | median stable session in hours | `100·min(1, ln(1+x)/ln 7)` | at least one session ≥ 1 h or a running one |
| Signal | 20 | RSSI mean m, weak share q | `100·clamp((m+85)/25)·(1−0.5·q)` | at least 10 RSSI values |
| Authentication | 10 | failed attempts | `100·e^(−x/2)` | log coverage |
| Roaming | 5 | roam flaps (ping-pong) | `100·e^(−x/3)` | log coverage |
| Recurring | 5 | active patterns n | `100 − 35·min(n, 3)` | at least 3 days of data |

- `score = Σ w·c·s / Σ w·c` over the parts with `c ≥ 0.3`; `coverage = Σ w·c / Σ w`.
  With a coverage below 0.5 the score is **unknown**.
- Normal roaming costs nothing; one roam flap lowers the score less than one `error`
  disconnect.
- Clients marked **sleepy** (planned sleep, e.g. IoT devices) pay nothing for `inactivity`.
- Classes (default `[90, 75, 50, 25]`): 90–100 *very stable*, 75–89 *stable*, 50–74
  *noticeable*, 25–49 *unstable*, 0–24 *critical*, otherwise *unknown*.
- The table and the entities show the 24 h score; the 7 d score is an attribute. The trend
  arrow compares the last 24 h with the 24 h before (±10 points).

## Recurring patterns

| Pattern | Rule | Status |
|---|---|---|
| Time of day | disconnects (`error`, `unknown`, `inactivity`) in hour h (HA time zone) on at least 4 of at least 7 covered days, at least 50 % of the covered days, at least 3× the rate of the other hours | observed, cause is a hypothesis |
| Signal getting worse | oldest 7 days against the latest 7 (3 against 3 with less data): at least 100 RSSI values, coverage ≥ 0.5, ≥ 70 % at the same AP and band in both; mean drop ≥ 6 dB | otherwise "not comparable" with the reason |
| Access point specific | at least 24 online hours at both APs; `error` disconnects per 24 h at the worst AP ≥ 3× and ≥ 0.5 above the best | observed rates, cause is a hypothesis |
| Shared disconnects | disconnect inside a Network Intelligence root | class `infra`, **no alarm of its own** |

## AP comparison

Per access point and band (router + band), for 24 h, 7 d or 30 d, from the buckets only:
clients, client hours, mean stability (weighted by client hours), disconnects, reconnects,
failed authentication and roams in and out **per 100 client hours**, `infra` disconnects,
RSSI mean and weak share. Values appear only from 10 client hours on (else *zu wenig Daten*);
below 5 events the panel says *geringe Datenbasis*. There is no ranking by absolute counts.

## Recommendations

Text only, never an action on a router. Each carries its measured numbers (`params`) and a
kind: `observation`, `hypothesis` (confidence at most 0.6) or `confirmed` (only when a
confirmed Network Intelligence root explains the disconnects).

| Key | When |
|---|---|
| `check_coverage` | ≥ 10 disconnects per 24 h and ≥ 30 % weak signal |
| `check_roaming` | ≥ 8 roams between two access points within 30 min |
| `check_device_schedule` | a time-of-day pattern |
| `check_ap` | an access-point-specific pattern |
| `infrastructure_cause` | most disconnects fall into confirmed roots |
| `infrastructure_disconnects` | disconnects during infrastructure problems were seen |
| `infrastructure_likely` | ≥ 3 clients of one access point with ≥ 3 reconnects each and no root |

The detail view also says whether the disconnects of the last 24 h point to the
infrastructure or to the client (attribution).

## Panel tab *Stabilität*

A sub-tab of **Diagnose** in the topology panel (labels in German):

- **Clients:** table (worst first), filters for router, band, class, state and a search;
  "Weitere laden" loads the next 100. A click opens the detail.
- **Detail** (1 h, 24 h, 7 d, 30 d): figures, connection timeline (online green, offline red,
  measurement gaps hatched; incidents as markers that open the incident), RSSI with min/max
  band, online share with disconnects, score parts, patterns and recommendations. Admins can
  switch the entities and the *sleepy* mark of the client here.
- **AP-Vergleich:** the AP comparison (default 7 d).
- **Einstellungen:** on/off, retention, store cap and the store status. Weights and class
  limits can only be changed over the API.

The tab loads data when it opens, when the window changes and at most every 60 s while it is
open. On phones the table becomes cards.

## Entities

None by default. An admin picks **up to 25 clients** (setting `entity_macs`, in the detail
view). Each gets five sensors without a device of their own, attached to the fleet entities'
router entry:

| Sensor | `unique_id` | Default |
|---|---|---|
| *{client} stability score* | `openwrt_router_client_<mac12>_stability_score` | on; attributes `score_7d`, `coverage` (not recorded) |
| *{client} connection quality* | `openwrt_router_client_<mac12>_connection_quality` | on; enum of the classes, unknown without enough data |
| *{client} reconnects (24 h)* | `openwrt_router_client_<mac12>_reconnects_24h` | off |
| *{client} connection uptime* | `openwrt_router_client_<mac12>_connection_uptime` | off; seconds since the session began |
| *{client} last disconnect* | `openwrt_router_client_<mac12>_last_disconnect` | off; timestamp |

`<mac12>` is the MAC in lower case without colons. Removing a client from `entity_macs`
removes its sensors from the entity registry. Updates come at most once a minute and need no
network call.

## API routes

All under `/api/openwrt_topology/intelligence/`, same access rules as the other Network
Intelligence routes (logged-in user, admin unless the panel is open to all users; 410 after
unload; POST admin only):

| Method | Path | Content |
|---|---|---|
| GET | `clients` | table; `router`, `band` (`2.4g`/`5g`/`6g`), `ssid`, `class`, `state`, `q` (search), `sort` (`score`, `name`, `availability`, `coverage`, `reconnects`, `last_disconnect`, `last_seen`; `-` = descending), `limit` ≤ 500 (default 100), `cursor` |
| GET | `clients/{mac}?window=1h\|24h\|7d\|30d` | detail with series (≤ 720 points) |
| GET | `clients/aps?window=24h\|7d\|30d` | AP comparison |
| GET / POST | `clients/settings` | settings, defaults, limits, status; POST takes a partial change and answers 400 with `errors` |

## Settings

| Key | Default | Range |
|---|---|---|
| `enabled` | `true` | off stops recording; history and entities stay |
| `retention_days` | 30 | 1–90 (day buckets; hour buckets are always 7 days) |
| `entity_macs` | `[]` | ≤ 25 MACs |
| `sleepy_macs` | `[]` | ≤ 1000 MACs |
| `weights` | see the score table | 0–100 each, at least one above 0 |
| `classes` | `[90, 75, 50, 25]` | four strictly falling values 0–100 |
| `max_store_mb` | 3 | 1–8 |

MACs excluded in the Network Intelligence settings are not recorded, and their history is
deleted.

## Storage

One file for all routers: `.storage/openwrt_router.client_history`, written only after a
change and at most every 300 s (at once on the last unload). Data per client: live state,
transitions of the last 24 h (≤ 64), hour buckets of 7 days and day buckets of
`retention_days`. Buckets are packed as short strings; the score is computed on request and
never stored.

Clean-up every hour: older hours, days and transitions go; clients idle longer than
`retention_days` go. Above `max_store_mb` the save trims in this order (a warning goes to
the log):

1. transitions of offline and unknown clients,
2. hour buckets older than 48 h of private-MAC clients,
3. hour buckets older than 48 h of all clients (their days stay),
4. whole clients, the longest inactive first (offline and unknown before online).

At most 1000 clients are tracked. An unreadable file is copied to
`openwrt_router.client_history.bak` and the history starts empty; a damaged client entry
drops only that client.

## Privacy

Everything stays local. The store and the panel contain client MACs, the last IP address and
hostname. The diagnostics download contains only counts (clients per state, store size,
trimmed entries, settings flags), no MAC, IP or hostname. No bus events are fired, and the
log lines contain no client data.

## Limits and FAQ

- **Not measurable** without new router calls: wired clients, end-to-end reachability (no
  ping), the real connection time of a client before the first poll, numeric reason codes
  where the log has only text. TX/RX rates are shown but are not part of the score.
- Detection follows the poll interval; a disconnect shorter than the offline rule
  (2 polls, at least 150 s) is a blip.
- *Score unknown?* Less than half of the weighted parts have enough data, for example right
  after the start, for a sleeping device or without a readable router log.
- *Why are the reconnects different from `unstable_clients`?* The v1.36 count behind the
  router sensor `unstable_clients` stays as it was (a connect within 300 s after a disconnect
  on the same router). The stability view counts only
  the reconnect events from the router log. Merging the two is still open.
- Guests are not removed sooner than other clients: their tracking stops after 1 day unknown or
  7 days offline, and they leave the file after `retention_days` or when the store is trimmed.

## Turning it off and rolling back

- **Off:** `enabled: false` (panel tab *Einstellungen*). Nothing is recorded; the network
  intelligence works on unchanged.
- **Delete the history:** remove `.storage/openwrt_router.client_history` while HA is stopped.
- **Remove the entities:** clear `entity_macs`.
- **Roll back the code:** install 1.41.0. The extra store file is then unused and can be
  deleted; Network Intelligence keeps its own store.
