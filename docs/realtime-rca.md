# Realtime events and root cause (1.41.0)

This builds on [Network Intelligence](network-intelligence.md). It makes Wi-Fi events reach
the engine faster, explains disconnects by their reason, grades every cause and adds a
recommendation per cause. It adds **no new router call kind and no ACL change**: everything
comes from the router log (`log read`, ACL v6 and later) and the data the integration already
polls.

## What is fast and what follows the poll

The router log is now read on **every poll** (before: every second poll). New log lines reach
the engine with the next poll, so an event shows up **at most one poll interval late**
(60 s by default; 120 s under CPU load, 300 s in SSH fallback mode). There is no push stream:
a stream over `ubus subscribe` was tried on two access points and crashed uhttpd, so it stays
switched off (see the plan in `docs/plans/2026-11-16-realtime-rca.md`, section 9).

| What | Source | Delay |
|---|---|---|
| Connect, disconnect, deauth with reason | Router log | ≤ 1 poll |
| Failed authentication, wrong PSK, handshake timeout | Router log | ≤ 1 poll |
| Roaming (disconnect at one AP, connect at the next) | Router log, usteer, client lists | ≤ 1 poll (usteer every 2nd poll) |
| DFS radar, channel change, radio restart | Router log, radio status | ≤ 1 poll |
| DHCP and DNS lines (dnsmasq, odhcpd) | Router log | ≤ 1 poll |
| Signal strength of a client | Client list (`get_clients`) | 1 poll, a snapshot only |
| Port link, uplink, WAN, reboot, CPU, memory | Poll differences | 1–2 polls |
| Router unreachable | Failed poll | 1 poll (the bus event follows after the 90 s settle time) |

usteer (fleet-wide client view) is read every second poll from poll 3 on
(`USTEER_READ_INTERVAL_CYCLES = 2`), on its own rhythm, independent of the log.

The Diagnose tab shows per router how old the last log read is (*Log vor 40 s*), or *Log:
kein Leserecht* when the router does not allow `log read`, or the error and the time of the
last good read.

## Disconnect reasons

Every Wi-Fi log line carries the category of its IEEE 802.11 reason code
(`reason_category`, `reason_code`):

| Category | Meaning | Example |
|---|---|---|
| `radio` | The radio link broke | missing ACKs, reason 34 |
| `security` | Authentication failed | 4-way handshake timeout, wrong PSK, SAE failure |
| `ap` | The access point ended the connection | AP busy, BSS transition, not enough bandwidth |
| `inactivity` | The client was idle too long | reasons 4, 39 |
| `client` | The client left on its own | reasons 3, 8, 36 |
| `unknown` | No reason or an unknown code | – |

Disconnects of the categories `radio` and `security` are stored as events with their possible
causes (`radio`: weak signal, interference, client power saving; `security`: wrong PSK, client
driver). All others stay counted only, as before. Reconnect storms list the reason categories
they saw.

## Cause levels

Every incident with a cause gets a **cause level**. It is derived each time from the stored
cause, its status, its confidence and the evidence, and never stored itself.

| Level | When |
|---|---|
| `confirmed` | The cause rests on measured data (`cause_status: confirmed`), for example a fresh weak signal, or a root linked over a path seen by LLDP |
| `likely` | A hypothesis with confidence ≥ 0.7 **and** at least two independent source families |
| `possible` | A hypothesis with confidence ≥ 0.4 |
| `unknown` | No cause, or a confidence below 0.4 |

Source families: the router log (hostapd, netifd, procd and dnsmasq lines count as **one**
family, they come from the same `logread`), the poll, usteer, the topology (LLDP), the fleet,
a comparison with the other clients on the same radio (peers), and a link to a root incident.
One source alone is therefore at most *possible*. A link over an inferred topology edge keeps a
confidence of at most 0.6 and so is never *likely*.

The level is in the panel (*bestätigt*, *wahrscheinlich*, *möglich*, *unbekannt*), in the
`incidents` API (`cause_level`), in the bus event `openwrt_router_incident_event`
(`cause_level`, new field) and in the diagnostics (`active_by_cause_level`).

## Root causes added

- **Port flap** (`lan_port_flap`) is now a root. Mass disconnects and client incidents of the
  access points behind the flapping port, or of the router whose own uplink port flaps, become
  its children. The link is `confirmed` over an observed LLDP path, else a hypothesis. An
  uplink-down above it still explains the port flap.
- **Peer comparison.** A client with reconnects is compared with the other clients on the same
  radio. With at least three peers without drops in the same time window, the top cause is
  `client_side` (*the device itself*) and the AP's power supply leaves the list. No
  comparison without a client list, on an unknown radio, or right after the AP went down.

## Log gaps

When the log cannot be read (error, no right) and later can be read again, lines from the time
between may be lost. The engine records one `system.log_gap` event with `gap_s` (seconds
between the last line before and the first line after) and `missed` (lines the router reports
as lost). After a router reboot the gap is the time the router was away. A busy router that
loses lines between two good reads records no gap.

## Rights

- **Needed:** `log read` (rpcd ACL v6 or later, already set up by the integration). Without it
  the Wi-Fi area of the score has no coverage and never reads healthy, and the panel says
  *Log: kein Leserecht*.
- **Not needed:** no `subscribe` right, no new ubus objects, no SSH commands. The integration
  makes no ACL change in this release.

## Limits

- Not realtime in the strict sense: up to one poll interval delay (see above).
- The log ring buffer of the router is small. On a very busy router lines can be lost between
  two polls; the read size adapts (100 to 700 lines) and a gap is recorded after failed reads.
- Signal strength is a snapshot per poll, not a history.
- No DNS probe: DNS trouble is seen only from dnsmasq log lines.
- No per-client metrics (online time, link quality) in this release.
- A recommendation is text only. It never changes anything on a router.

## Test scenarios

| # | Scenario | Tests |
|---|---|---|
| 1 | 8 reconnects in 10 min | `test_net_rt_log.py::test_scenario_1_reconnects_in_ten_minutes_with_reason_category`, `test_net_wifi.py::test_reconnect_storm_with_weak_signal_confirms_the_cause` |
| 2 | Normal roaming, no false alarm | `test_net_rt_log.py::test_scenario_2_steering_roam_is_no_alarm`, `test_net_wifi_review.py::test_m4_ping_pong_roaming_counts_no_reconnect` |
| 3 | Roam flapping between two APs | `test_net_rt_log.py::test_scenario_3_roam_flapping_with_reason_lines`, `test_net_wifi.py::test_roam_flapping_with_usteer_is_observed` |
| 4 | AP outage with 12 clients | `test_net_rt_scenarios.py::test_scenario_4_ap_outage_with_12_clients_is_one_root` |
| 5 | One unstable ESP32 among quiet clients | `test_net_rt_scenarios.py::test_scenario_5_*` (5 tests) |
| 6 | LAN uplink flapping with client drops | `test_net_rt_scenarios.py::test_scenario_6_*` (6 tests) |
| 7 | Shared DNS failure | `test_net_rt_scenarios.py::test_scenario_7_shared_dns_failure_is_one_event_not_per_client` |
| 8 | Several APs at once | `test_net_correlation.py::test_ak2_all_routers_down_is_one_lan_incident`, `::test_staggered_polls_settle_into_one_root` |
| 9 | Dedup | `test_net_rt_log.py::test_scenario_9_lines_read_twice_count_once`, `test_net_infra.py::test_scenario_duplicate_polls_and_lines_count_once` |
| 10 | Missing event data | `test_net_rt_scenarios.py::test_scenario_10_no_right_to_read_the_log`, `test_net_wifi.py::test_missing_log_lowers_coverage_and_never_reads_healthy` |
| 11 | Router and HA restart | `test_net_rt_scenarios.py::test_scenario_11_log_gap_after_a_router_reboot`, `test_net_engine.py::test_save_and_restart_restore_everything` |
| 12 | Log read fails and comes back | `test_net_rt_scenarios.py::test_scenario_12_log_read_fails_and_comes_back` |

## Recommendations per cause

The panel shows one recommendation per cause. The engine sends the key
`recommendation_key` (`rec_<cause>`); the German text lives in the panel, the
English text is listed here. A recommendation is text only: it never changes
anything on a router.

| Key | Recommendation |
|---|---|
| `rec_ap_full` | Spread the clients over more access points or raise the client limit of the AP. |
| `rec_attack` | Look for unknown devices; change the Wi-Fi password if needed. |
| `rec_auth` | Check the Wi-Fi password and the encryption on the client. |
| `rec_band_steering` | Check the band steering settings; pin the client to one band if needed. |
| `rec_client_driver` | Update the driver or firmware of the client. |
| `rec_client_power_save` | Turn off Wi-Fi power saving on the client (for example ESPHome `power_save_mode: none`). |
| `rec_client_side` | Other clients on the same radio are stable: check the device, its power supply and where it stands. |
| `rec_coverage` | Check AP placement or transmit power; add another AP if needed. |
| `rec_dhcp_server` | Check the DHCP server (dnsmasq/odhcpd) on the gateway. |
| `rec_dns_resolution` | Check the upstream DNS servers and the WAN link of the gateway. |
| `rec_interference` | Check the channel and sources of interference; pick a less busy channel. |
| `rec_ip_conflict` | Find the device with a fixed IP inside the DHCP range and change its address. |
| `rec_lan_unreachable` | Check the link between Home Assistant and the network (switch, cable, HA host). |
| `rec_mac_filter` | Check the MAC filter of the Wi-Fi network. |
| `rec_mass_disconnect` | Check the AP's system log for a radio restart, DFS radar or a power cut. |
| `rec_overlapping_coverage` | Reduce AP overlap (transmit power) or tune the roaming thresholds. |
| `rec_pool_exhausted` | Enlarge the DHCP pool or shorten the lease time. |
| `rec_port_flap` | Replace the cable and plugs on the port; check the other end and its power supply. |
| `rec_power_supply` | Check the power supply of the device (adapter, PoE budget). |
| `rec_psk_changed` | Was the Wi-Fi password changed? Then enter it again on the clients. |
| `rec_psk_wrong` | Enter the Wi-Fi password again on the client. |
| `rec_radio_change` | DFS radar or automatic channel choice; if it happens often, pick a non-DFS channel. |
| `rec_radio_restart` | Check the AP's system log for radio restarts. |
| `rec_roaming` | Check the roaming thresholds and the transmit power of the APs. |
| `rec_router_reboot` | Find the reason for the reboot in the system log (power, watchdog, update). |
| `rec_router_unreachable` | Check power and cable of the router; is its uplink port up? |
| `rec_sae_mismatch` | Check whether the client supports WPA3/SAE; otherwise use WPA2/WPA3 mixed mode. |
| `rec_static_ip` | Remove the fixed IP setting on the client or make it fit the network. |
| `rec_steering` | Check the steering settings (usteer). |
| `rec_uplink_config` | Check the uplink configuration (VLAN, bridge). |
| `rec_uplink_down` | Check the uplink cable and the switch port in front of it. |
| `rec_vlan` | Check the VLAN assignment of the Wi-Fi network or port. |
| `rec_wan_down` | Check the modem and the provider status; check the WAN cable. |
| `rec_weak_signal` | Check the signal: move the AP closer, align the antenna, use 2.4 GHz if needed. |
| `rec_wrong_network` | Check that the client is connected to the right Wi-Fi network. |
