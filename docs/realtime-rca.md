# Realtime events and root cause (1.41.0)

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
