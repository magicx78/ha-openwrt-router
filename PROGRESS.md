# PROGRESS — OpenWrt HA Integration

Entwicklungsprotokoll · Letzte Session: 2026-07-03 · Aktuell: **v1.20.0**

> Detaillierte Session-Protokolle bis v1.13.0 liegen in der Git-Historie dieser Datei;
> vollständige Release-Details in [CHANGELOG.md](CHANGELOG.md).

---

## Status: v1.20.0 — HA-Kompatibilitäts-Modernisierung (Branch `fix/ha-2026-8-modernization`)

Review der Integration gegen HA-Core-Standards Stand Juli 2026 (aktuell: HA 2026.7):

- **Kritisch behoben:** `DataUpdateCoordinator` bekommt `config_entry=` explizit —
  die implizite ContextVar-Übergabe entfällt in HA 2026.8.
- Toter Sync-Fallback `register_static_path` im Panel entfernt (seit HA 2024.6 obsolet).
- `manifest.json`: `integration_type: hub`; HACS-Floor ehrlich auf **2026.2.0**
  (Code brauchte real schon ≥2024.11).
- **de.json** neu; strings.json/en.json jetzt durchgängig englisch (waren gemischt).
- Blueprint auf Plural-Syntax (`triggers:`/`actions:`/`action:`) + `source_url` + `min_version`.
- CI: Release-Workflow gegated (test + hassfest), Test-Matrix 3.13/3.14
  (Py 3.12 löste nur HA 2024.x auf; HA 2026.3+ braucht Py ≥3.14),
  ha-compat testet jetzt wirklich die gemeldete Latest-HA (Version gepinnt).
- CHANGELOG-Lücke [1.19.0] nachgetragen; README-Badges dynamisch.

Nicht betroffen (verifiziert): Device-Tracker-Deprecations 2026.6
(battery_level/location_name), `show_advanced_options`, Update-Listener+Reload-Pattern.

---

## Meilensteine

| Version | Zeitraum | Inhalt |
|---------|----------|--------|
| **v1.20.0** | 2026-07 | HA-Kompatibilität 2026.8, de.json, CI-Modernisierung |
| **v1.19.0** | 2026-05 | rpcd-Session-Leak-Fix (Ursache des Router-OOM), ACL-Re-Validierung |
| **v1.18.0** | 2026-04 | Subprocess- + Panel-Lifecycle-Hardening, 24h-Prod-Sampler |
| **v1.17.x** | 2026-04 | Error-Sensor, Outage-Notifications, sshpass-Security-Fix, dynamische Sensoren default-off |
| **v1.16.0** | 2026-04 | HTTPS-Support (http / https / https-insecure) |
| **v1.15.x** | 2026-04 | rpcd-Memory-Leak-Fix (file/exec raus), Capability-Checklist im Config Flow, SSH-Fallback-Erkennung, adaptives Polling |
| **v1.14.x** | 2026-04 | Wiring-View, Traffic-View, Mobile-View |
| **v1.10–1.13** | 2026-04 | Topology-Panel-Ausbau: 5 Views, Minimap, Kontextmenü, Event-Timeline, VLAN-Badges (+Stale-Cache), CPU-History |
| **v1.0.x** | 2026-03 | Erstrelease: Sensoren, Switches, Buttons, Device Tracker, Update-Management |

---

## Architektur-Kurzreferenz

- `api.py` — alle HTTP/SSH-Calls (ubus JSON-RPC, `_safe_subprocess_exec` für SSH-Fallback)
- `coordinator.py` — 60s-Poll (adaptiv: 120s bei CPU >100%, 300s bei SSH-Fallback),
  Event-/DSL-/CPU-History, Feature-Detection beim ersten Refresh
- `topology_mesh.py` / `topology_panel.py` — Multi-Router-Aggregation + Sidebar-Panel
- Entities lesen ausschließlich aus `coordinator.data`; runtime_data (typisiert) am Entry

## Bekannte Einschränkungen

| Einschränkung | Ursache | Impact |
|---|---|---|
| Event-History überlebt HA-Restart nicht | `deque` in-memory | Ereignisse gehen beim Neustart verloren |
| `signal=null` für manche Clients | `iw station dump` bracket-format | Signal-Wert fehlt, kein Fehler |
| Ghost-Mode akkumuliert nicht über Restarts | keine Persistenz | frisch gestartete Instanz zeigt keine Ghost-Devices |
| Panel-Static-Path bleibt bis HA-Restart gebunden | aiohttp-Router ist append-only | toter Endpoint nach letztem Unload (View antwortet 410) |

---

## Deployment

```bash
git pull   # main
git push
```

Panel-URL: `http://10.10.10.165:8123/openwrt-topology`
Router-ACL: `/usr/share/rpcd/acl.d/ha-openwrt-router.json` auf Gateway + APs
Offene Arbeiten: siehe [TODO.md](TODO.md)
