# Installation — OpenWrt Router Integration

## Voraussetzungen

**Home Assistant:** Version **2026.2.0** oder neuer.

**OpenWrt-Router** (19.07+, getestet bis 25.x) mit laufendem `rpcd` und `uhttpd`:

```sh
# OpenWrt 23.x und älter (opkg)
opkg update && opkg install rpcd rpcd-mod-rpcsys
# OpenWrt 24.10+/25.x (apk)
apk update && apk add rpcd rpcd-mod-rpcsys

uci set rpcd.@rpcd[0].socket='/var/run/ubus/ubus.sock'
uci set rpcd.@rpcd[0].timeout=30
uci commit rpcd && service rpcd restart
```

Die benötigte rpcd-ACL (`/usr/share/rpcd/acl.d/ha-openwrt-router.json`) kann die
Integration beim Setup **automatisch deployen** (Checkbox im Setup-Assistenten,
kein SSH nötig) — Details und manuelle Alternative im [README](README.md).

## Installation über HACS (empfohlen)

Die Integration ist (noch) nicht im HACS Default Store — Installation als Custom Repository:

1. HACS → rechts oben ⋮ → **Custom repositories**
2. Repository: `https://github.com/magicx78/ha-openwrt-router` · Typ: **Integration** → Add
3. HACS → „OpenWrt Router" suchen → **Download**
4. Home Assistant neu starten

Updates erscheinen danach automatisch in HACS, sobald ein neues Release getaggt ist.

## Manuelle Installation

1. Aktuelles Release laden: https://github.com/magicx78/ha-openwrt-router/releases/latest
2. Ordner `custom_components/openwrt_router/` nach `<ha-config>/custom_components/` kopieren
3. Home Assistant neu starten

## Einrichtung

**Einstellungen → Geräte & Dienste → Integration hinzufügen → „OpenWrt Router"**

1. Host/IP, Port, Protokoll (HTTPS Self-Signed für die meisten Router), Benutzer
   (üblicherweise `root`) und Passwort eingeben — die Verbindung wird vor dem
   Speichern getestet.
2. Optional: Fritz!Box-DSL-Modem und/oder Managed Switch einbinden.
3. Capability-Checkliste prüfen; fehlende ubus-Berechtigungen auf Wunsch
   automatisch einrichten lassen.

Mehrere Router/APs: einfach weitere Einträge derselben Integration anlegen —
das Topology-Panel (Seitenleiste „Network Topology") aggregiert alle automatisch.

## Fehlersuche

- **Debug-Logging:**
  ```yaml
  logger:
    logs:
      custom_components.openwrt_router: debug
  ```
- Router-seitige Diagnose: [ROUTER_DIAGNOSTICS.md](ROUTER_DIAGNOSTICS.md)
- SSH-Fallback/Schlüssel: [SSH_SETUP.md](SSH_SETUP.md)
- Bekannte Einschränkungen: [PROGRESS.md](PROGRESS.md) § Bekannte Einschränkungen

---

*Hinweis: Die frühere Version dieser Datei beschrieb das Claude-Code-Entwicklungssetup —
jetzt unter [docs/CLAUDE_CODE_SETUP.md](docs/CLAUDE_CODE_SETUP.md).*
