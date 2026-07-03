# TODO — ha-openwrt-router

Stand: 2026-07-03 · Version: v1.20.0

---

## Backlog

### HA-Modernisierung (Folgearbeiten aus dem Kompatibilitäts-Review 2026-07)

- [ ] **Repairs statt persistent_notification** — SSH-Fallback- und Outage-Meldungen
      (coordinator.py, `async_create`/`async_dismiss`-Call-Sites) auf `issue_registry`
      umstellen: `ir.async_create_issue()` mit `translation_key`; SSH-Fallback als
      fixable Issue (RepairsFlow → `acl_provisioning.ensure_acl()` erneut ausführen),
      Outage als non-fixable Issue mit `ir.async_delete_issue()` bei Recovery.
      Benötigt `issues:`-Sektion in strings.json + en.json + de.json.
- [ ] **Notification-/Event-i18n** — Hardcodierte deutsche Texte im Coordinator
      (SSH-Fallback-Notification, Outage-Notification, Event-Timeline-Meldungen
      „WAN verbunden/getrennt", „CPU-Last erhöht", …) übersetzbar machen.
      Hängt sinnvoll mit der Repairs-Migration zusammen.
- [ ] **`topology_card`-WIP-Modul** — Import ist seit v1.19.0 geguardet; Modul
      fertigstellen oder Guard + Referenzen entfernen.
- [ ] Optional: **pytest-homeassistant-custom-component** als zusätzliche
      Smoke-Test-Ebene (echte `hass`-Fixture für Setup/Unload/Config-Flow) —
      bestehende Mock-Suite bleibt die Basis.

### HACS / Release

- [ ] **HACS Default Store — Neuanlauf.** PR hacs/default#6421 wurde am 2026-03-21
      ungemerged geschlossen. Vor Neu-Einreichung: aktuellen HACS-Submission-Prozess
      prüfen (hacs.xyz/docs/publish), PR an `home-assistant/brands` stellen
      (Voraussetzung fürs Default-Listing), dann neu einreichen.
      Bis dahin: Installation als Custom Repository (siehe INSTALL.md).

### Betrieb / Validierung

- [ ] **Prod-Validierung v1.19/v1.20** — 24h-RSS/rpcd-Beobachtung auf dem
      Produktiv-Gateway nach dem Session-Leak-Fix (Vergleich gegen
      `diagnostics/prod-24h-baseline.jsonl`, Sampler: `scripts/_prod_24h_sample.sh`).
- [ ] **Persistente Event-History** — `deque` ist in-memory; Events überleben
      keinen HA-Restart (Store-Helper oder JSON-Datei).

### Topology Frontend (Wunschliste, unverändert offen)

- [ ] Per-Client Traffic Chart — RX/TX-Verlauf pro WLAN-Client
- [ ] Shift+Click Multi-Device Compare
- [ ] Bridge-FDB-Visualisierung im PortStrip (welcher Port sieht welche MACs)

### Entities / Features (Roadmap)

- [ ] Per-Client Online-Zeit
- [ ] Link-Quality-Metriken (Signal/Noise pro Radio)
- [ ] Parental Control Support

---

## Erledigt (Auszug — Details in CHANGELOG.md)

- [x] v1.20.0 — HA-Kompatibilitäts-Review: `config_entry=` an DataUpdateCoordinator
      (HA-2026.8-Deadline), toter `register_static_path`-Fallback entfernt,
      `integration_type: hub`, HA-Floor 2026.2.0, deutsche Übersetzung (de.json),
      Blueprint auf Plural-Syntax + source_url, Release-Workflow gegated,
      CI-Matrix 3.13/3.14 (3.12 löste HA 2024.x auf), ha-compat pinnt echte Latest-HA
- [x] v1.19.0 — rpcd-Session-Leak-Fix (destroy bei Re-Login), ACL-Re-Validierung,
      Cache für ACL-geblockte Methoden
- [x] v1.18.0 — Subprocess- + Panel-Lifecycle-Hardening, 24h-Prod-Sampler
- [x] v1.17.x — Error-Sensor + Outage-Notifications, sshpass-Security-Fix (`-e` statt argv)
- [x] v1.16.0 — HTTPS-Support (http / https / https-insecure)
- [x] Fixtures `tests/fixtures/router_*.json`, brand/icon 256×256,
      hassfest/HACS/tests/ha-compat/release CI-Workflows, GitHub Releases
