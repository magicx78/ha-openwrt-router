# TODO — ha-openwrt-router

Stand: 2026-10-28 · Version: v1.39.0

---

## Backlog

### Nach Installation von 1.39.0 (Plan `docs/plans/2026-10-28-ssh-polling-und-audit.md`)

Alles lesend, Installation und HA-Neustart nur nach OK.

- [ ] **Diagnose** eines Routers herunterladen und nach MAC-/IP-Mustern,
      Hostnamen und SSIDs durchsuchen (A5).
- [ ] **Panel als Nicht-Admin** öffnen (403-Hinweis, kein Sidebar-Eintrag),
      Option „allen Benutzern anzeigen“ an/aus ohne Neustart; Sitzungsablauf
      ohne Request-Schleife (A13, C11 nie im Browser geprüft).
- [ ] **Rollen im Panel:** Gateway + zwei APs; Kanten vorhanden (A12).
- [ ] **Poll-Versatz:** im Debug-Log pollt jeder Router weiter, mit
      unterschiedlichen Zeitpunkten (A7).
- [ ] **Schnittstellen-Zähler:** `network.device status {}` liefert
      `statistics` für `br-lan`/`wan`; Raten-Sensoren nicht mehr 0 (A9).
- [ ] **ARP:** Größe von `/proc/net/arp` am Gateway, `getHostHints`-Antwort (A10).
- [ ] **„Nach Updates suchen“** auf Gateway und AP: Dauer, Ausgabe von
      `apk list -u` bzw. `opkg list-upgradable`, Fehlermeldung ohne SSH (A6).
- [ ] **Tracker:** nach HA-Neustart melden abwesende Clients `not_home` (A3).
- [ ] **Recorder:** Datenbankwachstum über einen Tag vergleichen (A8).
- [ ] **Dev-Skript `scripts/_add_topology_card.py`** liest das entfernte
      Attribut `topology_snapshot` – löschen oder auf das Panel umstellen.
- [ ] **Frontend-Folgen aus A12:** veraltete (`stale`) Clients/Kanten
      ausgrauen, `lldp_duplicates` als Parallel-Link zeigen, bei mehreren
      Gateways bewusst wählen statt `routerNodes[0]`.
- [ ] Optional: Button „Veraltete Tracker entfernen“ (wie `fritz`).

### Fehlerkorrektur nach 1.37 (Plan `docs/plans/2026-10-27-fehlerkorrektur-nach-1.37.md`)

- [x] P1/P2/P6 (v1.37.5), P3 + ACL v7 (v1.38.0), P4 (v1.38.1), P5 + B2 (v1.38.2),
      B1 (drei Config-Entries ohne Router entfernt).
- [ ] **B3: rpcd-Speichermessung mit ACL v6 auswerten** und ins Prüfprotokoll
      des Plans eintragen.
- [ ] **Hardware-Prüfung nach dem Update** (lesend): ACL v7 auf Gateway und APs
      verteilt, CPU-Sensor gegen `cat /proc/loadavg` + `nproc`, „WLAN neu laden“
      wendet an, Kanal aus dem `config`-Block, HA-Log nach Neustart ohne
      Root-Warnungs-Serie, ohne „network.reload“-Warnung und ohne
      `device_registry`-Deprecation.
- [ ] **Panel-Sichtprüfung** in HA: Clients mit privater MAC ohne Hersteller
      (Liste, Name „Privat-MAC …“, Detailansicht).
- [ ] **Release v1.38.2 prüfen:** Release-Text = CHANGELOG-Abschnitt, und ob
      HACS ihn im Update-Dialog zeigt (in der HACS-Doku nicht beschrieben).
- [ ] **WAN-Entities auf `ap2`/`ap4`** stehen weiter auf `unknown` (E3: kein
      Registry-Eingriff, `enabled_default` wirkt nur bei neuen Entities) –
      bei Bedarf in HA von Hand deaktivieren.
- [ ] **Befund 13:** zwei wiederhergestellte Device-Tracker mit altem AP-Namen in der Entity-ID
      (`unavailable`, `restored: true`) – Ursache klären, Registry-Eingriff
      nur mit OK.
- [ ] **Befund 14:** `uci_section` im Pfad `network.wireless status` (netifd
      liefert `section` neben `ifname`). Ein Fix ändert die `unique_id` der
      WLAN-Schalter betroffener Router – braucht eine eigene Entscheidung.
- [ ] **GitHub-Repo-Beschreibung** ohne Versionsnummer (HACS zeigt „v1.4.0“) –
      nur mit OK.

### HA-Modernisierung (Folgearbeiten aus dem Kompatibilitäts-Review 2026-07)

- [x] **Outage als Repairs-Issue** (v1.29.0) — `fleet.FleetOutageTracker` +
      `issues.py`; gleichzeitige Ausfälle aller Router → ein `lan_unreachable`.
- [ ] **SSH-Fallback als Repairs-Issue** — die SSH-Fallback-Meldung (coordinator.py,
      `async_create`) auf `issue_registry` umstellen, als fixable Issue
      (RepairsFlow → `acl_provisioning.ensure_acl()` erneut ausführen). `issues.py`
      und die `issues:`-Sektion in strings.json/en.json/de.json gibt es seit v1.29.0.
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

### LLDP-Nachlese (aus dem Merge-Review von PR #14, 2026-09-09)

- [ ] **OUI-Tabelle existiert doppelt** — `custom_components/openwrt_router/oui.py`
      (~667 Einträge) ist eine Handkopie von `OUI_TABLE` in
      `frontend/topology/src/api.ts`. Eine Quelle festlegen und die andere
      generieren, sonst driften die beiden auseinander. Ist schon passiert:
      `d2:4e:4f` fehlte ab v1.37.0 nur in `oui.py`, das Panel zog in v1.38.2 nach.
- [ ] **Ungenutzte LLDP-Konstanten** in `const.py` aufräumen:
      `LLDP_CLI_CHECK_CMD`, `LLDP_INIT_ENABLED_CMD`, `CAP_LLDP_NEIGHBORS`
      (dupliziert als String-Literal in `config_flow._LLDP_CAP`), dazu
      `SOURCE_ARP/FDB/DHCP/OUI`, `CLIENT_KEY_VLAN_IDS`, `CONNECTION_TYPE_WIRED`.
- [ ] **Checklist-Hinweis präzisieren** — LLDP braucht nicht nur `lldpd`,
      sondern auch SSH-Zugang. Auf einem Router mit sauberer ACL v5 **ohne**
      Dropbear-Login bleibt LLDP dauerhaft `unavailable`, der Hinweistext nennt
      aber nur die lldpd-Installation.
- [x] **`ruff` in der CI pinnen** — `tests.yaml` und `release.yaml` installieren
      `ruff==0.17.3`.

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

- [x] v1.38.x — CPU-Last pro Kern + rpcd-ACL v7, Kanal aus dem `config`-Block,
      AP-Interfaces im SSH-Fallback, WAN-Sensoren auf Routern ohne WAN
      standardmäßig aus, Panel ohne OUI-Hersteller bei privaten MACs,
      Release-Texte aus CHANGELOG.md
- [x] v1.37.x — `random_mac`, rpcd-`rc/list`-Leck umgangen, Banderkennung
      (UCI `band`, 6/60 GHz), Panel-Footer/WAN-Rate/HA-Namen, Log-Hygiene,
      `async_get_device`-Deprecation
- [x] v1.29–v1.36 — Repairs (Ausfall, RAM-Druck, Kanalkonflikt), Schalter
      erweiterte WLAN-Sensoren, Kanalplan, Router-Log + ACL v6, DFS-Events,
      DHCP-Pools, klebende/instabile Clients
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
