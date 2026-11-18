# Plan: Enterprise Core (Router-Identität, Capabilities, Configuration API v1)

<!-- Ablage: docs/plans/2026-11-17-enterprise-core.md · Branch claude/enterprise-core-49ade2
     (Basis main @ 0dc20cd). Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens.
     Rollen statt Namen. -->

Kennzeichnung wie in den anderen Plänen: **verifiziert** (mit `datei:zeile`, Stand `0dc20cd`),
**Entscheidung** (vom Master vorgegeben, hier nur begründet), **Nachtrag A–H / 1–4** (zwei
Vertragsnachträge des Masters nach Abgleich mit dem Plan von `config-manager`),
**[Architekt]** (kleine Entscheidung beim Ausarbeiten, vom Master überstimmbar), **offen**
(Abschnitt 10).

Der Vertrag selbst (Signaturen, Felder, Fehlertabelle, Beispiele, Abgleich mit
`config-manager`) steht in [`docs/dev/configuration-api-v1.md`](../dev/configuration-api-v1.md).
Dieser Plan erklärt, warum er so aussieht, und wie er eingebaut wird.

## Status

- **Stand:** 2026-11-18 · **Version 1.44.0** (Branch `claude/enterprise-core-49ade2`,
  nicht gemergt, kein Tag). Schritte 1–6 aus Abschnitt 8 sind gebaut und verdrahtet,
  dazu aus Schritt 8: gestufte ACL v9 als Angebot (Verteilen über den Core mit Freigabe),
  SSH-Host-Key-Pinning je Router mit Bestätigung statt stillem TOFU
  (`core_security.py`), Option `config_backup_enabled` (Standard aus), `rf.*` aus der
  verteilten ACL, Andocken von Security Center / Netzwerkdiagnose / WiFi RF
  (Event-Präfixe, Capability-Detektoren, Guard-Aktionen, `subscribe`) und der
  Panel-Container „Enterprise“. Die offenen Fragen Q3–Q6 des Vertrags sind entschieden
  (Vertrag 19.4). Nutzerdoku: `docs/enterprise-core.md`.
- **Noch nicht gebaut:** Schritt 7 (echter Provider aus `config-manager`), Restore,
  Oberfläche für Freigaben und SSH-Pins (nur Python-API).
- **Parallel:** Die Sitzung `config-manager` baut den Provider (Collector, UCI-Snapshots,
  Maskierung, Drift, Diff, Restore-Dry-Run) gegen diesen Vertrag.
- **Last:** 0 zusätzliche Router-Aufrufe je Poll und beim Setup (die gestufte ACL wird
  beim Start mit demselben `file/read` erkannt, das `ensure_acl` ohnehin macht). Router
  nur auf Admin-Aktion: ACL-Antrag 1× `file/read`, Verteilen `file/read` + Sicherung +
  Schreiben + rpcd-Neustart (oder ein SSH-Befehl über den Pin).
- **Regeln:** 0 neue Router-Aufrufe je Poll, keine Routeränderung, kein Version-Bump des
  Config-Entries, nie automatisches Zusammenführen.

---

## 1. Bestandsaufnahme

### 1.1 Identität eines Routers heute (verifiziert)

| Ort | Schlüssel | Fundstelle |
|---|---|---|
| Gerät im Device Registry | `identifiers={(DOMAIN, entry.entry_id)}` | `binary_sensor.py:135`, `button.py:157`, `device_tracker.py:464` u. a. |
| Entity-`unique_id` | `f"{entry_id}_<suffix>"` | alle Plattformen, z. B. `{entry_id}_unstable_clients` |
| `entry.unique_id` | `f"{host}_{port}"` (bewusst nicht die MAC, die oft leer ist) | `config_flow.py:647-670` |
| `configuration_url` | aus Host/Port | `button.py:162`, `button.py:308` |
| Topologie-Knoten | `mac or f"{hostname}_{host_ip}"` | `topology_diagnostic.py:276-286` |
| Net-Engine, Fleet, Client-Engine | Schlüssel `entry_id` | `fleet.py:131-136`, `client_engine.py:452-617` |
| Config-Entry-Version | `VERSION = 2`, `MINOR_VERSION = 2` | `config_flow.py:179-182` |

**De facto ist die `entry_id` die Router-Identität.** Die IP steckt nur in `entry.unique_id`,
`configuration_url` und (bei leerer MAC) in der Topologie-Knoten-ID.

### 1.2 Was bei einem IP-Wechsel heute bricht (verifiziert)

- Es gibt **keinen Reconfigure-Flow** (`config_flow.py`: nur `user`, `checklist`, `reauth*`,
  Options-Flow ohne Host). Ein neuer Host geht nur über „Eintrag löschen, neu anlegen“.
- Neuer Eintrag ⇒ neue `entry_id` ⇒ neues Gerät, neue Entities (Recorder-Historie hängt am
  alten `unique_id`), neue Schlüssel in Net-Engine, Fleet und Client-Engine (Event-Historie
  getrennt), Automationen mit alten Entity-IDs brechen.
- Die Topologie-Knoten-ID ändert sich, wenn `system board` keine MAC liefert (der Normalfall).
- Ein Backup-Katalog, der an Host oder `entry_id` hinge, verlöre die Zuordnung.

### 1.3 Identitätsdaten, die schon gepollt werden (verifiziert, keine neue Abfrage nötig)

- `coordinator.data.router_info`: model, hostname, release (version, revision, target),
  mac (meist leer), board_name, kernel, platform_architecture. Erster Poll und jeder
  `BOARD_REFRESH_CYCLES = 10`. Poll (`coordinator.py:695-705`, `const.py:71`).
- `ap_interfaces` / `sta_interfaces` (bssid, mac), `network_interfaces`, `wifi_radios`.
- `features` (`FEATURE_*`, `const.py:155-163`, `FEATURE_HAS_SERVICES` `const.py:564`),
  einmal beim ersten Refresh über `api.detect_features()` ermittelt.
- `api.uses_ssh_fallback` (`api.py:1312`), `lldp_status`, `log_status`.
- `updates_available["package_manager"]` (apk/opkg), **nur nach einer Update-Prüfung**.
- **Keine Seriennummer** wird abgefragt.

### 1.4 Was es nicht gibt

Keinen Backup-Manager, keine HA-Services, keine Websocket-Befehle. HTTP-Views prüfen Admin über
`request[KEY_HASS_USER].is_admin` (`topology_panel.py:150`, `:216-233`).

### 1.5 Wiederverwendete Muster

| Muster | Ort | Nutzung |
|---|---|---|
| Flottenweites Objekt, Lazy-Getter, isoliertes Setup | `client_engine.py:452-617` (`hass.data[f"{DOMAIN}_client_stability"]`) | `hass.data[DATA_ENTERPRISE_CORE]` |
| Store + `asyncio.Lock` + verzögertes Speichern + Flush beim letzten Unload | `client_engine.py`, `net_engine.py:425-601` | Registry-, Katalog-, Audit-Store |
| Events mit `Severity` info/warning/critical, Ring, Retention | `net_events.py:79-90`, `EventRing` | `CoreEvent.severity` nutzt **dieselbe** `Severity` |
| Bus-Event-Namen `f"{DOMAIN}_<thing>_event"` | `const.py:194`, `:527-532`, `:598` | `openwrt_router_core_event` |
| Logbuch | `logbook.py:26` | später: Core-Events beschreiben |
| Redaction | `diagnostics.py`, `DIAGNOSTICS_REDACT_KEYS` / `DIAGNOSTICS_TO_REDACT` (`const.py:253-283`) | `core_masking` nutzt `DIAGNOSTICS_REDACT_KEYS` mit |
| MAC-Helfer | `mac_utils.is_mac`, `is_locally_administered` | `normalize_mac`, Fingerprint |

---

## 2. Architekturentscheidungen (mit Begründung)

1. **Router-ID** `rtr_<32 hex>`, Standardwert `uuid5(ROUTER_ID_NAMESPACE, entry_id).hex`.
   Grund: braucht keinen Routerkontakt, ist wiederholbar, übersteht eine halb fertige
   Migration und sogar den Verlust des Registry-Stores. Sie ist ein **zusätzlicher**
   Schlüssel: `entry.unique_id`, Geräte-Identifier, Entity-`unique_id`s und die
   Config-Entry-Version bleiben. Der Store bildet `entry_id → router_id` ab und weicht vom
   Standard nur nach einer ausdrücklichen Adoption ab (Punkt 3).
   Namespace fest: `5fc97c09-217a-4ccb-af32-d954b049fecf` (Test pinnt ihn).
2. **Identitätsdatensatz** `RouterIdentity` mit `HardwareFingerprint` (board_name, model,
   universell verwaltete Unicast-MACs) und `IdentityStatus`:
   `unverified` (noch keine Daten, z. B. Eintrag in setup_retry), `confirmed`,
   `changed` (Board/Model anders oder keine MAC-Überschneidung ⇒ Hardwaretausch vermutet),
   `duplicate_suspected` (zwei Einträge teilen Fingerprint-MACs ⇒ geklonte Konfig oder
   dasselbe Gerät doppelt). Hostname- oder IP-Wechsel ändern die Router-ID nie. Werksreset
   (Hostname wieder „OpenWrt“, gleiche MACs/Board) behält ID und `confirmed`, erzeugt
   `router.identity_changed` (info). Nichts wird automatisch zusammengeführt.
   Grund: Identität darf nie von veränderlichen Netzwerkdaten abhängen; Zweifel werden
   sichtbar gemacht, nicht still aufgelöst.
3. **Entfernen ⇒ `orphaned`.** Historie und Versionen bleiben (Ordner wandert nach
   `removed/<router_id>/`, nie automatisch gelöscht). Ein neuer Eintrag bekommt eine neue
   Router-ID; `adoption_candidates(entry_id)` listet Waisen mit passendem Fingerprint,
   `async_adopt(entry_id, orphan_router_id, actor=…)` bindet die alte ID an den neuen Eintrag
   (Admin-Benutzer, auditiert). Grund: Neu-Anlegen ist heute der einzige Weg zu einem neuen
   Host; Adoption rettet die Historie ohne Raten.
4. **Registry** (`RouterRegistryProtocol`): Lookup in beide Richtungen, Capabilities,
   Erreichbarkeit aus `coordinator.last_update_success`, Verbindungsdaten (ohne
   Zugangsdaten), Firmware, Diagnosequellen, benötigte Rechte. Der Core gibt Providern eine
   `RouterConnection` mit der **bestehenden** `OpenWrtAPI` und dem Coordinator des Eintrags.
   Grund: Provider sprechen nie selbst mit dem Router; alle Router-I/O bleibt in `api.py`.
5. **Capabilities** als `Capability`-StrEnum mit Punktnamen, `CapabilityStatus` mit Zustand,
   Grundcode, Quelle, Rechten, Zeitpunkt und (Nachtrag F) `detail`-Mapping. Ermittlung aus
   `coordinator.data` und API-Flags, neu bewertet, wenn sich eine billige Signatur ändert
   (Firmware-Version, `features`, Transport, Paketmanager, Log/LLDP-Status). `FEATURE_*`
   wird 1:1 abgebildet (`FEATURE_CAPABILITIES`); **[Architekt]** `data.uci` neu, weil
   `FEATURE_UCI_AVAILABLE` existiert.
   **Nachtrag F:** Die Router-seitigen `config.*`-Proben (`config.cgi_backup`,
   `config.ssh_root`, `config.uci_read` mit `detail` je Config, `config.packagelist`)
   liefert der Provider über `async_probe(conn)`. Der Core ruft sie beim Setup, nach einer
   ACL-Neuverteilung und nach einem Firmware-Wechsel, **nie im Poll**. Ohne Provider
   `unavailable`/`no_provider`; mit `config_backup_enabled = false` `unavailable`/`disabled`.
   Namensräume `security.*`, `diag.*`, `log.*` sind reserviert; Module registrieren eigene
   Capability- und Event-Namen unter einem Präfix.
6. **Configuration API** versioniert (`CONFIGURATION_API_VERSION = 1`,
   `CONFIGURATION_API_MIN_VERSION = 1`), Zugriff über `async_get_configuration_api(hass,
   version=1)`. Innerhalb v1 nur additive Änderungen. Lesende Operationen laufen parallel,
   schreibende je Router serialisiert. Grund: mehrere Module (Firmware, Self-Healing, Time
   Machine) rufen gleichzeitig; ein Router darf nie zwei Schreibvorgänge zugleich sehen.
7. **Versions-Metadaten** `BackupRecord` (= Version, Alias `VersionRecord`) mit
   `BACKUP_METADATA_VERSION = 1` und Migrationskette (`METADATA_MIGRATIONS`); neuere Version
   ⇒ `BackupMetadataError`. **Nachtrag A/B:** Der Core besitzt **Index und Bytes**
   (`VersionStore`); der Provider erzeugt und analysiert Artefakte nur. Neue Felder:
   `last_seen_at`, `status`, `error_class`, `fetch_method`, `content_hash`, `uci_hash`,
   `protected`, `note` (≤ 500 Zeichen, ersetzt `label`), `artifacts`
   {`archive`|`uci`|`inventory`: `ArtifactRef`}. `sha256` (Archiv) und `size_bytes`
   (Summe) sind abgeleitete Eigenschaften. Neuer Grund `release_change`.
8. **Provider-Schnittstelle** `ConfigBackupProvider` (Protocol, runtime_checkable), genau ein
   Provider, zweiter ⇒ `ProviderConflictError`. Kein Dummy-Provider im Produktivcode.
   Methoden: `supported`, `async_probe`, `async_capture`, `async_collect`, `async_validate`,
   `async_compare`, `async_detect_drift`, `async_prepare_restore`, `async_execute_restore`.
   Jede Methode bekommt einen `ProviderContext` (bereichsgebundener Leser
   `read(version_id, kind)`, Registry-Lesezugriff, Installations-Schlüssel). Kein Export,
   kein Löschen, keine Events im Provider.
9. **Zentraler Guard** `ActionGuard` ist der einzige Ort, der eine `WriteAuthorization`
   prägt (einmalig, an Router + Aktion + Bindungsprüfsumme gebunden, mit Ablauf). Wer
   handelt (Versionsspeicher, Provider), ruft vorher `guard.consume(authorization, ...)`
   (Ledger, synchron). Der Guard nimmt nur einen `VerifiedActor` an (neu gegen `hass.auth`
   geprüft, Bedrohungsmodell im Vertrag, Abschnitt 6.1).
   **Nachtrag D:** synchrone Entscheidung `authorize(action, router_id, actor, …) ->
   AuthorizationDecision(state approved|denied|pending, audit_id, authorization |
   approval_request, reason)`. Aktionen: `backup`, `protect`, `drift_ack`, `export`,
   `delete`, `prune`, `restore`, `adopt`, `acl_deploy`, dazu `<modul>.<aktion>` über
   `register_action`, `installation_key_reset`.
10. **Events und Audit** `CoreEvent`, zwei Ringe (allgemein 1000, Sicherheit 500, je 90
    Tage), persistiert, auf dem Bus als `openwrt_router_core_event` (maskiert), abfragbar
    nach Router, Typ, Zeitfenster, Korrelations-ID, Ring. Eine zentrale Maskierung
    (`core_masking`) für Audit, Bus und Diagnose. Core-Typen sendet nur der Core, auch die
    aus Provider-Ergebnissen.
    **Nachtrag G:** Typen aus `config-manager` 9.1 (Zuordnung im Vertrag, Abschnitt 15),
    Dedup-Bereich `(router_id, type, dedup_key)` mit Wiederholungszähler, Cooldown für
    Fehler 24 h, Payload ohne Werte. Audit-pflichtige Typen werden immer geschrieben.
11. **Fehlerklassen** unter `ConfigApiError(HomeAssistantError)` mit stabilem `code`.
    **Nachtrag C:** jede trägt eine `error_class` (`ErrorClass`, enthält die elf Klassen
    aus `config-manager` 12.2).
12. **Stores** (späterer Schritt): `openwrt_router.router_registry`,
    `openwrt_router.config_catalog` (Versionsindex + Drift-Bestätigungen),
    `openwrt_router.audit`, `openwrt_router.installation_key`, je Version 1 mit
    Migrate-Funktion ab Tag eins.
13. **Erweiterungspunkte** für Security Intelligence, Network Intelligence, Network Time
    Machine, Firmware Lifecycle, Self-Healing (Beispiele im Vertrag, Abschnitt 17).
14. **Versionsspeicher (Nachtrag A).** `hass.config.path("openwrt_router",
    "config_backups", <router_id>)`, Ordner 0700, Dateien 0600, atomar über `.partial` +
    Umbenennen, Indexeintrag zuletzt, alle Datei-I/O im Executor. `sweep()` beim Start:
    `*.partial` löschen, indexlose Dateien älter als 1 h nach `orphaned/`, Indexeinträge ohne
    Datei als `missing` markieren. Grenzen 50 MB je Router, 250 MB gesamt. Dedup nur für
    `scheduled`/`drift` gegen die neueste brauchbare Version desselben `backup_type` und
    Status (Vertrag 7.4): Treffer setzt nur `last_seen_at`, Ergebnis `created=False`.
    Module sehen nur die Lesesicht `VersionReadView`; Aufbewahrung führt nur der Core aus
    (`RetentionPolicy` vom Modul).
15. **Drift-Bestätigung und Installations-Schlüssel (Nachtrag E).** `DriftAck(router_id,
    drift_id, state acknowledged|known, actor, ts, note, version_id)` im Katalog-Store;
    Basis: explizit > neueste `known`-Bestätigung > neueste brauchbare Version. 32 zufällige
    Bytes in `.storage`, gelesen über `async_get_installation_key()`, nie in Audit, Bus oder
    Diagnose. Nie still neu erzeugt: Zustand `lost` ⇒ Fehler, Event, Repair-Issue; neuer
    Schlüssel nur über `installation_key_reset`, danach Re-Baseline.
16. **Export ist kritisch (Nachtrag 2.1).** Kritisch heißt „Antrag + Admin-Freigabe“, nicht
    „schreibt“: Export liest nur, legt aber alle Router-Geheimnisse im Klartext offen. Nur
    Admin-Benutzer, eine Freigabe je Download, auditiert. Ablauf `async_request_export` ⇒
    `async_approve` ⇒ `async_export_backup(approval_id, actor=…)`.
17. **Keine eigene Verschlüsselung in Phase 1 (Nachtrag 2.2).** `StorageRef.storage_format`
    (`plain-v1`) plus `encrypted: bool`. Ein unbekanntes Format ⇒
    `UnsupportedStorageFormatError`. Schutz: 0700/0600 und HA-Backup-Verschlüsselung.
18. **Restore in Phase 1 nur Prüfen (Nachtrag 2.3).** Dry Run, Kompatibilität, Vorschau und
    Export. `async_request_restore` / `async_execute_restore` bleiben im Vertrag, werfen aber
    `CapabilityUnavailableError(config.restore)`, solange der Provider `config.restore` nicht
    meldet. Später: Restore auf UCI-Ebene mit Rollback.
19. **Option `config_backup_enabled` (Nachtrag 2.4).** Schaltet die `config.*`-Capabilities
    und die ACL-Stufe. Die gestufte ACL wird je Capability **nur angeboten**; auf den Router
    geschrieben wird erst nach der einzelnen Freigabe des Nutzers (`acl_deploy`, kritisch).
    In diesem Schritt nur dokumentiert.

### 2.1 Kleine Entscheidungen beim Ausarbeiten [Architekt]

- Alle Dataclasses `frozen=True, kw_only=True, slots=True`: neue Felder verschieben nie
  Positionsargumente (additive Änderung bleibt kompatibel).
- „Backup“ und „Version“ sind dasselbe. Kennung bleibt `backup_id` (`bkp_…`),
  `BackupRecord.version_id` ist ein Alias, `VersionRecord = BackupRecord`.
- Die Protocols stehen am Ende von `core_models.py` (der Auftrag nennt genau drei
  Typmodule).
- Bindungsprüfsummen (`binding_checksum(...)`) je Aktion: `protect` (version_id,
  protected), `drift_ack` (router_id, drift_id, state), `export` (version_id, artifact),
  `delete` und `prune` (sortierte IDs), `restore` (`plan.checksum`), `adopt` (entry_id,
  orphan_router_id), `acl_deploy` (router_id, ACL-Prüfsumme), `installation_key_reset`
  (letzte `installation_key_id`), `backup` ungebunden. Jeder `consume`-Versuch verbraucht
  die Autorisierung, auch ein fehlgeschlagener.
- `RestorePlan.checksum` ist eine berechnete Eigenschaft über den **unmaskierten** Inhalt
  (sonst hätten zwei Pläne, die sich nur im WLAN-Schlüssel unterscheiden, dieselbe Summe).
- `async_actor_from_context` ist `async` (der Benutzer kommt aus `hass.auth.async_get_user`).
  Reihenfolge: `user_id` ⇒ user, sonst `module` ⇒ module, sonst `parent_id` ⇒ automation,
  sonst system. Nur ein aktiver, nicht systemgenerierter Admin-Benutzer ist `is_admin`;
  Guard und API prüfen das bei jedem Aufruf neu (`async_verify_actor`).
- Löschen durch Benutzer/Module ist **critical** (zweistufig); geschützte Versionen ⇒
  `VersionProtectedError`. Aufbewahrung läuft als eigene Aktion `prune` (mutating, nur der
  Core als System, nach `plan_retention`; geschützte und die neueste brauchbare Version
  bleiben immer). Damit ist die frühere Frage F1 gelöst.
- Nur Admin-Benutzer (`ADMIN_USER_ONLY_ACTIONS`): `protect`, `drift_ack`, `export`,
  `adopt`, `acl_deploy`, `installation_key_reset`. `backup` dürfen Admin-Benutzer,
  Automationen, Module und System; ein Benutzer ohne Admin darf keine mutating- oder
  critical-Aktion.
- `CoreEvent.type`, `CapabilityStatus.capability`, `WriteAuthorization.action` sind `str`
  (Werte aus den Enums oder Modulnamen unter einem registrierten Präfix), damit ein Store
  Typen einer neueren Minor-Version laden kann.
- `CapabilityStatus.reason` ist `str`: Standardcodes aus `CapabilityReason` (neu:
  `disabled`, `not_probed`), Provider dürfen `provider:<code>` ergänzen.
- `ChangeKind.MODIFIED` heißt bei `config-manager` `changed`; `REORDERED` neu.
  `ConfigChange.area`/`risk` sind Strings (Klassifikation des Providers).
- `async_validate_backup` gibt den aktualisierten `BackupRecord` zurück.
- `mask_secrets` lässt `None` und `bool` stehen (Fehlen ist kein Geheimnis) und maskiert
  alles andere, auch leere Strings. `contains_secrets` ist von der Maskierung ausgenommen.
- Fristen: `APPROVAL_TTL` 15 min, `WRITE_AUTHORIZATION_TTL` 5 min, `ROUTER_LOCK_TIMEOUT`
  5 min, `ACTOR_VERIFICATION_TTL` 60 s, `FAILURE_EVENT_COOLDOWN` 24 h,
  `ORPHAN_SWEEP_MIN_AGE` 1 h.

### 2.2 Überarbeitung nach Review und Abgleich mit `config-manager`

Die vollständige Liste (breaking/additiv, Feld- und Signaturebene) und die Entscheidung zu
jedem der 14 Punkte von `config-manager` stehen im Vertrag, Abschnitt 19. Die wichtigsten
Linien:

- **Akteure:** `VerifiedActor` statt vertrauter `Actor.is_admin`; Bedrohungsmodell im
  Vertrag 6.1. Einlösen einer Freigabe nur durch den Antragsteller.
- **Bytes:** Module sehen nur `VersionReadView`; Provider lesen über einen
  bereichsgebundenen `ArtifactReader(version_id, kind)`; Locators sind einfache
  Dateinamen mit `realpath`-Prüfung.
- **Dedup, Aufbewahrung, Löschen:** reine Funktionen `dedup_candidate`,
  `should_deduplicate`, `plan_retention`, `validate_deletion` legen die Regeln heute schon
  fest.
- **Events:** zwei Ringe, Bereich `(router_id, type, dedup_key)`, Wiederholungszähler,
  Audit-Pflicht-Typen, Core-only-Namensräume.
- **Drift und Schlüssel:** Basisregeln, `DriftAck.version_id`, Zustände des
  Installations-Schlüssels, `installation_key_reset`, Re-Baseline, `not_comparable`.
- **Provider:** `ProviderContext` in jeder Methode; Snapshot-Format `uci_normalized` v1 von
  `config-manager`; Hashes nur vom Provider.
- **Warteschlange:** Platz → Router-Lock → autorisieren → holen → ablegen.
- **Maskierung:** eine Implementierung (`core_masking`), Obermenge aus Core und
  `config_mask`/`config_const`.

---

## 3. Modulaufteilung und Abhängigkeiten

| Modul | Inhalt | Status | hängt ab von |
|---|---|---|---|
| `core_masking.py` | die eine Maskierung: Namen, Kontextregeln, Archivpfade, HMAC-Digest, Freitext, `mask_secrets`, `mask_for_output` (rein, ohne HA) | **gebaut** | `const` |
| `core_errors.py` | `ErrorClass`, `ConfigApiError` + 27 Unterklassen | **gebaut** | `core_masking`, `homeassistant.exceptions` |
| `core_models.py` | Konstanten, Enums, Dataclasses, `VerifiedActor`, `WriteAuthorization`, reine Helfer (Policy, Einlösen, Dedup, Aufbewahrung, Basis), Protocols | **gebaut** | `const`, `core_errors`, `core_masking`, `mac_utils`, `net_events.Severity` |
| `router_identity.py` | Identität und Fingerprint aus `coordinator.data` bauen, Status bestimmen | **gebaut** (Teil 1) | `core_models` |
| `capabilities.py` | Capability-Ableitung aus `coordinator.data`/API-Flags, Signatur, Proben-Anlass; `rf.*` aus der verteilten ACL (1.44) | **gebaut** | `core_models` |
| `router_registry.py` | `RouterRegistry` (Store `router_registry`, Lookup, Adoption, Option, beobachtete ACL, Modul-Detektoren) | **gebaut** | `router_identity`, `capabilities`, `core_audit`, `core_guard` |
| `core_guard.py` | `ActionGuard` (Akteur prüfen, Policy, Approvals im Speicher, Prägen der `WriteAuthorization`, Ledger, `consume`) | **gebaut** (Teil 2) | `core_models`, `core_audit` |
| `core_audit.py` | zwei Audit-Ringe, Store `audit`, Dedup/Cooldown/Wiederholungszähler, Bus-Event, `events()`, `subscribe()` | **gebaut** (Teil 1) | `core_models`, `core_masking` |
| `core_store.py` | Store-Laden mit `.bak`/Wiederaufbau, `private`/`atomic_writes` | **gebaut** | `homeassistant.helpers.storage` |
| `version_store.py` (vorher `core_versions.py`) | `VersionStore` (Index im Store `config_catalog`, Dateien, Locator-Prüfung, Sweep, Grenzen, Drift-Acks, Archiv nach `removed/`) | **gebaut** | `core_models`, `core_audit` |
| `core_security.py` | `SshPinRegistry` (Store `ssh_host_keys`, je Router), `SecurityActions` (ACL-Verteilen, `ssh_pin_confirm`, `ssh_pin_reset`) | **gebaut** (1.44) | `core_models`, `core_guard`, `acl_provisioning`, `api` |
| `config_api.py` | `ConfigurationManager` (Flotten-Warteschlange, Locks, Provider-Aufrufe mit `ProviderContext`, Aufbewahrung, Installations-Schlüssel und Repair-Issue) | **gebaut** (Teil 2) | alle obigen |
| `enterprise_core.py` | Lebenszyklus: Lazy-Getter, Setup/Unload je Eintrag, Flush, Archiv beim Entfernen | **gebaut** | alle obigen |

Richtung: nur von unten nach oben; `core_models` importiert keinen Dienst. `api.py` und
`coordinator.py` werden nur unter `TYPE_CHECKING` referenziert. Kein Modul des Cores ruft
den Router; Provider bekommen `RouterConnection.api`.

---

## 4. Aufteilung mit `config-manager`

| Thema | Core (diese Reihe) | `config-manager` (Provider) |
|---|---|---|
| Router-ID, Identität, Registry, Adoption | ja | nein, liest nur `RouterRecord` |
| `config.*`-Capabilities | entscheidet, **wann** geprobt wird; Option `config_backup_enabled` | liefert `async_probe(conn, ctx)` mit allen `config.*`, auch nicht verfügbaren |
| Index (`BackupRecord`, Historie, Links, Validierung, Schutz, Notiz, Warnungen) | **besitzt** | liefert `VersionMeta` (mit `warnings`), `ValidationInfo` |
| Bytes (Ablage, Grenzen, Sweep, `removed/`, Export, Löschen) | **besitzt** (`VersionStore`) | liefert `ArtifactPayload`s, liest über `ctx.read(version_id, kind)` |
| Dedup | Regeln und Ausführung atomar beim Ablegen | berechnet `content_hash`/`uci_hash` (nur er) |
| Drift-Bestätigungen, Basis, Installations-Schlüssel | **besitzt** (inkl. Verlust und Reset) | liest sie über `ProviderContext` |
| UCI-Snapshot (`uci_normalized` v1), Diff, Drift, Restore-Plan | ruft auf, prüft, auditiert | implementiert |
| Restore-Ausführung | Phase 1 gesperrt | erst, wenn er `config.restore` meldet |
| Aufbewahrung (Retention) | führt `prune` nach `plan_retention` aus, behält geschützte und neueste brauchbare Version | liefert `RetentionPolicy` |
| Schreibrechte | prägt `WriteAuthorization`, Ledger | ruft `guard.consume()` vor dem Router-Schreiben |
| Events, Audit, Bus | erzeugt alle `CoreEvent`s (auch aus Provider-Ergebnissen), Dedup und Cooldown | meldet Ergebnisse, keine Events; eigene Typen nur unter eigenem Präfix |
| Maskierung | `core_masking`, die eine Implementierung | importiert `core_masking`; Secret-Digests mit dem Installations-Schlüssel |
| Router-I/O | keine | nur über `conn.api`; neue ubus/SSH-Aufrufe kommen als Methoden in `api.py` (eiserne Regel) |
| Locks, Warteschlange | Flotten-Warteschlange und Lock je Router um jede schreibende Operation | keine eigenen Router-Locks nötig |
| Gestufte ACL, SSH-Pinning (mit Bestätigung), Panel-Container „Enterprise“ | **gebaut** (1.44, Abschnitt 8) | hängt Untertab ein; SSH nur über `ctx.async_ssh_run_pinned` |

---

## 5. Migrationspfad

- **Lazy:** Beim Setup eines Eintrags fragt die Registry `router_id_for_entry`. Fehlt ein
  Eintrag im Store, wird `default_router_id(entry_id)` eingetragen; Status `unverified`
  bis zum ersten erfolgreichen Poll.
- **Deterministisch, ohne Routerkontakt:** Die ID hängt nur an der `entry_id`. Geht der
  Store verloren, entstehen dieselben IDs wieder (außer adoptierten; die Adoption steht im
  Audit-Log und kann wiederholt werden).
- **Idempotent:** Mehrfaches Setup, Neustart, abgebrochene Migration ergeben dieselbe ID.
- **Nie zusammenführen:** Doppelte Fingerprints ⇒ `duplicate_suspected` + Event, keine
  automatische Zusammenlegung. Adoption nur auf ausdrücklichen Befehl.
- **Kein Config-Entry-Version-Bump**, keine Änderung an Geräte- oder Entity-IDs.
- Bestehende Einträge brauchen keinen Schritt; ein Eintrag in `setup_retry` bekommt seine ID
  sofort, die Identität bleibt `unverified`.
- Versionsspeicher: neu, es gibt nichts zu migrieren. `StorageRef` ohne `storage_format`
  liest sich als `plain-v1`.

---

## 6. Leistungsbudget

- **0 neue Router-Aufrufe je Poll.** Identität und Capabilities lesen nur `coordinator.data`.
  Proben (`async_probe`) nur beim Setup, nach ACL-Neuverteilung und Firmware-Wechsel.
- Je Poll: Signatur bilden (ein Hash über wenige Felder, O(Interfaces)); Neubewertung nur bei
  Änderung. Identitätsabgleich beim ersten Poll und wenn `router_info` neu geholt wurde
  (jeder 10. Poll).
- Stores: verzögertes Speichern (Registry 30 s, Audit 60 s), Katalog sofort nach jedem
  Schreibvorgang (Index zuletzt), Flush beim letzten Unload.
- Datei-I/O nur im Executor; Sweep einmal beim Start, O(Dateien).
- Speicher: höchstens 50 MB je Router, 250 MB gesamt; Überschreitung ⇒
  `ArtifactTooLargeError` bzw. `StorageFullError`, nichts wird geschrieben.
- Audit-Ringe maximal 1000 (allgemein) + 500 (Sicherheit) Einträge; Bus-Events nur für
  Core-Events, nicht je Poll; wiederholte Fehler werden 24 h nicht gefeuert, nur gezählt.
- Backups flottenweit nacheinander (`FLEET_BACKUP_CONCURRENCY` = 1).
- Backups, Drift, Diff laufen nur auf Anforderung oder nach Zeitplan, nie im Poll-Pfad.

---

## 7. Testplan (16 Fälle)

| # | Fall | Prüft | Datei | Stand |
|---|---|---|---|---|
| 1 | Stabile ID bei IP-Wechsel | gleicher Eintrag, neuer Host ⇒ gleiche `router_id`; neu angelegter Eintrag ⇒ neue ID + Adoptionskandidat | `test_router_registry.py` | später (Grundlage `default_router_id` getestet) |
| 2 | Hostname-Wechsel | ID bleibt, Status `confirmed`, kein Event außer `identity_changed` info | `test_router_identity.py` | später |
| 3 | Doppelte Identitäten | zwei Einträge mit gleichen MACs ⇒ beide `duplicate_suspected`, Event, kein Merge | `test_router_identity.py` | später |
| 4 | Werksreset | Hostname „OpenWrt“, gleiche MACs/Board ⇒ ID bleibt, `confirmed`, Event info | `test_router_identity.py` | später |
| 5 | Migration bestehender Einträge | Eintrag ohne Store-Zeile ⇒ Standard-ID, idempotent, ohne Routeraufruf | `test_router_registry.py` | später |
| 6 | Backup über zentrale API | `async_create_backup` ⇒ Guard ⇒ `async_collect` ⇒ `async_put_version` mit gültiger Autorisierung; Dedup-Treffer ⇒ `created=False`, nur `last_seen_at` | `test_config_api.py`, `test_core_versions.py` | später |
| 7 | Versionshistorie | Liste neueste zuerst, `since`/`limit`; Metadaten-Migrationskette | `test_core_models.py` (Kette), `test_core_versions.py` | **teilweise gebaut** |
| 8 | Backup-Integrität | Prüfsumme/Größe, `corrupt`/`missing`, Sweep; ungültige Metadaten ⇒ `BackupMetadataError`; unbekanntes Format ⇒ `UnsupportedStorageFormatError` | `test_core_models.py`, `test_core_versions.py` | **teilweise gebaut** |
| 9 | API-Versionierung | v1 ok, v2/bool ⇒ `ApiVersionError` mit unterstützten Versionen | `test_core_models.py` | **gebaut** |
| 10 | Fehlende Capabilities | ohne Provider `no_provider`; Option aus ⇒ `disabled`; `require_capability` ⇒ `CapabilityUnavailableError`; Restore in Phase 1 gesperrt | `test_capabilities.py`, `test_config_api.py` | später |
| 11 | Unautorisierter Restore/Export | Modul/Automation darf nicht genehmigen und nicht exportieren; vorgetäuschtes `is_admin` wirkungslos; nur der Antragsteller löst ein; ohne Approval ⇒ `ApprovalRequiredError`; Autorisierung einmalig/gebunden/ablaufend | `test_core_models.py`, `test_core_contract_hardening.py` (Policy, Einlösen, Ledger), `test_core_guard.py` | **teilweise gebaut** |
| 12 | Router offline beim Backup | `RouterUnavailableError` (retryable), Event `backup_failed` einmal je 24 h, danach `backup_recovered` | `test_config_api.py` | später |
| 13 | Paralleler Zugriff | Lesen parallel, Schreiben je Router serialisiert, zweiter Schreibvorgang ⇒ `OperationInProgressError` | `test_config_api.py` | später |
| 14 | Event-/Audit-Erfassung | jede Operation erzeugt ein maskiertes Event; Dedup-Bereich, Ringe, Audit-Pflicht; Abfrage nach Zeitfenster/Korrelation | `test_core_models.py`, `test_core_contract_hardening.py`, `test_core_masking.py`, `test_core_audit.py` | **teilweise gebaut** |
| 15 | Unload/Neustart | Flush beim letzten Unload, Laden nach Neustart, Sweep, Waisen bleiben, Entfernen ⇒ `removed/` | `test_enterprise_core.py`, `test_core_versions.py` | später |
| 16 | Rückwärtskompatibilität | Geräte-/Entity-IDs, `entry.unique_id`, Config-Entry-Version unverändert; alte Metadaten migrierbar | `test_enterprise_core.py`, `test_core_models.py` | später |

Gebaut in diesem Schritt (429 Tests, davon einer auf Windows übersprungen):

- `tests/test_core_models.py` (110): Round-Trips `BackupRecord` (voll und
  minimal)/`Actor`/`CoreEvent`/`DriftAck`/`StorageRef`/`ArtifactRef`, abgeleitete Felder,
  Notizlänge, Metadaten-Versionsablehnung und Migrationskette, ungültige Felder, eindeutige
  Fehlercodes mit `error_class`, die elf Fehlerklassen aus `config-manager`, Speicherformat,
  `WriteAuthorization` (einmalig, Abweichung, Ablauf, nicht direkt konstruierbar),
  Policy-Tabellen, `binding_checksum`, `AuthorizationDecision`, Router-ID gepinnt,
  Capability-Namen, Plan-Prüfsumme, Protocols `runtime_checkable`.
- `tests/test_core_masking.py` (166): die 14 von `config-manager` gemeldeten Namen über
  beide Maskierungsfunktionen, jede `SECRET_OPTION`, Kontextnamen, CamelCase und
  Ergänzungen, lesbare Namen, Archivpfade, Digest, Freitext (Geheimnisse weg, IDs bleiben),
  Dataclasses, `bytes`, Ausnahmen, Marker, Zyklen, kein Import aus `config_*`.
- `tests/test_core_contract_hardening.py` (153): Review-Befunde 1–3, 4, 6, 9, 10, 12, 13,
  15, 16 und die Punkte des Koordinators (Warteschlange, `VersionMeta`-Regeln, Basis,
  Installations-Schlüssel, Drift-Events, Provider-Signaturen, Snapshot-Format).
  Der Symlink-Ausbruchstest läuft nur auf POSIX.

---

## 8. Reihenfolge der nächsten Schritte

1. `core_audit.py` + `core_guard.py` (keine Router-Abhängigkeit, gut testbar).
2. `core_versions.py` (`VersionStore`, nur Dateisystem, mit `tmp_path` testbar).
3. `router_identity.py` + `capabilities.py` (rein, aus Fixture-`coordinator.data`).
4. `router_registry.py` + Store `router_registry`.
5. `config_api.py` (`ConfigurationManager`, Locks, Installations-Schlüssel) gegen einen
   **Test**-Provider.
6. `enterprise_core.py` + Verdrahtung in `__init__.py` (isoliertes try/except-Setup wie
   Client-Engine), Diagnose-Abschnitt, Option `config_backup_enabled` im Options-Flow.
7. Integration mit dem echten Provider aus `config-manager`.
8. Später, je eigener Plan (Nachtrag H):
   - Gestufte rpcd-ACL in `acl_provisioning.py`, Rechte je Capability, nur angeboten, nie
     automatisch geschrieben: `"cgi-io": ["backup"]`; `uci`-Lesebereich für network,
     wireless, firewall, dhcp, system, dropbear, uhttpd, rpcd, ddns, sqm, usteer, mwan3,
     upnpd, openvpn; `"ubus": {"rpc-sys": ["packagelist"]}`. Schreiben nur nach Freigabe
     (`acl_deploy`), danach neue Proben.
   - TOFU-Pinning des SSH-Host-Keys nur für den Config-Pfad.
   - Leerer Panel-Navigationscontainer „Enterprise“ mit Untertab-Haken, erst nach Merge
     von 1.43.0.
   - Restore auf UCI-Ebene mit Rollback (eigener Plan, eigene Freigabe).

---

## 9. Risiken

- Zwei Sitzungen an denselben Dateien: `config-manager` braucht neue Methoden in `api.py`;
  dieser Plan fasst `api.py` nicht an. Reihenfolge über den Master abstimmen.
- `uuid5` über `entry_id`: Ein Nutzer, der Einträge per Backup-Restore von HA zurückholt,
  bekommt dieselben `entry_id`s und damit dieselben Router-IDs (gewollt).
- Maskierung ist namens- und musterbasiert: Ein Geheimnis unter einem neutralen Schlüssel in
  einem unbekannten Format wird nicht erkannt. Provider liefern strukturierte Daten
  (`uci_normalized` v1, Geheimnisse nur als HMAC-Marker), Diff-Werte werden über
  `is_secret_option` geprüft, Events tragen nur IDs und Zähler.
- Private Sentinels und das Ledger schützen gegen Fehler und fremde Akteure, nicht gegen ein
  Modul, das absichtlich private Helfer importiert (Bedrohungsmodell, Vertrag 6.1).
- Klartext-Archive auf der HA-Platte (Phase 1 ohne eigene Verschlüsselung): Schutz nur über
  Dateirechte und die HA-Backup-Verschlüsselung. Wer die HA-Platte liest, liest die
  Router-Geheimnisse. Deshalb Export kritisch und Ordner nicht unter `www`.
- `.storage`-Installations-Schlüssel landet in HA-Backups. Er schützt nur Digests, nicht die
  Archive.

---

## 10. Offene Fragen

- **F1** ~~Löschen critical oder mutating?~~ Gelöst: `delete` kritisch, `prune` für die
  Aufbewahrung (Abschnitt 2.1).
- **F2** Ist ein `pre_restore`-Backup vor jedem Restore Pflicht? Empfehlung: ja; scheitert es,
  wird der Restore abgebrochen. (Betrifft erst die spätere Restore-Phase.)
- **F3** ~~Ablage der Bytes beim Provider?~~ Gelöst durch Nachtrag A (Core).
- **F4** Seriennummer: heute nicht abgefragt. Erst mit einem bestehenden Aufruf möglich, der
  sie liefert; sonst bleibt `serial=None`.
- **F5** Dürfen Automationen Backups anlegen (mutating, als `automation` protokolliert)?
  Umgesetzt: ja. Genehmigen, Exportieren, Schützen und Drift bestätigen dürfen sie nie.
- **F6** ~~Zählt eine `failed`-Version (ohne Artefakte) im Index?~~ Entschieden: ja, damit
  Fehler in der Historie stehen; Größe 0. Sie nimmt nie am Dedup teil.
- **F7** ~~Darf ein Modul `async_put_version` direkt rufen?~~ Entschieden: ja, mit eigener
  `backup`-Autorisierung (erst holen, dann autorisieren).
- **F8** Dürfen tokenbasierte Clients freigeben? Ein HA-`Context` trägt nur `user_id`; der
  Refresh-Token-Typ (`normal`, `system`, `long_lived_access_token`) ist nur über HTTP/WS
  bekannt, bei Service-Aufrufen nicht. Stand: jeder aktive, nicht systemgenerierte
  Admin-Benutzer darf freigeben.
