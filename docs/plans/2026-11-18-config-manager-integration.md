# Plan: Configuration Manager an den Enterprise Core anbinden (1.45.0)

<!-- Keine IPs, MACs, Hostnamen, Passwörter oder Tokens. Belege als Datei:Zeile auf Stand 47b05a9.
     Kern-Dateien (enterprise_core.py, config_api.py, core_*.py, router_registry.py, version_store.py,
     acl_provisioning.py) werden NICHT geändert. -->

## Status

| Feld | Wert |
|---|---|
| Stand | 2026-11-18, Branch `claude/config-manager-d9fdac` (`47b05a9`) |
| Vorgänger | `docs/plans/2026-11-17-config-manager.md` (Phase 1, Gruppe I/Ia fertig), `docs/plans/2026-11-17-enterprise-core.md` |
| Vertrag | `docs/dev/configuration-api-v1.md` (API v1), `docs/dev/acl-tiers.md` |
| Ziel-Version | `manifest.json` 1.44.0 → **1.45.0** |
| Pakete | BACKEND, FRONTEND, DOKU/RELEASE (Abschnitt 13), ohne gemeinsame Dateien |

## Ziel

Der fertige Provider `ConfigManagerProvider` (`config_provider.py:905`) wird beim Core angemeldet und
bekommt Zeitplan, Dienst, Sensoren, HTTP-Routen und einen Panel-Untertab. Alles, was der Core schon
kann (Ablage, Dedup, Aufbewahrung, Events, Audit, Freigaben, Maskierung), wird nur aufgerufen und nicht
nachgebaut. **LÜCKE** markiert, was der Core nicht bietet; die Lösung liegt dann immer in unseren
neuen Dateien.

Feste Regeln für alle Pakete:

- Netzwerkaufrufe nur über den Provider → `api.py` (vorhandene `config_*`-Methoden, `api.py:6037–6394`).
  Entities lesen nur den Speicher der Laufzeit. `coordinator.py` bleibt unverändert.
- `net_engine.py`, `net_rules.py`, `net_events.py` werden weder geändert noch unterdrückt; Config-Ereignisse
  laufen nur über den Core-Bus (`core_models.py:106` `EVENT_CORE`).
- Benutzer-IDs gehen nie roh hinaus: `core_masking.pseudonymise_user_ids` (`core_masking.py:1202`), danach
  `mask_for_output` (`core_masking.py:1173`).
- Maskierung nur aus `core_masking` importieren, nie aus `config_mask` (Umstellung läuft parallel).
- `UpdateFailed` wird nirgends geschluckt; der Config Manager hängt sich nicht in `_async_update_data`.

---

## 1. Provider an- und abmelden

**LÜCKE L1 (Lebensdauer):** Der Core existiert einmal je HA-Instanz und wird beim Entladen des letzten
Eintrags geschlossen (`enterprise_core.py:190–212`, `close()` `:221–237` → `manager.close`
`config_api.py:2462–2478` wirft den Provider ab). Es darf nur einen Provider geben
(`config_api.py:503–551`, zweiter → `ProviderConflictError`). Das Beispiel `entry.async_on_unload(unregister)`
(`configuration-api-v1.md:942–945`) würde beim Entladen des **ersten** Eintrags den Provider für alle
anderen Router entfernen.

Lösung in `config_manager.py`: eine Laufzeit je Domain mit Referenzzählung.

| Schritt | Wo | Was |
|---|---|---|
| Setup je Eintrag | `__init__.py` nach dem Core-Hook (`__init__.py:528–540`), vor `async_forward_entry_setups` (`:552`) | `await config_manager.async_setup_entry(hass, entry)` in `try/except Exception` mit Warnung, wie `:530–539`; Setup scheitert nie daran |
| API holen | `config_manager.py` | `async_get_configuration_api(hass, version=1)` (`config_api.py:2909–2933`); `ConfigApiError` `core_not_running` → Log, kein Modul für diesen Eintrag |
| Laufzeit | `hass.data["openwrt_router_config_manager"]` → `ConfigManagerRuntime` | neu, wenn keine da ist **oder** `runtime.core is not async_get_core(hass)` (`enterprise_core.py:283–289`; neuer Core nach Neustart des Cores) |
| Anmelden | Laufzeit, einmal | `if api.provider_id is None: self._unregister = api.register_provider(factory(hass))` (`config_api.py:2565`, `:2574`); `factory` Standard `ConfigManagerProvider` (`config_provider.py:905`), in Tests austauschbar |
| Fremder Provider | Laufzeit | `api.provider_id not in (None, PROVIDER_ID)` (`config_provider.py:178`) → Log-Warnung, Modul bleibt passiv (keine Timer, Routen antworten `503 provider_conflict`) |
| Eintrag zählen | Laufzeit | `runtime.entries.add(entry_id)`; Abmelden je Eintrag über `entry.async_on_unload(partial(runtime.release, entry_id))` |
| Abmelden | `__init__.py` `async_unload_entry` im Block `unload_ok`, **vor** `async_unload_entry_core` (`__init__.py:603–693`) | `runtime.release(entry_id)`; beim letzten Eintrag: Timer stoppen, `api.subscribe`-Abmeldung, `self._unregister()` (idempotent, `config_api.py:546–551`), `hass.data` leeren |
| Entfernen | `async_remove_entry` (`__init__.py:696–723`) | nichts Eigenes; Archivieren macht der Core (`enterprise_core.py:329–356`) |

Aufbewahrung: Der Core startet mit `DEFAULT_RETENTION_POLICY = RetentionPolicy.gfs()` = 7/4/6
(`core_models.py:2512–2548`, `config_api.py:426`). **DECIDED:** kein Aufruf von `set_retention_policy`.

## 2. Optionen und Übersetzungen

Die Option `config_backup_enabled` gibt es schon (`core_models.py:171–172`, Options-Flow
`config_flow.py:114–198`, Anwenden ohne Neuladen `:155–161`, `:222–257`). Neu sind drei Felder im
**selben** Block, der nur erscheint, wenn `_offer_config_backup_option` wahr ist (`config_flow.py:186–219`).

| Schlüssel (`const.py`) | Selector | Standard | Wirkung |
|---|---|---|---|
| `config_backup_enabled` (vorhanden) | bool | aus | wie bisher, Core-Hook bleibt |
| `config_backup_schedule` | select `daily` / `off` | `daily` | `off` = nur Dienst, Panel und Release-Wechsel |
| `config_backup_time` | `TimeSelector` (`HH:MM:SS`) | `03:30:00` | Startzeit, plus Versatz je Router |
| `config_drift_check` | bool | an | Drift-Prüfung über den Fingerprint |

- Konstanten `OPTION_CONFIG_BACKUP_SCHEDULE`, `OPTION_CONFIG_BACKUP_TIME`, `OPTION_CONFIG_DRIFT_CHECK` und
  Standardwerte in `const.py` (Ende, markierter Block). Nicht in `config_const.py`.
- Kein Update-Listener (Konflikt mit Reauth, Kommentar `config_flow.py:135–137`): der Zeitplan liest
  `entry.options` bei jedem Takt neu (Abschnitt 3).
- **LÜCKE L6:** Aufbewahrung und Speichergrenzen gelten für die ganze Installation
  (`config_api.py:2002–2015`, `enterprise-core.md:141–149`). **DECIDED:** keine Aufbewahrungs- oder
  Größenfelder je Router.
- Übersetzungen in `strings.json`, `translations/en.json`, `translations/de.json`:
  - `options.step.init.data` und `data_description` für die drei Felder;
  - `selector.config_backup_schedule.options.{daily,off}`;
  - `entity.sensor.config_last_backup|config_backup_status|config_versions.name`;
  - `entity.sensor.config_backup_status.state.{ok,partial,failed,running,disabled,never}`;
  - `entity.binary_sensor.config_drift.name`;
  - `services.create_config_backup` mit `name`, `description` und `fields.device_id|note`;
  - `exceptions.config_backup_*` (Abschnitt 4).

## 3. Zeitplan

Kein Scheduler im Core (**LÜCKE L2**). `config_manager.py` hat **einen** Takt für alle Router:
`async_track_time_interval(hass, self._tick, timedelta(minutes=5))`. Der Takt rechnet nur im Speicher
und ruft keinen Router.

| Auslöser | Bedingung | Aufruf | Grenze |
|---|---|---|---|
| Täglich | Option an, `schedule == daily`, `now ≥ heute(time) + versatz(router_id)`, heute noch kein geplanter Lauf | `api.async_create_backup(rid, reason=BackupReason.SCHEDULED, actor=modul)` (`config_api.py:1585–1604`) | 1 je Tag; Nachholen nach HA-Start am selben Tag |
| Nachversuch | letzter Lauf mit `retryable` (`RouterUnavailableError`, `OperationTimeoutError`, `core_errors.py:129–156`) | wie täglich | einmal nach `FETCH_RETRY_DELAY_S` = 900 s (`config_const.py:568`) |
| Release-Wechsel | `registry.get(rid).firmware.version` ≠ `openwrt_version` der neuesten OK-Version (`core_models.py:2125`), beide gesetzt, Option an | `async_create_backup(..., reason=BackupReason.RELEASE_CHANGE)` (`core_models.py:869–870`) | 1 je (Router, Version), 300 s nach der ersten Beobachtung |
| Drift | Option an, `config_drift_check` an, `fingerprint_from_coordinator(data)` (`config_snapshot.py:816`) hat sich gegenüber dem letzten Wert geändert | `api.async_detect_drift(rid, actor=modul)` (`config_api.py:1312–1375`) | 300 s Entprellung (`DRIFT_DEBOUNCE_S`, `config_const.py:590`), höchstens 1 je Stunde (`DRIFT_MIN_INTERVAL_S`, `:591`) |
| Drift-Version | Drift-Bericht `drifted` mit neuer `drift_id` (`core_models.py:3313–3327`) | `async_create_backup(..., reason=BackupReason.DRIFT, backup_type=BackupType.UCI_SNAPSHOT)` | höchstens 4 je Router und Tag |

- Versatz: `int(sha256(router_id).hexdigest(), 16) % 3600` Sekunden; stabil und unabhängig von der Uhrzeit.
- Modul-Aktor: `Actor(kind=ActorKind.MODULE, module="config_manager")` über
  `async_actor_from_context(hass, None, module="config_manager")` (`core_models.py:1253–1286`).
- Fingerprint: über `coordinator.async_add_listener` je Eintrag (Muster `__init__.py:501–526`), nur
  Hash-Vergleich. Der erste Wert nach dem Start ist nur Bezugswert und löst keine Prüfung aus.
  `BackupNotFoundError` mit `no_baseline` → keine Prüfung, warten auf den Tageslauf.
- **LÜCKE L3:** Den Probe-Listener des Registers (`router_registry.py:1683`, Grund `firmware_changed`
  `:124–129`) belegt der Core selbst (`config_api.py:768`). Darum vergleichen wir die Firmware-Version
  wie oben. Das übersteht Neustarts, weil die Version am Datensatz steht.
- Warteschlange: Der Core lässt flottenweit ein Backup gleichzeitig laufen (`FLEET_BACKUP_CONCURRENCY = 1`,
  `core_models.py:210`, `config_api.py:1620–1679`). `OperationInProgressError` (`core_errors.py`, Code
  `operation_in_progress`) zählt nicht als Fehler, sondern als Neuversuch beim nächsten Takt.
- Läufe sind `hass.async_create_background_task`-Aufgaben, die beim letzten Abmelden abgebrochen werden.
- Merker im Speicher: `last_scheduled_day`, `retry_at`, `last_fp`, `fp_changed_at`, `last_drift_at`,
  `drift_versions_today`, `release_seen`. Beim Start werden `last_scheduled_day` und `release_seen` aus
  `api.async_list_backups(rid, limit=20)` (`config_api.py:1207`, nur Store, kein Router) gefüllt.
- Option aus: der Takt überspringt den Router; der Core sperrt ohnehin (`config_api.py:705–723`).

### Kosten je Router und Tag

| Posten | Router-Aufrufe | Daten (Schätzung) |
|---|---|---|
| Tageslauf (Archiv, UCI, Paketliste) | ~16 (1 + 14 `UCI_CONFIGS` `config_const.py:66` + 1) | 40–300 KB |
| Fingerprint, Release-Vergleich, Takt | 0 | 0 |
| Drift-Prüfung | ~14 je Prüfung, typisch 0–2, höchstens 24 | typisch < 160 KB, höchstens ~2 MB |
| Drift-Version | ~14 je Version, höchstens 4 | höchstens ~300 KB |
| Release-Wechsel | ~16, selten | 40–300 KB |
| **Typisch / Obergrenze** | **~16–45 / ~420** | **~40–500 KB / ~3 MB** |

Mit ausgeschalteter Option: **0** zusätzliche Aufrufe. Zum Vergleich: der Poll macht > 10 000 Aufrufe am Tag.

## 4. Dienst `openwrt_router.create_config_backup`

| Punkt | Festlegung |
|---|---|
| Registrierung | `async_setup(hass, config)` in `__init__.py` (gibt es noch nicht) mit `CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)`; Handler in `config_manager.py` |
| `services.yaml` (neu) | `device_id`: `device` mit `integration: openwrt_router`, `multiple: true`, Pflicht; `note`: `text`, optional, ≤ 200 Zeichen |
| Antwort | `supports_response=SupportsResponse.OPTIONAL` |
| Aktor | `async_actor_from_context(hass, call.context)`: Benutzer → `is_admin` aus `hass.auth`; mit `parent_id` → Automation; sonst System |
| Rechte | Der Core-Guard entscheidet (`backup` ist schreibend: Admin, Automation, Modul, System; Nicht-Admin abgelehnt, `configuration-api-v1.md:310–336`) |
| Ablauf | Gerät → Config-Entry → `registry.router_id_for_entry` (`router_registry.py:1755`) → `async_create_backup(reason=MANUAL, note=…)`, Router nacheinander |
| Fehler | `ServiceValidationError` mit `translation_key`: `config_backup_unknown_device`, `config_backup_disabled`, `config_backup_not_ready`, `config_backup_denied`; Router- oder Speicherfehler → `HomeAssistantError` `config_backup_failed` mit Platzhalter `error_class` |

Antwort, wenn `return_response` gesetzt ist:

```json
{"results": [{"router_id": "rtr_<32hex>", "backup_id": "bkp_<32hex>", "created": true,
              "status": "ok", "error_class": null}]}
```

`created: false` heißt: gleicher Inhalt, nur `last_seen_at` verschoben (`PutVersionResult`,
`core_models.py:2431–2435`). Bei `MANUAL` legt der Core immer eine neue Version an; Dedup gilt nur für
`scheduled` und `drift` (`configuration-api-v1.md:608–634`).

## 5. Events

**DECIDED:** Der Config Manager sendet **keine** eigenen Events. Alle Typen kommen vom Core
(`core_models.py:1038–1091`): `configuration.backup_created` (nur bei neuer Version),
`backup_failed` (Dedup `error_class`, 24 h, `config_api.py:1813–1850`), `backup_recovered`,
`backup_validated`, `backup_protection_changed`, `backup_exported`, `retention_applied`,
`drift_detected` (`dedup_key = drift_id`, `configuration-api-v1.md:1173–1179`), `drift_acknowledged`,
`change_critical`, `change_unknown`, `drift_incomplete`, `restore_checked`, `storage_*`, `router_archived`.

Der Manager meldet sich mit `api.subscribe(listener)` (`config_api.py:2870`) an. Der Listener prüft nur
`router_id` und Typ-Präfix `configuration.` / `router.adopted` / `security.config_option_changed` und ruft
`async_dispatcher_send(hass, SIGNAL_CONFIG_MANAGER, router_id)`. Danach liest die Laufzeit die Liste neu
aus dem Store (kein Router). Ein Präfix über `register_event_prefix` braucht es nicht.

## 6. Sensoren (`config_entities.py`, neu)

Muster: `net_entities._RouterIntelEntity` (`_attr_should_poll = False`, `has_entity_name`, Dispatcher in
`async_added_to_hass`, `DeviceInfo(identifiers={(DOMAIN, entry_id)})`, vgl. `sensor.py:727`).
Eingebunden mit je einer Zeile: `sensor.py` nach `:538` →
`async_setup_config_sensors(hass, entry, async_add_entities)`, `binary_sensor.py` nach `:112` →
`async_setup_config_binary_sensors(hass, entry, async_add_entities)`.

| Entity | `unique_id` | Art | Wert / Attribute |
|---|---|---|---|
| `sensor` Letztes Backup | `{router_id}_config_last_backup` | `timestamp` | `created_at` (bzw. `last_seen_at`) der neuesten OK-Version |
| `sensor` Backup-Status | `{router_id}_config_backup_status` | `enum` | `ok`, `partial`, `failed`, `running`, `disabled`, `never`; Attribute `error_class`, `last_attempt_at`, `next_run_at` |
| `sensor` Versionen | `{router_id}_config_versions` | `measurement`, `EntityCategory.DIAGNOSTIC` | Anzahl gespeicherter Versionen |
| `binary_sensor` Drift | `{router_id}_config_drift` | `problem` | an bei `drifted` und ohne Bestätigung; Attribute `drift_id`, `critical_count`, `unknown_count`, `comparison`, `checked_at` |

- `router_id` aus `core.registry.router_id_for_entry(entry.entry_id)`; fehlt er, werden keine Entities
  angelegt (Log). Bestehende `unique_id`s (`f"{entry.entry_id}_{key}"`, `sensor.py:714`) bleiben unverändert.
- Die Entities werden für jeden Router angelegt, auch mit ausgeschalteter Option (Status `disabled`),
  siehe QUESTION Q1.
- **LÜCKE L7:** Der Core speichert keinen letzten Drift-Bericht. Beim Start füllt die Laufzeit den
  Drift-Zustand aus `api.events(router_id=rid, types=[DRIFT_DETECTED, DRIFT_ACKNOWLEDGED])`
  (`config_api.py:2856`). Ohne Eintrag ist der Zustand `unknown`.
- Adoption (`router.adopted`, `core_models.py:1034`) ändert die `router_id` des Eintrags. Dann entfernt
  die Laufzeit die Einträge `{alte_id}_config_*` dieses Eintrags aus der Entity-Registry und plant
  `hass.config_entries.async_schedule_reload(entry_id)`.

## 7. HTTP-Routen (`config_views.py`, neu)

### 7.1 Basis

- `_ConfigView(HomeAssistantView)`: `requires_auth = True`. Ohne Admin → `403`, **immer**, auch wenn das
  Panel für alle offen ist (anders als `_IntelView._check`, `topology_panel.py:211–228`).
  `hass.data[_PANEL_VIEW_DISABLED_KEY]` (`topology_panel.py:80`, gesetzt `:692`) → `410`. Ohne Laufzeit → `503`.
  Die Konstante wird nur importiert.
- **DECIDED:** Die Routen melden sich selbst an, einmal je HA-Sitzung, mit eigenem Merker
  `hass.data["openwrt_router_config_views_bound"]`, im ersten `async_setup_entry` des Managers
  (`hass.http.register_view`, Muster `topology_panel.py:574–582`). `topology_panel.py` und `_api_views()`
  (`:454–467`) bleiben für BACKEND tabu.
- Präfix `/api/openwrt_topology/config`; `name = "api:openwrt_topology:config:<x>"`.
- Aktor jeder Anfrage: `Actor(kind=USER, user_id=request[KEY_HASS_USER].id, is_admin=…)` über
  `async_actor_from_context(hass, Context(user_id=user.id))`. Der Core prüft erneut (`VerifiedActor`).

### 7.2 Prüfung der Eingaben

| Eingabe | Regel | Fehler |
|---|---|---|
| `router_id` | `is_valid_id(v, "rtr_")` (`core_models.py:244`) und `registry.find` (`router_registry.py:1751`) | 400 / 404 |
| `backup_id` | `is_valid_id(v, "bkp_")`, Datensatz gehört zum `router_id` im Pfad | 400 / 404 |
| `approval_id` | `is_valid_id(v, "apr_")` | 400 |
| `drift_id` | String, 1–128 Zeichen aus `[A-Za-z0-9_-]` (Format nicht geprüft, siehe Abschnitt 15) | 400 |
| JSON-Body | höchstens 4 KB (`request.content_length`), Objekt, unbekannte Schlüssel → Fehler | 400 / 413 |
| `note` | höchstens 200 Zeichen, keine Steuerzeichen | 400 |
| `limit` | Ganzzahl 1–200, Standard 50 | 400 |
| `since`, `from`, `to` | ISO-8601 oder `backup_id` bzw. `live` | 400 |

IDs werden nie als Dateipfad benutzt. Pfade baut nur der Core.

### 7.3 Fehlerabbildung

Antwort immer `{"message": str, "code": str, "error_class": str, "retryable": bool}` aus
`mask_for_output(err.to_dict())` (`core_errors.py:52–85`). Unbekannte Ausnahmen → `500`, `code: "internal"`,
nur der Typname ins Log (wie `topology_panel.py:250–255`).

| Core-Fehler (`code`) | HTTP |
|---|---|
| `router_not_found`, `backup_not_found` | 404 |
| `authorization_denied` | 403 |
| `approval_required`, `approval_invalid`, `operation_in_progress` (+ `Retry-After: 30`), `version_protected`, `provider_conflict` | 409 |
| `capability_unavailable` (Option aus, nicht geprüft, keine Rechte) | 409 mit `details.state`, `details.reason` |
| `backup_integrity_failed`, `backup_incomplete`, `restore_incompatible`, `storage_ref_invalid` | 422 |
| `router_unavailable`, `provider_unavailable`, `core_not_running` | 503 |
| `operation_timeout` | 504 |
| `router_auth_failed`, `router_permission_denied`, `provider_error`, `artifact_too_large` | 502 |
| `storage_full` | 507 |
| `storage_error`, alles andere | 500 |

### 7.4 Ausgabe und Maskierung

Jede JSON-Antwort läuft so: Objekt → `to_dict()` → Aktor-Felder (`created_by`, `requested_by`,
`decided_by`) durch `{"kind": …, "mine": bool}` ersetzen → `pseudonymise_user_ids(…, runtime.salt)` →
`mask_for_output`. `runtime.salt = secrets.token_bytes(16)` je Laufzeit. **LÜCKE L11:** Das Bus-Salz ist
privat (`core_audit.py:115`). `Cache-Control: no-store` an jeder Antwort.

### 7.5 Routen

| # | Methode | Pfad | Core-Aufruf | Antwort |
|---|---|---|---|---|
| R1 | GET | `/overview` | `registry.list()`, `api.capability`, Laufzeit-Speicher | `Overview` |
| R2 | GET | `/routers/{router_id}` | `capability(rid, c)` für alle `config.*` (`configuration-api-v1.md:189–244`), `ssh_pin_status` (`config_api.py:2801`), `DEFAULT_TIER_REGISTRY.offerable(entry.options)` (`acl_provisioning.py:879`) | `RouterDetail` |
| R3 | GET | `/routers/{router_id}/versions?limit=&since=` | `async_list_backups` (`config_api.py:2616`) | `{"versions": [Version]}` |
| R4 | GET | `/versions/{backup_id}` | `async_get_backup` (`:2626`) | `Version` mit `artifacts` (Art, Größe, `sha256`) |
| R5 | POST | `/routers/{router_id}/backup` | `async_create_backup(reason=MANUAL, note)` | `{"backup_id", "created", "status"}` |
| R6 | POST | `/versions/{backup_id}/validate` | `async_validate_backup` (`:2630`) | `Version` |
| R7 | POST | `/versions/{backup_id}/protect` | `async_set_protected(id, protected, actor)` (`:2697`) | `Version` |
| R8 | GET | `/routers/{router_id}/diff?from=&to=` | `async_compare(ConfigRef.backup(a), ConfigRef.backup(b) \| ConfigRef.live(rid), actor)` (`core_models.py:3070–3100`, `config_api.py:1259–1310`) | `Diff` |
| R9 | GET | `/routers/{router_id}/drift` | Laufzeit-Speicher + `async_list_drift_acks` (`config_api.py:2717`) | `DriftState` |
| R10 | POST | `/routers/{router_id}/drift/check` | `async_detect_drift(rid, actor)` (beachtet die Stundengrenze nicht, Admin-Wunsch) | `DriftState` |
| R11 | POST | `/routers/{router_id}/drift/{drift_id}/ack` | `async_acknowledge_drift(rid, drift_id, state, actor, note)` (`config_api.py:1931–1998`) | `DriftState` |
| R12 | POST | `/versions/{backup_id}/restore-check` | `async_prepare_restore` (`config_api.py:1517–1581`) | `RestorePlan` |
| R13 | POST | `/versions/{backup_id}/export` | `async_request_export(id, actor, artifact)` (`config_api.py:2105–2126`) | `Approval` |
| R14 | GET | `/approvals?router_id=` | `pending_approvals(rid)` (`config_api.py:2850`), nur Aktionen `export`, `acl_deploy`, `ssh_pin_confirm`, `ssh_pin_reset` | `{"approvals": [Approval]}` |
| R15 | POST | `/approvals/{approval_id}/approve` | `async_approve` (`config_api.py:2399`) | `Approval` |
| R16 | POST | `/approvals/{approval_id}/reject` | `async_reject(id, actor, reason)` | `Approval` |
| R17 | POST | `/approvals/{approval_id}/download` | `async_export_backup(id, actor)` → `ExportHandle` (`config_api.py:2128–2196`, `core_models.py:3597`) | Datei (7.6) |
| R18 | POST | `/routers/{router_id}/acl-offer` | `async_request_acl_deploy(rid, ["config_backup_read"], actor)` + `acl_offer(approval_id)` (`config_api.py:2781–2793`) | `Approval` + `offer` |
| R19 | POST | `/routers/{router_id}/ssh-pin/{op}` (`confirm` \| `reset`) | `async_request_ssh_pin_confirm` / `_reset` (`config_api.py:2805`, `:2819`) | `Approval` |
| R20 | POST | `/approvals/{approval_id}/execute` | je `approval.action` (`get_approval` `:2846`): `acl_deploy` → `async_deploy_acl_offer`, `ssh_pin_confirm` → `async_confirm_ssh_pin`, `ssh_pin_reset` → `async_reset_ssh_pin`; `export` → 409 (dafür R17) | `{"done": true, "result": {…}}` |

**LÜCKE L5:** `async_validate_backup` (`config_api.py:1225`) nimmt keinen Aktor;
`async_detect_drift` (`:1312–1323`) und `async_prepare_restore` (`:1517`) prüfen kein Admin-Recht, obwohl
sie Inhalt oder Unterschiede liefern. Bei uns prüfen die Routen (immer Admin) und der Zeitplan (Modul) vorher.
**LÜCKE L4:** Für Freigaben, SSH-Pins und das ACL-Angebot gibt es keine Oberfläche und keine Route
(`enterprise-core.md:101–102`, `:154`; `configuration-api-v1.md:1428–1430`). R13–R20 decken nur die
Aktionen ab, die der Config Manager braucht.

Antwortformen (gekürzt; Zeiten in ISO-8601 UTC):

```json
// Overview (R1)
{"provider": "config_manager", "pending_approvals": 1,
 "routers": [{"router_id": "rtr_<32hex>", "name": "<Eintragstitel>", "enabled": true,
   "status": "ok", "error_class": null, "running": false,
   "last_backup_at": "2026-11-18T03:41:12+00:00", "versions": 12,
   "capability": {"state": "available", "reason": null},
   "schedule": {"mode": "daily", "time": "03:30", "next_run_at": "2026-11-19T03:52:00+00:00"},
   "drift": {"state": "open", "drift_id": "<id>", "critical_count": 1, "unknown_count": 0,
             "checked_at": "2026-11-18T09:10:00+00:00"}}]}

// RouterDetail (R2)
{"router_id": "rtr_<32hex>", "enabled": true,
 "capabilities": {"config.backup": {"state": "available", "reason": null},
                  "config.cgi_backup": {"state": "unavailable", "reason": "permission_denied"}},
 "ssh_pin": {"state": "pending", "fingerprint": "SHA256:<base64>"},
 "acl": {"offerable": ["config_backup_read"], "deployed_version": 8}}

// Version (R3/R4/R6/R7)
{"backup_id": "bkp_<32hex>", "router_id": "rtr_<32hex>", "created_at": "…", "last_seen_at": "…",
 "reason": "scheduled", "backup_type": "full_archive", "status": "ok", "protected": false,
 "created_by": {"kind": "module", "mine": false}, "openwrt_version": "24.10.0",
 "validation": {"state": "ok", "checked_at": "…"}, "warnings": [], "note": null,
 "artifacts": [{"kind": "archive", "size_bytes": 41234, "sha256": "<64hex>"}]}

// Diff (R8) – Werte maskiert, Geheimnisse nur „geändert“
{"from": "bkp_<32hex>", "to": "live", "complete": true,
 "changes": [{"area": "wlan", "risk": "high", "config": "wireless", "section": "default_radio0",
              "option": "key", "op": "changed", "old": "***", "new": "***"}]}

// DriftState (R9–R11)
{"state": "open", "report": {"drift_id": "<id>", "checked_at": "…", "baseline_backup_id": "bkp_<32hex>",
 "critical_count": 1, "unknown_count": 0, "comparison": "complete"}, "acks": []}

// RestorePlan (R12)
{"backup_id": "bkp_<32hex>", "compatible": true, "findings": [{"code": "release_downgrade", "level": "warning"}],
 "steps": [{"order": 1, "action": "archive_restore", "instructions": "config.restore.manual_upload"}],
 "expires_at": "…"}

// Approval (R13–R19)
{"approval_id": "apr_<32hex>", "action": "export", "router_id": "rtr_<32hex>", "subject_id": "bkp_<32hex>",
 "status": "pending", "requested_by": {"kind": "user", "mine": true}, "expires_at": "…"}
```

Bodys der POST-Routen: R5 `{"note"?: str}`, R7 `{"protected": bool}`, R11
`{"state": "acknowledged" | "known", "note"?: str}`, R13 `{"artifact"?: "archive" | "uci" | "inventory"}`,
R16 `{"reason"?: str}`, alle anderen `{}`.

### 7.6 Export-Ablauf und Download

1. R13 legt den Antrag an (kritische Aktion, gebunden an `binding_checksum(version_id, artifact)`,
   `configuration-api-v1.md:310–324`).
2. R15 gibt frei (der eigene Antrag darf freigegeben werden, `enterprise-core.md:84–90`).
3. R17 löst die Freigabe einmal ein. `handle.reader()` liest einmal; `sha256` wird neu berechnet. Weicht
   er von `handle.sha256` ab → `422 backup_integrity_failed`, kein Byte geht hinaus.

Kopfzeilen der Datei:

| Header | Wert |
|---|---|
| `Content-Type` | `handle.content_type` (`application/gzip` oder `application/json`) |
| `Content-Disposition` | `attachment; filename="<handle.filename>"`; der Name wird vorher auf `[A-Za-z0-9._-]` gekürzt |
| `Content-Length` | `handle.size_bytes` |
| `Cache-Control` / `Pragma` | `no-store` / `no-cache` |
| `X-Content-Type-Options` | `nosniff` |
| `Content-Security-Policy` | `default-src 'none'; sandbox` |
| `Referrer-Policy` | `no-referrer` |
| `X-Checksum-SHA256` | `handle.sha256` |

Ein zweites Einlösen → `409 approval_invalid`. Offene Anträge überleben keinen HA-Neustart
(`configuration-api-v1.md:447–449`); das Panel beginnt dann neu.

### 7.7 Manuelle Wiederherstellung

Automatischer Restore ist in Phase 1 aus: `async_request_restore` wirft `CapabilityUnavailableError`
(`configuration-api-v1.md:1355–1376`). Es gibt **keine** Route für `async_request_restore` oder
`async_execute_restore`. R12 liefert Befund und Schritte. Die Schritt-Texte sind i18n-Schlüssel und
stammen aus `_restore_steps` (`config_provider.py:709–735`). Das Panel zeigt dazu:

1. Ergebnis der Prüfung ansehen; bei `incompatible` abbrechen.
2. Archiv über R13/R15/R17 herunterladen (enthält alle Router-Geheimnisse im Klartext).
3. In LuCI unter „System → Sichern/Aktualisieren → Sicherung wiederherstellen“ hochladen oder von Hand
   `sysupgrade -r <datei>` ausführen. Das ist nicht umkehrbar.
4. Der Router startet neu. Ändert der Befund Zugang, Management-IP oder Firewall-Eingang, steht ein
   Hinweis auf Konsole oder Failsafe da.
5. Nach dem Neustart in HA R10 auslösen und den Drift prüfen.

## 8. Panel-Untertab

Registrierung über `registerEnterpriseTab` (`frontend/topology/src/enterprise/registry.ts:55–69`), Anzeige
über `EnterpriseView.tsx:7–24`, Navigation `Sidebar.tsx:52`, `TopologyView.tsx:566`.

**LÜCKE L8:** Eine Tab-Komponente bekommt keine Props und kein `hass` (`registry.ts:33–42`). Lösung in
unseren Dateien: `bindConfigHass(getHass)` speichert den Getter im Modul. `main.tsx` ruft es einmal im
Konstruktor des Panels auf, neben `createIntelApi(() => this._hass)` (`main.tsx:42`).
**LÜCKE L9:** `refreshToken` in `api.ts:972` ist nicht exportiert. `configApi.ts` hat eine eigene kleine
Kopie (401 → einmal erneuern, Muster `api.ts:1103–1158`). `api.ts` und `types.ts` bleiben unverändert.

| Datei (neu, `frontend/topology/src/enterprise/config/`) | Inhalt |
|---|---|
| `register.ts` | `bindConfigHass`, `registerEnterpriseTab({ id: 'config', title: 'Konfiguration', order: 10, component: ConfigManagerView, isAvailable: () => getHass()?.user?.is_admin === true })` |
| `configApi.ts` | `createConfigApi(getHass)`: alle Routen R1–R20, Bearer-Fetch auf `/api/openwrt_topology/config/…`, R17 als `blob` → `URL.createObjectURL` → `<a download>` → `revokeObjectURL` |
| `configTypes.ts` | Typen zu 7.5 |
| `configLogic.ts` | reine Funktionen: Zustand je Router, Fehlertext je `code`, Text je Restore-Schlüssel, Zeitformat, Risiko-Farbe |
| `configMock.ts` | Mock-Client für den Dev-Modus (`?configmock`), alle Zustände |
| `ConfigManagerView.tsx` | Router-Liste + Detail; Abschnitte Versionen, Drift, Vergleich, Zugang, Freigaben |
| `ConfigVersionList.tsx` | Versionen, Schutz-Schalter, Prüfen, Export, Restore-Prüfung |
| `ConfigDiffView.tsx` | nach Bereich gruppiert, Farbe nach Risiko, Geheimnisse als „geändert“ |
| `ConfigDriftPanel.tsx` | Drift-Bericht, „Jetzt prüfen“, Bestätigen / „als bekannt“ |
| `ConfigRestoreCheck.tsx` | Befund + Schritte (7.7) |
| `ConfigApprovalDialog.tsx` | zweistufig: Antrag → Häkchen „enthält alle Geheimnisse im Klartext“ → Freigeben → Ausführen; Ablaufzeit sichtbar |
| `ConfigAccessPanel.tsx` | SSH-Pin (Fingerprint anzeigen, bestätigen, zurücksetzen), ACL-Angebot (Unterschied und Risiken aus `offer`) |
| `config.css` | eigenes Stylesheet, per `?inline` als `<style>` in der View (Shadow Root wie `main.tsx:266–274`); `topology.css` bleibt |
| `configLogic.test.mjs` | Tests mit `node:test` (Node 24 entfernt Typen selbst), Import von `./configLogic.ts` |

Geänderte Dateien: `main.tsx` (Import von `register.ts`, `bindConfigHass` im Konstruktor, Dev-Mock bei
`?configmock` neben `:276`), `package.json` (nur Skript `"test": "node --test src/enterprise/config/"`, keine
neue Abhängigkeit), `dist/topology-bundle.js` (Build), `topology_panel.py:73` `_PANEL_VERSION` →
`"20261118-config-manager"`.

Zustände, die jede Ansicht zeigt:

| Zustand | Auslöser | Anzeige |
|---|---|---|
| Laden | erste Anfrage | Platzhalterzeilen |
| Kein Admin | `403` | Hinweis, keine Knöpfe (Tab ist für Nicht-Admins ohnehin aus) |
| Nicht geladen / Core aus | `410` / `503` | Hinweis und „Erneut versuchen“ |
| Fremder Provider | `409 provider_conflict` | Hinweis, nur Lesen |
| Option aus | `enabled: false` | Hinweis auf die Router-Optionen |
| Noch nicht geprüft / keine Rechte | `capability.state` + `reason` | Knopf ACL-Angebot oder SSH-Pin bestätigen |
| SSH-Pin ausstehend / abweichend | `ssh_pin.state` | Fingerprint + Bestätigen; bei Abweichung rote Warnung |
| Keine Versionen | Liste leer | „Jetzt sichern“ |
| Läuft | `running` / `409 operation_in_progress` | Spinner, Abfrage alle 5 s, höchstens 5 min |
| Fehler | `status: failed` | `error_class` als Text, `retryable` → „Erneut versuchen“ |
| Drift offen / bestätigt | `drift.state` | Zähler, Bestätigen |
| Freigabe abgelaufen | `409 approval_invalid` | „Neu beantragen“ |

Kleine Bildschirme: unter 600 px eine Spalte; Liste → Detail mit Zurück-Knopf; Tabellen werden zu Karten;
Knöpfe mindestens 40 px hoch; Diff-Zeilen mit `overflow-wrap: anywhere`; kein waagrechtes Scrollen.

Prüfung: `npm run build` (tsc strict + vite), `npm test` grün, Dev-Seite mit `?configmock` bei 375 px und
1280 px in allen Zuständen der Tabelle.

## 9. ACL

Die gestufte ACL v9 baut und verteilt der Core (Antwort Q2 im Vorgängerplan, `2026-11-17-config-manager.md:1141`).
Der Config Manager fasst `acl_provisioning.py` und `scripts/ha-openwrt-router.json` **nicht** an.

| Punkt | Beleg | Bei uns |
|---|---|---|
| Stufe `config_backup_read` (cgi-io backup, rpc-sys packagelist, uci read der 14 Configs) | `acl-tiers.md:33` | nur dieser Tier wird angeboten |
| Angebot nur mit Option an | `acl-tiers.md:102` (`option_disabled`) | R2 zeigt `offerable` aus `offerable(entry.options)` |
| Ablauf | `acl-tiers.md:179–180` | R18 → R15 → R20 (`acl_deploy`) |
| Nach dem Schreiben | Core prüft Capabilities neu | Panel lädt R2 neu |

Nichts wird automatisch auf einen Router geschrieben; jeder Schritt braucht den Klick eines Admins.

## 10. Diagnose

`diagnostics.py`: neuer Schlüssel `"config_manager": _config_manager_summary(hass, entry.entry_id)` neben
`"enterprise_core"` (`diagnostics.py:139`), Muster `_enterprise_core_summary` (`:187–227`) mit `mask_for_output`.
Inhalt: Provider angemeldet (bool), Option und Zeitplan, Anzahl Versionen, letzter Status, `error_class`,
`last_attempt_at`, `next_run_at`, Drift-Zustand mit Zählern, Merker des Zeitplans (Zeiten und Zähler),
`drift_versions_today`. Nie Snapshots, Diffs, Notizen, Fingerprints, Benutzer-IDs.

## 11. Doku und Release

| Datei | Änderung |
|---|---|
| `manifest.json` | `"version": "1.45.0"` |
| `CHANGELOG.md` | Abschnitt 1.45.0: Backup-Modul, Zeitplan, Dienst, 4 Entities je Router, Panel-Tab, Hinweis auf Geheimnisse im Export |
| `README.md` | Feature-Liste + Abschnitt „Konfigurations-Backup“ (Kurzform, Verweis auf die neue Doku) |
| `TODO.md` | erledigt: Backup Phase 1; offen: automatischer Restore (UCI, Phase 2), Löschen in der Oberfläche, Freigabe-UI für andere Module |
| `docs/configuration-manager.md` (neu) | Einschalten, Optionen, Zeitplan und Kosten, Sensoren, Dienst mit Beispiel, Panel, Export und manuelle Wiederherstellung (7.7), Grenzen, Datenschutz |
| `docs/enterprise-core.md` | „Kein Backup-Modul enthalten“ (`:153`) und „Keine Oberfläche für Freigaben“ (`:154`, `:101–102`) an 1.45.0 anpassen |

`CLAUDE.md` wird **nicht** geändert. Vorschläge für den Nutzer: in der Projektstruktur `config_manager.py`,
`config_entities.py`, `config_views.py`, `services.yaml` und `frontend/topology/src/enterprise/config/`
nennen; Testzahl aktualisieren; HACS-Stand auf 1.45.0.

## 12. Tests

Werkzeuge: `tests/core_testkit.py` (`make_hass` `:181`, `FakeEntry` `:271`, `FakeCoordinator` `:313`,
`router_data` `:349`, `setup_router` `:469`, `core_of` `:485`, `bus_events` `:518`) und
`tests/core_test_provider.py` (`FakeConfigProvider` `:168`, `start_env` `:485`, `approve_as` `:544`,
`restart` `:563`). Die Laufzeit bekommt `FakeConfigProvider` über `provider_factory`.

| # | Fall | Datei::Test |
|---|---|---|
| 12 | Versionierung | `tests/test_config_manager.py::test_scheduled_run_once_per_day`, `::test_identical_scheduled_run_is_deduplicated` (`created: false`, Sensor Versionen gleich), `::test_release_change_backup_once_per_version`, `::test_drift_version_capped_per_day` |
| 18 | Parallele Backups | `tests/test_config_manager.py::test_six_routers_run_one_at_a_time` (Tor im Fake, Höchstwert 1), `::test_stagger_stable_within_hour`, `::test_operation_in_progress_retried_next_tick` |
| 19 | HA-Neustart während Backup | `tests/test_config_manager.py::test_restart_mid_backup_reruns_same_day` (mit `restart`), `::test_unload_cancels_timers_and_tasks`, `::test_last_entry_unload_unregisters_provider`, `::test_first_entry_unload_keeps_provider` |
| 15 | Abgebrochener Restore | `tests/test_config_views.py::test_no_route_executes_restore`, `tests/test_config_manager_regressions.py::test_no_restore_execution_call` (AST-Suche nach `async_request_restore`/`async_execute_restore` in den neuen Modulen) |
| 16 | Verbindungsverlust nach Restore | `tests/test_config_views.py::test_restore_check_lists_lockout_step`; Frontend `configLogic.test.mjs` → „jeder Restore-Schlüssel hat einen Text“ |
| 20 | Regressionen | `tests/test_config_manager_regressions.py::test_option_off_zero_router_calls`, `::test_existing_unique_ids_unchanged`, `::test_no_net_imports` (kein `net_engine`/`net_rules`/`net_events`), `::test_entities_import_no_http`, `::test_bus_payloads_have_no_raw_user_id`; dazu volle Suite |
| – | Routen | `tests/test_config_views.py`: 403 für Nicht-Admin trotz offenem Panel, 410 nach letztem Unload, 400/404 für IDs, Fehlerabbildung parametrisiert über 7.3, Export-Header, zweites Einlösen 409, Prüfsummenfehler 422 ohne Bytes, kein Geheimnis-Marker des Fakes in einer JSON-Antwort |
| – | Entities | `tests/test_config_entities.py`: `unique_id`-Schema, Zustände inkl. `disabled`/`never`, Dispatcher-Update, Drift aus `api.events` nach Neustart, Adoption räumt auf |
| – | Options-Flow | `tests/test_config_options.py`: Felder nur mit Provider oder Option an, Standardwerte, Zeitformat, Speichern ohne Neuladen, Zeitplan liest den neuen Wert beim nächsten Takt |
| – | Dienst | `tests/test_config_service.py`: Admin ok, Nicht-Admin `ServiceValidationError`, Automation ok, Option aus, unbekanntes Gerät, Antwortform, mehrere Geräte nacheinander |
| – | Diagnose | `tests/test_diagnostics.py` erweitert: Block `config_manager` ohne Geheimnis-Marker und ohne Benutzer-ID |

Neue Testdateien bekommen Namen, die es noch nicht gibt; vorhandene `tests/test_config_*` bleiben unberührt.
CI: `ruff check`, `ruff format --check`, `pytest` (`.github/workflows/tests.yaml`), hassfest für `services.yaml`.

## 13. Pakete

| Paket | Besitzt (nur dieses Paket ändert sie) | Fertig, wenn |
|---|---|---|
| **BACKEND** | neu: `config_manager.py`, `config_entities.py`, `config_views.py`, `services.yaml`, `tests/test_config_manager.py`, `tests/test_config_views.py`, `tests/test_config_entities.py`, `tests/test_config_options.py`, `tests/test_config_service.py`, `tests/test_config_manager_regressions.py`; geändert: `__init__.py`, `sensor.py`, `binary_sensor.py`, `config_flow.py`, `const.py`, `strings.json`, `translations/en.json`, `translations/de.json`, `diagnostics.py`, `tests/test_diagnostics.py` | Abschnitt 1–7, 10 und 12 umgesetzt; `ruff` und volle Suite grün; Routen antworten wie 7.5 |
| **FRONTEND** | neu: `frontend/topology/src/enterprise/config/*`; geändert: `frontend/topology/src/main.tsx`, `frontend/topology/package.json`, `frontend/dist/topology-bundle.js`, **`topology_panel.py` nur Zeile `_PANEL_VERSION`** | Abschnitt 8; `npm run build` und `npm test` grün; Dev-Seite mit `?configmock` in allen Zuständen bei 375 px und 1280 px geprüft |
| **DOKU/RELEASE** | `manifest.json`, `CHANGELOG.md`, `README.md`, `TODO.md`, `docs/configuration-manager.md`, `docs/enterprise-core.md` | Abschnitt 11; Version 1.45.0; keine IPs, MACs oder Hostnamen in der Doku |

Reihenfolge: BACKEND und FRONTEND parallel gegen diesen Vertrag (FRONTEND zuerst mit `configMock.ts`).
DOKU/RELEASE danach. Zum Schluss prüft der Master das Panel gegen das echte Backend mit
`scripts/mock_router.py`. BACKEND ändert `config_flow.py` erst, wenn der Masking-Builder (`config_*.py`,
`tests/test_config_*`) gemergt ist.

## 14. Lücken im Core (Zusammenfassung)

| ID | Lücke | Beleg | Lösung bei uns |
|---|---|---|---|
| L1 | Provider-Lebensdauer ohne Zähler je Eintrag | `enterprise_core.py:190–237`, `config_api.py:503–566` | Domain-Laufzeit mit Zähler (1) |
| L2 | kein Scheduler | `configuration-api-v1.md` §8 (`:702–779`) | ein 5-min-Takt (3) |
| L3 | kein Firmware-Hook für Module | `router_registry.py:1683`, `config_api.py:768` | Versionsvergleich Register ↔ neueste Version (3) |
| L4 | keine Route/UI für Freigaben, SSH-Pin, ACL-Angebot | `enterprise-core.md:101–102`, `:154` | R13–R20 (7) |
| L5 | kein Admin-Check bei validate, detect_drift, prepare_restore | `config_api.py:1225`, `:1312–1323`, `:1517` | Admin-Check in den Routen (7) |
| L6 | Aufbewahrung/Größe nur global | `config_api.py:2002–2015` | keine Felder je Router (2) |
| L7 | kein gespeicherter Drift-Bericht | `config_api.py:1312–1375` (nur Events, Acks) | aus `api.events` wiederherstellen (6) |
| L8 | Tab ohne Props/hass | `registry.ts:33–42` | `bindConfigHass` (8) |
| L9 | `refreshToken` nicht exportiert | `api.ts:972` | Kopie in `configApi.ts` (8) |
| L10 | Freigaben gehen beim Neustart verloren | `configuration-api-v1.md:447–449` | Panel beantragt neu (7.6) |
| L11 | Bus-Salz privat | `core_audit.py:115` | eigenes Salz + `mine` (7.4) |

## 15. Annahmen und nicht Geprüftes

- `api.subscribe`-Listener laufen im Event-Loop und dürfen `async_dispatcher_send` aufrufen (nicht gelesen:
  Aufrufstelle in `config_api.py` nach `:2870`).
- `async_list_backups` sortiert die neuesten zuerst; `since` filtert auf `created_at` (nicht geprüft).
- Format von `drift_id` nicht geprüft; darum die lockere Regel in 7.2.
- Felder von `CapabilityStatus`, `ssh_pin_status()` und `acl_offer()` sind nur aus der Doku übernommen;
  BACKEND gleicht die Antwortformen in 7.5 am Code ab und ändert nur Feldnamen, keine Routen.
- `security.config_option_changed` kommt über `api.subscribe` an (Audit → Bus, `config_api.py:736`); sonst
  bemerkt der Takt den Wechsel nach höchstens 5 min.
- Node 24 (`node --version` lokal v24.22.1) entfernt TypeScript-Typen ohne Flag; in CI läuft kein Frontend-Test.
- Kosten in Abschnitt 3 sind Schätzungen aus dem Vorgängerplan (`2026-11-17-config-manager.md:905–925`).
- Nicht geprüft: Verhalten mit echten Routern, HA-Laufzeit, hassfest-Lauf für `services.yaml`.

## 16. Entscheidungen und offene Fragen

| Art | Inhalt |
|---|---|
| DECIDED | ein Provider je Installation mit Zähler, Abmelden beim letzten Eintrag vor dem Core-Unload |
| DECIDED | kein `set_retention_policy`; der Core-Standard 7/4/6 gilt |
| DECIDED | ein 5-min-Takt statt Zeit-Trigger je Router; liest Optionen live, holt verpasste Läufe nach |
| DECIDED | keine eigenen Events; Aktualisierung über `api.subscribe` + Dispatcher |
| DECIDED | Routen melden sich selbst an; `topology_panel.py` gehört FRONTEND nur für `_PANEL_VERSION` |
| DECIDED | Routen sind immer nur für Admins |
| DECIDED | keine Restore-Ausführung, keine Lösch-Route in 1.45.0 |
| DECIDED | Frontend-Tests mit `node:test` ohne neue Abhängigkeit |
| QUESTION Q1 | Entities bei ausgeschalteter Option: immer anlegen (Status `disabled`) / erst ab Einschalten — Empfehlung: immer anlegen |
| QUESTION Q2 | Nach neuem Drift automatisch eine UCI-Version (höchstens 4/Tag): ja / nein — Empfehlung: ja |
| QUESTION Q3 | Ziel des Dienstes: `device_id` / `config_entry_id` — Empfehlung: `device_id` |
| QUESTION Q4 | Löschen von Versionen im Panel schon in 1.45.0: nein / ja — Empfehlung: nein |
