# Configuration API v1 – Vertrag

<!-- Ablage: docs/dev/configuration-api-v1.md · Plan: docs/plans/2026-11-17-enterprise-core.md
     Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens in diesem Dokument. -->

Dieser Vertrag beschreibt, wie Module (zuerst `config-manager`, später Security
Intelligence, Network Intelligence, Time Machine, Firmware Lifecycle, Self-Healing) mit dem
Enterprise Core sprechen. Code, Docstrings und Bezeichner sind englisch, dieser Text deutsch.

Stand: 1.44.0 (2026-11-18). Überarbeitet nach dem Review (Critic) und dem Abgleich mit
`config-manager`. Alle Änderungen gegenüber Commit `5c9d248` stehen in Abschnitt 19, die von
1.44.0 ab #65.

## 0. Status: was es als Code gibt und was später kommt

| Teil | Modul | Stand |
|---|---|---|
| Konstanten, Enums, Dataclasses, reine Helfer (Policy, Dedup, Aufbewahrung, Basis), `VerifiedActor`, `WriteAuthorization`, Protocols | `core_models.py` | **Code, getestet** |
| `ErrorClass`, `ConfigApiError` + 27 Unterklassen | `core_errors.py` | **Code, getestet** |
| Die eine Maskierung: `mask_secrets`, `mask_for_output`, `redact_text`, `is_secret_key`, `is_secret_option`, `is_secret_path`, `secret_digest_factory` | `core_masking.py` | **Code, getestet** |
| `async_get_configuration_api(hass, version=1)`, `ConfigurationManager` (Warteschlange, Locks, Drift, Export, Löschen, Aufbewahrung, Proben) | `config_api.py` | **Code, getestet** (Teil 2) |
| `ActionGuard` (Implementierung von `ActionGuardProtocol`, mit Ledger) | `core_guard.py` | **Code, getestet** (Teil 2) |
| `VersionStore` (Implementierung von `VersionStoreProtocol`) inkl. Installations-Schlüssel und GFS-Aufbewahrung | `version_store.py` | **Code, getestet** (Teil 2) |
| Test-Provider (nur für Tests, kein Router-Aufruf) | `tests/core_test_provider.py` | nur unter `tests/` |
| `RouterRegistry`, Identität, Capability-Ableitung | `router_registry.py`, `router_identity.py`, `capabilities.py` | **Code, getestet** (Teil 1) |
| Zwei Audit-Ringe, Bus-Event, Dedup | `core_audit.py` | **Code, getestet** (Teil 1) |
| Store-Laden mit `.bak` und Wiederaufbau (gemeinsamer Helfer für Registry und Audit) | `core_store.py` | **Code, getestet** (Teil 1) |
| Lebenszyklus, Verdrahtung in `__init__.py` (Setup, Unload, Remove; jeder Haken in eigenem try/except) | `enterprise_core.py` | **Code, getestet** (Teil 1) |
| Option `config_backup_enabled` (Standard aus, Abschnitt 5), Repair-Issue des Installations-Schlüssels | `config_flow.py`, `router_registry.py`, `config_api.py` | **Code, getestet** (1.44.0) |
| Gestufte ACL v9 als Angebot, Verteilen über den Core (`acl_deploy`), ACL beim Start erhalten (`ensure_acl_respecting_offer`) | `acl_provisioning.py`, `core_security.py` | **Code, getestet** (1.44.0) |
| SSH-Host-Key-Pins je Router (Store `ssh_host_keys`), `ssh_pin_confirm`, `ssh_pin_reset`, `ProviderContext.async_ssh_run_pinned` | `core_security.py`, `api.py` | **Code, getestet** (1.44.0) |
| `rf.*` aus der verteilten ACL; Capability-Detektoren der Module (Abschnitt 17.1) | `capabilities.py`, `router_registry.py` | **Code, getestet** (1.44.0) |
| Panel-Container „Enterprise“ | Frontend | **Code** (1.44.0; Untertabs registrieren Module) |
| Backup-Engine (Provider) | `config-manager` | nicht enthalten: alle `config.*` sind `unavailable`, bis ein Provider installiert ist |

Alles, was „später“ ist, steht hier als **Signatur**. Die Signaturen sind als Protocols in
`core_models.py` festgeschrieben; ein Provider oder Modul kann heute schon dagegen
programmieren und mit eigenen Test-Doubles testen. Die reinen Regeln (wer darf was, welche
Version wird dedupliziert, was die Aufbewahrung löscht, welche Basis gilt) sind schon heute
als Funktionen im Code; die spätere Implementierung ruft genau diese Funktionen auf.

Import für Module:

```python
from custom_components.openwrt_router.core_models import (
    Actor, BackupReason, Capability, ConfigRef, GuardedAction, ProviderContext, ...
)
from custom_components.openwrt_router.core_errors import (
    ConfigApiError, ErrorClass, CapabilityUnavailableError, ...
)
from custom_components.openwrt_router.core_masking import mask_for_output, is_secret_key
```

## 1. Begriffe

| Begriff | Bedeutung |
|---|---|
| Version = Backup | Eine gesicherte Konfiguration eines Routers. Kennung `backup_id` (`bkp_<32 hex>`), Alias `version_id`. Typ `BackupRecord`, Alias `VersionRecord`. |
| Artefakt | Eine Datei einer Version: `archive` (sysupgrade-Archiv), `uci` (normalisierter UCI-Snapshot), `inventory` (Paketliste, Board-Daten). |
| Index | Metadaten aller Versionen im Store `openwrt_router.config_catalog`. Gehört dem Core. |
| Provider | Das eine Modul, das Artefakte vom Router holt und analysiert (`config-manager`). |
| Kritische Aktion | Braucht Antrag + Freigabe durch einen Admin-Benutzer. **Kritisch heißt nicht „schreibt“**: Export liest nur, ist aber kritisch, weil er alle Geheimnisse im Klartext herausgibt. |
| Bindungsprüfsumme | Prüfsumme, an die eine Freigabe/Autorisierung gebunden ist (Abschnitt 6.6). |
| `VerifiedActor` | Ein `Actor`, den der Core gerade gegen `hass.auth` geprüft hat (Abschnitt 6.2). Nur ihn nimmt der Guard an. |
| Ledger | Liste der vom Guard ausgegebenen `WriteAuthorization`-IDs; `consume` akzeptiert nur IDs daraus. |
| Basis | Die Version, gegen die Drift gemessen wird (Abschnitt 11.2). |

## 2. Versionierung und Zugriff

```python
CONFIGURATION_API_VERSION = 1
CONFIGURATION_API_MIN_VERSION = 1
SUPPORTED_API_VERSIONS = (1,)
PROVIDER_API_VERSION = 1
SUPPORTED_PROVIDER_API_VERSIONS = (1,)
BACKUP_METADATA_VERSION = 1

async def async_get_configuration_api(
    hass: HomeAssistant, version: int = 1
) -> ConfigurationApiProtocol: ...          # später, config_api.py

def ensure_supported_api_version(version: int) -> int: ...   # Code
```

- `SUPPORTED_API_VERSIONS` gilt für Konsumenten der API, `SUPPORTED_PROVIDER_API_VERSIONS`
  für `ConfigBackupProvider.provider_api_version`. Ein Provider mit einer anderen Version wird
  bei `register_provider` mit `ApiVersionError` abgelehnt.
- Innerhalb v1 nur **additive** Änderungen: neue optionale Felder mit Standardwert, neue
  Enum-Werte in **nicht persistierten** Enums, neue Event-Typen, neue Capability-Namen, neue
  Methoden. Alle Dataclasses sind `kw_only`, neue Felder verschieben also keine
  Positionsargumente.
- **Neuer Wert in einem persistierten Enum ist nicht additiv.** Persistiert (über
  `from_dict` gelesen) sind `ActorKind`, `BackupType`, `BackupReason`, `VersionStatus`,
  `ErrorClass`, `ValidationStatus`, `DriftAckState`, `Severity`, `EventResult` und die
  Artefaktschlüssel (`ArtifactKind`). Ein älterer Core würde einen neuen Wert als
  `BackupMetadataError` ablehnen. Ein neuer Wert erhöht deshalb `BACKUP_METADATA_VERSION`
  (bzw. `CORE_STORE_VERSION` für Audit und Drift-Bestätigungen) und bringt eine Migration in
  `METADATA_MIGRATIONS` mit.
- Ein Konsument muss unbekannte Werte in `str`-Feldern (`CoreEvent.type`,
  `CapabilityStatus.capability`/`reason`, `ApprovalRequest.action`) tolerieren.
- Unbekannte Version (auch `True`, `0`, `"1"`) ⇒ `ApiVersionError` mit
  `details["supported_versions"]`.

```python
try:
    api = await async_get_configuration_api(hass, version=1)
except ApiVersionError as err:
    _LOGGER.warning("Configuration API unavailable: %s", err.to_dict())
    return
```

## 3. Kennungen

| Präfix | Bedeutung | Erzeugung |
|---|---|---|
| `rtr_` | Router | `default_router_id(entry_id)` = `"rtr_" + uuid5(ROUTER_ID_NAMESPACE, entry_id).hex`; nach Adoption die alte ID |
| `bkp_` | Version | `new_id(BACKUP_ID_PREFIX)` (zufällig, nicht aus der Zeit ableitbar) |
| `evt_` | Audit-Eintrag | `new_id` |
| `apr_` | Freigabe-Antrag | `new_id` |
| `pln_` | Restore-Plan | `new_id` |
| `wau_` | WriteAuthorization | nur der Guard |
| `vac_` | Prüfung eines Akteurs (`VerifiedActor.verification_id`) | nur `async_verify_actor` |
| `cor_` | Korrelations-ID | `new_id`, frei vom Aufrufer |

`ROUTER_ID_NAMESPACE = 5fc97c09-217a-4ccb-af32-d954b049fecf` ändert sich nie.
`is_valid_id(value, prefix)` prüft das Format (`<prefix><32 hex klein>`).
`installation_key_id(key)` (16 hex) ist die öffentliche, nicht geheime Kennung eines
Installations-Schlüssels (Abschnitt 11.3).

### 3.1 Reservierte Präfixe und Namensräume

Ein Test (`test_core_followup_b7_contract.py`) prüft, dass jede Konstante hier steht.

| Präfix / Wert | Art | Wem gehört es | Konstante | Regel |
|---|---|---|---|---|
| `rtr_`, `bkp_`, `evt_`, `apr_`, `pln_`, `wau_`, `vac_`, `cor_` | Kennungen (§3) | Core | `*_ID_PREFIX` | nur vom Core vergeben (`cor_` auch vom Aufrufer) |
| `-` | Flotten-Kennung (§4.1) | Core | `FLEET_ROUTER_ID` | nie eine Router-ID |
| `usr_` | Benutzer-Pseudonym im Bus-Event (§12.1) | Core | `ACTOR_PSEUDONYM_PREFIX` | nur im Bus-Payload und in der Diagnose |
| `mac_`, `ipa_`, `hst_`, `ssd_`, `bss_`, `cli_` | Kennungs-Pseudonyme (§13) | Modul (mit eigenem Schlüssel) | `IDENTIFIER_PSEUDONYM_PREFIXES` | `pseudonymise_identifier` |
| `router.`, `configuration.`, `security.`, `core.` | Event-Namensräume (§12.3) | Core | `CORE_EVENT_NAMESPACES` | `emit` eines Moduls ⇒ `ValueError` |
| `security_center.`, `net_diagnostics.`, `wifi_rf.` | Event-Präfixe bekannter Module (§17.1) | das genannte Modul | `MODULE_EVENT_PREFIXES` | kein anderes Modul registriert darunter |
| `transport.`, `data.`, `stream.`, `pkg.` | Capability-Namensräume des Core (§5) | Core | `CORE_CAPABILITY_NAMESPACES` | kein Detektor darf sie melden |
| `config.` | Capability-Namensraum des Providers (§5) | Provider | `CONFIG_CAPABILITY_NAMESPACE` | nur über `async_probe` |
| `security.`, `diag.`, `rf.` | Capability-Namensräume der Module (§17.1) | `security_center`, `net_diagnostics`, `wifi_rf` | `MODULE_CAPABILITY_NAMESPACES`, `RESERVED_NAMESPACES` | Core vergibt dort nichts, außer `rf.txpowerlist`, `rf.survey`, `rf.scan` (`CORE_OWNED_MODULE_CAPABILITIES`) |
| `log.` | geteilter Capability-Namensraum | jedes Modul (als sein eines Präfix) | `RESERVED_NAMESPACES` | Core vergibt dort nichts |
| `<modul>.` | Aktionsnamen (§6.3) | das Modul | `register_action` | Name muss mit `<modul>.` beginnen; kein Core-Namensraum, keine `GuardedAction` |
| `core` | Schlüssel-Besitzer (§11.5) | Core | `CORE_KEY_OWNER` | kein Modul heißt so |
| `rebaseline:` | Präfix einer `drift_id` beim erlaubten Re-Baseline (§11.3) | Core | `REBASELINE_DRIFT_PREFIX` | nur vom Core |

## 4. Identität und Registry

```python
class RouterRegistryProtocol(Protocol):
    def get(self, router_id: str) -> RouterRecord: ...            # RouterNotFoundError
    def get_by_entry(self, entry_id: str) -> RouterRecord: ...    # RouterNotFoundError
    def find(self, router_id: str) -> RouterRecord | None: ...
    def list(self, *, include_orphaned: bool = False) -> tuple[RouterRecord, ...]: ...
    def capabilities(self, router_id: str) -> Mapping[str, CapabilityStatus]: ...
    def has_capability(self, router_id: str, capability: str) -> bool: ...
    def require_capability(self, router_id: str, capability: str) -> None: ...
    def adoption_candidates(self, entry_id: str) -> tuple[AdoptionCandidate, ...]: ...
    async def async_adopt(self, entry_id: str, orphan_router_id: str, *, actor: Actor) -> RouterRecord: ...
```

`async_adopt` prüft `actor` neu gegen `hass.auth` (Abschnitt 6.2); nur ein Admin-Benutzer
darf adoptieren.

`RouterRecord`:

| Feld | Typ | Bedeutung |
|---|---|---|
| `identity` | `RouterIdentity` | ID, Eintrag, Hostname, Host/Port, MACs, Modell, Board, Firmware, Rolle, APs, Interfaces, `fingerprint`, `identity_flags`, abgeleitet `status` |
| `state` | `RecordState` | `active` / `orphaned` |
| `connection` | `ConnectionInfo` | host, port, protocol, transport (`ubus`/`ssh_fallback`/`unknown`), nie Zugangsdaten |
| `reachability` | `RouterReachability` | `online`/`offline`/`unknown`, letzte Erfolgs-/Versuchszeit |
| `firmware` | `FirmwareInfo` | distribution, version, revision, target, kernel, architecture, board_name, package_manager |
| `capabilities` | `Mapping[str, CapabilityStatus]` | Abschnitt 5, schreibgeschützt (`MappingProxyType`) |
| `registered_at`, `orphaned_at`, `adopted_at` | `datetime \| None` | UTC |
| `previous_entry_ids` | `tuple[str, ...]` | Einträge vor einer Adoption |
| `router_id`, `entry_id` | Eigenschaften | `entry_id` ist `None`, solange verwaist |

Identität: `RouterIdentity.identity_flags: frozenset[IdentityFlag]` hält **alle** Zweifel
gleichzeitig (`unverified`, `changed` = Hardwaretausch vermutet, `duplicate_suspected`). Die
Eigenschaft `status: IdentityStatus` ist daraus abgeleitet
(`primary_identity_status`): `changed` vor `duplicate_suspected` vor `unverified`; keine
Flagge = `confirmed`. IP- oder Hostname-Wechsel ändert die ID nie; nichts wird automatisch
zusammengeführt.

Verwaiste Datensätze bleiben für Adoption und Verlauf, aber nicht unbegrenzt (Review PR
#55, Punkt 6). Bei jedem Core-Laden, nur wenn Einträge UND Versionsspeicher bekannt sind
(`RouterRegistry.prune_orphans`): ohne Versionen nach `ORPHAN_RETENTION_DAYS` (90) Tagen
vergessen; über `MAX_ORPHANED_RECORDS` (64) gehen die ältesten, die ohne Versionen zuerst.
Ein Datensatz, dessen Eintrag (oder früherer Eintrag) noch existiert, wird nie gelöscht.
Jedes Löschen zählt (`orphans_forgotten_aged`/`_capped`), loggt und auditiert
`router.forgotten`; ausgelassene Läufe zählen `orphan_prune_skipped`. Beim Entladen fällt
der Laufzeitzustand des Eintrags weg (`release_entry`, Zähler `runtimes_released`).

```python
record = api.registry.get_by_entry(entry.entry_id)
if IdentityFlag.DUPLICATE_SUSPECTED in record.identity.identity_flags:
    return  # nichts automatisch tun, auch wenn status "changed" zeigt

for cand in api.registry.adoption_candidates(new_entry_id):
    _LOGGER.debug("candidate %s, %d shared MACs", cand.router_id, len(cand.matched_macs))
# nur auf ausdrücklichen Befehl eines Admin-Benutzers:
await api.registry.async_adopt(new_entry_id, cand.router_id, actor=admin_actor)
```

### 4.1 Flotten-Kennung `-` (`FLEET_ROUTER_ID`)

`FLEET_ROUTER_ID = "-"` (`core_models`, von `core_guard` re-exportiert;
`is_fleet_router_id(value)`) steht für „die ganze Flotte“ bzw. „kein bekannter Router“:
`installation_key_reset` wird mit `router_id = "-"` autorisiert, und eine Ablehnung für eine
unbekannte Router- oder Versions-ID wird unter `-` auditiert (die unbekannte ID wird nicht
wiedergegeben). `-` ist **nie** eine Router-ID:

- `registry.get("-")` ⇒ `RouterNotFoundError` mit `details = {"reason":
  "invalid_router_id", "fleet": true}` (ab B7; `fleet` fehlt bei anderen ungültigen IDs),
  `router_id = None`. `registry.capabilities("-")` ebenso.
- `registry.find("-")` ⇒ `None`; `registry.has_capability("-", …)` ⇒ `False`.
- `AuditLog.events(router_id="-")` (`events(router_id="-")`) liefert genau die Einträge, die
  mit `router_id = "-"` gespeichert sind, **nicht** die ohne Router (`router_id = None`, etwa
  `core.store_recovered` oder Modul-Events ohne Router). Nur der Dedup-Bereich
  (`dedup_scope`, §12.4) fasst `None` und `-` zusammen.

## 5. Capabilities

`CapabilityStatus`:

| Feld | Typ | Bedeutung |
|---|---|---|
| `capability` | `str` | Wert aus `Capability` oder Modulname unter registriertem Präfix |
| `state` | `CapabilityState` | `available` / `unavailable` / `unknown` |
| `reason` | `str` | `CapabilityReason` (`ok`, `no_data_yet`, `not_checked`, `not_probed`, `not_detected`, `permission_denied`, `transport_unsupported`, `unsupported_firmware`, `router_offline`, `entry_not_loaded`, `disabled`, `no_provider`, `provider_declined`) oder `provider:<code>` |
| `source` | `str` | z. B. `features.has_iwinfo`, `api.uses_ssh_fallback`, `probe:config_manager` |
| `detected_at` | `datetime` | UTC |
| `reason_text` | `str \| None` | Klartext für die UI; nie Konfigurationswerte, in `to_dict()` geschrubbt |
| `required_permissions` | `tuple[str, ...]` | fehlende rpcd-Rechte, z. B. `cgi-io:backup` |
| `detail` | `Mapping[str, Any]` | Einzelergebnisse, z. B. `{"wireless": True, "firewall": False}` für `config.uci_read`; schreibgeschützt, in `to_dict()` maskiert |
| `available` | Eigenschaft | `state is AVAILABLE` |

Namen (alle mit Punkt):

| Gruppe | Namen | Quelle |
|---|---|---|
| Transport | `transport.ubus`, `transport.ssh` | `api.uses_ssh_fallback` |
| Daten | `data.system_board`, `data.wireless`, `data.hostapd_clients`, `data.dhcp_leases`, `data.lldp`, `data.logs`, `data.iwinfo`, `data.services`, `data.uci` | `coordinator.data`, `FEATURE_CAPABILITIES` |
| Stream, Pakete | `stream.ubus`, `pkg.apk`, `pkg.opkg` | `coordinator.data` |
| Konfiguration (Provider) | `config.capture`, `config.backup`, `config.validate`, `config.diff`, `config.drift`, `config.restore_dry_run`, `config.restore`, `config.export` | `provider.supported(router)` + `async_probe` |
| Konfiguration (Router-Probe) | `config.cgi_backup`, `config.ssh_root`, `config.uci_read`, `config.packagelist` | `provider.async_probe(conn, ctx)` |

Regeln:

- Proben (`PROBED_CAPABILITIES`) laufen beim Setup, nach einer ACL-Neuverteilung und nach
  einem Firmware-Wechsel. **Nie im Poll.** Vor der ersten Probe: `unknown`/`not_probed`.
- `provider.supported(router)` ist die grobe Ja/Nein-Vorprüfung ohne Router-Aufruf.
  `async_probe` meldet **jede** `config.*`-Capability, über die der Provider entscheidet,
  auch nicht verfügbare (z. B. `config.restore` = `unavailable` in Phase 1, während alle
  anderen verfügbar sind). Nicht gemeldete `config.*`-Namen bleiben `unknown`/`not_probed`.
- Eine Probe prüft **nur Rechte und Metadaten** (z. B. ACL-Einträge, Paketliste, ob ein
  Endpunkt existiert). Sie holt nie ein Backup und liest keine Konfiguration, nur um zu
  sehen, ob es geht. Was sich so nicht klären lässt, meldet der Provider als
  `unknown`/`determined_on_first_use` (`CapabilityReason.DETERMINED_ON_FIRST_USE`).
- Ein `config.*` im Zustand `unknown`/`determined_on_first_use` **darf versucht werden**
  (`require_capability` lässt es durch). Das Ergebnis der ersten Verwendung setzt den Status:
  Erfolg ⇒ `available`; `ErrorClass.PERMISSION` ⇒ `unavailable`/`permission_denied`;
  `ErrorClass.NOT_AVAILABLE` ⇒ `unavailable`/`not_detected`; jeder andere Fehler lässt ihn
  `unknown`. `detail.settled_by` nennt die Operation; Zähler `first_use_settled`. Die
  Registry-Sicht folgt beim nächsten Coordinator-Poll.
- Neue Proben: beim Anhängen eines Routers, nach Firmware-Wechsel und auf Anfrage
  (`request_probe`, z. B. nach ACL-Neuverteilung). Laufende Proben werden zusammengefasst:
  höchstens eine läuft und eine wartet je Router (Zähler `probes_coalesced`).
- Ohne Provider: alle `config.*` `unavailable`/`no_provider`.
- Option `config_backup_enabled` aus (`OPTION_CONFIG_BACKUP_ENABLED`): alle `config.*`
  `unavailable`/`disabled`, es wird nicht geprobt.
- `config.restore` ist in Phase 1 `unavailable`, bis der Provider es meldet (Abschnitt 16).
- Reservierte Capability-Namensräume `security.`, `diag.`, `rf.`, `log.`
  (`RESERVED_NAMESPACES`, Tabelle §3.1): der Core vergibt dort selbst keine Capability,
  außer `rf.txpowerlist`, `rf.survey`, `rf.scan` (aus der ACL). Module melden darunter eigene
  Capability-Namen über **einen** Detektor mit **einem** Präfix
  (`register_capability_detector`, Abschnitt 17.1). Für **Event-Typen** gilt eine andere
  Regel (Abschnitt 12.3).

```python
if not api.registry.has_capability(router_id, Capability.CONFIG_UCI_READ):
    return
status = api.registry.capabilities(router_id)[Capability.CONFIG_UCI_READ]
readable = [name for name, ok in status.detail.items() if ok]
```

```python
# Provider-Seite: Probe (nur lesend, nur über conn.api)
async def async_probe(
    self, conn: RouterConnection, ctx: ProviderContext
) -> Mapping[str, CapabilityStatus]:
    now = utcnow()
    ok = await conn.api.async_probe_cgi_backup()   # neue Methode in api.py (config-manager)
    return {
        Capability.CONFIG_CGI_BACKUP: CapabilityStatus(
            capability=Capability.CONFIG_CGI_BACKUP,
            state=CapabilityState.AVAILABLE if ok else CapabilityState.UNAVAILABLE,
            reason=CapabilityReason.OK if ok else CapabilityReason.PERMISSION_DENIED,
            source="probe:config_manager",
            detected_at=now,
            required_permissions=() if ok else ("cgi-io:backup",),
        ),
        Capability.CONFIG_RESTORE: CapabilityStatus(
            capability=Capability.CONFIG_RESTORE,
            state=CapabilityState.UNAVAILABLE,
            reason="provider:phase1",
            source="probe:config_manager",
            detected_at=now,
        ),
    }
```

## 6. Guard: Bedrohungsmodell, Akteure, Entscheidung, Autorisierung

### 6.1 Bedrohungsmodell

| | |
|---|---|
| **Vertraut** | Code im HA-Prozess: Core und Module. Python kann private Sentinels (`_mint_write_authorization`, `_VERIFY_SENTINEL`) nicht erzwingen. |
| **Abgewehrt** | Nicht-Admin-Benutzer und Automationen, die schreibende oder kritische Aktionen auslösen; ein Modul, das (aus Versehen oder durch einen Fehler) `Actor(is_admin=True)` weitergibt; Wiederverwendung einer Freigabe durch einen anderen Akteur; eine Freigabe für Version A, die Version B oder ein anderes Artefakt exportiert; doppelte Nutzung einer `WriteAuthorization`; eine Autorisierung, die der Guard nicht ausgegeben hat; Löschen fremder Versionen über eine Freigabe eines anderen Routers; Pfadausbruch über `StorageRef.locator`; Geheimnisse in Freitext, Events und Fehlern. |
| **Nicht abgewehrt** | Ein Modul, das absichtlich private Helfer importiert oder Store-Dateien direkt liest; ein kompromittierter HA-Admin; Root auf dem Host; HA-Backups, die `.storage` (Installations-Schlüssel) und Klartext-Archive enthalten. |
| **Quelle der Wahrheit** | `hass.auth`. Jede API-Methode mit `actor` und der Guard lösen den Benutzer **bei jedem Aufruf neu** auf. Ein vom Aufrufer gesetztes `Actor.is_admin` wird ignoriert. |

### 6.2 Akteure und Prüfung

- `Actor` ist ein Datensatz, kein Berechtigungsnachweis. `async_actor_from_context(hass,
  context, module=None)` baut ihn aus einem HA-`Context` (Reihenfolge: `user_id` ⇒ `user`,
  sonst `module` ⇒ `module`, sonst `parent_id` ⇒ `automation`, sonst `system`).
- `async_verify_actor(hass, actor) -> VerifiedActor` prüft neu: Benutzer existiert und ist
  aktiv (sonst `AuthorizationError`, `reason=unknown_user`); `is_admin` nur, wenn der
  Benutzer aktiv, Admin und **nicht** systemgeneriert ist. Modul-, Automations- und
  Systemakteure kommen ohne Adminrechte durch.
- `async_resolve_actor(hass, context, module=None)` = beides in einem Schritt. Der Guard
  bietet dieselben Methoden (`guard.async_verify_actor`, `guard.async_resolve_actor`).
- `VerifiedActor` kann nur `async_verify_actor` bauen (Sentinel, sonst `TypeError`). Er gilt
  `ACTOR_VERIFICATION_TTL` (60 s); danach lehnt der Guard mit
  `actor_verification_expired` ab.

```python
actor = await api.guard.async_resolve_actor(call.context, module="config_manager")
```

### 6.3 Aktionen

| Aktion (`GuardedAction`) | Klasse | Wer darf | Bindung (`checksum`) |
|---|---|---|---|
| `backup` | mutating | Admin-Benutzer, Automation, Modul, System | keine |
| `protect` | mutating | nur Admin-Benutzer | `binding_checksum(version_id, protected)` |
| `drift_ack` | mutating | nur Admin-Benutzer | `binding_checksum(router_id, drift_id, state)` |
| `export` | **critical** | nur Admin-Benutzer (Antrag und Freigabe) | `binding_checksum(version_id, artifact)` |
| `delete` | **critical** | Antrag: Admin-Benutzer, Modul, System; Freigabe: Admin-Benutzer | `binding_checksum(*sorted(version_ids))` |
| `prune` | mutating | nur System (die Aufbewahrung des Core) | `binding_checksum(*sorted(version_ids))` |
| `restore` | **critical** | Antrag: Admin-Benutzer, Modul; Freigabe: Admin-Benutzer | `plan.checksum` |
| `adopt` | mutating | nur Admin-Benutzer | `binding_checksum(entry_id, orphan_router_id)` |
| `acl_deploy` | **critical** | nur Admin-Benutzer | `binding_checksum(router_id, acl_checksum)` |
| `installation_key_reset` | **critical** | nur Admin-Benutzer | `router_id = "-"` (flottenweit), `binding_checksum(last_key_id)` mit der `installation_key_id` der neuesten Version |
| `ssh_pin_confirm` | **critical** | nur Admin-Benutzer | `binding_checksum(router_id, pending_fingerprint)` |
| `ssh_pin_reset` | **critical** | nur Admin-Benutzer | `binding_checksum(router_id, fingerprint, "reset")` (`fingerprint` = gepinnter, sonst ausstehender Key) |
| `<modul>.<aktion>` | bei `register_action` | bei `register_action` | frei |

**Modulaktionen registrieren (ab B5):**
`api.guard.register_action(name, action_class, *, module, admin_user_only=False,
sensitive_read=False, rate_limit=None)`.

| Klasse | Wer darf | Freigabe | Audit bei Erteilung |
|---|---|---|---|
| `read` | jeder geprüfte Akteur | nein | `security.authorization_granted` (Sicherheitsring) |
| `read` + `sensitive_read=True` | Admin-Benutzer, Modul, System, Automation; Benutzer ohne Admin ⇒ `not_admin` | nein | wie `read` |
| `active` (ab B5) | Admin-Benutzer, Modul, System, Automation; Benutzer ohne Admin ⇒ `not_admin` | nein | `core.active_action_granted` (**allgemeiner** Ring, audit-pflichtig) |
| `mutating` | Admin-Benutzer, Modul, System, Automation | nein | `security.authorization_granted` |
| `critical` | Antrag: Admin-Benutzer, Modul, System | ja | `security.approval_*`, beim Einlösen `security.authorization_granted` |

- `active` heißt „handelt am Router oder im Netz, ändert keine Konfiguration“ (Scan, Ping,
  Survey). Ablehnungen bleiben `security.authorization_denied` (Sicherheitsring).
- `admin_user_only=True` heißt weiterhin „nur ein geprüfter Admin-**Benutzer**“ (auch
  Module und System werden abgelehnt). Für ein sensibles Lesen, das Module weiter dürfen
  sollen, ist `sensitive_read=True` gedacht (nur mit `read`, sonst `ValueError`).
- `rate_limit=RateLimit(max_calls=…, per=timedelta(…))` (nur mit `active`, sonst
  `ValueError`; `max_calls` 1..100000, `per` > 0 und ≤ 1 Tag): höchstens `max_calls`
  Erteilungen je `(aktion, router_id)` im gleitenden Fenster `per`; nur Erteilungen zählen.
  Darüber: `DENIED`, `reason` `rate_limited` (`REASON_RATE_LIMITED`),
  `AuthorizationDecision.retry_after` (Sekunden), `error_for_decision` ⇒
  `RateLimitedError` (§14). Auditiert als `core.action_rate_limited` (allgemeiner Ring,
  Warnung, `dedup_key` = Aktion, Cooldown = `per`: ein Eintrag je Router, Aktion und
  Fenster, Wiederholungen in `repeat_count`), Zähler `rate_limited`. Höchstens
  `MAX_RATE_WINDOWS` = 1024 offene Fenster; darüber fällt das älteste weg (Zähler
  `rate_windows_dropped`, Debug-Log).
- Gleiche Registrierung erneut ist ein No-op; eine abweichende (auch nur anderes Limit)
  ⇒ `ValueError`.

Tabellen im Code: `ACTION_CLASSES`, `ADMIN_USER_ONLY_ACTIONS`, `SYSTEM_ONLY_ACTIONS`. Die
Regel selbst ist `policy_denial_reason(action, actor)`:

1. kein `VerifiedActor` ⇒ `unverified_actor`; abgelaufen ⇒ `actor_verification_expired`
2. unbekannte Aktion ⇒ `unknown_action`
3. `SYSTEM_ONLY_ACTIONS` und kein System ⇒ `system_only`
4. `ADMIN_USER_ONLY_ACTIONS` und kein geprüfter Admin-Benutzer ⇒ `not_admin`
5. `read` ⇒ erlaubt (außer `sensitive_reads`, ab B5: weiter mit 6)
6. **Benutzer ohne Admin ⇒ `not_admin` für jede mutating-, active- oder
   critical-Aktion**, auch `backup`, und für ein `sensitive_read`
7. critical und Automation ⇒ `automation_not_allowed`

- **read:** die Lese-Operationen des Core (Listen, Capture, Vergleich, Validierung,
  Drift, Dry Run) rufen `authorize` **nicht** auf; sie prüfen den Akteur selbst (siehe
  nächster Punkt). Auditiert werden davon nur Ablehnungen und Dry Run/Kompatibilitätsprüfung
  (`restore_checked`); erfolgreiches Lesen nicht (zu häufig). Ruft ein Modul `authorize`
  für eine `read`-Aktion auf (eigene Modulaktion), dann gilt dasselbe wie bei `mutating`:
  der Guard prägt eine `WriteAuthorization` (im Ledger, `consume` möglich, aber nicht
  nötig) und auditiert die Erteilung als `security.authorization_granted`
  (Sicherheitsring, audit-pflichtig). Für häufige Modul-Lesezugriffe deshalb `authorize`
  nur bei sensiblen Lesezugriffen (`sensitive_read=True`) verwenden.
- **read von Konfigurationsinhalt** (`async_capture`, `async_compare`; Geheimnisse
  enthalten): ein Benutzer muss geprüfter Admin sein, sonst `AuthorizationError`
  `not_admin`, auditiert als `security.authorization_denied` (Sicherheitsring, `action`
  `config_capture` bzw. `config_compare`), vor jedem Provider-Aufruf und vor dem Nachschlagen
  von Versionen. Modul-, System- und Automationsakteure lesen ohne Adminrechte (wie
  `backup`, das denselben Inhalt liest und ablegt). Die Prüfung sitzt in den Methoden selbst,
  nicht in einem Panel. Erfolgreiche Lesezugriffe werden weiter nicht auditiert.
- **mutating:** sofortige Entscheidung `approved` oder `denied`.
- **critical:** erster Aufruf ⇒ `pending` + `ApprovalRequest`; ein Admin-Benutzer gibt frei
  (`approve`) oder lehnt ab (`reject`); erst ein zweiter `authorize(..., approval_id=…)`
  **desselben Antragstellers** liefert `approved` + `WriteAuthorization`. Antrag gilt
  `APPROVAL_TTL` (15 min), eine Freigabe erlaubt **genau eine** Ausführung (beim Export:
  einen Download).
- Selbstfreigabe ist erlaubt: Ein Admin darf seinen eigenen Antrag freigeben
  (Ein-Admin-Haushalt). Die zweite Stufe ist eine bewusste Bestätigung, kein
  Vier-Augen-Prinzip.

**Ablauf `acl_deploy` (1.44.0, `core_security.SecurityActions`):**

```python
req = await api.async_request_acl_deploy(router_id, ["rf_survey"], actor=admin)
#   Stufen prüfen (unbekannt => ConfigApiError invalid/unknown_tier; Stufe braucht eine
#   Option, die aus ist => AclOfferRefusedError option_disabled, auditiert), dann EIN
#   file/read der aktuellen ACL, describe_offer, Antrag gebunden an
#   binding_checksum(router_id, acl_checksum)
offer = api.acl_offer(req.approval_id)       # added/removed/risks für die Anzeige
await api.async_approve(req.approval_id, actor=admin)
result = await api.async_deploy_acl_offer(req.approval_id, actor=admin)
#   Lock je Router -> Autorisierung -> acl_provisioning.async_deploy_acl_offer(guard_consume)
#   -> rpcd-Neustart abwarten, neu anmelden, ACL-Sperr-Cache leeren, beobachtete ACL
#   setzen, Capabilities neu bewerten, Proben anstoßen (jeder Schritt einzeln, Fehler in
#   post_step_errors) -> security.acl_deployed mit command und rollback_command
```

- SSH-Weg nur gepinnt: geht `file/write` per ubus nicht, läuft der eine SSH-Befehl über
  `SshPinRegistry.async_run`. Ohne bestätigten Pin ⇒ `AuthorizationError` mit
  `reason = ssh_pin_pending` (allgemein `ssh_<grund>`), Event `security.acl_deploy_failed`,
  nichts geschrieben. Ohne Runner (direkter Aufruf von
  `acl_provisioning.async_deploy_acl_offer` ohne `ssh_runner`) ⇒ `AclOfferRefusedError`
  `ssh_pin_unavailable`; der gemeinsame ungeprüfte SSH-Weg schreibt nie eine angebotene
  ACL.
- Fehler beim Schreiben ⇒ `ConfigApiError` mit `details.reason`, `written`,
  `rollback_command`; Transportfehler ⇒ `RouterUnavailableError`. Beides mit
  `security.acl_deploy_failed`.

**Ablauf SSH-Pin (1.44.0):** `SSH_PIN_FIRST_USE_POLICY = "confirm"` (eine Konstante). Der
erste Kontakt speichert den Key als *ausstehend* und bricht ab
(`OpenWrtHostKeyError("pin_pending")`, Event `security.ssh_pin_pending`); jeder weitere
Aufruf lehnt **vor** dem Verbinden ab. `api.ssh_pin_status(router_id)` zeigt den Zustand
(`none`/`pending`/`pinned`) und Fingerprints. `async_request_ssh_pin_confirm` (ohne
ausstehenden Key ⇒ `conflict`/`no_pending_pin`) → Freigabe → `async_confirm_ssh_pin`;
`async_request_ssh_pin_reset` (ohne Key ⇒ `conflict`/`no_pin`) → Freigabe →
`async_reset_ssh_pin`. Hat sich der Key zwischen Antrag und Einlösen geändert ⇒
`AuthorizationError` `pin_changed` (auditiert). Ein abweichender Key ist immer
`OpenWrtHostKeyMismatchError` und genau ein `security.ssh_pin_mismatch` je Versuch.

### 6.4 Entscheidung, Freigabe, Einlösen

```python
class ActionGuardProtocol(Protocol):
    async def async_verify_actor(self, actor: Actor) -> VerifiedActor: ...
    async def async_resolve_actor(self, context: Context | None, *,
                                  module: str | None = None) -> VerifiedActor: ...
    def authorize(
        self, action: str, router_id: str, actor: VerifiedActor, *,
        subject_id: str | None = None, checksum: str | None = None,
        approval_id: str | None = None, correlation_id: str | None = None,
    ) -> AuthorizationDecision: ...
    def consume(self, authorization: WriteAuthorization, *, action: str,
                router_id: str, checksum: str | None = None) -> None: ...
    def approve(self, approval_id: str, *, actor: VerifiedActor) -> ApprovalRequest: ...
    def reject(self, approval_id: str, *, actor: VerifiedActor,
               reason: str | None = None) -> ApprovalRequest: ...
    def get_approval(self, approval_id: str) -> ApprovalRequest: ...
    def pending_approvals(self, router_id: str | None = None) -> tuple[ApprovalRequest, ...]: ...
    def register_action(self, name: str, action_class: ActionClass, *, module: str,
                        admin_user_only: bool = False) -> None: ...
```

`authorize` ist **synchron** und schreibt immer genau einen Audit-Eintrag.

`AuthorizationDecision`:

| Feld | Typ | Bedeutung |
|---|---|---|
| `state` | `DecisionState` | `approved` / `denied` / `pending` |
| `action`, `router_id` | `str` | worum es geht |
| `audit_id` | `str` | `event_id` des Audit-Eintrags |
| `authorization` | `WriteAuthorization \| None` | nur bei `approved` (nicht in `repr`) |
| `approval_request` | `ApprovalRequest \| None` | nur bei `pending` |
| `reason` | `str \| None` | bei `denied`: ein Grund aus 6.3, dazu `approval_rejected` |
| `approved` | Eigenschaft | `state is APPROVED` |

`ApprovalRequest`: `approval_id`, `action`, `router_id`, `subject_id` (Plan, Version oder
Listenschlüssel), `checksum`, `requested_by`, `requested_at`, `expires_at`, `status`
(`pending`/`approved`/`rejected`/`expired`/`used`), `decided_by`, `decided_at`, `reason`
(Freitext, in `to_dict()` geschrubbt), `correlation_id`.

- **Freigeben/Ablehnen** (`approver_denial_reason`): nur ein frischer `VerifiedActor`, der
  Admin-Benutzer ist; Antrag muss `pending` und nicht abgelaufen sein. Gründe:
  `unverified_actor`, `actor_verification_expired`, `not_admin`, `not_pending`, `expired`.
- **Einlösen** (`check_redeem`): nur der Antragsteller (`Actor.same_principal`: gleicher
  `user_id`, gleiches Modul, oder beide System), neu geprüft; ein Benutzer muss noch Admin
  sein. Aktion, Router und Bindungsprüfsumme müssen passen. Fehler:
  `AuthorizationError` (Akteur nicht geprüft), `ApprovalRequiredError` (noch `pending`),
  sonst `ApprovalInvalidError` mit `details["reason"]` ∈ `rejected`, `expired`, `used`,
  `action_mismatch`, `router_mismatch`, `checksum_mismatch`, `not_requester`, `not_admin`.
- **Offene Anträge überleben keinen Neustart.** Sie liegen nur im Speicher; nach einem
  Neustart ist ein Antrag unbekannt (`ApprovalInvalidError`) und muss neu gestellt werden.
  Der Audit-Eintrag des Antrags bleibt.

### 6.5 WriteAuthorization, Ledger und `consume`

- Nur der Guard prägt sie (`_mint_write_authorization`, privater Sentinel) und trägt ihre ID
  ins **Ledger** ein. Direkter Aufruf von `WriteAuthorization(...)` ⇒ `TypeError`.
- Gebunden an `action`, `router_id` und (optional) `checksum`; gültig
  `WRITE_AUTHORIZATION_TTL` (5 min). `authorization.actor` ist der geprüfte Akteur; der
  Store setzt daraus `created_by`.
- Wer handelt (Store, Provider vor dem Router-Schreiben), ruft **unmittelbar vorher**
  `guard.consume(authorization, action=…, router_id=…, checksum=…)`. Die frühere öffentliche
  Methode `WriteAuthorization.consume` heißt jetzt `_consume` und ist Guard-intern.
- `consume` prüft: ID im Ledger (sonst `unknown_authorization`), einmalig (`already_used`),
  Ablauf (`expired`), Bindung (`action_mismatch`, `router_mismatch`, `checksum_mismatch`).
  Jeder Versuch verbraucht sie, auch ein fehlgeschlagener (fail closed). Erfolg und
  Fehlschlag werden auditiert (`security.authorization_consumed` /
  `security.authorization_denied`).
- `consume` ist **synchron** und läuft auf dem Event-Loop, nie in einem Executor-Job; so
  gibt es kein Rennen zwischen Prüfen und Verbrauchen.

### 6.6 Bindungsprüfsumme

`binding_checksum(*parts)` = sha256 über die kanonische JSON-Liste der Teile. Reihenfolge
zählt. Eine Freigabe für Version A kann so nie Version B exportieren, eine Freigabe für das
Archiv nie den UCI-Snapshot, eine Freigabe für „schützen“ nie „Schutz aufheben“.

```python
# Modul: Backup vor einer eigenen Aktion (mutating)
actor = await api.guard.async_verify_actor(Actor.for_module("firmware"))
decision = api.guard.authorize(GuardedAction.BACKUP, router_id, actor)
if not decision.approved:
    raise AuthorizationError(decision.reason or "denied", router_id=router_id)

# Erweiterungsaktion registrieren (einmal beim Setup des Moduls)
api.guard.register_action("self_healing.restart_service", ActionClass.CRITICAL,
                          module="self_healing")
```

## 7. Versionsspeicher

### 7.1 Ablage

| Eigenschaft | Wert |
|---|---|
| Wurzel | `hass.config.path(*CONFIG_BACKUP_PATH, <router_id>)` = `<config>/openwrt_router/config_backups/<router_id>/` (nicht unter `www`) |
| Rechte | Ordner `0o700`, Dateien `0o600` (`STORAGE_DIR_MODE`, `STORAGE_FILE_MODE`) |
| Schreiben | in `<name>.partial` (neu angelegt mit `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `0o600`; ohne `O_NOFOLLOW` auf der Plattform nur `O_EXCL`), `fsync`, umbenennen; **Indexeintrag zuletzt**. Liegt am `.partial`-Pfad ein Link, eine Junction oder ein Ordner: `StorageError` `reason=partial_not_regular` (`found`), nie gefolgt, Zähler `partial_refused`; eine gleichnamige reguläre Datei (abgebrochener Schreibvorgang desselben Locators) wird entfernt und das Anlegen einmal wiederholt |
| I/O | jede Datei-Operation im Executor |
| Format | `StorageRef.storage_format = "plain-v1"` (Klartext, keine eigene Verschlüsselung), `encrypted = False` |
| Grenzen | 50 MiB je Router, 250 MiB gesamt (`DEFAULT_*_STORAGE_LIMIT_BYTES`) |
| Router entfernt | Ordner nach `removed/<router_id>/`; nie automatisch gelöscht |

**Locator-Regeln:** `StorageRef.locator` ist **ein** Dateiname
(`STORAGE_LOCATOR_PATTERN` = `[A-Za-z0-9._-]+`), ohne `..`, ohne führenden Punkt, ohne
Trenner. `validate_locator` prüft das beim Bau jedes `StorageRef`
(`InvalidStorageRefError`, `reason=bad_locator`). `resolve_artifact_path(router_dir,
locator)` löst Symlinks auf (`realpath`, im Executor) und lehnt alles außerhalb des
Router-Ordners ab (`reason=path_escape`). Beim Lesen aus dem Index wird ein ungültiger
Locator zu `BackupMetadataError`.

### 7.2 Sweep beim Start (`async_sweep() -> SweepReport`)

1. `*.partial` löschen (`partial_deleted`).
2. Dateien ohne Indexeintrag, älter als `ORPHAN_SWEEP_MIN_AGE` (1 h), nach `orphaned/`
   verschieben (`orphaned_moved`).
3. Indexeinträge ohne Datei: `validation.status = missing` (`marked_missing`).
4. Event `configuration.storage_swept`, nur wenn ein Zähler > 0 ist.

### 7.3 Lesesicht und Store (getrennt)

Module bekommen über `api.versions` nur die **Lesesicht** ohne Bytes. Der Store selbst ist
core-intern; kein Modul bekommt ihn.

```python
class VersionReadView(Protocol):                       # api.versions
    async def async_list_versions(self, router_id: str | None = None, *,
        since: datetime | None = None, limit: int = 50) -> tuple[BackupRecord, ...]: ...
    async def async_get_version(self, version_id: str) -> BackupRecord: ...
    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]: ...
    def usage_bytes(self, router_id: str | None = None) -> int: ...

class VersionStoreProtocol(VersionReadView, Protocol):  # nur der Core
    async def async_put_version(self, router_id: str,
        artifacts: Mapping[str, ArtifactPayload], meta: VersionMeta, *,
        authorization: WriteAuthorization) -> PutVersionResult: ...
    async def async_read_artifact(self, version_id: str, kind: str) -> bytes: ...
    async def async_delete_versions(self, version_ids: Sequence[str], *,
        authorization: WriteAuthorization) -> tuple[str, ...]: ...
    async def async_set_protected(self, version_id: str, protected: bool, *,
        authorization: WriteAuthorization) -> BackupRecord: ...
    async def async_set_validation(self, version_id: str,
        validation: ValidationInfo) -> BackupRecord: ...
    async def async_put_drift_ack(self, ack: DriftAck, *,
        authorization: WriteAuthorization) -> DriftAck: ...
    async def async_sweep(self) -> SweepReport: ...
    async def async_archive_router(self, router_id: str) -> None: ...
```

Bytes bekommt ein Provider nur über den **bereichsgebundenen Leser** in
`ProviderContext.read(version_id, kind)` (Abschnitt 10): Er bedient nur die Versionen des
jeweiligen Aufrufs und prüft sha256 gegen den Index. Ein `read_artifact` für Module gibt es
nicht; der Export läuft über die kritische Aktion `export`.

| Operation | Autorisierung | Verhalten | Fehler |
|---|---|---|---|
| `async_put_version` | `backup` | `consume`, prüft sha256 jedes `ArtifactPayload`, Grenzen, schreibt atomar; `created_by = authorization.actor`; **Dedup** nach 7.4. Eine `failed`-Version ohne Artefakte bekommt trotzdem einen Indexeintrag (Verlauf). | `AuthorizationError`, `BackupIntegrityError`, `ArtifactTooLargeError`, `StorageFullError`, `StorageError` |
| `async_list_versions` | – | neueste zuerst, `limit` ≤ `MAX_LIST_LIMIT` (500) | – |
| `async_get_version` | – | | `BackupNotFoundError` |
| `async_read_artifact` | – (core-intern) | prüft Locator, `storage_format` und sha256 | `InvalidStorageRefError`, `UnsupportedStorageFormatError`, `BackupIntegrityError`, `StorageError` |
| `async_delete_versions` | `delete` oder `prune` | `delete`: vorher `validate_deletion` (fremde IDs ⇒ `AuthorizationError` `router_mismatch`; geschützte ⇒ `VersionProtectedError`, nichts gelöscht). `prune`: nur IDs aus `plan_retention`. Rückgabe: gelöschte IDs | `BackupNotFoundError`, `VersionProtectedError`, `StorageError` |
| `async_set_protected` | `protect` | | `BackupNotFoundError` |
| `async_set_validation` | – (core-intern) | speichert Prüfergebnis; `invalid`/`corrupt`/`missing` ⇒ Event `configuration.integrity_failed` | `BackupNotFoundError` |
| `async_put_drift_ack` | `drift_ack` | ersetzt eine frühere Bestätigung derselben `drift_id` | – |
| `async_archive_router` | – (Lebenszyklus) | verschiebt nach `removed/` | `StorageError` |

Sperren: Die API hält den Router-Lock für jede schreibende Operation (Abschnitt 8); der
Store hat zusätzlich eine eigene interne Sperre für seinen Index (mehrere Router schreiben
in denselben Store).

**Provider-Ausgabe ist ungeprüfte Eingabe.** Der Core prüft beim Ablegen (erzwungen in
`config_api.py` und `version_store.py`, Tests `tests/test_config_untrusted_input.py`):

1. `async_collect` muss ein `CollectedVersion` mit `VersionMeta` liefern; sonst
   `ProviderError(error_class=invalid)` mit `reason` `not_a_collected_version` bzw.
   `meta_not_version_meta`.
2. Artefaktarten sind eine **geschlossene Menge** (`ArtifactKind`); jede andere Art ⇒
   `invalid`/`unknown_artifact_kind`; ein Wert, der kein `ArtifactPayload` ist ⇒
   `artifact_not_a_payload`. Der Store prüft dasselbe noch einmal (`BackupMetadataError`,
   Zähler `refused_input`).
3. Das Größenlimit (`router_limit`) gilt **vor** dem Hashen: ein zu großes Artefakt ⇒
   `ArtifactTooLargeError`, ohne dass es gehasht oder geschrieben wird.
4. sha256 rechnet **der Core**. Ein mitgelieferter `ArtifactPayload.sha256` muss passen,
   sonst `BackupIntegrityError`; in `ArtifactRef.sha256` steht immer der Core-Wert.
5. Locator erzeugt **nur der Core** (`<backup_id>.<kind>`). Ein Provider kann keinen Pfad
   vorgeben; ein ungültiger Locator in einer `ArtifactRef` ⇒ `InvalidStorageRefError`.
6. Metadaten sind begrenzt (Länge von `note`, Warnungscodes nach `WARNING_CODE_PATTERN`,
   `MAX_WARNINGS`); IDs (`drift_id`, `not_compared`-Einträge, Links) sind Tokens ohne
   Pfadtrenner; `installation_key_id` ist `None` oder genau 16 Kleinbuchstaben-Hex
   (`check_key_id`).
7. Ungültige Router- oder Versions-IDs werden abgelehnt, **ohne** die ID im Fehler
   zurückzugeben (`RouterNotFoundError` `invalid_router_id`, `BackupNotFoundError`
   `invalid_version_id`; `async_read_artifact` mit unbekannter Art ⇒
   `BackupNotFoundError` `unknown_artifact_kind`).

```python
# Modul (z. B. config-manager außerhalb der Warteschlange) legt eine selbst geholte Version ab.
# Erst holen (nur lesend), DANN autorisieren: die Autorisierung gilt nur 5 min.
collected = await provider.async_collect(conn, request, ctx)
actor = await api.guard.async_verify_actor(Actor.for_module("config_manager"))
decision = api.guard.authorize(GuardedAction.BACKUP, router_id, actor)
if not decision.approved:
    raise AuthorizationError(decision.reason or "denied", router_id=router_id)
result = await api.async_put_version(
    router_id, collected.artifacts, collected.meta, authorization=decision.authorization
)
if not result.created:
    _LOGGER.debug("unchanged since %s", result.record.created_at)
```

### 7.4 Dedup beim Ablegen

`dedup_candidate(records, backup_type)` + `should_deduplicate(candidate, meta,
artifact_kinds)`:

1. Kandidat ist die neueste Version **desselben** `backup_type` mit Status `ok` oder
   `partial`, deren `validation` nicht `invalid`, `corrupt` oder `missing` ist. `failed`
   nimmt nie teil.
2. Nur die Gründe `scheduled` und `drift` (`DEDUP_REASONS`) können ein Dedup-Treffer sein.
   `manual`, alle `pre_*`, `incident`, `migration`, `import` und jede Version mit
   `links.incident_id` legen **immer** eine neue Version an (keine Notiz, kein Grund geht
   verloren).
3. Der neue Status muss dem des Kandidaten gleichen (`partial` dedupliziert nie gegen `ok`
   und umgekehrt), ein neuer `failed` nie.
4. Gleiche Artefaktarten; mit Archiv gleicher `content_hash`, ohne Archiv gleicher
   `uci_hash`. Beide Hashes kommen **immer vom Provider**; der Core rechnet sie nie nach.
5. Gleiche `installation_key_id` wie der Kandidat. Nach einem Schlüsselwechsel legt der
   Core also immer eine neue Version an; sonst bliebe die Basis auf dem alten Schlüssel und
   jede Drift-Prüfung wäre erneut ein Re-Baseline (Schleife).
   **(1.44.0, Urteil Q6)** Zusätzlich muss die sha256, die der **Core** über die neuen
   Artefakte rechnet, je Art der gespeicherten sha256 des Kandidaten gleichen
   (`should_deduplicate(..., artifact_sha256=...)`). Gleiche Provider-Hashes bei anderen
   Bytes ⇒ neue Version, Zähler `dedup_refused_sha256`. Ein Provider, dessen Archiv
   wechselnde Zeitstempel enthält, wird damit nie dedupliziert (gewollt: lieber eine
   Version zu viel als eine unterdrückte).
6. Treffer ⇒ nur `last_seen_at` wird gesetzt, `PutVersionResult(created=False)`, keine
   Dateien, kein `backup_created`-Event.

### 7.5 Aufbewahrung

Nur der Core löscht im Rahmen der Aufbewahrung (Aktion `prune`, nur System). Ein Modul
liefert die Regel, der Core führt sie aus.

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class RetentionPolicy:
    max_versions: int | None = None
    max_age: timedelta | None = None
    max_bytes_per_router: int | None = None

api.set_retention_policy(RetentionPolicy(max_versions=30, max_age=timedelta(days=90)),
                         module="config_manager")
results = await api.async_apply_retention()      # tuple[RetentionResult, ...], je Router
```

**GFS (Standard).** `RetentionPolicy` hat zwei Regelwerke, die sich nicht mischen lassen
(beides zusammen ⇒ `ValueError`): GFS mit `daily`/`weekly`/`monthly` oder Anzahl/Alter mit
`max_versions`/`max_age`. `max_bytes_per_router` gilt für beide. Solange kein Modul eine
Regel setzt, gilt `DEFAULT_RETENTION_POLICY = RetentionPolicy.gfs()` = 7 Tage / 4
ISO-Wochen / 6 Kalendermonate. Die Aufbewahrung läuft **nach jedem Ablegen** für den
betroffenen Router (als System, Aktion `prune`).

```python
api.set_retention_policy(RetentionPolicy.gfs(daily=14, weekly=8, monthly=12),
                         module="config_manager")
```

Folge des Standards: Mehrere geplante Versionen desselben Tages werden sofort auf die
neueste verwendbare ausgedünnt (sichtbar als `configuration.retention_applied`).
**(1.44.0, Urteil Q3)** GFS dünnt `manual` und alle `pre_*` nie aus
(`KeepReason.MANUAL`); sie bleiben, bis das Größenlimit oder ein Löschen sie entfernt.
Das Größenlimit entfernt sie erst nach allen anderen und nennt sie einzeln in
`RetentionResult.limit_deleted_manual` (alle vom Limit entfernten stehen in
`limit_deleted`).

`plan_retention(router_id, records, policy, *, now=None, max_bytes=None)`:

- **Immer behalten**: geschützte Versionen (`KeepReason.PROTECTED`) und die neueste
  verwendbare Version (`usable` = Status `ok` und Validierung `unverified`/`valid`,
  `KeepReason.NEWEST_VALID`). Sie zählen zuerst gegen die Grenzen.
- GFS: je Tag/Woche/Monat im Fenster die neueste verwendbare Version
  (`KeepReason.DAILY`/`WEEKLY`/`MONTHLY`), gezählt in der Zeitzone von `now`. Nicht
  verwendbare Versionen vertreten nie einen Zeitraum; sie bleiben nur innerhalb des
  Tagesfensters (`KeepReason.RECENT_FAILED`).
- Anzahl/Alter, neueste zuerst: älter als `max_age` oder jenseits von `max_versions` ⇒
  löschen; sonst `KeepReason.WITHIN_POLICY`. Verwendbare zählen vor nicht verwendbaren,
  eine `failed`-Version verdrängt also nie eine verwendbare.
- Über dem Größenlimit (das kleinere aus `max_bytes_per_router` und dem Router-Limit des
  Store): zuerst nicht verwendbare, dann die ältesten entfernen, nie geschützte oder die
  neueste verwendbare. Reicht das nicht, `RetentionResult.over_limit = True` und Event
  `configuration.storage_limit_exceeded`; erzwungen wird nichts.
- `RetentionResult(router_id, evaluated_at, deleted, kept)`: **jede** bewertete Version
  steht in `deleted` oder mit Grund in `kept`; nichts geschieht still. Event
  `configuration.retention_applied` (Audit-Pflicht).
- `StorageFullError` beim Ablegen: der Core wendet zuerst die Aufbewahrung **dieses** Routers
  an und versucht es genau einmal neu; scheitert es wieder, `configuration.backup_failed`
  mit `error_class=storage_full`. Es wird nie über Router hinweg gelöscht.

## 8. Operationen der Configuration API

`ConfigurationApiProtocol` (Objekt aus `async_get_configuration_api`). Alle Methoden mit
Router-Bezug werfen `RouterNotFoundError`, wenn die ID unbekannt ist. Jede Methode mit
`actor: Actor` prüft den Akteur neu gegen `hass.auth` (Abschnitt 6.2).

| Methode | Klasse | Rückgabe | Wichtige Fehler |
|---|---|---|---|
| `api_version`, `registry`, `guard`, `versions` (`VersionReadView`), `provider_id` | – | Eigenschaften | – |
| `register_provider(provider)` | – | Abmelde-Callback | `ProviderConflictError`, `ApiVersionError` (Provider-Version) |
| `async_get_installation_key()` | – | `bytes` (32) | `InstallationKeyLostError` |
| `installation_key_state` | – | `InstallationKeyState` | – |
| `async_request_installation_key_reset(*, actor)` | critical, Admin | `ApprovalRequest` | `AuthorizationError` |
| `async_reset_installation_key(approval_id, *, actor)` | critical | `None` | `ApprovalInvalidError` |
| `async_get_baseline(router_id, *, baseline_backup_id=None)` | read | `Baseline \| None` | `BackupNotFoundError` |
| `async_capture(router_id, *, actor, configs=None)` | read, Inhalt (Benutzer: nur Admin) | `ConfigSnapshot` | `AuthorizationError` (`not_admin`, auditiert), `CapabilityUnavailableError`, `RouterUnavailableError`, `ProviderError` |
| `async_list_backups(router_id=None, *, since=None, limit=50)` | read | `tuple[BackupRecord, ...]` | – |
| `async_get_backup(backup_id)` | read | `BackupRecord` | `BackupNotFoundError` |
| `async_validate_backup(backup_id, *, actor=None)` | read (mit `actor`: Benutzer nur Admin; ohne `actor` Altaufruf, Zähler `validate_without_actor`) | `BackupRecord` (mit neuer `validation`) | `AuthorizationError` (`not_admin`, auditiert), `BackupNotFoundError` |
| `async_compare(base, other, *, actor)` | read, Inhalt (Benutzer: nur Admin) | `ConfigDiff` | `AuthorizationError` (`not_admin`, auditiert), `BackupNotFoundError`, `CapabilityUnavailableError` |
| `async_detect_drift(router_id, *, actor, baseline_backup_id=None)` | read, Inhalt (Benutzer: nur Admin) | `DriftReport` | `AuthorizationError` (`not_admin`, auditiert), `BackupNotFoundError` (keine Basis), `RouterUnavailableError`, `InstallationKeyLostError` |
| `async_check_restore_compatibility(backup_id, target_router_id, *, actor)` | read, auditiert (Benutzer: nur Admin) | `CompatibilityCheck` | `AuthorizationError` (`not_admin`), `BackupNotFoundError` |
| `async_prepare_restore(backup_id, target_router_id, *, actor)` | read, auditiert (Dry Run; Benutzer: nur Admin) | `RestorePlan` | `AuthorizationError` (`not_admin`, auditiert), `CapabilityUnavailableError` (`config.restore_dry_run`) |
| `async_create_backup(router_id, *, reason, actor, backup_type=None, note=None, links=None)` | mutating | `PutVersionResult` | `AuthorizationError`, `OperationInProgressError`, `RouterUnavailableError`, `OperationTimeoutError`, `StorageFullError`, … |
| `async_put_version(router_id, artifacts, meta, *, authorization)` | mutating (`backup`) | `PutVersionResult` | wie `VersionStoreProtocol.async_put_version` |
| `async_set_protected(backup_id, protected, *, actor)` | mutating, Admin | `BackupRecord` | `AuthorizationError` |
| `async_acknowledge_drift(router_id, drift_id, *, state, actor, note=None)` | mutating, Admin | `DriftAck` | `AuthorizationError` |
| `async_list_drift_acks(router_id)` | read | `tuple[DriftAck, ...]` | – |
| `set_retention_policy(policy, *, module)` | – | `None` | – |
| `async_apply_retention(router_id=None)` | mutating (`prune`, als System) | `tuple[RetentionResult, ...]` | `StorageError` |
| `async_request_export(backup_id, *, actor, artifact="archive")` | critical, Admin | `ApprovalRequest` | `AuthorizationError` |
| `async_export_backup(approval_id, *, actor)` | critical, nur Antragsteller | `ExportHandle` | `ApprovalRequiredError`, `ApprovalInvalidError` |
| `async_request_deletion(backup_ids, *, actor)` | critical | `ApprovalRequest` | `BackupNotFoundError`, `VersionProtectedError`, `AuthorizationError` (`router_mismatch`) |
| `async_delete_backups(approval_id, *, actor)` | critical, nur Antragsteller | gelöschte IDs | `ApprovalInvalidError` |
| `async_request_restore(plan, *, actor)` | critical | `ApprovalRequest` | **Phase 1:** `CapabilityUnavailableError` |
| `async_approve(approval_id, *, actor)` / `async_reject(...)` | Admin | `ApprovalRequest` | `AuthorizationError`, `ApprovalInvalidError` |
| `async_execute_restore(approval_id, *, actor)` | critical | `RestoreResult` | **Phase 1:** `CapabilityUnavailableError` |
| `get_approval`, `pending_approvals` | read | | `ApprovalInvalidError` |
| `events(..., ring=None)`, `subscribe(listener)`, `register_event_prefix(prefix, *, module)`, `emit(..., entry_id=None) -> EmitResult` | – | Abschnitt 12 | `ValueError` (Core-Typ von einem Modul) |

**Nebenläufigkeit.** Lesen läuft parallel. Jede mutating/critical Operation nimmt **zuerst**
den Lock des Routers und **autorisiert danach**; so kann eine Autorisierung nicht ablaufen,
während sie auf den Lock wartet. Wer den Lock nicht innerhalb von `ROUTER_LOCK_TIMEOUT`
bekommt ⇒ `OperationInProgressError` (retryable).

**Flottenweite Warteschlange.** Backups laufen über eine Warteschlange des Core mit
`FLEET_BACKUP_CONCURRENCY` (Standard 1) Plätzen. Reihenfolge, fest:

1. Platz in der Flotten-Warteschlange
2. Lock des Routers
3. Akteur prüfen, `guard.authorize(backup, …)` (Audit; Ablehnung ⇒ `AuthorizationError`)
4. `provider.async_collect(conn, CollectRequest(...), ctx)`
5. Dedup (7.4), `guard.consume`, Ablegen (`created_by = authorization.actor`)
6. Events: `configuration.backup_created` nur bei `created=True`; bei Fehler
   `configuration.backup_failed` (`dedup_key = error_class`, 24 h Cooldown); erster Erfolg
   danach `configuration.backup_recovered`
7. Lock und Platz freigeben

Damit wartet keine ausgegebene Autorisierung in der Warteschlange (6 Router × bis 180 s
würden die 5 min sonst überschreiten).

```python
actor = await async_actor_from_context(hass, call.context, module="config_manager")
result = await api.async_create_backup(router_id, reason=BackupReason.MANUAL, actor=actor,
                                       note="before VLAN change")
```

Export (kritisch, liest nur, gebunden an Version **und** Artefakt):

```python
req = await api.async_request_export(backup_id, actor=admin, artifact=ArtifactKind.ARCHIVE)
await api.async_approve(req.approval_id, actor=admin)              # Admin bestätigt
handle = await api.async_export_backup(req.approval_id, actor=admin)   # nur der Antragsteller
data = await handle.reader()       # ein Download; zweiter Aufruf von async_export_backup
                                   # mit derselben approval_id ⇒ ApprovalInvalidError
```

Löschen (alle IDs eines Routers; geschützte vorher freigeben):

```python
req = await api.async_request_deletion([bkp_a, bkp_b], actor=admin)
await api.async_approve(req.approval_id, actor=other_admin)
deleted = await api.async_delete_backups(req.approval_id, actor=admin)   # Antragsteller
```

## 9. Datenmodell

Alle Typen sind `frozen`, `kw_only`, `slots`. Mapping-Felder werden beim Bau tief
schreibgeschützt (`MappingProxyType`, Listen als Tupel); Schreiben ⇒ `TypeError`. Enum-Felder
nehmen auch den `str`-Wert und werden umgewandelt; ein ungültiger Wert ⇒ `ValueError`.
`from_dict` prüft Typen streng (z. B. `protected: "yes"`, `note: 5`, Zeitstempel ohne
Zeitzone ⇒ Fehler, nie stillschweigend korrigiert).

### 9.1 `BackupRecord` (= `VersionRecord`, Metadatenformat 1)

| Feld | Typ | Pflicht | Bedeutung |
|---|---|---|---|
| `metadata_version` | `int` | ja (=1) | Format dieser Metadaten |
| `backup_id` | `str` | ja | `bkp_<32 hex>`; Alias-Eigenschaft `version_id` |
| `router_id` | `str` | ja | `rtr_<32 hex>` |
| `created_at` | `datetime` (UTC) | ja | Erstellzeit |
| `last_seen_at` | `datetime \| None` | | letzter Dedup-Treffer |
| `backup_type` | `BackupType` | ja | `full_archive` / `uci_snapshot` / `partial` |
| `reason` | `BackupReason` | ja | `manual`, `scheduled`, `pre_firmware_update`, `release_change`, `pre_restore`, `pre_change`, `drift`, `incident`, `migration`, `import` |
| `status` | `VersionStatus` | | `ok` / `partial` / `failed` |
| `error_class` | `ErrorClass \| None` | | warum `partial`/`failed` |
| `fetch_method` | `str \| None` | | z. B. `cgi`, `ssh` (Provider) |
| `content_hash` | `str \| None` (64 hex) | | Dedup-Fingerprint der Archivinhalte (Provider) |
| `uci_hash` | `str \| None` (64 hex) | | Inhalts-Hash des UCI-Snapshots (Provider) |
| `openwrt_version`, `hardware_model`, `board_name` | `str \| None` | | Herkunft |
| `compatibility` | `CompatibilityInfo \| None` | | Format, Version, Target, Board, Modell, Architektur, Paketmanager |
| `artifacts` | `Mapping[str, ArtifactRef]` | | Schlüssel `archive` / `uci` / `inventory` (nur `ArtifactKind`) |
| `validation` | `ValidationInfo` | | `unverified`/`valid`/`invalid`/`corrupt`/`missing`, Zeit, Text |
| `links` | `BackupLinks` | | `incident_id`, `change_id`, `correlation_id`, `parent_backup_id` |
| `created_by` | `Actor` | ja | aus der Autorisierung, nie vom Aufrufer |
| `contains_secrets` | `bool` | | Standard `True` |
| `protected` | `bool` | | vor Aufbewahrung und `delete` geschützt |
| `note` | `str \| None` | | ≤ `NOTE_MAX_LENGTH` (500) |
| `warnings` | `tuple[str, ...]` | | Maschinencodes aus `VersionMeta.warnings` |
| `installation_key_id` | `str \| None` | | Schlüssel, mit dem die Geheimnis-Digests gebildet wurden |
| `sha256` | Eigenschaft | | sha256 des Archivs oder `None` |
| `size_bytes` | Eigenschaft | | Summe aller Artefakte |
| `usable` | Eigenschaft | | Status `ok` und Validierung `unverified`/`valid` |

`to_dict()` enthält zusätzlich `sha256` und `size_bytes`; `from_dict()` ignoriert sie und
wirft bei jedem Fehler `BackupMetadataError` (ältere Formate laufen durch
`migrate_backup_metadata`, neuere werden abgelehnt).

### 9.2 Artefakte und Ablegen

| Typ | Felder |
|---|---|
| `StorageRef` | `locator` (ein Dateiname, Abschnitt 7.1; für Module opak), `kind="file"`, `storage_format="plain-v1"`, `encrypted=False` |
| `ArtifactRef` | `storage`, `sha256` (64 hex), `size_bytes` (≥ 0), `content_type` |
| `ArtifactPayload` | `data: bytes` (nicht in `repr`), `sha256`, `content_type`; Eigenschaft `size_bytes` |
| `VersionMeta` | `backup_type`, `reason`, `status`, `error_class`, `fetch_method`, `content_hash`, `uci_hash`, `openwrt_version`, `hardware_model`, `board_name`, `compatibility`, `contains_secrets`, `note`, `links`, `correlation_id`, `warnings`, `installation_key_id`. **Kein `created_by`.** |
| `PutVersionResult` | `record`, `created` |
| `SweepReport` | `checked_at`, `partial_deleted`, `orphaned_moved`, `marked_missing` |
| `CollectRequest` | `router_id`, `backup_type`, `reason`, `actor`, `correlation_id`, `note`, `links`, `fetch_method` |
| `CollectedVersion` | `artifacts: Mapping[str, ArtifactPayload]`, `meta: VersionMeta` (Warnungen in `meta.warnings`) |
| `RetentionPolicy`, `RetentionResult` | Abschnitt 7.5 |

Regeln zu `VersionMeta`:

- `error_class` ist genau bei `partial` und `failed` Pflicht, bei `ok` verboten
  (`ValueError`).
- Teilerfolg „Archiv fehlgeschlagen, UCI ok“: `backup_type=partial`, `status=partial`,
  `error_class` = Fehler des Archivs.
- `warnings`: Maschinencodes nach `WARNING_CODE_PATTERN` (`code` oder `code:detail`, z. B.
  `uci_missing:sqm`, `config_missing_in_archive:firewall`), höchstens `MAX_WARNINGS` (50).
  Kein Freitext, keine Werte.

### 9.3 Analyse

| Typ | Felder |
|---|---|
| `ConfigSnapshot` | `router_id`, `captured_at`, `configs` (opak, Abschnitt 10.3), `openwrt_version`, `board_name`, `format` (Standard `uci_normalized`), `format_version` (1), `contains_secrets`, `uci_hash` (Provider), `installation_key_id`; Eigenschaft `checksum` = Bindungsprüfsumme des Core, **nicht** vergleichbar mit `uci_hash` |
| `ConfigRef` | genau eins von `backup_id` / `router_id` (live); `ConfigRef.backup(id)`, `ConfigRef.live(router_id)` |
| `ConfigChange` | `kind` (`added`/`removed`/`modified`/`reordered`/`not_comparable`), `config`, `section`, `option`, `section_type`, `before`, `after`, `area`, `risk`; Eigenschaft `secret` (über `is_secret_option`, kontextabhängig) |
| `ConfigDiff` | `base`, `other`, `compared_at`, `changes`, `truncated`; Eigenschaften `has_changes`, `comparable_changes` (ohne `not_comparable`); `to_dict()` mit `counts` |
| `DriftReport` | `router_id`, `baseline_backup_id`, `checked_at`, `drifted`, `diff`, `drift_id`, `ack_state`, `ignored_paths`, `baseline_rule`, `critical_count`, `unknown_count`, `secrets_comparable`, `rebaseline` (Abschnitt 11) |
| `Baseline` | `router_id`, `version_id`, `rule` (`BaselineRule`), `drift_id`, `decided_at` |
| `CompatibilityCheck` | `compatible`, `issues` (`code`, `message`, `blocking`; `message` in `to_dict()` geschrubbt) |
| `RestorePlan` | `plan_id`, `backup_id`, Quell-/Zielrouter, `provider_id`, `created_at`, `compatibility`, `steps`, `diff`, `live_checksum`, `requires_reboot`, `warnings`, `instructions`; Eigenschaft `checksum` (unmaskiert) |
| `RestoreResult` | `approval_id`, `plan_id`, `router_id`, `status`, Zeiten, `pre_restore_backup_id`, `applied_steps`, `failed_step`, `message` (geschrubbt), `reboot_required`, `rolled_back`, `correlation_id` |
| `ExportHandle` | `backup_id`, `artifact` (`ArtifactKind`), `filename`, `content_type`, `size_bytes`, `sha256`, `contains_secrets`, `reader()`, `expires_at` |

### 9.4 `Actor` und `VerifiedActor`

`Actor`: `kind` (`user`/`automation`/`system`/`module`), `user_id`, `context_id`,
`parent_context_id`, `module`, `is_admin` (nur `user` kann Admin sein; sonst auf `False`
gesetzt; vom Core nie aus Aufrufer-Angaben übernommen). `Actor.system()`,
`Actor.for_module(name)`, `actor.same_principal(other)`,
`await async_actor_from_context(hass, context, module=None)`.

`VerifiedActor` (Abschnitt 6.2): `actor`, `is_admin`, `verified_at`, `verification_id`,
`is_fresh(now)`, `to_dict()`.

## 10. Provider-Schnittstelle (`ConfigBackupProvider`)

### 10.1 Signaturen

```python
@runtime_checkable
class ConfigBackupProvider(Protocol):
    provider_id: str                      # Eigenschaft, z. B. "config_manager"
    provider_api_version: int             # in SUPPORTED_PROVIDER_API_VERSIONS
    def supported(self, router: RouterRecord) -> bool: ...
    async def async_probe(self, conn: RouterConnection,
                          ctx: ProviderContext) -> Mapping[str, CapabilityStatus]: ...
    async def async_capture(self, conn: RouterConnection, request: CaptureRequest,
                            ctx: ProviderContext) -> ConfigSnapshot: ...
    async def async_collect(self, conn: RouterConnection, request: CollectRequest,
                            ctx: ProviderContext) -> CollectedVersion: ...
    async def async_validate(self, record: BackupRecord,
                             ctx: ProviderContext) -> ValidationInfo: ...
    async def async_compare(self, base: ConfigSource, other: ConfigSource,
                            ctx: ProviderContext, *, base_router: RouterRecord,
                            other_router: RouterRecord) -> ConfigDiff: ...
    async def async_detect_drift(self, conn: RouterConnection, baseline: BackupRecord,
                                 acks: Sequence[DriftAck], ctx: ProviderContext, *,
                                 router: RouterRecord) -> DriftReport: ...
    async def async_prepare_restore(self, conn: RouterConnection, record: BackupRecord,
                                    target: RouterRecord,
                                    ctx: ProviderContext) -> RestorePlan: ...
    async def async_execute_restore(self, conn: RouterConnection, plan: RestorePlan,
                                    authorization: WriteAuthorization,
                                    ctx: ProviderContext) -> RestoreResult: ...
```

### 10.2 `ProviderContext`

Jeder Aufruf bekommt einen eigenen Kontext:

| Feld | Typ | Bedeutung |
|---|---|---|
| `registry` | `RouterRegistryProtocol` | Lesezugriff auf die Registry |
| `read` | `ArtifactReader` = `Callable[[str, str], Awaitable[bytes]]` | `await ctx.read(version_id, kind)`; nur die Versionen dieses Aufrufs, sha256 geprüft (`BackupIntegrityError`) |
| `installation_key` | `Callable[[], Awaitable[bytes]]` | intern; Module rufen `await ctx.async_get_installation_key()` |
| `installation_key_state` | `InstallationKeyState` | `ok` / `lost` / `uninitialised` |
| `correlation_id` | `str \| None` | der Operation |

Der Schlüssel wird je Verwendung geholt und nie gehalten;
`async_get_installation_key()` wirft `InstallationKeyLostError`, solange er verloren ist.

Weitere Regeln:

- `ConfigSource = BackupRecord | ConfigSnapshot`.
- `async_compare` bekommt den `RouterRecord` beider Seiten (z. B. Management-Host für die
  Einstufung „Management-IP kritisch“).
- `RouterConnection(router_id, entry_id, api, coordinator, transport)`: `api` ist die
  **bestehende** `OpenWrtAPI` des Eintrags. Neue Router-Aufrufe kommen als Methoden in
  `api.py`, nie als eigenes HTTP/SSH im Provider.
- Der Provider speichert, exportiert und löscht **nichts**; er gibt Bytes in
  `CollectedVersion` zurück.
- Der Provider **feuert keine Events**. Er gibt Ergebnisse zurück; der Core erzeugt daraus
  die Events (Abschnitt 12.3).
- Vor jedem Schreiben auf den Router ruft der Provider `api.guard.consume(authorization,
  ...)`.
- Fehler: Provider wirft `ConfigApiError`-Unterklassen (`RouterUnavailableError`,
  `RouterPermissionError`, `OperationTimeoutError`, `BackupIncompleteError`,
  `ArtifactTooLargeError`, …) oder `ProviderError(cause=…, error_class=…)`. Für
  „Daten ungültig“ ist `ProviderError(error_class=ErrorClass.INVALID)` der vorgesehene Weg.
  Unerwartete Ausnahmen wickelt der Core in `ProviderError`.
- Genau ein Provider; ein zweiter `register_provider` ⇒ `ProviderConflictError`.

```python
unregister = api.register_provider(ConfigManagerProvider(hass))
entry.async_on_unload(unregister)
```

### 10.3 Snapshot-Format `uci_normalized` v1

`ConfigSnapshot.configs` ist für den Core **opak**: vom Provider definiert, JSON-fähig,
beschrieben durch `format` + `format_version`. Für v1 gilt die Form von `config-manager`:

```text
configs[<config>] = {
    "sections": {
        <section_key>: {
            "type": <section_type>,
            "options": { <option>: <wert> | [<wert>, ...] | {"secret": "<hmac16>"} },
        },
    },
    "order": [<section_key>, ...],          # Reihenfolge der Sections
}
```

- `order` hält die Reihenfolge, weil eine Option `type` sonst mit dem Section-Typ kollidiert.
- Geheime Werte stehen nur als Marker `{"secret": "<16 hex>"}`
  (`secret_digest_factory(installation_key)`, `SECRET_MARKER_KEY`, `SECRET_DIGEST_LENGTH`).
  `installation_key_id` des Snapshots nennt den Schlüssel.
- Ein anderes Format braucht einen neuen `format`-Namen oder eine höhere `format_version`.

**Hash-Regel.** `uci_hash` und `content_hash` kommen **immer vom Provider** (seine kanonische
Form). Der Core rechnet sie nie nach und vergleicht sie nur auf Gleichheit.
`ConfigSnapshot.checksum` (`canonical_checksum`, `ensure_ascii=True`) ist nur eine
Bindungsprüfsumme des Core (z. B. `RestorePlan.live_checksum`) und mit `uci_hash` nicht
vergleichbar.

## 11. Drift, Basis und Installations-Schlüssel

### 11.1 Bestätigung (`DriftAck`)

| Feld | Typ | Bedeutung |
|---|---|---|
| `router_id` | `str` | |
| `drift_id` | `str` | stabile Kennung des Drifts (Provider) |
| `state` | `DriftAckState` | `acknowledged` (gesehen, Basis bleibt) / `known` (neue Basis) |
| `actor` | `Actor` | Admin-Benutzer |
| `ts` | `datetime` (UTC) | |
| `note` | `str \| None` | ≤ 500 Zeichen |
| `version_id` | `str \| None` | bei `known` **Pflicht**: die Version des bestätigten Live-Stands; bei `acknowledged` verboten |

Bei `known` holt der Core vor dem Speichern der Bestätigung eine Version des Live-Stands mit
`reason=drift` (oder bekommt per Dedup die vorhandene) und trägt ihre ID in `version_id` ein.
Der Provider bekommt die Bestätigungen in `async_detect_drift(..., acks, ctx, router=...)`
und setzt `DriftReport.ack_state`.

```python
ack = await api.async_acknowledge_drift(router_id, report.drift_id,
                                        state=DriftAckState.KNOWN, actor=admin)
assert ack.version_id is not None
```

### 11.2 Basis

`select_baseline(router_id, records, acks, *, explicit_backup_id=None)` und
`api.async_get_baseline(router_id, *, baseline_backup_id=None) -> Baseline | None`:

1. `explicit` – der Aufrufer nennt `baseline_backup_id`; sie muss eine verwendbare Version
   dieses Routers sein (sonst Fehler).
2. `known_ack` – die neueste `known`-Bestätigung, deren Version noch verwendbar ist
   (sonst wird sie übersprungen).
3. `newest_valid` – die neueste verwendbare Version.

`Baseline.rule` und `DriftReport.baseline_rule` sagen, welche Regel gegriffen hat. Kein
Ergebnis ⇒ `None` (die API wirft dann `BackupNotFoundError` in `async_detect_drift`).

### 11.3 Installations-Schlüssel

32 zufällige Bytes (`INSTALLATION_KEY_BYTES`) im Store `openwrt_router.installation_key`. Nur
für HMAC-Digests von Geheimnissen in Snapshots. **Nie** in Audit, Bus-Event, Diagnose, Log.
Der Store wird mit `private=True` (Dateirechte 0600) und `atomic_writes=True` angelegt und
nur einmal geschrieben (beim Erzeugen bzw. nach einem Reset).
`installation_key_id(key)` (16 hex) ist öffentlich und wird an Versionen und Snapshots
gestempelt.

Zustand (`installation_key_state(key_readable=, has_versions=, has_acks=)`):

| Zustand | Wann | Verhalten |
|---|---|---|
| `ok` | Schlüssel lesbar | normal |
| `uninitialised` | erster Start, keine Versionen, keine Bestätigungen | **nur hier** erzeugt der Core einen Schlüssel |
| `lost` | Store fehlt oder ist unlesbar, aber Versionen oder Bestätigungen existieren | kein stilles Neuerzeugen; `InstallationKeyLostError`; einmal Event `core.installation_key_lost` (Sicherheitsring); Repair-Issue `ISSUE_INSTALLATION_KEY_LOST`; Digests gelten als `not_comparable` |

Neuer Schlüssel nach Verlust nur über die kritische Aktion `installation_key_reset`
(`async_request_installation_key_reset` ⇒ Admin-Freigabe ⇒
`async_reset_installation_key`, nur der Antragsteller). Event `core.installation_key_reset`.
Danach meldet der Provider bei der nächsten Drift-Prüfung je Router `DriftReport.rebaseline
= True` („Schlüssel gewechselt“). Das darf **zusammen** mit echten Änderungen kommen
(`drifted = True` oder vergleichbare Änderungen im Diff); dann ist der Bericht ein Drift
und der Core sendet die Drift-Events wie sonst (dazu ein Log-Eintrag und Zähler
`rebaseline_refused`). Der Core legt den Live-Stand nur bei einer **Entwarnung** als
neue Basis ab (`DriftReport.rebaseline_allowed`: `rebaseline`, kein Drift, keine
vergleichbare Änderung, Vergleich `complete`) **und** nur, wenn er selbst einen
Schlüsselwechsel kennt (offener Re-Baseline-Vermerk nach `installation_key_reset`). Ein
`rebaseline` ohne solchen Vermerk wird verworfen (Zähler `rebaseline_unconfirmed`). Ein
`drifted = False` mit vergleichbaren Änderungen gilt als Drift (Zähler
`drift_inconsistent`). Eine `known`-Bestätigung löscht den offenen Vermerk, weil sie selbst
eine neue Basis setzt.

### 11.4 Vollständigkeit des Vergleichs

`DriftReport.comparison` (`DriftComparison`): `complete`, `partial` (dann nennt
`not_compared` die Configs, die nicht gelesen oder verglichen werden konnten; Pflicht) oder
`unknown` (der Vergleich als Ganzes ist nicht verlässlich). `complete` mit
`not_compared` ⇒ `ValueError`.

- **Entwarnung** (`DriftReport.all_clear`) nur bei `complete` ohne Drift. Nur dann setzt
  der Core den Drift-Dedup-Zustand zurück.
- Unvollständig ⇒ Event `configuration.drift_incomplete` (`data`: `comparison`,
  `not_compared` gekürzt, `not_compared_count`), der Dedup-Zustand eines laufenden Drifts
  bleibt, ein Re-Baseline findet nicht statt. Der Zustand steht im Ergebnis und im Audit.

Vergleichbarkeit: Wurde die Basis mit einem anderen Schlüssel gebildet
(`installation_key_id` verschieden) oder ist der Schlüssel verloren, meldet der Provider
geheime Optionen als `ChangeKind.NOT_COMPARABLE` und `secrets_comparable=False`. Solche
Änderungen sind **kein Drift** (`ConfigDiff.comparable_changes` lässt sie weg).

```python
key = await ctx.async_get_installation_key()      # im Provider
digest = secret_digest_factory(key)               # core_masking
marker = {"secret": digest(f"{config}/{section}/{option}/{value}")}
```

### 11.5 Modul-Schlüssel (ab Folgeauftrag B1)

`await api.async_get_module_key(module, purpose="") -> bytes` liefert 32 Bytes, abgeleitet
aus dem Installations-Schlüssel mit HKDF-SHA256 (RFC 5869, nur `hmac`/`hashlib`):

| Teil | Wert |
|---|---|
| Salz | `MODULE_KEY_SALT = b"openwrt_router/hkdf-salt/v1"` |
| `info` | `MODULE_KEY_INFO_PREFIX` (`b"openwrt_router/module-key/v1"`), NUL, Modulname, NUL, `purpose` |
| Länge | `MODULE_KEY_BYTES = 32` |
| Helfer | `hkdf_sha256(...)`, `derive_module_key(installation_key, module, purpose)` (rein, `core_models`) |

- Nur ein Modul, das in diesem Core-Lauf sein Event-Präfix registriert hat
  (`register_event_prefix`), bekommt einen Schlüssel, und nur seinen eigenen (der Name ist
  Teil der Ableitung). `core` ist kein Modul (`reserved_module`). Fehler sind
  `ConfigApiError` mit `reason` `invalid_module` / `reserved_module` /
  `module_not_registered` / `invalid_purpose`; gezählt in `module_keys_refused`, Ausgaben in
  `module_keys_issued`. In einem Python-Prozess ist das eine Namensprüfung, keine Isolation:
  wer Code im selben Prozess hat, kann jeden Namen angeben.
- `purpose`: höchstens 64 Zeichen `[a-z0-9_.:-]`, ohne `..`. Andere Zwecke ⇒ unabhängige
  Schlüssel.
- `lost` ⇒ `InstallationKeyLostError`, kein Ersatz. `uninitialised` ⇒ die erste Nutzung legt
  den echten Installations-Schlüssel an, genau wie beim Provider (Log, `keys_created`).
- Nach `installation_key_reset` ändern sich alle Modul-Schlüssel; Module erkennen das an
  `installation_key_id`-Stempeln ihrer eigenen Daten.
- Der Schlüssel steht nie in Diagnose, Log, Event oder `repr`.

## 12. Events und Audit

### 12.1 `CoreEvent`

| Feld | Typ | Bedeutung |
|---|---|---|
| `event_id` | `str` | `evt_…` |
| `ts` | `datetime` (UTC) | |
| `type` | `str` | `CoreEventType`-Wert oder Modultyp unter registriertem Präfix |
| `source` | `str` | z. B. `core`, `config_manager` |
| `severity` | `Severity` | `info`/`warning`/`critical` (aus `net_events`) |
| `result` | `EventResult` | `success`/`failure`/`denied`/`pending`/`info` |
| `router_id`, `entry_id` | `str \| None` | |
| `actor` | `Actor \| None` | |
| `correlation_id` | `str \| None` | |
| `dedup_key` | `str \| None` | nur der Unterscheider, z. B. `drift_id` oder `error_class` |
| `repeat_count` | `int` | Wiederholungen im Cooldown |
| `last_repeat_at` | `datetime \| None` | letzte Wiederholung |
| `data` | `Mapping` | **nur IDs und Zähler, nie Konfigurationswerte**; schreibgeschützt, bei Ausgabe zusätzlich maskiert |
| `security_relevant` | `bool` (Standard `False`) | ab B3: vom Modul gesetzt (`emit(..., security_relevant=True)`) ⇒ Sicherheitsring |
| `audit_mandatory` | `bool` (Standard `False`) | ab B3: vom Audit-Log gesetzt, wenn das Modul den Typ als audit-pflichtig registriert hat ⇒ kein Dedup |
| `client_ref` | `str \| None` | ab B8: Client als Pseudonym `cli_<16 hex>` (`CLIENT_REF_PATTERN`, aus `pseudonymise_identifier("client", …)` mit dem Modul-Schlüssel); eine rohe MAC oder ein anderes Pseudonym ⇒ `ValueError` |
| `confidence` | `float \| None` | ab B8: Sicherheit eines Befunds, endlich, 0..1 (`int` wird `float`; `bool`, Text ⇒ Fehler) |
| `classification` | `str \| None` | ab B8: Maschinencode des Befunds, `EVENT_CLASSIFICATION_PATTERN` = `[a-z0-9][a-z0-9_.:-]{0,63}` (z. B. `port_scan`, `rogue_ap.suspected`) |
| `incident_ref` | `str \| None` | ab B8: Kennung eines Incidents des Moduls (`check_token`: 1–128 Zeichen `[A-Za-z0-9._:@-]`, kein `..`) |
| `radio_id` | `str \| None` | ab B8: Funkschnittstelle, z. B. `radio1` (`check_token`) |
| `dedup_scope` | Eigenschaft | `(router_id or "-", type, dedup_key)` oder `None` |
| `audit_ring` | Eigenschaft | `general` / `security` |

`EmitResult(event, published, deduplicated)` ist die Rückgabe von `emit`.

Die B8-Felder (`EVENT_REF_FIELDS`) setzt ein Modul über `emit(..., client_ref=…,
confidence=…, classification=…, incident_ref=…, radio_id=…)` (Audit-Log und API). Alle
Standard `None`; sie stehen in `to_dict()`/`from_dict()`, im Store und im Bus-Payload, sind
**nicht** Teil des Dedup-Bereichs und werden nicht maskiert (sie nehmen nur Pseudonyme und
Codes an). Alte Einträge lesen sich unverändert; ein älterer Core ignoriert die neuen
Schlüssel (`from_dict` liest nur benannte Schlüssel), daher keine Store-Version.

Bus-Event `EVENT_CORE = "openwrt_router_core_event"` mit `CoreEvent.to_dict()`; bewusst
getrennt von `EVENT_INCIDENT`, `net_rules` bleibt unverändert. Das Event landet im Recorder
und im Logbuch (`logbook.py` zeigt `<type>: <result>` unter dem Eintragstitel, nie einen
Benutzer). Jede `user_id` im Bus-Payload (`actor.user_id` und verschachtelte) ist ein
Pseudonym `usr_<12 hex>` (`core_masking.pseudonymise_user_ids`, derselbe Helfer wie in der
Diagnose). Audit-Store, `api.events(...)` und `subscribe`-Listener behalten die echte ID.

Salz des Bus-Pseudonyms (ab Folgeauftrag B1): Ist der Installations-Schlüssel beim Laden
des Core vorhanden (`ok`), ist das Salz `derive_core_key(key, "bus_pseudonym")` (HKDF wie
§11.5, Besitzer `core`): **gleicher Benutzer, gleiches Pseudonym über Neustarts hinweg**,
bis zu einem `installation_key_reset`. Ohne Schlüssel (erster Start, `lost`, Store nicht
geladen) bleibt das Salz zufällig für diesen Lauf; das zählt `bus_salt_ephemeral` und steht
einmal im Log. Das Senden scheitert daran nie; der Core legt dafür keinen Schlüssel an.
Abwägung: Ein stabiles Pseudonym lässt Recorder- und Logbuch-Einträge eines Benutzers über
Neustarts verknüpfen (gewollt für Auswertungen), damit aber auch durch jeden, der den
Recorder liest. Den Benutzer selbst verrät es nicht: ohne den Installations-Schlüssel ist
das Pseudonym nicht umkehrbar und nicht nachrechenbar. Die Diagnose nimmt weiterhin je
Download ein frisches Salz, damit zwei Downloads nicht verknüpfbar sind.

### 12.2 Zwei Audit-Ringe

| Ring | Größe | Aufbewahrung | Inhalt |
|---|---|---|---|
| `general` | `AUDIT_MAX_EVENTS` = 1000 | `AUDIT_RETENTION_DAYS` = 90 | alles andere |
| `security` | `SECURITY_AUDIT_MAX_EVENTS` = 500 | 90 Tage | jeder `security.*`-Typ und `SECURITY_EVENT_TYPES` (Export, Löschen, Adoption, Restore-Schritte, Installations-Schlüssel verloren/neu) |

`audit_ring_for(type)` entscheidet, ab B3 zusätzlich `CoreEvent.security_relevant`: ein
Modul markiert ein eigenes Event als sicherheitsrelevant, dann liegt es im Sicherheitsring
(Standard: allgemein; Zähler `security_relevant_module_events`). Kerntypen behalten ihren
Ring. Ein Dedup-Fenster zählt nur im selben Ring: ein sicherheitsrelevantes Event erhöht
nie den `repeat_count` eines allgemeinen Eintrags desselben Bereichs. So verdrängen viele
Backup-Events nie die Sicherheitsspur. Persistiert im Store `openwrt_router.audit`. `api.events(..., ring=None)`
liest beide Ringe, `ring=AuditRing.SECURITY` nur einen.

### 12.3 Typen und wer sie sendet

`router.registered`, `router.identity_changed`, `router.duplicate_suspected`,
`router.capabilities_changed`, `router.orphaned`, `router.adopted`,
`configuration.backup_created`, `configuration.backup_failed`,
`configuration.backup_recovered`, `configuration.backup_validated`,
`configuration.backup_protection_changed`, `configuration.backup_exported`,
`configuration.backup_deleted`, `configuration.retention_applied`,
`configuration.drift_detected`, `configuration.drift_acknowledged`,
`configuration.change_critical`, `configuration.change_unknown`,
`configuration.drift_incomplete`,
`configuration.integrity_failed`, `configuration.restore_checked`,
`configuration.restore_requested`, `configuration.restore_approved`,
`configuration.restore_rejected`, `configuration.restore_completed`,
`configuration.restore_failed`, `configuration.storage_swept`,
`configuration.storage_limit_exceeded`,
`security.authorization_denied`, `security.authorization_consumed`,
`security.authorization_granted`,
`security.approval_requested`, `security.approval_approved`, `security.approval_rejected`,
`security.approval_expired`, `core.installation_key_lost`, `core.installation_key_reset`,
`core.store_recovered`;
neu in 1.44.0: `security.acl_deployed`, `security.acl_deploy_failed`,
`security.ssh_pin_pending`, `security.ssh_pin_confirmed`, `security.ssh_pin_mismatch`,
`security.ssh_pin_reset`, `configuration.router_archived`;
neu (Review PR #55): `router.forgotten`;
neu (Folgeauftrag B5): `core.active_action_granted`, `core.action_rate_limited`.

- `core.active_action_granted` (Ring `general`, audit-pflichtig): eine `active`-Aktion
  wurde erteilt. `data` wie `security.authorization_granted` (`action`,
  `authorization_id`, `approval_id` = `null`, `verification_id`, `bound`).
- `core.action_rate_limited` (Ring `general`, Warnung, nicht audit-pflichtig,
  `dedup_key` = Aktion, Cooldown = Fenster des Limits): `action`, `reason`
  (`rate_limited`), `retry_after`, `max_calls`, `per` (Sekunden).

- `router.forgotten` (Ring `security`, audit-pflichtig): ein verwaister Datensatz wurde
  gelöscht. `data`: `reason` (`aged`/`capped`), `orphaned_at`, `has_versions`,
  `last_entry_id`, `retention_days`, `max_orphans`.

- 1.44.0, alle im Ring `security` und, außer `ssh_pin_pending`, audit-pflichtig:
  - `security.acl_deployed` (Warnung): `AclDeployResult.to_dict()` (u. a. `command`,
    `rollback_command`, `backup_path`, `transport`, `changed`, `rpcd_restarted`, Stufen,
    Prüfsummen), dazu `approval_id` und `post_step_errors`.
  - `security.acl_deploy_failed`: `reason`, bei Schreibfehlern `written` und
    `rollback_command`.
  - `security.ssh_pin_pending` (Warnung, `dedup_key` = Fingerprint): `fingerprint`,
    `algorithm`, `first_seen`, `action = ssh_pin_confirm`.
  - `security.ssh_pin_confirmed` (Warnung): `fingerprint`, `algorithm`, `policy`.
  - `security.ssh_pin_mismatch` (kritisch): `reason`, `expected_fingerprint`,
    `presented_fingerprint`.
  - `security.ssh_pin_reset` (Warnung): `previous_state`, `previous_fingerprint`.
  - `configuration.router_archived` (Ring `security`, Urteil Q5): `moved`, `target`
    (`removed/<router_id>` oder `null`), `versions`; bei Fehler `moved = false`, `cause`.

- `core.store_recovered` (Ring `general`, audit-pflichtig, Schwere `warning`): ein
  Core-Store (`openwrt_router.router_registry` oder `openwrt_router.audit`) war unlesbar oder
  hatte eine unbekannte Hauptversion; die Datei wurde als `.bak` gesichert und neu
  aufgebaut. `data`: `store`, `backup_written`, bei der Registry zusätzlich
  `adoption_links_lost` und `lost_router_ids` (Router-IDs, deren Adoption neu gemacht
  werden muss; aus dem Audit-Log ermittelt, nicht automatisch wiederhergestellt).
  Sind in einem sonst lesbaren Registry-Store nur einzelne Einträge unlesbar, werden sie
  übersprungen; das Event kommt dann mit `backup_written = false` und
  `records_skipped` (Anzahl).
- **Nur der Core** sendet Typen in `CORE_EVENT_NAMESPACES` (`router.`, `configuration.`,
  `security.`, `core.`; `is_core_event_type`). `emit` eines Moduls mit einem solchen Typ ⇒
  `ValueError`.
- Aus Provider-Ergebnissen erzeugt der Core: aus einem `DriftReport`
  (`drift_event_types(report)`) `drift_detected` (bei `drifted`), `change_critical` (bei
  `critical_count > 0`), `change_unknown` (bei `unknown_count > 0`), jeweils mit
  `dedup_key = drift_id`, dazu `drift_incomplete` bei Vergleich `partial`/`unknown`;
  nichts nur bei einem erlaubten Re-Baseline (`rebaseline_allowed`, Abschnitt 11.3). Aus einer `ValidationInfo`
  (`integrity_failed(validation)`, Status `invalid`/`corrupt`/`missing`)
  `integrity_failed`.
- Module senden eigene Typen nur unter einem eigenen, registrierten Präfix, der **nicht** in
  einem Core-Namensraum liegt, z. B. `security_center.` oder `self_healing.`. (Für
  Capabilities bleibt `security.<modul>.` erlaubt, Abschnitt 5.)
- `security.approval_*` gelten für kritische Aktionen außer Restore (Export, Löschen,
  ACL-Verteilung, Schlüssel-Reset, Modulaktionen); Restore behält seine `restore_*`-Typen.

### 12.4 Dedup und Cooldown

- Bereich: `(router_id or "-", type, dedup_key)` (`CoreEvent.dedup_scope`).
- Wiederholung im festen Cooldown-Fenster: **nicht** auf dem Bus; der gespeicherte Eintrag
  bekommt `repeat_count + 1` und `last_repeat_at`; `EmitResult(published=False,
  deduplicated=True)`.
- **Audit-Pflichtige Typen** (`AUDIT_MANDATORY_EVENT_TYPES`) ignorieren `dedup_key`: jeder
  wird als eigener Eintrag geschrieben.
- Fehler: `dedup_key = error_class`, Cooldown `FAILURE_EVENT_COOLDOWN` (24 h); der erste
  Erfolg danach feuert `backup_recovered` und setzt den Bereich zurück.
- Drift: `dedup_key = drift_id`; derselbe Drift feuert einmal. Die `drift_id` wird neu
  vergeben, wenn der Drift verschwindet (`drifted=False`) oder die Basis wechselt; ein
  wiederkehrender Drift feuert also erneut.
- Erfolge (`backup_created`) nur bei neuer Version, nie bei Dedup-Treffern.

### 12.5 Audit-Pflicht und Modul-Events

Jede Guard-Entscheidung und jedes `consume`, dazu: manuelles Backup, Schutz an/aus, Drift
bestätigt/bekannt, Dry Run und Kompatibilitätsprüfung (`restore_checked`), Export (wer, wann,
welche Version, welches Artefakt), Löschen, Aufbewahrung, Adoption, Verlust und Reset des
Installations-Schlüssels, Wiederaufbau eines Core-Stores (`core.store_recovered`).

**Modul-eigene Pflichttypen (ab B3).** `api.register_audit_mandatory_types(types, *,
module) -> remover`: jeder Typ muss unter einem Präfix liegen, das dieses Modul registriert
hat (nicht das nackte Präfix); Kerntypen, reservierte Namensräume, Typen anderer Module
und `module="core"` ⇒ `ValueError` (dann wird nichts registriert). Folge: kein Dedup
(`CoreEvent.audit_mandatory = True`, `dedup_scope = None`), jedes Auftreten wird
gespeichert und gesendet; offene Dedup-Fenster dieser Typen enden sofort. Zähler
`module_mandatory_types`. Rückgängig: der Rückgabewert, das Abmelden des Präfixes
(`register_event_prefix` liefert jetzt einen Entferner; wer ihn ignoriert, verhält sich wie
in 1.44) und das Ende des Core (der nächste Core beginnt ohne Registrierungen). Die
Kerntypen in `AUDIT_MANDATORY_EVENT_TYPES` kann kein Modul ändern.

```python
remove_prefix = api.register_event_prefix("security_center.", module="security_center")
api.register_audit_mandatory_types(["security_center.login_failed"], module="security_center")
api.emit("security_center.login_failed", source="security_center", router_id=router_id,
         security_relevant=True, result=EventResult.FAILURE, data={"attempts": 3})
res = api.emit("security_center.port_scan", source="security_center", router_id=router_id,
               entry_id=entry.entry_id, severity=Severity.WARNING,
               result=EventResult.INFO, dedup_key="port_scan", data={"count": 12})
if res.deduplicated:
    _LOGGER.debug("repeat %d", res.event.repeat_count)

def _on_event(event: CoreEvent) -> None:
    if event.type == CoreEventType.DRIFT_DETECTED:
        hass.async_create_task(refresh_drift_view(event.router_id))

unsubscribe = api.subscribe(_on_event)   # Listener sind synchron und kurz
recent = api.events(router_id=router_id, types=[CoreEventType.BACKUP_FAILED], since=t0)
denials = api.events(ring=AuditRing.SECURITY, types=[CoreEventType.AUTHORIZATION_DENIED])
```

## 13. Maskierung

Es gibt **genau eine** Implementierung: `core_masking.py`. Sie ist die Obermenge aus der
früheren Core-Maskierung und `config_mask`/`config_const` des `config-manager`-Zweigs.
`config-manager` importiert sie und hält keine eigene Liste; `core_masking` importiert kein
`config_*`-Modul.

| Funktion | Zweck |
|---|---|
| `is_secret_key(name, extra_keys=())` (= `is_secret_name`) | Name klingt nach Geheimnis. Reihenfolge: exakter Name (auch normalisiert: Punkte, Anführungszeichen, `--`) ⇒ `SAFE_KEYS`/`SAFE_SUFFIXES` ⇒ Teilstrings ⇒ Muster `_key$`, `^key\d*$`, `pin$` ⇒ Wörter (auch CamelCase) |
| `is_secret_option(config, section_type, option)` | dasselbe plus Kontextregeln (`SECRET_CONTEXT_OPTIONS`, z. B. `ddns`, `rpcd`, `wireguard_*`, `openvpn`) |
| `is_secret_path(path)` | Archivpfad mit Geheimnissen (`SECRET_ARCHIVE_PATHS`, 28 Muster, z. B. `etc/shadow`, `etc/config/wireless`, Host-Keys) |
| `secret_digest_factory(key)` | HMAC-SHA256, 16 hex, Schlüssel ≥ 16 Bytes |
| `redact_text(text)`, `scrub_text(text \| None)` | Freitext: PEM-Blöcke, URL-Zugangsdaten, `Bearer`/`Basic`/`Digest`, UCI-/Zuweisungs-/Flag-Formen (`option key '…'`, `password=…`, `--password …`), crypt-Hashes, WireGuard-Schlüssel, lange Tokens. IDs (`bkp_…`, `rtr_…`) und sha256 bleiben. |
| `mask_secrets(data, *, extra_keys=())` | Schlüsselmodus für `to_dict()`: geheime Schlüssel ⇒ `**REDACTED**`, Dataclasses ⇒ maskierte dicts, `bytes` ⇒ `**REDACTED**`, Marker ⇒ `**REDACTED**`; Strings unter normalen Schlüsseln bleiben |
| `mask_for_output(data, *, extra_keys=())` | Ausgabe-Schranke (Log, Diagnose, UI): wie oben, zusätzlich jeder String durch `redact_text` (außer unter `SAFE_KEYS`/`SAFE_SUFFIXES`) und Ausnahmen geschrubbt |
| `mask_value(value)` | ein Wert; `None` und `bool` bleiben |

Namenslisten: `SECRET_OPTIONS` (UCI-Optionen, u. a. `key`, `key1`–`key4`, `psk`, `sae_password`,
`r0kh`, `r1kh`, `pincode`, `wps_pin`, `private_key`, `preshared_key`, `password`, …),
`SECRET_EXTRA_NAMES` (`authorization`, `cookie`, `set_cookie`, `proxy_authorization`,
`session`, `session_id`, `sessionid`, `sid`, `sysauth`, `ubus_rpc_session`),
`SECRET_SUBSTRINGS` (`apikey`, `credential`, `pass`, `private`, `psk`, `pwd`, `secret`,
`token`), `SECRET_WORDS` (u. a. `auth`, `privkey`, `session`, `bearer`, `community`), dazu
`DIAGNOSTICS_REDACT_KEYS`. Lesbar bleiben `SAFE_KEYS` (`key_mgmt`, `auth_server`,
`auth_port`, `keepalive`, `persistent_keepalive`, `ft_psk_generate_local`, `dedup_key`,
`contains_secrets`, `sha256`) und Namen auf `_count`, `_hash`, `_sha256`, `_id`, `_ids`.

- Alle `to_dict()` der Typen mit Konfigurationsinhalt maskieren; Freitextfelder
  (`ConfigApiError.message`, `CompatibilityIssue.message`, `RestoreStep.description`,
  `RestoreResult.message`, `ApprovalRequest.reason`, `CapabilityStatus.reason_text`) werden
  geschrubbt. Prüfsummen (`ConfigSnapshot.checksum`, `RestorePlan.checksum`) laufen über den
  **unmaskierten** Inhalt.
- Zyklen ⇒ `**REDACTED**`, Tiefe > `MAX_DEPTH` (64) ⇒ `**TRUNCATED**`. Die Eingabe wird nie
  verändert.
- Grenze: namens- und musterbasiert. Ein Geheimnis unter einem neutralen Schlüssel in einem
  Format, das kein Muster trifft, wird nicht erkannt; deshalb tragen Events nur IDs und
  Zähler.

```python
_LOGGER.debug("snapshot %s", mask_for_output(snapshot.configs))
```

**Wertabhängige Ausnahmen (ab Folgeauftrag B4).** Nur die breite Ausgaberegel ändert sich;
`is_snapshot_secret` bleibt gleich (eine UCI-Option `radio_key` bleibt im Diff maskiert).

| Regel | Namen | Wert bleibt lesbar | Wert wird maskiert |
|---|---|---|---|
| Kennungen (`is_identifier_name`) | `IDENTIFIER_KEY_NAMES`: `router_key`, `radio_key`, `client_key`, `device_key`, `entry_key`, `event_key`, `incident_key`, `finding_key`, `rule_key`, `scope_key`, `msg_key`, `message_key`, `sort_key`, `cache_key`, `lookup_key`, `recommendation_key`, `translation_key` (Wörter mit `_` verbunden, also auch `routerKey`, `RADIO-KEY`) | alles, was nicht wie Schlüsselmaterial aussieht | `looks_like_key_material`: PEM-Block, base64/base64url ab 22 Zeichen, Hex ab 32 Zeichen (Core-IDs `xxx_<32 hex>` und aus Wörtern gebaute Namen ausgenommen); gilt für Schlüssel, `{"key": "radio_key", "value": …}`-Datensätze und Freitext `radio_key=…` |
| Zähler (`is_counter_name`) | Endung `COUNTER_SUFFIXES` (`_failures`, `_failed`, `_fail`, `_errors`, `_attempts`, `_retries`, `_total`), nicht exakt geheim, kein Treffer des Präzisionsmusters, kein geheimer Teilstring | Zahlen (`int`/`float`, im Freitext eine alleinstehende Zahl) | jeder andere Wert (`auth_failures="hunter2"`) |

Bewusst nicht gelistet: echte Schlüsselnamen wie `group_key`, `wpa_key`, `public_key`.
Grenze: ein Passwort unter einem Kennungsnamen, das nicht wie Schlüsselmaterial aussieht,
bleibt lesbar; Kennungsnamen gehören Modul-Daten, nie Konfigurationswerten. In
maskiertem, verschachteltem JSON (`\"auth_failures\": 3`) gilt weiter die alte Regel
(maskiert).

**Netzwerk-Kennungen.** Die Core-Maskierung maskiert MAC, IP, Hostname, SSID und BSSID
**nicht**. Wer sie verbergen muss, nimmt seinen Modul-Schlüssel (§11.5) und

- `pseudonymise_identifier(kind, value, key) -> str` (rein, kein I/O, deterministisch):
  `kind` ∈ `mac`, `ip`, `hostname`, `ssid`, `bssid`, `client` (Client = seine MAC);
  Ergebnis `<Präfix><16 hex>` (`IDENTIFIER_PSEUDONYM_HEX_LENGTH`, insgesamt 20 Zeichen),
  Präfixe `IDENTIFIER_PSEUDONYM_PREFIXES`: `mac_`, `ipa_`, `hst_`, `ssd_`, `bss_`, `cli_`.
  HMAC-SHA256 über `b"openwrt_router/identifier/v1"`, NUL, Art, NUL, normalisierter Wert;
  die Art gehört zur Eingabe (dieselbe MAC als `mac` und als `client` ist nicht
  verknüpfbar). Normalisierung: MAC/BSSID/Client klein mit `:` (`AA-BB-…`,
  `aabb.ccdd.eeff`, bloße 12 Hex), IPv4/IPv6 kanonisch komprimiert, Hostname klein ohne
  abschließenden Punkt, SSID unverändert (Groß/Klein zählt, 1–32 Bytes). `ValueError` bei
  unbekannter Art, falschem Wert oder Schlüssel unter 16 Bytes, `TypeError` für einen
  Nicht-String.
- `pseudonymise_fields(data, key, fields)`: Kopie, in der Strings (auch in Listen) unter den
  Feldnamen von `fields` (`{"mac": "mac", "ip": "ip"}`) ersetzt sind; ungültige Werte werden
  `IDENTIFIER_INVALID` (`**INVALID_IDENTIFIER**`, nie der Rohwert), `None` bleibt.

## 14. Fehler

Alle Fehler erben von `ConfigApiError(HomeAssistantError)` und haben `code`,
`error_class`, `message`, `router_id`, `retryable`, `details` und `to_dict()` (Details
maskiert, Nachricht geschrubbt). `code` und `error_class` ändern sich innerhalb v1 nie.

| Klasse | `code` | `error_class` | Wann | Retryable |
|---|---|---|---|---|
| `ConfigApiError` | `config_api_error` | `internal` | Basisklasse | nein |
| `ApiVersionError` | `api_version_unsupported` | `unsupported_version` | API- oder Provider-Version nicht unterstützt | nein |
| `RouterNotFoundError` | `router_not_found` | `not_found` | unbekannte Router- oder Entry-ID | nein |
| `RouterIdentityError` | `router_identity_error` | `conflict` | Adoption abgelehnt, verwaister Datensatz als aktiv benutzt | nein |
| `RouterUnavailableError` | `router_unavailable` | `unreachable` | Eintrag nicht geladen oder Router offline | ja |
| `RouterAuthError` | `router_auth_failed` | `auth` | Login am Router abgelehnt | nein |
| `RouterPermissionError` | `router_permission_denied` | `permission` | rpcd-ACL/SSH-Nutzer ohne Recht | nein |
| `OperationTimeoutError` | `operation_timeout` | `timeout` | Router-Aufruf oder Operation zu langsam | ja |
| `CapabilityUnavailableError` | `capability_unavailable` | `not_available` | Capability fehlt (auch Restore in Phase 1) | nein |
| `ProviderUnavailableError` | `provider_unavailable` | `not_available` | kein Provider registriert | nein |
| `ProviderConflictError` | `provider_conflict` | `conflict` | zweiter Provider | nein |
| `AuthorizationError` | `authorization_denied` | `denied` | Guard lehnt ab, Akteur unbekannt/ungeprüft, oder `consume` scheitert (`details.reason`: `not_admin`, `unverified_actor`, `unknown_user`, `unknown_authorization`, `already_used`, `expired`, `action_mismatch`, `router_mismatch`, `checksum_mismatch`, …) | nein |
| `ApprovalRequiredError` | `approval_required` | `approval` | kritische Aktion ohne freigegebenen Antrag (noch `pending`) | nein |
| `ApprovalInvalidError` | `approval_invalid` | `approval` | Antrag unbekannt, abgelaufen, benutzt, abgelehnt, anders gebunden, nicht vom Antragsteller eingelöst | nein |
| `BackupNotFoundError` | `backup_not_found` | `not_found` | Version unbekannt | nein |
| `BackupIntegrityError` | `backup_integrity_failed` | `checksum_mismatch` | sha256/Größe passt nicht | nein |
| `BackupMetadataError` | `backup_metadata_invalid` | `invalid` | Metadaten kaputt oder neuer als unterstützt | nein |
| `BackupIncompleteError` | `backup_incomplete` | `incomplete` | kein verwertbares Artefakt geholt | nein |
| `ArtifactTooLargeError` | `artifact_too_large` | `too_large` | Artefakt oder Router-Kontingent zu groß | nein |
| `StorageFullError` | `storage_full` | `storage_full` | Gesamtgrenze erreicht, nichts geschrieben | nein |
| `StorageError` | `storage_error` | `storage_error` | Dateisystemfehler | nein |
| `UnsupportedStorageFormatError` | `storage_format_unsupported` | `invalid` | unbekanntes `storage_format` | nein |
| `InvalidStorageRefError` | `storage_ref_invalid` | `invalid` | Locator kein einfacher Dateiname oder außerhalb des Router-Ordners (`details.reason`: `bad_locator`, `path_escape`) | nein |
| `VersionProtectedError` | `version_protected` | `conflict` | `delete` mit geschützten Versionen (`details.version_ids`), nichts gelöscht | nein |
| `InstallationKeyLostError` | `installation_key_lost` | `not_available` | Installations-Schlüssel verloren, während Versionen oder Bestätigungen existieren | nein |
| `RestoreIncompatibleError` | `restore_incompatible` | `incompatible` | Version passt nicht zum Zielrouter | nein |
| `OperationInProgressError` | `operation_in_progress` | `busy` | Router-Lock belegt | ja |
| `ProviderError` | `provider_error` | `internal` (überschreibbar) | unerwarteter Providerfehler, Ursache verkettet, nur Typname in `details.cause` | nein (überschreibbar) |
| `RateLimitedError` | `rate_limited` | `rate_limited` | zu viele Aufrufe einer Aktion (je Router); nichts getan. `retry_after` (Sekunden, endlich, ≥ 0) als Attribut, in `details.retry_after` und oben in `to_dict()` (ab B6); der Guard liefert ihn für `active`-Aktionen über ihrem `RateLimit` (`details.reason` `rate_limited`, `action`, `audit_id`; ab B5) | ja (fest) |
| `SafetyRefusedError` | `safety_refused` | `safety_refused` | Core oder Modul lehnt ab, weil die Aktion unsicher ist (z. B. trennt die Verwaltungsverbindung); keine Rechtefrage. `reason` (Attribut und `details.reason`, Muster `SAFETY_REASON_PATTERN` = `[a-z0-9][a-z0-9_.:-]{0,63}`) (ab B6) | nein (fest) |

`ErrorClass` enthält außerdem die elf Klassen aus `config-manager` 12.2 (`unreachable`,
`timeout`, `auth`, `permission`, `not_available`, `too_large`, `incomplete`, `invalid`,
`checksum_mismatch`, `storage_full`, `storage_error`) und wird auch in
`BackupRecord.error_class` und als `dedup_key` von `backup_failed` benutzt.

`rate_limited` und `safety_refused` (ab B6) sind **Aufruf-Klassen**
(`NON_PERSISTED_ERROR_CLASSES`): sie beschreiben einen abgelehnten Aufruf und landen nie
in einem gespeicherten Datensatz. `VersionMeta` und `BackupRecord` lehnen sie mit
`ValueError` ab; `version_error_class` bildet sie auf `busy` bzw. `denied` ab. Ein älterer
Core liest deshalb nie einen unbekannten Wert; der neue Wert ist additiv, ohne
`BACKUP_METADATA_VERSION`-Erhöhung (Ausnahme zur Regel in §2, weil nie persistiert).

```python
try:
    await api.async_create_backup(router_id, reason=BackupReason.SCHEDULED, actor=Actor.system())
except ConfigApiError as err:
    if err.retryable:
        schedule_retry()
    _LOGGER.warning("backup failed: %s", err.to_dict())
```

## 15. Abgleich mit config-manager Abschnitt 12

Jede verbleibende Abweichung zwischen den Anforderungen in `config-manager` (Plan,
Abschnitte 5, 9.1, 12, 20) und diesem Vertrag. Die 14 Punkte des Vertragsabgleichs nach
`5c9d248` stehen in Abschnitt 19.2.

| `config-manager` | Dieser Vertrag | Grund / was zu tun ist |
|---|---|---|
| 12.1 `version_id` | `backup_id` + Alias-Eigenschaft `version_id`, Typalias `VersionRecord` | ein Name im Index, Alias für beide Sprechweisen |
| 12.1 `kind` (`scheduled`/`manual`/`drift`/`release_change`) | `reason: BackupReason` (alle vier Werte vorhanden, plus weitere) | `kind` ist bei uns die Art der Artefakte (`backup_type`) |
| 12.1 `archive_sha256` | `artifacts["archive"].sha256`, abgeleitet als `record.sha256` | ein sha256 je Artefakt, keine doppelte Wahrheit |
| 12.1 `size_bytes` je Artefakt | `ArtifactRef.size_bytes`; `record.size_bytes` = Summe | – |
| 12.1 `storage_ref` je Artefakt | `artifacts[kind].storage: StorageRef` | – |
| 12.1 `release_version` | `openwrt_version` (+ `compatibility.openwrt_version`) | bestehender Name im Core |
| 12.1 `protected` „nur über Freigabe“ | Aktion `protect`: mutating, nur Admin-Benutzer, sofortige Entscheidung (keine zweistufige Freigabe) | Schutz verringert kein Risiko; zweistufig wäre nur Reibung |
| 12.2 `put_version(...) -> version_id` | `async_put_version(..., *, authorization) -> PutVersionResult(record, created)` | Dedup-Treffer muss erkennbar sein; Schreiben braucht eine Autorisierung (`backup`) |
| 12.2 `delete_versions(ids)` „nur Aufbewahrung oder Freigabe“ | `async_delete_versions(ids, *, authorization)` mit `prune` (nur Core, nach `plan_retention`) oder `delete` (kritisch, geschützte ⇒ `VersionProtectedError`) | Aufbewahrungsregel kommt vom Modul (`RetentionPolicy`), Ausführung vom Core |
| 12.2 `set_protected`, `put_drift_ack` | mit `authorization` (`protect` / `drift_ack`) | – |
| 12.2 Operationen ohne `async_` | alle mit `async_`-Präfix | HA-Konvention |
| 12.3 Verschlüsselung „gemäß Q3“ | keine eigene; `storage_format="plain-v1"`, `encrypted=False` | Nachtrag 2.2 |
| 12.4 / 9.1 Event-Namen | `config_backup_succeeded` → `configuration.backup_created`; `config_backup_failed` → `configuration.backup_failed`; `config_backup_recovered` → `configuration.backup_recovered`; `config_drift_detected` → `configuration.drift_detected`; `config_drift_acknowledged` → `configuration.drift_acknowledged`; `config_restore_checked` → `configuration.restore_checked` | Core-Schema mit Punkt-Namensraum; ein Bus-Event `openwrt_router_core_event`, Typ im Feld `type`; gesendet nur vom Core |
| 12.4 Dedup und Cooldown | `CoreEvent.dedup_key` + `dedup_scope`, `FAILURE_EVENT_COOLDOWN` 24 h, Umsetzung im Core (`emit`) | – |
| 12.4 Audit für Export „wer, wann, welche Version“ | ja, plus Artefakt und Antrag/Freigabe als `security.approval_*` im Sicherheitsring | – |
| 12.5 Freigabe „synchron freigegeben/abgelehnt/wartet + Kennung“ | `authorize()` ⇒ `AuthorizationDecision(state, audit_id, …)` | – |
| 12.5 `export` als schreibende Aktion | `export` ist **critical**: Antrag ⇒ Admin-Freigabe ⇒ ein Download durch den Antragsteller | Nachtrag 2.1; erster `authorize` liefert `pending`, nicht `approved` |
| 12.5 `restore` „später“ | im Vertrag, Phase 1 `CapabilityUnavailableError` | Nachtrag 2.3 |
| 12.6 Proben „einmal beim Setup und nach ACL-Neuverteilung“ | zusätzlich nach Firmware-Wechsel | neue Firmware kann rpcd-ACL und CGI ändern |
| 12.6 `config.uci_read` „je Config“ | `CapabilityStatus.detail = {config_name: bool}` | – |
| 11.6 Diff `changed` | `ChangeKind.MODIFIED` (`"modified"`) | bestehender Wert; Provider bildet ab |
| 11.6 Area/Risk als Enums | `ConfigChange.area`/`risk` als `str`; Zähler `critical_count`/`unknown_count` im `DriftReport` | Klassifikation gehört dem Provider |
| 9.2 Sensoren je Router | nicht im Core-Vertrag | Entities baut `config-manager` (Gruppe II) mit `router_id` aus der Registry |
| Q2 Besitz ACL v9 | Core, später: gestufte ACL, nur angeboten, Aktion `acl_deploy` (kritisch, nur Admin-Benutzer) | Nachtrag H / 2.4 |
| Q6 SSH-Host-Key | TOFU nur für den Config-Pfad, später | Nachtrag H |
| Q10 Panel-Container | Core legt „Enterprise“ an, nach Merge von 1.43.0 | Nachtrag H |
| Maskierung `config_mask`/`config_const` | aufgegangen in `core_masking` (Abschnitt 13) | eine Implementierung |

## 16. Restore in Phase 1

Verfügbar: Dry Run (`async_prepare_restore`), Kompatibilität
(`async_check_restore_compatibility`), Vorschau (`RestorePlan.diff`, `instructions` als
i18n-Schlüssel für eine Anleitung) und Export. Beides wird als
`configuration.restore_checked` auditiert.

Nicht verfügbar: `async_request_restore` und `async_execute_restore` werfen
`CapabilityUnavailableError(capability="config.restore")`, solange der Provider
`config.restore` nicht als verfügbar meldet. Eine spätere Phase bringt Restore auf
UCI-Ebene mit Rollback (eigener Plan). Ob vor einem Restore ein `pre_restore`-Backup
Pflicht ist, ist offen (Abschnitt 19.4).

```python
plan = await api.async_prepare_restore(backup_id, router_id, actor=admin)
if not plan.compatibility.compatible:
    show(plan.compatibility.issues)
try:
    await api.async_request_restore(plan, actor=admin)
except CapabilityUnavailableError:
    show(plan.instructions)   # Phase 1: Anleitung statt Ausführung
```

## 17. Erweiterungspunkte

| Modul | Nutzt | Beispiel |
|---|---|---|
| Security Intelligence (`security_center`) | Event-Präfix `security_center.`, Capability-Präfix `security.`, `subscribe`, Sicherheitsring lesen | `register_event_prefix("security_center.", module="security_center")`; reagiert auf `security.authorization_denied` |
| Network Intelligence | `links.incident_id`, `BackupReason.INCIDENT`, Drift als Kontext (nur lesend) | Backup bei kritischem Incident: `async_create_backup(..., reason=INCIDENT, links=BackupLinks(incident_id=…))` (nie dedupliziert) |
| Network Time Machine | `async_list_backups(since=…)`, `async_compare(ConfigRef.backup(a), ConfigRef.backup(b))`, `events(since=…)` | Zeitleiste aus Versionen und Events |
| Firmware Lifecycle | `BackupReason.PRE_FIRMWARE_UPDATE`/`RELEASE_CHANGE`, `FirmwareInfo`, `CompatibilityInfo` | vor Update `async_create_backup`, nach Update Proben neu |
| Self-Healing | `register_action("self_healing.<aktion>", CRITICAL, …)`, `BackupReason.PRE_CHANGE`, Korrelations-ID | Backup + Freigabe vor jedem Eingriff, alles mit einer `correlation_id` |
| Diagnose (`net_diagnostics`) | Event-Präfix `net_diagnostics.`, Capability-Präfix `diag.` **oder** `log.` (ein Detektor, ein Präfix), `active`-Aktionen mit `RateLimit` (§6.3) | `register_capability_detector("net_diagnostics", detect, prefix="diag.")` meldet `diag.traceroute`; ein Name außerhalb des Präfixes (z. B. `log.syslog`) wird verworfen und gezählt |

### 17.1 Andocken der Module (1.44.0)

| Modul (`module=`) | Event-Präfix (`MODULE_EVENT_PREFIXES`) | Capability-Präfix (`MODULE_CAPABILITY_NAMESPACES`) | Core-eigene Namen darin | ACL-Stufen |
|---|---|---|---|---|
| `security_center` | `security_center.` | `security.` (oder `log.`) | – | später (`security.`) |
| `net_diagnostics` | `net_diagnostics.` | `diag.` (oder `log.`) | – | später (`diag.`) |
| `wifi_rf` | `wifi_rf.` | `rf.` (oder `log.`) | `rf.txpowerlist`, `rf.survey`, `rf.scan` (`CORE_OWNED_MODULE_CAPABILITIES`, aus der ACL) | `rf_scan`, `rf_survey` |
| Provider (`config-manager`) | – (der Core sendet `configuration.*`) | `config.` (nur über `async_probe`) | – | `config_backup_read` (nur mit Option) |

```python
api.register_event_prefix("wifi_rf.", module="wifi_rf")        # nur das eigene Präfix
api.guard.register_action("wifi_rf.set_channel", ActionClass.CRITICAL,
                          module="wifi_rf", admin_user_only=True)
remove = api.register_capability_detector(
    "wifi_rf", detect, prefix="rf.", signature=lambda data: data.get("wifi_radios"))
unsubscribe = api.subscribe(on_event)
```

- `detect(record, data) -> Mapping[str, CapabilityStatus]` ist synchron und macht **keine**
  I/O; er läuft nur, wenn sich die Capability-Signatur des Core oder sein eigenes
  `signature(data)` ändert. Ein Modul hat höchstens einen Detektor und damit **ein**
  Präfix: sein eigener Namensraum (oder ein Präfix darunter) **oder** `log.`, nicht beides.
  Der Modulname ist der aus `MODULE_EVENT_PREFIXES` (`net_diagnostics`, nicht
  `net-diagnostics`); ein unbekannter Name unter einem fremden Namensraum ⇒ `ValueError`.
- Registrieren ⇒ `ValueError` bei: Präfix ohne Punkt am Ende, Core-Namensraum
  (`transport.`, `data.`, `stream.`, `pkg.`, `config.`), fremdem Modul-Namensraum, zweitem
  Detektor desselben Moduls; `TypeError` bei Nicht-Callables.
- Gemeldete Namen außerhalb des Präfixes, Core-eigene Namen, Werte, die kein
  `CapabilityStatus` sind, oder deren `capability` nicht zum Schlüssel passt, werden
  verworfen und gezählt (`detector_entries_refused`, Warnung im Log). Eine Ausnahme im
  Detektor zählt `detector_errors`, loggt eine Warnung und lässt den Poll unberührt.
- Die Capability-Ansicht der Registry kann bis zum nächsten Poll nachlaufen (Urteil e):
  ein neuer Detektor, eine Option oder eine ACL-Beobachtung setzt die Neubewertung an;
  sichtbar wird sie beim nächsten Lesen nach dem Poll oder sofort, wo der Core selbst
  neu bewertet (Option, ACL-Verteilen).

## 18. Später (nur dokumentiert, kein Code)

Gebaut in 1.44.0 (vorher hier nur dokumentiert): gestufte rpcd-ACL als Angebot
(`docs/dev/acl-tiers.md`), SSH-Pinning mit Bestätigung, Panel-Container „Enterprise“,
Option `config_backup_enabled`. Offen:

- **Restore auf UCI-Ebene** mit Rollback.
- **Oberfläche für Freigaben** (Panel/WebSocket) für Export, Löschen, `acl_deploy`,
  `ssh_pin_confirm`, `ssh_pin_reset`; heute nur Python-API.

## 19. Vertragsänderungen seit 5c9d248

B = breaking (bestehender Aufrufer muss sich ändern), A = additiv. „Verhalten“ heißt: die
Signatur bleibt, die Regel ist neu.

**Brechende Änderungen seit 1.44.0** (Folgeauftrag, Zeilen ab #100; was ein Modul ändern
muss):

- (#100) Bus-Pseudonyme sind bei vorhandenem Installations-Schlüssel über Neustarts stabil
  statt je Lauf neu. Wer sich auf den Wechsel nach einem Neustart verlassen hat, darf das
  nicht mehr.
- (#101) `async_detect_drift`, `async_prepare_restore`, `async_check_restore_compatibility`
  und `async_validate_backup(..., actor=...)`: ein Benutzer ohne Admin bekommt
  `AuthorizationError` `not_admin`. Module, die diese Aufrufe für normale Benutzer anbieten,
  müssen auf Admin prüfen oder als Modul-/Systemakteur aufrufen (und dann selbst
  entscheiden, wem sie das Ergebnis zeigen).
- (#102) Ausgabe zeigt jetzt Werte unter Kennungsnamen (`router_key`, `radio_key`, …) und
  Zahlen unter Zählernamen (`auth_failures`, …), die vorher `**REDACTED**` waren. Ein Modul,
  das unter solchen Namen Geheimnisse ablegt, muss sie umbenennen.

### 19.1 Änderungen auf Feld- und Signaturebene

**Akteure und Guard**

| # | Änderung | Art |
|---|---|---|
| 1 | `ActionGuardProtocol.authorize(..., actor: Actor)` → `actor: VerifiedActor`; ebenso `approve(..., actor: VerifiedActor)`, `reject(..., actor: VerifiedActor)` | B |
| 2 | neu: `VerifiedActor`, `async_verify_actor(hass, actor)`, `async_resolve_actor(hass, context, module=None)`, `ACTOR_VERIFICATION_TTL`, `VERIFICATION_ID_PREFIX` (`vac_`); Guard: `async_verify_actor`, `async_resolve_actor` | A |
| 3 | `is_admin` eines übergebenen `Actor` wird ignoriert; API und Guard lösen über `hass.auth` neu auf; systemgenerierte Benutzer sind nie Admin | B (Verhalten) |
| 4 | Benutzer ohne Admin: jede mutating/critical Aktion ⇒ `not_admin`, auch `backup` | B (Verhalten) |
| 5 | neu: `policy_denial_reason`, `approver_denial_reason`, `check_redeem`, `Actor.same_principal` | A |
| 6 | Freigabe einlösen nur durch den Antragsteller (`not_requester`) | B (Verhalten) |
| 7 | `WriteAuthorization.consume(...)` → `_consume(...)` (Guard-intern); neu `ActionGuardProtocol.consume(authorization, *, action, router_id, checksum=None)` mit Ledger (`unknown_authorization`), synchron auf dem Event-Loop | B |
| 8 | neu: `GuardedAction.INSTALLATION_KEY_RESET` (critical, nur Admin-Benutzer) | A |
| 9 | Export-Bindung `binding_checksum(version_id)` → `binding_checksum(version_id, artifact)`; `async_request_export(..., artifact=ArtifactKind.ARCHIVE)` | B (Bindung), A (Parameter) |
| 10 | offene Anträge überleben keinen Neustart (dokumentiert) | Verhalten |

**Versionsspeicher**

| # | Änderung | Art |
|---|---|---|
| 11 | `ConfigurationApiProtocol.versions` → `VersionReadView` (vorher `VersionStoreProtocol`); `VersionStoreProtocol(VersionReadView)` ist core-intern | B |
| 12 | `VersionStoreProtocol.async_read_artifact(storage_ref: StorageRef)` → `async_read_artifact(version_id: str, kind: str)` | B |
| 13 | `ArtifactReader = Callable[[StorageRef], Awaitable[bytes]]` → `Callable[[str, str], Awaitable[bytes]]`, bereichsgebunden je Aufruf | B |
| 14 | `StorageRef.locator` wird geprüft (`STORAGE_LOCATOR_PATTERN`); neu `validate_locator`, `resolve_artifact_path`, `InvalidStorageRefError` | B (Verhalten), A (Helfer) |
| 15 | `VersionMeta.created_by` entfernt; der Store setzt `created_by = authorization.actor` | B |
| 16 | `VersionMeta.error_class` genau bei `partial`/`failed` Pflicht | B (Verhalten) |
| 17 | neu: `VersionMeta.warnings`, `VersionMeta.installation_key_id`, `BackupRecord.warnings`, `BackupRecord.installation_key_id`, `BackupRecord.usable`, `WARNING_CODE_PATTERN`, `MAX_WARNINGS`, `USABLE_VALIDATION` | A |
| 18 | `CollectedVersion.warnings` entfernt (→ `meta.warnings`) | B |
| 19 | Dedup beim Ablegen: statt „gleicher Hash wie die neueste Version des Routers“ die Regeln aus 7.4; neu `dedup_candidate`, `should_deduplicate`, `DEDUP_REASONS` | B (Verhalten), A (Helfer) |
| 20 | `delete` mit geschützten Versionen ⇒ `VersionProtectedError`; fremde IDs ⇒ `AuthorizationError` `router_mismatch`; neu `validate_deletion` | B (Verhalten), A (Helfer) |
| 21 | neu: `RetentionPolicy`, `RetentionResult`, `KeepReason`, `plan_retention`, API `set_retention_policy`, `async_apply_retention`, Event `configuration.retention_applied`; `prune` nur noch System (vorher System/Modul) | A, B (`prune` für Module) |
| 22 | neu: API `async_put_version(router_id, artifacts, meta, *, authorization)` | A |

**Identität, Drift, Schlüssel**

| # | Änderung | Art |
|---|---|---|
| 23 | `RouterIdentity.status` (Feld) → `identity_flags: frozenset[IdentityFlag]` + abgeleitete Eigenschaft `status`; neu `IdentityFlag`, `primary_identity_status` | B (Konstruktor), A (Lesen von `status` bleibt) |
| 24 | `DriftAck.version_id`: bei `known` Pflicht, sonst verboten | B |
| 25 | neu: `Baseline`, `BaselineRule`, `select_baseline`, API `async_get_baseline` | A |
| 26 | `async_get_installation_key()` erzeugt nicht mehr beim ersten Zugriff, sondern nur im Zustand `uninitialised`; sonst ggf. `InstallationKeyLostError` | B (Verhalten) |
| 27 | neu: `InstallationKeyState`, `installation_key_state()`, `installation_key_id()`, `INSTALLATION_KEY_ID_LENGTH`, `ISSUE_INSTALLATION_KEY_LOST`, API `installation_key_state`, `async_request_installation_key_reset`, `async_reset_installation_key`, `InstallationKeyLostError` | A |
| 28 | neu: `ChangeKind.NOT_COMPARABLE`, `ConfigDiff.comparable_changes` | A |
| 29 | neu: `DriftReport.baseline_rule`, `critical_count`, `unknown_count`, `secrets_comparable`, `rebaseline`; `drift_event_types`, `integrity_failed`. (Die Regel „`rebaseline` mit `drifted` ⇒ `ValueError`“ ist durch #56 ersetzt.) | A |

**Provider**

| # | Änderung | Art |
|---|---|---|
| 30 | jede `ConfigBackupProvider`-Methode bekommt `ctx: ProviderContext`; Parameter `read` entfällt (in `async_validate`, `async_compare`, `async_detect_drift`, `async_prepare_restore`) | B |
| 31 | `async_compare(base, other, ctx, *, base_router, other_router)` | B |
| 32 | `async_detect_drift(conn, baseline, acks, ctx, *, router)` (vorher `conn, baseline, read, acks`) | B |
| 33 | neu: `ProviderContext` (`registry`, `read`, `installation_key`, `installation_key_state`, `correlation_id`, `async_get_installation_key()`) | A |
| 34 | `ConfigSnapshot.format` Standard `"uci_json"` → `"uci_normalized"` (`SNAPSHOT_FORMAT_UCI_NORMALIZED`); `configs: Mapping[str, Mapping[str, Any]]` → `Mapping[str, Any]` (opak) | B |
| 35 | neu: `ConfigSnapshot.uci_hash`, `ConfigSnapshot.installation_key_id`; `checksum` ausdrücklich nur Bindungsprüfsumme | A |
| 36 | Provider feuert keine Events; der Core erzeugt sie aus Ergebnissen | Verhalten |

**Events**

| # | Änderung | Art |
|---|---|---|
| 37 | `dedup_key(router_id, discriminator)` entfernt; `CoreEvent.dedup_key` ist nur der Unterscheider, Bereich `CoreEvent.dedup_scope` = `(router_id or "-", type, dedup_key)` | B |
| 38 | `emit(...) -> CoreEvent \| None` → `emit(...) -> EmitResult`; neu Parameter `entry_id` | B (Rückgabe), A (Parameter) |
| 39 | `emit` eines Core-Typs durch ein Modul ⇒ `ValueError`; Modul-Präfixe nicht in `CORE_EVENT_NAMESPACES` (Beispiel `security.ids.` → `security_center.`) | B |
| 40 | neu: `CoreEvent.repeat_count`, `last_repeat_at`, Eigenschaften `dedup_scope`, `audit_ring`; `EmitResult` | A |
| 41 | neu: `AuditRing`, `SECURITY_AUDIT_MAX_EVENTS` (500), `SECURITY_EVENT_TYPES`, `AUDIT_MANDATORY_EVENT_TYPES`, `audit_ring_for`, `CORE_EVENT_NAMESPACES`, `is_core_event_type`; `events(..., ring=None)` | A |
| 42 | neu: Event-Typen `configuration.change_critical`, `configuration.change_unknown`, `configuration.integrity_failed`, `configuration.retention_applied`, `security.authorization_consumed`, `core.installation_key_lost`, `core.installation_key_reset` | A |
| 43 | Wiederholung im Cooldown: Eintrag bekommt `repeat_count`, statt nicht gespeichert zu werden | B (Verhalten) |

**Allgemein**

| # | Änderung | Art |
|---|---|---|
| 44 | Mapping-Felder tief schreibgeschützt (`MappingProxyType`, Tupel); Schreiben ⇒ `TypeError` | B (Verhalten) |
| 45 | Enum-Felder werden umgewandelt, ungültige Werte ⇒ `ValueError` (vorher ungeprüft) | B (Verhalten) |
| 46 | `from_dict` prüft Typen streng; Zeitstempel ohne Zeitzone werden abgelehnt (vorher als UTC angenommen) | B (Verhalten) |
| 47 | `BackupRecord.artifacts`-Schlüssel nur `ArtifactKind`; `ExportHandle.artifact` geprüft | B (Verhalten) |
| 48 | Freitext in `to_dict()` geschrubbt (`ConfigApiError.message`, `CompatibilityIssue.message`, `RestoreStep.description`, `RestoreResult.message`, `ApprovalRequest.reason`) | A |
| 49 | neu: `FLEET_BACKUP_CONCURRENCY`, `STORAGE_LOCATOR_PATTERN`; `SUPPORTED_PROVIDER_API_VERSIONS` jetzt dokumentiert | A |
| 50 | neu in `core_errors`: `InvalidStorageRefError`, `VersionProtectedError`, `InstallationKeyLostError` | A |

**Maskierung (`core_masking`)**

| # | Änderung | Art |
|---|---|---|
| 51 | `mask_secrets` maskiert mehr Namen (Obermenge), `bytes` ⇒ `**REDACTED**`, Dataclasses ⇒ maskierte dicts, Sets ⇒ sortierte Listen | B (Verhalten) |
| 52 | `MAX_DEPTH` 32 → 64; `SECRET_SUBSTRINGS` neu zusammengesetzt (`pass` statt `password`/`passwd`/`passphrase`, dazu `apikey`, `credential`, `private`, `psk`, `pwd`); `SAFE_KEYS` erweitert | B (Konstanten) |
| 53 | neu: `mask_for_output`, `redact_text`, `scrub_text`, `is_secret_name`, `is_secret_option`, `is_secret_path`, `secret_digest_factory`, `SECRET_OPTIONS`, `SECRET_CONTEXT_OPTIONS`, `SECRET_EXTRA_NAMES`, `SECRET_ARCHIVE_PATHS`, `SAFE_SUFFIXES`, `SECRET_MARKER_KEY`, `SECRET_DIGEST_LENGTH` | A |

**Teil 1 (Registry, Identität, Capabilities, Audit)**

| # | Änderung | Art |
|---|---|---|
| 54 | neu: Event-Typ `CoreEventType.STORE_RECOVERED` = `core.store_recovered`, in `AUDIT_MANDATORY_EVENT_TYPES` (Abschnitt 12.3). Grund: ein unlesbarer Core-Store wird neu aufgebaut; ohne eigenes Event wäre der Verlust von Adoptionen nur im Log sichtbar. | A |

**Teil 2 (Guard, Versionsspeicher, Configuration API)**

| # | Änderung | Art |
|---|---|---|
| 55 | Implementiert: `core_guard.py` (`ActionGuard`), `version_store.py` (`VersionStore`, Installations-Schlüssel), `config_api.py` (`ConfigurationManager`, `async_get_configuration_api(hass, version=1)`), angehängt an `EnterpriseCore`. Modulname `core_versions.py` → `version_store.py`. Ohne Provider kein Router-Aufruf. | A |
| 56 | `DriftReport(rebaseline=True, drifted=True)` ist erlaubt (vorher `ValueError`, ersetzt #29): Schlüsselwechsel und echte Änderung zusammen sind ein Drift. Neu `DriftReport.rebaseline_allowed`; Re-Baseline nur bei Entwarnung und bekanntem Schlüsselwechsel (11.3). | B (Verhalten) |
| 57 | neu: `DriftComparison` (`complete`/`partial`/`unknown`), `DriftReport.comparison`, `DriftReport.not_compared`, `DriftReport.all_clear`, Event `configuration.drift_incomplete`. `partial` ohne `not_compared` oder `complete` mit `not_compared` ⇒ `ValueError`. Keine Entwarnung und kein Dedup-Reset bei unvollständigem Vergleich (11.4). | A (Felder mit Standard `complete`), B (Verhalten) |
| 58 | Proben prüfen nur Rechte/Metadaten; neu `CapabilityReason.DETERMINED_ON_FIRST_USE`; `config.*` in `unknown`/`determined_on_first_use` darf versucht werden, das Ergebnis setzt den Status (Abschnitt 5). | A, B (Verhalten von `require_capability`) |
| 59 | Ungeprüfte Provider-Eingabe (7.3): Größenlimit vor dem Hash, sha256 vom Core, geschlossene Artefaktarten, nur Core-Locator, begrenzte Metadaten, `check_key_id`; neue `reason`-Werte `not_a_collected_version`, `meta_not_version_meta`, `unknown_artifact_kind`, `artifact_not_a_payload`. | B (Verhalten), A (Helfer) |
| 60 | Dedup verlangt zusätzlich gleiche `installation_key_id` (7.4, Regel 5). | B (Verhalten) |
| 61 | `RouterRegistry.get` und `VersionStore.get` lehnen ungültige IDs ab, ohne sie zurückzugeben (`reason` `invalid_router_id` / `invalid_version_id`). | B (Verhalten) |
| 62 | Aufbewahrung: `RetentionPolicy.daily`/`weekly`/`monthly`, `RetentionPolicy.gfs()`, `uses_gfs`, `DEFAULT_RETENTION_POLICY` (GFS 7/4/6), `KeepReason.DAILY`/`WEEKLY`/`MONTHLY`/`RECENT_FAILED`, `plan_retention(..., now=, max_bytes=)`, `RetentionResult.over_limit`; Aufbewahrung nach jedem Ablegen. | A, B (Standardverhalten: vorher keine Aufbewahrung ohne Modulregel) |
| 63 | neu: Event-Typen `configuration.storage_limit_exceeded`, `security.authorization_granted` (Audit-Pflicht: jede Guard-Entscheidung schreibt einen Eintrag). | A |
| 64 | `core_store.create_store(..., private=False, atomic_writes=False)`: neue optionale Parameter; der Store des Installations-Schlüssels nutzt `private=True`, `atomic_writes=True`. | A |

**1.44.0 (ACL-Angebot, Option, SSH-Pins, Urteile, Andocken)**

| # | Änderung | Art |
|---|---|---|
| 65 | `__init__.py` und Config-Flow rufen `ensure_acl_respecting_offer(api, observe=…)` statt `ensure_acl`/`check_and_deploy_acl`: eine verteilte gestufte ACL bleibt über Neustarts; ohne gestufte ACL dieselben Aufrufe und Bytes wie vorher (Test). Neu `AclEnsureOutcome`, `ensure_acl_outcome`, `observe_deployed_acl`. | A, B (Verhalten: gestufte ACL wird nicht mehr auf v8 zurückgesetzt) |
| 66 | neu: API `async_request_acl_deploy`, `acl_offer`, `async_deploy_acl_offer` (Abschnitt 6.3); `acl_provisioning.async_deploy_acl_offer(..., ssh_runner=None)`: SSH-Schreiben nur über einen gepinnten Runner, sonst `AclOfferRefusedError` `ssh_pin_unavailable` (vorher gemeinsamer ungeprüfter SSH-Weg). | A, B (Verhalten des SSH-Wegs) |
| 67 | neu: `Capability.RF_TXPOWERLIST`/`RF_SURVEY`/`RF_SCAN`, `ACL_CAPABILITIES`, `CORE_OWNED_MODULE_CAPABILITIES`, `STRICT_CAPABILITIES`, `DeployedAclObservation`; Registry `note_deployed_acl`, `deployed_acl`. `rf.*` aus der verteilten ACL; unbekannte ACL ⇒ `unknown` mit Grund. | A |
| 68 | Option `config_backup_enabled` (`OPTION_CONFIG_BACKUP_ENABLED`, `DEFAULT_CONFIG_BACKUP_ENABLED = False`): aus ⇒ `config.*` `disabled` (vor `no_provider`), kein Provider-Aufruf (auch keine Probe), `async_validate_backup` und `async_compare` mit gespeicherten Versionen ⇒ `CapabilityUnavailableError` `disabled` (Zähler `refused_disabled`); ACL-Stufe `config_backup_read` abgelehnt. Registry `set_config_enabled`, `config_enabled`; Manager `on_config_option_changed`. | B (Verhalten: Standard aus) |
| 69 | neu: `SshPinRegistry`/`RouterPinStore` (Store `openwrt_router.ssh_host_keys`, privat, atomar, `migrate_pin_store`), `SSH_PIN_FIRST_USE_POLICY = "confirm"`, `GuardedAction.SSH_PIN_CONFIRM`/`SSH_PIN_RESET` (critical, nur Admin), API `ssh_pin_status`, `async_request_ssh_pin_confirm`, `async_confirm_ssh_pin`, `async_request_ssh_pin_reset`, `async_reset_ssh_pin`. | A |
| 70 | `ProviderContext.ssh` + `ctx.async_ssh_run_pinned(router_id, command, *, timeout, binary)`; ohne Pin-Store ⇒ `AuthorizationError` `ssh_pin_unavailable`. `api.async_ssh_run_pinned` reicht `OpenWrtHostKeyError` aus `async_save_pin` unverändert durch (vorher immer `pin_save_failed`). | A, B (Verhalten der Fehlergründe) |
| 71 | GFS dünnt `manual`/`pre_*` nicht aus: `KeepReason.MANUAL`, `GFS_KEEP_REASONS`; `RetentionResult.limit_deleted`, `limit_deleted_manual` (7.5). | B (Verhalten), A (Felder) |
| 72 | Dedup vergleicht zusätzlich die sha256 des Core: `should_deduplicate(..., artifact_sha256=None)` (7.4); Zähler `dedup_refused_sha256`. | B (Verhalten), A (Parameter) |
| 73 | Entfernen eines Eintrags verschiebt seine Versionen nach `removed/<router_id>/`: `VersionStore.async_archive_router`, Event `configuration.router_archived`. | B (Verhalten), A |
| 74 | `created_at` neuer Versionen ist je Store streng monoton (+1 µs bei gleicher oder rückläufiger Uhr, Zähler `created_at_adjusted`); „neueste zuerst“ ist damit eindeutig. | Verhalten |
| 75 | neu: Event-Typen `security.acl_deployed`, `security.acl_deploy_failed`, `security.ssh_pin_pending`, `security.ssh_pin_confirmed`, `security.ssh_pin_mismatch`, `security.ssh_pin_reset`, `configuration.router_archived` (12.3). | A |
| 76 | neu: `register_capability_detector(module, detector, *, prefix, signature=None)` (17.1); Zähler `detector_runs`, `detector_errors`, `detector_entries_refused`. | A |

**1.44.0 — Sicherheits- und Korrektheitsprüfung vom 2026-11-18 (Befunde 1–18)**

| # | Änderung | Art |
|---|---|---|
| 77 | Optionale ACL-Stufen (Befund 1): Allowlist statt Sperrliste. Nur exakte Tripel aus `OPTIONAL_TIER_ALLOWLIST` oder der geprüften Tabelle `OPTIONAL_TIER_EXTENSIONS` (leer), keine Musterzeichen `* ? [ ] { } \` in Objekt/Methode, Dateien nur `read` mit normalisiertem Pfad unter `OPTIONAL_TIER_FILE_READ_PREFIXES`; die Basis-Stufe ist fest (v8). Ablehnung: `AclTierRightRefusedError` (Unterklasse von `AclTierError`) mit `tier_id`, `right`, `reason` (`write_section`, `pattern`, `not_allowlisted`, `file_method`, `file_path`, `base_tier_fixed`), Warn-Log. | B (Verhalten: vorher angenommene Rechte werden abgelehnt), A |
| 78 | `AclOffer.rights`, `tier_rights`, `rights_text()`; `to_dict()` zusätzlich `rights`, `tier_rights`, `rights_text`: der Admin gibt Rechte frei, nicht nur eine Prüfsumme (Befund 1). | A |
| 79 | `api.async_ssh_run_pinned`, Erstkontakt (Befund 2): eine Verbindung OHNE Zugangsdaten liest den Host-Key und bricht im Handshake vor der Anmeldung ab; angemeldet wird nur auf einer Verbindung, die auf einen BESTÄTIGTEN Pin festgelegt ist. Bei `confirm` endet der Erstkontakt mit `pin_pending` ohne Anmeldung; ein sofort bestätigender Store (tofu) meldet sich auf einer zweiten Verbindung an. `_PinningSSHClient(None)` lehnt jeden Key ab. | B (Verhalten: eine Verbindung mehr, keine Anmeldung vor der Bestätigung) |
| 80 | `api.async_ssh_run_pinned(..., max_output_bytes=None)` und `ctx.async_ssh_run_pinned(..., max_output_bytes=None)` (Befund 3): stdout stückweise bis zur Grenze (Standard `PINNED_SSH_DEFAULT_MAX_OUTPUT_BYTES` = Artefakt-Grenze + 1 MiB), darüber Abbruch mit `OpenWrtSshOutputTooLargeError` (`error_class` `too_large`, `limit_bytes`, `received_bytes`), im Core `ArtifactTooLargeError` `reason` `ssh_output_too_large`, Zähler `output_too_large`; stderr höchstens `PINNED_SSH_STDERR_MAX_BYTES` (4096), `PinnedSshResult.stderr_truncated`. ACL-Deploy per SSH: Grenze 64 KiB. Gesamt-Timeout unverändert. | A, B (Verhalten: zu große Ausgabe bricht ab) |
| 81 | Guard `add_approval_listener(listener(approval_id, reason)) -> remover`, `reason` `ttl`/`unload`/`rejected` (Befund 4); Manager und Sicherheitsaktionen verwerfen dort ihre Antragsdaten (Zähler `requests_dropped_on_expiry`, `requests_dropped_on_close`, Guard `listener_errors`). Dry-Run-Pläne leben `RESTORE_PLAN_TTL` (= `APPROVAL_TTL`), höchstens `MAX_RESTORE_PLANS` (50), Zähler `plans_expired`, `plans_evicted`. | A, B (Verhalten: abgelaufener Plan unbekannt) |
| 82 | Offene Freigaben begrenzt (Befund 4): `MAX_OPEN_APPROVALS_PER_PRINCIPAL` (20), `MAX_OPEN_APPROVALS_TOTAL` (200); darüber Entscheidung `DENIED` mit `too_many_open_approvals` bzw. `too_many_open_approvals_total` (auditiert, Zähler `approvals_capped`, Warn-Log). | B (Verhalten) |
| 83 | neu: Event `security.config_option_changed` (Sicherheitsring, Pflicht-Audit), `data` `option`, `old`, `new`, `source` (`options_flow`), `actor_known`; Manager `on_config_option_changed(router_id, enabled, *, actor=None)`, `audit_config_option_changed(router_id, enabled, *, actor=None)` (Befund 5). Der Options-Flow von HA liefert meist keinen Benutzer: dann `actor` None, `actor_known` False. | A |
| 84 | `AuditLog.emit` maskiert `data` mit `mask_for_output`, BEVOR es gehalten, gespeichert oder veröffentlicht wird (Befund 6). Strings unter id/hash-Schlüsseln bleiben nur in ihrer strengen Form, sonst `redact_text`; `pw` ist geheim; neue Textformen (escaptes JSON, URL-kodierte und verwechselbare/Nullbreiten-Namen, `sshpass -p`, `name<TAB>wert`, `<name>wert</name>`, `root/PW`); Feld-Datensätze (`key`/`name`/`field`/… nennt ein Geheimnis) maskieren ihre Werte. `value`/`keys` sind KEINE geheimen Namen (Diffs bleiben lesbar). SSH-Fingerabdrücke (`SHA256:`+43) und Pfade aus Core-IDs (`removed/rtr_…`) bleiben im Freitext lesbar. | B (Verhalten: gespeicherte Audit-Daten maskiert) |
| 85 | Audit-Dedup-Fenster (Befund 7): abgelaufene Fenster werden beim Öffnen eines neuen entfernt, höchstens `MAX_DEDUP_SCOPES` (4096) offen; Zähler `dedup_scopes_pruned`, `dedup_scopes_dropped` (Warn-Log), `summary()["dedup_scopes"]`. Ein verworfenes Fenster heißt nur: die nächste Wiederholung wird wieder veröffentlicht. | Verhalten, A |
| 86 | Startup-Sweep folgt keinen symbolischen Links und Windows-Junctions (Befund 8): nie gefolgt, verschoben oder gelöscht, nur gezählt: `SweepReport.symlinks_skipped`, Zähler `sweep_symlinks_skipped`, `configuration.storage_swept` auch bei Links. | A, Verhalten |
| 87 | neu: Event `core.installation_key_replaced` (Sicherheitsring, Pflicht) und Reparaturhinweis `installation_key_replaced` (Warnung, nicht persistent), wenn ein Schlüssel entsteht, während eine unbrauchbare Schlüsseldatei existierte (Befund 9); `VersionStore.key_replaced_hook`, Zähler `keys_replaced`. | A |
| 88 | Feindliches ACL-JSON (Befund 10): `parse_acl_text(text) -> (parsed, why)` mit `MAX_ACL_TEXT_BYTES` (64 KiB) VOR dem Parsen, `why` `missing`/`too_large`/`too_deep`/`invalid_json`, nie eine Ausnahme (Zähler `acl_current_unparsable`); `ensure_acl` behandelt tiefe Verschachtelung als `corrupted`; Versionsnummer der Stufen-Markierung höchstens 6 Ziffern; Backup-Name `….json.bak-<UTC-Sekunde>-<8 hex>` (zufälliger Zusatz). | B (Verhalten: Backup-Name), A |
| 89 | Diagnose (Befund 11): `actor.user_id` in den Audit-Einträgen wird zu `usr_<12 hex>` (HMAC mit Zufallssalz je Download; gleicher Benutzer gleich innerhalb eines Downloads). | B (Verhalten der Diagnoseausgabe) |
| 90 | setup_retry (Befund 12): ein neuer Core überspringt den Startup-Sweep, wenn der letzte Sweep dieses HA-Laufs weniger als `SWEEP_MIN_INTERVAL_SECONDS` (600 s) her ist UND seitdem kein Core eine Versionsdatei geschrieben, gelöscht oder verschoben hat (`VersionStore.file_activity`); Zähler `sweeps_skipped`. Die Freigabe schreibt nur Stores mit offenen Änderungen: `EnterpriseCore.async_flush(*, only_pending=False)`, `SshPinRegistry.dirty`, `VersionStore.has_pending_save`. | Verhalten, A |
| 91 | Defekter Store unter echtem HA (Befund 13): HA benennt ungültiges JSON in `<datei>.corrupt.<Zeit>` um und liefert None; das gilt jetzt als fehlgeschlagenes Laden (`StoreLoad.corrupt_path`, Recovery-Event wie bei einer Ausnahme). Versionsindex wiederhergestellt: `index_recovered_at` (persistiert); der Sweep lässt Dateien ohne Indexeintrag liegen, solange der Index wiederhergestellt oder leer ist (`SweepReport.unindexed_kept`, Zähler `sweep_unindexed_kept`, `core.store_recovered` mit `index_state`, `unindexed_files_kept`). | B (Verhalten: nichts nach `orphaned/`), A |
| 92 | `backup_recovered` (Befund 14): auch ein deduplizierter Erfolg beendet Fehlerfenster; welche Fehlerklassen offen waren, kommt zusätzlich aus dem gespeicherten Audit (nach einem Neustart); der Dedup-Reset gilt allen Fehlerklassen des Routers. | Verhalten |
| 93 | `capabilities.merge(..., *, last_known=None)` (Befund 16); die Registry führt den letzten bekannten Zustand je Router: bekannt → unknown → anders bekannt meldet `router_capabilities_changed` vom letzten bekannten Zustand (vorher stille Erstdetektion). | A, Verhalten |
| 94 | Config-Flow (Befund 17): wurde nichts geschrieben, unterscheidet der Fehler `acl_tiered_kept` (gestufte ACL behalten), `acl_check_transient` (ACL nicht lesbar, nichts geändert) und wie bisher `acl_already_current`; Konstanten `ERROR_ACL_TIERED_KEPT`, `ERROR_ACL_CHECK_TRANSIENT`; Texte en/de. | A, Verhalten (UI-Text) |
| 95 | `async_capture` und `async_compare` (Review PR #55, Punkt 2): ein Benutzer ohne Admin ⇒ `AuthorizationError` `reason` `not_admin` (`details.action` `config_capture`/`config_compare`, `audit_id`), auditiert auf dem Sicherheitsring, vor jedem Provider-Aufruf; Modul-, System- und Automationsakteure unverändert. Konstanten `READ_CAPTURE`, `READ_COMPARE` (`config_api`). | B (Verhalten) |
| 96 | Versionsdateien (Review PR #55, Punkt 3): `.partial` wird exklusiv angelegt (`O_CREAT \| O_EXCL`, `O_NOFOLLOW` wo vorhanden, `0o600`, Rechte per `fchmod` am offenen Deskriptor). Link/Junction/Ordner am `.partial`-Pfad ⇒ `StorageError` `reason` `partial_not_regular`, `found` (`symlink`/`folder`/`other`), Warn-Log, Zähler `partial_refused` (zählt auch in `write_errors`); gleichnamige reguläre Datei ⇒ entfernt, einmal neu angelegt. | Verhalten, A |
| 97 | `ensure_acl_outcome(respect_offer=True)` (Review PR #55, Punkt 5): eine gestufte ACL ohne alle Basis-Leserechte bleibt behalten, aber mit Warn-Log, `AclEnsureOutcome.missing_base_rights` (neu, Standard `()`) und Reparaturhinweis `acl_base_rights_missing_<entry_id>` (de/en, verschwindet bei vollständigen Rechten und beim Entladen). Neu `missing_base_read_rights(acl)`, `issues.async_sync_acl_base_rights_issue`, `ISSUE_ACL_BASE_RIGHTS_MISSING`. Auf diesem Pfad `parse_acl_text` statt `json.loads`: zu groß/zu tief ⇒ `corrupted`, v8 wird eingespielt. Pfad ohne Angebot unverändert. | A, Verhalten |
| 98 | Router-Registry (Review PR #55, Punkt 6): Entladen verwirft den Laufzeitzustand (`RouterRegistry.release_entry`, von `EnterpriseCore.forget_entry`). Verwaiste Datensätze begrenzt: `prune_orphans(known_entry_ids, versioned_router_ids)` beim Core-Laden; ohne Versionen nach `ORPHAN_RETENTION_DAYS` = 90 Tagen, über `MAX_ORPHANED_RECORDS` = 64 die ältesten (ohne Versionen zuerst); Datensätze bestehender (auch früherer) Einträge nie; ohne bekannte Einträge oder ohne geladenen Versionsspeicher nichts. Neuer Event-Typ `router.forgotten` (Ring `security`, audit-pflichtig); Zähler `runtimes_released`, `orphans_forgotten_aged`, `orphans_forgotten_capped`, `orphan_prune_skipped`. | A, Verhalten |
| 99 | Bus-Event `openwrt_router_core_event` (Review PR #55, Punkt 7): jede `user_id` im Payload wird zu `usr_<12 hex>` (HMAC-SHA256, Zufallssalz je Audit-Log, nur im Speicher). Gemeinsamer Helfer `core_masking.pseudonymise_user_id(s)`, `ACTOR_PSEUDONYM_PREFIX` jetzt in `core_masking` (Diagnose re-exportiert); die Diagnose ersetzt nun auch verschachtelte `user_id`. Audit-Store und Listener unverändert mit echter ID. | B (Verhalten des Bus-Payloads) |

Befunde 15 und 18 ändern nur Tests (kein Vertrag): die Wächter „HA-eigene Daten
unverändert“ prüfen zusätzlich die Aufrufe `async_update_entry`, `async_remove`,
`async_reload`, `async_schedule_reload`, `async_forward_entry_setups(_setup)`
(`core_testkit.ha_entry_calls`), und der ACL-Aufruf-Pin vergleicht mit wörtlichen
Erwartungen aus 1.43 statt beide Varianten miteinander.

**Folgeauftrag nach 1.44.0 (Teil B)**

| # | Änderung | Art |
|---|---|---|
| 100 | Modul-Schlüssel (B1, §11.5): `api.async_get_module_key(module, purpose="")` (HKDF-SHA256, `MODULE_KEY_SALT`, `MODULE_KEY_INFO_PREFIX` `…/v1`, 32 Bytes); nur für Module mit registriertem Event-Präfix; `lost` ⇒ `InstallationKeyLostError`. Reine Helfer `hkdf_sha256`, `derive_module_key`, `check_module_name`, `MODULE_NAME_PATTERN`, `MODULE_KEY_PURPOSE_PATTERN`, `CORE_KEY_OWNER`; `AuditLog.registered_modules()`; Zähler `module_keys_issued`/`module_keys_refused`. Bus-Pseudonym (§12.1): Salz aus `derive_core_key(key, "bus_pseudonym")`, über Neustarts stabil; ohne Schlüssel zufällig je Lauf, Zähler `bus_salt_ephemeral` + ein Log-Eintrag. `async_get_installation_key` für Provider unverändert. | A; B (Verhalten des Bus-Pseudonyms) |
| 101 | `async_validate_backup(backup_id, *, actor=None)` (neues optionales Argument), `async_detect_drift`, `async_prepare_restore` und damit `async_check_restore_compatibility` (B2): Benutzer ohne Admin ⇒ `AuthorizationError` `not_admin` (`details.action` `config_validate`/`config_drift`/`config_restore_dry_run`, `audit_id`), auditiert auf dem Sicherheitsring, vor jedem Nachschlagen und Provider-Aufruf; Audit-Router ist der bekannte Router bzw. der Router einer bekannten Version, sonst `-` (unbekannte IDs werden nicht wiedergegeben). Modul-, System- und Automationsakteure unverändert. `async_validate_backup` ohne `actor` bleibt erlaubt (Altaufruf), Zähler `validate_without_actor`. Konstanten `READ_VALIDATE`, `READ_DRIFT`, `READ_RESTORE_DRY_RUN`. | A (Signatur); B (Verhalten für Benutzer ohne Admin) |
| 102 | Maskierung (B4, §13): Kennungsnamen (`IDENTIFIER_KEY_NAMES`, `is_identifier_name`) sind keine geheimen Namen mehr, ihr Wert wird nur bei Schlüsselmaterial maskiert (`looks_like_key_material`); Zählernamen (`COUNTER_SUFFIXES`, `is_counter_name`) zeigen Zahlen. `is_snapshot_secret` unverändert. Neu, rein: `pseudonymise_identifier(kind, value, key)`, `pseudonymise_fields(data, key, fields)`, `IDENTIFIER_PSEUDONYM_PREFIXES`, `IDENTIFIER_PSEUDONYM_HEX_LENGTH` (16), `IDENTIFIER_INVALID`. MAC/IP/Hostname/SSID/BSSID werden vom Core nie maskiert (unverändert, jetzt festgeschrieben). | A; Verhalten (weniger Überdeckung) |
| 103 | Modul-Events (B3, §12.1/§12.2/§12.5): `CoreEvent.security_relevant`, `CoreEvent.audit_mandatory` (beide `bool`, Standard `False`, in `to_dict`/`from_dict`; alte Einträge lesen sich unverändert, keine Store-Version); `emit(..., security_relevant=False)` (Audit-Log und API); `register_audit_mandatory_types(types, *, module) -> remover`; `register_event_prefix(...)` liefert einen Entferner statt `None`; Dedup nur im selben Ring; Zähler `security_relevant_module_events`, `module_mandatory_types`. Bus-Payload hat zwei neue Schlüssel. | A |
| 104 | Fehler (B6, §14): `RateLimitedError` (`code` `rate_limited`, `ErrorClass.RATE_LIMITED`, immer retryable, `retry_after`) und `SafetyRefusedError` (`code` `safety_refused`, `ErrorClass.SAFETY_REFUSED`, nie retryable, `reason`); `NON_PERSISTED_ERROR_CLASSES`, `SAFETY_REASON_PATTERN`. Beide Klassen sind Aufruf-Klassen: `VersionMeta`/`BackupRecord` lehnen sie ab, `version_error_class` bildet sie auf `busy`/`denied` ab, keine Metadaten-Version. Ein Provider, der eine davon als `error_class` eines Datensatzes setzen wollte, bekommt `ValueError` (vorher gab es die Werte nicht). | A |
| 105 | Guard (B5, §6.3, §12.3): `ActionClass.ACTIVE` ("aktiv, nicht ändernd"; nicht persistiert), Politik wie `mutating`, keine Freigabe, Erteilung als `core.active_action_granted` auf dem allgemeinen Ring (audit-pflichtig), Ablehnung wie bisher auf dem Sicherheitsring. `register_action(..., sensitive_read=False, rate_limit=None)` (Guard und `api.guard`); `RateLimit(max_calls, per)`, `RATE_LIMIT_MAX_CALLS`, `RATE_LIMIT_MAX_PERIOD`; Ablehnung `rate_limited` mit `AuthorizationDecision.retry_after` (neues optionales Feld, auch in `to_dict`), `core.action_rate_limited` (allgemeiner Ring, dedupliziert je Fenster), `error_for_decision` ⇒ `RateLimitedError`; `REASON_RATE_LIMITED`, `MAX_RATE_WINDOWS`. `policy_denial_reason(..., sensitive_reads=frozenset())`. Zähler `active_granted`, `rate_limited`, `rate_windows_dropped`. B6 kam vor B5, weil das Limit `RateLimitedError` braucht. | A |
| 106 | Vertrag an Code angeglichen (B7): §6.3 beschreibt, dass `authorize` auch für `read` eine `WriteAuthorization` prägt und `security.authorization_granted` auditiert (die Core-Lesewege rufen `authorize` nicht auf); §17/§17.1 Modulnamen `security_center`/`net_diagnostics` und „ein Detektor, ein Präfix“ (`diag.` **oder** `log.`); §5 nennt `rf.` als reservierten Namensraum; neue Tabelle §3.1 (alle reservierten Präfixe, per Test vollständig); neuer §4.1. Code: `FLEET_ROUTER_ID` jetzt in `core_models` (`core_guard.FLEET_ROUTER_ID` bleibt, derselbe Wert), `is_fleet_router_id`; `registry.get("-")` ergänzt `details.fleet = true` (Grund unverändert `invalid_router_id`). | A |
| 107 | `CoreEvent` (B8, §12.1): neue optionale Felder `client_ref` (`cli_<16 hex>`, `CLIENT_REF_PATTERN`), `confidence` (0..1, `float`), `classification` (`EVENT_CLASSIFICATION_PATTERN`), `incident_ref`, `radio_id` (`check_token`); `EVENT_REF_FIELDS`; `emit(...)` (Audit-Log, API, Protokoll) nimmt sie als Schlüsselwortargumente. Standard `None`, in `to_dict`/`from_dict`, nicht im Dedup-Bereich, keine Store-Version. Bus-Payload hat fünf neue Schlüssel. | A |

### 19.2 Die 14 Punkte von `config-manager` (Abgleich zu `5c9d248`)

| # | Punkt | Entscheidung | Grund |
|---|---|---|---|
| 1 | Dedup gegen „neueste Version“ unklar; wer sperrt | **übernommen** | Regeln 7.4 (gleicher `backup_type`, `ok`/`partial`, nicht `invalid`/`corrupt`/`missing`, `failed` nie, nur `scheduled`/`drift`). Sperren: Router-Lock der API plus interne Index-Sperre des Store. |
| 2 | Autorisierung läuft in der Flotten-Warteschlange ab | **übernommen** | Core besitzt die Warteschlange: Platz → Lock → autorisieren → holen → ablegen (Abschnitt 8). |
| 3 | Wie wird `known` zur neuen Basis | **übernommen** | Core holt (oder dedupliziert) eine Version mit `reason=drift`; `DriftAck.version_id` hält sie; Basisregel `known_ack`. |
| 4 | Fehlende Event-Typen; wer sendet `drift_detected`; Core-Typen von Modulen | **geändert** | Statt `configuration.backup_integrity_failed` heißt der Typ `configuration.integrity_failed`; dazu `change_critical`/`change_unknown` als eigene Typen statt Zähler an `drift_detected`. Der Core sendet alle aus Provider-Ergebnissen; Module dürfen keine Core-Typen senden. Kein Event für „Größenlimit trotz Aufbewahrung“ (siehe 10). |
| 5 | Installations-Schlüssel und Router im Provider | **geändert** | Statt Konstruktor-Callable und optionalem `router` in `async_compare`: `ProviderContext` (Schlüssel, Leser, Registry) in jeder Methode, `base_router`/`other_router` als Pflicht-Schlüsselwortargumente. |
| 6 | Format `ConfigSnapshot.configs` | **übernommen** | `configs` ist opak; `uci_normalized` v1 mit `sections`/`options`/`order` ist das dokumentierte Format (10.3). |
| 7 | Hash-Gleichheit | **übernommen** | `uci_hash` und `content_hash` kommen immer vom Provider; `ConfigSnapshot.checksum` ist nur Bindungsprüfsumme. |
| 8 | Teilerfolg „Archiv fehlgeschlagen, UCI ok“ | **übernommen** | `backup_type=partial`, `status=partial`, `error_class` des Archivs; die `error_class`-Regel wird erzwungen. |
| 9 | `warnings` gehen verloren | **geändert** | `CollectedVersion.warnings` entfällt; Warnungen sind Maschinencodes in `VersionMeta.warnings` und landen in `BackupRecord.warnings` (nicht im `uci`-Artefakt). |
| 10 | Wer räumt bei `StorageFullError` flottenweit auf | **geändert** | Niemand löscht über Router hinweg. Der Core wendet die Aufbewahrung des betroffenen Routers an und versucht einmal neu, sonst `backup_failed` mit `error_class=storage_full`. Kein neuer Event-Typ. |
| 11 | `config.restore=unavailable` melden | **übernommen** | `async_probe` meldet alle `config.*`, über die der Provider entscheidet, auch nicht verfügbare. |
| 12 | Fehlerklasse `invalid` ohne Ausnahme | **abgelehnt** (keine neue Klasse) | `ProviderError(error_class=ErrorClass.INVALID)` ist der vorgesehene Weg und so dokumentiert. |
| 13 | Guard `backup` verlangt keinen Admin | **geändert** | Der Guard lehnt jetzt jeden Nicht-Admin-Benutzer für jede mutating/critical Aktion ab, auch `backup`; die eigene Admin-Prüfung der Route ist nicht mehr nötig. Automationen, Module und System dürfen `backup` weiter. |
| 14 | Installations-Schlüssel entsteht still neu | **übernommen** | Zustand `lost`, `InstallationKeyLostError`, einmal `core.installation_key_lost`, Repair-Issue, Digests `not_comparable`; neuer Schlüssel nur über `installation_key_reset`, danach Re-Baseline. |
| – | Welche Maskierung bleibt / Import aus `config_const` | **abgelehnt** | Es gibt eine Implementierung in `core_masking` (Obermenge aus beiden). `config-manager` importiert sie; `core_masking` importiert kein `config_*`-Modul. |

Gemessen an `5c9d248` (Test vor der Änderung): von den 14 gemeldeten Namen (`r0kh`, `r1kh`,
`pincode`, `param_enc`, `param_opt`, `update_url`, `askpass`, `sessionid`, `session_id`,
`authorization`, `proxy_authorization`, `cookie`, `set_cookie`, `auth_user_pass`) liefen
**13** unmaskiert durch; nur `auth_user_pass` wurde über das Wort `auth` erkannt. Nach der
Wortliste des Reviews waren es noch 7 (`r0kh`, `r1kh`, `pincode`, `param_enc`, `param_opt`,
`update_url`, `askpass`). Jetzt werden alle 14 maskiert (`tests/test_core_masking.py`).

### 19.3 Entschieden

- `protect` wirkt sofort, nur Admin-Benutzer.
- Eine `failed`-Version ohne Artefakte bekommt einen Indexeintrag.
- Ein Modul darf `async_put_version` mit einer eigenen `backup`-Autorisierung nutzen.
- `acl_deploy` ist kritisch, nur Admin-Benutzer, gebunden an `router_id` und
  ACL-Prüfsumme.
- `installation_key_reset` ist flottenweit (`router_id = "-"`) und an die
  `installation_key_id` der neuesten Version gebunden; ein späterer zweiter Verlust braucht
  eine neue Freigabe.
- Selbstfreigabe durch denselben Admin ist erlaubt (kein Vier-Augen-Prinzip).
- Modul-Event-Typen liegen unter einem eigenen Präfix außerhalb der Core-Namensräume.
- Die 14 Punkte aus 19.2.
- Teil 2: `FLEET_BACKUP_CONCURRENCY = 1`; die Aufbewahrung läuft nach jedem Ablegen; der
  Standard ist GFS 7/4/6.
- Teil 2: Ein fehlgeschlagener Versuch mit einer Autorisierung (falscher Router, falsche
  Aktion) verbraucht sie.
- Teil 2: Ein Schlüsselwechsel mit gleichzeitiger echter Änderung ist ein Drift; ein
  Re-Baseline gibt es nur bei vollständiger Entwarnung.
- 1.44.0: Erster SSH-Kontakt ist kein stilles TOFU, sondern `pending` bis
  `ssh_pin_confirm`; eine Abweichung lehnt immer ab und wird auditiert.
- 1.44.0: Ist `config_backup_enabled` aus, meldet `config.*` `disabled`, auch ohne
  Provider (die Option gewinnt vor `no_provider`).
- 1.44.0: Der Schalter `config_backup_enabled` erscheint im Options-Flow nur mit
  installiertem Provider oder solange er an ist; ohne Provider bleibt das Formular wie in
  1.43. Er wird direkt angewandt, ohne Update-Listener und ohne Neuladen (ein Listener
  kollidierte mit `async_update_reload_and_abort` der Reauth-Schritte; HA-Blog
  2026-05-07, ab 2026.12 ein Fehler).
- 1.44.0: Die Capability-Ansicht der Registry darf bis zum nächsten Poll nachlaufen.

### 19.4 Offene Fragen an den Nutzer

1. **Ist ein `pre_restore`-Backup vor jedem Restore Pflicht?** Betrifft erst die
   Restore-Phase; in Phase 1 gibt es keinen Restore.
2. **Dürfen tokenbasierte Clients freigeben?** Ein HA-`Context` trägt nur `user_id`. Über
   HTTP/WebSocket ist der Refresh-Token-Typ bekannt (`normal`, `system`,
   `long_lived_access_token`); bei Service-Aufrufen ist er nicht unterscheidbar. Stand des
   Vertrags: jeder aktive, nicht systemgenerierte Admin-Benutzer darf freigeben, egal über
   welchen Token. Eine Einschränkung auf `normal` ginge nur für HTTP/WS-Wege.
3. ~~Soll GFS manuelle und `pre_*`-Versionen vom Ausdünnen ausnehmen?~~ **Entschieden
   (1.44.0): ja**, GFS dünnt sie nie aus; das Größenlimit nennt sie, wenn es sie entfernt
   (7.5, #71).
4. ~~Braucht der Export `config.export`?~~ **Entschieden (1.44.0): nein**, der Export
   bleibt nur an die Freigabe gebunden (er liest gespeicherte Bytes, kein Router-Aufruf).
5. ~~Soll `async_archive_router` beim Entfernen eines Eintrags automatisch laufen?~~
   **Entschieden (1.44.0): ja**, nach `removed/<router_id>/`, auditiert (#73). Offen:
   eine spätere Adoption holt die Versionen nicht zurück.
6. ~~Soll der Core für den Dedup zusätzlich seine eigenen sha256 vergleichen?~~
   **Entschieden (1.44.0): ja** (7.4, #72).
