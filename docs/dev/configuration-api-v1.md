# Configuration API v1 – Vertrag

<!-- Ablage: docs/dev/configuration-api-v1.md · Plan: docs/plans/2026-11-17-enterprise-core.md
     Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens in diesem Dokument. -->

Dieser Vertrag beschreibt, wie Module (zuerst `config-manager`, später Security
Intelligence, Network Intelligence, Time Machine, Firmware Lifecycle, Self-Healing) mit dem
Enterprise Core sprechen. Code, Docstrings und Bezeichner sind englisch, dieser Text deutsch.

## 0. Status: was es als Code gibt und was später kommt

| Teil | Modul | Stand |
|---|---|---|
| Konstanten, Enums, Dataclasses, Helfer, `WriteAuthorization`, Protocols | `core_models.py` | **Code, getestet** |
| `ErrorClass`, `ConfigApiError` + 24 Unterklassen | `core_errors.py` | **Code, getestet** |
| `mask_secrets`, `is_secret_key`, `mask_value` | `core_masking.py` | **Code, getestet** |
| `async_get_configuration_api(hass, version=1)` | `config_api.py` | später |
| `ActionGuard` (Implementierung von `ActionGuardProtocol`) | `core_guard.py` | später |
| `VersionStore` (Implementierung von `VersionStoreProtocol`) | `core_versions.py` | später |
| `RouterRegistry`, Identität, Capability-Ableitung | `router_registry.py`, `router_identity.py`, `capabilities.py` | später |
| Audit-Ring, Bus-Event, Dedup | `core_audit.py` | später |
| Lebenszyklus, Verdrahtung in `__init__.py`, Option `config_backup_enabled` | `enterprise_core.py`, `config_flow.py` | später |
| Gestufte ACL, TOFU-SSH-Pinning, Panel-Container „Enterprise“ | Abschnitt 18 | später, nur dokumentiert |

Alles, was „später“ ist, steht hier als **Signatur**. Die Signaturen sind als Protocols in
`core_models.py` festgeschrieben; ein Provider oder Modul kann heute schon dagegen
programmieren und mit eigenen Test-Doubles testen.

Import für Module:

```python
from custom_components.openwrt_router.core_models import (
    Actor, BackupReason, Capability, ConfigRef, GuardedAction, ...
)
from custom_components.openwrt_router.core_errors import (
    ConfigApiError, ErrorClass, CapabilityUnavailableError, ...
)
```

## 1. Begriffe

| Begriff | Bedeutung |
|---|---|
| Version = Backup | Eine gesicherte Konfiguration eines Routers. Kennung `backup_id` (`bkp_<32 hex>`), Alias `version_id`. Typ `BackupRecord`, Alias `VersionRecord`. |
| Artefakt | Eine Datei einer Version: `archive` (sysupgrade-Archiv), `uci` (normalisierter UCI-Snapshot), `inventory` (Paketliste, Board-Daten). |
| Index | Metadaten aller Versionen im Store `openwrt_router.config_catalog`. Gehört dem Core. |
| Provider | Das eine Modul, das Artefakte vom Router holt und analysiert (`config-manager`). |
| Kritische Aktion | Braucht Antrag + Freigabe durch einen Admin-Benutzer. **Kritisch heißt nicht „schreibt“**: Export liest nur, ist aber kritisch, weil er alle Geheimnisse im Klartext herausgibt. |
| Bindungsprüfsumme | Prüfsumme, an die eine Freigabe/Autorisierung gebunden ist (Abschnitt 6.4). |

## 2. Versionierung und Zugriff

```python
CONFIGURATION_API_VERSION = 1
CONFIGURATION_API_MIN_VERSION = 1
SUPPORTED_API_VERSIONS = (1,)
PROVIDER_API_VERSION = 1
BACKUP_METADATA_VERSION = 1

async def async_get_configuration_api(
    hass: HomeAssistant, version: int = 1
) -> ConfigurationApiProtocol: ...          # später, config_api.py

def ensure_supported_api_version(version: int) -> int: ...   # Code
```

- Innerhalb v1 nur **additive** Änderungen: neue optionale Felder mit Standardwert, neue
  Enum-Werte, neue Event-Typen, neue Capability-Namen, neue Methoden. Alle Dataclasses sind
  `kw_only`, neue Felder verschieben also keine Positionsargumente.
- Ein Konsument muss unbekannte Enum-Werte in `str`-Feldern (`CoreEvent.type`,
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
| `cor_` | Korrelations-ID | `new_id`, frei vom Aufrufer |

`ROUTER_ID_NAMESPACE = 5fc97c09-217a-4ccb-af32-d954b049fecf` ändert sich nie.
`is_valid_id(value, prefix)` prüft das Format (`<prefix><32 hex klein>`).

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

`RouterRecord`:

| Feld | Typ | Bedeutung |
|---|---|---|
| `identity` | `RouterIdentity` | ID, Eintrag, Hostname, Host/Port, MACs, Modell, Board, Firmware, Rolle, APs, Interfaces, `fingerprint`, `status` |
| `state` | `RecordState` | `active` / `orphaned` |
| `connection` | `ConnectionInfo` | host, port, protocol, transport (`ubus`/`ssh_fallback`/`unknown`), nie Zugangsdaten |
| `reachability` | `RouterReachability` | `online`/`offline`/`unknown`, letzte Erfolgs-/Versuchszeit |
| `firmware` | `FirmwareInfo` | distribution, version, revision, target, kernel, architecture, board_name, package_manager |
| `capabilities` | `Mapping[str, CapabilityStatus]` | Abschnitt 5 |
| `registered_at`, `orphaned_at`, `adopted_at` | `datetime \| None` | UTC |
| `previous_entry_ids` | `tuple[str, ...]` | Einträge vor einer Adoption |
| `router_id`, `entry_id` | Eigenschaften | `entry_id` ist `None`, solange verwaist |

`IdentityStatus`: `unverified`, `confirmed`, `changed` (Hardwaretausch vermutet),
`duplicate_suspected`. IP- oder Hostname-Wechsel ändert die ID nie; nichts wird automatisch
zusammengeführt.

```python
record = api.registry.get_by_entry(entry.entry_id)
if record.identity.status is IdentityStatus.DUPLICATE_SUSPECTED:
    return  # nichts automatisch tun

for cand in api.registry.adoption_candidates(new_entry_id):
    _LOGGER.debug("candidate %s, %d shared MACs", cand.router_id, len(cand.matched_macs))
# nur auf ausdrücklichen Befehl eines Admin-Benutzers:
await api.registry.async_adopt(new_entry_id, cand.router_id, actor=admin_actor)
```

## 5. Capabilities

`CapabilityStatus`:

| Feld | Typ | Bedeutung |
|---|---|---|
| `capability` | `str` | Wert aus `Capability` oder Modulname unter registriertem Präfix |
| `state` | `CapabilityState` | `available` / `unavailable` / `unknown` |
| `reason` | `str` | `CapabilityReason` (`ok`, `no_data_yet`, `not_checked`, `not_probed`, `not_detected`, `permission_denied`, `transport_unsupported`, `unsupported_firmware`, `router_offline`, `entry_not_loaded`, `disabled`, `no_provider`, `provider_declined`) oder `provider:<code>` |
| `source` | `str` | z. B. `features.has_iwinfo`, `api.uses_ssh_fallback`, `probe:config_manager` |
| `detected_at` | `datetime` | UTC |
| `reason_text` | `str \| None` | Klartext für die UI |
| `required_permissions` | `tuple[str, ...]` | fehlende rpcd-Rechte, z. B. `cgi-io:backup` |
| `detail` | `Mapping[str, Any]` | Einzelergebnisse, z. B. `{"wireless": True, "firewall": False}` für `config.uci_read`; in `to_dict()` maskiert |
| `available` | Eigenschaft | `state is AVAILABLE` |

Namen (alle mit Punkt):

| Gruppe | Namen | Quelle |
|---|---|---|
| Transport | `transport.ubus`, `transport.ssh` | `api.uses_ssh_fallback` |
| Daten | `data.system_board`, `data.wireless`, `data.hostapd_clients`, `data.dhcp_leases`, `data.lldp`, `data.logs`, `data.iwinfo`, `data.services`, `data.uci` | `coordinator.data`, `FEATURE_CAPABILITIES` |
| Stream, Pakete | `stream.ubus`, `pkg.apk`, `pkg.opkg` | `coordinator.data` |
| Konfiguration (Provider) | `config.capture`, `config.backup`, `config.validate`, `config.diff`, `config.drift`, `config.restore_dry_run`, `config.restore`, `config.export` | `provider.supported(router)` |
| Konfiguration (Router-Probe) | `config.cgi_backup`, `config.ssh_root`, `config.uci_read`, `config.packagelist` | `provider.async_probe(conn)` |

Regeln:

- Proben (`PROBED_CAPABILITIES`) laufen beim Setup, nach einer ACL-Neuverteilung und nach
  einem Firmware-Wechsel. **Nie im Poll.** Vor der ersten Probe: `unknown`/`not_probed`.
- Ohne Provider: alle `config.*` `unavailable`/`no_provider`.
- Option `config_backup_enabled` aus (`OPTION_CONFIG_BACKUP_ENABLED`): alle `config.*`
  `unavailable`/`disabled`, es wird nicht geprobt.
- `config.restore` ist in Phase 1 `unavailable`, bis der Provider es meldet (Abschnitt 16).
- Reservierte Namensräume `security.`, `diag.`, `log.` (`RESERVED_NAMESPACES`): der Core
  vergibt dort selbst nichts. Module registrieren ein Präfix (Abschnitt 12.4) und melden
  darunter eigene Namen.

```python
if not api.registry.has_capability(router_id, Capability.CONFIG_UCI_READ):
    return
status = api.registry.capabilities(router_id)[Capability.CONFIG_UCI_READ]
readable = [name for name, ok in status.detail.items() if ok]
```

```python
# Provider-Seite: Probe (nur lesend, nur über conn.api)
async def async_probe(self, conn: RouterConnection) -> Mapping[str, CapabilityStatus]:
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
    }
```

## 6. Guard: Klassen, Entscheidung, Autorisierung

### 6.1 Aktionen

| Aktion (`GuardedAction`) | Klasse | Wer darf | Bindung (`checksum`) |
|---|---|---|---|
| `backup` | mutating | Benutzer, Automation, Modul, System | keine |
| `protect` | mutating | nur Admin-Benutzer | `binding_checksum(version_id, protected)` |
| `drift_ack` | mutating | nur Admin-Benutzer | `binding_checksum(router_id, drift_id, state)` |
| `export` | **critical** | nur Admin-Benutzer (Antrag und Freigabe) | `binding_checksum(version_id)` |
| `delete` | **critical** | Antrag: Benutzer/Modul; Freigabe: Admin-Benutzer | `binding_checksum(*sorted(version_ids))` |
| `prune` | mutating | nur System/Modul (Aufbewahrung) | `binding_checksum(*sorted(version_ids))` |
| `restore` | **critical** | Antrag: Benutzer/Modul; Freigabe: Admin-Benutzer | `plan.checksum` |
| `adopt` | mutating | nur Admin-Benutzer | `binding_checksum(entry_id, orphan_router_id)` |
| `acl_deploy` | **critical** | Freigabe: Admin-Benutzer | später festgelegt |
| `<modul>.<aktion>` | bei `register_action` | bei `register_action` | frei |

Tabellen im Code: `ACTION_CLASSES`, `ADMIN_USER_ONLY_ACTIONS`, `SYSTEM_ONLY_ACTIONS`.

- **read:** keine Autorisierung. Auditiert werden nur Dry Run und Kompatibilitätsprüfung
  (`restore_checked`); Lesen der Live-Konfiguration, Listen und Vergleiche nicht (zu häufig).
- **mutating:** sofortige Entscheidung `approved` oder `denied`.
- **critical:** erster Aufruf ⇒ `pending` + `ApprovalRequest`; ein Admin-Benutzer gibt frei
  (`approve`) oder lehnt ab (`reject`); erst ein zweiter `authorize(..., approval_id=…)`
  liefert `approved` + `WriteAuthorization`. Antrag gilt `APPROVAL_TTL` (15 min), eine
  Freigabe erlaubt **genau eine** Ausführung (beim Export: einen Download).
- `prune` löscht nie eine `protected`-Version: solche IDs werden übersprungen und fehlen im
  Rückgabewert.

### 6.2 Entscheidung

```python
class ActionGuardProtocol(Protocol):
    def authorize(
        self, action: str, router_id: str, actor: Actor, *,
        subject_id: str | None = None, checksum: str | None = None,
        approval_id: str | None = None, correlation_id: str | None = None,
    ) -> AuthorizationDecision: ...
    def approve(self, approval_id: str, *, actor: Actor) -> ApprovalRequest: ...
    def reject(self, approval_id: str, *, actor: Actor, reason: str | None = None) -> ApprovalRequest: ...
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
| `reason` | `str \| None` | bei `denied`, z. B. `not_admin`, `system_only`, `unknown_action`, `approval_rejected` |
| `approved` | Eigenschaft | `state is APPROVED` |

`ApprovalRequest`: `approval_id`, `action`, `router_id`, `subject_id` (Plan, Version oder
Listenschlüssel), `checksum`, `requested_by`, `requested_at`, `expires_at`, `status`
(`pending`/`approved`/`rejected`/`expired`/`used`), `decided_by`, `decided_at`, `reason`,
`correlation_id`.

### 6.3 WriteAuthorization

- Nur der Guard prägt sie (`_mint_write_authorization`, privater Sentinel). Direkter Aufruf
  von `WriteAuthorization(...)` ⇒ `TypeError`.
- Gebunden an `action`, `router_id` und (optional) `checksum`; gültig
  `WRITE_AUTHORIZATION_TTL` (5 min).
- Wer handelt, ruft **unmittelbar vorher** `consume(action=…, router_id=…, checksum=…)`.
  Jeder Versuch verbraucht sie, auch ein fehlgeschlagener (fail closed). Fehler:
  `AuthorizationError` mit `details["reason"]` ∈ `already_used`, `expired`,
  `action_mismatch`, `router_mismatch`, `checksum_mismatch`.

### 6.4 Bindungsprüfsumme

`binding_checksum(*parts)` = sha256 über die kanonische JSON-Liste der Teile. Reihenfolge
zählt. Eine Freigabe für Version A kann so nie Version B exportieren, eine Freigabe für
„schützen“ nie „Schutz aufheben“.

```python
# Modul: Backup vor einer eigenen Aktion (mutating)
decision = api.guard.authorize(GuardedAction.BACKUP, router_id, Actor.for_module("firmware"))
if not decision.approved:
    raise AuthorizationError(decision.reason or "denied", router_id=router_id)

# Erweiterungsaktion registrieren (einmal beim Setup des Moduls)
api.guard.register_action("self_healing.restart_service", ActionClass.CRITICAL,
                          module="self_healing")
```

## 7. Versionsspeicher (`VersionStoreProtocol`)

### 7.1 Ablage

| Eigenschaft | Wert |
|---|---|
| Wurzel | `hass.config.path(*CONFIG_BACKUP_PATH, <router_id>)` = `<config>/openwrt_router/config_backups/<router_id>/` (nicht unter `www`) |
| Rechte | Ordner `0o700`, Dateien `0o600` (`STORAGE_DIR_MODE`, `STORAGE_FILE_MODE`) |
| Schreiben | in `<name>.partial`, `fsync`, umbenennen; **Indexeintrag zuletzt** |
| I/O | jede Datei-Operation im Executor |
| Format | `StorageRef.storage_format = "plain-v1"` (Klartext, keine eigene Verschlüsselung), `encrypted = False` |
| Grenzen | 50 MiB je Router, 250 MiB gesamt (`DEFAULT_*_STORAGE_LIMIT_BYTES`) |
| Router entfernt | Ordner nach `removed/<router_id>/`; nie automatisch gelöscht |

### 7.2 Sweep beim Start (`async_sweep() -> SweepReport`)

1. `*.partial` löschen (`partial_deleted`).
2. Dateien ohne Indexeintrag, älter als `ORPHAN_SWEEP_MIN_AGE` (1 h), nach `orphaned/`
   verschieben (`orphaned_moved`).
3. Indexeinträge ohne Datei: `validation.status = missing` (`marked_missing`).
4. Event `configuration.storage_swept`, nur wenn ein Zähler > 0 ist.

### 7.3 Operationen

```python
class VersionStoreProtocol(Protocol):
    async def async_put_version(self, router_id: str,
        artifacts: Mapping[str, ArtifactPayload], meta: VersionMeta, *,
        authorization: WriteAuthorization) -> PutVersionResult: ...
    async def async_list_versions(self, router_id: str | None = None, *,
        since: datetime | None = None, limit: int = 50) -> tuple[BackupRecord, ...]: ...
    async def async_get_version(self, version_id: str) -> BackupRecord: ...
    async def async_read_artifact(self, storage_ref: StorageRef) -> bytes: ...
    async def async_delete_versions(self, version_ids: Sequence[str], *,
        authorization: WriteAuthorization) -> tuple[str, ...]: ...
    async def async_set_protected(self, version_id: str, protected: bool, *,
        authorization: WriteAuthorization) -> BackupRecord: ...
    async def async_set_validation(self, version_id: str,
        validation: ValidationInfo) -> BackupRecord: ...
    async def async_put_drift_ack(self, ack: DriftAck, *,
        authorization: WriteAuthorization) -> DriftAck: ...
    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]: ...
    async def async_sweep(self) -> SweepReport: ...
    async def async_archive_router(self, router_id: str) -> None: ...
    def usage_bytes(self, router_id: str | None = None) -> int: ...
```

| Operation | Autorisierung | Verhalten | Fehler |
|---|---|---|---|
| `async_put_version` | `backup` | prüft sha256 jedes `ArtifactPayload`, Grenzen, schreibt atomar. **Dedup:** gleicher `content_hash` (oder ohne Archiv gleicher `uci_hash`) wie die neueste Version des Routers ⇒ nur `last_seen_at` setzen, `created=False`, keine Dateien | `BackupIntegrityError`, `ArtifactTooLargeError`, `StorageFullError`, `StorageError` |
| `async_list_versions` | – | neueste zuerst, `limit` ≤ `MAX_LIST_LIMIT` (500) | – |
| `async_get_version` | – | | `BackupNotFoundError` |
| `async_read_artifact` | – | prüft `storage_format` und sha256 | `UnsupportedStorageFormatError`, `BackupIntegrityError`, `StorageError` |
| `async_delete_versions` | `delete` oder `prune` | Rückgabe: tatsächlich gelöschte IDs; `prune` überspringt `protected` | `BackupNotFoundError`, `StorageError` |
| `async_set_protected` | `protect` | | `BackupNotFoundError` |
| `async_set_validation` | – (core-intern) | speichert Prüfergebnis | `BackupNotFoundError` |
| `async_put_drift_ack` | `drift_ack` | ersetzt eine frühere Bestätigung derselben `drift_id` | – |
| `async_archive_router` | – (Lebenszyklus) | verschiebt nach `removed/` | `StorageError` |

```python
# Modul (z. B. Zeitplan von config-manager) legt eine Version direkt ab
decision = api.guard.authorize(GuardedAction.BACKUP, router_id, Actor.for_module("config_manager"))
collected = await provider.async_collect(conn, request)
result = await api.versions.async_put_version(
    router_id, collected.artifacts, collected.meta, authorization=decision.authorization
)
if not result.created:
    _LOGGER.debug("unchanged since %s", result.record.created_at)
```

## 8. Operationen der Configuration API

`ConfigurationApiProtocol` (Objekt aus `async_get_configuration_api`). Alle Methoden mit
Router-Bezug werfen `RouterNotFoundError`, wenn die ID unbekannt ist.

| Methode | Klasse | Rückgabe | Wichtige Fehler |
|---|---|---|---|
| `api_version`, `registry`, `guard`, `versions`, `provider_id` | – | Eigenschaften | – |
| `register_provider(provider)` | – | Abmelde-Callback | `ProviderConflictError`, `ApiVersionError` (Provider-Version) |
| `async_get_installation_key()` | – | `bytes` (32) | – |
| `async_capture(router_id, *, actor, configs=None)` | read | `ConfigSnapshot` | `CapabilityUnavailableError`, `RouterUnavailableError`, `ProviderError` |
| `async_list_backups(router_id=None, *, since=None, limit=50)` | read | `tuple[BackupRecord, ...]` | – |
| `async_get_backup(backup_id)` | read | `BackupRecord` | `BackupNotFoundError` |
| `async_validate_backup(backup_id)` | read | `BackupRecord` (mit neuer `validation`) | `BackupNotFoundError` |
| `async_compare(base, other, *, actor)` | read | `ConfigDiff` | `BackupNotFoundError`, `CapabilityUnavailableError` |
| `async_detect_drift(router_id, *, actor, baseline_backup_id=None)` | read | `DriftReport` | `BackupNotFoundError` (keine Basis), `RouterUnavailableError` |
| `async_check_restore_compatibility(backup_id, target_router_id, *, actor)` | read, auditiert | `CompatibilityCheck` | `BackupNotFoundError` |
| `async_prepare_restore(backup_id, target_router_id, *, actor)` | read, auditiert (Dry Run) | `RestorePlan` | `CapabilityUnavailableError` (`config.restore_dry_run`) |
| `async_create_backup(router_id, *, reason, actor, backup_type=None, note=None, links=None)` | mutating | `PutVersionResult` | `AuthorizationError`, `OperationInProgressError`, `RouterUnavailableError`, `OperationTimeoutError`, `StorageFullError`, … |
| `async_set_protected(backup_id, protected, *, actor)` | mutating, Admin | `BackupRecord` | `AuthorizationError` |
| `async_acknowledge_drift(router_id, drift_id, *, state, actor, note=None)` | mutating, Admin | `DriftAck` | `AuthorizationError` |
| `async_list_drift_acks(router_id)` | read | `tuple[DriftAck, ...]` | – |
| `async_request_export(backup_id, *, actor)` | critical, Admin | `ApprovalRequest` | `AuthorizationError` |
| `async_export_backup(approval_id, *, actor)` | critical | `ExportHandle` | `ApprovalRequiredError`, `ApprovalInvalidError` |
| `async_request_deletion(backup_ids, *, actor)` | critical | `ApprovalRequest` | `BackupNotFoundError` |
| `async_delete_backups(approval_id, *, actor)` | critical | gelöschte IDs | `ApprovalInvalidError` |
| `async_request_restore(plan, *, actor)` | critical | `ApprovalRequest` | **Phase 1:** `CapabilityUnavailableError` |
| `async_approve(approval_id, *, actor)` / `async_reject(...)` | Admin | `ApprovalRequest` | `AuthorizationError`, `ApprovalInvalidError` |
| `async_execute_restore(approval_id, *, actor)` | critical | `RestoreResult` | **Phase 1:** `CapabilityUnavailableError` |
| `get_approval`, `pending_approvals` | read | | `ApprovalInvalidError` |
| `events(...)`, `subscribe(listener)`, `register_event_prefix(prefix, *, module)`, `emit(...)` | – | Abschnitt 12 | – |

Nebenläufigkeit: Lesen läuft parallel. Jede mutating/critical Operation hält den Lock des
Routers; wer ihn nicht innerhalb von `ROUTER_LOCK_TIMEOUT` bekommt ⇒
`OperationInProgressError` (retryable).

Ablauf `async_create_backup`:

1. `guard.authorize(backup, …)` (Audit: manuelles Backup bei `reason=manual`).
2. Lock des Routers.
3. `provider.async_collect(conn, CollectRequest(...))`.
4. `versions.async_put_version(..., authorization=...)`.
5. Event `configuration.backup_created` nur bei `created=True`; bei Fehler
   `configuration.backup_failed` (Dedup `(router_id, error_class)`, 24 h Cooldown); erster
   Erfolg danach `configuration.backup_recovered`.

```python
actor = await async_actor_from_context(hass, call.context, module="config_manager")
result = await api.async_create_backup(router_id, reason=BackupReason.MANUAL, actor=actor,
                                       note="before VLAN change")
```

Export (kritisch, liest nur):

```python
req = await api.async_request_export(backup_id, actor=admin)       # pending
await api.async_approve(req.approval_id, actor=admin)              # Admin bestätigt
handle = await api.async_export_backup(req.approval_id, actor=admin)
data = await handle.reader()       # ein Download; zweiter Aufruf von async_export_backup
                                   # mit derselben approval_id ⇒ ApprovalInvalidError
```

Löschen:

```python
req = await api.async_request_deletion([bkp_a, bkp_b], actor=actor)
await api.async_approve(req.approval_id, actor=admin)
deleted = await api.async_delete_backups(req.approval_id, actor=actor)
```

## 9. Datenmodell

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
| `content_hash` | `str \| None` (64 hex) | | Dedup-Fingerprint der Archivinhalte |
| `uci_hash` | `str \| None` (64 hex) | | Inhalts-Hash des UCI-Snapshots |
| `openwrt_version`, `hardware_model`, `board_name` | `str \| None` | | Herkunft |
| `compatibility` | `CompatibilityInfo \| None` | | Format, Version, Target, Board, Modell, Architektur, Paketmanager |
| `artifacts` | `Mapping[str, ArtifactRef]` | | Schlüssel `archive` / `uci` / `inventory` |
| `validation` | `ValidationInfo` | | `unverified`/`valid`/`invalid`/`corrupt`/`missing`, Zeit, Text |
| `links` | `BackupLinks` | | `incident_id`, `change_id`, `correlation_id`, `parent_backup_id` |
| `created_by` | `Actor` | ja | wer |
| `contains_secrets` | `bool` | | Standard `True` |
| `protected` | `bool` | | vor `prune` geschützt |
| `note` | `str \| None` | | ≤ `NOTE_MAX_LENGTH` (500) |
| `sha256` | Eigenschaft | | sha256 des Archivs oder `None` |
| `size_bytes` | Eigenschaft | | Summe aller Artefakte |

`to_dict()` enthält zusätzlich `sha256` und `size_bytes`; `from_dict()` ignoriert sie und
wirft bei jedem Fehler `BackupMetadataError` (ältere Formate laufen durch
`migrate_backup_metadata`, neuere werden abgelehnt).

### 9.2 Artefakte

| Typ | Felder |
|---|---|
| `StorageRef` | `locator` (relativ zum Router-Ordner, für Module opak), `kind="file"`, `storage_format="plain-v1"`, `encrypted=False` |
| `ArtifactRef` | `storage`, `sha256` (64 hex), `size_bytes` (≥ 0), `content_type` |
| `ArtifactPayload` | `data: bytes` (nicht in `repr`), `sha256`, `content_type`; Eigenschaft `size_bytes` |
| `VersionMeta` | `backup_type`, `reason`, `created_by`, `status`, `error_class`, `fetch_method`, `content_hash`, `uci_hash`, `openwrt_version`, `hardware_model`, `board_name`, `compatibility`, `contains_secrets`, `note`, `links`, `correlation_id` |
| `PutVersionResult` | `record`, `created` |
| `SweepReport` | `checked_at`, `partial_deleted`, `orphaned_moved`, `marked_missing` |
| `CollectRequest` | `router_id`, `backup_type`, `reason`, `actor`, `correlation_id`, `note`, `links`, `fetch_method` |
| `CollectedVersion` | `artifacts: Mapping[str, ArtifactPayload]`, `meta: VersionMeta`, `warnings` |

### 9.3 Analyse

| Typ | Felder |
|---|---|
| `ConfigSnapshot` | `router_id`, `captured_at`, `configs[config][section][option]`, `openwrt_version`, `board_name`, `format`, `format_version`, `contains_secrets`; Eigenschaft `checksum` (unmaskiert) |
| `ConfigRef` | genau eins von `backup_id` / `router_id` (live); `ConfigRef.backup(id)`, `ConfigRef.live(router_id)` |
| `ConfigChange` | `kind` (`added`/`removed`/`modified`/`reordered`), `config`, `section`, `option`, `section_type`, `before`, `after`, `area`, `risk`; Eigenschaft `secret` |
| `ConfigDiff` | `base`, `other`, `compared_at`, `changes`, `truncated`; `to_dict()` mit `counts` |
| `DriftReport` | `router_id`, `baseline_backup_id`, `checked_at`, `drifted`, `diff`, `drift_id`, `ack_state`, `ignored_paths` |
| `CompatibilityCheck` | `compatible`, `issues` (`code`, `message`, `blocking`) |
| `RestorePlan` | `plan_id`, `backup_id`, Quell-/Zielrouter, `provider_id`, `created_at`, `compatibility`, `steps`, `diff`, `live_checksum`, `requires_reboot`, `warnings`, `instructions`; Eigenschaft `checksum` (unmaskiert) |
| `RestoreResult` | `approval_id`, `plan_id`, `router_id`, `status`, Zeiten, `pre_restore_backup_id`, `applied_steps`, `failed_step`, `message`, `reboot_required`, `rolled_back`, `correlation_id` |
| `ExportHandle` | `backup_id`, `artifact`, `filename`, `content_type`, `size_bytes`, `sha256`, `contains_secrets`, `reader()`, `expires_at` |

### 9.4 `Actor`

`kind` (`user`/`automation`/`system`/`module`), `user_id`, `context_id`,
`parent_context_id`, `module`, `is_admin` (nur `user` kann Admin sein; sonst auf `False`
gesetzt). `Actor.system()`, `Actor.for_module(name)`,
`await async_actor_from_context(hass, context, module=None)`.

## 10. Provider-Schnittstelle (`ConfigBackupProvider`)

```python
@runtime_checkable
class ConfigBackupProvider(Protocol):
    provider_id: str                      # Eigenschaft, z. B. "config_manager"
    provider_api_version: int             # 1
    def supported(self, router: RouterRecord) -> bool: ...
    async def async_probe(self, conn: RouterConnection) -> Mapping[str, CapabilityStatus]: ...
    async def async_capture(self, conn, request: CaptureRequest) -> ConfigSnapshot: ...
    async def async_collect(self, conn, request: CollectRequest) -> CollectedVersion: ...
    async def async_validate(self, record: BackupRecord, read: ArtifactReader) -> ValidationInfo: ...
    async def async_compare(self, base: ConfigSource, other: ConfigSource,
                            read: ArtifactReader) -> ConfigDiff: ...
    async def async_detect_drift(self, conn, baseline: BackupRecord, read: ArtifactReader,
                                 acks: Sequence[DriftAck]) -> DriftReport: ...
    async def async_prepare_restore(self, conn, record: BackupRecord, target: RouterRecord,
                                    read: ArtifactReader) -> RestorePlan: ...
    async def async_execute_restore(self, conn, plan: RestorePlan,
                                    authorization: WriteAuthorization) -> RestoreResult: ...
```

- `ArtifactReader = Callable[[StorageRef], Awaitable[bytes]]` (= `versions.async_read_artifact`).
- `ConfigSource = BackupRecord | ConfigSnapshot`.
- `RouterConnection(router_id, entry_id, api, coordinator, transport)`: `api` ist die
  **bestehende** `OpenWrtAPI` des Eintrags. Neue Router-Aufrufe kommen als Methoden in
  `api.py`, nie als eigenes HTTP/SSH im Provider.
- Der Provider speichert, exportiert und löscht **nichts**; er gibt Bytes in
  `CollectedVersion` zurück.
- Fehler: Provider wirft `ConfigApiError`-Unterklassen (`RouterUnavailableError`,
  `RouterPermissionError`, `OperationTimeoutError`, `BackupIncompleteError`,
  `ArtifactTooLargeError`, …) oder `ProviderError(cause=…, error_class=…)`. Unerwartete
  Ausnahmen wickelt der Core in `ProviderError`.
- Genau ein Provider; ein zweiter `register_provider` ⇒ `ProviderConflictError`.

```python
unregister = api.register_provider(ConfigManagerProvider(hass))
entry.async_on_unload(unregister)
```

## 11. Drift-Bestätigung und Installations-Schlüssel

`DriftAck`:

| Feld | Typ | Bedeutung |
|---|---|---|
| `router_id` | `str` | |
| `drift_id` | `str` | stabile Kennung des Drifts (Provider) |
| `state` | `DriftAckState` | `acknowledged` (gesehen, Basis bleibt) / `known` (neue Basis) |
| `actor` | `Actor` | Admin-Benutzer |
| `ts` | `datetime` (UTC) | |
| `note` | `str \| None` | ≤ 500 Zeichen |

Der Provider bekommt die Bestätigungen in `async_detect_drift(..., acks=...)` und setzt
`DriftReport.ack_state`.

Installations-Schlüssel: 32 zufällige Bytes (`INSTALLATION_KEY_BYTES`) im Store
`openwrt_router.installation_key`, beim ersten Zugriff erzeugt. Nur für HMAC-Digests von
Geheimnissen in Snapshots. **Nie** in Audit, Bus-Event, Diagnose, Log.

```python
key = await api.async_get_installation_key()
digest = hmac.new(key, value.encode(), "sha256").hexdigest()
```

```python
ack = await api.async_acknowledge_drift(router_id, report.drift_id,
                                        state=DriftAckState.KNOWN, actor=admin)
```

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
| `dedup_key` | `str \| None` | `dedup_key(router_id, drift_id)` oder `dedup_key(router_id, error_class)` |
| `data` | `Mapping` | **nur IDs und Zähler, nie Konfigurationswerte**; zusätzlich maskiert |

Ring `AUDIT_MAX_EVENTS = 1000`, Aufbewahrung `AUDIT_RETENTION_DAYS = 90`, persistiert im
Store `openwrt_router.audit`. Bus-Event `EVENT_CORE = "openwrt_router_core_event"` mit
`CoreEvent.to_dict()`; bewusst getrennt von `EVENT_INCIDENT`, `net_rules` und `logbook.py`
bleiben unverändert.

### 12.2 Typen

`router.registered`, `router.identity_changed`, `router.duplicate_suspected`,
`router.capabilities_changed`, `router.orphaned`, `router.adopted`,
`configuration.backup_created`, `configuration.backup_failed`,
`configuration.backup_recovered`, `configuration.backup_validated`,
`configuration.backup_protection_changed`, `configuration.backup_exported`,
`configuration.backup_deleted`, `configuration.drift_detected`,
`configuration.drift_acknowledged`, `configuration.restore_checked`,
`configuration.restore_requested`, `configuration.restore_approved`,
`configuration.restore_rejected`, `configuration.restore_completed`,
`configuration.restore_failed`, `configuration.storage_swept`,
`security.authorization_denied`, `security.approval_requested`,
`security.approval_approved`, `security.approval_rejected`, `security.approval_expired`.

`security.approval_*` gelten für kritische Aktionen außer Restore (Export, Löschen,
ACL-Verteilung, Modulaktionen); Restore behält seine `restore_*`-Typen.

### 12.3 Dedup und Cooldown

- Gleicher `dedup_key` innerhalb des Cooldowns ⇒ weder gespeichert noch gefeuert
  (`emit` gibt `None` zurück).
- Fehler: `(router_id, error_class)`, Cooldown `FAILURE_EVENT_COOLDOWN` (24 h); der erste
  Erfolg danach feuert `backup_recovered` und setzt den Schlüssel zurück.
- Drift: `(router_id, drift_id)`; derselbe Drift feuert einmal, ein geänderter Drift hat eine
  neue `drift_id`.
- Erfolge (`backup_created`) nur bei neuer Version, nie bei Dedup-Treffern.

### 12.4 Audit-Pflicht

Jede Guard-Entscheidung, dazu: manuelles Backup, Schutz an/aus, Drift bestätigt/bekannt,
Dry Run und Kompatibilitätsprüfung (`restore_checked`), Export (wer, wann, welche Version),
Löschen, Adoption.

```python
api.register_event_prefix("security.ids.", module="security_center")
api.emit("security.ids.port_scan", source="security_center", router_id=router_id,
         severity=Severity.WARNING, result=EventResult.INFO,
         dedup_key=dedup_key(router_id, "port_scan"), data={"count": 12})

def _on_event(event: CoreEvent) -> None:
    if event.type == CoreEventType.DRIFT_DETECTED:
        hass.async_create_task(refresh_drift_view(event.router_id))

unsubscribe = api.subscribe(_on_event)   # Listener sind synchron und kurz
recent = api.events(router_id=router_id, types=[CoreEventType.BACKUP_FAILED], since=t0)
```

## 13. Maskierung

- `mask_secrets(data, *, extra_keys=())` gibt eine Kopie zurück; Schlüssel, die nach
  Geheimnis klingen (`password`, `key`, `psk`, `private_key`, `token`, `secret`,
  `ubus_rpc_session`, …, plus `DIAGNOSTICS_REDACT_KEYS`), werden zu `**REDACTED**`.
  `None` bleibt `None`. Tiefe begrenzt (`**TRUNCATED**`).
- Alle `to_dict()` der Typen mit Konfigurationsinhalt maskieren. Prüfsummen
  (`ConfigSnapshot.checksum`, `RestorePlan.checksum`) laufen über den **unmaskierten**
  Inhalt.
- Grenze: namensbasiert. Ein Geheimnis unter einem neutralen Schlüssel wird nicht erkannt.

```python
_LOGGER.debug("snapshot %s", mask_secrets(snapshot.configs))
```

## 14. Fehler

Alle Fehler erben von `ConfigApiError(HomeAssistantError)` und haben `code`,
`error_class`, `message`, `router_id`, `retryable`, `details` und `to_dict()` (Details
maskiert). `code` und `error_class` ändern sich innerhalb v1 nie.

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
| `AuthorizationError` | `authorization_denied` | `denied` | Guard lehnt ab oder `consume` scheitert (`details.reason`) | nein |
| `ApprovalRequiredError` | `approval_required` | `approval` | kritische Aktion ohne freigegebenen Antrag | nein |
| `ApprovalInvalidError` | `approval_invalid` | `approval` | Antrag unbekannt, abgelaufen, benutzt, abgelehnt, anders gebunden | nein |
| `BackupNotFoundError` | `backup_not_found` | `not_found` | Version unbekannt | nein |
| `BackupIntegrityError` | `backup_integrity_failed` | `checksum_mismatch` | sha256/Größe passt nicht | nein |
| `BackupMetadataError` | `backup_metadata_invalid` | `invalid` | Metadaten kaputt oder neuer als unterstützt | nein |
| `BackupIncompleteError` | `backup_incomplete` | `incomplete` | kein verwertbares Artefakt geholt | nein |
| `ArtifactTooLargeError` | `artifact_too_large` | `too_large` | Artefakt oder Router-Kontingent zu groß | nein |
| `StorageFullError` | `storage_full` | `storage_full` | Gesamtgrenze erreicht, nichts geschrieben | nein |
| `StorageError` | `storage_error` | `storage_error` | Dateisystemfehler | nein |
| `UnsupportedStorageFormatError` | `storage_format_unsupported` | `invalid` | unbekanntes `storage_format` | nein |
| `RestoreIncompatibleError` | `restore_incompatible` | `incompatible` | Version passt nicht zum Zielrouter | nein |
| `OperationInProgressError` | `operation_in_progress` | `busy` | Router-Lock belegt | ja |
| `ProviderError` | `provider_error` | `internal` (überschreibbar) | unerwarteter Providerfehler, Ursache verkettet, nur Typname in `details.cause` | nein (überschreibbar) |

`ErrorClass` enthält außerdem die elf Klassen aus `config-manager` 12.2 (`unreachable`,
`timeout`, `auth`, `permission`, `not_available`, `too_large`, `incomplete`, `invalid`,
`checksum_mismatch`, `storage_full`, `storage_error`) und wird auch in
`BackupRecord.error_class` und in Dedup-Schlüsseln benutzt.

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
Abschnitte 5, 9.1, 12, 20) und diesem Vertrag:

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
| 12.2 `delete_versions(ids)` „nur Aufbewahrung oder Freigabe“ | `async_delete_versions(ids, *, authorization)` mit `prune` (Aufbewahrung, überspringt `protected`) oder `delete` (kritisch) | – |
| 12.2 `set_protected`, `put_drift_ack` | mit `authorization` (`protect` / `drift_ack`) | – |
| 12.2 Operationen ohne `async_` | alle mit `async_`-Präfix | HA-Konvention |
| 12.3 Verschlüsselung „gemäß Q3“ | keine eigene; `storage_format="plain-v1"`, `encrypted=False` | Nachtrag 2.2 |
| 12.4 / 9.1 Event-Namen | `config_backup_succeeded` → `configuration.backup_created`; `config_backup_failed` → `configuration.backup_failed`; `config_backup_recovered` → `configuration.backup_recovered`; `config_drift_detected` → `configuration.drift_detected`; `config_drift_acknowledged` → `configuration.drift_acknowledged`; `config_restore_checked` → `configuration.restore_checked` | Core-Schema mit Punkt-Namensraum; ein Bus-Event `openwrt_router_core_event`, Typ im Feld `type` |
| 12.4 Dedup und Cooldown | `CoreEvent.dedup_key`, `FAILURE_EVENT_COOLDOWN` 24 h, Umsetzung im Core (`emit`) | – |
| 12.4 Audit für Export „wer, wann, welche Version“ | ja, plus Antrag/Freigabe als `security.approval_*` | – |
| 12.5 Freigabe „synchron freigegeben/abgelehnt/wartet + Kennung“ | `authorize()` ⇒ `AuthorizationDecision(state, audit_id, …)` | – |
| 12.5 `export` als schreibende Aktion | `export` ist **critical**: Antrag ⇒ Admin-Freigabe ⇒ ein Download | Nachtrag 2.1; erster `authorize` liefert `pending`, nicht `approved` |
| 12.5 `restore` „später“ | im Vertrag, Phase 1 `CapabilityUnavailableError` | Nachtrag 2.3 |
| 12.6 Proben „einmal beim Setup und nach ACL-Neuverteilung“ | zusätzlich nach Firmware-Wechsel | neue Firmware kann rpcd-ACL und CGI ändern |
| 12.6 `config.uci_read` „je Config“ | `CapabilityStatus.detail = {config_name: bool}` | – |
| 11.6 Diff `changed` | `ChangeKind.MODIFIED` (`"modified"`) | bestehender Wert; Provider bildet ab |
| 11.6 Area/Risk als Enums | `ConfigChange.area`/`risk` als `str` | Klassifikation gehört dem Provider |
| 9.2 Sensoren je Router | nicht im Core-Vertrag | Entities baut `config-manager` (Gruppe II) mit `router_id` aus der Registry |
| Q2 Besitz ACL v9 | Core, später: gestufte ACL, nur angeboten, Aktion `acl_deploy` (kritisch) | Nachtrag H / 2.4 |
| Q6 SSH-Host-Key | TOFU nur für den Config-Pfad, später | Nachtrag H |
| Q10 Panel-Container | Core legt „Enterprise“ an, nach Merge von 1.43.0 | Nachtrag H |

## 16. Restore in Phase 1

Verfügbar: Dry Run (`async_prepare_restore`), Kompatibilität
(`async_check_restore_compatibility`), Vorschau (`RestorePlan.diff`, `instructions` als
i18n-Schlüssel für eine Anleitung) und Export. Beides wird als
`configuration.restore_checked` auditiert.

Nicht verfügbar: `async_request_restore` und `async_execute_restore` werfen
`CapabilityUnavailableError(capability="config.restore")`, solange der Provider
`config.restore` nicht als verfügbar meldet. Eine spätere Phase bringt Restore auf
UCI-Ebene mit Rollback (eigener Plan).

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
| Security Intelligence (`security-center`) | Präfix `security.<modul>.` für Events/Capabilities, `subscribe`, Audit lesen | `register_event_prefix("security.center.", module="security_center")`; reagiert auf `security.authorization_denied` |
| Network Intelligence | `links.incident_id`, `BackupReason.INCIDENT`, Drift als Kontext (nur lesend) | Backup bei kritischem Incident: `async_create_backup(..., reason=INCIDENT, links=BackupLinks(incident_id=…))` |
| Network Time Machine | `async_list_backups(since=…)`, `async_compare(ConfigRef.backup(a), ConfigRef.backup(b))`, `events(since=…)` | Zeitleiste aus Versionen und Events |
| Firmware Lifecycle | `BackupReason.PRE_FIRMWARE_UPDATE`/`RELEASE_CHANGE`, `FirmwareInfo`, `CompatibilityInfo` | vor Update `async_create_backup`, nach Update Proben neu |
| Self-Healing | `register_action("self_healing.<aktion>", CRITICAL, …)`, `BackupReason.PRE_CHANGE`, Korrelations-ID | Backup + Freigabe vor jedem Eingriff, alles mit einer `correlation_id` |
| Diagnose (`net-diagnostics`) | Präfix `diag.`/`log.` | eigene Capabilities `diag.traceroute` unter registriertem Präfix |

## 18. Später (nur dokumentiert, kein Code)

- **Gestufte rpcd-ACL** in `acl_provisioning.py`, Rechte je Capability, nur angeboten, nie
  automatisch geschrieben; Schreiben erst nach der einzelnen Freigabe des Nutzers
  (`acl_deploy`), gekoppelt an `config_backup_enabled`:
  - `config.cgi_backup`: `"cgi-io": ["backup"]`
  - `config.uci_read`: `uci`-Lesebereich für `network`, `wireless`, `firewall`, `dhcp`,
    `system`, `dropbear`, `uhttpd`, `rpcd`, `ddns`, `sqm`, `usteer`, `mwan3`, `upnpd`,
    `openvpn`
  - `config.packagelist`: `"ubus": {"rpc-sys": ["packagelist"]}`

  Danach neue Proben. Hinweis für die UI: Diese Rechte geben dem HA-rpcd-Nutzer
  Lesezugriff auf alle Router-Geheimnisse.
- **TOFU-Pinning des SSH-Host-Keys**, nur für den Config-Pfad.
- **Panel-Navigationscontainer „Enterprise“**, leer, mit Untertab-Haken für Module; erst nach
  Merge von 1.43.0.
- **Option `config_backup_enabled`** im Options-Flow (`const.py`, `config_flow.py`).
- **Restore auf UCI-Ebene** mit Rollback.
