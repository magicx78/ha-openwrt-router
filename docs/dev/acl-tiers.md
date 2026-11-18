# Gestufte rpcd-ACL (ACL v9, nur als Angebot) und SSH-Host-Key-Pinning

Stand: 2026-11-18. Code: `custom_components/openwrt_router/acl_provisioning.py`
(Block „Tiered ACL“ am Dateiende) und `api.py` (Block „Config/backup path: SSH with
TOFU host-key pinning“ am Dateiende), seit 1.44.0 `core_security.py` (Pins je Router,
ACL-Verteilen über den Core). Tests: `tests/test_acl_tiers.py`,
`tests/test_ssh_hostkey_pinning.py`, `tests/test_enterprise_core_v144.py`. Vertrag:
`docs/dev/configuration-api-v1.md` Abschnitte 5, 6.3, 12.3 und 17.1.

## 1. Grundsatz

- Der **automatische Weg bleibt unverändert**: `ensure_acl()` schreibt beim Start weiter
  genau ACL v8 (`RPCD_ACL_CONTENT`, `ACL_VERSION = 8`). Die Tests prüfen das byteweise
  (sha256 der geschriebenen Datei = Stand `62cd6c8`).
- Die gestufte ACL v9 ist **nur ein Angebot**. Kein Code schreibt sie von sich aus.
  Schreiben kann nur `async_deploy_acl_offer()`, und nur mit einer
  `WriteAuthorization` für die Aktion `acl_deploy`, gebunden an diesen Router und an
  die Prüfsumme genau dieser ACL-Datei.
- Ob und wie weit die ACL auf die Router kommt, entscheidet der Nutzer je Router.
- Eine ACL-Datei, ein Schreibvorgang und **höchstens ein rpcd-Neustart je Router** für
  alle Module zusammen. Dafür gibt es die Stufen.

## 2. Stufen

Eine Stufe (`AclTier`) hat: `tier_id`, `title`, `capabilities` (Namen, die sie
bedient), `rights` (genaue rpcd-Rechte als `AclRight(section, scope, object, method)`),
`risk` (Hinweis für die UI), `module`, `mandatory`, `option` (Schalter im Options-Flow,
der an sein muss).

| Stufe | Pflicht | Option | Rechte, die sie hinzufügt | Capabilities |
|---|---|---|---|---|
| `read` (Basis) | ja | – | alles aus ACL v8 (Lese- **und** Schreibteil) **ohne** `ubus iwinfo scan`, **plus** `ubus iwinfo txpowerlist` | `data.system_board`, `data.wireless`, `data.hostapd_clients`, `data.dhcp_leases`, `data.logs`, `data.iwinfo`, `data.services`, `data.uci`, `rf.txpowerlist` |
| `config_backup_read` | nein | `config_backup_enabled` | `read cgi-io: backup`; `read ubus rpc-sys: packagelist`; `read uci: network, wireless, firewall, dhcp, system, dropbear, uhttpd, rpcd, ddns, sqm, usteer, mwan3, upnpd, openvpn` | `config.cgi_backup`, `config.packagelist`, `config.uci_read` |
| `rf_survey` | nein | – | `read ubus iwinfo: survey` | `rf.survey` |
| `rf_scan` | nein | – | `read ubus iwinfo: scan` | `rf.scan` |

Bewusst **nicht** enthalten: `iwinfo countrylist`, `iwinfo phyname`, jedes zusätzliche
`file exec`, jedes `iw`.

Die Basis enthält den Schreibteil von v8 unverändert (`network.wireless up/down`,
`network reload`, `file exec /etc/init.d/rpcd`). Ohne ihn würden WLAN-Schalter,
„WLAN neu laden“ und der rpcd-Neustart nach einer ACL-Verteilung nicht mehr gehen.
Die Basis wird aus `RPCD_ACL_CONTENT` abgeleitet; ein Test hält fest, dass der
Unterschied zu v8 genau `-scan +txpowerlist` ist.

### Risiken (Text für die UI, im Code englisch in `AclTier.risk`)

- **`read`**: gleiche Rechte wie v8, ohne Funkscan, plus das reine Lesen der
  Sendeleistungsstufen. Kein Zugriff auf Geheimnisse.
- **`config_backup_read`**: **Gibt dem rpcd-Benutzer von Home Assistant Lesezugriff auf
  alle Geheimnisse des Routers.** Das Backup-Archiv enthält `/etc/shadow` (Passwort-Hashes
  aller Router-Logins, auch root) und private Schlüssel (SSH-Host-Keys, VPN- und
  TLS-Schlüssel), dazu die WLAN-Schlüssel; die UCI-Configs enthalten WLAN-, VPN- und
  DDNS-Passwörter. Wer diesen HA-rpcd-Login nutzen kann, kann sie lesen.
- **`rf_survey`**: liest Kanalstatistiken (belegt/Rauschen je Kanal) aus dem Treiber,
  wechselt den Kanal nicht. Auf der Hardware des Nutzers noch nicht gemessen.
- **`rf_scan`**: ein Scan kann das Funkmodul kurz vom Kanal nehmen (Clients sehen eine
  kurze Lücke) und blockiert rpcd, solange er läuft. Nur auf Anforderung, nie im Poll.

### Kennzeichnung auf dem Router

Die Gruppenbeschreibung trägt eine Marke, die rpcd ignoriert:
`Home Assistant openwrt_router integration, tiered ACL v9; tiers: read,rf_scan`.
`parse_tiered_acl()` liest sie, `classify_deployed_acl()` liefert `missing`,
`legacy_current` (genau v8), `tiered_current`, `tiered_other` oder `foreign`.

## 3. Angebot zeigen, freigeben, verteilen

```python
from .acl_provisioning import DEFAULT_TIER_REGISTRY, describe_offer, async_deploy_acl_offer

# 1. Was darf angeboten werden (Option config_backup_enabled beachten)
tiers = DEFAULT_TIER_REGISTRY.offerable(entry.options)

# 2. Unterschied zur Datei auf dem Router (nur lesen: file/read, dann json.loads)
offer = describe_offer(current_acl_or_None, ["rf_survey"], options=entry.options)
offer.to_dict()   # added / removed (z. B. "read ubus:iwinfo.scan"), risks, acl_checksum

# 3. Freigabe (kritisch, nur Admin-Benutzer; Vertrag 6.3)
decision = guard.authorize(GuardedAction.ACL_DEPLOY, router_id, actor,
                           checksum=offer.binding_checksum(router_id))
# -> pending; Admin gibt frei; zweiter authorize(..., approval_id=...) -> WriteAuthorization

# 4. Verteilen
result = await async_deploy_acl_offer(
    api, offer.tiers, router_id=router_id,
    authorization=decision.authorization, guard_consume=guard.consume,
    options=entry.options,
)
result.to_dict()  # command, backup_path, rollback_command, rpcd_restarted
```

Bindung: `binding_checksum(router_id, acl_checksum)`, `acl_checksum` = sha256 von
`render_acl(acl)` (genau die Bytes, die geschrieben werden; Schlüssel sortiert,
Einrückung 2). Gleiche Stufenmenge in anderer Reihenfolge ergibt dieselbe Prüfsumme.

`async_deploy_acl_offer` lehnt ab (`AclOfferRefusedError`, Unterklasse von
`AuthorizationError`, `reason` in `details`), **bevor** irgendetwas an den Router geht:

| Grund | Wann |
|---|---|
| `option_disabled` | eine Stufe braucht eine Option, die aus ist (`options=None` zählt als „alle aus“); Autorisierung bleibt unverbraucht |
| `no_authorization` | keine `WriteAuthorization` übergeben |
| Grund des Guards | `consume` scheitert: `unknown_authorization`, `already_used`, `expired`, `action_mismatch`, `router_mismatch`, `checksum_mismatch` |
| `consume_failed` | der Guard wirft etwas anderes |
| `not_consumed` / `*_mismatch` | Nachprüfung nach `consume`: die Autorisierung muss danach verbraucht sein und zu Aktion, Router und Prüfsumme passen (Schutz gegen einen `guard_consume`, der nichts tut) |

Ablauf nach erfolgreichem `consume`:

1. ACL-Datei per `file/read` lesen. Ist sie inhaltlich gleich der neuen: **nichts
   schreiben, kein Neustart** (`changed=False`).
2. Vorhandene Datei sichern nach
   `/usr/share/rpcd/ha-openwrt-router.json.bak-<JJJJMMTTThhmmssZ>-<8 hex>` (außerhalb
   von `acl.d`, damit rpcd sie nicht lädt; der zufällige Zusatz verhindert, dass zwei
   Verteilungen in derselben Sekunde dieselbe Sicherung überschreiben).
   Die gelesene Datei wird defensiv geparst (`parse_acl_text`): über
   `MAX_ACL_TEXT_BYTES` (64 KiB) gar nicht, zu tiefe Verschachtelung und ungültiges
   JSON gelten als „nicht lesbar“ (gezählt, geloggt), nie als Ausnahme. Die
   Versionsnummer der Marke hat höchstens 6 Ziffern.
3. Neue Datei schreiben, dann einmal `/etc/init.d/rpcd restart`.
4. Wird ubus `file/write` abgelehnt oder ist die alte Datei per ubus nicht lesbar, geht
   alles in **einem** SSH-Befehl: `[ ! -e ACL ] || cp -p ACL BACKUP`, dann in eine
   Temp-Datei schreiben und umbenennen, dann einmal rpcd neu starten. Ohne gelungene
   Sicherung wird nicht geschrieben. Per ubus wird nie geschrieben, wenn die alte Datei
   nicht gelesen werden konnte (ubus meldet „fehlt“ und „gesperrt“ gleich).

### Rückweg

`AclDeployResult.rollback_command` (auch in `AclOfferDeployError`, sobald eine Sicherung
existiert):

- mit Sicherung: `cp -p <backup> /usr/share/rpcd/acl.d/ha-openwrt-router.json && /etc/init.d/rpcd restart`
- ohne vorherige Datei: `rm -f /usr/share/rpcd/acl.d/ha-openwrt-router.json && /etc/init.d/rpcd restart`
  (beim nächsten HA-Start schreibt `ensure_acl` wieder v8)

`previous_content` und `previous_checksum` der alten Datei stehen im Ergebnis, damit HA
eine Kopie hat. Befehl und Rückweg gehören ins Änderungsprotokoll.

## 4. Zusammenspiel mit `ensure_acl` (wichtig vor dem Freischalten)

`ensure_acl()` vergleicht beim Start die Datei mit v8 und **überschreibt alles andere**,
also auch eine freigegebene gestufte ACL (Test
`test_ensure_acl_still_replaces_a_tiered_acl_with_v8`). Deshalb gibt es
`ensure_acl_respecting_offer(api, *, observe=None)`: lässt jede Datei mit der Marke in
Ruhe (`reason = tiered_kept`) und verhält sich für alle anderen genau wie `ensure_acl()`.

**Seit 1.44.0 umgestellt:** `__init__.py` (Setup jedes Eintrags) und der Repair-Schritt
im Config-Flow (Checkliste) rufen `ensure_acl_respecting_offer`. Es nutzt dasselbe eine
`file/read`, das `ensure_acl` ohnehin macht (`ensure_acl_outcome`): **kein zusätzlicher
Router-Aufruf.** Ohne gestufte ACL sind Aufrufe und geschriebene Bytes identisch mit
`ensure_acl` (Test `test_respecting_offer_makes_exactly_the_calls_of_ensure_acl` für v8,
fehlend, alt, kaputt, nicht erreichbar, Schreiben blockiert). Seit der Prüfung vom
2026-11-18 vergleicht der Test beide Varianten mit wörtlichen Erwartungen aus 1.43
(Pfad, Prüfsumme der v8-Bytes, SSH-Befehl und Timeout), nicht nur miteinander.

**Behalten, aber sichtbar (Review PR #55, Punkt 5):** Still behalten wird eine gestufte
ACL nur, wenn sie alle Basis-Leserechte gewährt (`rights_from_acl(acl) >=
_base_read_rights()`). Fehlen welche, bleibt sie trotzdem unangetastet (nur ein
freigegebenes Angebot ändert sie), aber `ensure_acl_outcome` schreibt eine Warnung ins Log
und meldet die fehlenden Rechte in `AclEnsureOutcome.missing_base_rights`
(`missing_base_read_rights(acl)`, sortierte `describe()`-Texte). Das Setup öffnet daraus
den Reparaturhinweis `acl_base_rights_missing_<entry_id>` (Warnung, nicht persistent,
Texte de/en, Platzhalter `router`, `count`, `rights`, `path`; ohne `config_entry_id`,
damit er unter HA 2026.2.3 läuft). Er verschwindet beim nächsten Setup mit vollständigen
Rechten und beim Entladen; ist die ACL nicht lesbar (Ergebnis unbekannt), bleibt er
unverändert. Auf diesem Pfad wird der Text mit `parse_acl_text` gelesen, also gelten
`MAX_ACL_TEXT_BYTES` und `MAX_ACL_NESTING_DEPTH`: zu groß oder zu tief = `corrupted`, es
wird v8 eingespielt (wie bei kaputtem JSON). Der Pfad ohne Angebot (reines v8) ist
unverändert, der wörtliche Aufruf-Test von oben läuft unverändert durch.

Im Config-Flow nennt der Fehler den Grund, wenn nichts geschrieben wurde:
`acl_tiered_kept` (gestufte ACL behalten), `acl_check_transient` (ACL nicht lesbar,
nichts geändert), sonst wie bisher `acl_already_current`.

`observe` bekommt das `AclEnsureOutcome` (gelesener Inhalt, ob bekannt, Grund); der Core
macht daraus `observe_deployed_acl(...)` und daraus `rf.*` (Abschnitt 5). Ein Fehler im
Beobachter wird geloggt und ändert das Ergebnis nicht.

Verteilen über den Core (statt direkt `async_deploy_acl_offer`): `ConfigurationApi`
`async_request_acl_deploy` → Freigabe → `async_deploy_acl_offer`; Ablauf, Fehler und
Events im Vertrag, Abschnitt 6.3 und 12.3.

## 5. Folgen des fehlenden `iwinfo scan` in der Basis

- Heute ruft **kein** Code `iwinfo scan` auf. `const.py:105` definiert
  `UBUS_IWINFO_SCAN = "scan"`, benutzt wird die Konstante nirgends (geprüft mit grep in
  `api.py`, `coordinator.py` und dem ganzen Integrationsordner).
- Wer die Basis ohne `rf_scan` verteilt, verliert also heute nichts. Betroffen ist erst
  das künftige Modul `wifi-rf` mit `rf.scan`.
- **Seit 1.44.0** meldet `capabilities.py` `rf.txpowerlist`, `rf.survey` und `rf.scan`
  aus der beobachteten ACL: Recht vorhanden ⇒ `available`; fehlt es ⇒ `unavailable` /
  `permission_denied` mit `required_permissions` aus `missing_permissions(acl, name)`;
  ACL unbekannt (noch nicht gelesen, nicht lesbar, Transportfehler) ⇒ `unknown` mit
  Grund. Mit plain v8: `rf.scan` verfügbar, die anderen beiden `permission_denied`.
  Gesehen wird nur die Datei der Integration, keine anderen Dateien in `acl.d`.

## 6. Spätere Stufen (`security.`, `diag.`)

Stufen stehen in einer Registry (`AclTierRegistry`), nicht in einer if-Kette.

**Regeln (seit der Sicherheitsprüfung vom 2026-11-18: Allowlist statt Sperrliste).**
rpcd vergleicht ACL-Einträge mit `fnmatch`; eine Sperrliste kann deshalb nie
vollständig sein (`fil?`, `f*`, `*` oder `[w]rite` gewähren, was sie beim Namen
verbietet). Eine optionale Stufe darf nur enthalten:

| Bereich | erlaubt |
|---|---|
| Abschnitt | nur `read` |
| Musterzeichen | keine: `* ? [ ] { } \` in Objekt oder Methode werden immer abgelehnt |
| `ubus`, `uci`, `cgi-io` und jeder andere Bereich außer `file` | nur ein exaktes Tripel `(Bereich, Objekt, Methode)` aus `OPTIONAL_TIER_ALLOWLIST` (was die eingebauten Stufen brauchen: `cgi-io backup`, `rpc-sys packagelist`, die genannten UCI-Configs, `iwinfo survey`, `iwinfo scan`) oder aus der Erweiterungstabelle `OPTIONAL_TIER_EXTENSIONS`; `rpc-sys`, `system`, `luci`, `uci`, `cgi-io` sonst nie |
| `file` | nur Methode `read`, absoluter Pfad, der nach `posixpath.normpath` unverändert bleibt (kein `..`, kein `//`), unter `/proc/net/`, `/sys/class/net/` oder `/sys/class/ieee80211/` |

Die Basis-Stufe `read` ist fest: sie wird aus ACL v8 abgeleitet und lässt sich über die
Registry nicht erweitern (`base_tier_fixed`). Abgelehnt wird mit
`AclTierRightRefusedError` (Unterklasse von `AclTierError`): `tier_id`, das abgelehnte
`right` und `reason` (`write_section`, `pattern`, `not_allowlisted`, `file_method`,
`file_path`, `base_tier_fixed`); dazu ein Warn-Log. Weiter abgelehnt: doppelte IDs und
eine zweite Pflichtstufe.

**Neues Recht für ein späteres Modul.** Zuerst trägt eine geprüfte Änderung das exakte
Tripel in `OPTIONAL_TIER_EXTENSIONS` in `acl_provisioning.py` ein, mit einem Kommentar,
warum es nur liest. Beispiel Network Diagnostics:

```python
OPTIONAL_TIER_EXTENSIONS: Final[frozenset[tuple[str, str, str]]] = frozenset(
    {
        # net-diagnostics: luci getTraceroute startet nur traceroute zu einem
        # Ziel und liefert die Ausgabe; keine Konfiguration, kein Schreiben.
        ("ubus", "luci", "getTraceroute"),
    }
)
```

Erst danach registriert das Modul seine Stufe:

```python
DEFAULT_TIER_REGISTRY.register(AclTier(
    tier_id="diag_traceroute", title="Traceroute", module="net_diagnostics",
    capabilities=("diag.traceroute",),
    rights=frozenset({AclRight("read", "ubus", "luci", "getTraceroute")}),
    risk="...",
))
```

Ohne den Eintrag lehnt `register()` mit `not_allowlisted` ab (Test
`test_f01_allowlisted_and_extension_rights_are_accepted`). Die Tabelle ist heute leer.

**Was der Admin freigibt.** `describe_offer(...)` liefert neben Prüfsumme und Unterschied
jedes Recht der vorgeschlagenen Datei: `AclOffer.rights`, je Stufe `tier_rights` und
`rights_text()` (lesbare Liste, gruppiert nach Stufe, mit „hinzugefügt“/„entfernt“
gegenüber dem Router); `to_dict()` enthält `rights`, `tier_rights` und `rights_text`.
Freigegeben werden damit Rechte, nicht nur eine Prüfsumme.

Zuordnung der Capability-Präfixe: `config.` Configuration Manager, `rf.` WiFi RF,
`diag.` Network Diagnostics, `security.` Security Center.

## 7. SSH-Host-Key-Pinning, nur Config/Backup-Pfad (seit 1.44.0 mit Bestätigung)

Heute: der gemeinsame SSH-Weg verbindet mit `asyncssh.connect(..., known_hosts=None)`
(`api.py:3036`, `OpenWrtAPI._asyncssh_get_connection`), prüft den Host-Key also gar
nicht. `sshpass` gibt es seit v1.22.0 nicht mehr. Das bleibt so für alle bestehenden
Aufrufer.

Neu (am Ende von `api.py`): `async_ssh_run_pinned(api, cmd, *, pin_store, timeout=60,
binary=False, max_output_bytes=None) -> PinnedSshResult`.

- Eigene Verbindung je Aufruf, nie die gemeinsame ungeprüfte.
- `known_hosts=([gepinnter_key] oder [], [], [])` und ein eigener `SSHClient`: asyncssh
  prüft den Schlüssel im Handshake, **vor** der Anmeldung. Mit Pin akzeptiert er nur
  diesen Schlüssel und nur dessen Schlüsseltyp.
- Erste Nutzung (seit der Sicherheitsprüfung vom 2026-11-18): eine eigene Verbindung
  **ohne Zugangsdaten** (kein Passwort, keine Schlüssel, kein Agent, kein GSS) liest den
  Host-Key im Handshake; der `SSHClient` merkt ihn sich und lehnt ihn ab, asyncssh bricht
  also **vor** der Anmeldung ab. Danach `pin_store.async_save_pin(HostKeyPin)`. Wirft der
  Store (`pin_pending` bei `confirm`), endet der Aufruf dort: keine Anmeldung, kein
  Befehl. Bestätigt der Store sofort (nur `tofu`, nicht Standard), folgt eine **zweite**
  Verbindung, die nur genau diesen Key akzeptiert, und erst sie meldet sich an. Scheitert
  das Speichern: `OpenWrtHostKeyError("pin_save_failed")`, keine Anmeldung, kein Befehl.
- Angemeldet wird also nur auf einer Verbindung, deren Key gleich einem gespeicherten
  Pin ist.
- Ausgabe begrenzt: der Befehl läuft über `create_process`; stdout wird stückweise bis
  `max_output_bytes` gelesen (Standard `PINNED_SSH_DEFAULT_MAX_OUTPUT_BYTES` =
  Artefakt-Grenze + 1 MiB). Darüber: Prozess schließen,
  `OpenWrtSshOutputTooLargeError` (`error_class` `too_large`, `limit_bytes`,
  `received_bytes`); im Core `ArtifactTooLargeError` `ssh_output_too_large`, Zähler
  `output_too_large`. stderr bleibt höchstens 4 KiB (`stderr_truncated`), der Rest wird
  gelesen und verworfen. Das ACL-Verteilen per SSH nutzt 64 KiB. Gesamt-Timeout
  unverändert.
- Abweichung: `OpenWrtHostKeyMismatchError` (`mismatch` oder `algorithm_unavailable`).
  **Kein** Rückfall auf den ungepinnten Weg. Die Fehlerklasse erbt nicht von
  `OpenWrtConnectionError`, damit „Router nicht erreichbar, später wieder“-Zweige sie
  nicht schlucken.
- Anmeldung (nur auf der gepinnten Verbindung) wie beim gemeinsamen Weg (erst
  Passwort, dann Schlüssel), ohne dessen Zustand `_ssh_use_key` zu ändern.
- `HostKeyPin`: `algorithm`, `fingerprint` (`SHA256:…`), `public_key` (OpenSSH-Zeile),
  `host` (nur zur Info, der Pin folgt der `router_id`), `pinned_at` (ISO UTC);
  `to_dict()`/`from_dict()`.
- `HostKeyPinStore`: zwei Koroutinen `async_load_pin()` / `async_save_pin(pin)`. Wirft
  einer davon `OpenWrtHostKeyError`, reicht `async_ssh_run_pinned` ihn unverändert durch
  (seit 1.44.0; `async_load_pin` lehnt so **vor** dem Verbinden ab).

**Seit 1.44.0: Speicher je Router und kein stilles TOFU** (`core_security.py`):

- `SshPinRegistry` (Store `openwrt_router.ssh_host_keys`, `private`, `atomic_writes`,
  `migrate_pin_store`) gibt je `router_id` einen `RouterPinStore`. Geschrieben wird nur
  bei Pin-Ereignissen (erster Kontakt, Bestätigung, Reset), nie je Poll.
- Regel ist eine Konstante: `SSH_PIN_FIRST_USE_POLICY = SSH_PIN_POLICY_CONFIRM`. Der erste
  Kontakt speichert den Key als **ausstehend**, sendet `security.ssh_pin_pending` und
  bricht mit `OpenWrtHostKeyError("pin_pending")` ab, **ohne** den Befehl auszuführen.
  Danach lehnt jeder Aufruf vor dem Verbinden ab, bis ein Admin `ssh_pin_confirm`
  (kritisch, gebunden an Router und Fingerprint) freigibt und einlöst.
- Abweichender Key: immer `OpenWrtHostKeyMismatchError`, Event
  `security.ssh_pin_mismatch` (kritisch, erwarteter und gezeigter Fingerprint), der Pin
  bleibt unverändert.
- Neuer Router-Key (Neuinstallation): `ssh_pin_reset` (kritisch, nur Admin), Event
  `security.ssh_pin_reset`; der nächste Kontakt ist wieder „ausstehend“.
- Module bekommen gepinntes SSH nur über `ProviderContext.async_ssh_run_pinned(router_id,
  command, timeout=…, binary=…)`; das ACL-Verteilen per SSH nutzt denselben Weg.
- Erster Kontakt ohne Passwort (behoben, Sicherheitsprüfung 2026-11-18, vorher
  „bekannte Grenze“): beim allerersten Kontakt geht **kein** Passwort und kein Schlüssel
  an den Router, bevor ein Admin den Key bestätigt hat. Ein Angreifer im Netz beim
  ersten Kontakt sieht nur einen Verbindungsaufbau ohne Anmeldung; der Admin vergleicht
  den Fingerprint aus `security.ssh_pin_pending` mit dem Router, bevor er bestätigt.
  Tests: `test_f02_first_contact_sends_no_credentials`,
  `test_first_use_is_pending_not_trusted`.
