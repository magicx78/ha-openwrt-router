# Configuration Manager

<!-- Nutzerdoku ab 1.45.0. Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens;
     Beispiele nutzen 192.0.2.x und neutrale Namen. Jede Aussage ist am Code geprüft
     (config_manager.py, config_provider.py, config_collector.py, config_archive.py,
     config_snapshot.py, config_diff.py, config_restore.py, config_views.py, config_entities.py,
     config_const.py, api.py). Aufbau und Zusagen des Cores: docs/enterprise-core.md;
     Vertrag für Entwickler: docs/dev/configuration-api-v1.md; ACL: docs/dev/acl-tiers.md. -->

## Inhalt

1. [Was es tut und was nicht](#1-was-es-tut-und-was-nicht)
2. [Die drei Artefakte](#2-die-drei-artefakte)
3. [Auslöser](#3-auslöser)
4. [Versionen, Dedup und Aufbewahrung](#4-versionen-dedup-und-aufbewahrung)
5. [Drift-Erkennung](#5-drift-erkennung)
6. [Diff-Ansicht](#6-diff-ansicht)
7. [Panel „Enterprise → Konfiguration“](#7-panel-enterprise--konfiguration)
8. [Sensoren und Ereignisse](#8-sensoren-und-ereignisse)
9. [Berechtigungen auf dem Router](#9-berechtigungen-auf-dem-router)
10. [Backup und Wiederherstellung (Anleitung)](#10-backup-und-wiederherstellung-anleitung)
11. [Sicherheitshinweise und Schutzgrenzen](#11-sicherheitshinweise-und-schutzgrenzen)
12. [Last für Router und Home Assistant](#12-last-für-router-und-home-assistant)
13. [Bekannte Einschränkungen](#13-bekannte-einschränkungen)
14. [Fehlerklassen](#14-fehlerklassen)

## 1. Was es tut und was nicht

Der Configuration Manager sichert die Konfiguration Ihrer OpenWrt-Router in Home Assistant,
hält mehrere Versionen vor, zeigt Unterschiede zwischen Versionen und dem aktuellen Stand und
erkennt Änderungen an der Router-Konfiguration („Drift“). Er baut auf dem Enterprise Core
(ab 1.44.0) auf: Ablage, Aufbewahrung, Freigaben, Audit-Log und Maskierung kommen vom Core,
nicht vom Manager.

**Was er in Phase 1 (1.45.0) nicht tut:**

- Er **spielt nie etwas auf einen Router zurück**, weder ein Archiv noch einzelne UCI-Werte.
  Es gibt keine Route, keinen Dienst und keinen Knopf dafür. Das Panel prüft eine
  Wiederherstellung nur und erklärt die manuellen Schritte ([Abschnitt 10](#10-backup-und-wiederherstellung-anleitung)).
- Er setzt Drift nie automatisch zurück. Sie sehen den Unterschied und entscheiden.
- Er hat keinen eigenen Update-Pfad für die Router-Firmware und löst kein Firmware-Update aus.
- Er verschlüsselt die gespeicherten Archive nicht selbst ([Abschnitt 11](#11-sicherheitshinweise-und-schutzgrenzen)).
- Er schickt nichts an externe Dienste.

**Standardmäßig AUS.** Solange der Schalter nicht gesetzt ist, ruft der Manager keinen
Router, legt nichts auf der Platte an und zeigt im Panel nur „ausgeschaltet“. Die Sensoren
gibt es trotzdem (Status `disabled`).

### Einschalten

Einstellungen → Geräte & Dienste → OpenWrt Router → der Router → **Konfigurieren**. Die
Felder stehen in den Optionen **je Router**. Die Felder erscheinen, sobald der Backup-Provider
beim Core angemeldet ist (die Integration meldet ihn selbst an) oder solange der Schalter an ist.

| Option (Schlüssel) | Auswahl | Vorgabe | Wirkung |
|---|---|---|---|
| `config_backup_enabled` | Schalter | **aus** | Gesamtschalter für diesen Router. Aus: kein Backup, keine Probe, kein Vergleich, kein Zeitplan; gespeicherte Versionen bleiben. Wirkt sofort, ohne Neuladen. |
| `config_backup_schedule` | `daily` / `off` | `daily` | `daily`: ein Backup pro Tag. `off`: nur Dienst, Panel, Release-Wechsel und Drift-Versionen. Wirkt nur bei eingeschaltetem Backup. |
| `config_backup_time` | Uhrzeit (`HH:MM:SS`, Ortszeit von Home Assistant) | `03:30:00` | Startzeit des Tageslaufs. Jeder Router bekommt einen festen Versatz von 0 bis 59 Minuten und 59 Sekunden dazu. |
| `config_drift_check` | Schalter | an | Drift-Prüfung, wenn die Poll-Daten eine konfigurationsnahe Änderung zeigen. Wirkt nur bei eingeschaltetem Backup. |

Der Manager liest die Optionen bei jedem Takt neu; es gibt keinen Update-Listener und kein
Neuladen. Aktuelle Zeitplan-Änderungen gelten daher spätestens beim nächsten
5-Minuten-Takt.

> **Warnung vor dem Einschalten:** Ein Archiv enthält **alle** Router-Geheimnisse im Klartext
> (`/etc/shadow`, WLAN-, VPN- und TLS-Schlüssel, SSH-Host-Keys). Lesen Sie
> [Abschnitt 9](#9-berechtigungen-auf-dem-router) und [Abschnitt 11](#11-sicherheitshinweise-und-schutzgrenzen),
> bevor Sie es einschalten.

## 2. Die drei Artefakte

Eine Version besteht aus bis zu drei Dateien:

| Artefakt | Inhalt | Wofür |
|---|---|---|
| `archive` | Das Archiv, wie es der Router liefert (`sysupgrade -b`-Format, `tar.gz`), unverändert. Enthält Geheimnisse im Klartext. | Wiederherstellung von Hand ([Abschnitt 10](#10-backup-und-wiederherstellung-anleitung)). |
| `uci` | Normalisierter UCI-Snapshot (JSON) der 14 Configs `network`, `wireless`, `firewall`, `dhcp`, `system`, `dropbear`, `uhttpd`, `rpcd`, `ddns`, `sqm`, `usteer`, `mwan3`, `upnpd`, `openvpn`. Geheimwerte stehen nur als gesalzene HMAC-Prüfwerte darin, nicht im Klartext. | Vergleich, Diff, Drift. |
| `inventory` | Paket- und Systeminventar (JSON): Board, Modell, OpenWrt-Release, Kernel, Paketmanager, installierte Pakete, Dateiliste des Archivs. | Prüfung vor einer Wiederherstellung, Anzeige. |

Das Archiv holt der Manager auf dem ersten Weg, der funktioniert:

1. **LuCI-Backup-Endpunkt** `cgi-backup` (Paket `cgi-io`) über denselben Host und dasselbe
   Protokoll wie die ubus-Verbindung. Er braucht das rpcd-Recht `cgi-io: backup` (lesen).
2. **SSH als root**, fester Befehl `/sbin/sysupgrade --create-backup -`. Der SSH-Benutzer
   der Integration muss `root` sein; mit einem anderen Benutzer wird der Weg abgelehnt, ohne
   zu verbinden.

Meldet ein Weg „nicht vorhanden“ oder „keine Rechte“ (`not_available`, `permission`), geht
es zum nächsten; Router nicht erreichbar oder Zeitüberschreitung beendet den Versuch sofort,
ebenso ein zu großes Archiv (`too_large`). Ein Anmeldefehler, ein abgebrochener Transfer oder
ein ungültiges Archiv auf dem ersten Weg führt dagegen zum zweiten Weg.

**Router ohne Archivweg** (weder `cgi-io` noch root-SSH) bekommen nur den Snapshot: Die
Version hat dann den Typ `uci_snapshot` und gilt als vollständig (Status `ok`), enthält aber
**kein** Archiv. Das Panel zeigt „Nur UCI-Snapshot“; eine Wiederherstellung über LuCI oder
`sysupgrade -r` ist damit nicht möglich. Liefert der Weg einen echten Fehler (zum Beispiel
Zeitüberschreitung), der Snapshot aber gelingt, ist die Version `partial` mit der
Fehlerklasse des Archivs und zählt nicht als Bezugsbasis.

Den Snapshot liest der Manager zuerst per ubus (`uci get`); verweigert rpcd das, liest er mit
`uci show` per SSH.

## 3. Auslöser

Es gibt **einen** Takt für alle Router, alle 5 Minuten. Er rechnet nur im Speicher und
ruft keinen Router, solange nichts fällig ist. Läufe gehen nacheinander durch eine
Warteschlange: **Parallelität 1** für die ganze Flotte, unabhängig von der Zahl der Router.
Ein Lauf, der auf einen anderen trifft, zählt nicht als Fehler, sondern wird beim nächsten
Takt neu versucht.

| Auslöser | Bedingung | Version |
|---|---|---|
| **Täglich** | Option an, Zeitplan `daily`, Uhrzeit plus Versatz des Routers erreicht, heute noch kein geplanter Lauf | Grund `scheduled`, Archiv + Snapshot + Inventar |
| **Nachversuch** | Der Tageslauf scheiterte mit einem wiederholbaren Fehler (Router nicht erreichbar, Zeitüberschreitung) | einmal nach 15 Minuten |
| **Release-/Firmware-Wechsel** | Die Firmware-Version am Router-Datensatz weicht von der der neuesten brauchbaren Version ab; 300 s nach der ersten Beobachtung | Grund `release_change`, einmal je Router und Version |
| **Drift** | Die Poll-Daten ändern sich konfigurationsnah ([Abschnitt 5](#5-drift-erkennung)) | erst eine Drift-Prüfung; bei neuer, unbestätigter Drift eine Version vom Typ `uci_snapshot`, Grund `drift` |
| **Manuell** | Panel „Jetzt sichern“ oder Dienst | Grund `manual`, immer eine neue Version |

**Tageslauf und Staffelung.** Der Versatz ist je Router fest (aus der Router-ID abgeleitet,
0 bis 3599 Sekunden) und ändert sich nicht mit der Uhrzeit. Verpasst Home Assistant den
Zeitpunkt (aus, Neustart), wird der Lauf am selben Tag nachgeholt. Der Manager merkt sich den
Tag aus den gespeicherten Versionen; ein Neustart führt also nicht zu einem zweiten
Tageslauf, wenn heute schon einer lief.

**Release-Wechsel.** Verglichen wird die Firmware-Version des Routers (aus dem Core-Register)
mit der OpenWrt-Version der neuesten brauchbaren Version. Fehlt eine der beiden Angaben,
passiert nichts. Das Archiv nach dem Wechsel zeigt also den Stand **nach** dem Update; eine
Sicherung **vor** dem Update muss vorher entstehen (siehe unten).

### Manuell: Dienst `openwrt_router.create_config_backup`

| Feld | Pflicht | Beschreibung |
|---|---|---|
| `device_id` | ja | Ein oder mehrere OpenWrt-Router-Geräte dieser Integration (Geräteauswahl). |
| `note` | nein | Beschreibung, höchstens 200 Zeichen, keine Steuerzeichen. Nie Passwörter eintragen. |

Die Router laufen nacheinander. Mit `response_variable` kommt je Router
`{"router_id", "backup_id", "created", "status", "error_class"}` zurück (`created` ist
hier immer `true`, weil ein manuelles Backup stets eine neue Version anlegt). Scheitert nur ein Teil der Router, steht der Fehler im Ergebnis;
scheitern alle, endet der Aufruf mit einem Fehler. Der Dienst braucht einen Admin-Benutzer
oder eine Automation; Nicht-Admins werden abgelehnt. Ist die Option am Router aus, wird vor
jedem Lauf abgebrochen.

```yaml
actions:
  - action: openwrt_router.create_config_backup
    data:
      device_id: 0123456789abcdef0123456789abcdef   # Router-Gerät
      note: "Vor dem VLAN-Umbau"
    response_variable: result
  - action: persistent_notification.create
    data:
      title: "Router-Backup"
      message: >-
        Erstellt: {{ result.results[0].created }},
        Status: {{ result.results[0].status }}
```

### „Vor einem Firmware-Update“

Die Integration hat **keinen eigenen Update-Pfad**: Sie startet kein Firmware-Update und kann
deshalb nicht selbst „vorher“ sichern. Empfohlen: Rufen Sie den Dienst als Schritt vor dem
Update auf, in einem Skript oder von Hand, und prüfen Sie in den Sensoren, dass die Version
da ist, bevor Sie updaten.

```yaml
script:
  router_update_vorbereiten:
    sequence:
      - action: openwrt_router.create_config_backup
        data:
          device_id: 0123456789abcdef0123456789abcdef
          note: "Vor Firmware-Update"
        response_variable: result
      - condition: template
        value_template: "{{ result.results[0].status == 'ok' }}"
      # erst hier das Update über Ihren üblichen Weg (LuCI, attended sysupgrade, …)
```

Zusätzlich sichert der Manager 300 Sekunden nach einem erkannten Release-Wechsel (Stand nach
dem Update).

## 4. Versionen, Dedup und Aufbewahrung

**Metadaten je Version:** Zeitpunkt (`created_at`) und letzter gleicher Befund
(`last_seen_at`), Grund (`manual`, `scheduled`, `release_change`, `drift`), Typ
(`full_archive`, `uci_snapshot`, `partial`), Status (`ok`, `partial`, `failed`), ob geschützt,
wer sie angelegt hat (Benutzer, Automation, Modul, System; Benutzer-IDs gehen nie roh in
Antworten), OpenWrt-Version, Prüfzustand (`unverified`, `valid`, `invalid`, `corrupt`,
`missing`), Warnungen, Beschreibung und je Artefakt Art, Größe und SHA-256.

**Dedup.** Geplante und Drift-Versionen werden nicht neu gespeichert, wenn sie nur die letzte
wiederholen; dann wird nur `last_seen_at` verschoben (`created: false`). Manuelle Versionen
legen immer neu an, damit keine Beschreibung verloren geht. Warum nicht einfach die
Archiv-Prüfsumme? Zwei `sysupgrade -b`-Läufe über dieselben Dateien müssen nicht dieselben
Bytes ergeben (Zeitstempel und Header im Tar), die Prüfsumme der Datei würde also fast immer
abweichen. Darum vergleicht der Provider einen **Inhalts-Hash** über Dateinamen, Typen,
Rechte und Inhalte der Archiv-Mitglieder (ohne Zeiten, Besitzer und Reihenfolge); ohne Archiv
den Hash des UCI-Snapshots. **Zusätzlich** verlangt der Core seit 1.44.0 bei jeder Art, dass
die gespeicherten Dateien **byte-gleich** sind (SHA-256 des Cores). Gleicher Inhalts-Hash bei
abweichenden Bytes legt eine neue Version an (der Core zählt das als `dedup_refused_sha256`).
Ob echte Router Archive byte-gleich liefern, wurde nicht gemessen; wenn nicht, wächst der
Speicher mit jedem Tag um ein Archiv, bis die Aufbewahrung ausdünnt.

**Aufbewahrung (Core, GFS):** je Router die neueste brauchbare Version von **7 Tagen, 4
Wochen und 6 Monaten**. Die Aufbewahrung läuft nach jeder neu gespeicherten Version. Es gibt
keine Felder dafür je Router; die Werte gelten für die ganze Installation.

- **Geschützte Versionen** und die neueste brauchbare Version werden nie entfernt. Schützen
  und Aufheben geht im Panel (Knopf „Schützen“).
- **Manuelle Versionen** und Versionen vom Typ `pre_*` werden vom GFS-Ausdünnen nie berührt.
- **Größenlimit (Core):** 50 MiB je Router und 250 MiB insgesamt (Standardwerte). Ein Archiv
  über 16 MiB komprimiert wird gar nicht erst übernommen (`too_large`). Ist das Limit erreicht,
  läuft die Aufbewahrung einmal und die Speicherung wird einmal wiederholt; reicht das nicht,
  scheitert sie mit `storage_full`. Ein Ereignis `configuration.storage_limit_exceeded` meldet es.
  **Bekannte Einschränkung im Core:** Muss das Limit Versionen entfernen, räumt es manuelle
  Versionen erst, nachdem alle anderen weg sind. Eine gute geplante Version kann dadurch
  früher fallen als nötig, obwohl das Entfernen einer einzigen manuellen Version gereicht
  hätte. Der Fall ist als erwarteter Fehlschlag festgehalten
  (`tests/test_config_retention_acceptance.py`, `xfail` strict); er hängt am Core.

Löschen im Panel gibt es nicht (siehe [Abschnitt 13](#13-bekannte-einschränkungen)). Wird ein
Router-Eintrag aus Home Assistant entfernt, verschiebt der Core seine Versionen nach
`removed/<router_id>/` und protokolliert das.

## 5. Drift-Erkennung

Drift heißt: Die Konfiguration auf dem Router weicht von der Bezugsversion ab. Der Manager
vergleicht dazu den **aktuellen UCI-Stand** (14 Configs, live vom Router gelesen) mit der
Bezugsversion, standardmäßig der neuesten brauchbaren Version, oder der Version, die Sie
zuletzt als „bekannt“ markiert haben.

**Wann geprüft wird.**

- **Automatisch** (Option `config_drift_check`): Der Manager vergleicht nach jedem Poll einen
  Fingerprint aus konfigurationsnahen Poll-Daten, ohne zusätzlichen Router-Aufruf: Board und
  Release, Hostname, WAN-Interface und -Protokoll, je Funkschnittstelle UCI-Abschnitt, SSID,
  Band, Aktiv-Flag und Modus, Interface-Namen mit IPv4-Adresse und Präfix (nicht bei Uplinks),
  VLAN-Zuordnung der Ports, DHCP-Pools und der Aktiv-Status von Diensten. Zähler, Uptime,
  Clients, Signal, Kanal und Link-Status zählen nicht. Ändert sich der Fingerprint, wartet der
  Manager **5 Minuten (Entprellung)** und prüft dann, **höchstens einmal je Stunde** (also
  höchstens 24 Prüfungen je Router und Tag). Der erste Wert nach dem Start ist nur Bezug und
  löst nichts aus. Gibt es noch keine Bezugsversion, wartet er auf den Tageslauf.
- **Von Hand:** „Drift jetzt prüfen“ im Panel, ohne Stundengrenze.

> **Grenze:** Änderungen, die der Fingerprint nicht abbildet (zum Beispiel eine
> Firewall-Regel oder ein Dropbear-Port), löst die automatische Prüfung nicht aus. Sie
> erscheinen bei der manuellen Prüfung oder im Vergleich mit dem aktuellen Stand.

**Neue Drift → neue Version.** Ist die Drift neu (`drift_id` noch nicht gesehen) und nicht
bestätigt, legt der Manager eine Version vom Typ `uci_snapshot`, Grund `drift`, an: **höchstens
4 je Router und Tag**, gezählt je Versuch.

**Bereiche.** Jede Änderung bekommt einen Bereich: `vlan`, `interface`, `mgmt_ip`, `firewall`,
`dhcp`, `dns`, `wlan`, `routing`, `services`, `ssh`, `system`, `other` (nicht eingestuft).

**Risikostufen:** `critical`, `high`, `medium`, `low`. Ein reines Umsortieren gilt als `low`.
**Als kritisch gilt:**

- die **Management-IP**: Adress-, Netzmasken-, Protokoll-, Geräte- und Gateway-Optionen des
  Interfaces, über das Home Assistant den Router erreicht;
- **VLAN** (`bridge-vlan`, Switch-Abschnitte, `ports`/`type`/`vid` an Geräten);
- **Firewall**: `defaults`, Zonen-Optionen `input`/`network`/`device`/`subnet`, jede
  Eingangsregel ohne `dest`, jede Regel und Weiterleitung auf Port 22 oder 80/443;
- **SSH-Zugriff und Web-Verwaltung**: jede Änderung in `dropbear`, `uhttpd` und `rpcd`;
- **Uplinks** (`wan`, `wan6`, `wwan` und das erkannte WAN-Interface);
- das Hinzufügen oder Entfernen ganzer Zonen, Bridge-VLANs, Geräte und Interfaces.

Ist das Management-Interface nicht sicher bekannt (Host ist ein Name oder per DHCP vergeben),
wird **jede Adressänderung** an Nicht-Uplink-Interfaces als kritisch gewertet.

**Bestätigen oder als bekannt markieren.**

- **Bestätigen** (`acknowledged`): „gesehen“. Die Bezugsversion bleibt; die Drift gilt nicht
  mehr als offen.
- **Als bekannt markieren** (`known`): Der aktuelle Stand wird die neue Bezugsbasis. Dafür
  nimmt der Core zuvor eine Version des aktuellen Stands auf (ein weiterer Lesedurchgang).
  Eine Notiz (höchstens 200 Zeichen) ist möglich.

Der Manager **setzt nie automatisch zurück**; Sie müssen den Router selbst ändern.

**„Nicht vergleichbar“ ist ein eigener Zustand.** Konnte eine Config nur auf einer Seite
gelesen werden, oder lassen sich Geheimwerte nicht vergleichen (anderer Installations-Schlüssel),
steht der Befund als nicht vergleichbar da, nie als „alles in Ordnung“. Eine Drift mit nicht
vergleichbaren Anteilen wird als `unknown_count` gezählt und lässt sich bestätigen, aber nicht
als bekannt übernehmen. Fehlt der Installations-Schlüssel, erscheint ein Reparatur-Hinweis
(Details im Core).

## 6. Diff-Ansicht

Der Vergleich zeigt je Änderung Bereich, Config, Abschnitt, Option und eine Operation:

- **hinzugefügt**, **entfernt** oder **geändert**;
- gruppiert nach Bereich, nach Risiko eingefärbt, kritische Bereiche zuerst und aufgeklappt;
- **Geheimwerte nie im Klartext**: Bei Passwörtern, Schlüsseln und Ähnlichem steht nur
  „Geheimer Wert geändert (Inhalt wird nicht angezeigt)“. Die Maskierung geschieht auf dem
  Server (Core und Ergänzung des Managers), nicht im Browser. Die Erkennung geht nach
  Optionsnamen; ein ungewöhnlich benanntes Geheimnis kann sie verfehlen.

Verglichen werden **zwei Versionen desselben Routers** oder eine Version mit dem **aktuellen
Stand** („Aktueller Stand (Router)“). Letzteres liest die Konfiguration einmal vom Router
(14 Aufrufe) und braucht eingeschaltetes Backup. Eine zu lange Liste wird als gekürzt
gekennzeichnet, ein Vergleich mit fehlenden Configs als unvollständig.

## 7. Panel „Enterprise → Konfiguration“

Der Eintrag erscheint in der Seitenleiste unter **Enterprise**, Untertab **Konfiguration**,
Titel „Configuration Manager“, und **nur für Administratoren**. Alle Routen dahinter
antworten Nicht-Admins immer mit 403, auch wenn das Topologie-Panel für alle Benutzer
offen ist. Das Panel ist deutsch.

**Übersicht.** Eine Zeile je Router: Backup-Status, letztes Backup, Versionen, Drift
(mit Zahl der kritischen Änderungen), OpenWrt-Version und Risiko. Oben steht die Zahl offener
Freigaben. Läuft ein Backup, fragt die Ansicht alle 5 Sekunden nach, höchstens 5 Minuten.

**Router-Detail.** Kennzahlen (letztes Backup, Versionen, OpenWrt, Zeitplan, nächster Lauf,
Archivweg: Vollarchiv, nur UCI-Snapshot, keiner), dann die Abschnitte:

- **Backup jetzt**: Beschreibung (höchstens 200 Zeichen) und „Jetzt sichern“.
- **Zugang**: Fähigkeiten, SSH-Host-Key bestätigen oder zurücksetzen, Angebot für das
  Router-Recht (nur sichtbar, wenn etwas nötig ist, [Abschnitt 9](#9-berechtigungen-auf-dem-router)).
- **Drift**: Zustand, Zähler (kritisch, nicht einstufbar), „Drift jetzt prüfen“,
  „Unterschiede ansehen“, „Bestätigen“, „Als bekannt markieren“.
- **Offene Freigaben**: begonnene Exporte fortsetzen.
- **Versionen**: Zeitleiste der letzten 30 Tage, Tabelle mit Zeit, Typ/Grund, Größe,
  Prüfsumme (gekürzt, voller Wert beim Daraufzeigen), Prüfzustand, Beschreibung und den
  Aktionen **Prüfen** (Bytes gegen Prüfsumme und Struktur), **Schützen**, **Exportieren**,
  **Wiederherstellung prüfen**, **Vergleichen**.
- **Vergleich**: [Abschnitt 6](#6-diff-ansicht).

**Zustände** (jede Ansicht zeigt sie): Laden; kein Admin (403); Integration nicht geladen
oder Core aus (410/503) mit „Erneut versuchen“; fremdes Backup-Modul beim Core (nur Lesen);
Option aus (Hinweis auf die Router-Optionen); fehlende Rechte oder noch nicht geprüft
(Hinweis auf „Zugang“); SSH-Pin ausstehend oder abweichend (rote Warnung bei Abweichung);
keine Versionen (Knopf „Jetzt sichern“); Backup läuft; Fehler mit Fehlerart und „Erneut
versuchen“; Drift offen oder bestätigt; Freigabe abgelaufen („Neu beantragen“).

## 8. Sensoren und Ereignisse

Je Router, am Gerät des Routers, auch bei ausgeschaltetem Backup. `unique_id` ist
`<Router-ID>_<Schlüssel>`. Die Entitäten lesen nur den Speicher der Integration und rufen nie
einen Router.

| Schlüssel (`translation_key`) | Typ | Wert |
|---|---|---|
| `config_last_backup` | Sensor, Zeitstempel | Zeitpunkt der neuesten brauchbaren Version |
| `config_backup_status` | Sensor, Aufzählung | `ok`, `partial`, `failed`, `running`, `disabled`, `never`; Attribute `error_class`, `last_attempt_at`, `next_run_at` |
| `config_versions` | Sensor, Zähler, Kategorie „Diagnose“ | Zahl gespeicherter Versionen |
| `config_drift` | Binärsensor, Problem | an bei offener, unbestätigter Drift; unbekannt, solange nie geprüft; Attribute `drift_id`, `critical_count`, `unknown_count`, `comparison`, `checked_at` |

Die Namen sind „Last configuration backup“, „Configuration backup status“, „Configuration
versions“ und „Configuration drift“ (deutsch entsprechend). Statuswerte: `failed` heißt, der
letzte Versuch scheiterte nach dem letzten Erfolg; `partial` heißt, die neueste Version ist unvollständig
(zum Beispiel nur der Snapshot nach einem Archivfehler); `never` heißt noch keine Version; `disabled` Backup aus.

**Ereignisse.** Der Manager sendet **keine eigenen Ereignisse**. Er hört auf die Ereignisse
des Cores (Bus-Ereignis `openwrt_router_core_event`, Typ im Feld `type`) mit dem Präfix
`configuration.`, `router.adopted` und `security.config_option_changed`, um Sensoren
aktuell zu halten. Die Core-Typen, die er auslöst oder mitliest:

| Typ | Wann |
|---|---|
| `configuration.backup_created` | nur bei **neuer** Version |
| `configuration.backup_failed` | Fehler, je Fehlerklasse 24 Stunden lang nur gezählt |
| `configuration.backup_recovered` | erstes Gelingen nach Fehlern |
| `configuration.backup_validated` | Prüfung einer Version |
| `configuration.backup_protection_changed` | Schützen / Aufheben |
| `configuration.backup_exported` | ein Export wurde eingelöst |
| `configuration.retention_applied` | Aufbewahrung hat Versionen entfernt |
| `configuration.drift_detected` | neue Drift |
| `configuration.drift_acknowledged` | Drift bestätigt oder als bekannt markiert |
| `configuration.change_critical` | Drift mit kritischer Änderung |
| `configuration.change_unknown` | Drift mit nicht einstufbarer Änderung |
| `configuration.drift_incomplete` | Prüfung konnte nicht alles vergleichen |
| `configuration.restore_checked` | Wiederherstellungs-Prüfung |
| `configuration.integrity_failed` | gespeicherte Datei beschädigt oder fehlt |
| `configuration.storage_swept`, `…storage_limit_exceeded`, `…router_archived` | Ablage |

Ereignisse tragen nur IDs, Zähler und Fingerprints. Beispiel: Benachrichtigung bei kritischer
Drift.

```yaml
triggers:
  - trigger: event
    event_type: openwrt_router_core_event
    event_data:
      type: configuration.change_critical
actions:
  - action: notify.notify
    data:
      message: "Kritische Konfigurationsänderung an einem OpenWrt-Router."
```

## 9. Berechtigungen auf dem Router

Die Standard-ACL der Integration (v8) enthält die Rechte für das Archiv **nicht**. Das Backup
braucht die ACL-Stufe `config_backup_read` mit diesen rpcd-Rechten (alle nur **lesend**):

- `cgi-io: backup` (das Archiv über `cgi-backup`);
- `uci`: die 14 Configs aus [Abschnitt 2](#2-die-drei-artefakte);
- `rpc-sys: packagelist` (Paketliste).

> **Dieses Recht gibt Home Assistant Lesezugriff auf ALLE Geheimnisse des Routers**:
> Passwort-Hashes aller Logins (auch root), SSH-Host-Keys, VPN- und TLS-Schlüssel, WLAN-,
> VPN- und DDNS-Passwörter. Wer den rpcd-Login von Home Assistant nutzen kann, kann sie lesen.

**Nur auf Angebot, nie automatisch.** Die Stufe wird nur angeboten, wenn `config_backup_enabled`
am Router an ist. Auf den Router wird sie erst nach einer ausdrücklichen Einzelfreigabe
geschrieben. Der Ablauf im Panel, Abschnitt „Zugang“:

1. Angebot beantragen. Das Panel zeigt neue und entfallende Rechte sowie die Risiken.
2. Haken setzen („verstanden“) und freigeben. Ein Admin darf seinen eigenen Antrag freigeben;
   die Freigabe gilt 15 Minuten und ist an Router und Inhalt gebunden.
3. Ausführen. Der Core sichert die alte ACL-Datei, schreibt die neue, startet rpcd einmal
   neu, prüft die Fähigkeiten neu und schreibt Befehl und Rückweg (`rollback_command`) in das
   Sicherheits-Log. Eine so verteilte ACL bleibt bei HA-Neustarts erhalten.

Das Schreiben per SSH läuft nur über den gepinnten Weg des Cores ([Abschnitt 11](#11-sicherheitshinweise-und-schutzgrenzen)).

**Was ohne das Recht passiert.**

| Fall | Ergebnis |
|---|---|
| Recht `cgi-io: backup` fehlt, SSH-Benutzer ist `root` | Archiv per SSH |
| Recht fehlt, kein root-SSH | nur UCI-Snapshot (sofern `uci` lesbar ist) |
| nichts lesbar | Fehlerklasse `permission` |
| `cgi-io` nicht installiert | wie „Recht fehlt“, Fehlerklasse `not_available` |

**Pakete.** Für den cgi-Weg brauchen Sie auf dem Router **`cgi-io`** und **LuCI** (die
`cgi-backup`-Verknüpfung legt LuCI an). Die Paketliste liest `rpc-sys packagelist`
(`rpcd-mod-rpcsys`); **`rpc-sys` fehlt auf manchen Geräten**. Dann liest der Manager die Liste
per SSH: `apk list -I` bei OpenWrt 25.12 und neuer, `opkg list-installed` bei älteren. Ohne
Paketliste ist das Inventar `partial`, das Backup selbst gelingt trotzdem.

## 10. Backup und Wiederherstellung (Anleitung)

> **In Phase 1 führt die Integration KEINE Wiederherstellung aus.** Alles unten machen Sie
> selbst auf dem Router. **Jede Wiederherstellung ist nicht automatisch reversibel**: Das
> Einspielen überschreibt die Konfiguration, auch Passwörter, SSH- und TLS-Schlüssel;
> `sysupgrade -r` hat keinen Rückweg. Legen Sie vorher eine aktuelle Sicherung an.

### Export (nur Admin)

Ein Archiv herunterzuladen ist eine kritische Aktion mit Freigabe, weil es alle Geheimnisse
enthält. Im Panel bei der Version „Exportieren“:

1. **Antrag**: Artefakt wählen (Archiv, UCI-Snapshot oder Inventar).
2. **Bestätigung**: Haken „Ich habe verstanden, dass die Datei alle Passwörter und Schlüssel
   im Klartext enthält“, dann freigeben.
3. **Download**: **genau ein** Download je Freigabe. Ein zweites Einlösen scheitert.

Die Freigabe gilt 15 Minuten und geht bei einem HA-Neustart verloren (dann neu beantragen).
Jeder Export steht im Audit-Log (`configuration.backup_exported`). Die Datei heißt
`<Router-ID>-<Versions-ID>-archive.tar.gz`. Vor der Auslieferung rechnet der Server die
SHA-256 neu; weicht sie ab, geht kein Byte hinaus (`backup_integrity_failed`).

### Prüfsumme prüfen

Die SHA-256 steht in der Versionsliste (voller Wert beim Daraufzeigen) und im Antwort-Kopf
`X-Checksum-SHA256` des Downloads. Prüfen Sie die Datei vor dem Einspielen:

```sh
sha256sum rtr_xxxxxxxx-bkp_xxxxxxxx-archive.tar.gz
```

Der Wert muss übereinstimmen. Die Prüfsumme zeigt nur, dass die Datei seit dem Speichern
unverändert ist; sie sagt nichts darüber, ob der Router beim Sichern vertrauenswürdig war.

### Restore-Prüfung im Panel

„Wiederherstellung prüfen“ (nur für Versionen mit Archiv) prüft die Version gegen den Router,
von dem sie stammt, und liest dafür die aktuelle Konfiguration und das Inventar vom Router
(etwa 15 Aufrufe). Das Ergebnis:

- **Blockierend** (Wiederherstellung abbrechen): Archiv ungültig, Prüfsumme stimmt nicht, anderes
  Board, anderes Switch-Modell (swconfig statt DSA oder umgekehrt).
- **Warnungen**: Board oder Release unbekannt, älteres Release (Downgrade), Wechsel der
  Hauptversion, Firewall-Wechsel fw3 → fw4, anderer Paketmanager (opkg/apk), fehlende Pakete,
  unbekannte Paketliste, unvollständiges Inventar, **Aussperr-Risiko** (Änderungen an
  Management-IP, VLAN, Firewall oder SSH/uhttpd/rpcd), Passwort-, SSH- und TLS-Dateien im
  Archiv (der Login kann sich ändern), nicht vergleichbare Configs.
- **Vorschau**: die Unterschiede „aktueller Stand → Archiv“ (maskiert), betroffene Bereiche,
  ob ein Neustart nötig ist und ob die Verbindung abbrechen kann.

### Manuelle Wiederherstellung, Schritt für Schritt

1. Restore-Prüfung ansehen. Bei „Nicht kompatibel“ **abbrechen**.
2. Eine **aktuelle Sicherung** des jetzigen Stands anlegen und exportieren.
3. Ändert die Prüfung Zugang, Management-IP oder Firewall-Eingang: **Konsole oder
   Failsafe-Modus bereithalten** (unten).
4. Fehlende Pakete vorher auf dem Router installieren (`apk add …` bei OpenWrt 25.12,
   `opkg install …` bei älteren; Paketnamen können sich unterscheiden).
5. Archiv exportieren, Prüfsumme prüfen.
6. Einspielen, **eine** der Möglichkeiten:
   - **LuCI:** System → Sichern/Aktualisieren (Backup / Flash Firmware) → Sicherung
     wiederherstellen (Restore backup), Archiv hochladen. Auf englischer Oberfläche:
     System → Backup / Flash Firmware.
   - **Kommandozeile:** Archiv per `scp` auf den Router kopieren, dann
     `sysupgrade -r /tmp/backup.tar.gz` und anschließend `reboot`.
7. Der Router startet neu. WLAN und Netzwerk fallen kurz aus.

### Prüfliste danach

- Der Router antwortet (Ping, LuCI-Anmeldung).
- Management-IP und Zugang (SSH, LuCI) sind wie erwartet; Passwort und Schlüssel können sich
  geändert haben, weil das Archiv sie überschreibt.
- Interfaces und Uplink: WAN verbunden, Internet erreichbar.
- Dienste: WLAN sendet, Clients verbinden sich, DHCP und DNS arbeiten.
- VLANs und Firewall-Zonen verhalten sich wie vorher.
- Die Integration in Home Assistant ist wieder verbunden.
- **Konfiguration entspricht dem Erwarteten:** im Panel „Drift jetzt prüfen“. Der Router muss
  zur eingespielten Version passen (ohne Unterschiede oder nur die, die Sie erwarten). Ein
  Host-Key-Wechsel nach der Wiederherstellung ist möglich (SSH-Pin neu bestätigen).

### Wenn Sie ausgesperrt sind

Der Router lässt sich über das Netzwerk nicht mehr erreichen:

1. **Failsafe-Modus:** Router neu starten und beim Start die Reset-Taste (oder die für das
   Gerät dokumentierte Taste) drücken, bis die LED schnell blinkt. Der Router kommt mit
   Standard-Adresse und ohne Passwort hoch; verbinden Sie einen Rechner direkt per Kabel.
   Dann `mount_root` und die Konfiguration unter `/etc/config/` von Hand korrigieren.
2. **Serielle Konsole:** Haben Sie eine, ist sie der sicherste Weg: Fehler in `/etc/config/`
   beheben oder den Failsafe-Modus von dort steuern.
3. **Werksreset als letzter Ausweg:** im Failsafe-Modus `firstboot` und `reboot`. Das löscht
   die gesamte Konfiguration; danach das Archiv erneut einspielen oder neu einrichten.

Die genaue Taste, die Standard-Adresse und das Verhalten sind gerätespezifisch; die
OpenWrt-Seite zu Failsafe und Werksreset und die Geräteseite sind maßgeblich. Das hier ist
eine Gedächtnisstütze, keine Anleitung für Ihr Gerät.

## 11. Sicherheitshinweise und Schutzgrenzen

- **Archive enthalten Geheimnisse im Klartext**: WLAN-Passwörter, Schlüssel, Passwort-Hashes.
- **Keine eigene Verschlüsselung in Phase 1.** Der Schutz besteht aus Dateirechten, dem
  abgeschotteten Ordner und der Verschlüsselung Ihrer HA-Backups.
- **Ablage:** `<HA-Konfigurationsordner>/openwrt_router/config_backups/<Router-ID>/`, Ordner
  mit Modus `0700`, Dateien mit `0600` (wo das Dateisystem Unix-Rechte kennt), atomar
  geschrieben. **Nicht** unter `www`; der Ordner wird nie über HTTP ausgeliefert.
- **Wer Zugriff auf das HA-Dateisystem oder auf HA-Backups hat, kann die Archive lesen.**
  Home Assistant Backups enthalten den Konfigurationsordner normalerweise mit: **verschlüsseln
  Sie HA-Backups** und behandeln Sie sie wie ein Passwort.
- **Nur Admins.** Alle Routen des Managers verlangen Anmeldung und Admin-Rechte (403 sonst),
  Antworten tragen `Cache-Control: no-store`. Benutzer-IDs verlassen die Integration nur als
  Pseudonym.
- **Maskierung auf dem Server**, nie im Browser: Antworten, Logs, Ereignisse und Diagnose
  zeigen keine Geheimwerte.
- **Nichts geht an externe Dienste.** Der Manager spricht nur mit Ihren Routern.
- **Archivprüfung ohne Entpacken.** Ein Archiv wird nie auf die Platte entpackt. Es wird im
  Speicher geprüft: relative Pfade ohne `..`, NUL, Steuerzeichen und Backslashes; nur
  reguläre Dateien, Verzeichnisse und Symlinks; Symlinks nur innerhalb des Archivs oder auf
  Laufzeitpfade des Routers (`/etc/`, `/usr/`, `/lib/`, `/tmp/`, `/var/`, `/proc/mounts`),
  kein Mitglied unterhalb eines Symlinks; Größen: höchstens 16 MiB komprimiert, 64 MiB
  entpackt, 16 MiB je Datei, 5000 Mitglieder, Verhältnis höchstens 200:1 (ab 1 MiB entpackt),
  Namen höchstens 255 Zeichen. Es müssen `network` und `system` darin sein, sonst
  `incomplete`.
- **SSH-Host-Key-Pinning, ehrlich:** Der Core liefert gepinntes SSH (der erste gesehene Key
  ist *ausstehend*, bis ein Admin ihn bestätigt; ein abweichender Key wird immer abgelehnt;
  Zurücksetzen nur ausdrücklich). Es gilt für das **Schreiben der ACL** und den gepinnten
  Weg des Cores. **Die SSH-Zugriffe des Managers selbst (Archiv per `sysupgrade`, `uci show`
  und Paketliste) laufen über die gemeinsame SSH-Verbindung der Integration, die den Host-Key
  nicht prüft** (`known_hosts=None`, wie der SSH-Fallback des Polls). Wer im LAN zwischen Home
  Assistant und Router sitzt, könnte dort das SSH-Passwort abgreifen oder ein gefälschtes
  Archiv liefern, das in sich gültig ist. Bevorzugen Sie den cgi-Weg mit **HTTPS** und
  nutzen Sie den SSH-Rückfall nur in einem vertrauenswürdigen Netz. Das Panel zeigt zwar
  den Pin-Zustand und erlaubt Bestätigen/Zurücksetzen, schützt damit aber diesen SSH-Weg
  nicht (siehe [Abschnitt 13](#13-bekannte-einschränkungen)).
- **Installations-Schlüssel:** Die HMAC-Prüfwerte der Geheimwerte im Snapshot hängen am
  Schlüssel `.storage/openwrt_router.installation_key`. Geht er verloren, lassen sich Geheimwerte
  alter und neuer Versionen nicht mehr vergleichen (Reparatur-Hinweis, Neuanlage nur durch
  einen Admin mit Freigabe).

## 12. Last für Router und Home Assistant

Zahlen aus dem Code gezählt (Router-Aufrufe je Router; die Anmeldung zählt nicht mit):

| Posten | Router-Aufrufe |
|---|---|
| **Ausgeschaltet** (`config_backup_enabled` aus) | **0** |
| Takt, Fingerprint-Vergleich, Release-Vergleich | 0 |
| **Tageslauf** (Archiv + 14 UCI-Configs + Paketliste) | **etwa 16** |
| Drift-Prüfung (14 UCI-Configs) | etwa 14 |
| Drift-Version (14 UCI-Configs + Paketliste, kein Archiv) | etwa 15 |
| Release-Wechsel-Lauf | etwa 16 |
| Restore-Prüfung im Panel (14 UCI-Configs + Paketliste) | etwa 15 |
| Vergleich Version ↔ aktueller Stand, „Als bekannt markieren“ | etwa 14 und ein Backup-Lauf |
| Probe der Fähigkeiten (Einrichtung, ACL-Verteilung, Firmware-Wechsel; nie im Poll) | etwa 16 |
| **Lesende Panel-Routen** (Übersicht, Detail, Versionen, Drift-Stand, Freigaben, Prüfen, Schützen, Bestätigen) | **0** |

- Obergrenzen je Router und Tag: **höchstens 24 automatische Drift-Prüfungen** (höchstens
  eine je Stunde) und **höchstens 4 Drift-Versionen**. Damit liegt die Obergrenze bei rund
  430 Aufrufen je Router und Tag (16 + 24 × 14 + 4 × 15 + 16 für einen Release-Wechsel);
  im Alltag ein Lauf plus null bis zwei Prüfungen, also grob 16 bis 45.
- Fehlen die `uci`-Rechte im ubus, liest der Manager jede Config per SSH (ein Kanal je
  Config statt ein ubus-Aufruf).
- Läufe gehen immer einzeln; eine Operation hat höchstens 180 s Gesamtzeit (cgi 60 s,
  SSH 120 s je Archiv).
- **Home Assistant:** Ein Archiv (höchstens 16 MiB) und seine Prüfung liegen kurz im
  Arbeitsspeicher; die Prüfung läuft im Executor, nicht im Event-Loop. Auf der Platte
  braucht jeder Router bis zu 50 MiB (insgesamt 250 MiB).

**Nicht gemessen:** Laufzeit und Größe eines echten `sysupgrade -b` wurden **nicht an
Geräten gemessen**; ebenso nicht die Belastung eines Routers während des Archivs. Die Zeit-
und Größenangaben oben sind Grenzwerte aus dem Code, keine Messwerte.

## 13. Bekannte Einschränkungen

**Nicht unterstützt in Phase 1:**

- **Keine automatische Wiederherstellung**, weder des Archivs noch auf UCI-Ebene. Kein
  Rollback. (Geplant als spätere Phase, siehe `TODO.md`.)
- **Restore nur auf den Router, von dem die Version stammt.** Das Panel prüft immer gegen
  den eigenen Router; ein Restore auf ein anderes Modell oder eine andere Hardware ist
  nicht vorgesehen. Die Prüfung **blockiert** bei anderem Board, anderem Switch-Modell
  (swconfig/DSA), ungültigem Archiv und falscher Prüfsumme; sie **warnt** bei unbekanntem Board
  oder Release, Downgrade, Wechsel der Hauptversion, fw3 → fw4, anderem Paketmanager, fehlenden
  Paketen, unbekannter Paketliste, unvollständigem Inventar und Aussperr-Risiko.
- **Kein Archiv ohne LuCI (`cgi-io`) und ohne root-SSH**; dann nur der UCI-Snapshot.
- **Kein Konfigurationsvergleich zwischen verschiedenen Routern.** Das Panel vergleicht nur
  Versionen desselben Routers (und die eigene Version mit dem aktuellen Stand); eine fremde
  Version im Pfad wird mit „nicht gefunden“ abgelehnt.
- **Zu große Configs:** Ein UCI-Text über 1 MiB (`uci show` oder `etc/config/<name>` im
  Archiv) wird nicht ausgewertet und als zu groß gemeldet. Mehrzeilige Werte werden
  unterstützt, solange die Grenze hält.
- **Beschreibung nur beim Anlegen:** Sie lässt sich später nicht ändern.
- **Kein Löschen im Panel.** Versionen verschwinden nur durch die Aufbewahrung (oder den
  Core).
- **Freigaben gehen bei einem HA-Neustart verloren;** das Panel beginnt dann neu.
- **Management-Interface per DHCP oder Hostname** wird streng bewertet: Jede Adressänderung
  an einem Nicht-Uplink-Interface gilt als kritisch (kann zu vielen kritischen Meldungen führen).
- **Freier Platz auf dem Router:** Die Warnung „zu wenig Platz“ ist in der Restore-Prüfung
  vorgesehen, aber der Manager liest den freien Platz nicht aus; sie erscheint derzeit nicht.
- **Größenlimit der Aufbewahrung (Core):** Eine gute geplante Version kann früher fallen als
  nötig ([Abschnitt 4](#4-versionen-dedup-und-aufbewahrung); als Test festgehalten).
- **SSH ohne Host-Key-Prüfung** im Weg des Managers ([Abschnitt 11](#11-sicherheitshinweise-und-schutzgrenzen)).
- **Automatische Drift-Prüfung** nur bei Änderungen, die der Fingerprint zeigt
  ([Abschnitt 5](#5-drift-erkennung)).
- **Dedup braucht byte-gleiche Dateien** ([Abschnitt 4](#4-versionen-dedup-und-aufbewahrung)).
- **Nicht an echten Routern gemessen** und das Panel nicht im echten Home Assistant gesehen
  (nur Entwicklungs-Mock und Tests): Laufzeit und Größe von `sysupgrade -b`, Verhalten
  auf realer Hardware.

## 14. Fehlerklassen

Das Panel und der Sensor `config_backup_status` nennen die Klasse als `error_class`.

| Klasse | Bedeutung | Was tun |
|---|---|---|
| `unreachable` | Router nicht erreichbar | Netz, Strom und `uhttpd`/`rpcd` prüfen; ein Nachversuch kommt nach 15 Minuten von allein. |
| `timeout` | Zeitüberschreitung beim Router | Router auslasten lassen und später erneut versuchen; bei großem Archiv `sysupgrade` auf dem Router prüfen. |
| `auth` | Anmeldung am Router fehlgeschlagen | Benutzer und Passwort der Integration prüfen (Neu-Anmeldung der Integration). |
| `permission` | Recht fehlt (rpcd-ACL oder SSH-Benutzer nicht root) | Angebot `config_backup_read` im Panel („Zugang“) freigeben oder root-SSH einrichten ([Abschnitt 9](#9-berechtigungen-auf-dem-router)). |
| `not_available` | Weg oder Funktion nicht vorhanden (zum Beispiel kein `cgi-io`) | `cgi-io` und LuCI installieren, sonst reicht der UCI-Snapshot. |
| `too_large` | Archiv über 16 MiB oder UCI-Text über 1 MiB | Unnötige Dateien aus der Sicherung nehmen (`/etc/sysupgrade.conf`) oder Konfiguration verkleinern. |
| `incomplete` | Antwort unvollständig oder Archiv ohne Pflicht-Configs | Erneut versuchen; tritt es wieder auf, Router-Speicher und `sysupgrade -b` von Hand prüfen. |
| `invalid` | Archiv oder Dokument ungültig (Pfade, Symlinks, Größen) | Version nicht verwenden; Router und Archiv prüfen, neue Version anlegen. |
| `checksum_mismatch` | Gespeicherte Datei stimmt nicht mehr mit ihrer Prüfsumme überein | Version nicht verwenden, Datenträger prüfen, neue Version anlegen. |
| `storage_full` | Speicherlimit für Versionen erreicht | Nicht mehr benötigte Schutz-Markierungen aufheben, Aufbewahrung abwarten oder Limit beim Core beachten. |
| `storage_error` | Speichern auf der Platte scheiterte | Platz und Rechte des Konfigurationsordners prüfen. |
| `busy` | Es läuft schon ein Lauf (Panel: 409, Wiederholung nach 30 s) | Warten; der Takt versucht es neu. |
| `denied` | Der Core hat die Aktion abgelehnt (kein Admin) | Mit einem Admin-Benutzer wiederholen. |
| `approval` | Freigabe fehlt, abgelaufen oder schon eingelöst | Neu beantragen. |
| `incompatible` | Version passt nicht zum Router (Restore-Prüfung blockiert) | Nicht wiederherstellen; Befunde ansehen. |

Weitere Klassen (`not_found`, `conflict`, `unsupported_version`, `internal`) stammen vom Core
und stehen in `docs/dev/configuration-api-v1.md`.
