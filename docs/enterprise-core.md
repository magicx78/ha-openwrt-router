# Enterprise Core

<!-- Nutzerdoku ab 1.44.0. Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens.
     Vertrag für Entwickler: docs/dev/configuration-api-v1.md; ACL: docs/dev/acl-tiers.md. -->

## Was es ist

Der Enterprise Core ist ein interner Unterbau der Integration, ab Version 1.44.0. Er gibt
jedem Router eine feste Kennung, merkt sich, was ein Router kann, prüft kritische Aktionen
über Freigaben und schreibt ein Audit-Log. Spätere Module bauen darauf auf: das
Konfigurations-Backup (`config-manager`), das Security Center, die Netzwerkdiagnose und
WiFi RF.

**Was sich für bestehende Installationen ändert:** Core-Ereignisse
(`openwrt_router_core_event`) erscheinen im Logbuch, beim ersten Start einmal
`router.registered` je Router, und im Recorder. Sonst:

- keine neue Entität, keine geänderte `unique_id`, keine geänderte Geräte- oder Entity-ID,
  keine neue Version des Config-Entries, nichts zu migrieren;
- **0 zusätzliche Router-Aufrufe je Poll.** Der Core liest nur, was der Poll ohnehin holt;
- ein Fehler im Core lässt weder einen Poll noch das Einrichten eines Routers scheitern; er
  steht im Log;
- auf den Router wird nichts geschrieben, solange kein Admin es ausdrücklich freigibt.

Der Core legt diese Dateien unter `.storage/` an: `openwrt_router.router_registry`,
`openwrt_router.audit`, `openwrt_router.config_catalog`, `openwrt_router.ssh_host_keys`
und, erst wenn ein Backup-Modul ihn braucht, `openwrt_router.installation_key`.

## Router-Identität

Jeder Config-Entry bekommt eine Router-ID der Form `rtr_` plus 32 Hex-Zeichen. Sie wird aus
der `entry_id` abgeleitet, ohne den Router zu fragen; derselbe Eintrag hat nach einem
Neustart, nach einem verlorenen Store oder nach dem Wiederherstellen eines HA-Backups
dieselbe ID. Dazu merkt sich der Core einen Fingerabdruck aus Daten des Polls (MAC-Adressen,
Modell, Board, Firmware).

| Fall | Was passiert | Status |
|---|---|---|
| Neu eingerichtet, noch kein Poll | ID sofort vorhanden | `unverified` |
| **IP-Wechsel** (gleicher Eintrag, neuer Host) | ID bleibt, Event `router.identity_changed` (Info) | `confirmed` |
| **Hostname-Wechsel** | ID bleibt, Event `router.identity_changed` (Info) | `confirmed` |
| **Werksreset** (Hostname wieder „OpenWrt“, gleiche MACs und gleiches Board) | ID bleibt, Event (Info) | `confirmed` |
| **Hardwaretausch** (anderes Board oder keine gemeinsame MAC) | ID bleibt am Eintrag, Event `router.identity_changed` (Warnung) | `changed` |
| **Duplikat** (zwei Einträge teilen MACs) | beide werden markiert, Event `router.duplicate_suspected`; **nie** automatisch zusammengelegt | `duplicate_suspected` |
| **Eintrag gelöscht und neu angelegt** | der neue Eintrag bekommt eine neue ID; die alte wird `orphaned` und ist Kandidat für eine **Adoption** | – |
| **Adoption** | nur ein Admin-Benutzer, auf ausdrücklichen Befehl: der neue Eintrag übernimmt die alte ID; steht im Audit-Log | `confirmed` |

Mehrere Zweifel können gleichzeitig gelten; angezeigt wird der wichtigste (`changed` vor
`duplicate_suspected` vor `unverified`).

## Capabilities

Je Router hält der Core eine Liste von Fähigkeiten mit Zustand (`available`, `unavailable`,
`unknown`), Grund und Zeitpunkt. Sie werden nur neu bewertet, wenn sich die Poll-Daten
ändern, die sie betreffen.

| Präfix | Woher | Beispiele |
|---|---|---|
| `transport.`, `data.`, `stream.`, `pkg.` | Core, aus den Poll-Daten | `transport.ubus`, `data.wireless`, `pkg.apk` |
| `config.` | Backup-Modul (Provider) | `config.backup`, `config.restore` |
| `rf.` | Core für `rf.txpowerlist`, `rf.survey`, `rf.scan` (aus der verteilten rpcd-ACL); sonst Modul WiFi RF | `rf.scan` |
| `security.` | Modul Security Center | `security.firewall_audit` |
| `diag.` | Modul Netzwerkdiagnose | `diag.traceroute` |
| `log.` | gemeinsam für mehrere Module | – |

- **`config.*` ohne Backup-Modul:** Es ist kein Backup-Modul eingebaut. Alle `config.*`
  sind `unavailable`, bis eines installiert ist; der Core ruft dafür nie den Router.
- **Option `config_backup_enabled`** (Standard **aus**, in den Optionen des Routers):
  aus heißt `config.*` = `disabled`, das Backup-Modul wird für diesen Router nie aufgerufen,
  und die ACL-Stufe `config_backup_read` wird nicht angeboten. Der Schalter erscheint erst,
  wenn ein Backup-Modul installiert ist (oder solange er an ist). Er wirkt sofort, ohne
  Neuladen. Achtung: ein Konfigurations-Backup enthält **alle** Router-Geheimnisse,
  darunter `/etc/shadow` (Passwort-Hashes aller Router-Logins) und private Schlüssel
  (SSH-Host-Keys, VPN- und TLS-Schlüssel).
- **`rf.*` aus der ACL:** Mit der normalen ACL (v8) ist `rf.scan` verfügbar;
  `rf.txpowerlist` und `rf.survey` sind `unavailable` mit Grund `permission_denied` und der
  Liste der fehlenden Rechte. Ist die ACL unbekannt (noch nicht gelesen, nicht lesbar),
  stehen alle drei auf `unknown` mit Begründung.
- Die Capability-Ansicht der Registry kann bis zum nächsten Poll nachlaufen (zum Beispiel
  direkt nach einem Neustart oder einer ACL-Verteilung).

## Freigaben

Kritische Aktionen laufen in zwei Schritten: Antrag, dann Freigabe durch einen
Admin-Benutzer, dann genau **eine** Ausführung durch den Antragsteller. Die Freigabe gilt
15 Minuten und ist an Router und Prüfsumme gebunden (eine andere ACL, ein anderer
Host-Key oder ein anderer Router passt nicht). Automationen dürfen keine kritische Aktion
auslösen, Nicht-Admins gar keine schreibende. Ein Admin darf seinen eigenen Antrag
freigeben (bewusste Bestätigung, kein Vier-Augen-Prinzip). Offene Anträge überleben keinen
Neustart von Home Assistant.

| Aktion | Was sie tut |
|---|---|
| `export` | gespeicherte Backup-Datei herunterladen |
| `delete` | Backup-Versionen löschen |
| `acl_deploy` | gestufte rpcd-ACL auf den Router schreiben |
| `ssh_pin_confirm` | erstmals gesehenen SSH-Host-Key eines Routers bestätigen |
| `ssh_pin_reset` | gespeicherten SSH-Host-Key eines Routers vergessen |
| `installation_key_reset` | verlorenen Installations-Schlüssel neu anlegen |

Heute gibt es diese Anträge nur über die Python-Schnittstelle für Module; eine Oberfläche
dafür kommt mit dem ersten Modul, das sie braucht.

### Gestufte ACL (nur Angebot)

Die Integration schreibt beim Start wie bisher ihre rpcd-ACL v8. Zusätzliche Rechte (zum
Beispiel für Funkkanal-Messungen) gibt es nur als **Angebot**: ein Admin beantragt die
Stufen, sieht Unterschied und Risiken, gibt frei. Dann sichert der Core die alte Datei,
schreibt die neue, startet rpcd einmal neu, prüft die Capabilities neu und schreibt
Befehl und Rückweg (`rollback_command`) ins Sicherheits-Log. Eine so verteilte ACL bleibt
bei jedem HA-Neustart erhalten; sie wird nicht mehr auf v8 zurückgesetzt. Muss das
Schreiben über SSH laufen, dann nur über den gepinnten Weg (unten); ohne bestätigten
Host-Key wird abgelehnt.

### SSH-Host-Key-Pinning

Für das Backup und das ACL-Schreiben per SSH merkt sich der Core je Router den Host-Key.

- **Erster Kontakt:** der Key wird *ausstehend* gespeichert, der Befehl läuft **nicht**.
  Event `security.ssh_pin_pending`. Bis ein Admin den Key bestätigt (`ssh_pin_confirm`),
  wird jeder weitere Versuch abgelehnt, ohne den Router zu kontaktieren. Der erste Kontakt
  liest nur den Host-Key über eine Verbindung ohne Zugangsdaten und endet vor der
  Anmeldung; Passwort oder Schlüssel gehen erst an einen bestätigten Key.
- **Abweichender Key:** immer abgelehnt, vor der Anmeldung, Event
  `security.ssh_pin_mismatch` (kritisch). Kein Rückfall auf ungeprüftes SSH.
- **Router neu installiert:** Key mit `ssh_pin_reset` vergessen, beim nächsten Kontakt neu
  bestätigen.
- Der bisherige SSH-Fallback des Polls bleibt unverändert.

## Audit-Log

Zwei Ringe im Store `openwrt_router.audit`: allgemein (höchstens 1000 Einträge) und
Sicherheit (500 Einträge, alles mit `security.`), je höchstens 90 Tage. Jeder Eintrag geht
auch als HA-Event auf den Bus. Einträge enthalten nur IDs, Zähler und Fingerprints, keine
IP-Adressen, Hostnamen oder Geheimnisse. Wiederholte Fehler werden 24 Stunden lang nur
gezählt, nicht erneut gemeldet; Pflicht-Einträge (Freigaben, Export, Löschen, ACL,
SSH-Pins) werden immer einzeln geschrieben.

## Versionsspeicher (für ein späteres Backup-Modul)

- Ablage unter dem HA-Konfigurationsordner, nie unter `www`; höchstens 50 MB je Router,
  250 MB gesamt.
- Aufbewahrung GFS: 7 Tage, 4 Wochen, 6 Monate. Manuelle Versionen und Versionen vor einer
  Änderung (`pre_*`) werden nie ausgedünnt; muss das Größenlimit sie entfernen, nennt das
  Ergebnis sie einzeln.
- Eine geplante Version, die der letzten gleicht, wird nur dann nicht neu gespeichert,
  wenn die Dateien byte-gleich sind.
- Wird ein Router aus HA entfernt, verschiebt der Core seine Versionen nach
  `removed/<router_id>/` und protokolliert das.

## Grenzen

- Der Core selbst enthält kein Backup-Modul; das liefert der Configuration Manager
  (seit 1.45.0, siehe [configuration-manager.md](configuration-manager.md)). Ist er aus,
  sind alle `config.*` nicht verfügbar.
- Freigaben und SSH-Pins bedient das Panel „Enterprise → Konfiguration“ des Configuration
  Managers (siehe [configuration-manager.md](configuration-manager.md)); der Core selbst
  bringt keine eigene Oberfläche mit.
- `rf.*` sieht nur die ACL-Datei der Integration, keine anderen Dateien in
  `/usr/share/rpcd/acl.d/`.
- Klartext-Backups auf der HA-Platte: Schutz nur über Dateirechte und die
  HA-Backup-Verschlüsselung.
- Nach einer Adoption holt der Core archivierte Versionen aus `removed/` nicht
  automatisch zurück.
