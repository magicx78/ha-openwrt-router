# Self-Healing (Phase 7; Paket B: Zustandsmaschine, Datenmodell, Speicher)

<!-- Entwicklerdoku zu Phase 7 „Enterprise Self-Healing & Automated Remediation“, Stand
     Paket B (Branch feature/self-healing-b, 2026-11-27). Gebaut sind nur
     heal_model.py und heal_store.py und die Kennung `rem_` in core_models.py. Aussagen zu
     Paket B sind am Code gelesen und mit tests/test_heal_model_v1530.py und
     tests/test_heal_store_v1530.py geprüft (FakeDisks, ein Test schreibt eine echte Datei mit
     HAs Store); nicht auf Routern, nicht in einer laufenden HA-Instanz. Alles andere in dieser
     Datei ist **Plan** und als solcher markiert: Jeder Abschnitt hat eine Zeile
     „Stand heute“. Keine IPs, MACs, Hostnamen, Client-Namen, Passwörter oder Tokens;
     Router-Kennungen in Beispielen sind Platzhalter. -->

## Inhalt

1. [Worum es geht und was heute da ist](#1-worum-es-geht-und-was-heute-da-ist)
2. [Modulaufbau](#2-modulaufbau)
3. [Datenmodell](#3-datenmodell)
4. [Zustände und Übergänge](#4-zustände-und-übergänge)
5. [Speicher, Neustart, Grenzen, Versionen](#5-speicher-neustart-grenzen-versionen)
6. [Die eine Sicherheitskette](#6-die-eine-sicherheitskette)
7. [Geschlossener Katalog der Aktionen](#7-geschlossener-katalog-der-aktionen)
8. [Playbooks A–G](#8-playbooks-ag)
9. [Entscheidung und Konfidenz](#9-entscheidung-und-konfidenz)
10. [Modi, Wartung, Schleifenschutz](#10-modi-wartung-schleifenschutz)
11. [HTTP-API, Entitäten, Ereignisse, Dienste](#11-http-api-entitäten-ereignisse-dienste)
12. [Time Machine, Audit, Security Center, KI-Berater](#12-time-machine-audit-security-center-ki-berater)
13. [Dashboard „Self-Healing Center“](#13-dashboard-self-healing-center)
14. [Bedrohungsmodell](#14-bedrohungsmodell)
15. [Arbeitspakete und Releases](#15-arbeitspakete-und-releases)
16. [Entscheidungen des Eigentümers und offene Fragen](#16-entscheidungen-des-eigentümers-und-offene-fragen)
17. [Tests und was nicht geprüft ist](#17-tests-und-was-nicht-geprüft-ist)

---

## 1. Worum es geht und was heute da ist

Self-Healing soll Störungen, die Network Intelligence als Vorfall erkennt, **erklären**, eine
passende Reparatur **vorschlagen**, sie vor jedem Schritt **prüfen** und erst ganz am Ende –
und nur in engen Grenzen – **ausführen**. Oberste Regel: Eine missglückte Reparatur darf nie
einen größeren Ausfall verursachen als die Störung selbst.

**Ehrlich vorweg:**

- **Es gibt keinen automatischen Rollback.** Auf den Routern ist kein bestätigtes Commit in
  Gebrauch, es gibt keinen Watchdog und keinen zweiten Zugangsweg. Die Rollback-Zustände
  stehen im Modell, damit der Ablauf vollständig beschrieben ist; erreichbar macht sie kein
  Produktivcode, und die einzige Mechanismusart im Modell ist `none`
  (`RollbackMechanism.NONE`).
- **Wiederherstellen einer Konfiguration ist nur ein Probelauf.** Der Configuration Manager
  kann eine Wiederherstellung planen und prüfen (`async_prepare_restore`), aber nicht
  ausführen; Self-Healing ändert daran nichts.
- Ausführen soll Self-Healing deshalb nur Aktionen, deren Fehlschlag **begrenzt** bleibt: einen
  einzelnen Dienst-Neustart, der keine Konfiguration ändert (ab 1.54.0, Abschnitt 15). Alles,
  was Konfiguration, Schnittstellen oder Firmware ändert oder den Router neu startet, bleibt
  eine Empfehlung oder ist modelliert und gesperrt.

**Stand heute (Paket B):** Es gibt das Datenmodell mit der Zustandsmaschine
(`heal_model.py`), den Speicher (`heal_store.py`) und die Kennung `rem_`
(`core_models.REMEDIATION_ID_PREFIX`). Beides ist **nicht verdrahtet**: Kein Code in
`__init__.py` lädt den Speicher, es gibt keinen Router-Aufruf, keine Route, keine Entität,
keinen Listener, keine Datei auf der Platte einer Installation. Ein Update auf einen Stand mit
Paket B ändert für Benutzer nichts.

## 2. Modulaufbau

Geplant ist **eine** Instanz für die ganze Flotte je HA-Installation, verdrahtet wie Security
Center und Netzwerkdiagnose (am Ende von `__init__.py` um `async_setup_entry` und
`async_unload_entry` gelegt; der erste Eintrag erzeugt sie, das Entladen des letzten gibt sie
frei).

| Datei | Art | Aufgabe | Stand heute |
|---|---|---|---|
| `heal_model.py` | rein (ohne HA) | Zustände, die eine Übergangstabelle, `RemediationAction`, Neustartregel, Schleifenschutz-Daten, Einstellungen, Wartungsfenster; `transition()` ist der einzige Weg, einen Zustand zu ändern | **gebaut** (Paket B) |
| `heal_store.py` | async | Store `openwrt_router.self_healing`, Schreiben vor dem Handeln, Grenzen | **gebaut** (Paket B) |
| `heal_catalog.py` | rein | geschlossene Liste typisierter Aktionen | Plan (Paket D) |
| `heal_policy.py` | rein | Risiko, Konfidenz, die fünf Ergebnisse, Modi, Allowlist, Schutzschalter | Plan (D, I) |
| `heal_preflight.py` | rein + async | Vorabprüfungen aus vorhandenen Daten, **kein Router-Aufruf** | Plan (E) |
| `heal_playbooks.py` | rein | Playbooks A–G als versionierte Daten | Plan (F, G) |
| `heal_verify.py` | rein + async | Ergebnisklassen aus späteren Polls | Plan (H) |
| `heal_engine.py` | async | Ablauf, Sperren, Warteschlange, Zeitgeber, Neustart | Plan (C1, I) |
| `heal_views.py` | HTTP | Routen (Abschnitt 11) | Plan (C1, C2) |
| `heal_entities.py` | HA | nur lesende Entitäten | Plan (K) |
| `heal_executor.py` | async | **das einzige Modul, das schreibend einen Router aufruft** | Plan (C2, 1.54.0) |
| `api.py` (Ergänzung) | – | `restart_service_typed(name)` mit fester Dienstliste | Plan (C2, 1.54.0) |
| `frontend/…/enterprise/selfhealing/` | TS | Tab „Self-Healing“ | Plan (J) |

Namen (aus dem Entwurf übernommen): Modul `self_healing`, Dateien `heal_*.py`, Store-Schlüssel
`openwrt_router.self_healing`, Audit-Präfix `self_healing.`, Routen unter
`/api/openwrt_router/enterprise/selfhealing/v1/`. In Paket B gibt es davon nur den
Store-Schlüssel; er steht in `heal_store.py` (nicht in `const.py`), wie bei der Time Machine.

## 3. Datenmodell

Ein Datensatz `RemediationAction` je Reparaturversuch (`heal_model.py`). Alle Teile sind
unveränderliche Dataclasses (`frozen=True`); jede Änderung erzeugt einen neuen Datensatz.
`to_dict()`/`from_dict()` prüfen jedes Feld; ein ungültiges Feld wirft `HealModelError`, und
die Meldung nennt nur den Feldnamen, nie den Wert.

| Feld | Inhalt |
|---|---|
| `action_id` | `rem_` + 32 hex |
| `router_id` | `rtr_` + 32 hex (die Router-Kennung des Enterprise Core) |
| `state`, `history` | Zustand und Verlauf (Abschnitt 4); fest: nur `transition()` ändert sie |
| `created_at`, `updated_at` | Wanduhr in Sekunden, auf Millisekunden gerundet; `updated_at` = Zeitpunkt des letzten Übergangs |
| `action_type`, `params` | Katalog-Kennung (Kleinbuchstaben, Punkte) und Parameter: höchstens 8 Schlüssel, nur Zahlen, Wahrheitswerte, kurze Wörter oder Listen davon |
| `incident_id`, `incident_type`, `incident_reopen` | Wurzelvorfall von Network Intelligence und wie oft er wieder geöffnet wurde |
| `components` | höchstens 16 typisierte Bauteile, z. B. `{"kind": "service", "name": "dnsmasq"}` |
| `cause` | `{code, status, level, confidence, source_families}` – von Network Intelligence übernommen, hier nie neu berechnet |
| `playbook_id`, `playbook_version` | welches Playbook in welcher Fassung |
| `decision` | Ergebnis (eines von fünf), `score`, `factors[]` (`{factor, value, reason}`), `why`, `why_not` |
| `risk` | `{risk_class 0..3, reasons[]}` |
| `prerequisites`, `planned_changes`, `expected_impact` | Listen; Auswirkung `{clients_on_router, clients_on_component, dependants (Router-Kennungen), est_outage_s}` – Zahlen, keine Client-Namen |
| `preflight` | Liste `{check, outcome pass/fail/unknown, reason}` |
| `approval` | `{status, guard_approval_id (apr_…), binding_hash, requested_by, decided_by, expires_at}`; `requested_by`/`decided_by` sind **Akteursarten**, keine Benutzer |
| `backup_ref` | `{version_id (bkp_…) oder null, reason}`; für einen Dienst-Neustart `null` mit `not_needed_no_config_change` |
| `execution` | `{attempt_no, intent_written_at, call_started_at, call_finished_at, call_result ok/rejected/inconclusive}` |
| `verification` | `{result resolved/partial/not_resolved/unknown/new_fault, before{}, after{}, checks[]}`; `before`/`after` höchstens 32 Schlüssel, Listen höchstens 32 Einträge |
| `rollback` | `{mechanism, statement, status}`; `mechanism` ist immer `none` |
| `audit_refs` | höchstens 64 Audit-Kennungen (`evt_…`) |
| `state_fingerprint` | sha256 des Zustands, an den eine Freigabe gebunden ist |
| `idempotency_id` | `idm_` + Hash des Idempotenz-Schlüssels; der Schlüssel selbst wird **nie** gespeichert |
| `flags` | `interrupted`, `in_maintenance`, `acknowledged_by_admin` |

Abweichungen vom Entwurf (alle in Paket B):

- **DECIDED: kein `entry_id` im Datensatz.** `router_id` ist maßgeblich; eine HA-Eintragskennung
  sieht für die Maskierung des Core wie Schlüsselmaterial aus und gehört nicht in diese Datei.
- **DECIDED: `cause.code` statt `cause.key`**, `reason` statt `reason_key`, `statement` statt
  `statement_key`. Der Core behandelt jeden Feldnamen mit „key“ als geheim.
- **DECIDED: der Verlauf speichert nur Akteursarten** (`engine`, `admin`, `recovery`). Welcher
  Benutzer gehandelt hat, steht im Audit-Log des Core, nicht hier.
- **DECIDED: Idempotenz- und Doppelt-Kennungen sind Hashes** (`idm_`, `dda_`, `ddi_`), nie die
  Rohwerte.

Hilfsfunktionen: `action_dedupe_id(router_id, action_type, params)` (gleiche Eingabe → gleiche
`dda_`-Kennung), `incident_dedupe_id(router_id, incident_id, component)` (`ddi_`),
`idempotency_id(raw)` (`idm_`) und `binding_hash(action, catalog_version=…)` (sha256 über
Router, Aktion, Parameter, Katalog- und Playbook-Fassung, Vorfall mit Wiederöffnungszahl und
Zustands-Fingerabdruck).

**Stand heute:** gebaut und getestet. Niemand erzeugt bisher Datensätze außer den Tests.

## 4. Zustände und Übergänge

17 Zustände (Werte in Kleinbuchstaben): `detected`, `analyzed`, `proposed`, `preflight`,
`waiting_approval`, `approved`, `executing`, `verifying`, `resolved`, `rejected`, `cancelled`,
`failed`, `rollback_pending`, `rolling_back`, `rolled_back`, `escalated`,
`manual_recovery_required`.

**Endzustände:** `resolved`, `rejected`, `cancelled`, `escalated`, `manual_recovery_required`,
`rolled_back`. Aus einem Endzustand führt kein Übergang hinaus (`TerminalStateError`).

Normaler Weg: DETECTED → ANALYZED → PROPOSED → PREFLIGHT → (WAITING_APPROVAL →) APPROVED →
EXECUTING → VERIFYING → RESOLVED.

Es gibt **eine** Tabelle (`heal_model.TRANSITIONS`): 31 Zeilen, 48 erlaubte Paare aus Übergang
und Akteur. E = Engine, A = Administrator, R = Wiederherstellung nach einem Neustart.

| Von | Nach | Wer | Bedingung / Wirkung |
|---|---|---|---|
| DETECTED | ANALYZED | E | |
| DETECTED | CANCELLED | E, A | |
| ANALYZED | PROPOSED | E | auch „nicht möglich“ wird als Vorschlag ohne ausführbare Aktion gespeichert |
| ANALYZED | CANCELLED | E, A | |
| PROPOSED | PREFLIGHT | E, A | |
| PROPOSED | REJECTED | A | |
| PROPOSED | CANCELLED | E, A | |
| PROPOSED | ESCALATED | A | |
| PREFLIGHT | WAITING_APPROVAL | E | |
| PREFLIGHT | APPROVED | E | (Auto-Heal; ab 1.54.0) |
| PREFLIGHT | CANCELLED | E, A, R | |
| WAITING_APPROVAL | APPROVED | A | |
| WAITING_APPROVAL | REJECTED | A | |
| WAITING_APPROVAL | CANCELLED | E, A, R | |
| WAITING_APPROVAL | ESCALATED | A | |
| APPROVED | EXECUTING | E | **nur beim ersten Mal** (`first_entry`), **dauerhaft schreiben vor dem Handeln** (`durable`); setzt `execution.intent_written_at` |
| APPROVED | CANCELLED | E, A, R | |
| EXECUTING | VERIFYING | E, R | R setzt `flags.interrupted` |
| EXECUTING | FAILED | E | |
| VERIFYING | VERIFYING | R | nur wenn noch nicht unterbrochen; setzt `flags.interrupted` |
| VERIFYING | RESOLVED | E | |
| VERIFYING | FAILED | E | nur wenn **nicht** unterbrochen |
| VERIFYING | ESCALATED | E, A | |
| VERIFYING | MANUAL_RECOVERY_REQUIRED | E, R | |
| FAILED | ESCALATED | E, A, R | |
| FAILED | ROLLBACK_PENDING | E | nur beim ersten Mal und nicht unterbrochen; heute unerreichbar (kein Mechanismus) |
| ROLLBACK_PENDING | ROLLING_BACK | E | nur beim ersten Mal, dauerhaft schreiben vor dem Handeln |
| ROLLBACK_PENDING | MANUAL_RECOVERY_REQUIRED | E, A, R | |
| ROLLING_BACK | ROLLED_BACK | E | |
| ROLLING_BACK | MANUAL_RECOVERY_REQUIRED | E | |
| ROLLING_BACK | VERIFYING | R | setzt `flags.interrupted` |

`transition(action, to_state, *, actor, ts, reason, changes=None)` gibt einen **neuen**
Datensatz zurück und hängt einen Verlaufseintrag `{from_state, to_state, ts, actor, reason}`
an – mit genau dem übergebenen Zeitpunkt, nie einem selbst erfundenen. Ein Zeitsprung der Uhr
rückwärts wird so festgehalten, wie er kam, nicht „korrigiert“. Höchstens 24 Einträge (der
längste erlaubte Weg hat 13). Verweigert wird mit einer typisierten Ausnahme
(`IllegalTransitionError`, `ActorNotAllowedError`, `PreconditionFailedError`,
`TerminalStateError`, `BadTransitionInputError`); der alte Datensatz bleibt unverändert.

Entscheidungen gegenüber dem Entwurf:

- **DECIDED: ROLLED_BACK bleibt Endzustand**; die Kante ROLLED_BACK → ESCALATED des Entwurfs
  entfällt. Ist der Vorfall danach noch offen, entsteht ein neuer Datensatz.
- **DECIDED: ein unterbrochenes ROLLING_BACK wird VERIFYING** (Rollback-Status `unknown`),
  ein nach dem Neustart noch ausstehender Rollback wird MANUAL_RECOVERY_REQUIRED – ein Rollback
  wird nach einem Neustart nie begonnen.
- **DECIDED: ein Administrator darf aus PROPOSED, WAITING_APPROVAL, VERIFYING und FAILED
  eskalieren**; abbrechen darf er bis APPROVED, ab EXECUTING nicht mehr.
- **DECIDED: die Selbstschleife VERIFYING → VERIFYING (R) gibt es genau einmal**; ein zweiter
  Neustart ändert nichts mehr.

Eigenschaften, die die Tests über alle Wege prüfen: Kein Weg führt zweimal nach EXECUTING
(erschöpfende Suche über 88 Konfigurationen, 200 Zufallswege, im Speicher 40 Zufallsläufe mit
Neustarts); die Wiederherstellung (R) betritt nie EXECUTING, ROLLING_BACK oder APPROVED; nur ein
Administrator gibt frei oder lehnt ab.

**Stand heute:** gebaut und getestet; die Engine, die die Übergänge auslöst, fehlt.

## 5. Speicher, Neustart, Grenzen, Versionen

Code: `heal_store.SelfHealingStore`. Store `openwrt_router.self_healing`, Version 1.1, über
`core_store.create_store` (private Datei, atomares Schreiben, Migrationsfunktion ab dem ersten
Tag). Inhalt:

| Schlüssel | Inhalt |
|---|---|
| `saved_at` | Zeitpunkt des Schreibens |
| `write_seq` | zählt jedes Schreiben; daran erkennt das Rücklesen das eigene Schreiben |
| `settings` | Modul an/aus, Grenzen des Schleifenschutzes, je Router Modus und Allowlist |
| `actions` | die Datensätze (Abschnitt 3) |
| `loop` | Schleifenschutz als Daten (Abschnitt 10) |
| `maintenance` | Wartungsfenster für Schnittstellen und Dienste |

**Schreiben.** Eine Änderung im Arbeitsspeicher stellt **ein** verzögertes Schreiben nach
10 s an (weitere hängen sich daran). Sofort geschrieben wird nach dem Laden, wenn die
Neustartregel etwas geändert oder etwas Kaputtes übersprungen hat.

**Schreiben vor dem Handeln** (`async_apply_durable`). Die Übergänge, die die Tabelle als
`durable` markiert (nach EXECUTING und nach ROLLING_BACK), gehen nur hier; der normale Weg
`apply()` lehnt sie ab (`WriteAheadRequiredError`). Ablauf:

1. Übergang prüfen (ein unerlaubter wirft, nichts wird geschrieben).
2. Kein Schreiben, wenn der Speicher nicht geladen ist (`not_loaded`), HA herunterfährt
   (`stopping`; Zustände stopping, final_write, stopped), ein anderer Halter die Router-Sperre
   hat (`router_locked`) oder die Datei auch ohne Endzustände zu groß wäre (`over_size`).
3. Die Datei mit dem neuen Zustand **sofort** schreiben und **zurücklesen** (im Executor).
   Nur wenn die gelesene Datei genau dieses Schreiben (`write_seq`) mit genau diesem Datensatz
   enthält, ändert sich der Datensatz im Arbeitsspeicher, und das Ergebnis ist `ok`.
4. Sonst bleibt der Datensatz, wo er war (`write_failed` bzw. `not_durable`), und das nächste
   Schreiben wird sofort angestellt, damit auf der Platte wieder der wahre Zustand steht. Der
   Aufrufer darf dann den Router **nicht** aufrufen.

**DECIDED: Rücklesen statt nur `await async_save`.** Der Entwurf verlangte ein abgewartetes
`async_save`. Das reicht nicht: HAs `Store.async_save` fängt einen Schreibfehler
(`WriteError`) selbst ab, schreibt ihn ins Log und kehrt normal zurück; während HA
herunterfährt, schreibt es gar nicht, sondern merkt sich die Daten für das letzte Schreiben.
Ein Test mit HAs echtem Store auf einer temporären Platte lässt das Schreiben scheitern und
zeigt, dass erst das Rücklesen den Fehler findet
(`test_the_real_store_catches_a_write_home_assistant_swallows`). Gelesen am Code von HA 2026.2.

Während ein solches Schreiben läuft, ist der Datensatz gesperrt (`BusyError` für andere
Änderungen), und die Router-Sperre ist schon vergeben, damit sich niemand dazwischen drängt.

**Neustartregel** (`heal_model.restart_recovery`, angewendet beim Laden mit dem Akteur
`recovery` und dem Zeitpunkt des Ladens):

| Gefunden beim Laden | Danach | Grund im Verlauf |
|---|---|---|
| EXECUTING, ROLLING_BACK, VERIFYING (noch nicht unterbrochen) | VERIFYING, `interrupted` | `interrupted_by_restart` |
| ROLLBACK_PENDING | MANUAL_RECOVERY_REQUIRED | `rollback_lost_on_restart` |
| APPROVED, WAITING_APPROVAL | CANCELLED, Freigabe `invalidated` | `approval_lost_on_restart` |
| PREFLIGHT | CANCELLED | `preflight_lost_on_restart` |
| FAILED | ESCALATED | `failed_before_restart` |
| DETECTED, ANALYZED, PROPOSED, Endzustände | unverändert | – |

Eine unterbrochene Aktion heißt „Ergebnis unbekannt, muss geprüft werden“ und wird **nie noch
einmal ausgeführt**. Freigaben des Guards leben nur im Arbeitsspeicher und sind nach einem
Neustart weg; deshalb verfällt auch die Freigabe hier. **DECIDED:** PREFLIGHT wird abgebrochen
(die Prüfung muss neu laufen) und FAILED eskaliert (die Entscheidung über einen Rollback fiel
vor dem Neustart nicht mehr). Dass nach einer Unterbrechung der Schutzschalter des Schlüssels
öffnet (Entwurf), kommt mit Paket I.

Sperren und Doppelt-Kennungen werden beim Laden aus den Datensätzen neu aufgebaut. **Sperren
von Schreibzugriffen außerhalb der Engine fallen beim Laden weg** – nach einem Neustart kann
keiner davon mehr laufen.

**Verlust und Schaden.** Eine fehlende Datei ist ein erster Start (Standardwerte). Eine
unlesbare, fremde oder neuere Hauptversion startet leer, bleibt als `.bak` (bzw. HAs
`.corrupt.<Zeit>`) liegen und **pausiert Auto-Heal für die ganze Flotte** für 24 h (Grund
`store_lost`), weil Versuche und Schutzschalter unbekannt sind. Einzelne kaputte Teile
(Datensatz, doppelte Kennung, Einstellungen, Wartungsliste) werden übersprungen und gezählt;
dann gibt es ebenfalls eine `.bak`-Kopie und die Pause (Grund `store_damaged`). Kaputte
Einstellungen heißen Standardwerte, also Observe für jeden Router.

**Grenzen** (keine davon wirft je eine laufende Aktion hinaus):

| Grenze | Wert | Verhalten |
|---|---|---|
| Datensätze gesamt | 500 | ein neuer verdrängt den ältesten Endzustand; gibt es keinen, wird er abgelehnt (`CapacityError`) |
| offene je Router | 20 | darüber wird ein neuer abgelehnt |
| Aufbewahrung Endzustände | 90 Tage | `prune()` entfernt ältere |
| Idempotenz | 24 h, höchstens 1000 | danach frei |
| Wartungsfenster | höchstens 100, beendete 90 Tage | |
| Versuchszähler | 7 Tage ohne Versuch und ohne laufende Abklingzeit, höchstens 1000 | |
| Schutzschalter | ein **offener** bleibt immer; geschlossene 90 Tage, höchstens 1000 | |
| Fremd-Schreibzugriffe | die letzten 200 | |
| Datei | 1 000 000 Byte | darüber fallen Endzustände, die ältesten zuerst; reicht das nicht, wird ein verzögertes Schreiben trotzdem ausgeführt (gezählt, `save_over_size`), weil sonst eine offene Aktion verloren ginge, und ein Schreiben vor dem Handeln wird abgelehnt (`over_size`) |

Gemessen (Python 3.13, HAs eigene JSON-Serialisierung, eingerückt wie HA schreibt): ein
vollständig gefüllter Datensatz wie in `full_action()` der Tests hat **5 908 Byte**, ein neuer
2 269 Byte. 500 vollständige Datensätze wären 2 952 828 Byte; die Dateigrenze hält also
höchstens rund 170 solcher Datensätze, die übrigen Endzustände fallen vorher. Offen können bei
20 je Router und rund 6 KB je Datensatz für etwa 8 Router alle gleichzeitig in der Datei
stehen. **DECIDED:** 1 MB aus dem Entwurf beibehalten; die Grenze ist die strengere, und eine
Aktion, die nicht mehr sicher in die Datei passt, wird nicht ausgeführt.

**Versionen:** Unterversionen nur additiv (eine neuere Unterversion wird gelesen, unbekannte
Schlüssel werden ignoriert); eine unbekannte Hauptversion → `.bak` und leer, wie bei den
Core-Speichern.

**Stand heute:** gebaut und getestet; nichts lädt den Speicher, es entsteht keine Datei.

## 6. Die eine Sicherheitskette

```
Plan → Risiko → Vorabprüfung → Freigabe → [letzte Vorabprüfung] → Ausführen → Prüfen → Abschluss | Eskalation
```

Geplant: Nur `heal_executor` ruft schreibend einen Router auf, mit einem Ticket, das nur die
Engine bauen kann. Der `binding_hash` ist die Prüfsumme der Guard-Freigabe; ändert sich der
Zustand zwischen Freigabe und Ausführung, passen die Prüfsummen nicht mehr, die Aktion wird
abgebrochen (`binding_changed`) und neu vorgeschlagen. Kurz vor dem Router-Aufruf verbraucht
der Executor eine einmalige Schreiberlaubnis des Guards. `POST …/execute` verlangt einen
`Idempotency-Key`; eine Wiederholung liefert den vorhandenen Datensatz und ruft nie ein
zweites Mal. „Abschluss“ heißt: Die Prüfung sagt `resolved`; auf dem Router wird nichts
„committet“, weil keine Aktion Konfiguration ändert.

Geplante Guard-Aktionen: `self_healing.<aktion>` (CRITICAL, Weg über einen Menschen),
`self_healing.auto.<aktion>` (MUTATING, nur die Engine in Auto-Heal, nach der eigenen
Richtlinie), `self_healing.settings` (MUTATING, nur Administratoren), `self_healing.enable_auto`
(CRITICAL, nur Administratoren), `self_healing.rediagnose` (ACTIVE, begrenzt).

**Stand heute:** nur die Datenteile: `binding_hash()`, `idempotency_id()`, die Felder für
Freigabe und Ausführung und das Schreiben vor dem Handeln. Kein Executor, kein Ticket, keine
Guard-Aktion, kein Router-Aufruf.

## 7. Geschlossener Katalog der Aktionen

Das Risiko wird berechnet (Grundklasse + Rolle + Topologie + Clients), nie nur aus dem Namen
gelesen.

| Kennung | Router-Aufruf | Risiko | Verfügbar |
|---|---|---|---|
| `observe.evaluate` | keiner (vorhandene Daten) | 0 | ja |
| `diag.refresh` | ein normaler Poll | 1 | ja, höchstens 1 je 5 min je Router |
| `diag.ha_probes` | Netzwerkdiagnose auf HA-Seite | 1 | nur mit eingeschalteter Diagnose |
| `service.restart` (`dnsmasq`, `odhcpd`) | `rc init` über `restart_service_typed` | 2 | **ab 1.54.0**, nur im Modus Freigabe |
| `wifi.radio_restart` | `network.wireless down/up` (auf der Flotte nicht geprüft) | 2 | nein (`call_unverified_on_fleet`) |
| `router.reboot` | – | 3 | nein, modelliert und gesperrt; der vorhandene Knopf bleibt |
| `config.restore` | – | 3 | nein; Playbook F liefert nur einen Probelauf |
| `interface.cycle` | – | 3 | nein, nur Empfehlung |
| `client.*` (trennen, sperren, umlenken) | – | – | nie |
| Firewall, VLAN, Management-Adresse, Routing, Firmware | – | 3 | nie in Phase 7 |

Gemeinsame Vorabprüfungen (jede `pass`, `fail` oder `unknown`; `fail` oder `unknown` einer
kritischen sperrt): Router erreichbar, Identität eindeutig, Aktion unterstützt, Rechte
vorhanden, keine gleichzeitige Reparatur, Wartung beachtet, kein gefährlicher Zustand,
Management-Weg in Ordnung, Bauteile bekannt, Wiederherstellung geklärt (Risiko 3 ohne
Mechanismus → sperren), Freigabe gültig, Schutzschalter geschlossen.

Bestätigtes Commit (`uci apply` mit Rollback) gibt es in rpcd, es ist aber ungenutzt, nicht in
der ACL, deckt nur UCI ab und geht bei einem Neustart von rpcd oder des Routers verloren. Kein
Watchdog, kein zweiter Zugangsweg.

**Stand heute:** nichts davon gebaut. Das Modell kennt nur die Risikoklassen 0–3 und lehnt
eine Allowlist mit Risiko über 1 ab (Abschnitt 10).

## 8. Playbooks A–G

Alle Playbooks arbeiten nur am **Wurzelvorfall** von Network Intelligence; ihre Leseschritte
nutzen Daten, die ohnehin gepollt werden.

| Playbook | Mögliche Aktion | Harte Regel |
|---|---|---|
| A `dns_recovery` | `service.restart dnsmasq` | kein Neustart, wenn die Ursache außerhalb liegt (WAN aus, Upstream gestört, Gateway nicht erreichbar) oder dnsmasq absichtlich aus ist |
| B `dhcp_recovery` | `service.restart dnsmasq/odhcpd` nur, wenn der Dienst nicht läuft oder ständig neu startet | nie Leases anfassen; voller Pool oder Konflikt ist eine Empfehlung |
| C `radio_recovery` | `wifi.radio_restart` (nicht verfügbar) | nie auf einem Funk mit STA- oder Mesh-Schnittstelle |
| D `interface_recovery` | keine (Empfehlung) | kein automatisches Ab- und Anschalten einer Uplink- oder Management-Schnittstelle |
| E `wan_recovery` | keine (Empfehlung) | kein pauschaler Neustart |
| F `drift_recovery` | keine (Plan mit Version, Bereichen, Prüfergebnis, manuellen Schritten) | kein automatisches Zurücksetzen; Wiederherstellen ist ein **Probelauf** |
| G `client_recovery` | keine | kein Trennen, kein Sperren, kein erzwungenes Umlenken |

**Stand heute:** nichts davon gebaut. Das Modell hat die Felder `playbook_id` und
`playbook_version`.

## 9. Entscheidung und Konfidenz

Geplante Bewertung (fest, jeder Faktor mit Grund gespeichert):

```
base  = {confirmed: 0.9, likely: 0.7, possible: 0.4, unknown: 0.0}[cause_level]
fit   = 1.0 (direkter Zustand des Ziels), 0.5 (nur Log-Hinweise), sonst 0
score = base × fit − 0.3 je fehlgeschlagenem/unbekanntem Versuch desselben Schlüssels in 24 h
                   − 0.2 bei Drift im selben Bereich in 24 h;   begrenzt auf [0, 1]
```

Ergebnis (erste passende Regel): **Unsupported**, **Not Safe**, **Insufficient Evidence**
(`score < 0.6`, eine Hypothese mit weniger als zwei Quellenfamilien, nur zeitliche Nähe,
fehlende Logs, veraltete Hinweise), **Requires Approval** (Risiko ≥ 2, Modus Freigabe, nicht
auf der Allowlist), **Recommended**. Zeitliche Nähe allein führt nie zu einer schreibenden
Aktion.

**Stand heute:** nur die Daten: `Decision` (Ergebnis, `score`, `factors`, `why`, `why_not`),
`Risk`, `Cause`. Keine Bewertung.

## 10. Modi, Wartung, Schleifenschutz

**Modi** je Router: `observe` (analysieren, vorschlagen, nur lesend prüfen), `approval` (dazu
der Freigabe-Ablauf) und `auto_heal` (dazu automatisches Ausführen erlaubter Aktionen nach der
Vorabprüfung; nur ein Administrator kann umschalten, nie eine Automation, ein Dienst oder eine
Entität).

Entscheidungen des Eigentümers, im Modell umgesetzt:

- **Nach dem Update ist das Modul für jeden Router an, im Modus Observe**
  (`DEFAULT_MODULE_ENABLED = True`, `DEFAULT_MODE = observe`; `HealSettings.from_dict({})`
  liefert genau das, ebenso jeder unbekannte Router über `HealSettings.router(rid)`).
- **Auto-Heal ist nie voreingestellt, die Allowlist ist leer.**
- **DECIDED (Frage Q7, die strengere Lesart):** Eine Allowlist darf nur Aktionen bis Risiko 1
  enthalten (`AUTO_HEAL_MAX_RISK`); Risiko 2 und 3 lehnt das Modell ab. Höchstens 16 Einträge
  je Router.

**Wartung:** Netz und Router übernehmen das Wartungsfenster und den Router-Schalter von Network
Intelligence (eine Wahrheit für beide Module). Schnittstellen und Dienste bekommen eigene
Fenster im Speicher (`MaintenanceWindow`: `mtw_`-Kennung, Bereich `interface`/`service`,
Router, Ziel, Beginn, Ende oder offen, Grund, angelegt von `engine` oder `admin`, nie von
`recovery`). In der Wartung kein Auto-Heal; Vorschläge entstehen weiter und sind markiert.

**Schleifenschutz** – als Daten im Speicher (`LoopLimits`, `LoopState`):

| Mechanismus | Standard | Grenzen |
|---|---|---|
| Abklingzeit je (Router, Aktion, Bauteil) | 30 min | 10 min – 24 h |
| Versuche je Schlüssel in 24 h | 2 | 1–3 |
| Wartezeit zwischen Versuchen | 30 min × 2^n | höchstens 24 h |
| Schutzschalter je Schlüssel | schließt nur durch Bestätigung eines Administrators | – |
| Flotten-Pause | ab 3 Fehlschlägen in 24 h, 24 h lang | 1–10; 1 h – 7 Tage |
| gleichzeitig laufende Aktionen in der Flotte | 1 | 1 |
| Doppelte je Vorfall und Bauteil, je (Router, Aktion, Parameter) | die vorhandene offene Aktion wird zurückgegeben | – |
| Router-Sperre | eine laufende Reparatur je Router | – |

**Router-Sperre und Schreibzugriffe von außerhalb** (Entscheidung des Eigentümers): Das Modell
hat je Router **eine** Sperre mit genau einem Halter (`LockRecord`: Halter `engine` mit der
Aktionskennung oder `external` mit einer Quelle wie `button.reboot`).
`LoopState.repair_active(router_id)` sagt, ob gerade eine Reparatur den Router hält. Die
Engine bekommt die Sperre automatisch mit den Zuständen EXECUTING, VERIFYING, ROLLBACK_PENDING
und ROLLING_BACK und gibt sie mit dem nächsten Zustand wieder ab; ein Übergang in einen dieser
Zustände, während ein anderer Halter die Sperre hat, wird abgelehnt (`router_locked`). Knöpfe
und Schalter (später) nehmen die Sperre mit `try_external_lock()`, geben sie mit
`release_external_lock()` frei und halten ihren Schreibzugriff mit `record_external_write()`
fest (Router, Quelle, Ziel, Zeitpunkt, Audit-Kennung; die letzten 200).

**Stand heute:** Grenzen, Zähler, Sperre und Fremd-Schreibzugriffe gibt es als Daten mit
Prüfung, Speicherung und Tests. Es gibt **keine Logik**, die einen Versuch zählt, einen
Schutzschalter öffnet oder die Flotte pausiert – außer der Pause nach einem verlorenen oder
beschädigten Speicher. Knöpfe und Schalter benutzen die Sperre noch nicht.

## 11. HTTP-API, Entitäten, Ereignisse, Dienste

Geplant: Routen unter `/api/openwrt_router/enterprise/selfhealing/v1/` (`overview`,
`actions`, `actions/{id}`, `history`, `settings`, `plans`, `…/preflight`,
`…/request-approval`, `…/approve`, `…/reject|defer|cancel|escalate|acknowledge`,
`…/rediagnose`, `…/execute`, `audit`), schreibend nur für Administratoren, Rumpf höchstens
8 KiB, nur bekannte Schlüssel, Fehler wiederholen nie die Eingabe. Kein Endpunkt nimmt einen
Befehl, Pfad, Host oder freien Text an, der den Router erreicht.

Entitäten nur lesend (Flotten-Modus, aktive Aktionen, offene Freigaben, Erfolge und
Fehlschläge 30 Tage, letztes Ergebnis, „Auto-Heal an“ als Binärsensor, Modus je Router); sie
kommen in den unique_id-Snapshot. Ein Bus-Ereignis `openwrt_router_remediation_event` ohne
Adressen. **Keine Dienste.**

**Stand heute:** nichts davon gebaut. Keine Route, keine Entität, keine unique_id, kein
Ereignis.

## 12. Time Machine, Audit, Security Center, KI-Berater

Geplant:

- **Audit:** Präfix `self_healing.` mit Modul `self_healing`, Ereignisse für jeden Schritt ab
  dem Vorschlag, Pflichtereignisse ab der Freigabe. Den Anteil am Audit-Kontingent (siebtes
  Modul) und die Gesamtgröße passt **Paket K** an, nicht Paket B.
- **Time Machine:** Marken `remediation_event` aus den echten Audit-Zeitpunkten, keine
  erfundenen Ereignisse; „vorher/nachher“ aus den eigenen Messungen der Aktion.
- **Security Center:** eine offene Erkennung am Router oder seinem Management-Weg heißt
  **Not Safe**; das Security Center legt ein Veto ein, nie umgekehrt. Sicherheitsrelevante
  Dienste stehen nicht im Katalog.
- **KI-Berater:** nur eine Schnittstelle; Rat ändert nie Risiko, Richtlinie, Modus, Allowlist
  oder Freigabe.

**Stand heute:** nichts davon gebaut. In `core_models.py` steht nur die Kennung `rem_`;
Audit-Präfix, Audit-Anteil und Pflichttypen sind unverändert.

## 13. Dashboard „Self-Healing Center“

Geplant: Tab `selfhealing` mit Übersicht (Modus je Router, laufende Aktionen, offene
Freigaben, Schutzschalter, Flotten-Pause und dauerhaft die Zeile „Automatischer Rollback: auf
dieser Plattform nicht verfügbar“), Warteschlange, Aktionsdetail (Analyse, Plan, Prüfliste,
Sicherungsverweis oder „nicht nötig: keine Konfigurationsänderung“, Risiko, Verlauf, vorher und
nachher, Rollback-Aussage), Freigabe-Ablauf (Knöpfe nur für verfügbare Aktionen) und Verlauf.
Andere Benutzer sehen eine maskierte Kurzfassung ohne Knöpfe.

**Stand heute:** nichts davon gebaut; Frontend und `_PANEL_VERSION` unverändert.

## 14. Bedrohungsmodell

| Bedrohung | Gegenmaßnahme | Stand heute |
|---|---|---|
| Nicht-Administrator oder Automation löst ein Schreiben aus | Guard, schreibende Routen nur für Administratoren, keine Dienste, nur lesende Entitäten | Plan |
| Freigabe wiederholt, doppelt ausgeführt | einmalige Schreiberlaubnis, Idempotenz, Prüfsumme | **teilweise**: das Modell lässt EXECUTING nur einmal zu; der Speicher gibt bei gleicher Idempotenz-, Aktions- oder Vorfallkennung die vorhandene Aktion zurück |
| Zustand ändert sich zwischen Freigabe und Ausführung | `binding_hash` mit Fingerabdruck, letzte Vorabprüfung | Funktion `binding_hash()` vorhanden |
| Engine repariert eigene Nebenwirkungen | Kennzeichnung eigener Aktionen, Schutzschalter, Versuche, Pause, eine Aktion gleichzeitig | Daten vorhanden, keine Logik |
| Erzwungene Störungen (DNS absichtlich kaputt) | höchstens 2 Versuche in 24 h, Regel „Ursache außerhalb“ | Plan |
| Eingeschleuste Parameter | geschlossener Katalog, geprüfte Parameter, nie SSH für Schreibzugriffe | **teilweise**: das Modell nimmt nur kurze Wörter, Zahlen und Wahrheitswerte und lehnt geheime Schlüsselnamen und schlüsselartige Werte ab |
| HA startet mitten in einer Aktion neu | Schreiben vor dem Handeln, „unbekannt“, nie wiederholen | **gebaut**: Rücklesen, Neustartregel, Tests 22 |
| Router verloren mitten in der Aktion | `inconclusive` → VERIFYING → MANUAL_RECOVERY_REQUIRED, kein Wiederholen | Übergänge vorhanden |
| Umgehung über vorhandene Knöpfe und Schalter | Sperre beachten, Audit | Sperre und Fremd-Schreibzugriff als Daten vorhanden, noch nicht benutzt |
| Geheimnisse oder Adressen in Logs, Audit, Speicher | nur Kennungen, Zähler, Codes | **gebaut** für den Speicher; Test mit der Maskierung des Core |
| Speicher manipuliert oder verloren | atomares Schreiben, private Datei; Verlust → Observe und 24 h Flotten-Pause | **gebaut** |

## 15. Arbeitspakete und Releases

| Paket | Inhalt | Stand |
|---|---|---|
| **B** | Zustandsmaschine, Datenmodell, Speicher, Neustartregel, Grenzen | **dieser Stand** |
| C1 | Engine-Gerüst, Modulschalter, Verdrahtung, lesende Routen, Listener | offen |
| D | Katalog und Richtlinie | offen |
| E | Vorabprüfungen | offen |
| F | Playbooks A–G | offen |
| G | Anbindung Configuration Manager (Sicherungsverweis, Drift-Plan, Probelauf) | offen |
| H | Prüfung und die fünf Ergebnisklassen | offen |
| I | Eskalation, Schutzschalter, Flotten-Pause, Rollback-Zustände (nur Modell) | offen |
| K | Entitäten, Ereignis, Audit-Präfix und -Anteil, Time Machine, Security-Veto, unique_id-Snapshot | offen |
| J | Tab im Dashboard | offen |
| C2 | Schreibweg (`restart_service_typed`, Executor, Freigabe-Routen, Ausführen mit Idempotenz) | **1.54.0** |
| L | Gesamttests, Leistung, Sicherheitsprüfung, Doku | offen |

Entscheidungen des Eigentümers:

- **1.53.0 ist nur Observe**: kein Router-Schreibweg, keine ACL-Änderung, kein zusätzlicher
  Router-Aufruf. Die erste schreibende Aktion kommt mit **1.54.0** (Paket C2).
- Das Modul ist nach dem Update für jeden Router **an, im Modus Observe**.
- Gemergt wird erst nach einer unabhängigen Prüfung.

## 16. Entscheidungen des Eigentümers und offene Fragen

| # | Frage | Stand |
|---|---|---|
| Q1 | Schreibweg in Phase 7? | **entschieden:** 1.53.0 nur Observe, schreiben ab 1.54.0 |
| Q2 | Standard nach dem Update | **entschieden:** an, jeder Router in Observe; Auto-Heal nie voreingestellt, Allowlist leer |
| Q3 | Router-Rechte für `rc init` | offen (Empfehlung des Entwurfs: Root-Anmeldung dokumentieren, später ein eigener rpcd-Benutzer) |
| Q4 | vorhandene Knöpfe und Schalter | **teilweise:** Sperre je Router und Erfassen von Schreibzugriffen außerhalb der Engine sind im Modell; ob Knöpfe und Schalter sie benutzen und ob sie nur für Administratoren werden, ist offen |
| Q5 | Funk-Neustart | offen (Entwurf: nicht in 1.54.0) |
| Q6 | Router-Neustart als Aktion | offen (Entwurf: nie im Katalog) |
| Q7 | Was Auto-Heal enthalten darf | offen; das Modell setzt die strengere Lesart um: nur Risiko ≤ 1 |
| Q8 | Watchdog auf dem Router | offen (Entwurf: keiner) |

## 17. Tests und was nicht geprüft ist

- `tests/test_heal_model_v1530.py`: die ganze Matrix Zustand × Zustand × Akteur gegen die
  Tabelle, erschöpfende Suche und Zufallswege (kein zweites EXECUTING, Endzustände bleiben),
  Neustartregel, Verlauf mit den übergebenen Zeitpunkten, Zeitsprung rückwärts,
  Rundreise jedes Feldes, kaputte Datensätze, Doppelt- und Idempotenz-Kennungen, keine
  Zugangsdaten (Maskierung des Core), Schleifenschutz, Einstellungen, Sperre, Wartung.
- `tests/test_heal_store_v1530.py`: erster Start, Rundreise, jeder der 17 Zustände durch den
  Speicher, Neustart während der Ausführung (Auftragstest 22), Verlust, neuere Version,
  kaputte Datei und kaputte Teile, Doppelte über einen Neustart (Auftragstest 32), Grenzen und
  Verdrängung (nie eine offene Aktion), Schreiben vor dem Handeln mit allen Fehlerarten, HAs
  echter Store auf einer temporären Platte, 40 Zufallsläufe mit Neustarts, Sperre und
  Fremd-Schreibzugriffe, keine Zugangsdaten in der Datei.

Nicht geprüft: auf Routern (es gibt keinen Router-Aufruf), in einer laufenden HA-Instanz
(nichts ist verdrahtet), mit echten Plattenfehlern außer dem nachgestellten `WriteError`,
mit mehr als einem Prozess auf derselben Datei, und die Größen mit Datensätzen, die alle
Felder bis an ihre Grenzen füllen (gemessen ist nur der Datensatz der Tests).
