# Self-Healing (Phase 7; Paket B: Zustandsmaschine, Datenmodell, Speicher; Paket C1: Engine-Gerüst, nur Observe; Paket D: Katalog, Richtlinie; Paket X: Richtlinie in der Engine)

<!-- Entwicklerdoku zu Phase 7 „Enterprise Self-Healing & Automated Remediation“, Stand
     Paket D (Branch feature/self-healing-d, 2026-11-27, auf B und C1). Gebaut sind heal_model.py
     und heal_store.py (Paket B), die Kennung `rem_` in core_models.py, seit Paket C1
     heal_engine.py, heal_views.py, der Modulschalter `self_healing_enabled` und die
     Verdrahtung in __init__.py, config_flow.py und diagnostics.py, seit Paket D
     heal_catalog.py und heal_policy.py (reine Logik), seit Paket X (Branch
     feature/self-healing-x) entscheidet die Engine über heal_policy.gate (PolicyDecider).
     Aussagen zu B, C1 und D sind am Code gelesen und mit tests/test_heal_*_v1530.py geprüft
     (FakeDisks, ein Test schreibt eine echte Datei mit HAs Store; die C1-Tests mit dem echten
     Network-Intelligence-Motor der P6-Tests und dem echten api/Coordinator aus
     tests/full_router_kit.py); nicht auf Routern,
     nicht in einer laufenden HA-Instanz. Alles andere in dieser
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

**Stand heute (Paket C1, nur Observe):** Es gibt das Datenmodell mit der Zustandsmaschine
(`heal_model.py`), den Speicher (`heal_store.py`), die Kennung `rem_`
(`core_models.REMEDIATION_ID_PREFIX`) und seit C1 die **Engine** (`heal_engine.py`, Abschnitt
2.1) mit **lesenden Routen** (`heal_views.py`, Abschnitt 11). Nach dem Update ist das Modul an
(ein Schalter für die ganze Flotte in den Optionen, `self_healing_enabled`): Die Engine
startet mit dem ersten Router-Eintrag, hört auf die Vorfall-Meldungen von Network
Intelligence und legt zu einem gemeldeten Wurzelvorfall auf genau einem Router einen
Datensatz an, der bis „vorgeschlagen“ (PROPOSED) läuft und dort stehen bleibt. Es gibt
**keinen Router-Aufruf, keinen Schreibweg, keinen Dienst, keine Entität, kein Bus-Ereignis**
und keine neue unique_id. Die Datei `openwrt_router.self_healing` entsteht mit dem ersten
Datensatz (verzögert) und spätestens, wenn die Engine stoppt.

**Stand heute (Paket D):** Dazu kommen der geschlossene Katalog (`heal_catalog.py`,
Abschnitt 7) und die Richtlinie (`heal_policy.py`, Abschnitte 9 und 10): Risiko nach Kontext,
Konfidenzwert, die fünf Ergebnisse, Modi und Allowlist, Schleifenschutz-Entscheidungen. Beide
sind **reine Logik** ohne HA-Import, ohne Router-Aufruf, ohne Zeitquelle und ohne
Ausführungsweg. Auch Paket D ändert für Benutzer nichts.

**Stand heute (Paket X):** Die Engine entscheidet über die Richtlinie: `PolicyDecider`
(Abschnitt 2.1) baut aus dem Kontext eines Datensatzes einen `DecisionInput` und fragt
`heal_policy.gate`; der Datensatz trägt die Entscheidung des Gates selbst (Wert, Regeln,
Risiko). Die Engine zeigt den Modus der Richtlinie (Hold und Flotten-Pause: Observe). Weiter
als PROPOSED geht nichts, ausführbar ist nichts, kein Router-Aufruf kommt dazu.

## 2. Modulaufbau

Geplant ist **eine** Instanz für die ganze Flotte je HA-Installation, verdrahtet wie Security
Center und Netzwerkdiagnose (am Ende von `__init__.py` um `async_setup_entry` und
`async_unload_entry` gelegt; der erste Eintrag erzeugt sie, das Entladen des letzten gibt sie
frei).

| Datei | Art | Aufgabe | Stand heute |
|---|---|---|---|
| `heal_model.py` | rein (ohne HA) | Zustände, die eine Übergangstabelle, `RemediationAction`, Neustartregel, Schleifenschutz-Daten, Einstellungen, Wartungsfenster; `transition()` ist der einzige Weg, einen Zustand zu ändern | **gebaut** (Paket B) |
| `heal_store.py` | async | Store `openwrt_router.self_healing`, Schreiben vor dem Handeln, Grenzen | **gebaut** (Paket B) |
| `heal_catalog.py` | rein | geschlossene Liste typisierter Aktionen, Parameterprüfung, Rollback-Aussage je Aktion | **gebaut** (Paket D) |
| `heal_policy.py` | rein | Risiko nach Kontext, Konfidenzwert, die fünf Ergebnisse, Modi, Allowlist, Abklingzeit, Schutzschalter und Flotten-Pause als Entscheidungen | **gebaut** (Paket D); seit Paket X ruft die Engine `gate` und `effective_mode` über `PolicyDecider` (Abschnitt 2.1); `record_outcome` ruft später I |
| `heal_preflight.py` | rein + async | Vorabprüfungen aus vorhandenen Daten, **kein Router-Aufruf** | Plan (E) |
| `heal_playbooks.py` | rein | Playbooks A–G als versionierte Daten | Plan (F, G) |
| `heal_verify.py` | rein + async | Ergebnisklassen aus späteren Polls | Plan (H) |
| `heal_engine.py` | async | Ablauf, Sperren, Warteschlange, Zeitgeber, Neustart | **gebaut** bis PROPOSED (C1, Abschnitt 2.1); Ausführen, Sperren, Warteschlange Plan (C2, I) |
| `heal_views.py` | HTTP | Routen (Abschnitt 11) | **gebaut**: fünf lesende Routen (C1); schreibende Plan (C2) |
| `heal_entities.py` | HA | nur lesende Entitäten | Plan (K) |
| `heal_executor.py` | async | **das einzige Modul, das schreibend einen Router aufruft** | Plan (C2, 1.54.0) |
| `api.py` (Ergänzung) | – | `restart_service_typed(name)` mit fester Dienstliste | Plan (C2, 1.54.0) |
| `frontend/…/enterprise/selfhealing/` | TS | Tab „Self-Healing“ | Plan (J) |

Namen (aus dem Entwurf übernommen): Modul `self_healing`, Dateien `heal_*.py`, Store-Schlüssel
`openwrt_router.self_healing`, Audit-Präfix `self_healing.`, Routen unter
`/api/openwrt_router/enterprise/selfhealing/v1/`. Der Store-Schlüssel steht in
`heal_store.py` (nicht in `const.py`), wie bei der Time Machine; seit C1 stehen in `const.py`
der Optionsschlüssel `self_healing_enabled` (Standard an) und die `hass.data`-Schlüssel der
Engine und der gebundenen Routen. Audit-Präfix und Modulname im Audit gibt es noch nicht
(Paket K).

### 2.1 Die Engine (Paket C1)

**Lebenslauf** wie die Time Machine: `async_setup_self_healing` (am Ende von
`async_setup_entry`, der Eintrag steht dann in `SETUP_IN_PROGRESS`) erzeugt die Engine mit dem
ersten nicht deaktivierten Eintrag, solange der Schalter an ist; der Schalter wird nach dem
Warten auf die Sperre noch einmal gelesen. `async_release_self_healing` (nach
`async_unload_entry`) stoppt sie mit dem letzten. Scheitert das Entladen des Basis-Eintrags,
bleibt der Router wie bei der Time Machine in der Engine (HA setzt `FAILED_UNLOAD`, Teile laufen
bis zum Neustart weiter); die Engine handelt nur für Einträge im Zustand `LOADED`. Der
Optionsschalter nimmt nur Einträge auf, die `LOADED` sind und Laufzeitdaten mit Coordinator
haben. Ohne echtes Konfigurationsverzeichnis (`hass.config.config_dir` keine Zeichenkette,
etwa ein nachgebildetes `hass`) startet keine Engine und kein Speicher; das wird einmal je
Instanz gewarnt. Fehler bleiben dort, werden nur mit ihrem Typ geloggt, und ein Router-Eintrag
scheitert nie an Self-Healing. Der Optionsfluss schreibt den Schalter auf alle Einträge durch
und schaltet die laufende Engine direkt (ohne Neuladen); sagt ein Eintrag „aus“, ist das Modul
aus (die strengere Lesart). Aus heißt: keine Engine, kein Speicher, kein Listener, kein
Zeitgeber, keine Route.

**Start:** Speicher laden (die Neustartregel läuft dabei zuerst, Abschnitt 5), dann der
Listener auf `openwrt_router_incident_event` (eine `@callback`-Methode, kein Lambda), der
Zeitgeber alle **300 s**, die Bindung an den Core (Router Registry; fehlt der Core, versucht es
jeder Takt wieder) und ein Abgleich mit Network Intelligence. Jeder hinzukommende Router
gleicht noch einmal ab.

**Die Meldung ist nur ein Auslöser** (Review PR #78). `openwrt_router_incident_event` kann in HA
jeder feuern (eine Automation, eine andere Integration); über die REST- und WebSocket-API
gefeuerte Meldungen haben den Ursprung `remote` und werden nur gezählt
(`skipped_remote_event`). Von einer lokalen Meldung nimmt die Engine nur die Vorfallkennung;
Zustand, Router, Art und Ursache liest sie aus dem Vorfall von Network Intelligence selbst.

**Ein Vorfall, Schritt für Schritt** (`handle_incident`):

1. Nur Meldungen mit `state` `opened`, `reopened` oder `resolved`, einer Vorfallkennung von
   1 bis 64 Zeichen und, falls vorhanden, `entry_ids` als Liste von Zeichenketten zählen;
   alles andere wird gezählt (`skipped_bad_event`, ohne Warnung) und verworfen.
2. Network Intelligence nicht geladen: nichts (`skipped_ni_unavailable`). Kennt es den Vorfall
   nicht: nichts (`skipped_unknown_incident`). Gelöst oder ignoriert laut Network
   Intelligence: die Datensätze schließen (unten). Bestätigt (`acknowledged`): kein neuer
   Datensatz, ein offener bleibt.
3. Modul im Speicher aus (`settings.enabled`): nichts (`skipped_module_disabled`).
4. Ein neuer Datensatz nur, wenn Network Intelligence den Vorfall für seine **jetzige**
   Öffnung selbst gemeldet hat (`NetIntelligence.announced_reopen_count`, gespeichert in NI):
   Wurzel, nach der Beruhigungszeit, ab `notify_min_severity`, nicht nur auf Routern in der
   Wartung. Sonst nichts (`skipped_not_announced`).
5. Ist er ein stilles Kind (`net_rules.suppressed_child`): nichts (`skipped_child`).
6. Genau **ein** Router: die Router des Vorfalls in Network Intelligence ohne die Flotte (die
   `entry_ids` der Meldung zählen nie). Keiner, mehrere oder nur die Flotte: nichts
   (`skipped_no_single_router`).
7. Der Eintrag muss in der Engine, nicht deaktiviert und `LOADED` sein, und der Core muss ihm
   eine aktive Router-Kennung geben (`rtr_…`; ein verwaister Datensatz zählt nicht). Sonst
   nichts (`skipped_router_not_loaded`, `skipped_router_disabled`, `skipped_no_router_id`).
8. Ein Datensatz je Öffnung: gibt es für Vorfall und Zahl der Wiedereröffnungen schon einen
   Observe-Datensatz (in jedem Zustand, auch geschlossen), entsteht keiner. Das wird **nicht**
   gezählt (Paket X, b): sonst triebe jede gefälschte Meldung mit einer bekannten Kennung den
   Zähler hoch. `deduplicated` zählt nur, wenn erst der Speicher ein Doppeltes erkennt, und
   dann höchstens einmal je Öffnung (gemerkt in einer begrenzten Liste, 1000).
   **Dieselbe Öffnung** heißt: gleiche Kennung, gleiche Zahl der Wiedereröffnungen und
   `first_seen` des Vorfalls nicht später als der gespeicherte (Paket X, d). Network
   Intelligence zählt nach einem Zurücksetzen seines Speichers wieder ab `inc-1`; ein Vorfall
   mit derselben Kennung und späterem `first_seen` ist ein anderer. Offene Datensätze des
   älteren schließen als `incident_gone`. Rückwärts verschoben (`first_seen` früher, wie
   `_shift` nach einem Uhrsprung) bleibt es derselbe; fehlt die Zeit auf einer Seite (Datensätze
   aus C1), entscheidet die Kennung.
9. `RemediationAction.new` mit Aktion `observe.evaluate`, Parameter `{"incident": "inc-N",
   "first_seen": …}` (`first_seen` auf Millisekunden, nur wenn Network Intelligence ihn hat),
   Vorfallkennung, -art und Zahl der Wiedereröffnungen, Zeitpunkt = Wanduhr der Engine in
   diesem Moment; dann `SelfHealingStore.add()`. Doppelte erkennt der Speicher (je Vorfall,
   je Aktion, je Router-Bauteil); eine Ablehnung wegen Grenzen wird gezählt
   (`refused_capacity`), ein vom Modell abgelehnter Wert ebenfalls (`refused_invalid`), nie
   geworfen.
10. Hat der Router schon einen offenen Datensatz eines **anderen** Vorfalls, wartet der neue
    Vorfall im Speicher der Engine (höchstens 200, die ältesten fallen heraus, `deferred`) und
    bekommt seinen Datensatz, sobald der erste geschlossen ist (Grund `incident_deferred`).
    Die Engine sieht das am Halter des Router-Platzes vorher und baut dafür keinen Datensatz;
    ein wartender Vorfall wird nicht erneut angesehen, solange derselbe Datensatz den Platz
    hält (gemerkt je Öffnung, höchstens `SKIP_MEMO_MAX` = 1000, Paket X, c). 500 wartende
    Vorfälle auf einem Router kosten den Takt so nur Nachschlagen im Speicher.
    Gelöste, ignorierte oder bestätigte Vorfälle bekommen auf keinem Weg einen Datensatz, auch
    wenn Network Intelligence sie noch als gemeldet führt (Paket X, a).
11. Meldet Network Intelligence für den Router Wartung, bekommt der Datensatz die Markierung
    `in_maintenance`.
12. DETECTED → ANALYZED mit der Ursache, **wie Network Intelligence sie meldet** (Code, Status,
    Stufe, Konfidenz, Quellenfamilien); ohne Ursache Grund `no_cause_reported`, nichts wird
    erfunden.
13. ANALYZED → PROPOSED mit dem Vorschlag der Entscheidungsschnittstelle (unten). Weiter geht
    die Engine nie.

Zeigt Network Intelligence den Vorfall gelöst oder ignoriert, schließen seine offenen
Observe-Datensätze (DETECTED/ANALYZED/PROPOSED → CANCELLED, Akteur Engine, Zeitpunkt =
Wanduhr der Engine, Grund `incident_cleared` oder `incident_ignored`); eine Meldung `resolved`
allein schließt nichts. Der Takt alle 300 s liest die Sicherheitsuhr (`store.now()`), räumt auf
(`prune()`) und gleicht mit den Vorfällen von Network Intelligence ab: verschwunden →
`incident_gone`, gelöst → `incident_cleared`, ignoriert → `incident_ignored`, inzwischen stilles
Kind → `incident_now_child`; ein Datensatz, der nach einem Neustart in DETECTED oder ANALYZED
stand, läuft weiter. Ist Network Intelligence nicht geladen, wird nichts geschlossen
(unbekannt ist nicht gelöst). Datensätze anderer Aktionen und Zustände ab PREFLIGHT fasst die
Engine nie an (eine unterbrochene Ausführung bleibt „muss geprüft werden“).

**Nachholen** (Review PR #78): Network Intelligence meldet einen Vorfall nur einmal je Öffnung
(und merkt sich das über einen Neustart), die Warteliste der Engine lebt nur im Speicher. Damit
ein offener Vorfall nach einem Neustart nicht ohne Datensatz bleibt, nimmt jeder Abgleich (Start,
jeder hinzukommende Router, jeder Takt) gemeldete aktive Wurzeln auf genau einem geladenen
Router ohne Datensatz ihrer Öffnung auf: derselbe Weg und dieselben Prüfungen wie oben (Grund
`incident_reconciled`, Zähler `reconciled`), höchstens `RECONCILE_MAX` (20) neue Datensätze je
Lauf, Überspringen wird dabei nicht gezählt, kein Router-Aufruf, nur Speicher. Ein Eintrag, der
beim Start noch in `SETUP_IN_PROGRESS` steht, wird mit dem nächsten Takt nachgeholt.

**Entscheidungsschnittstelle** (`heal_engine.py`): `HealDecider` ist ein Protocol mit
`propose(context: DecisionContext) -> Proposal`. `DecisionContext` (eingefroren) enthält den
Datensatz, die Router-Kennung, eingestellten und geltenden Modus, Hold, Flotten-Pause,
Modulschalter, Wartung (und ob sie bekannt ist), ob der Router geladen ist, Identitätsstatus
und Rolle aus dem Core, die Ursache, die Quellenfamilien, ob der Vorfall jetzt eine Wurzel
ist, `evidence_sufficient`, Kopien von Versuchen und Schutzschaltern, die Zeit der
Sicherheitsuhr, die Allowlist und `write_path_available` (in 1.53.0 immer `False`).
`Proposal` trägt `Decision`, `Risk`, Playbook, Voraussetzungen, geplante Änderungen,
erwartete Wirkung, `executable`, die Katalogaktion (`action_type`) und eine Erklärung als
reines JSON. Der Entscheider muss rein sein (kein I/O, kein Router, keine Änderung am
Speicher); er läuft im Event-Loop, auch für die Route `plans`.

**Die Richtlinie in der Engine (Paket X).** Die laufende Engine (`async_setup_self_healing`)
benutzt `PolicyDecider`: er bildet den Kontext auf einen `heal_policy.DecisionInput` ab und
ruft `heal_policy.gate` (nie `decide` direkt, nie eine eigene Entscheidung); der Vorschlag
entsteht aus der Entscheidung des Gates (`to_model`, `risk.to_model`, `to_impact` bei
schreibenden Aktionen) und ist **nie** ausführbar. Geplante Änderungen gibt es nur bei einer
schreibenden Aktion mit handelndem Ergebnis (je Bauteil `kind`, Name, Aktion). Liefert das
Gate keine Entscheidung (Modul aus), gilt `ObserveOnlyDecider` mit der Erklärung des Gates.
Eine Ausnahme der Richtlinie zählt `decider_failed`, und `ObserveOnlyDecider` gilt
(`insufficient_evidence`, Score 0, Grund `no_decision_policy`, Risiko unbewertet).
`HealEngine(hass)` ohne Entscheider nutzt weiter `ObserveOnlyDecider` (Tests, Rückfall).

Ein Ablauf: Wurzelvorfall → Datensatz DETECTED → ANALYZED (Ursache von Network
Intelligence) → `context_for` (Speicher auf der Sicherheitsuhr, Core, Network Intelligence)
→ `PolicyDecider.propose` → Faktenquelle → `DecisionInput` → `gate` → Entscheidung des
Gates → `Proposal` → Prüfung der Engine (Typ, Klammer unten) → PROPOSED. Ohne Faktenquelle
bewertet die Richtlinie die Aktion des Datensatzes selbst, `observe.evaluate` (Risiko 0,
kein Router-Aufruf; die Buchungsparameter `incident`/`first_seen` werden zu `{}`, nur wenn sie
genau die des Datensatzes sind): **Recommended**, nur lesend.

**Welche Fakten die Engine füllt** (nur, was sie im Speicher hat; ihr Wert gilt immer, auch
`None`, nie der einer Faktenquelle): Rolle (`gateway`, `access_point`, `unknown`, sonst
unbekannt), Identität bestätigt (`identity_status == "confirmed"`), Wartung (Markierung oder
Network Intelligence; ohne Network Intelligence unbekannt), Schutzschalter offen und frühere
Fehlversuche in 24 h (`prior_failed_attempts`) aus dem `LoopState` auf der Sicherheitsuhr für
die Schlüssel der Kandidatenaktion, Wurzel oder Kind, Vorfallart, Ursachenstufe, -status und
-konfidenz, Zahl der Quellenfamilien. Modus, Hold, Flotten-Pause, Modulschalter und Allowlist
gehen an das Gate, `guards_green` ist `None`. **Unbekannt bleiben** Erreichbarkeit, abhängige
Router, Clients, Management-Weg, Funk-Uplink, Dienstfakten, Security-Erkennungen,
gleichzeitige Reparatur, `diag_enabled`, Schwere, Frische, Befund am Ziel, Ursache außerhalb,
zeitliche Nähe und Konfigurationsänderungen in 24 h. Ein geladener Router-Eintrag sagt nichts
über die Erreichbarkeit und wird nicht als `reachable` gelesen.

**Naht für E und F** (`HealFactsProvider`): ein Protocol mit `facts(context) -> HealFacts`.
`HealFacts` (eingefroren, geprüft) nennt eine Kandidatenaktion mit Parametern (Standard: die
des Datensatzes), einen `RiskContext`, `IncidentFacts`, `config_change_24h` und das Playbook.
Standard ist `UnknownFactsProvider` (alles unbekannt). Die Quelle bekommt eine Kopie des
Kontexts; eine Ausnahme (`facts_failed`), ein anderer Typ oder ein nachträglich veränderter
Wert (`facts_invalid`, `HealFacts` wird mit `replace` neu geprüft) heißt „nichts bekannt“.
Paket E (Vorabprüfungen) und F (Playbooks) setzen eine eigene Quelle ein:
`HealEngine.decider = PolicyDecider(provider)`.

**Die Klammer aus C1 bleibt für alles, was schreiben könnte:** eine handelnde Empfehlung ohne
bestätigte Ursache und mit weniger als zwei Quellenfamilien (nur zeitliche Nähe oder ein
einzelner Hinweis) → `insufficient_evidence` mit `why_not = insufficient_evidence_sources`
und Score höchstens 0,59 (`decision_clamped`). Ausgenommen ist nur ein Schritt mit Risiko 0,
der nichts schreibt: Aktion im Katalog, `writes` falsch, Grundrisiko 0, vorgeschlagenes
Risiko 0, keine geplante Änderung (heute `observe.evaluate`). `diag.refresh` (Risiko 1) und
jede unbekannte Aktion werden weiter geklammert.

Ausführbar ist in 1.53.0 nichts: `plan_for` meldet immer `executable: false`, die Blocker als
Codes (`no_write_path`, `mode_observe`, `router_held`, `fleet_paused`, `module_disabled`,
`in_maintenance`, `identity_not_confirmed`, `router_not_loaded`,
`insufficient_evidence_sources`, `nothing_executable`, `not_in_planning`) und seit Paket X
die Erklärung der Richtlinie: Wertzeilen, ausgelöste Regeln, Codes, Risiko, die Antwort des
Gates (Erlaubnis, Modus, Gründe; `executable_now` immer falsch), bekannte und unbekannte
Fakten und die deutschen Texte aus `REASON_TEXT_DE`. Gespeichert wird beim Lesen nichts.

**Modus:** Engine, Routen und Diagnose zeigen `HealEngine.effective_mode` =
`heal_policy.effective_mode` für Risiko 1: Modul aus, Hold oder Flotten-Pause → Observe.
`SelfHealingStore.effective_mode` (Freigabe statt Auto-Heal in der Pause) bleibt unverändert,
die Engine liest ihn nicht mehr.

**Leistung:** ereignisgetrieben plus ein Takt alle 5 Minuten; gelesen wird nur Speicher
(Vorfälle von Network Intelligence, Registry des Core), geschrieben nur über das verzögerte
Schreiben des Speichers. Kein Coordinator-Listener, kein Refresh, kein Poll; die Aufrufliste
zweier Polls ist mit laufender Engine, einem Vorfall und einem Takt gleich der ohne
(Test `test_zero_extra_router_calls`).

**DECIDED (C1):**

- Ein Schalter für die Flotte, wie bei der Time Machine; ein Eintrag mit „aus“ schaltet aus.
- Quelle sind die von Network Intelligence gemeldeten Vorfälle, nicht die Rohliste: Kinder,
  kurze Störungen, Vorfälle unter `notify_min_severity` und Vorfälle in der Wartung erzeugen so
  keinen Datensatz. Die Bus-Meldung ist nur der Auslöser; was gemeldet ist, sagt Network
  Intelligence selbst (Review PR #78).
- Je Router höchstens ein offener Observe-Datensatz (Bauteil-Doppelte des Speichers ohne
  Bauteil = der Router); weitere Wurzeln warten in der Engine. Die Warteliste geht bei einem
  Neustart verloren; Network Intelligence meldet offene Vorfälle nach einem Neustart nicht neu
  (geprüft: `_announced` ist gespeichert). Das Nachholen im Abgleich gibt ihnen ihren Datensatz.
- Flotten- und Mehr-Router-Vorfälle erzeugen keinen Datensatz.
- Zeitpunkte sind die Wanduhr der Engine, wenn sie handelt; geschlossen wird nur aus
  DETECTED, ANALYZED oder PROPOSED.
- Diagnose ohne Kennungen: nur Zähler, Stufen, Gründe und Restzeiten.

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
| `backup_ref` | `{version_id (bkp_…) oder null, reason}`; für einen Dienst-Neustart `null` (Plan, Paket G: der Neustart schreibt keine Konfiguration, lädt aber die **gespeicherte** – eine abweichende gespeicherte Konfiguration sperrt ihn, Abschnitt 9.1) |
| `execution` | `{attempt_no, intent_written_at, call_started_at, call_finished_at, call_result ok/rejected/inconclusive}` |
| `verification` | `{result resolved/partial/not_resolved/unknown/new_fault, before{}, after{}, checks[]}`; `before`/`after` höchstens 32 Schlüssel, Listen höchstens 32 Einträge |
| `rollback` | `{mechanism, statement, status}`; `mechanism` ist immer `none` |
| `audit_refs` | höchstens 64 Audit-Kennungen (`evt_…`) |
| `state_fingerprint` | sha256 des Zustands, an den eine Freigabe gebunden ist |
| `idempotency_id` | `idm_` + Hash des Idempotenz-Schlüssels; der Schlüssel selbst wird **nie** gespeichert |
| `flags` | `interrupted`, `in_maintenance`, `acknowledged_by_admin`, `hold_released` |

Abweichungen vom Entwurf (alle in Paket B):

- **DECIDED: kein `entry_id` im Datensatz.** `router_id` ist maßgeblich; eine HA-Eintragskennung
  sieht für die Maskierung des Core wie Schlüsselmaterial aus und gehört nicht in diese Datei.
- **DECIDED: `cause.code` statt `cause.key`**, `reason` statt `reason_key`, `statement` statt
  `statement_key`. Der Core behandelt jeden Feldnamen mit „key“ als geheim.
- **DECIDED: der Verlauf speichert nur Akteursarten** (`engine`, `admin`, `recovery`). Welcher
  Benutzer gehandelt hat, steht im Audit-Log des Core, nicht hier.
- **DECIDED: Idempotenz- und Doppelt-Kennungen sind Hashes** (`idm_`, `dda_`, `ddi_`, `ddc_`),
  nie die Rohwerte. Sperren tragen eine eigene Kennung `lck_` (Abschnitt 10).
- **DECIDED (Review PR #75): ein Risiko ohne Bewertung zählt als das höchste** (`risk_class`
  ist ohne Angabe 3). Ein Datensatz, den noch niemand bewertet hat, kommt so nie als
  „nur lesend“ an einer Sperre (Hold, Abschnitt 5.1) vorbei.

Hilfsfunktionen: `action_dedupe_id(router_id, action_type, params)` (gleiche Eingabe → gleiche
`dda_`-Kennung), `incident_dedupe_id(incident_id)` (`ddi_`, flottenweit),
`component_dedupe_id(router_id, component)` (`ddc_`), `component_ref(component)`
(`kind:name` für die Schlüssel des Schleifenschutzes, bei zu langem Namen `cmp_` + Hash),
`idempotency_id(raw)` (`idm_`) und `binding_hash(action, catalog_version=…)` (sha256 über
Router, Aktion, Parameter, Katalog- und Playbook-Fassung, Vorfall mit Wiederöffnungszahl und
Zustands-Fingerabdruck).

### 3.1 Feldregeln (Review PR #75)

Kein sicherheitsrelevantes Feld lässt sich außerhalb seines Übergangs ändern. Es gibt nur drei
Wege, einen Datensatz zu ändern: `transition(…, changes=…)` (mit dem Zustandswechsel),
`with_changes(**felder)` (ohne Zustandswechsel, Speicher: `update()`) und
`with_flags(in_maintenance=…, acknowledged_by_admin=…)` (Speicher: `update_flags()`;
`hold_released` setzt nur `release_hold()`).

**Nie änderbar** (weder `with_changes` noch `transition`): `action_id`, `router_id`, `state`,
`history`, `created_at`, `updated_at` (diese vier setzt nur `transition` selbst),
**`action_type`, `params`, `incident_id`, `components`, `idempotency_id`** (die Eingaben der
Doppelt-Prüfung, Punkt P1-2) und **`flags`**.

**DECIDED (P1-2): die Eingaben der Doppelt-Prüfung werden nach DETECTED eingefroren**, statt
die Doppelt-Tabellen bei jeder Änderung neu zu buchen. Begründung: die Engine legt den
Datensatz erst an, wenn das Playbook die Aktion gewählt hat; einfrieren passt zu ihrem Ablauf,
ist einfacher und strenger. Soll eine andere Aktion laufen, entsteht ein neuer Datensatz (der
alte wird abgebrochen).

| Feld | wann änderbar |
|---|---|
| `incident_type`, `incident_reopen`, `cause`, `playbook_id`, `playbook_version`, `decision`, `risk`, `prerequisites`, `planned_changes`, `expected_impact`, `backup_ref`, `state_fingerprint` | nur in der Planung (DETECTED, ANALYZED, PROPOSED, PREFLIGHT): `with_changes` oder ein Übergang **aus** einem dieser Zustände |
| `preflight` | Planung (auch `with_changes`) oder ein Übergang aus APPROVED |
| `rollback` | Planung (auch `with_changes`) oder ein Übergang aus FAILED, ROLLBACK_PENDING, ROLLING_BACK |
| `approval` | nur mit einem Übergang aus der Planung oder aus WAITING_APPROVAL, dazu APPROVED → CANCELLED; ab WAITING_APPROVAL bleiben `guard_approval_id` und `binding_hash` gleich (die Bindung ändert sich nie) |
| `execution` | nur mit einem Übergang aus APPROVED, EXECUTING oder VERIFYING; `intent_written_at` und `attempt_no` nur beim Eintritt in EXECUTING (den Zeitpunkt setzt das Modell, die Nummer der Speicher) |
| `verification` | nur mit einem Übergang aus PREFLIGHT, APPROVED, EXECUTING, VERIFYING, ROLLING_BACK |
| `audit_refs` | jederzeit, aber nur anhängen (die alten Einträge bleiben vorn, in ihrer Reihenfolge) |
| `flags.interrupted` | nur die Neustartregel (Übergänge mit `interrupts`) setzt es; nichts löscht es |
| `flags.in_maintenance` | `with_flags`, in beide Richtungen |
| `flags.acknowledged_by_admin` | `with_flags`, nur von `false` nach `true` |
| `flags.hold_released` | nur `SelfHealingStore.release_hold()` (Review 2, P2-2), nur von `false` nach `true`; `update_flags()` lehnt es ab |

`RemediationAction.new()` nimmt `flags`, `approval`, `execution` und `verification` nicht an:
ein neuer Datensatz beginnt mit ihren Standardwerten. **`SelfHealingStore.add()` nimmt nur
solche Datensätze** (`is_new`: DETECTED mit genau einem Verlaufseintrag, `updated_at` =
`created_at`, diese vier Felder auf Standard; Review 2, P3). Ein mit dem Konstruktor oder
`from_dict` gebauter Datensatz mit anderen Werten wird abgelehnt; nur das Laden der Datei
bringt solche Datensätze.

**Stand heute:** gebaut und getestet. Seit Paket C1 legt die Engine Datensätze an (Observe, bis
PROPOSED, Abschnitt 2.1).

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
(erschöpfende Suche über 88 Konfigurationen, die Breitensuche des Reviews mit bis zu drei
Neustarts, 200 Zufallswege, im Speicher 40 Zufallsläufe mit Neustarts); die Wiederherstellung
(R) betritt nie EXECUTING, ROLLING_BACK oder APPROVED; nur ein Administrator gibt frei oder
lehnt ab. Die 40 Zufallsläufe bevorzugen den Weg der Engine nach vorn (75 % der Schritte), damit
sie wirklich bis zum dauerhaften Schreiben kommen: gemessen führen 30 von 40 Läufen mindestens
eine Aktion aus, 48 Ausführungen insgesamt, keine doppelt. Der Test verlangt mindestens 20
Läufe und 40 Ausführungen. (Vor dem Review lief dort keine einzige Ausführung.)

**Stand heute:** gebaut und getestet. Seit Paket C1 löst die Engine die Übergänge DETECTED →
ANALYZED → PROPOSED und das Schließen aus; alles ab PREFLIGHT fehlt noch (C2, E, H, I).

## 5. Speicher, Neustart, Grenzen, Versionen

Code: `heal_store.SelfHealingStore`. Store `openwrt_router.self_healing`, Version 1.2 (Minor 2
seit Paket D: Versuchsdatensätze tragen zusätzlich `recent`, Abschnitt 10.2), über
`core_store.create_store` (private Datei, atomares Schreiben, Migrationsfunktion ab dem ersten
Tag). Inhalt:

| Schlüssel | Inhalt |
|---|---|
| `saved_at` | Zeitpunkt des Schreibens |
| `write_seq` | zählt jedes Schreiben; daran erkennt das Rücklesen das eigene Schreiben |
| `settings` | Modul an/aus, Grenzen des Schleifenschutzes, je Router Modus und Allowlist |
| `actions` | die Datensätze (Abschnitt 3) |
| `loop` | Schleifenschutz als Daten (Abschnitt 10), Holds (5.1), Sicherheitsuhr (5.2) |
| `maintenance` | Wartungsfenster für Schnittstellen und Dienste |

**Schreiben.** Eine Änderung im Arbeitsspeicher stellt **ein** verzögertes Schreiben nach
10 s an (weitere hängen sich daran). Sofort geschrieben wird nach dem Laden, wenn die
Neustartregel etwas geändert oder etwas Kaputtes übersprungen hat.

**Schreiben vor dem Handeln** (`async_apply_durable`). Die Übergänge, die die Tabelle als
`durable` markiert (nach EXECUTING und nach ROLLING_BACK), gehen nur hier; der normale Weg
`apply()` lehnt sie ab (`WriteAheadRequiredError`). Ablauf:

1. Übergang prüfen (ein unerlaubter wirft, nichts wird geschrieben).
2. Kein Schreiben, wenn der Speicher nicht geladen (`not_loaded`) oder schon geschlossen ist
   (`closed`), HA herunterfährt (`stopping`; Zustände stopping, final_write, stopped), der
   Router gesperrt ist (`router_held`, Abschnitt 5.1), ein anderer Halter die Router-Sperre
   hat (`router_locked`) oder die offenen Datensätze allein schon zu groß sind (`over_size`).
3. Nur beim Eintritt in EXECUTING: der Schleifenschutz prüft je Schlüssel (Router, Aktion,
   Bauteil) einen offenen Schutzschalter (`breaker_open`), eine laufende Abklingzeit
   (`cooling_down`) und die Versuche in 24 h (`max_attempts`). Geht es weiter, wird der
   Versuch **im selben Schreiben** gebucht: Zeitpunkt in `recent`, Zähler = Versuche in den
   letzten 24 h (gleitendes Fenster, Abschnitt 10.2), Abklingzeit = die längere von `cooldown_s`
   und dem exponentiellen Backoff (`backoff_base_s` · 2^(n−1), höchstens `backoff_cap_s`), nie
   kürzer als eine schon laufende; das Ergebnis des neuen Versuchs ist offen (`last_result`
   `None`); `execution.attempt_no` = Nummer des Versuchs. Alles auf der Sicherheitsuhr
   (Abschnitt 5.2). Das ist eine zweite Linie neben der Entscheidung der Engine (Paket D/I).
4. Die Schreibnummer (`write_seq`) wird **vor** dem Warten vergeben. Die Datei mit dem neuen
   Zustand wird **sofort** geschrieben und **zurückgelesen** (im Executor). Nur wenn die
   gelesene Datei diese oder eine spätere Schreibnummer mit genau diesem Datensatz enthält,
   ändert sich der Datensatz im Arbeitsspeicher, und das Ergebnis ist `ok`.
5. Sonst bleibt der Datensatz, wo er war (`write_failed` bzw. `not_durable`), und das nächste
   Schreiben wird sofort angestellt, damit auf der Platte wieder der wahre Zustand steht. Der
   Aufrufer darf dann den Router **nicht** aufrufen.

**Nebenläufigkeit (Review P1-1).** Es läuft immer nur ein dauerhafter Schritt; `async_flush()`
und `async_close()` warten auf ihn (dieselbe asyncio-Sperre). Solange er läuft, enthält **jede**
Nutzlast, die gebaut wird – ein verzögertes Schreiben oder HAs letztes Schreiben beim
Herunterfahren – schon den neuen Datensatz, die gebuchten Versuche und die Router-Sperre. Kein
späteres Schreiben kann so den alten Zustand zurück auf die Platte legen, nachdem `ok`
gemeldet wurde. Schlägt der Schritt fehl, steht auf der Platte vielleicht kurz der neue Zustand,
obwohl `ok` nicht kam; das ist die sichere Richtung (nach einem Neustart „unbekannt“, nie
wiederholt), und das sofort angestellte Schreiben legt den wahren Zustand zurück. Nach
`async_close()` meldet kein dauerhafter Schritt mehr Erfolg (`closed`). Zwei Tests stellen den
Fall des Reviews nach (Schließen, während das Rücklesen zurückkommt), einer davon mit HAs
echtem Store und Executor.

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
öffnet (Entwurf), kommt mit Paket I. Macht die Neustartregel eine Aktion, die schon EXECUTING
erreicht hatte, endgültig (FAILED → ESCALATED, ROLLBACK_PENDING → MANUAL_RECOVERY_REQUIRED),
wird ihr Router gesperrt wie in Abschnitt 5.1. Diese Holds ohne Ende setzt jedes Laden aus den
Datensätzen neu (Abschnitt 5.1), auch wenn der Schleifenschutz in der Datei kaputt war.

Sperren und Doppelt-Kennungen werden beim Laden aus den Datensätzen neu aufgebaut. **Sperren
von Schreibzugriffen außerhalb der Engine fallen beim Laden weg** – nach einem Neustart kann
keiner davon mehr laufen. Holds (5.1) und die Sicherheitsuhr (5.2) stehen in der Datei und
überleben den Neustart.

**Verlust und Schaden.** Eine fehlende Datei ist ein erster Start (Standardwerte). Eine
unlesbare, fremde oder neuere Hauptversion startet leer, bleibt als `.bak` (bzw. HAs
`.corrupt.<Zeit>`) liegen, **pausiert Auto-Heal für die ganze Flotte** für 24 h (Grund
`store_lost`), weil Versuche und Schutzschalter unbekannt sind, und **sperrt die ganze Flotte**
für 24 h (Hold `store_lost`). Einzelne kaputte Teile (Datensatz, doppelte Kennung,
Einstellungen, Wartungsliste, Schleifenschutz) werden übersprungen und gezählt; dann gibt es
ebenfalls eine `.bak`-Kopie und die Pause (Grund `store_damaged`), und:

- ein kaputter Datensatz oder ein kaputtes Wartungsfenster mit **lesbarer** Router-Kennung
  sperrt diesen Router für 24 h (Hold `record_unreadable`);
- ist die Router-Kennung nicht lesbar oder der Schleifenschutz kaputt, wird die **ganze Flotte**
  für 24 h gesperrt;
- zeigt ein kaputter Datensatz in seinem rohen `state` oder Verlauf (`history[].to_state`) noch
  EXECUTING, VERIFYING oder ROLLING_BACK (ein Router-Aufruf kann gelaufen sein), gilt der Hold
  **ohne Ende**, nur ein Administrator hebt ihn auf (Review 2, Punkt 3) – für seinen Router,
  bei unlesbarer Router-Kennung für die Flotte.

**DECIDED (Koordinator, P2-7):** gesperrt heißt Observe, Freigabe und Auto-Heal blockiert; die
Sperre gilt 24 h oder bis ein Administrator sie aufhebt, steht in der Datei und ist sichtbar
(`router_hold()`, `stats()["holds"]`). Kaputte Einstellungen heißen Standardwerte, also Observe
für jeden Router.

**DECIDED (Koordinator, Review 2 Punkt 3):** ein kaputter Datensatz, der noch zeigt, dass er
einen Router-Aufruf erreicht hat, sperrt ohne Ende; ohne diesen Hinweis bleiben es 24 h.
**DECIDED (Unter-Sitzung):** ist dabei die Router-Kennung nicht lesbar, wird die **Flotte** ohne
Ende gesperrt – der Ausgang ist auf irgendeinem Router unbekannt, und nur ein Administrator kann
sagen, auf welchem. Ein beendeter Datensatz mit einem solchen Verlauf zählt ebenso (streng:
der Verlauf allein entscheidet, nicht, ob der Ausgang bekannt war).

**Grenzen** (keine davon wirft je eine laufende Aktion hinaus; alle Zeiten auf der
Sicherheitsuhr, Abschnitt 5.2):

| Grenze | Wert | Verhalten |
|---|---|---|
| Datensätze gesamt | 500 | ein neuer verdrängt den ältesten Endzustand, nie einen, den ein geltender Hold nennt (Review 3); gibt es keinen, wird er abgelehnt (`CapacityError`) |
| offene je Router | 20 | darüber wird ein neuer abgelehnt |
| Aufbewahrung Endzustände | 90 Tage Sicherheitsuhr ab dem Ende | `prune()` entfernt ältere; gemessen ab der Sicherheitszeit, zu der der Datensatz endete (`loop.terminal_at`), nie an seinen Wanduhr-Stempeln (Review 2, P2-4) |
| Idempotenz | 24 h, höchstens 1000 | die Kennung einer **offenen** Aktion bleibt immer; die einer beendeten ist nach 24 h vergessen (siehe unten) |
| Wartungsfenster | höchstens 100, beendete 90 Tage | ein Fenster fällt erst, wenn Wanduhr **und** Sicherheitsuhr 90 Tage über seinem Ende sind (seine Zeiten sind Wanduhr-Zeiten des Administrators) |
| Versuchszähler | 7 Tage ohne Versuch, nur außerhalb des 24-h-Fensters und ohne laufende Abklingzeit, höchstens 1000 (die Obergrenze verdrängt nur solche) | |
| Schutzschalter | ein **offener** bleibt immer; geschlossene 90 Tage, höchstens 1000 | |
| Holds | ohne Ende nur durch einen Administrator; mit Ende danach | |
| Fremd-Schreibzugriffe | die letzten 200 | |
| Datei | 1 000 000 Byte | darüber fallen Endzustände, die ältesten zuerst (nie einer, den ein geltender Hold nennt) – aber **nur, wenn das die Datei unter die Grenze bringt**. Sind die offenen Datensätze allein schon zu groß, fällt nichts (Review P2-10): ein verzögertes Schreiben wird trotzdem ausgeführt (gezählt, `save_over_size`), weil sonst eine offene Aktion verloren ginge, und ein Schreiben vor dem Handeln wird abgelehnt (`over_size`) |

**Idempotenz (Review P2-5).** Eine bekannte Idempotenz-Kennung, deren Datensatz fehlt
(verdrängt oder entfernt), wird abgelehnt (`IdempotencyExpiredError`) und **nie** zu einer neuen
Aktion. Nach Ablauf (24 h auf der Sicherheitsuhr, Aktion beendet) ist die Kennung vergessen; eine
Wiederholung darf dann einen neuen Datensatz anlegen. Was eine zweite Ausführung trotzdem
verhindert, zeigen Tests: ist die erste Aktion noch offen, gibt die Doppelt-Prüfung sie zurück
(ihre Kennung wird auch nie vergessen); ist sie beendet, lehnt der Schleifenschutz beim
dauerhaften Schritt mit `cooling_down` bzw. `max_attempts` ab.

**Größe.** Die Größe ist eine Schätzung nach oben aus den zwischengespeicherten Größen der
Datensätze (je Datensatz einmal in seiner Tiefe in der Datei gemessen, plus Trennzeichen);
nur der Teil außerhalb der Datensätze wird je Schreiben serialisiert. Früher wurde die ganze
Nutzlast bei jedem Verdrängen neu serialisiert (rund 70 ms nahe 1 MB in der Ereignisschleife).

Gemessen (Python 3.13, HAs eigene JSON-Serialisierung, eingerückt wie HA schreibt): ein
vollständig gefüllter Datensatz wie in `full_action()` der Tests hat **5 908 Byte**, ein neuer
2 269 Byte. 500 vollständige Datensätze wären 2 952 828 Byte; die Dateigrenze hält also
höchstens rund 170 solcher Datensätze, die übrigen Endzustände fallen vorher. Offen können bei
20 je Router und rund 6 KB je Datensatz für etwa 8 Router alle gleichzeitig in der Datei
stehen. **DECIDED:** 1 MB aus dem Entwurf beibehalten; die Grenze ist die strengere, und eine
Aktion, die nicht mehr sicher in die Datei passt, wird nicht ausgeführt.

### 5.1 Gesperrte Router (Holds)

Ein **Hold** (`heal_model.RouterHold`, in `loop.holds`, Schlüssel Router-Kennung bzw. `""` für
die Flotte) ist etwas anderes als die Router-Sperre (`LockRecord`): die Sperre gilt, solange
eine Reparatur läuft; ein Hold bleibt danach, bis ein Administrator ihn aufhebt oder seine Zeit
abläuft. Solange ein Hold gilt:

- ist der wirksame Modus des Routers Observe (`effective_mode()`), auch wenn Approval oder
  Auto-Heal eingestellt ist;
- lehnt der Speicher für eine Aktion mit Risiko 1 oder mehr jeden Schritt zu einem Schreiben ab:
  WAITING_APPROVAL, APPROVED, EXECUTING, ROLLBACK_PENDING, ROLLING_BACK (`RouterHeldError` bzw.
  `router_held`);
- laufen nur lesende Diagnosen (Risiko 0) weiter.

| Grund | wann | Ende |
|---|---|---|
| `outcome_unknown` | eine Aktion, die EXECUTING erreicht hatte, endet in MANUAL_RECOVERY_REQUIRED | nur Administrator |
| `outcome_escalated` | eine solche Aktion endet in ESCALATED – außer wenn der Router den Aufruf sauber abgelehnt hat (EXECUTING → FAILED mit `call_result` `rejected`, nicht unterbrochen) | nur Administrator |
| `record_unreadable` | kaputter Datensatz beim Laden (Router, sonst Flotte) | 24 h oder Administrator; **nur Administrator**, wenn sein roher Zustand oder Verlauf noch EXECUTING, VERIFYING oder ROLLING_BACK zeigt |
| `store_lost` | Datei verloren, unlesbar oder neuer (Flotte) | 24 h oder Administrator |
| `stuck_released` | ein Administrator beendet eine hängende Aktion (`admin_release_stuck`) | nur Administrator |
| `lock_forced` | ein Administrator entfernt eine hängende Fremd-Sperre (`admin_force_release_lock`) | nur Administrator |

**DECIDED (Koordinator, P2-8):** ein Hold mit Grund, Zeitpunkt und Aktions-Kennung, getrennt von
der Router-Sperre, steht in der Datei und gilt bis zur ausdrücklichen Freigabe durch einen
Administrator (`release_hold(router_id oder None, actor=admin, ts=…)`); lesende Diagnosen
(Risiko 0) sind nicht blockiert. Treffen zwei Holds auf denselben Schlüssel, bleibt der, der
länger gilt.

**Holds aus den Datensätzen (Review 2, P2-2).** Die Holds `outcome_unknown` und
`outcome_escalated` folgen aus den beendeten Datensätzen selbst (`hold_reason_for`). Jedes Laden
setzt sie für jeden solchen Datensatz neu, ohne Ende – ein kaputter Abschnitt `loop` macht aus
ihnen also nicht mehr einen 24-h-Hold der Flotte. Hebt ein Administrator den Hold eines Routers
auf, markiert `release_hold()` jeden beendeten Datensatz dieses Routers, dessen Ende einen Hold
setzt, mit `flags.hold_released`; markierte Datensätze setzen ihren Hold nicht wieder. Das
geschieht **nur, wenn wirklich ein Hold aufgehoben wurde** (Rückgabe True); ohne Hold ändert
`release_hold()` nichts und gibt False zurück, kann also nie stillschweigend künftige Holds
entschärfen (Review 3). **DECIDED (Unter-Sitzung, Review 3):** diese Variante statt „True,
wenn markiert“, weil ein Aufruf ohne Hold sonst die Wiederherstellung nach einem kaputten
Abschnitt `loop` abschalten könnte.

Der Datensatz hinter einem geltenden Hold wird **nie verdrängt und nie nach 90 Tagen entfernt**
(weder beim Anlegen noch wegen der Dateigröße noch von `prune()`; Review 3): sonst bliebe nach
einem kaputten Abschnitt `loop` nichts, woraus der Hold wieder entsteht. Erst nach der Freigabe
gilt seine Aufbewahrung wieder. Holds ohne Datensatz (`lock_forced`, `record_unreadable`,
`store_lost`) kommen bei einem kaputten Abschnitt `loop` nicht zurück; dann gilt der 24-h-Hold
der Flotte.

**Auswege für den Administrator (Review P3).** `admin_release_stuck(action_id, actor=admin, ts=…)`
führt eine Aktion, die in EXECUTING, VERIFYING oder ROLLING_BACK hängt, über die
Wiederherstellungskanten (EXECUTING/ROLLING_BACK → VERIFYING mit `interrupted`, dann →
MANUAL_RECOVERY_REQUIRED) heraus, gibt die Router-Sperre frei und hinterlässt den Hold
`stuck_released`; nie eine neue Ausführung oder einen Rollback.
`admin_force_release_lock(router_id, actor=admin, ts=…)` entfernt eine hängende Fremd-Sperre
und hinterlässt den Hold `lock_forced`; eine Sperre der Engine fasst es nicht an. Beides prüft
nur die Akteursart; dass wirklich ein HA-Administrator handelt und das Audit, kommt mit den
Routen (Paket C2/F).

### 5.2 Sicherheitsuhr

Alle Wartezeiten des Schleifenschutzes laufen auf der **Sicherheitsuhr**
(`heal_model.SafetyClock`, in `loop.clock`, abgefragt mit `SelfHealingStore.now()`), nicht auf
der Wanduhr. Sie geht **nie rückwärts** und je Beobachtung **höchstens 900 s**
(`CLOCK_STEP_MAX_S`) vor. Wie weit, hängt davon ab, ob es eine Beobachtung aus demselben Lauf
von HA gibt (Review 2, P2-1):

- **Während HA läuft** zählt die **monotone Uhr** (Standard `time.monotonic`, im Speicher über
  `monotonic=` einstellbar): der Schritt ist die monotone Zeit seit der letzten Beobachtung
  (`observe(wall, elapsed=…)`). Die Wanduhr bewegt die Sicherheitsuhr dann **gar nicht**. Die
  Höchstmarke `high` rückt um denselben Schritt mit (und auf die Wanduhrzeit, wenn die höher
  ist; Review 3) – so zählt die im Lauf gezählte Zeit beim nächsten Start nicht noch einmal,
  auch wenn die Wanduhr im Lauf zurückgestellt war.
- **Bei der ersten Beobachtung nach einem Start** (die monotone Uhr beginnt mit jedem Prozess
  neu) und ohne monotone Quelle zählt die Wanduhr, aber **nur, soweit sie über der Höchstmarke
  liegt** (`high`: die höchste gesehene Wanduhrzeit, im Lauf um die gezählte Zeit vorgerückt;
  steht in der Datei und sinkt nie). Ein Sprung zurück zählt nichts, und die Strecke bis zur
  Höchstmarke zählt auch danach nicht noch einmal.

Sprünge werden gezählt (`jumps_ahead`, `jumps_back`, in `stats()`).

Vorher rückte die Uhr nach einem Sprung zurück von der niedrigeren Wanduhrzeit aus wieder vor:
eine Wanduhr, die um 900 s hin und her sprang, ergab in rund 200 s etwa 22 h Sicherheitszeit,
eine Abklingzeit von 30 min war nach rund 16 s vorbei, und das 24-h-Fenster der Versuche ließ
sich genauso aushebeln (Review 2, P2-1).

**Garantie.**

- **Während HA läuft, verkürzt keine Änderung der Wanduhr eine Wartezeit** – weder vor noch
  zurück noch hin und her. Die Sicherheitsuhr läuft dann nie schneller als die monotone Uhr,
  also nie schneller als die echte Zeit.
- **Verkürzen kann eine Wartezeit nur ein Start von HA**, und zwar um **höchstens 900 s je
  Start**: beim Start zählt nur die Wanduhrzeit über der Höchstmarke, höchstens 900 s. Weil die
  Marke im Lauf mit der gezählten Zeit vorrückt, ist das echte Ausfallzeit oder Zeit, um die
  die Wanduhr der echten Zeit vorausgeht – beides ist von außen nicht zu unterscheiden. Echte
  Zeit zählt nie doppelt (Review 3: vorher zählte die Laufzeit nach einem Zurückstellen beim
  nächsten Start noch einmal, 48 solche Zyklen in 12 h ergaben 24 h). Eine Wanduhr, die einmal
  falsch vorgeht und dabei bleibt, gewinnt die 900 s nur einmal.
- Alles andere **verlängert** Wartezeiten höchstens: Ausfallzeit über 900 s, mehr als 900 s
  zwischen zwei Beobachtungen, eine Wanduhr, die nach einem Start unter ihrer Höchstmarke liegt
  (sie zählt erst wieder, wenn sie die Marke überholt).
- Liegt die Sicherheitszeit weniger als 400 Tage vor `TIME_MAX` (eine absurde Wanduhr beim
  ersten Start), lehnt der dauerhafte Schritt in EXECUTING mit `clock_invalid` ab, und Holds und
  Pausen beim Laden enden bei `TIME_MAX` (Review 3). Die Uhr bleibt dort stehen; nur ein
  Administrator kann das auflösen (Datei neu anlegen).

**DECIDED (P2-9, Review 2 P2-1): im Zweifel länger warten** – monotone Uhr während des Laufs,
Höchstmarke über Starts. Der Preis: ging die Wanduhr einmal weit vor und wurde dann korrigiert,
zählt nach dem nächsten Neustart keine Ausfallzeit, bis die echte Zeit die Höchstmarke erreicht;
während HA läuft, vergeht die Zeit normal. Die Engine (Paket C1) fragt die Uhr mindestens alle
5 Minuten ab, sonst gehen Minuten über 900 s je Abfrage verloren (länger, nie kürzer).

**Aufbewahrung (Review 2, P2-4).** Endzustände werden nicht mehr an ihrem `updated_at`
(Wanduhr) gemessen: startete die Sicherheitsuhr bei einem ersten Start mit einer weit
vorgehenden Wanduhr, hätte jedes `prune()` jeden später beendeten Datensatz sofort gelöscht.
Jetzt stempelt der Speicher die Sicherheitszeit, zu der ein Datensatz endet
(`loop.terminal_at`), und misst die 90 Tage ab dort; ein beendeter Datensatz ohne Stempel (nach
einem kaputten Abschnitt `loop`) bekommt beim Laden die aktuelle Sicherheitszeit. Wartungsfenster
tragen Wanduhr-Zeiten des Administrators; eins fällt erst, wenn Wanduhr **und** Sicherheitsuhr
90 Tage über seinem Ende sind.

| Wartezeit | Uhr | Sprung zurück | Sprung nach vorn |
|---|---|---|---|
| Abklingzeit, Backoff (`cooldown_until`) | Sicherheitsuhr | im Lauf: ohne Wirkung (echte Zeit zählt weiter, die Marke rückt mit), beim nächsten Start zählt sie nicht noch einmal; nach einem Start: nichts unter der Marke – länger | im Lauf: ohne Wirkung; beim Start: höchstens +900 s über der Marke |
| 24-h-Fenster der Versuche | Sicherheitsuhr | im Lauf ohne Wirkung; nach einem Start länger | im Lauf nie kürzer; beim Start höchstens 900 s kürzer |
| Pause der Flotte (`paused_until`) | Sicherheitsuhr | ebenso | ebenso |
| Hold mit Ende (`until`) | Sicherheitsuhr | ebenso | ebenso |
| Idempotenz (24 h) | Sicherheitsuhr | im Lauf ohne Wirkung; nach einem Start länger behalten | ebenso |
| Aufbewahrung Endzustände (90 Tage) | Sicherheitsuhr ab `loop.terminal_at`; nie ein Datensatz, den ein geltender Hold nennt | ebenso | ebenso; nie an Wanduhr-Stempeln gemessen |
| Aufbewahrung Versuche (7 Tage), Schutzschalter (90 Tage) | Sicherheitsuhr | ebenso | ebenso |
| Aufbewahrung Wartungsfenster (90 Tage nach `end`) | Wanduhr **und** Sicherheitsuhr | länger behalten | länger behalten |
| Wartungsfenster aktiv | Wanduhr **oder** Sicherheitsuhr | zählt, solange eine von beiden im Fenster liegt: länger | ebenso: länger |
| Freigabe (`approval.expires_at`) | Guard des Core, nicht dieser Speicher (das Feld ist nur Auskunft) | offen für C2: ein Sprung zurück darf eine Freigabe nicht verlängern | verfällt früher (sicher) |
| Router-Sperre (`since`) | Wanduhr, nur Auskunft | läuft nie ab | läuft nie ab |
| Verlauf, `created_at`, `updated_at` | Wanduhr, wie übergeben | festgehalten, wie er kam | festgehalten, wie er kam |

**Versionen:** Unterversionen nur additiv (eine neuere Unterversion wird gelesen, unbekannte
Schlüssel werden ignoriert); eine unbekannte Hauptversion → `.bak` und leer, wie bei den
Core-Speichern.

**Stand heute:** gebaut und getestet. Seit Paket C1 lädt die Engine den Speicher beim Start; die
Datei entsteht mit dem ersten Datensatz (Abschnitt 1). Paket D hat Minor 2 hinzugefügt
(`recent`, Abschnitt 10.2).

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

Code: `heal_catalog.py` (Paket D), Katalogfassung `CATALOG_VERSION = 1`. Der Katalog ist
**Daten**: je Aktion ein unveränderlicher `CatalogEntry` in einer schreibgeschützten Abbildung
(`CATALOG`), beim Import einmal gebaut. Es gibt keine Funktion, die eine Aktion hinzufügt,
ersetzt oder entfernt; eine Kennung aus dem Frontend, einem Dienst oder einem Vorfall wird
nachgeschlagen, nie gedeutet. Das Risiko wird berechnet (Grundklasse + Kontext, Abschnitt 9),
nie nur aus dem Namen gelesen.

| Kennung | Parameter (geschlossen) | Router-Aufruf (nur Name) | ACL | Status | Grundrisiko | Rollback-Aussage |
|---|---|---|---|---|---|---|
| `observe.evaluate` | – | keiner | – | bereit | 0 | `read_only_nothing_changes`: nichts ändert sich |
| `diag.refresh` | – | `coordinator.refresh` (ein normaler Poll) | vorhandene Lese-Rechte | bereit; höchstens einmal je 5 min je Router (`min_interval_s = 300`, `heal_policy.interval_verdict`) | 1 | `read_only_nothing_changes` |
| `diag.ha_probes` | – | `diag.manual_run` (HA-Seite) | – | bereit, nur mit eingeschalteter Diagnose | 1 | `read_only_nothing_changes` |
| `service.restart` | `service` ∈ {`dnsmasq`, `odhcpd`} | `rc.init.restart` | `rc/init` (nicht in ACL v8; heute nur über die Root-Anmeldung) | **bereit** für das erste Schreib-Release (`first_write_release_approval_only`), nur mit Freigabe | 2 | `applies_saved_config_no_undo_manual_if_not_back`: der Neustart lädt die **gespeicherte** Konfiguration – weicht sie von der laufenden ab, setzt er diese Änderung in Kraft; es gibt kein Zurücknehmen; kommt der Dienst nicht wieder, **manuelle Wiederherstellung** |
| `wifi.radio_restart` | `radio` ∈ {`radio0` … `radio3`} | `network.wireless.down_up` | `network.wireless/down`, `/up` (in ACL v8) | **gesperrt** (`call_unverified_on_fleet`) | 2 | `up_undoes_down_only_while_path_holds`: ein zweiter Aufruf (`up`) nimmt es zurück, **nur solange der Management-Weg hält**, sonst manuell |
| `router.reboot` | – | `system.reboot` | `system/reboot` (nicht in ACL v8) | **gesperrt** (`modelled_blocked_no_out_of_band`); der vorhandene Knopf bleibt | 3 | `no_rollback_no_out_of_band_path`: kein Rollback, manuelle Wiederherstellung |
| `config.restore` | `version_id` = `bkp_` + 32 hex | keiner (kein Ausführer) | – | **gesperrt** (`restore_dry_run_only`); Playbook F liefert nur einen Probelauf | 3 | `no_rollback_restore_is_manual`: kein Rollback, manuell |
| `interface.cycle` | `interface` ∈ {`lan`, `wan`, `wan6`} | `network.interface.down_up` | `network.interface/down`, `/up` (nicht in ACL v8) | **gesperrt** (`recommendation_only_no_acl`), nur Empfehlung | 3 | `up_undoes_down_only_while_path_holds` |

**Nie im Katalog** (eine solche Kennung wird abgelehnt wie jede unbekannte, die Erklärung
nennt die Familie): Aktionen an Clients (`client.*`: trennen, sperren, umlenken;
`never_client_action`), Firewall (`never_firewall`), VLAN (`never_vlan`), Management-Adresse
(`never_management_ip`), Routing (`never_routing`), Firmware (`never_firmware`),
`network reload` (`never_network_reload`), ein Neustart von `wpad` (`never_wpad_restart`; als
Dienstname von `service.restart` ist `wpad` ebenfalls kein erlaubter Wert), das Löschen von
DHCP-Leases (`dhcp.*`, `never_dhcp_lease_delete`), UCI-Schreiben und Befehle
(`never_config_write`, `never_shell`).

**Vorläufig, nicht entschieden:** Die Auswahl oben (nur `service.restart` für das erste
Schreib-Release; Funk-Neustart, Router-Neustart, Wiederherstellen und Schnittstelle ab/an
modelliert und gesperrt; Auto-Heal nur bis Risiko 1) ist die **strenge Voreinstellung aus dem
Auftrag zu Paket D**. Der Eigentümer hat die offenen Fragen Q5–Q7 (Abschnitt 16) noch nicht
beantwortet; entschieden ist nur, dass 1.53.0 nur beobachtet.

Jeder Eintrag trägt außerdem: Fassung, ob er schreibt, was er unterbricht (`disruption`:
keiner, Dienst, Funk, Schnittstelle, Router), das Zielbauteil, die **Fakten, die die Richtlinie
braucht** (`needs_facts`, Felder von `heal_policy.RiskContext`), die **Prüfungen danach**
(`verification_probes`, z. B. `service_running_new_pid`, `service_stable_two_polls`,
`root_incident_not_reopened`) und die geschätzte Unterbrechung.

**Prüfung** (`validate(action_type, params)` → `ValidatedAction` mit Parametern und Bauteil,
sonst `CatalogError` mit einem Code, der den Wert nie wiederholt): die Kennung muss ein
genaues `str` sein und im Katalog stehen (keine Groß-/Kleinschreibung, keine Leerzeichen, keine
Unterklasse von `str`); Parameter müssen eine Abbildung mit genau den bekannten Namen sein; jeder
Wert muss ein genaues `str` aus der geschlossenen Menge sein bzw. die feste Form `bkp_` + 32 hex
(ganz, `fullmatch`) haben. Jeder Wert wird **genau einmal** gelesen; geprüft und behalten wird
derselbe Wert, als schreibgeschützte Abbildung. Codes: `action_type_invalid`,
`unknown_action`, `never_*`, `params_invalid`, `param_unknown`, `param_missing`,
`param_value_invalid`, `entry_not_in_catalog`, `components_invalid`. Eine gesperrte Aktion
besteht die Prüfung der Form; die Richtlinie lehnt sie als „Nicht unterstützt“ mit ihrem Grund
ab.

**Eine `ValidatedAction` gibt es nur um den Katalogeintrag selbst** (Review PR #77):
`__post_init__` verlangt, dass `entry` **dasselbe Objekt** wie `CATALOG[entry.action_type]` ist
(eine gleiche oder veränderte Kopie wird mit `entry_not_in_catalog` abgelehnt), prüft die
Parameter noch einmal und leitet die Bauteile aus ihnen ab (andere Bauteile:
`components_invalid`). `dataclasses.replace` läuft durch dieselbe Prüfung.

**DECIDED (Paket D):** keine Rollback-Art „heilt sich über den Dienst-Supervisor“. procd startet
einen abgestürzten Dienst zwar neu, aber das ist kein Rollback: kommt `dnsmasq` nach einem
Neustart wegen eines Konfigurationsfehlers nicht hoch, scheitert auch procd. Die Aussage für
`service.restart` ist deshalb die strengere „keine Konfigurationsänderung, sonst manuell“.
**DECIDED:** Funk und Schnittstelle nehmen nur Namen aus einer festen Liste
(`radio0`–`radio3`, `lan`/`wan`/`wan6`), keine vom Router gelieferten Namen – beide Aktionen
sind gesperrt, und eine feste Liste lässt sich nicht einschleusen.

**1.53.0 führt nichts aus, was einen Router aufruft:** `EXECUTABLE_IN_RELEASE` enthält nur
`observe.evaluate` (kein Router-Aufruf). Paket C2 (1.54.0) nimmt `service.restart` auf.

Gemeinsame Vorabprüfungen (jede `pass`, `fail` oder `unknown`; `fail` oder `unknown` einer
kritischen sperrt): Router erreichbar, Identität eindeutig, Aktion unterstützt, Rechte
vorhanden, keine gleichzeitige Reparatur, Wartung beachtet, kein gefährlicher Zustand,
Management-Weg in Ordnung, Bauteile bekannt, Wiederherstellung geklärt (Risiko 3 ohne
Mechanismus → sperren), Freigabe gültig, Schutzschalter geschlossen.

Bestätigtes Commit (`uci apply` mit Rollback) gibt es in rpcd, es ist aber ungenutzt, nicht in
der ACL, deckt nur UCI ab und geht bei einem Neustart von rpcd oder des Routers verloren. Kein
Watchdog, kein zweiter Zugangsweg.

**Stand heute (Paket D):** Katalog, Parameterprüfung, Rollback-Aussagen und die Liste der
nie erlaubten Familien sind gebaut und getestet (`tests/test_heal_catalog_v1530.py`). Die
gemeinsamen Vorabprüfungen oben sind **nicht** gebaut (Paket E); die Richtlinie liest deren
Ergebnis heute als Fakten aus `RiskContext` (Abschnitt 9). Kein Eintrag hat einen Ausführer;
`router_call` und `required_acl` sind nur Namen für Erklärung und Prüfung.

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

Code: `heal_policy.py` (Paket D). Eingaben sind eingefrorene Fakten, **keine Zeit und kein
Router-Aufruf**: `DecisionInput` (Aktion, Parameter, `IncidentFacts`, `RiskContext`, Zahl der
fehlgeschlagenen oder unbekannten Versuche in 24 h, Konfigurationsänderung im selben Bereich in
24 h). Jedes Feld von `RiskContext` und `IncidentFacts` darf `None` sein, ebenso die Zahl der
früheren Versuche – das heißt „unbekannt“ und wird nie als „harmlos“ gelesen (Review PR #77:
kein `or 0`, kein Wahrheitswert-Test auf einem Eingabefakt). `DecisionInput` nimmt nur genau
`IncidentFacts` und `RiskContext` (keine Unterklassen) und hält die Parameter als eingefrorene
Kopie, deren Werte genau einmal gelesen wurden.

### 9.1 Risiko nach Kontext (`classify_risk`)

Ausgang ist das Grundrisiko des Katalogs (Abschnitt 7). Regeln **heben nur an**, keine senkt:

| Regel (Code) | gilt für | Wirkung |
|---|---|---|
| `role_unknown` | schreibende Aktion, Rolle des Routers unbekannt | HOCH |
| `identity_not_confirmed` | schreibende Aktion, Identität nicht bestätigt | HOCH |
| `open_security_finding` | schreibende Aktion, offene Erkennung des Security Centers | HOCH |
| `in_maintenance_window` | schreibende Aktion im Wartungsfenster | mindestens MITTEL |
| `service_disabled_on_purpose` | Dienst-Neustart eines absichtlich abgeschalteten Dienstes (er würde einen zweiten DHCP-/DNS-Server starten) | HOCH |
| `service_config_unapplied` | Dienst-Neustart, während die gespeicherte Konfiguration des Dienstes von der laufenden abweicht (`service_config_unapplied is True`): der Neustart würde diese Änderung in Kraft setzen; richtiger Weg ist das Drift-Playbook | HOCH |
| `service_serves_other_routers` | Dienst-Neustart auf einem Router, dessen DNS/DHCP andere Router bedient (`service_dependant_routers > 0`) | mindestens MITTEL (eigener Regelcode für die Freigabe) |
| `target_on_management_path` | Funk oder Schnittstelle auf HAs Weg zum Router; **jeder** Router-Neustart | HOCH |
| `wireless_uplink_radio` | Funk mit STA- oder Mesh-Schnittstelle | HOCH |
| `uplink_for_other_routers` | Neustart eines Routers, hinter dem andere hängen; Funk/Schnittstelle, die deren Uplink trägt | HOCH |
| `clients_affected` | Unterbrechung mit Clients am Router (Funk: am Funk) | mindestens MITTEL |
| `context_missing` | ein Fakt aus `needs_facts` der Aktion ist unbekannt | HOCH, **nicht bewertet** |

Für `service.restart` sind seit dem Review von PR #77 zusätzlich nötig: `service_enabled`,
`service_config_unapplied`, `clients_on_router`, `dependants` (hinter dem Router hängende
Router), `service_dependant_routers` und `service_dependant_clients` (Router und Clients, die
DNS/DHCP dieses Routers nutzen); fehlt einer, ist das Risiko HOCH und nicht bewertet. Die Rolle
ist für jede schreibende Aktion nötig. `classify_risk` nimmt nur eine echte `ValidatedAction`
und genau `RiskContext`, sonst `PolicyError`.

Beispiele aus der Form dieser Flotte (ein Gateway, mehrere APs; drei APs hängen hinter einem
AP; ein kleiner AP hat dnsmasq und odhcpd absichtlich aus):

- `wifi.radio_restart` (Grundrisiko 2) auf dem AP, hinter dem drei APs hängen: läuft deren
  Uplink über diesen Funk (`target_carries_dependants`), greift `uplink_for_other_routers` →
  HOCH; mit Mesh- oder STA-Schnittstelle zusätzlich `wireless_uplink_radio`. Derselbe Neustart
  an einem AP am Ende der Kette, ohne Uplink und ohne Management-Weg, bleibt 2. Das Ergebnis
  ist heute in beiden Fällen **Unsupported** (`action_disabled`, die Aktion ist gesperrt);
  die Not-Safe-Gründe stehen trotzdem in `hits` und würden auch nach einer Freischaltung
  sperren.
- `service.restart dnsmasq` (Grundrisiko 2) auf dem Gateway, dessen DNS/DHCP fünf Router und
  ihre Clients nutzen → bleibt 2 (Freigabe; **DECIDED** vom Auftraggeber: nicht höher), aber
  mit dem Regelcode `service_serves_other_routers`, und die Freigabe zeigt Zahl der Router und
  Clients (`impact`, siehe 9.3). Derselbe Neustart auf einem AP ohne abhängige Router hat
  diesen Code nicht und eine kleinere Auswirkung; das Risiko sinkt nie unter 2. Auf dem kleinen
  AP, auf dem dnsmasq absichtlich aus ist → `service_disabled_on_purpose` → HOCH, **Not Safe**:
  „läuft nicht“ ist dort der Sollzustand.

### 9.2 Konfidenzwert (`score`)

Ganze Punkte von 0 bis 100 (`ScoreBreakdown.unit` = Punkte/100 für `Decision.score`). Jeder
Beitrag steht mit Code und Grund in `contributions`; ihre Summe ist immer `total` (die
Begrenzung ist eine eigene Zeile).

| Faktor (Code) | Punkte |
|---|---|
| `cause_level` | confirmed 40 · likely 30 · possible 15 · unknown/fehlt 0 |
| `cause_status` | bestätigte Ursache +10, Hypothese 0 |
| `incident_confidence` | 10 × Konfidenz des Vorfalls (0–1), kaufmännisch gerundet; fehlt: 0 |
| `source_families` | 0 Familien 0 · 1 Familie 5 · 2 und mehr 10 |
| `target_fact` | direkter Zustand des Ziels 30 · nur Log-Hinweis 10 · keiner 0 |
| `prior_attempts` | −25 je fehlgeschlagenem oder offenem Versuch desselben Schlüssels in 24 h; **Verlauf unbekannt** (`None`): −25 (`prior_attempts_unknown`) und eine schreibende Aktion ist gesperrt (`history_unknown`) |
| `config_change` | −20 bei einer Konfigurationsänderung im selben Bereich in 24 h **oder wenn unbekannt** |
| `severity` | Schwere `info` −10, **unbekannt** (`None`, `severity_unknown`) ebenfalls −10, sonst 0 |
| `clamp` | was nötig ist, damit die Summe in 0..100 bleibt |

Schwelle für eine schreibende Aktion: **60** (`PolicyLimits.score_min`, nur strenger
einstellbar: 60–100). Ein bestätigter Wurzelvorfall (Konfidenz 1,0, Schwere nicht `info`,
keine Konfigurationsänderung) mit direktem Zielzustand und zwei Quellenfamilien liegt bei
40+10+10+10+30 = 100; derselbe Vorfall mit einem gescheiterten
Versuch in 24 h bei 75, mit zweien bei 50 (unter der Schwelle).

### 9.3 Die fünf Ergebnisse (`decide`)

`decide()` sammelt **jede** Regel, die greift (`hits` mit Code, Ergebnis, sperrend ja/nein,
Einzelheiten ohne Adressen), und nimmt das erste Ergebnis in dieser Reihenfolge:

1. **Unsupported**: Kennung nicht im Katalog oder `never_*`, Parameter abgelehnt, Aktion
   gesperrt (`action_disabled` mit ihrem Grund), schreibende Aktion für einen Folgevorfall
   (`not_root_incident`, repariert wird nur der Wurzelvorfall), Diagnose aus
   (`diagnostics_off`).
2. **Not Safe** (nur schreibende): Router nicht erreichbar, die harten Risikogründe aus 9.1
   (Identität, Rolle, Security, absichtlich aus, ungeladene Dienst-Konfiguration,
   Management-Weg, Funk-Uplink, Uplink anderer Router), offener Schutzschalter, gleichzeitige
   Reparatur, **Ursache sicher außerhalb des Routers** bei einem Dienst-Neustart
   (`cause_outside_router`, Regel von Playbook A), bewertetes Risiko HOCH
   (`risk_high_no_recovery`: es gibt keinen Rollback-Mechanismus).
3. **Insufficient Evidence**: ein nötiger Fakt fehlt (`context_missing`); für schreibende
   außerdem Verlauf der Versuche unbekannt (`history_unknown`), kein Vorfall, Wurzel unbekannt,
   bei einem Dienst-Neustart Ort der Ursache unbekannt (`cause_location_unknown`), **nur
   zeitliche Nähe**
   (`temporal_correlation_only`), veraltete Hinweise, Hypothese mit weniger als zwei
   Quellenfamilien, kein direkter Zielzustand, Wert unter der Schwelle. Nächster Schritt ist
   dann immer `diag.refresh`.
4. **Requires Approval**: schreibende Aktion mit Risiko ≥ 2.
5. **Recommended**: alles andere (Diagnose, Risiko ≤ 1).

Dazu zwei Hinweise, die nie sperren: `impact_summary` (Art der Unterbrechung, Clients am
Router und am Ziel, abhängige Router, **Router und Clients, die DNS/DHCP dieses Routers
nutzen**, geschätzte Unterbrechung) und `recovery_statement` (Rollback-Art und -Aussage aus
dem Katalog). Dieselbe Auswirkung steht in `PolicyDecision.impact` und in der Erklärung;
`to_impact()` liefert den `Impact`-Datensatz des Modells für den Plan (bei einem
Dienst-Neustart sind `clients_on_component` die Clients, die den Dienst nutzen; die Kennungen
der abhängigen Router füllt die Engine). Jeder Code hat einen deutschen Satz in
`REASON_TEXT_DE`; `PolicyDecision.explanation()` liefert Ergebnis, Begründung, Auswirkung und
alle Regeln als Klartext, `to_model()` den `Decision`-Datensatz des Modells.

**Zeitliche Nähe allein führt nie zu einer schreibenden Aktion:** `temporal_only` muss
ausdrücklich `False` sein; `None` zählt wie `True`. Eine lesende Aktion bleibt erlaubt und
bekommt den Hinweis `temporal_link_diagnose_only`.

**DECIDED (Paket D, jeweils die strengere Lesart):** fehlender Kontext → Risiko HOCH,
„nicht bewertet“ und **Insufficient Evidence** (nicht Not Safe: erst nachsehen, dann
entscheiden); unbekannte Frische zählt als veraltet, unbekannte Konfigurationsänderung als
Änderung, unbekannte Wurzel als Insufficient Evidence; jeder Router-Neustart gilt als auf dem
Management-Weg; Schwere `info` kostet 10 Punkte; Requires Approval hängt am Risiko, nicht am
Modus – den Modus prüft erst `gate()` (Abschnitt 10). **DECIDED (Review PR #77):** unbekannter
Verlauf der Versuche kostet 25 Punkte und sperrt jede schreibende Aktion; unbekannte Schwere
zählt wie `info`; unbekannter Ort der Ursache sperrt einen Dienst-Neustart (Insufficient
Evidence), sicher außerhalb heißt Not Safe; eine ungeladene Dienst-Konfiguration heißt Not
Safe für den Neustart, unbekannt Insufficient Evidence, nur sicher `False` lässt ihn weiter.
Die allgemeinen −20 für eine Konfigurationsänderung in 24 h bleiben daneben.

**Stand heute (Paket D, X):** Risiko, Wert, Ergebnis und Erklärung sind gebaut und getestet
(`tests/test_heal_policy_v1530.py`). Seit Paket X füllt die Engine, was sie im Speicher hat
(Abschnitt 2.1); die übrigen Fakten (Security Center, Topologie, Vorabprüfungen) kommen mit E
und F über `HealFactsProvider`. Bis dahin ist jedes unbekannte Feld „unbekannt“ und sperrt
eine schreibende Aktion.

**Anbindung an die Engine (Paket X, gebaut):** `heal_engine.PolicyDecider` (Abschnitt 2.1)
bildet `DecisionContext` auf `DecisionInput` ab und ruft `gate()`; die Fakten, die die Engine
im Speicher hat, sind gefüllt (Rolle, Identität, Wartung, Schutzschalter, Verlauf der
Versuche, Wurzel, Ursache), alle übrigen bleiben unbekannt oder kommen von einer Faktenquelle
(E, F). Der Modus kommt aus `heal_policy.effective_mode`. Eine schreibende Aktion bleibt damit
heute Insufficient Evidence (fehlender Kontext), außer eine Faktenquelle liefert alles; dann
höchstens Requires Approval, nie ausführbar.

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
- **Vorläufig (Frage Q7, strenge Voreinstellung, bis der Eigentümer entscheidet):** Eine
  Allowlist darf nur Aktionen bis Risiko 1 enthalten (`AUTO_HEAL_MAX_RISK`); Risiko 2 und 3
  lehnt das Modell ab. Höchstens 16 Einträge je Router.

**Wartung:** Netz und Router übernehmen das Wartungsfenster und den Router-Schalter von Network
Intelligence (eine Wahrheit für beide Module). Schnittstellen und Dienste bekommen eigene
Fenster im Speicher (`MaintenanceWindow`: `mtw_`-Kennung, Bereich `interface`/`service`,
Router, Ziel, Beginn, Ende oder offen, Grund, angelegt von `engine` oder `admin`, nie von
`recovery`). In der Wartung kein Auto-Heal; Vorschläge entstehen weiter und sind markiert.

**Schleifenschutz** – als Daten im Speicher (`LoopLimits`, `LoopState`):

| Mechanismus | Standard | Grenzen |
|---|---|---|
| Abklingzeit je (Router, Aktion, Bauteil) | 30 min | 10 min – 24 h |
| Versuche je Schlüssel in **jeder** Spanne von 24 h (gleitendes Fenster) | 2 | 1–3 |
| Wartezeit zwischen Versuchen | 30 min × 2^n | höchstens 24 h |
| Schutzschalter je Schlüssel | schließt nur durch Bestätigung eines Administrators | – |
| Flotten-Pause | ab 3 Fehlschlägen in 24 h, 24 h lang | 1–10; 1 h – 7 Tage |
| gleichzeitig laufende Aktionen in der Flotte | 1 | 1 |
| Mindestabstand je Router und Aktion (Katalog `min_interval_s`) | `diag.refresh`: 5 min | – |
| Doppelte (Review P2-6) | eine offene Aktion je (Router, Aktion, Parameter), **je Wurzelvorfall** (flottenweit) und **je (Router, Bauteil)** über alle Bauteile der Aktion (ohne Bauteil: der Router selbst); sonst wird die vorhandene offene Aktion zurückgegeben | – |
| Router-Sperre | eine laufende Reparatur je Router | – |
| Hold | Router (oder Flotte) nur Observe, Abschnitt 5.1 | – |

Die Schlüssel von Versuchen und Schutzschaltern sind (Router, Aktion, `kind:name` des Bauteils);
eine Aktion mit mehreren Bauteilen zählt bei jedem. Vorfälle nummeriert Network Intelligence
flottenweit (`inc-N`), deshalb genügt die Vorfallkennung allein als Schlüssel.

**Router-Sperre und Schreibzugriffe von außerhalb** (Entscheidung des Eigentümers): Das Modell
hat je Router **eine** Sperre mit genau einem Halter (`LockRecord`: Halter `engine` mit der
Aktionskennung oder `external` mit einer Quelle wie `button.reboot`). **Jeder Halter hat seine
eigene Kennung `lock_id` (`lck_` + 32 hex, Review P1-3):** ein zweiter Druck auf denselben Knopf
ist ein zweiter Halter und wird abgelehnt, solange der erste die Sperre hat, und freigeben kann
nur, wer die Kennung hat – nie über den Namen der Quelle. `LoopState.repair_active(router_id)`
sagt, ob gerade eine Reparatur den Router hält. Die Engine bekommt die Sperre automatisch mit
den Zuständen EXECUTING, VERIFYING, ROLLBACK_PENDING und ROLLING_BACK und gibt sie mit dem
nächsten Zustand wieder ab; ein Übergang in einen dieser Zustände, während ein anderer Halter
die Sperre hat, wird abgelehnt (`router_locked`). Knöpfe und Schalter (später) nehmen die Sperre
mit `try_external_lock(router_id, source, ts)` (gibt die `lock_id` zurück oder `None`), geben sie
mit `release_external_lock(router_id, lock_id)` frei und halten ihren Schreibzugriff mit
`record_external_write()` fest (Router, Quelle, Ziel, Zeitpunkt, Audit-Kennung; die letzten
200). Eine hängende Fremd-Sperre entfernt nur ein Administrator (Abschnitt 5.1).

### 10.1 Richtlinie: Modus, Freigabe, Auto-Heal (`gate`, Paket D)

`gate(inp, mode=…, allowlist=…, module_enabled=…, held=…, fleet_paused=…, guards_green=…,
limits=…)` sagt, was mit der Aktion eines `DecisionInput` auf einem Router geschehen darf
(`Permission`: `none`, `recommend`, `run_read_only`, `needs_approval`, `auto_run`).

**Der Gate nimmt die Eingabe, nie eine Entscheidung** (Review PR #77, P1): er prüft Aktion und
Parameter selbst gegen den Katalog und ruft `decide()` selbst auf; die Entscheidung, die er
dabei getroffen hat, steht in `GateVerdict.decision`. Eine von außen gebaute, mit
`dataclasses.replace` veränderte oder umetikettierte `PolicyDecision` kann deshalb nichts
freischalten – es gibt keinen Weg, sie dem Gate zu geben (ein anderer Typ als genau
`DecisionInput` ist ein `PolicyError`). `limits` muss genau `PolicyLimits` sein. Ob Wartung
ist, liest der Gate aus `inp.context.in_maintenance` – derselbe Fakt, den `decide()` liest
(eine Quelle). `gate_for_router()` liest Modus, Allowlist, Hold und Pause aus `HealSettings`
und `LoopState`, auf der Sicherheitsuhr. Prüfreihenfolge, die erste passende gewinnt:

1. `module_enabled`, `held` oder `fleet_paused` ist kein echter Wahrheitswert (etwa `None`)
   → `none` (`gate_input_invalid`). Modul aus → `none` (`module_disabled`). Danach prüft der
   Gate seine eingefrorenen Eingaben noch einmal (`replace` von Kontext, Vorfall und Eingabe,
   Paket X, g): ein mit `object.__setattr__` nachträglich gesetzter Wert → `none`
   (`gate_input_invalid`); die Parameter werden dabei genau einmal gelesen, und die Aktion
   nimmt der Gate aus seiner eigenen Entscheidung (`PolicyDecision.refusal`, Katalogeintrag
   und Parameter der Entscheidung), nie ein zweites Mal aus der Eingabe. `decide()` prüft
   ebenso neu und wirft `PolicyError`; `limits` wird auch neu geprüft.
2. Aktion oder Parameter vom Katalog abgelehnt → `none` mit dem Code der Ablehnung; Aktion
   gesperrt (`action_disabled`) oder ihr Risiko **unter** dem Grundrisiko des Katalogs
   (`risk_below_catalog`) → `none`.
3. **Risiko 3 → immer `none`** (`risk_high_never_authorised`) – kein Modus, kein Schalter und
   keine Allowlist ändert das.
4. Entscheidung nicht Recommended oder Requires Approval → `none` (`decision_blocked`).
5. Risiko 0 und nicht schreibend → `run_read_only` in jedem Modus.
6. **Wirksamer Modus** (`effective_mode`): Modul aus → Observe; **gesperrter Router (Hold) oder
   pausierte Flotte → Observe für alles ab Risiko 1** (Entscheidung des Eigentümers); einer der
   drei Schalter kein echter Wahrheitswert → Observe; sonst der eingestellte Modus.
7. Observe → `recommend` (Grund `observe_mode`, `router_held` oder `fleet_paused`).
8. Freigabe → `needs_approval` für alles ab Risiko 1.
9. Auto-Heal → `auto_run` **nur**, wenn die Aktion Risiko ≤ 1 hat, nicht Requires Approval ist,
   ein gültiger Allowlist-Eintrag sie mit genau diesen Parametern deckt, **sicher keine**
   Wartung ist (`inp.context.in_maintenance is False`) und alle Vorabprüfungen **sicher grün** sind
   (`guards_green is True`); sonst `needs_approval` mit allen Gründen (`risk_above_auto_limit`,
   `not_allowlisted`, `in_maintenance`, `guards_not_green`).

Darf etwas laufen (`run_read_only`, `auto_run`), aber das Release kann die Aktion nicht
ausführen, kommt `not_in_release` dazu und `executable_now` bleibt falsch. In 1.53.0 ist nur
`observe.evaluate` ausführbar.

**DECIDED (Paket D):** eine pausierte Flotte heißt in der Richtlinie **Observe** (Regel des
Eigentümers), strenger als `SelfHealingStore.effective_mode()` aus Paket B, der dann Freigabe
liefert. Ein Test hält fest, dass die Richtlinie nie mehr erlaubt als der Speicher; die Engine
benutzt seit Paket X `heal_policy.effective_mode` und `gate`. **DECIDED:** `diag.refresh`
hat Risiko 1, ist also im Modus Observe nur eine Empfehlung und in 1.53.0 nicht ausführbar.
**DECIDED (Review PR #77):** der Gate nimmt den `DecisionInput` und entscheidet selbst
(statt `PolicyDecision` unbaubar zu machen); ein Schalter, der kein echter Wahrheitswert ist,
heißt `none`.

**Allowlist** (`validate_allowlist(vorschlag)` → `AllowlistVerdict`, alles oder nichts):
abgelehnt werden keine Liste (`allowlist_invalid`), mehr als 16 Einträge (`too_many_entries`),
ein Eintrag, den das Modell ablehnt (`entry_invalid`, darunter `max_risk` über 1), unbekannte
und `never_*`-Aktionen, gesperrte Aktionen (`action_disabled`), Parameter außerhalb der
geschlossenen Mengen, Aktionen mit Grundrisiko über 1 (`risk_above_auto_limit`: Risiko 2 und 3
nie), ein `max_risk` unter dem Risiko der Aktion (`max_risk_below_action_risk`, er könnte nie
passen) und Doppelte (`duplicate_entry`). `is_allowlisted()` prüft jeden gespeicherten Eintrag
beim Lesen noch einmal; ein Eintrag, der heute nicht mehr gültig wäre, passt nie. Heute bleibt
damit nur `diag.refresh` und `diag.ha_probes` als möglicher Allowlist-Inhalt.

### 10.2 Schleifenschutz als Entscheidungen (Paket D)

Alle Zeiten sind Zeiten der **Sicherheitsuhr** (`safe_now`, Abschnitt 5.2), nie die Wanduhr;
`safe_now_of(clock)` liest nur `clock.safe`.

- **Gleitendes Fenster** (Review PR #77, **DECIDED** vom Auftraggeber): höchstens N Versuche in
  **jeder** Spanne von 24 h Sicherheitszeit, nicht in einem festen Fenster, das nach 24 h neu
  anfängt. Jeder Versuchsdatensatz hält dafür die Zeitpunkte der letzten (höchstens 3 =
  größtes N) Versuche in `recent`; gezählt werden die, die jünger als 24 h sind
  (`AttemptRecord.times_in_window`). Sind N aufgebraucht, darf der nächste Versuch erst, wenn
  der älteste der N letzten die Spanne verlässt: `retry_at` = dessen Zeit + 24 h.
- **Abklingzeit und Wartezeit** (`cooldown_after`, `backoff_schedule`, `book_attempt`): nach
  Versuch *n* in den letzten 24 h wartet der Schlüssel max(Abklingzeit, min(Basis × 2^(n−1),
  Obergrenze)). Mit den Standards (30 min, Basis 30 min, Obergrenze 24 h, 2 Versuche) heißt das
  **1800 s nach dem ersten, 3600 s nach dem zweiten Versuch**; bei 3 erlaubten Versuchen 1800,
  3600, 7200 s. Eine laufende Abklingzeit wird **nie verkürzt** (`max(alt, neu)`), auch nicht
  wenn ältere Versuche die Spanne verlassen haben. Beim Buchen wird das Ergebnis auf „offen“
  (`None`) gesetzt. `book_attempt` bucht genau wie `heal_store._next_attempts` (ein Test
  vergleicht beide über Zufallsfolgen). Eine Buchung über die Grenze hinaus (die Prüfung
  lehnt sie ab, die Funktion muss aber für sich sicher sein) verdoppelt weiter ab der Stufe
  davor (Paket X, h): `recent` hält nur 3 Zeiten, ohne das würde die Wartezeit kürzer als nach
  der alten festen Regel. Die Fenstergröße `ATTEMPT_WINDOW_S` steht nur in `heal_model.py`
  (Paket X, k).
- **Speicherformat** (`heal_store`, Minor 2, nur hinzugefügt): `recent` ist ein neues Feld des
  Versuchsdatensatzes. Eine Datei des bisherigen Stands (Minor 1, ohne `recent`) lädt weiter;
  ihre Versuche gelten streng als **zum Zeitpunkt des letzten Versuchs** (`last_at`, sonst
  `window_start`) gemacht, so oft wie `count` (höchstens 3) – das zählt nie weniger als vorher.
- **Darf noch ein Versuch laufen** (`loop_verdict`, `loop_verdict_for`), Reihenfolge: offener
  Schutzschalter auf irgendeinem Schlüssel (`breaker_open`, kein Zeitpunkt – nur ein
  Administrator schließt), Flotten-Pause (`fleet_paused`, bis zu ihrem Ende), Abklingzeit
  (`cooling_down`, bis zur spätesten), Versuche in den letzten 24 h aufgebraucht
  (`max_attempts`, bis der älteste zählende die Spanne verlässt). Seit Paket X prüft
  `heal_store._attempt_refusal` beim dauerhaften Schritt nach EXECUTING dieselben Punkte in
  derselben Reihenfolge, auch die Flotten-Pause (vorher fehlte sie dort; ein Zufallstest
  vergleicht beide).
- **Mindestabstand** (`interval_verdict(action, last_run_at=…, safe_now=…)`): eine Aktion mit
  `min_interval_s` im Katalog (heute `diag.refresh`, 300 s) läuft je Router höchstens einmal in
  diesem Abstand; sonst `min_interval` mit `retry_at`. `last_run_at` `None` heißt „unbekannt“:
  eine lesende Aktion darf, eine **schreibende** wird abgelehnt (`interval_unknown`), außer der
  Aufrufer sagt ausdrücklich `never_ran=True` (Paket X, i; `never_ran` zusammen mit einer Zeit
  ist ein `PolicyError`).
- **Schutzschalter** (`record_outcome`, `OutcomeEvent`): **sofort offen** nach jedem Ausgang,
  der den Router sperrt (`not_resolved`, `partial`, `new_fault`, `unknown`, `escalated`,
  `stuck_released`), nach `rolled_back` und nach jedem unterbrochenen Versuch
  (`outcome_event_for` liefert dann `unknown`) – damit sind die beiden Auflagen für Paket I
  aus Abschnitt 15 erfüllt. Eine saubere Ablehnung durch den Router vor jeder Änderung
  (`rejected`) zählt und öffnet nach **1** automatischen oder **2** manuellen Fehlschlägen
  (`PolicyLimits`, nur strenger einstellbar). `resolved` schließt **nie** einen offenen
  Schalter und setzt den Zähler **nicht** zurück (Review PR #77, **DECIDED**: sonst öffnen
  manuelle Ablehnungen im Wechsel mit Erfolgen ihn nie); die Fehlschläge zählen, bis ein
  Administrator bestätigt. Schließen und Zurücksetzen nur `acknowledge_breaker(…, actor=admin)`.
- **Flotten-Pause:** jeder Ausgang außer `resolved` ist ein Fehlschlag; 3 Fehlschläge in 24 h
  (Sicherheitsuhr) pausieren Auto-Heal flottenweit für 24 h (Grund `fleet_failures`); eine
  schon laufende längere Pause bleibt.
- **Doppelte** (`dedupe_verdict`): je (Router, Aktion, Parameter), je Wurzelvorfall und je
  (Router, Bauteil), mit denselben Kennungen wie der Speicher; zurück kommen die Kennung der
  vorhandenen offenen Aktion und die Art (`action`, `incident`, `component`). Aktion,
  Parameter und Bauteile kommen aus der Prüfung des Katalogs, nie vom Aufrufer (eine
  abgelehnte Aktion ist ein `CatalogError`).
- **Konfidenzwert:** `prior_failed_attempts()` zählt für Abschnitt 9.2 die Versuche
  desselben Schlüssels in den letzten 24 h, die nicht sicher erfolgreich waren. Der Speicher
  hält je Schlüssel die Zeitpunkte und nur das Ergebnis des **letzten** Versuchs; nur wenn
  dieser letzte in der Spanne liegt und `resolved` ist, zählt er nicht. Ein Versuch, dessen
  Ausgang noch nicht festgehalten ist, zählt als **offen**, nie als Erfolg (das Buchen setzt
  das Ergebnis zurück). Über mehrere Schlüssel gilt der höchste Wert.

Beispiel aus dem Auftrag: `service.restart dnsmasq` scheitert zweimal am selben Router
(`not_resolved`). Nach dem ersten Mal ist der Schutzschalter des Schlüssels offen; ein zweiter
Versuch kommt ohne Bestätigung eines Administrators gar nicht zustande. Scheitern in 24 h
drei Aktionen irgendwo in der Flotte, pausiert die Flotte 24 h und jeder Router gilt ab Risiko 1
als Observe.

**Stand heute:** Grenzen, Zähler, Sperre, Holds und Fremd-Schreibzugriffe gibt es als Daten mit
Prüfung, Speicherung und Tests. Der Speicher zählt Versuche und hält Abklingzeit, Versuche in
24 h, offene Schutzschalter und Holds beim dauerhaften Schritt nach EXECUTING ein (Abschnitt 5).
**Paket D** liefert die Logik, die einen Schutzschalter öffnet, die Flotte nach Fehlschlägen
pausiert und den Modus wirksam macht – als reine Funktionen, die neue Kopien zurückgeben. Noch
ruft sie niemand auf und nichts schreibt ihr Ergebnis in den Speicher (die Engine aus C1 geht
nur bis PROPOSED; Anbindung als eigenes Paket, Ausgänge mit I). Am Speicher aus Paket B hat Paket D nur das gleitende Fenster, die nie verkürzte
Abklingzeit und das offene Ergebnis beim Buchen geändert (Review PR #77, Punkte 6–8, Minor 2).
Paket X: der dauerhafte Schritt des Speichers lehnt während einer Flotten-Pause ab
(`fleet_paused`, für jedes Risiko, wie `loop_verdict`), und eine Buchung über die Grenze
verkürzt die Wartezeit nicht. Knöpfe und Schalter benutzen die Sperre noch nicht.

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

**Stand heute (C1):** fünf **lesende** Routen, sonst nichts davon. Keine schreibende Route,
keine Entität, keine unique_id, kein Ereignis, kein Dienst.

| Route (GET) | Recht | Inhalt |
|---|---|---|
| `…/v1/overview` | Administratoren; andere Benutzer nur, solange ein Eintrag das Panel für alle öffnet, und dann nur Zähler | Stand, `release_mode: observe_only`, `write_path: false`, `automatic_rollback: not_available`, Zähler je Zustand, Flotten-Pause und -Hold, `last_activity` (letzter Übergang eines Datensatzes; für andere Benutzer auf die Minute abgerundet); für Administratoren dazu je Router Modus (eingestellt/geltend), `loaded` (in der Engine, aktiviert und `LOADED`), Hold, offene Datensätze und wartende Vorfälle |
| `…/v1/actions` | nur Administratoren | Datensätze, neueste zuerst; Filter `router_id`, `state` (Liste), `open` 0/1; `limit` 1–200 (Standard 50), `offset` bis 10 000 |
| `…/v1/actions/{action_id}` | nur Administratoren | ein Datensatz mit ganzem Verlauf, Hold des Routers, geltender Modus |
| `…/v1/settings` | nur Administratoren | Schalter, Einstellungen des Speichers, feste Grenzen |
| `…/v1/plans` | nur Administratoren | was die Entscheidungsschnittstelle vorschlagen würde und was blockiert (`router_id`, `action_id`); legt nichts an, ändert nichts, keine Freigabe |

Reihenfolge der Prüfungen wie bei den Schwester-Routen: 401 ohne Anmeldung (HA), 403 für
fehlende Rechte (vor allem anderen), 410 solange die Panel-Ansicht aus ist, 503
`not_running` ohne laufende Engine, dann kein Rumpf (4 KiB-Grenze von `read_body`) und die
strenge Abfrage (nur bekannte Schlüssel, je einmal, höchstens 64 Zeichen, Kennungen nach
Muster); ein 400 nennt Feld und Grund, nie die Eingabe. Fehler haben feste Texte und
`Cache-Control: no-store`; ein 500 wird nur mit Typ und Stelle geloggt. Die Routen werden
erst mit dem ersten Start der Engine registriert (Schalter von Anfang an aus: keine Route);
wird später ausgeschaltet, antworten sie 503 und lesen nichts. Zeichenketten von außen
(Vorfallart, Ursachencode) stehen nur als JSON-Daten im Rumpf und nur, wenn das Modell sie
als Code annimmt.

**DECIDED (C1):** Die Übersicht folgt den Rechten der Time-Machine-Zeitleiste und der
Übersicht des Security Centers (maskierte Kurzfassung, Abschnitt 13); alles, was Router,
Vorfälle, Ursachen oder Modi je Router nennt, ist nur für Administratoren, weil es mehr zeigt
als die vorhandenen lesenden Enterprise-Routen Nicht-Administratoren zeigen. Die geplanten
Routen `history` und `…/preflight` sind in C1 in `actions/{id}` (Verlauf) und `plans`
(Vorschau) enthalten.

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
| Freigabe wiederholt, doppelt ausgeführt | einmalige Schreiberlaubnis, Idempotenz, Prüfsumme | **teilweise**: das Modell lässt EXECUTING nur einmal zu; der Speicher gibt bei gleicher Idempotenz-, Aktions-, Vorfall- oder Bauteilkennung die vorhandene Aktion zurück, lehnt eine Idempotenz-Kennung ohne Datensatz ab, und die Eingaben dieser Prüfung sind eingefroren |
| Zustand ändert sich zwischen Freigabe und Ausführung | `binding_hash` mit Fingerabdruck, letzte Vorabprüfung | Funktion `binding_hash()` vorhanden; Bindung und Fingerabdruck sind nach der Planung unveränderlich |
| Engine repariert eigene Nebenwirkungen | Kennzeichnung eigener Aktionen, Schutzschalter, Versuche, Pause, eine Aktion gleichzeitig | **teilweise**: der Speicher hält Abklingzeit, Versuche und offene Schutzschalter beim Ausführen ein; die Logik, die Schutzschalter öffnet und die Flotte pausiert, ist gebaut (`heal_policy.record_outcome`, Paket D), aber noch nicht aufgerufen (Ausgänge mit I); seit Paket X lehnt der dauerhafte Schritt in der Flotten-Pause ab |
| Automatischer Eingriff nur wegen zeitlicher Nähe | `temporal_only` muss ausdrücklich `False` sein, sonst Insufficient Evidence | **gebaut** in der Richtlinie (Abschnitt 9.3) |
| Risiko 3 über einen allgemeinen Schalter oder eine Allowlist erlaubt | Risiko 3 nie erlaubt; Allowlist nur bis Risiko 1; der Gate prüft Katalog und Parameter selbst und trifft die Entscheidung selbst | **gebaut** in der Richtlinie (Abschnitt 10.1) |
| Gefälschte oder veränderte Entscheidung (eigener Konstruktor, `dataclasses.replace`, andere Parameter als geprüft, nachträglich mit `object.__setattr__` geänderte Eingaben) | `gate()` nimmt nur den `DecisionInput`, prüft ihn mit `replace` neu und ruft `decide()` selbst; die Aktion kommt aus seiner eigenen Entscheidung; eine `ValidatedAction` gibt es nur um den Katalogeintrag selbst, mit erneuter Prüfung der Parameter; Parameter werden einmal gelesen und eingefroren | **gebaut** (Review PR #77 und Paket X, Abschnitte 7 und 10.1) |
| Faktenquelle (E/F) liefert falsche Typen oder lügt über Fakten der Engine | Typ genau `HealFacts`, erneute Prüfung, sonst „nichts bekannt“ (gezählt); Fakten der Engine gelten immer; Kopie des Kontexts; nichts geht über PROPOSED | **gebaut** (Paket X, Abschnitt 2.1) |
| Gefälschte Meldungen treiben Zähler oder Rechenzeit | Meldung nur Auslöser; Wiederholung einer erfassten Öffnung nicht gezählt; wartende Vorfälle ohne neuen Datensatz je Takt, begrenzte Merkliste | **gebaut** (Paket X, Abschnitt 2.1) |
| Unbekannter Kontext als harmlos gelesen | jedes unbekannte Feld zählt als HOCH und nicht bewertet; unbekannter Verlauf der Versuche sperrt ein Schreiben; Schalter des Gates (`held`, `fleet_paused`, `module_enabled`) müssen echte Wahrheitswerte sein | **gebaut** (Abschnitte 9 und 10.1) |
| Versuchsgrenze am Fensterrand umgangen (zwei Versuche kurz vor und zwei kurz nach dem Ende eines festen Fensters) | gleitendes Fenster: höchstens N Versuche in jeder Spanne von 24 h; Abklingzeit nie verkürzt; offener Ausgang zählt nie als Erfolg | **gebaut** in Richtlinie und Speicher (Abschnitt 10.2) |
| Ergebnis unbekannt, die nächste Aktion verschlimmert es | Hold bis zur Freigabe durch einen Administrator | **gebaut** im Speicher (Abschnitt 5.1) |
| Wanduhr springt (NTP, RTC, Hand) | Sicherheitsuhr: monotone Zeit im Lauf, Höchstmarke der Wanduhr über Starts, im Zweifel länger warten | **gebaut** (Abschnitt 5.2); ein Start kann höchstens 900 s gewinnen |
| Erzwungene Störungen (DNS absichtlich kaputt) | höchstens 2 Versuche in 24 h, Regel „Ursache außerhalb“ | **teilweise**: die Richtlinie sperrt einen Dienst-Neustart bei `cause_outside_router` (sicher außerhalb: Not Safe, unbekannt: Insufficient Evidence); den Fakt füllt erst Paket F |
| Eingeschleuste Parameter | geschlossener Katalog, geprüfte Parameter, nie SSH für Schreibzugriffe | **teilweise**: das Modell nimmt nur kurze Wörter, Zahlen und Wahrheitswerte und lehnt geheime Schlüsselnamen und schlüsselartige Werte ab; der Katalog (Paket D) nimmt nur genaue `str` aus geschlossenen Mengen, keine Unterklassen, keine Zusatzschlüssel, und wiederholt abgelehnte Werte nie; nie-Familien (Client, Firewall, VLAN, Management, Routing, Firmware, `network`, `wpad`, UCI, Shell) stehen nicht im Katalog. Kein Schreibweg vorhanden |
| HA startet mitten in einer Aktion neu | Schreiben vor dem Handeln, „unbekannt“, nie wiederholen | **gebaut**: Rücklesen, Neustartregel, Tests 22 |
| Router verloren mitten in der Aktion | `inconclusive` → VERIFYING → MANUAL_RECOVERY_REQUIRED, kein Wiederholen | Übergänge vorhanden |
| Umgehung über vorhandene Knöpfe und Schalter | Sperre beachten, Audit | Sperre und Fremd-Schreibzugriff als Daten vorhanden, noch nicht benutzt |
| Geheimnisse oder Adressen in Logs, Audit, Speicher | nur Kennungen, Zähler, Codes | **gebaut** für den Speicher; Test mit der Maskierung des Core |
| Speicher manipuliert oder verloren | atomares Schreiben, private Datei; Verlust → Observe, 24 h Flotten-Pause und 24 h Hold der Flotte; kaputter Datensatz → 24 h Hold seines Routers, ohne Ende, wenn er noch eine Ausführung zeigt; Holds aus beendeten Datensätzen werden bei jedem Laden neu gesetzt | **gebaut** |

## 15. Arbeitspakete und Releases

| Paket | Inhalt | Stand |
|---|---|---|
| **B** | Zustandsmaschine, Datenmodell, Speicher, Neustartregel, Grenzen | **gebaut** (PR #75) |
| **C1** | Engine-Gerüst, Modulschalter, Verdrahtung, lesende Routen, Listener | **gebaut** (PR #78; nur Observe, Abschnitt 2.1 und 11) |
| **D** | Katalog (`heal_catalog.py`) und Richtlinie (`heal_policy.py`): Risiko nach Kontext, Konfidenzwert, fünf Ergebnisse, Modi, Allowlist, Abklingzeit, Schutzschalter, Flotten-Pause – reine Logik | **gebaut** (PR #77) |
| **X** | Richtlinie in der Engine: `PolicyDecider` über `gate`, Fakten der Engine, Naht `HealFactsProvider` für E/F, Modus der Richtlinie in Engine, Routen und Diagnose, Klammer nur noch für Schreibendes, Erklärung in `plans`; Flotten-Pause im dauerhaften Schritt; Review-Punkte a–k | **dieser Stand** |
| E | Vorabprüfungen | offen |
| F | Playbooks A–G; **muss `IncidentFacts.cause_outside_router` füllen** (Playbook A: kein DNS-Neustart, wenn die Ursache klar außerhalb des Routers liegt) – bis dahin ist er `None` und sperrt jeden Dienst-Neustart (Insufficient Evidence) | offen |
| G | Anbindung Configuration Manager (Sicherungsverweis, Drift-Plan, Probelauf) | offen |
| H | Prüfung und die fünf Ergebnisklassen | offen |
| I | Eskalation, Schutzschalter, Flotten-Pause, Rollback-Zustände (nur Modell); die Entscheidungen dazu liefert Paket D (`record_outcome`, `outcome_event_for`), I muss sie nach jedem Ausgang aufrufen und das Ergebnis speichern; **der Schutzschalter muss bei ROLLED_BACK öffnen** – die Kante ROLLED_BACK → ESCALATED des Entwurfs gibt es nicht mehr (Abschnitt 4), über sie geht es also nicht; **der Schutzschalter muss auch öffnen, wenn ein Ausgang unbekannt ist** (`outcome_unknown`, `outcome_escalated`, `stuck_released`): hebt ein Administrator heute den Hold auf (`release_hold`), kann dieselbe Aktion noch einmal laufen, sobald ihre Abklingzeit vorbei ist (Review 2, im Test des Reviewers belegt) | offen |
| K | Entitäten, Ereignis, Audit-Präfix und -Anteil, Time Machine, Security-Veto, unique_id-Snapshot | offen |
| J | Tab im Dashboard | offen |
| C2 | Schreibweg (`restart_service_typed`, Executor, Freigabe-Routen, Ausführen mit Idempotenz) | **1.54.0** |

| L | Gesamttests, Leistung, Sicherheitsprüfung, Doku | offen |

**Auflage aus Review PR #77, erledigt mit Paket X:** der dauerhafte Schritt des Speichers nach
EXECUTING (`heal_store._attempt_refusal`) prüft jetzt Hold, Schutzschalter, **Flotten-Pause**,
Abklingzeit und Versuche, in der Reihenfolge von `loop_verdict`; der Speicher ist damit nie
lockerer als die Richtlinie.

Entscheidungen des Eigentümers:

- **1.53.0 ist nur Observe**: kein Router-Schreibweg, keine ACL-Änderung, kein zusätzlicher
  Router-Aufruf. Die erste schreibende Aktion kommt mit **1.54.0** (Paket C2).
- Das Modul ist nach dem Update für jeden Router **an, im Modus Observe**.
- Gemergt wird erst nach einer unabhängigen Prüfung.

**DECIDED (Master, Review 2) für das Paket, das die vorhandenen Knöpfe und Schalter
verdrahtet:** auf einem **gesperrten** Router (Hold, Abschnitt 5.1) bleiben sie erlaubt – der
Administrator stellt dann von Hand wieder her – und schreiben einen Audit-Eintrag. Abgelehnt
werden sie nur, solange eine Aktion der Engine die Router-Sperre hält (`try_external_lock`
gibt dann `None`). Der Speicher setzt das heute schon so um: `try_external_lock` prüft keinen
Hold.

## 16. Entscheidungen des Eigentümers und offene Fragen

| # | Frage | Stand |
|---|---|---|
| Q1 | Schreibweg in Phase 7? | **entschieden:** 1.53.0 nur Observe, schreiben ab 1.54.0 |
| Q2 | Standard nach dem Update | **entschieden:** an, jeder Router in Observe; Auto-Heal nie voreingestellt, Allowlist leer |
| Q3 | Router-Rechte für `rc init` | offen (Empfehlung des Entwurfs: Root-Anmeldung dokumentieren, später ein eigener rpcd-Benutzer) |
| Q4 | vorhandene Knöpfe und Schalter | **teilweise:** Sperre je Router und Erfassen von Schreibzugriffen außerhalb der Engine sind im Modell; ob Knöpfe und Schalter sie benutzen und ob sie nur für Administratoren werden, ist offen |
| Q5 | Funk-Neustart | **offen, vorläufig streng** (Voreinstellung aus dem Auftrag zu Paket D, der Eigentümer hat noch nicht geantwortet): modelliert und gesperrt; nur `service.restart` (dnsmasq, odhcpd, Risiko 2, nur mit Freigabe) ist für das erste Schreib-Release vorgesehen |
| Q6 | Router-Neustart als Aktion | **offen, vorläufig streng** (Voreinstellung aus dem Auftrag zu Paket D, der Eigentümer hat noch nicht geantwortet): modelliert und gesperrt, ebenso Wiederherstellen und Schnittstelle ab/an; der vorhandene Knopf bleibt |
| Q7 | Was Auto-Heal enthalten darf | **offen, vorläufig streng** (Voreinstellung aus dem Auftrag zu Paket D, der Eigentümer hat noch nicht geantwortet): nur Risiko ≤ 1; Risiko 3 erlaubt kein allgemeiner Schalter; unbewertetes Risiko zählt als HOCH |
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
  echter Store auf einer temporären Platte, 40 gelenkte Zufallsläufe mit Neustarts (mindestens
  die Hälfte führt wirklich aus), Sperre und Fremd-Schreibzugriffe, keine Zugangsdaten in der
  Datei.
- `tests/test_heal_review_v1530.py`: zu jedem Punkt des Reviews von PR #75 der umgedrehte
  Angriffstest (vor der Korrektur rot): Schließen während des Rücklesens (FakeDisks und HAs
  echter Store), verzögertes Schreiben während des dauerhaften Schritts, eingefrorene
  Doppelt-Felder, ein Halter je Sperre, Feldregeln, Idempotenz nach dem Verdrängen und nach
  Ablauf, Doppelte je Vorfall und Bauteil, Holds bei kaputtem Datensatz, Verlust und
  unbekanntem Ausgang, Sicherheitsuhr, Verdrängen nur wenn es hilft, Auswege des Administrators,
  schlüsselartige Namen; dazu die Breitensuche des Reviews über die Tabelle mit bis zu drei
  Neustarts.
- `tests/test_heal_review2_v1530.py`: die Punkte des zweiten Reviews (vor der Korrektur rot):
  Sicherheitsuhr (falsch vor und zurück, Hin-und-her-Sprünge, Abklingzeit und 24-h-Fenster bei
  springender Wanduhr, monotone Schritte, Höchstmarke über Neustarts), kaputter Abschnitt
  `loop` behält Holds ohne Ende, aufgehobene Holds kommen nicht wieder, kaputter Datensatz mit
  Ausführung im Verlauf sperrt ohne Ende, Aufbewahrung ab dem Sicherheitsstempel, `add()` nur
  für neue Datensätze. Dazu Tests für Schutzmechanismen, die schon da waren, aber ohne Test, der
  scheitert, wenn man sie entfernt (jeder einzeln durch Entfernen geprüft): Hold-Prüfung und
  Versuchsbuchung im dauerhaften Schritt, Sperre von Flush und Schließen, Reservierung der
  Schreibnummer, Nummernprüfung beim Rücklesen, Idempotenz-Kennungen offener Aktionen,
  `audit_refs` nur wachsend.
- `tests/test_heal_review3_v1530.py`: die Punkte des dritten Reviews (vor der Korrektur rot):
  Laufzeit zählt beim nächsten Start nicht doppelt (Modell und Abklingzeit im Speicher), Kappung
  der Höchstmarke, der Datensatz hinter einem Hold bleibt (Verdrängen, Größe, `prune()`), saubere
  Ablehnung nahe `TIME_MAX` (Ausführen und Laden), `release_hold()` ohne Hold ändert nichts. Dazu
  Tests für Schutzmechanismen ohne scheiternden Test: Wartungsfenster nur bei beiden Uhren,
  veraltete Endstempel, Datensätze ohne Stempel, Zurücksetzen der monotonen Bezugszeit beim Laden,
  monotone Uhr rückwärts. Jeder Schutz wurde einzeln entfernt; die Tests scheitern dann.
- `tests/test_heal_catalog_v1530.py` (Paket D, 86 Tests): der Katalog ist genau die Liste des
  Eigentümers, jeder Eintrag ist in sich stimmig (Status mit Grund, Rollback-Art passt zur
  Aktion – schreibende nie `read_only`, Neustart, Wiederherstellen und Dienst-Neustart nur
  manuell; die Fakten sind Felder von `RiskContext`, im Richtlinien-Test), `service.restart` ist
  die einzige bereite schreibende Aktion, 1.53.0 führt nichts aus, was einen Router aufruft,
  der Katalog ist unveränderlich, die Tabelle ist reines JSON; Prüfung gültiger und gesperrter
  Aktionen, jede nie-Familie, Parameterfehler (auch Shell-Zeichen, Groß-/Kleinschreibung,
  Unterklassen von `str`), Fehlermeldungen ohne den Wert; dazu eine Eigenschaftsprüfung mit
  5 Startwerten × 2000 zufälligen Kennungen und Parametern (nur Katalogeinträge kommen durch).
- `tests/test_heal_policy_v1530.py` (Paket D, 141 Tests): Risiko je Rolle und Topologie, jede
  Kontextregel einzeln, fehlender Kontext, Risiko sinkt nie (Zufall); die Regeltabelle des
  Werts, Summe und Wiederholbarkeit; alle fünf Ergebnisse mit Erklärung und deutschem Text;
  nicht erlaubte Aktionen, Risiko 3 über einen allgemeinen Schalter, gefälschtes Risiko (zu
  hoch und unter dem Katalog); jede Not-Safe- und Insufficient-Regel, zeitliche Nähe als
  Eigenschaft, Folgevorfall, Diagnose aus, Grenzen von `PolicyLimits`; Observe, Freigabe,
  Auto-Heal, Hold, Pause, Wartung, Modul aus, `effective_mode`, `gate_for_router`;
  Allowlist-Prüfung und erneute Prüfung gespeicherter Einträge; Wartezeit, Abklingzeit,
  Versuche und Fenster **gegen `heal_store._attempt_refusal` und `_next_attempts`**;
  Schutzschalter je Ausgang, Schwelle für `rejected`, `outcome_event_for` gegen
  `hold_reason_for`, unterbrochen → `unknown`; Flotten-Pause und Fenster, längere Pause
  bleibt, das dnsmasq-Beispiel des Auftrags; Rundreise der Schutzschalter durch `LoopState`;
  nur Sicherheitsuhr (Wanduhr verändert, Ergebnis gleich); Doppelte; Richtlinie nie lockerer als
  `SelfHealingStore.effective_mode`; Reinheit (per AST: kein Import von `homeassistant`,
  `api`, `coordinator`, `heal_store`, `aiohttp`, `asyncssh`, `subprocess`, `socket`, `time`,
  `datetime`).
- **Mutationsprüfung Paket D:** 32 gezielte Änderungen an `heal_catalog.py` und
  `heal_policy.py` (je eine Schutzregel entfernt oder gelockert, etwa `wpad` erlaubt,
  Neustart bereit, keine Begrenzung des Werts, Risiko 3 nicht abgelehnt, Allowlist-Einträge
  nicht neu geprüft, `resolved` schließt den Schutzschalter, Wanduhr statt Sicherheitsuhr);
  alle 32 lassen mindestens einen Test scheitern.
- `tests/test_heal_review_pr77_v1530.py` (Review PR #77, 108 Tests): zu jedem Punkt des
  Reviews der umgedrehte Angriffstest; gegen den Stand vor der Korrektur scheitern 94 davon, die
  übrigen halten Schutz fest, der schon da war, aber ohne Test (etwa `fullmatch`, saubere
  Ablehnungen in der Flotten-Pause). Gate nimmt keine Entscheidung (auch nicht über
  `dataclasses.replace`), erneute Prüfung von Aktion und Parametern, Parameter, die bei jedem
  Lesen etwas anderes liefern; unbekannter Verlauf; `held`/`fleet_paused`/`module_enabled`
  `None`; gefälschte `ValidatedAction`; Rolle, Topologie und Auswirkung des Dienst-Neustarts;
  gleitendes Fenster und Vergleich Richtlinie/Speicher über Zufallsfolgen; Laden einer Datei
  im Format Minor 1; nie verkürzte Abklingzeit; offener Ausgang; ungeladene
  Dienst-Konfiguration; Ursache außerhalb; Prüfung der Sicherungskennung mit `fullmatch`;
  `is_root=None` allein; saubere Ablehnungen in der Flotten-Pause; Schwelle 59/60; Konfidenz
  über 1, negativ, NaN, bool; Typprüfung von `limits`; manuelle Ablehnungen im Wechsel mit
  Erfolgen; `diag.refresh` je 5 min; `dhcp.*`; die Doku nennt Q5–Q7 vorläufig. Dazu je ein
  Test für die zehn Mutationen, die das Review überlebt hatten, und für eigene, die zuerst
  überlebten (Clients am Funk, jeder Neustart auf dem Management-Weg, `max_risk` des Eintrags,
  `risk_high_no_recovery`, Auto-Heal nie bei Requires Approval, Typprüfung vor jeder frühen
  Ablehnung, Wartezeit nach gesenkter Grenze, `resolved` nur für den eigenen Versuch).
- **Mutationsprüfung Review PR #77:** die 32 Mutationen des Reviewers (4 davon an den neuen
  Code angepasst, weil sich die Stelle geändert hat) und 44 eigene an den neuen Regeln (Gate,
  Katalogbindung, None-Regeln, gleitendes Fenster in Richtlinie und Speicher, Abklingzeit,
  offenes Ergebnis, Ursache außerhalb, ungeladene Konfiguration, Auswirkung, Mindestabstand):
  jede der 76 lässt mindestens einen Test scheitern, darunter die zehn, die das Review
  überlebt hatten (M3, M5, M6, M8, M16, M19, M22, M23, M24, M26).

Nicht geprüft (Paket D, X): wer die übrigen Fakten von `RiskContext` und `IncidentFacts`
füllt (etwa `service_config_unapplied`, `service_dependant_routers`, `cause_outside_router`)
und ob sie stimmen (Topologie, Security Center, Vorabprüfungen – E, F); die Ausgänge (I); dass die Router-Aufrufe der gesperrten Aktionen auf der Flotte
so funktionieren, wie der Katalog sie benennt; die deutschen Texte in einer Oberfläche.

- `tests/test_heal_engine_v1530.py` (C1): Auftragstest 1 (Observe: ein Datensatz bis
  PROPOSED, nie weiter, kein Plan ausführbar, auch nicht mit einem handelnden Entscheider und
  bestätigter Ursache; kein Dienst, kein Bus-Ereignis, keine Sperre), Auftragstest 34 (eine
  Wurzel des echten Network-Intelligence-Motors ergibt über dessen Bus-Meldung genau einen
  Datensatz, seine Lösung schließt ihn mit der Zeit der Engine; Wiederholung, Kind, Flotte,
  mehrere Router ergeben keinen; zeitliche Nähe allein wird `insufficient_evidence`),
  null zusätzliche Router-Aufrufe (echter api/Coordinator aus `full_router_kit`), Start und
  Stopp mit den Einträgen, Neustart mit Datensätzen auf der Platte (unterbrochene Ausführung
  bleibt unberührt; offene Observe-Datensätze werden nur bei geladenem Network Intelligence
  geschlossen), Hold und Flotten-Pause, Modul aus (nichts entsteht), Takt und Sicherheitsuhr,
  Entscheidungsschnittstelle, Diagnoseblock ohne Kennungen, Optionsschalter.
- `tests/test_heal_views_v1530.py` (C1): Auftragstest 31 (nur GET-Routen in der Tabelle und
  im Router, 405 für jede andere Methode, 401 ohne Anmeldung, 403 für Nicht-Administratoren
  an allen Routen außer der Übersicht, auch bei offenem Panel; Übersicht dann nur Zähler),
  410, 503, Rumpf abgelehnt, strenge Abfrage ohne Echo, Filter und Seiten, Verlauf, `plans`
  ändert nichts, Holds und Pause sichtbar, kein Geheimnis, keine Adresse, kein Name im Rumpf.
- `tests/test_heal_c1_review_v1530.py` (C1): die Punkte des Reviews von PR #78 (vor der
  Korrektur rot): nur `LOADED`-Einträge (Optionsschalter, Engine, Übersicht), der Eintrag in
  seinem eigenen Setup startet die Engine, Schalter in der Sperre neu gelesen, keine Engine
  ohne Konfigurationsverzeichnis, Optionsfluss speichert ohne `heal_engine`, gefälschte
  Meldungen (`resolved` schließt nichts, unbekannter oder nie gemeldeter Vorfall erzeugt nichts
  und blockiert nichts, `remote` ignoriert, ohne Network Intelligence nichts), kaputte
  Meldungen ohne Warnung, `last_activity` für andere Benutzer auf die Minute, Nachholen nach
  einem Neustart und im Takt (begrenzt, ein Datensatz je Öffnung, kein Router-Aufruf). Dazu
  Tests für Schutzmechanismen, die schon da waren, aber ohne scheiternden Test (Mutationen des
  Reviewers M06, M10, M15, M18, M20, M23, M27, M28): Ausnahme im Empfänger, Ausnahme im Takt,
  Obergrenze der Warteliste, Abbruch der Core-Bindung beim Stopp, nur eigene Planungs-
  Datensätze schließen, gescheitertes Entladen.
- Nach dem ganzen Testlauf darf kein Verzeichnis `MagicMock` stehen (Hook
  `pytest_sessionfinish` in `tests/conftest.py`, der Lauf scheitert sonst). Seit Paket X (e)
  nennt ein roter Abschnitt das Verzeichnis, und die letzte Zeile lautet „N passed, 1 stray
  MagicMock directory (run failed)“ statt nur „N passed“.
- `tests/test_heal_x_policy_v1530.py`, `tests/test_heal_x_engine_v1530.py`,
  `tests/test_heal_x_misc_v1530.py` (Paket X): der Gate prüft nachträglich veränderte
  Eingaben neu und liest Parameter genau einmal (g); Buchungen über die Grenze nie kürzer als
  die alte Regel, Zufallsvergleich (h); unbekannter letzter Lauf sperrt Schreibendes (i); die
  drei überlebenden Mutationen des Reviews (gleiche Kopie eines Katalogeintrags,
  `PolicyLimits`-Unterklasse ohne Prüfung, Fensterrand unter einer Sekunde) (j); eine
  Definition von `ATTEMPT_WINDOW_S` per AST (k); Flotten-Pause im dauerhaften Schritt und
  Vergleich mit `loop_verdict` über Zufallsfolgen. Engine mit echter Richtlinie: Standard der
  laufenden Engine, gefüllte und unbekannte Fakten, Fakten der Engine schlagen die Quelle,
  Schutzschalter und Fehlversuche aus dem `LoopState`, günstige Quelle für `service.restart`
  höchstens Requires Approval, 13 feindliche Quellen und 6 Kandidaten (nichts über PROPOSED),
  Rückfall bei Fehler der Richtlinie, Hold und Pause zeigen Observe (Engine, Übersicht,
  Diagnose), die Klammer in beiden Richtungen, die Erklärung in `plans` (und über die echte
  Route) ohne Speichern, echter Network-Intelligence-Motor Ende zu Ende, null zusätzliche
  Router-Aufrufe; Punkte a–d der Engine; Hook (e) in einem Kindprozess; Optionstext (f).
- **Mutationsprüfung Paket X:** 47 gezielte Lockerungen an `heal_policy.py`,
  `heal_store.py` und `heal_engine.py` (Neuprüfung im Gate, Ablehnungsweg, Abklingzeit über
  der Grenze, unbekannter letzter Lauf, Flotten-Pause im Speicher, Vorrang der Engine-Fakten,
  Abbildung der Wartung, Klammer, Punkte a–d, Erklärung). Im ersten Lauf überlebten zehn,
  alle hinter einem zweiten Schutz (z. B. Merkzettel und Vorprüfung des Slots in c, Reconcile
  und `_close_stale` in d, eine Klammer-Bedingung, die der heutige Katalog nie verletzt); für
  jede kam ein eigener Test dazu, danach ließ jede der 47 mindestens einen Test scheitern.
- Der unique_id-Snapshot (`tests/test_unique_ids_snapshot_v1494.py`) ist unverändert grün:
  C1 bringt keine Entität.

Nicht geprüft: auf Routern (es gibt keinen Router-Aufruf), in einer laufenden HA-Instanz
(die C1-Tests laufen mit einem nachgebildeten `hass`, dem echten Network-Intelligence-Motor
und HAs echter View-Hülle auf einem aiohttp-Testserver; Optionsfluss, Neuladen und Diagnose-
Download nicht in echtem HA), mit echten Plattenfehlern außer dem nachgestellten `WriteError`,
mit mehr als einem Prozess auf derselben Datei, und die Größen mit Datensätzen, die alle
Felder bis an ihre Grenzen füllen (gemessen ist nur der Datensatz der Tests).

**Bekannte Grenzen und TODO (Review P3 und Folgen):**

- `binding_hash` und `state_fingerprint` sind sha256-Werte; die Maskierung des Core hält
  64 hex für Schlüsselmaterial. Die Tests nehmen genau diese zwei Felder aus
  (`DIGEST_FIELDS`); wer die Datei später mit der Maskierung des Core anzeigt (Paket J/K), muss
  sie ebenso als Prüfsumme kennzeichnen, sonst werden sie geschwärzt.
- Die Prüfung schlüsselartiger Namen (`_token`) lehnt jetzt auch Abschnitte ab, die wie JWT-,
  API-Schlüssel- oder Base64-Stücke aussehen (ab 12 Zeichen mit Groß-, Kleinbuchstaben und
  Ziffern, oder ab 16 Zeichen mit mindestens 4 Ziffern). Ein echter Router-Name dieser Form
  (etwa `Wohnzimmer12AP`) würde ebenfalls abgelehnt; der Datensatz entsteht dann nicht. Keine
  Heuristik erkennt jeden Schlüssel.
- Zeit, in der HA aus war, zählt auf der Sicherheitsuhr höchstens 900 s (Abschnitt 5.2): nach
  einer langen Pause dauern Abklingzeiten und Holds entsprechend länger. Die Engine fragt die
  Uhr seit C1 alle 300 s ab (Test `test_the_tick_reads_the_safety_clock_every_five_minutes`).
- Ein Start mit einer Wanduhr über der Höchstmarke kann eine Wartezeit um höchstens 900 s
  verkürzen (Abschnitt 5.2); das ist von echter Ausfallzeit nicht zu unterscheiden. Eine Wanduhr,
  die bei jedem Start um weitere 900 s vorgeht, gewinnt 900 s je Start (Test des Reviewers
  `test_restart_loop_with_ever_further_ahead_clock_gains_n_steps`).
- Ein kaputter Datensatz, der beendet ist (etwa RESOLVED oder FAILED), aber im Verlauf
  EXECUTING zeigt, sperrt seinen Router bis zur Freigabe durch einen Administrator (streng
  gewählt, siehe Abschnitt 5). Der
  Modelltest des Reviewers `test_clock_wrong_then_corrected_gains_time` (reine Wanduhr, ohne
  monotone Zeit) bleibt deshalb grün; im Speicher gilt dieser Weg nur für die erste Beobachtung
  nach einem Start.
- Die Freigabe-Frist (`approval.expires_at`) prüft der Guard des Core (Paket C2); dort muss ein
  Sprung der Wanduhr zurück eine Freigabe ebenfalls nicht verlängern.
- Ob ein Administrator wirklich ein HA-Administrator ist, prüfen die Routen (C2); der Speicher
  sieht nur die Akteursart. Das Audit dieser Eingriffe kommt mit Paket F/K.
