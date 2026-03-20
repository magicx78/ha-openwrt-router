# Claude Code Setup — ha-openwrt-router

## Was ist hier drin

```
CLAUDE.md                      ← Projekt-Kontext (Repo-Root)
.claude/agents/
  ├── coordinator.md           ← Koordiniert komplexe Multi-Domain Aufgaben
  ├── openwrt-api.md           ← Spezialist: api.py + coordinator.py
  ├── ha-entities.md           ← Spezialist: sensor/switch/tracker/button
  └── hacs-release.md          ← Spezialist: CI, Releases, HACS
```

---

## Installation (3 Schritte)

### Schritt 1 — Dateien ins Repo kopieren

```bash
# Im Repo-Root von ha-openwrt-router:
cp CLAUDE.md .                    # Projekt-Kontext
cp -r .claude/ .                  # Agents-Ordner
```

Die finale Struktur im Repo:
```
ha-openwrt-router/
├── CLAUDE.md                  ← NEU
├── .claude/
│   └── agents/
│       ├── coordinator.md     ← NEU
│       ├── openwrt-api.md     ← NEU
│       ├── ha-entities.md     ← NEU
│       └── hacs-release.md    ← NEU
├── custom_components/
│   └── openwrt_router/
├── tests/
└── ...
```

### Schritt 2 — Claude Code starten

```bash
cd ha-openwrt-router
claude
```

Claude Code liest `CLAUDE.md` automatisch beim Start.

### Schritt 3 — Skill einbinden (optional aber empfohlen)

Den `home-automation.skill` in Claude Code als Skill hinterlegen
damit Claude auch ESPHome + LVGL Wissen hat wenn du ein Display baust.

---

## Wie die Agents funktionieren

### Einfache Aufgabe → direkt zum Spezialisten

```
Du:    "füge einen Memory Usage Sensor hinzu"
Claude: ruft ha-entities auf → schreibt sensor.py + translations
```

```
Du:    "der hassfest workflow schlägt fehl"
Claude: ruft hacs-release auf → analysiert + repariert
```

```
Du:    "implementiere async_get_bandwidth() für eth0"
Claude: ruft openwrt-api auf → schreibt api.py + Test
```

### Komplexe Aufgabe → Coordinator koordiniert

```
Du:    "baue den Bandwidth Sensor komplett von A bis Z"
Claude: ruft coordinator auf
        → koordiniert openwrt-api (api.py + coordinator.py)
        → koordiniert ha-entities (sensor.py + translations)
        → prüft Konsistenz zwischen beiden
```

```
Du:    "bereite Release 0.2.0 vor"
Claude: ruft coordinator auf
        → prüft Code-Stand
        → koordiniert hacs-release (CHANGELOG, manifest, Tag)
```

### Agents committen nichts

Agents schreiben und ändern Dateien — aber `git commit` und `git push`
machst du selbst. Claude zeigt dir was geändert wurde.

---

## Beispiel-Prompts die gut funktionieren

```
"bandwidth sensoren für eth0 und wlan0 hinzufügen"
"ci workflows für hassfest und hacs erstellen"
"brand/icon.png generieren"
"device tracker zeigt keine ip-adressen an, debug das"
"release 0.2.0 vorbereiten mit changelog"
"neuen switch für guest wifi hinzufügen"
"was fehlt noch für den hacs default store"
```
