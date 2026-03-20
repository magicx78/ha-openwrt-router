# HACS Default Store Registrierung

Dieses Projekt ist jetzt bereit für die **HACS Default Store** Registrierung. Das bedeutet, dass Nutzer die Integration direkt über HACS installieren können (ohne Custom Repository).

---

## Status

✅ **Alles vorbereitet:**
- `manifest.json` mit korrekter Version (1.0.4)
- `hacs.json` mit `category: "integration"`
- 5x GitHub Releases (v1.0.0 - v1.0.4) mit Release-Notes
- `README.md` vorhanden
- `CHANGELOG.md` mit allen Versionen

❌ **Noch nicht im Default Store** (nächster Schritt)

---

## Schritt 1: Manuell (über Web UI)

1. **Gehe zu:** https://github.com/hacs/default
2. **Fork das Repo** (Button oben rechts)
3. **Dein Fork öffnen** (github.com/deinusername/default)
4. **Branch erstellen:** `add-openwrt-router`
5. **Datei bearbeiten:** `repositories.json`

### repositories.json eintrag hinzufügen (am Ende vor der schließenden `]`):

```json
{
  "repository": "magicx78/ha-openwrt-router",
  "category": "integration",
  "topics": [
    "openwrt",
    "router",
    "wifi",
    "wan"
  ]
}
```

6. **Commit & Push**
7. **Pull Request erstellen** gegen `hacs/default` main branch

---

## Schritt 2: Warten auf Approval

**HACS Team** wird prüfen:
- ✅ `manifest.json` ist korrekt
- ✅ `hacs.json` vorhanden
- ✅ GitHub Releases existieren
- ✅ Keine Malware/Sicherheitsprobleme
- ✅ Code-Qualität

Typische Genehmigung: **1-3 Tage**

---

## Danach: Automatische Updates

Sobald der PR merged ist:
1. Nutzer öffnen HACS
2. Suchen "OpenWrt Router"
3. Installieren direkt (kein Custom Repository nötig)
4. Bei neuer Version → HACS zeigt Update-Button automatisch

---

## Lokale HACS-Validierung

Um zu testen, dass alles funktioniert:

```bash
# Teste die Manifest-Datei
python3 -m json.tool custom_components/openwrt_router/manifest.json

# Teste die HACS-Konfiguration
python3 -m json.tool hacs.json
```

Beide sollten **valid JSON** sein (keine Fehler).

---

## Struktur-Anforderungen (alle ✅)

```
ha-openwrt-router/
├── custom_components/openwrt_router/
│   ├── __init__.py
│   ├── manifest.json          ✅ domain, version, requirements
│   ├── const.py
│   ├── api.py
│   ├── coordinator.py
│   ├── sensor.py
│   ├── switch.py
│   ├── device_tracker.py
│   └── ...
├── README.md                  ✅ vorhanden
├── CHANGELOG.md               ✅ vorhanden
├── hacs.json                  ✅ vorhanden
├── .github/workflows/         ⏸️  optional aber empfohlen
│   ├── hassfest.yaml         (validiert manifest.json)
│   └── hacs.yaml             (validiert HACS-Struktur)
└── brand/
    └── icon.png              ⏸️  optional, 256×256px

```

---

## Häufige Fehler

❌ Version in `manifest.json` stimmt nicht mit Release überein
✅ **Gelöst:** v1.0.4 in manifest.json

❌ `hacs.json` hat kein `category` Feld
✅ **Gelöst:** `"category": "integration"` hinzugefügt

❌ GitHub Releases existieren nicht
✅ **Gelöst:** 5 Releases mit Release-Notes erstellt

---

## Nächste Aktion

**Nutzer sollte:**
1. Zu https://github.com/hacs/default gehen
2. Fork erstellen
3. Pull Request mit Integration eintrag stellen
4. Auf Approval warten

**Automated Option:** Falls GitHub CLI verfügbar:
```bash
gh repo fork hacs/default
git clone gh://deinusername/default
# ... make changes to repositories.json ...
gh pr create --repo hacs/default --title "Add OpenWrt Router integration"
```

---

## Kontakt

GitHub Issues: https://github.com/magicx78/ha-openwrt-router/issues
