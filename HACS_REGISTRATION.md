# HACS Default Store Registrierung

Dieses Projekt ist **[IN REVIEW]** für die **HACS Default Store** Registrierung. Die Integration wurde am 2026-03-20 als PR #6421 eingereicht.

---

## Status

✅ **Alles vorbereitet:**
- `manifest.json` mit korrekter Version (1.0.8) ← aktualisiert
- `hacs.json` mit `category: "integration"`
- 8x GitHub Releases (v1.0.0 - v1.0.8) mit Release-Notes ← vollständig
- `README.md` vorhanden und aktualisiert mit v1.0.8
- `CHANGELOG.md` mit allen Versionen dokumentiert
- `brand/icon.png` vorhanden (256×256px)

🔄 **PR eingereicht:**
- PR #6421: https://github.com/hacs/default/pull/6421
- Status: **Awaiting HACS Maintainer Review** (typisch 1-7 Tage)
- Sobald genehmigt: Nutzer können direkt über HACS installieren

---

## Eingereichte PR — Warten auf Approval

**Pull Request:** https://github.com/hacs/default/pull/6421
**Status:** ⏳ **Awaiting Review** (eingereicht 2026-03-20)

**HACS Team wird prüfen:**
- ✅ `manifest.json` ist korrekt
- ✅ `hacs.json` vorhanden
- ✅ GitHub Releases existieren (v1.0.0-v1.0.8)
- ✅ Keine Malware/Sicherheitsprobleme
- ✅ Code-Qualität
- ✅ Documentation (README, CHANGELOG aktualisiert)

**Typische Genehmigung:** 1-7 Tage

## Was passiert nach Approval?

Sobald der PR #6421 genehmigt und gemergt wird:

1. Nutzer können die Integration direkt suchen: HACS → Integrations → "OpenWrt Router"
2. Installation ohne Custom Repository
3. Updates werden automatisch von HACS verwaltet
4. Dieser Dokumentations-Eintrag wird archiviert

---

## Struktur-Anforderungen (alle ✅ erfüllt)

```
ha-openwrt-router/
├── custom_components/openwrt_router/
│   ├── __init__.py                ✅
│   ├── manifest.json              ✅ v1.0.8, domain, requirements
│   ├── const.py
│   ├── api.py                     ✅ Update Management API
│   ├── coordinator.py
│   ├── config_flow.py             ✅ SSL/HTTPS Support
│   ├── sensor.py                  ✅ 11 Sensoren + Update Status
│   ├── switch.py                  ✅ WiFi + Band Info + Client Count
│   ├── button.py                  ✅ Reload WiFi + Update Buttons
│   ├── device_tracker.py
│   ├── diagnostics.py
│   ├── strings.json
│   └── translations/en.json
├── README.md                       ✅ v1.0.8, aktualisiert
├── CHANGELOG.md                    ✅ Vollständig dokumentiert
├── hacs.json                       ✅ category: "integration"
├── brand/icon.png                  ✅ 256×256px
├── .github/workflows/
│   ├── hassfest.yaml              ✅ manifest validation
│   ├── hacs.yaml                  ✅ HACS validation
│   └── tests.yaml                 (optional)
└── tests/                          (optional aber empfohlen)

```

---

## Version-History für HACS

| Version | Release Date | Key Features |
|---------|---|---|
| 1.0.8 | 2026-03-20 | **Update Management**: Check & perform package updates |
| 1.0.7 | 2026-03-20 | **SSL/HTTPS**: Secure connections, self-signed cert support |
| 1.0.6 | 2026-03-20 | Sensor visibility improvements |
| 1.0.5 | 2026-03-20 | WiFi switch UX (band info, client count) |
| 1.0.4 | 2026-03-19 | Sensor display names |
| 1.0.3 | 2026-03-19 | WAN statistics (kernel fs) |
| 1.0.1 | 2026-03-19 | Entity naming consistency |
| 1.0.0 | 2026-03-11 | Initial release |

---

## Lokale Validierung (vor PR submission)

Die Validierung wurde durchgeführt:

```bash
✅ manifest.json — valid JSON, version 1.0.8
✅ hacs.json — valid JSON, category definiert
✅ hassfest — no errors
✅ HACS Action — no warnings
```

---

## Roadmap nach Approval

1. **Nutzer sehen Integration im Default Store** (HACS → Integrations → "OpenWrt Router")
2. **Installation ohne Custom Repository** (nur suchen & installieren)
3. **Automatische Updates** (wenn neue Version tagged wird)
4. **Community-Feedback** (über GitHub Issues)

---

## Support & Issues

- **GitHub Issues:** https://github.com/magicx78/ha-openwrt-router/issues
- **HACS PR:** https://github.com/hacs/default/pull/6421
- **Community:** Feel free to star ⭐ and fork!
