# HACS Default Store Registrierung

Stand: 2026-07-03 · Integration-Version: v1.20.0

## Status: ❌ Erste Einreichung geschlossen — Neuanlauf offen

- **PR [hacs/default#6421](https://github.com/hacs/default/pull/6421)** (eingereicht
  2026-03-20 mit v1.0.8) wurde am **2026-03-21 ungemerged geschlossen**.
- Die Integration ist damit **nicht** im HACS Default Store. Installation funktioniert
  weiterhin uneingeschränkt als **Custom Repository** (siehe [INSTALL.md](INSTALL.md)).

## Voraussetzungen — aktueller Erfüllungsstand

| Anforderung | Status |
|---|---|
| `hacs.json` (name, homeassistant ≥ 2026.2.0, render_readme) | ✅ |
| `manifest.json` (domain, version, issue_tracker, integration_type, alphabetisch) | ✅ |
| GitHub Releases (aktuell bis v1.19.0, v1.20.0 folgt automatisch) | ✅ |
| README + CHANGELOG gepflegt | ✅ |
| `brand/icon.png` 256×256 im Repo | ✅ |
| CI: hassfest + HACS-Action grün | ✅ |
| GitHub Topics gesetzt | ✅ |
| **PR an [home-assistant/brands](https://github.com/home-assistant/brands)** | ❌ offen — Voraussetzung für Default-Listing |

## Nächste Schritte für den Neuanlauf

1. Aktuellen Submission-Prozess prüfen: https://hacs.xyz/docs/publish/integration
   (Prozess hat sich seit der ersten Einreichung geändert — Grund für die Schließung
   von #6421 vor der Neu-Einreichung verifizieren).
2. Brands-PR stellen (`custom_integrations/openwrt_router/` mit icon/logo).
3. Neu einreichen und PR-Link hier eintragen.

Tracking: siehe [TODO.md](TODO.md) § HACS / Release.
