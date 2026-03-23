# SSH Setup für ha-openwrt-router

## Schnell-Verbindung

Nach der SSH-Key-Installation:

```bash
ssh openwrt
```

Das ist alles! Kein Passwort nötig.

---

## Was wurde eingerichtet

1. **SSH Key generiert**: `~/.ssh/openwrt_ed25519`
   - ED25519 Schlüssel (modern, sicher, schnell)
   - Öffentlicher Key: `~/.ssh/openwrt_ed25519.pub`

2. **Public Key zum Router kopiert**: `~/.ssh/authorized_keys`
   - Router akzeptiert SSH-Anmeldung mit Schlüssel
   - Kein Passwort bei Anmeldung nötig

3. **SSH Config aufgesetzt**: `~/.ssh/config`
   ```
   Host openwrt
       HostName 10.10.10.1
       User root
       IdentityFile ~/.ssh/openwrt_ed25519
       StrictHostKeyChecking no
       UserKnownHostsFile /dev/null
   ```

---

## Warum SSH Key Auth besser ist

| Aspekt | Passwort | SSH Key |
|--------|----------|---------|
| Sicherheit | ⚠️ Text-basiert | ✅ Kryptografisch |
| Automation | ❌ sshpass nötig | ✅ Direkt |
| Passwort speichern | ❌ Sicherheitsrisiko | ✅ Nicht nötig |
| Mehrere Geräte | ⚠️ Copy-Paste | ✅ Verbreitung einfach |

---

## Weitere SSH Kommandos

```bash
# Direkt Kommando ausführen
ssh openwrt "uptime"
ssh openwrt "ls -la /root"

# Interactive Shell
ssh openwrt

# Mit Port-Weiterleitung (falls nötig)
ssh -L 8080:localhost:80 openwrt

# SCP (Datei kopieren)
scp openwrt:/root/ha-wifi-control.sh ./
scp ./config.yml openwrt:/tmp/
```

---

## Falls SSH Key verloren geht

Wiederherstellen mit Passwort:

```bash
sshpass -p '16051979Cs$' ssh root@10.10.10.1
```

Oder: Neuen Key generieren und wieder kopieren.

---

## Integration mit ha-openwrt-router

Die HA Integration nutzt **SSH Fallback** für:
- WiFi-Kontrolle (enable/disable SSID)
- System-Metriken (CPU, Memory, Uptime)
- WAN Status (RX/TX Bytes)
- Disk/tmpfs Statistiken

**Aktuell:** Integration nutzt sshpass + Passwort (funktioniert ✅)

**Zukünftig:** Integration könnte SSH Key verwenden (sicherer, aber mehr Setup)

---

**Eingerichtet:** 2026-03-23
**Router:** 10.10.10.1 (Cudy WR3000 v1)
**Status:** ✅ SSH-Zugriff funktioniert
