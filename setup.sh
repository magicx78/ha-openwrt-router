#!/bin/bash

# ============================================
# Claude Code Setup — Ubuntu
# Deinen API Key hier eintragen:
# ============================================

API_KEY="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"

# ============================================
# Ab hier nichts ändern
# ============================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "============================================"
echo "  Claude Code Setup für Ubuntu"
echo "============================================"
echo ""

# API Key prüfen
if [[ "$API_KEY" == "sk-ant-DEIN-KEY-HIER" ]]; then
    echo -e "${RED}FEHLER: API Key nicht gesetzt!${NC}"
    echo "Öffne dieses Script und trage deinen Key ein:"
    echo "  API_KEY=\"sk-ant-dein-echter-key\""
    exit 1
fi

# Sudo prüfen
if ! sudo -n true 2>/dev/null; then
    echo "Sudo-Passwort wird benötigt:"
    sudo true
fi

# ---- System-Updates ----
echo -e "${GREEN}[1/4] System-Pakete aktualisieren...${NC}"
sudo apt-get update -qq
sudo apt-get install -y curl

# ---- Node.js 20 ----
echo ""
echo -e "${GREEN}[2/4] Node.js prüfen...${NC}"

if command -v node &>/dev/null; then
    NODE_VER=$(node --version | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VER" -ge 18 ]; then
        echo "Node.js $(node --version) bereits vorhanden ✓"
    else
        echo -e "${YELLOW}Node.js $(node --version) zu alt — wird aktualisiert...${NC}"
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    fi
else
    echo "Node.js wird installiert..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "Node.js $(node --version) ✓"

# ---- Claude Code installieren ----
echo ""
echo -e "${GREEN}[3/4] Claude Code installieren...${NC}"
sudo npm install -g @anthropic-ai/claude-code
echo "Claude Code $(claude --version) ✓"

# ---- API Key setzen ----
echo ""
echo -e "${GREEN}[4/4] API Key konfigurieren...${NC}"

# WICHTIG: Umgebungsvariable setzen (verhindert OAuth-Login)
export ANTHROPIC_API_KEY="$API_KEY"

# Dauerhaft in ~/.bashrc speichern
if grep -q "ANTHROPIC_API_KEY" ~/.bashrc; then
    sed -i "s|export ANTHROPIC_API_KEY=.*|export ANTHROPIC_API_KEY=\"$API_KEY\"|" ~/.bashrc
    echo "API Key in ~/.bashrc aktualisiert ✓"
else
    echo "" >> ~/.bashrc
    echo "# Claude Code API Key" >> ~/.bashrc
    echo "export ANTHROPIC_API_KEY=\"$API_KEY\"" >> ~/.bashrc
    echo "API Key in ~/.bashrc gespeichert ✓"
fi

# Fertig
echo ""
echo "============================================"
echo -e "${GREEN}  Setup abgeschlossen!${NC}"
echo "============================================"
echo ""
echo "Jetzt ausführen:"
echo ""
echo "  source ~/.bashrc"
echo "  claude"
echo ""
echo "Oder direkt im Projekt:"
echo "  source ~/.bashrc && cd ha-openwrt-router && claude"
echo ""
