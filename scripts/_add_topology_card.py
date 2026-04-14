"""Add topology markdown card to the System/Network Lovelace view."""
import json
import shutil

LOVELACE_PATH = "/config/.storage/lovelace.lovelace"
BACKUP_PATH   = "/config/.storage/lovelace.lovelace.bak"

MARKDOWN_CONTENT = """\
{% set routers = [
  ('sensor.secureap_gateway_network_topology', 'sECUREaP Gateway'),
  ('sensor.secureap_ap3_network_topology', 'sECUREaP AP3'),
  ('sensor.secureap_ap4_network_topology', 'sECUREaP AP4'),
  ('sensor.secureap_apclient1_network_topology', 'sECUREaP APClient1'),
  ('sensor.openwrt_network_topology', 'OpenWrt'),
] %}
{% for entity_id, name in routers %}
{% set snap = state_attr(entity_id, 'topology_snapshot') %}
{% if snap %}
{% set cli = snap.nodes | selectattr('type', 'eq', 'client') | list %}
### {{ name }} · {{ cli | length }} Clients
| Gerät | IP | Signal |
|---|---|---|
{% for c in cli | sort(attribute='label') %}| {{ c.label }} | {{ c.attributes.ip or '—' }} | {{ c.attributes.signal ~ ' dBm' if c.attributes.signal else '—' }} |
{% endfor %}{% if not cli %}*Keine Clients verbunden*{% endif %}

{% endif %}
{% endfor %}\
"""

NEW_SECTION = {
    "type": "grid",
    "column_span": 2,
    "cards": [
        {
            "type": "heading",
            "heading": "Router-Clients",
            "heading_style": "title",
        },
        {
            "type": "markdown",
            "content": MARKDOWN_CONTENT,
        },
    ],
}

# Backup
shutil.copy2(LOVELACE_PATH, BACKUP_PATH)
print(f"Backup: {BACKUP_PATH}")

# Load
with open(LOVELACE_PATH) as f:
    data = json.load(f)

views = data["data"]["config"]["views"]

# Find System/Network view
system_view = None
for v in views:
    if v.get("path") == "system-network":
        system_view = v
        break

if system_view is None:
    print("ERROR: system-network view not found"); exit(1)

# Skip if already added
for s in system_view.get("sections", []):
    for card in s.get("cards", []):
        if card.get("type") == "markdown" and "topology_snapshot" in card.get("content", ""):
            print("INFO: Card already present — skipping"); exit(0)

# Append new section
system_view.setdefault("sections", []).append(NEW_SECTION)

# Save (compact, preserve encoding)
with open(LOVELACE_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, separators=(",", ":"))

print("OK: Markdown card added to 'System/Network' view")
