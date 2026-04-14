"""Update the broken IoT markdown card in the CCTV Lovelace view.

The existing card uses 'switch.secure_iot_2_4_ghz' which doesn't exist.
Replaces it with a template that aggregates across all 4 real entities
and adds | default([], true) to prevent TypeError on None.
"""
import json, shutil

LOVELACE_PATH = "/config/.storage/lovelace.lovelace"
BACKUP_PATH   = "/config/.storage/lovelace.lovelace.bak3"

NEW_CONTENT = """\
{% set switches = [
  'switch.secureap_gateway_secure_iot_2_4_ghz',
  'switch.secureap_apclient1_secure_iot_2_4_ghz',
  'switch.secureap_ap3_secure_iot_2_4_ghz',
  'switch.secureap_ap4_secure_iot_2_4_ghz',
] %}
{% set seen = namespace(macs=[]) %}
{% set all_c = namespace(list=[]) %}
{% for sw in switches %}
{% set clients = state_attr(sw, 'clients') | default([], true) %}
{% for c in clients %}
{% if c.mac not in seen.macs %}
{% set seen.macs = seen.macs + [c.mac] %}
{% set all_c.list = all_c.list + [c] %}
{% endif %}
{% endfor %}
{% endfor %}
## IoT-Geräte — {{ all_c.list | length }} online
{% for c in all_c.list | sort(attribute='name') %}
**{{ c.name }}** — {{ c.ip }} — {{ c.signal_dbm }} dBm — expires {{ c.dhcp_expires }}
{% endfor %}
{% if not all_c.list %}*Keine IoT-Geräte verbunden*{% endif %}\
"""

shutil.copy2(LOVELACE_PATH, BACKUP_PATH)
print(f"Backup: {BACKUP_PATH}")

with open(LOVELACE_PATH) as f:
    data = json.load(f)

views = data["data"]["config"]["views"]
cctv_view = next((v for v in views if v.get("path") == "cctv"), None)
if cctv_view is None:
    print("ERROR: cctv view not found"); exit(1)

updated = False
for section in cctv_view.get("sections", []):
    for card in section.get("cards", []):
        if card.get("type") == "markdown" and "secure_iot_2_4_ghz" in card.get("content", ""):
            card["content"] = NEW_CONTENT
            updated = True
            print("Updated existing broken card")

if not updated:
    print("WARN: No matching card found to update")

with open(LOVELACE_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, separators=(",", ":"))

print("OK: Saved")
