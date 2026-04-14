"""Patch CCTV Lovelace view: add mushroom-select-card + update markdown card with filter logic."""
import json, shutil

LOVELACE_PATH = "/config/.storage/lovelace.lovelace"
BACKUP_PATH   = "/config/.storage/lovelace.lovelace.bak4"

SELECTOR_CARD = {
    "type": "custom:mushroom-select-card",
    "entity": "input_select.netz_filter",
    "name": "Netz-Filter",
    "icon": "mdi:filter-outline",
    "layout": "horizontal",
}

MARKDOWN_CONTENT = """\
{% set filter = states('input_select.netz_filter') | default('Alle') %}
{% set iot_sw = [
  'switch.secureap_gateway_secure_iot_2_4_ghz',
  'switch.secureap_apclient1_secure_iot_2_4_ghz',
  'switch.secureap_ap3_secure_iot_2_4_ghz',
  'switch.secureap_ap4_secure_iot_2_4_ghz',
] %}
{% set klee_sw = [
  'switch.secureap_gateway_tenant_klee_2_4_ghz',
  'switch.secureap_apclient1_tenant_klee_2_4_ghz',
  'switch.secureap_ap3_tenant_klee_2_4_ghz',
  'switch.secureap_ap4_tenant_klee_2_4_ghz',
  'switch.secureap_gateway_tenant_klee_5_ghz',
  'switch.secureap_apclient1_tenant_klee_5_ghz',
  'switch.secureap_ap3_tenant_klee_5_ghz',
  'switch.secureap_ap4_tenant_klee_5_ghz',
] %}
{% if filter == 'IoT' %}{% set src = iot_sw %}
{% elif filter == 'Klee' %}{% set src = klee_sw %}
{% else %}{% set src = iot_sw + klee_sw %}{% endif %}
{% set seen = namespace(macs=[]) %}
{% set all_c = namespace(list=[]) %}
{% for sw in src %}
{% set clients = state_attr(sw, 'clients') | default([], true) %}
{% for c in clients %}
{% if c.mac not in seen.macs %}
{% set seen.macs = seen.macs + [c.mac] %}
{% if filter != 'Letzte 10 Min' or c.connected_since | int < 600 %}
{% set all_c.list = all_c.list + [c] %}
{% endif %}{% endif %}
{% endfor %}{% endfor %}
## {{ filter }} — {{ all_c.list | length }} Geräte
{% for c in all_c.list | sort(attribute='name') %}
**{{ c.name }}** — {{ c.ip }} — {{ c.signal_dbm }} dBm — expires {{ c.dhcp_expires }}
{% endfor %}{% if not all_c.list %}*Keine Geräte*{% endif %}\
"""

shutil.copy2(LOVELACE_PATH, BACKUP_PATH)
print(f"Backup: {BACKUP_PATH}")

with open(LOVELACE_PATH) as f:
    data = json.load(f)

views = data["data"]["config"]["views"]
cctv = next((v for v in views if v.get("path") == "cctv"), None)
if cctv is None:
    print("ERROR: cctv view not found"); exit(1)

sections = cctv.setdefault("sections", [])
if not sections:
    print("ERROR: no sections in cctv view"); exit(1)

target_section = sections[1]  # section with the markdown card
cards = target_section.setdefault("cards", [])

# 1. Insert mushroom-select-card at index 0 (if not already there)
has_selector = any(
    c.get("entity") == "input_select.netz_filter"
    for c in cards
)
if not has_selector:
    cards.insert(0, SELECTOR_CARD)
    print("Added mushroom-select-card")
else:
    print("Selector card already present — skipping")

# 2. Update markdown card content (find by type=markdown)
updated = False
for card in cards:
    if card.get("type") == "markdown":
        card["content"] = MARKDOWN_CONTENT
        updated = True
        print("Updated markdown card with filter template")
        break

if not updated:
    print("WARN: no markdown card found to update")

with open(LOVELACE_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, separators=(",", ":"))

print("OK: lovelace saved")
