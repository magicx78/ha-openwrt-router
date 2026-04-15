"""Remove all openwrt_router entities from HA entity registry and config entries."""
import json, os

storage = "/opt/ha-config/.storage"

# 1. Remove config entries for openwrt_router
ce_path = os.path.join(storage, "core.config_entries")
if os.path.exists(ce_path):
    with open(ce_path) as f:
        data = json.load(f)
    before = len(data["data"]["entries"])
    data["data"]["entries"] = [e for e in data["data"]["entries"] if e.get("domain") != "openwrt_router"]
    after = len(data["data"]["entries"])
    with open(ce_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Config entries: removed {before - after} openwrt_router entries ({before} -> {after})")

# 2. Remove entity registry entries for openwrt_router
er_path = os.path.join(storage, "core.entity_registry")
if os.path.exists(er_path):
    with open(er_path) as f:
        data = json.load(f)
    before = len(data["data"]["entities"])
    data["data"]["entities"] = [e for e in data["data"]["entities"] if e.get("platform") != "openwrt_router"]
    after = len(data["data"]["entities"])
    with open(er_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Entity registry: removed {before - after} openwrt_router entities ({before} -> {after})")

# 3. Remove device registry entries for openwrt_router
dr_path = os.path.join(storage, "core.device_registry")
if os.path.exists(dr_path):
    with open(dr_path) as f:
        data = json.load(f)
    before = len(data["data"]["devices"])
    data["data"]["devices"] = [
        d for d in data["data"]["devices"]
        if not any(ident[0] == "openwrt_router" for ident in d.get("identifiers", []))
    ]
    after = len(data["data"]["devices"])
    with open(dr_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Device registry: removed {before - after} openwrt_router devices ({before} -> {after})")

print("Done. Start HA and re-add the integration.")
