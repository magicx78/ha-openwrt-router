import os, json
# HA stores auth in .storage/auth
storage_path = "/opt/ha-config/.storage/auth"
if os.path.exists(storage_path):
    with open(storage_path) as f:
        data = json.load(f)
    users = data.get("data", {}).get("users", [])
    creds = data.get("data", {}).get("credentials", [])
    for u in users:
        print("user:", u.get("name"), u.get("id"), "system:", u.get("system_generated"))
    for c in creds:
        print("cred:", c.get("auth_provider_type"), c.get("data", {}).get("username"))
else:
    print("no auth file, listing .storage:")
    for f in os.listdir("/opt/ha-config/.storage"):
        print(" ", f)
