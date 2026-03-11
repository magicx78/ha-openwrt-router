#!/usr/bin/env python3
"""Minimal mock OpenWrt ubus JSON-RPC server for integration testing.

Simulates the ubus endpoint at http://localhost:8088/ubus.
Responds to all calls the openwrt_router integration makes.

Usage:
    python3 scripts/mock_router.py

Then configure the integration with:
    host: 127.0.0.1
    port: 8088
    username: root
    password: test
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

MOCK_SESSION_TOKEN = "deadbeefdeadbeefdeadbeefdeadbeef"

RESPONSES = {
    ("session", "login"): {
        "ubus_rpc_session": MOCK_SESSION_TOKEN,
        "timeout": 300,
        "expires": 300,
        "acls": {},
        "data": {"username": "root"},
    },
    ("system", "board"): {
        "kernel": "6.6.73",
        "hostname": "OpenWrt-Dev",
        "model": "GL.iNet GL-MT3000",
        "board_name": "glinet,gl-mt3000",
        "release": {
            "distribution": "OpenWrt",
            "version": "24.10.0",
            "revision": "r28427",
            "codename": "Snapdragon",
            "target": "mediatek/filogic",
            "description": "OpenWrt 24.10.0 r28427",
        },
        "mac": "aa:bb:cc:dd:ee:ff",
    },
    ("system", "info"): {
        "uptime": 86400,
        "load": [65536, 131072, 98304],  # 1.0, 2.0, 1.5 × 65536
        "memory": {
            "total": 268435456,   # 256 MB
            "free": 134217728,    # 128 MB
            "shared": 4194304,
            "buffered": 8388608,
            "available": 142606336,
        },
    },
    ("network.interface", "dump"): {
        "interface": [
            {
                "interface": "wan",
                "up": True,
                "uptime": 3600,
                "proto": "dhcp",
                "ipv4-address": [{"address": "203.0.113.42", "mask": 24}],
                "statistics": {"rx_bytes": 1048576, "tx_bytes": 524288},
            },
            {
                "interface": "lan",
                "up": True,
                "uptime": 86000,
                "proto": "static",
                "ipv4-address": [{"address": "192.168.1.1", "mask": 24}],
                "statistics": {"rx_bytes": 5242880, "tx_bytes": 2097152},
            },
        ]
    },
    ("network.wireless", "status"): {
        "radio0": {
            "up": True,
            "pending": False,
            "interfaces": [
                {
                    "ifname": "phy0-ap0",
                    "config": {
                        "ssid": "OpenWrt-Home",
                        "mode": "ap",
                        "encryption": "psk2",
                        "disabled": False,
                        "section": "default_radio0",
                    },
                }
            ],
        },
        "radio1": {
            "up": True,
            "pending": False,
            "interfaces": [
                {
                    "ifname": "phy1-ap0",
                    "config": {
                        "ssid": "OpenWrt-Home-5G",
                        "mode": "ap",
                        "encryption": "psk2",
                        "disabled": False,
                        "section": "default_radio1",
                    },
                },
                {
                    "ifname": "phy1-ap1",
                    "config": {
                        "ssid": "Guest-WiFi",
                        "mode": "ap",
                        "encryption": "psk2",
                        "disabled": False,
                        "section": "guest_radio1",
                    },
                },
            ],
        },
    },
    ("iwinfo", "info"): {
        "phy0-ap0": {
            "ssid": "OpenWrt-Home",
            "bssid": "AA:BB:CC:DD:EE:01",
            "frequency": 2412,
            "phy": "radio0",
        },
        "phy1-ap0": {
            "ssid": "OpenWrt-Home-5G",
            "bssid": "AA:BB:CC:DD:EE:02",
            "frequency": 5200,
            "phy": "radio1",
        },
    },
    ("iwinfo", "assoclist"): {
        "results": [
            {"mac": "b8:27:eb:aa:bb:01", "signal": -55, "noise": -95},
            {"mac": "ac:de:48:11:22:01", "signal": -70, "noise": -95},
        ]
    },
    ("uci", "get"): {
        "values": {
            "default_radio0": {
                ".type": "wifi-iface",
                "ssid": "OpenWrt-Home",
                "disabled": "0",
                "device": "radio0",
            },
            "default_radio1": {
                ".type": "wifi-iface",
                "ssid": "OpenWrt-Home-5G",
                "disabled": "0",
                "device": "radio1",
            },
            "guest_radio1": {
                ".type": "wifi-iface",
                "ssid": "Guest-WiFi",
                "disabled": "0",
                "device": "radio1",
            },
        }
    },
    ("uci", "set"): {},
    ("uci", "commit"): {},
    ("network", "reload"): {},
    ("file", "read"): {
        "data": (
            "1741600000 b8:27:eb:aa:bb:01 192.168.1.101 raspberrypi 01:b8:27:eb:aa:bb:01\n"
            "1741600001 ac:de:48:11:22:01 192.168.1.102 myphone *\n"
        )
    },
}

AUTH_ERROR = [6, None]   # UBUS_STATUS_PERMISSION_DENIED


class UbusMockHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[mock-router] {fmt % args}")

    def do_POST(self):
        if self.path != "/ubus":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        token, obj, method, params = body.get("params", [None, "", "", {}])

        # Login always succeeds
        if obj == "session" and method == "login":
            result_data = RESPONSES[("session", "login")]
            self._respond(body.get("id", 1), [0, result_data])
            return

        # All other calls require the valid session token
        if token != MOCK_SESSION_TOKEN:
            self._respond(body.get("id", 1), AUTH_ERROR)
            return

        key = (obj, method)
        if key in RESPONSES:
            self._respond(body.get("id", 1), [0, RESPONSES[key]])
        else:
            print(f"[mock-router] UNHANDLED: {obj}/{method}")
            self._respond(body.get("id", 1), [3, None])  # METHOD_NOT_FOUND

    def _respond(self, rpc_id, result):
        payload = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8088), UbusMockHandler)
    print("Mock OpenWrt router listening on http://127.0.0.1:8088/ubus")
    print("  Host:     127.0.0.1")
    print("  Port:     8088")
    print("  Username: root")
    print("  Password: test (any password accepted)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMock router stopped.")
