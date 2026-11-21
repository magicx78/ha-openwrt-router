"""30-day simulation of the traffic history store (plan 2026-11-20 §5).

Reference fleet of the plan: 6 routers, 17 infrastructure points each
(~100), 150 WLAN clients; one rate per point and 60-s poll, evening peak.
Prints per profile: rates fed, points, buckets per tier, bytes of both
store files exactly as Home Assistant writes them, run time.

    python scripts/traffic_history_sim.py [days] [step_s]

Needs the test environment (Home Assistant installed); no router, no
network, nothing is written.
"""

from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tests")]

from test_traffic_history import simulate

from custom_components.openwrt_router.traffic_history import (
    PROFILES,
    TrafficHistory,
)


def main() -> None:
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    step = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    for name in PROFILES:
        out = simulate(TrafficHistory(profile=name), 0, days, step=step)
        out.pop("end")
        print(json.dumps({"days": days, "step_s": step, **out}))


if __name__ == "__main__":
    main()
