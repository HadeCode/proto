"""Backend integration test for all nine ARGUS-ONE threat classes.

Start the API first with ``py -3.13 -m uvicorn backend.main:app`` from the
ARGUS-ONE directory, then run this script from the work directory.
"""

from collections import Counter

import requests

from argus_one import demo_flows


URL = "http://127.0.0.1:8000/api/flows/batch"
EXPECTED_THREATS = {
    "SYN Flood",
    "UDP Reflection / Amplification",
    "Spoofed-Source Flood",
    "Botnet C2 Beaconing",
    "DGA Domain",
    "DNS Tunnelling",
    "Encrypted-Session Malware",
    "Port Scanning",
    "Data Exfiltration",
}


def main() -> None:
    response = requests.post(URL, json=demo_flows(), timeout=60)
    response.raise_for_status()
    payload = response.json()
    if payload.get("success") is not True:
        raise RuntimeError(f"unexpected backend response: {payload}")

    alerts = payload.get("alerts", [])
    found = {alert.get("threat_class") for alert in alerts}
    missing = EXPECTED_THREATS - found
    counts = Counter(alert.get("threat_class") for alert in alerts)

    print(f"Sent {len(demo_flows())} synthetic metadata records.")
    print(f"Received {len(alerts)} alerts.")
    print("Threat classes:")
    for threat in sorted(found):
        print(f"- {threat}: {counts[threat]}")

    if missing:
        raise RuntimeError(f"missing expected detections: {sorted(missing)}")
    print("PASS: all nine ARGUS-ONE threat classes were detected.")


if __name__ == "__main__":
    main()
