#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOCK_DIR = ROOT / "data" / "mock"

ALERTS_PATH = MOCK_DIR / "alerts.json"
STATUS_PATH = MOCK_DIR / "status.json"

SIM_ALERT = {
    "id": "AL-1004",
    "type": "Kerberoasting",
    "severity": "critical",
    "time": "2026-02-01T09:05:00Z",
    "user": "svc_web",
    "host": "WS-19",
    "details": "Kerberoasting simulation triggered by script."
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path: Path, data):
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def update_alerts():
    alerts = load_json(ALERTS_PATH)
    data = alerts.get("data", {})
    recent = data.get("recent", [])

    recent = [a for a in recent if a.get("id") != SIM_ALERT["id"]]
    recent.insert(0, SIM_ALERT)

    data["recent"] = recent
    alerts["data"] = data

    counts = data.get("counts", {})
    counts["critical"] = sum(1 for a in recent if a.get("severity") == "critical")
    counts["high"] = sum(1 for a in recent if a.get("severity") == "high")
    counts["medium"] = sum(1 for a in recent if a.get("severity") == "medium")
    counts["low"] = sum(1 for a in recent if a.get("severity") == "low")
    data["counts"] = counts

    total = len(recent)
    alerts["summary"] = f"{total} recent alerts in last 24h. {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium."

    save_json(ALERTS_PATH, alerts)
    return total


def update_status(alert_total: int):
    status = load_json(STATUS_PATH)
    data = status.get("data", {})
    data["alerts_total"] = alert_total
    data["last_refresh"] = "2026-02-01T09:10:00Z"
    data["fixtures_version"] = "2026-02-01-sim"
    status["data"] = data
    status["summary"] = f"Mock status OK. {alert_total} alerts, {data.get('incidents_open', 0)} incidents, {data.get('detectors', 0)} detectors."
    save_json(STATUS_PATH, status)


def main():
    total = update_alerts()
    update_status(total)
    print("Simulation applied to mock fixtures.")


if __name__ == "__main__":
    main()
