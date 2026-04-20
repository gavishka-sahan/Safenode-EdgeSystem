import os
import json
import requests
from datetime import datetime, timezone

API_BASE = "http://localhost:8000/api/v1"
HEALTH_DIR = "/root/safenode/Safenode-EdgeSystem/Cloud/cloud_data_storage/health"


def decode_edge_health(data):
    return {
        "cpu_usage_percent":    0,
        "memory_usage_percent": 0,
        "disk_usage_percent":   0,
        "network_rx_bytes":     data.get("bandwidth_bytes", 0),
        "network_tx_bytes":     0,
        "cpu_temperature":      0,
    }


def decode_extractor_health(data):
    hw  = data.get("hardware", {})
    net = hw.get("network", data.get("network", {}))
    return {
        "cpu_usage_percent":    min(hw.get("cpu_usage_percent", 0), 100),
        "memory_usage_percent": hw.get("memory", {}).get("percent", 0),
        "disk_usage_percent":   hw.get("disk_usage_percent", 0),
        "network_rx_bytes":     net.get("bytes_recv", 0),
        "network_tx_bytes":     net.get("bytes_sent", 0),
        "cpu_temperature":      hw.get("cpu_temperature_c", 0),
    }


def insert_health(payload):
    try:
        r = requests.post(f"{API_BASE}/device-health-logs", json=payload, timeout=5)
        if r.status_code not in (200, 201):
            print(f"  ✗ Insert failed ({r.status_code}): {r.text}")
            return False
        return True
    except Exception as e:
        print(f"  ✗ Request error: {e}")
        return False


def main():
    all_files   = sorted(os.listdir(HEALTH_DIR))
    health_files = [f for f in all_files if f.endswith(".json")]

    print(f"Found {len(health_files)} health files\n")

    inserted = 0
    skipped  = 0

    for filename in health_files:
        path = os.path.join(HEALTH_DIR, filename)
        try:
            with open(path) as f:
                data = json.load(f)
        except Exception as e:
            print(f"  ✗ Failed to parse {filename}: {e}")
            skipped += 1
            continue

        module = data.get("module", "")

        if module == "edge_ml":
            payload = decode_edge_health(data)
        elif module == "feature_extractor":
            payload = decode_extractor_health(data)
        else:
            print(f"  ⚠ Unknown module '{module}' in {filename}, skipping")
            skipped += 1
            continue

        ok = insert_health(payload)
        if ok:
            print(f"  ✓ {module} | cpu={payload['cpu_usage_percent']}% | mem={payload['memory_usage_percent']}% | rx={payload['network_rx_bytes']}")
            inserted += 1
        else:
            skipped += 1

    print(f"\nDone. Inserted: {inserted} | Skipped: {skipped}")


if __name__ == "__main__":
    main()
