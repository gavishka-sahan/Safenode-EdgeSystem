"""
Batch loader: reads edge_health.jsonl and extractor_health.jsonl,
posts each record to the health logs API, re-queues failures.
"""

import os
import json
import requests

from jsonl_utils import snapshot_file, read_lines, requeue_lines, remove_snapshot

API_BASE = "http://localhost:8000/api/v1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "cloud_data_storage")

EDGE_HEALTH_FILE = os.path.join(DATA_DIR, "edge_health.jsonl")
EXTRACTOR_HEALTH_FILE = os.path.join(DATA_DIR, "extractor_health.jsonl")


def decode_edge_health(data):
    # Prefer the full hardware block (new format matches extractor schema).
    # Fall back to the legacy flat bandwidth_bytes field so records produced
    # by an older EdgeHealth.py still decode, just with zeros for the
    # metrics it didn't collect.
    hw = data.get("hardware")
    if hw:
        net = hw.get("network", {})
        return {
            "cpu_usage_percent":    min(hw.get("cpu_usage_percent", 0), 100),
            "memory_usage_percent": hw.get("memory", {}).get("percent", 0),
            "disk_usage_percent":   hw.get("disk_usage_percent", 0),
            "network_rx_bytes":     net.get("bytes_recv", 0),
            "network_tx_bytes":     net.get("bytes_sent", 0),
            "cpu_temperature":      hw.get("cpu_temperature_c", 0) or 0,
        }
    # Legacy payload — only bandwidth total was published
    return {
        "cpu_usage_percent":    0,
        "memory_usage_percent": 0,
        "disk_usage_percent":   0,
        "network_rx_bytes":     data.get("bandwidth_bytes", 0),
        "network_tx_bytes":     0,
        "cpu_temperature":      0,
    }


def decode_extractor_health(data):
    hw = data.get("hardware", {})
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


def process_file(live_path, decoder, label):
    snapshot_path = snapshot_file(live_path)
    if snapshot_path is None:
        return 0, 0

    lines = read_lines(snapshot_path)
    if not lines:
        remove_snapshot(snapshot_path)
        return 0, 0

    print(f"[{label}] {len(lines)} record(s) to process")

    inserted = 0
    failed_lines = []

    for raw in lines:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"  ✗ Malformed JSON dropped: {e}")
            # Corrupted line — don't re-queue, just skip it
            continue

        payload = decoder(data)

        if insert_health(payload):
            inserted += 1
            print(f"  ✓ cpu={payload['cpu_usage_percent']}% mem={payload['memory_usage_percent']}% rx={payload['network_rx_bytes']}")
        else:
            failed_lines.append(raw)

    # Re-queue failed lines to the live file for the next run
    requeue_lines(live_path, failed_lines)
    remove_snapshot(snapshot_path)

    return inserted, len(failed_lines)


def main():
    if not os.path.isdir(DATA_DIR):
        print(f"Data directory not found: {DATA_DIR}")
        return

    total_inserted = 0
    total_failed = 0

    ins, fail = process_file(EDGE_HEALTH_FILE, decode_edge_health, "edge")
    total_inserted += ins
    total_failed += fail

    ins, fail = process_file(EXTRACTOR_HEALTH_FILE, decode_extractor_health, "extractor")
    total_inserted += ins
    total_failed += fail

    print(f"\nDone. Inserted: {total_inserted} | Failed (re-queued): {total_failed}")


if __name__ == "__main__":
    main()
