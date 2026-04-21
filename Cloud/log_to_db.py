"""
Batch loader: reads edge_log.jsonl and extractor_log.jsonl, posts each
line to the system-logs API. Also wipes metadata.jsonl on each run
since it has no DB target and exists only for debugging.
"""

import os
import json
import requests

from jsonl_utils import snapshot_file, read_lines, requeue_lines, remove_snapshot

API_BASE = "http://localhost:8000/api/v1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "cloud_data_storage")

EDGE_LOG_FILE = os.path.join(DATA_DIR, "edge_log.jsonl")
EXTRACTOR_LOG_FILE = os.path.join(DATA_DIR, "extractor_log.jsonl")
METADATA_FILE = os.path.join(DATA_DIR, "metadata.jsonl")

# API enforces string_too_long at 1000 chars on the message field.
# Extractor bundles batch many log lines into one payload, which
# regularly exceeds this. Truncate silently rather than re-queue
# forever (a structural validation failure will never succeed on retry).
MESSAGE_MAX_LEN = 1000


def insert_log(log_source, message):
    if len(message) > MESSAGE_MAX_LEN:
        message = message[:MESSAGE_MAX_LEN]
    payload = {
        "log_level":  "INFO",
        "log_source": log_source,
        "message":    message,
    }
    try:
        r = requests.post(f"{API_BASE}/system-logs", json=payload, timeout=5)
        if r.status_code not in (200, 201):
            print(f"  ✗ Insert failed ({r.status_code}): {r.text}")
            return False
        return True
    except Exception as e:
        print(f"  ✗ Request error: {e}")
        return False


def process_log_file(live_path, log_source, label):
    snapshot_path = snapshot_file(live_path)
    if snapshot_path is None:
        return 0, 0

    lines = read_lines(snapshot_path)
    if not lines:
        remove_snapshot(snapshot_path)
        return 0, 0

    print(f"[{label}] {len(lines)} line(s) to process")

    inserted = 0
    failed_lines = []

    for raw in lines:
        try:
            data = json.loads(raw)
            message = data.get("message", "")
        except json.JSONDecodeError:
            # Non-JSON line — treat whole line as the message for robustness
            message = raw.strip()

        if insert_log(log_source, message):
            inserted += 1
        else:
            failed_lines.append(raw)

    requeue_lines(live_path, failed_lines)
    remove_snapshot(snapshot_path)

    return inserted, len(failed_lines)


def wipe_metadata():
    """Clear the raw metadata passthrough file. No DB target, debug-only."""
    if os.path.exists(METADATA_FILE):
        try:
            os.remove(METADATA_FILE)
            print("[metadata] Cleared metadata.jsonl")
        except OSError as e:
            print(f"[metadata] Could not clear: {e}")


def main():
    if not os.path.isdir(DATA_DIR):
        print(f"Data directory not found: {DATA_DIR}")
        return

    total_inserted = 0
    total_failed = 0

    ins, fail = process_log_file(EDGE_LOG_FILE, "telemetry/edge/log", "edge_log")
    total_inserted += ins
    total_failed += fail

    ins, fail = process_log_file(EXTRACTOR_LOG_FILE, "telemetry/extractor/log", "extractor_log")
    total_inserted += ins
    total_failed += fail

    wipe_metadata()

    print(f"\nDone. Inserted: {total_inserted} | Failed (re-queued): {total_failed}")


if __name__ == "__main__":
    main()
