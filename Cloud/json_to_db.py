import os
import json
import uuid
import time
import requests
from datetime import datetime

API_BASE = "http://localhost:8000/api/v1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_DIR = os.path.join(BASE_DIR, "cloud_data_storage", "json")
DETECTION_DIR = os.path.join(BASE_DIR, "cloud_data_storage", "detection_results")
ORPHAN_DIR = os.path.join(JSON_DIR, "orphaned")

# How long to wait for the matching detection file before declaring orphan.
# Feature + detection files are published back-to-back by CloudAdapter;
# 30s is a generous safety window for MQTT/network/disk-write jitter.
GRACE_PERIOD_SECONDS = 30

# Map model names and attack_type strings to clean dashboard labels
MODEL_TO_ATTACK = {
    "mirai":  "Mirai",
    "dos":    "DOS",
    "replay": "Replay",
    "spoof":  "Spoofing",
}

ATTACK_TYPE_MAP = {
    "mirai-greip_flood":  "Mirai",
    "mirai-greeth_flood": "Mirai",
    "mirai-udpplain":     "Mirai",
    "mirai":              "Mirai",
    "dos":                "DOS",
    "dos-synflood":       "DOS",
    "dos-udpflood":       "DOS",
    "replay":             "Replay",
    "spoofing":           "Spoofing",
    "none":               "Normal",
}


def get_protocol(flow_id):
    try:
        proto_num = int(flow_id.split("/")[-1])
        return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, "TCP")
    except Exception:
        return "TCP"


def resolve_attack_type(detection_data):
    """Resolve clean attack label from detection JSON."""
    raw_type = (detection_data.get("attack_type") or "").strip().lower()
    if raw_type and raw_type not in ("none", "class_1", ""):
        mapped = ATTACK_TYPE_MAP.get(raw_type)
        if mapped:
            return mapped

    threats = detection_data.get("threats", [])
    if threats:
        top_threat = max(threats, key=lambda t: t.get("confidence", 0.0))

        threat_type = (top_threat.get("attack_type") or "").strip().lower()
        mapped = ATTACK_TYPE_MAP.get(threat_type)
        if mapped:
            return mapped

        model_name = top_threat.get("model", "").strip().lower()
        if model_name in MODEL_TO_ATTACK:
            return MODEL_TO_ATTACK[model_name]

    return "Normal"


def load_detections_by_flow():
    """Load all detection JSONs indexed by flow_id. Returns {flow_id: (filepath, data)}."""
    if not os.path.isdir(DETECTION_DIR):
        return {}

    detections = {}
    for filename in os.listdir(DETECTION_DIR):
        if not filename.endswith("_detection.json"):
            continue
        filepath = os.path.join(DETECTION_DIR, filename)
        try:
            with open(filepath) as f:
                data = json.load(f)
            flow_id = data.get("flow_id")
            if flow_id:
                # If two detections share a flow_id (rare — same tuple reused), keep newest
                if flow_id in detections:
                    existing_path, _ = detections[flow_id]
                    if os.path.getmtime(filepath) > os.path.getmtime(existing_path):
                        detections[flow_id] = (filepath, data)
                else:
                    detections[flow_id] = (filepath, data)
        except Exception as e:
            print(f"  ✗ Skipping detection {filename}: {e}")
    return detections


def parse_feature_file(filepath):
    """Parse a features JSON file into a normalized record."""
    with open(filepath) as f:
        data = json.load(f)
    feat = data.get("features", {})
    return {
        "src_ip":      data.get("src_ip", "0.0.0.0"),
        "dst_ip":      data.get("dst_ip", "0.0.0.0"),
        "flow_id":     data.get("flow_id", "unknown"),
        "timestamp":   data.get("timestamp", datetime.utcnow().isoformat()),
        "ttl":         feat.get("ttl_value", 0.0),
        "byte_count":  int(feat.get("byte_count", 0)),
        "packet_size": float(feat.get("avg_packet_size", 0.0)),
    }


def insert_pair(event_id, feature_record, detection_data):
    """Insert both detection event and traffic feature. Returns True only if BOTH succeed."""
    attack_label = resolve_attack_type(detection_data)
    is_threat = detection_data.get("is_threat", False)
    inference_time = float(detection_data.get("inference_time_ms", 0.0))
    mitigation = detection_data.get("mitigation", "blocked" if is_threat else "none")

    detection_payload = {
        "event_id":              event_id,
        "attack_type":           attack_label,
        "severity":              "High" if is_threat else "Low",
        "model_name":            "EdgeML",
        "processing_latency_ms": inference_time,
        "mitigation":            mitigation,
    }
    traffic_payload = {
        "event_id":       event_id,
        "timestamp":      feature_record["timestamp"],
        "src_ip":         feature_record["src_ip"],
        "dst_ip":         feature_record["dst_ip"],
        "protocol":       get_protocol(feature_record["flow_id"]),
        "byte_count":     feature_record["byte_count"],
        "packet_size":    feature_record["packet_size"],
        "ttl":            feature_record["ttl"],
        "classification": attack_label,
        "ml":             True,
        "dl":             False,
    }

    try:
        r1 = requests.post(f"{API_BASE}/detection-events", json=detection_payload, timeout=5)
        r2 = requests.post(f"{API_BASE}/traffic-features", json=traffic_payload, timeout=5)
    except Exception as e:
        print(f"  ✗ Request error: {e}")
        return False, None

    ok = r1.status_code in (200, 201) and r2.status_code in (200, 201)
    if not ok:
        print(f"  ✗ Insert failed: detection={r1.status_code} traffic={r2.status_code}")
    return ok, attack_label


def main():
    if not os.path.isdir(JSON_DIR):
        print(f"JSON directory not found: {JSON_DIR}")
        return

    os.makedirs(ORPHAN_DIR, exist_ok=True)

    feature_files = sorted(
        f for f in os.listdir(JSON_DIR)
        if f.endswith("_features.json")
    )
    detections = load_detections_by_flow()

    print(f"Found {len(feature_files)} feature files | {len(detections)} detection records\n")

    inserted, waiting, orphaned, failed = 0, 0, 0, 0
    counts = {}
    now = time.time()

    for filename in feature_files:
        feature_path = os.path.join(JSON_DIR, filename)

        try:
            record = parse_feature_file(feature_path)
        except Exception as e:
            print(f"  ✗ Error parsing {filename}: {e}")
            failed += 1
            continue

        flow_id = record["flow_id"]
        pair = detections.get(flow_id)

        if pair is None:
            # No matching detection — check file age
            age = now - os.path.getmtime(feature_path)
            if age < GRACE_PERIOD_SECONDS:
                # Still within grace period — leave for next run
                waiting += 1
                continue
            else:
                # True orphan — quarantine so the queue can drain
                print(f"  ⚠ ORPHAN (no detection after {int(age)}s): {filename} | flow={flow_id}")
                try:
                    os.rename(feature_path, os.path.join(ORPHAN_DIR, filename))
                except OSError as e:
                    print(f"    ✗ Could not quarantine: {e}")
                orphaned += 1
                continue

        detection_path, detection_data = pair

        ok, label = insert_pair(str(uuid.uuid4()), record, detection_data)
        if ok:
            counts[label] = counts.get(label, 0) + 1
            print(f"  ✓ {label} | {record['src_ip']} → {record['dst_ip']} | flow={flow_id}")
            # Delete BOTH files only after successful dual-insert
            for p in (feature_path, detection_path):
                try:
                    os.remove(p)
                except OSError as e:
                    print(f"    ⚠ Could not delete {p}: {e}")
            inserted += 1
        else:
            # Leave both files on disk — will retry next run
            failed += 1

    print(f"\nDone. Inserted: {inserted} | Waiting: {waiting} | Orphaned: {orphaned} | Failed: {failed}")
    if counts:
        print(f"Distribution: {counts}")


if __name__ == "__main__":
    main()
