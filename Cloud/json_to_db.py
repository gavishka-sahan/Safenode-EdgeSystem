import os
import json
import uuid
import requests
from datetime import datetime

API_BASE = "http://localhost:8000/api/v1"
JSON_DIR = "/root/safenode/Safenode-EdgeSystem/Cloud/cloud_data_storage/json"
DETECTION_DIR = "/root/safenode/Safenode-EdgeSystem/Cloud/cloud_data_storage/detection_results"

# Map model names and detailed attack types to clean dashboard labels
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


def resolve_attack_type(data):
    """
    Resolve clean attack label from detection JSON.
    1. Try mapping attack_type field directly
    2. Fall back to model name from threats array
    3. Fall back to Normal
    """
    # Try top-level attack_type first
    raw_type = (data.get("attack_type") or "").strip().lower()
    if raw_type and raw_type not in ("none", "class_1", ""):
        mapped = ATTACK_TYPE_MAP.get(raw_type)
        if mapped:
            return mapped

    # Fall back to threats array — pick highest confidence threat
    threats = data.get("threats", [])
    if threats:
        top_threat = max(threats, key=lambda t: t.get("confidence", 0.0))

        # Try mapping the threat's attack_type
        threat_type = (top_threat.get("attack_type") or "").strip().lower()
        mapped = ATTACK_TYPE_MAP.get(threat_type)
        if mapped:
            return mapped

        # Fall back to model name
        model_name = top_threat.get("model", "").strip().lower()
        if model_name in MODEL_TO_ATTACK:
            return MODEL_TO_ATTACK[model_name]

    return "Normal"


def load_detections():
    """Load all detection JSONs into a dict keyed by flow_id."""
    detections = {}
    for filename in os.listdir(DETECTION_DIR):
        if not filename.endswith("_detection.json"):
            continue
        try:
            with open(os.path.join(DETECTION_DIR, filename)) as f:
                data = json.load(f)
            flow_id = data.get("flow_id")
            if flow_id:
                detections[flow_id] = {
                    "is_threat":         data.get("is_threat", False),
                    "attack_type":       resolve_attack_type(data),
                    "inference_time_ms": float(data.get("inference_time_ms", 0.0)),
                    "mitigation":        data.get("mitigation", "none"),
                }
        except Exception as e:
            print(f"  ✗ Skipping detection file {filename}: {e}")
    return detections


def parse_features(filepath):
    """Parse a features JSON file."""
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


def insert(event_id, record, detection):
    """Insert into both API endpoints."""
    detection_payload = {
        "event_id":              event_id,
        "attack_type":           detection["attack_type"],
        "severity":              "High" if detection["is_threat"] else "Low",
        "model_name":            "EdgeML",
        "processing_latency_ms": detection["inference_time_ms"],
        "mitigation":            detection["mitigation"],
    }
    traffic_payload = {
        "event_id":       event_id,
        "timestamp":      record["timestamp"],
        "src_ip":         record["src_ip"],
        "dst_ip":         record["dst_ip"],
        "protocol":       get_protocol(record["flow_id"]),
        "byte_count":     record["byte_count"],
        "packet_size":    record["packet_size"],
        "ttl":            record["ttl"],
        "classification": detection["attack_type"],
        "ml":             True,
        "dl":             False,
    }
    r1 = requests.post(f"{API_BASE}/detection-events", json=detection_payload, timeout=5)
    r2 = requests.post(f"{API_BASE}/traffic-features", json=traffic_payload, timeout=5)
    return r1.status_code in (200, 201), r2.status_code in (200, 201)


def main():
    feature_files = sorted(f for f in os.listdir(JSON_DIR) if f.endswith("_features.json"))
    detections = load_detections()

    print(f"Found {len(feature_files)} feature files | {len(detections)} detection records\n")

    inserted, skipped, counts = 0, 0, {}

    default = {
        "is_threat":         False,
        "attack_type":       "Normal",
        "inference_time_ms": 0.0,
        "mitigation":        "none",
    }

    for filename in feature_files:
        try:
            record = parse_features(os.path.join(JSON_DIR, filename))
            detection = detections.get(record["flow_id"], default)
            ok1, ok2 = insert(str(uuid.uuid4()), record, detection)

            if ok1 and ok2:
                label = detection["attack_type"]
                counts[label] = counts.get(label, 0) + 1
                print(f"  ✓ {label} | {record['src_ip']} → {record['dst_ip']} | threat={detection['is_threat']}")
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ✗ Error processing {filename}: {e}")
            skipped += 1

    print(f"\nDone. Inserted: {inserted} | Skipped: {skipped}")
    print(f"Distribution: {counts}")


if __name__ == "__main__":
    main()
