"""
Batch loader: pairs features.jsonl and detections.jsonl by flow_id,
posts each matched pair as (detection_event, traffic_feature),
re-queues unmatched features (may pair with a detection next run),
quarantines true orphans older than the grace period.

Cross-file atomicity:
    Both files are snapshotted in immediate succession so any feature
    whose detection arrives between the two renames is preserved —
    the unmatched feature is re-queued to the live features.jsonl
    and will pair up on the next run.
"""

import os
import json
import uuid
import requests
from datetime import datetime

from jsonl_utils import snapshot_file, read_lines, requeue_lines, remove_snapshot

API_BASE = "http://localhost:8000/api/v1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "cloud_data_storage")

FEATURES_FILE = os.path.join(DATA_DIR, "features.jsonl")
DETECTIONS_FILE = os.path.join(DATA_DIR, "detections.jsonl")
ORPHAN_FILE = os.path.join(DATA_DIR, "orphaned_features.jsonl")

# Max number of consecutive runs a feature may stay in the queue without
# finding its matching detection before being declared orphan.
# With a 60s timer, ORPHAN_THRESHOLD_RUNS=2 means ~2 minutes of grace.
ORPHAN_THRESHOLD_RUNS = 2

MODEL_THRESHOLDS = {
    "mirai":  0.30,
    "dos":    0.20,
    "replay": 0.80,
    "spoof":  0.92,
}

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

        def margin(t):
            model = t.get("model", "").lower()
            thr = MODEL_THRESHOLDS.get(model, 0.5)
            conf = t.get("confidence", 0.0)
            denom = 1.0 - thr
            return (conf - thr) / denom if denom > 0 else 0.0

        top_threat = max(threats, key=margin)
        # top_threat = max(threats, key=lambda t: t.get("confidence", 0.0))

        threat_type = (top_threat.get("attack_type") or "").strip().lower()
        mapped = ATTACK_TYPE_MAP.get(threat_type)
        if mapped:
            return mapped

        model_name = top_threat.get("model", "").strip().lower()
        if model_name in MODEL_TO_ATTACK:
            return MODEL_TO_ATTACK[model_name]

    return "Normal"


def insert_pair(feature_data, detection_data):
    """
    Insert both detection event and traffic feature.
    Returns (success: bool, attack_label: str | None).
    """
    attack_label = resolve_attack_type(detection_data)
    is_threat = detection_data.get("is_threat", False)
    inference_time = float(detection_data.get("inference_time_ms", 0.0))
    mitigation = detection_data.get("mitigation", "blocked" if is_threat else "none")

    features = feature_data.get("features", {})
    event_id = str(uuid.uuid4())

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
        "timestamp":      feature_data.get("timestamp", datetime.utcnow().isoformat()),
        "src_ip":         feature_data.get("src_ip", "0.0.0.0"),
        "dst_ip":         feature_data.get("dst_ip", "0.0.0.0"),
        "protocol":       get_protocol(feature_data.get("flow_id", "unknown")),
        "byte_count":     int(features.get("byte_count", 0)),
        "packet_size":    float(features.get("avg_packet_size", 0.0)),
        "ttl":            float(features.get("ttl_value", 0.0)),
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


def parse_records(raw_lines):
    """Parse JSONL lines into (record, raw_line) tuples. Drops malformed."""
    out = []
    for raw in raw_lines:
        try:
            data = json.loads(raw)
            out.append((data, raw))
        except json.JSONDecodeError as e:
            print(f"  ✗ Malformed JSON dropped: {e}")
    return out


def main():
    if not os.path.isdir(DATA_DIR):
        print(f"Data directory not found: {DATA_DIR}")
        return

    # Snapshot both files in rapid succession.
    # Any detection that arrives between these two renames will be
    # handled on the next run (feature re-queued, detection stays in live file).
    features_snap = snapshot_file(FEATURES_FILE)
    detections_snap = snapshot_file(DETECTIONS_FILE)

    feature_lines = read_lines(features_snap)
    detection_lines = read_lines(detections_snap)

    print(f"Found {len(feature_lines)} features | {len(detection_lines)} detections")

    if not feature_lines and not detection_lines:
        remove_snapshot(features_snap)
        remove_snapshot(detections_snap)
        print("Nothing to process")
        return

    # Index detections by flow_id so features can look them up in O(1).
    # If duplicates exist for the same flow_id, keep the last one seen.
    detection_records = parse_records(detection_lines)
    detections_by_flow = {}
    for data, raw in detection_records:
        flow_id = data.get("flow_id")
        if flow_id:
            detections_by_flow[flow_id] = (data, raw)

    feature_records = parse_records(feature_lines)

    inserted = 0
    failed_pairs = []     # (feature_raw, detection_raw) — API error, retry both
    unmatched_features = []  # feature_raw — no detection yet, retry feature
    counts = {}

    for feature_data, feature_raw in feature_records:
        flow_id = feature_data.get("flow_id", "unknown")
        detection_pair = detections_by_flow.get(flow_id)

        if detection_pair is None:
            # Check retry count embedded in the feature record itself
            retry_count = int(feature_data.get("_retry_count", 0))

            if retry_count >= ORPHAN_THRESHOLD_RUNS:
                # True orphan — write to quarantine file
                with open(ORPHAN_FILE, "a") as f:
                    f.write(feature_raw if feature_raw.endswith("\n") else feature_raw + "\n")
                print(f"  ⚠ ORPHAN quarantined (retry={retry_count}): flow={flow_id}")
            else:
                # Bump retry counter and re-queue
                feature_data["_retry_count"] = retry_count + 1
                unmatched_features.append(json.dumps(feature_data) + "\n")
            continue

        detection_data, detection_raw = detection_pair

        ok, label = insert_pair(feature_data, detection_data)
        if ok:
            counts[label] = counts.get(label, 0) + 1
            print(f"  ✓ {label} | {feature_data.get('src_ip', '?')} → {feature_data.get('dst_ip', '?')} | flow={flow_id}")
            inserted += 1
        else:
            # API failure — re-queue both for retry
            failed_pairs.append((feature_raw, detection_raw))

    # Re-queue failed pairs (both files)
    if failed_pairs:
        with open(FEATURES_FILE, "a") as f:
            for feat_raw, _ in failed_pairs:
                f.write(feat_raw if feat_raw.endswith("\n") else feat_raw + "\n")
        with open(DETECTIONS_FILE, "a") as f:
            for _, det_raw in failed_pairs:
                f.write(det_raw if det_raw.endswith("\n") else det_raw + "\n")

    # Re-queue unmatched features (waiting for detections to arrive next run)
    requeue_lines(FEATURES_FILE, unmatched_features)

    # Re-queue detections whose feature was unmatched this run (waiting
    # for the feature to be retried next run). Failed pairs already have
    # their detection re-queued via the failed_pairs block above.
    flows_needing_detection = set()
    for line in unmatched_features:
        try:
            fid = json.loads(line).get("flow_id")
            if fid:
                flows_needing_detection.add(fid)
        except json.JSONDecodeError:
            pass

    unmatched_detections = [
        raw for data, raw in detection_records
        if data.get("flow_id") in flows_needing_detection
    ]
    requeue_lines(DETECTIONS_FILE, unmatched_detections)

    remove_snapshot(features_snap)
    remove_snapshot(detections_snap)

    print(f"\nDone. Inserted: {inserted} | Waiting: {len(unmatched_features)} | Failed (re-queued): {len(failed_pairs)}")
    if counts:
        print(f"Distribution: {counts}")


if __name__ == "__main__":
    main()
