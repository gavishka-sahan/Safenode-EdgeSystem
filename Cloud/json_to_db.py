"""
Batch loader: pairs features.jsonl and detections.jsonl by flow_id,
posts each matched pair as (detection_event, traffic_feature),
re-queues unmatched features (may pair with a detection next run),
quarantines true orphans older than the grace period.

Also runs cloud-side DL inference per paired flow:
    - Loads the ResNet model once per oneshot run (~5s cold start)
    - Inserts a separate detection-event row labeled DL_ResNet_v3
    - When DL disagrees with edge consensus, inserts an UNCERTAIN row
    - Updates the dl boolean on traffic-features
    - DL failure is non-fatal — edge rows still insert if DL crashes

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

# DL inference is optional — if TensorFlow / model artifacts are unavailable,
# the loader still processes edge rows. Failure here must NOT prevent edge
# detections from reaching the database.
#
# Import the low-level functions instead of handle_dl_inference_from_json
# because that function POSTs to /detection-events on its own. We need to
# control the POST ourselves so the DL row shares an event_id with a paired
# traffic-features row (matching the edge-row pattern).
try:
    from DLInferenceService import _run_inference as _dl_run_inference
    from DLInferenceService import extract_from_json as _dl_extract_from_json
    DL_AVAILABLE = True
except Exception as _dl_load_err:
    print(f"⚠ DL inference unavailable: {_dl_load_err}")
    _dl_run_inference = None
    _dl_extract_from_json = None
    DL_AVAILABLE = False

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


def run_dl_inference(features: dict):
    """
    Run cloud DL inference on a flow's feature dict.

    Returns dict with keys: predicted_class, confidence, is_threat, probabilities
    Returns None on any failure — caller treats this as "no DL verdict for this flow"
    and falls back to edge-only insertion.
    """
    if not DL_AVAILABLE or _dl_run_inference is None:
        return None
    if not features:
        return None
    try:
        f = _dl_extract_from_json(features)
        return _dl_run_inference(f)
    except Exception as e:
        print(f"  ⚠ DL inference error: {e}")
        return None


def insert_dl_row(label, model_name, severity, mitigation, inference_time,
                  timestamp, src_ip, dst_ip, protocol,
                  byte_count, packet_size, ttl, dl_threat_flag):
    """
    Insert one (detection_event, traffic_feature) pair labeled by DL.
    Mirrors the edge insert pattern but with model_name/label from DL.

    Returns True if both inserts succeeded.
    """
    event_id = str(uuid.uuid4())

    detection_payload = {
        "event_id":              event_id,
        "attack_type":           label,
        "severity":              severity,
        "model_name":            model_name,
        "processing_latency_ms": inference_time,
        "mitigation":            mitigation,
    }
    traffic_payload = {
        "event_id":       event_id,
        "timestamp":      timestamp,
        "src_ip":         src_ip,
        "dst_ip":         dst_ip,
        "protocol":       protocol,
        "byte_count":     byte_count,
        "packet_size":    packet_size,
        "ttl":            ttl,
        "classification": label,
        "ml":             False,
        "dl":             dl_threat_flag,
    }

    try:
        r1 = requests.post(f"{API_BASE}/detection-events", json=detection_payload, timeout=5)
        r2 = requests.post(f"{API_BASE}/traffic-features", json=traffic_payload, timeout=5)
    except Exception as e:
        print(f"  ✗ DL insert request error ({label}): {e}")
        return False

    ok = r1.status_code in (200, 201) and r2.status_code in (200, 201)
    if not ok:
        print(f"  ✗ DL insert failed ({label}): detection={r1.status_code} traffic={r2.status_code}")
    return ok


def insert_pair(feature_data, detection_data):
    """
    Insert one detection event + traffic feature row for EACH model that fired
    on this flow. If multiple models fired (e.g. dos + replay + spoof on the
    same flow), each gets its own row so the dashboard reflects all detections
    rather than collapsing to a single 'winning' label.

    Returns (success: bool, labels: list[str]).
    A success means at least one (detection, feature) pair inserted cleanly.
    """
    is_threat = detection_data.get("is_threat", False)
    inference_time = float(detection_data.get("inference_time_ms", 0.0))
    mitigation = detection_data.get("mitigation", "blocked" if is_threat else "none")
    features = feature_data.get("features", {})
    flow_id = feature_data.get("flow_id", "unknown")
    timestamp = feature_data.get("timestamp", datetime.utcnow().isoformat())
    src_ip = feature_data.get("src_ip", "0.0.0.0")
    dst_ip = feature_data.get("dst_ip", "0.0.0.0")
    protocol = get_protocol(flow_id)
    byte_count = int(features.get("byte_count", 0))
    packet_size = float(features.get("avg_packet_size", 0.0))
    ttl = float(features.get("ttl_value", 0.0))

    # ── Run cloud DL inference up front so the dl boolean on the edge
    # rows below reflects the actual DL verdict (rather than a stale False).
    # If DL fails, dl_result is None and we fall back to dl=False on edge rows
    # and skip the DL/UNCERTAIN inserts entirely.
    dl_result = run_dl_inference(features)
    dl_threat = bool(dl_result["is_threat"]) if dl_result else False

    # Build the list of (label, model_name, confidence) tuples to insert.
    # If threats[] is non-empty, insert one row per fired model.
    # If threats[] is empty (benign flow), insert one row labeled Normal.
    threats = detection_data.get("threats", [])
    rows_to_insert = []

    if threats:
        for threat in threats:
            model_name = (threat.get("model") or "").strip().lower()
            threat_type = (threat.get("attack_type") or "").strip().lower()

            # Resolve label: prefer the threat's attack_type, fall back to model name
            label = ATTACK_TYPE_MAP.get(threat_type)
            if not label and model_name in MODEL_TO_ATTACK:
                label = MODEL_TO_ATTACK[model_name]
            if not label:
                label = "Normal"

            confidence = float(threat.get("confidence", 0.0))
            rows_to_insert.append((label, model_name or "EdgeML", confidence))
    else:
        # Benign flow — keep existing behavior (single Normal row)
        rows_to_insert.append(("Normal", "EdgeML", 0.0))

    inserted_labels = []
    any_success = False

    for label, model_name, confidence in rows_to_insert:
        event_id = str(uuid.uuid4())

        detection_payload = {
            "event_id":              event_id,
            "attack_type":           label,
            "severity":              "High" if is_threat and label != "Normal" else "Low",
            "model_name":            model_name,
            "processing_latency_ms": inference_time,
            "mitigation":            mitigation,
        }
        traffic_payload = {
            "event_id":       event_id,
            "timestamp":      timestamp,
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "protocol":       protocol,
            "byte_count":     byte_count,
            "packet_size":    packet_size,
            "ttl":            ttl,
            "classification": label,
            "ml":             True,
            "dl":             dl_threat,
        }

        try:
            r1 = requests.post(f"{API_BASE}/detection-events", json=detection_payload, timeout=5)
            r2 = requests.post(f"{API_BASE}/traffic-features", json=traffic_payload, timeout=5)
        except Exception as e:
            print(f"  ✗ Request error ({label}): {e}")
            continue

        ok = r1.status_code in (200, 201) and r2.status_code in (200, 201)
        if ok:
            any_success = True
            inserted_labels.append(label)
        else:
            print(f"  ✗ Insert failed ({label}): detection={r1.status_code} traffic={r2.status_code}")

    # ── DL row insertion ────────────────────────────────────────────────
    # Insert a separate detection-event row representing the cloud DL verdict.
    # This runs independently of the edge inserts above — even if some edge
    # inserts failed, we still want the DL second opinion in the database.
    if dl_result is not None:
        dl_label = dl_result["predicted_class"]   # Benign / Mirai / Spoof / Scan / DoS
        dl_severity = "High" if dl_threat else "Low"
        dl_mitigation = "blocked" if dl_threat else "none"

        if insert_dl_row(
            label=dl_label,
            model_name="DL_ResNet_v3",
            severity=dl_severity,
            mitigation=dl_mitigation,
            inference_time=0.0,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            byte_count=byte_count,
            packet_size=packet_size,
            ttl=ttl,
            dl_threat_flag=dl_threat,
        ):
            inserted_labels.append(f"DL:{dl_label}")
            any_success = True

        # ── UNCERTAIN flag on edge/DL disagreement ──────────────────────
        # Edge consensus = is_threat from the detection record (any edge
        # model fired). DL consensus = dl_threat. If they disagree, insert
        # an UNCERTAIN row so the dashboard surfaces it for admin review.
        edge_threat = bool(is_threat)
        if edge_threat != dl_threat:
            edge_view = "threat" if edge_threat else "benign"
            dl_view = "threat" if dl_threat else "benign"
            print(f"  ⚠ DISAGREE on flow={flow_id}: edge={edge_view} DL={dl_view} ({dl_label})")
            if insert_dl_row(
                label="UNCERTAIN",
                model_name="DisagreementFlag",
                severity="Medium",
                mitigation="review",
                inference_time=0.0,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                byte_count=byte_count,
                packet_size=packet_size,
                ttl=ttl,
                dl_threat_flag=dl_threat,
            ):
                inserted_labels.append("UNCERTAIN")
                any_success = True

    return any_success, inserted_labels


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

        ok, labels = insert_pair(feature_data, detection_data)
        if ok:
            for label in labels:
                counts[label] = counts.get(label, 0) + 1
            labels_str = ", ".join(labels) if labels else "(none)"
            print(f"  ✓ {labels_str} | {feature_data.get('src_ip', '?')} → {feature_data.get('dst_ip', '?')} | flow={flow_id}")
            inserted += len(labels)
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
