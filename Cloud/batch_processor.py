"""
Batch Processor - SafeNode IoT IDS
====================================
Reads features.jsonl and detections.jsonl written by CloudSubscriber,
correlates them by flow_id, runs DL inference, and posts results to FastAPI.

Designed to run continuously as a service or be called periodically.
Uses atomic file rotation so CloudSubscriber is never interrupted.

Run:
    sudo /usr/bin/python3 /root/safenode/Safenode-EdgeSystem/Cloud/batch_processor.py

Author: Generated for Phantom's Research Pipeline
"""

import json
import os
import time
import uuid
import requests
import numpy as np
import joblib
from datetime import datetime
from tensorflow import keras

# ============================================================================
# CONFIG
# ============================================================================

BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DATA_DIR       = os.path.join(BASE_DIR, "cloud_data_storage")

FEATURES_FILE  = os.path.join(DATA_DIR, "features.jsonl")
DETECTIONS_FILE= os.path.join(DATA_DIR, "detections.jsonl")

MODEL_PATH     = os.path.join(BASE_DIR, "cloud_security_model_final_v3.h5")
SCALER_PATH    = os.path.join(BASE_DIR, "scaler_final_v3.pkl")

API_BASE       = "http://localhost:8000/api/v1"
CLASS_NAMES    = ["Benign", "Mirai", "Spoof", "Scan", "DoS"]
POLL_INTERVAL  = 5  # seconds between each processing cycle

FEATURE_ORDER  = [
    'ttl_value', 'ip_header_len', 'Init_Win_bytes_Fwd',
    'packet_count', 'byte_count', 'packets_per_sec', 'bytes_per_sec',
    'fwd_packet_count', 'bwd_packet_count', 'fwd_byte_count', 'bwd_byte_count',
    'avg_packet_size', 'packet_size_variance', 'bwd_packet_len_mean', 'fwd_packet_len_mean',
    'flow_duration', 'avg_iat', 'min_iat', 'max_iat', 'iat_variance',
    'syn_flag_count', 'ack_flag_count', 'rst_flag_count',
    'psh_flag_count', 'fin_flag_count', 'urg_flag_count',
]

# ============================================================================
# LOAD MODEL (once at startup)
# ============================================================================

print("Loading DL model artifacts...")
model  = keras.models.load_model(MODEL_PATH, compile=False)
scaler = joblib.load(SCALER_PATH)
print(f"✓ Model  : {MODEL_PATH}")
print(f"✓ Scaler : {SCALER_PATH}")
print(f"✓ Classes: {CLASS_NAMES}")
print(f"✓ Watching: {DATA_DIR}")
print(f"✓ Poll interval: {POLL_INTERVAL}s\n")

# ============================================================================
# DL INFERENCE
# ============================================================================

def run_dl(features: dict) -> dict:
    eps = 1e-6
    f = {name: float(features.get(name, 0.0)) for name in FEATURE_ORDER}
    f['packet_size_cv']  = f['packet_size_variance'] / (f['avg_packet_size'] + eps)
    f['payload_density'] = f['byte_count']            / (f['packet_count']    + eps)
    f['fwd_bwd_ratio']   = f['fwd_packet_count']      / (f['bwd_packet_count'] + eps)

    vec = np.array([f[k] for k in FEATURE_ORDER + ['packet_size_cv', 'payload_density', 'fwd_bwd_ratio']], dtype=np.float32)
    vec = np.log1p(vec)
    vec = scaler.transform(vec.reshape(1, -1))

    probs       = model.predict(vec, verbose=0)[0]
    class_index = int(np.argmax(probs))

    return {
        "predicted_class": CLASS_NAMES[class_index],
        "confidence":      round(float(probs[class_index]), 4),
        "is_threat":       CLASS_NAMES[class_index] != "Benign",
        "probabilities":   {CLASS_NAMES[i]: round(float(probs[i]), 4) for i in range(5)}
    }

# ============================================================================
# ATTACK TYPE NORMALIZER
# ============================================================================

def normalize_attack(attack_type: str, is_threat: bool) -> str:
    if not is_threat:
        return "Normal"
    lower = attack_type.lower()
    if 'mirai'  in lower: return 'Mirai'
    if 'replay' in lower: return 'Replay'
    if 'spoof'  in lower or 'sniff' in lower: return 'Spoofing'
    if 'dos'    in lower or 'ddos'  in lower or 'flood' in lower or 'class_1' in lower: return 'DOS'
    return 'Spoofing'

# ============================================================================
# FILE ROTATION — atomic rename so CloudSubscriber is never blocked
# ============================================================================

def rotate_file(filepath: str) -> str | None:
    """
    Rename filepath → filepath.processing if it exists and has content.
    Returns the new path, or None if nothing to process.
    """
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return None
    processing_path = filepath + ".processing"
    os.rename(filepath, processing_path)
    return processing_path


def read_and_delete(filepath: str) -> list[dict]:
    """Read all JSONL lines from a file, delete it, return parsed records."""
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"  ⚠ Skipped malformed line: {e}")
    os.remove(filepath)
    return records

# ============================================================================
# FASTAPI POSTING
# ============================================================================

def post_detection_event(attack_type: str, severity: str, model_name: str,
                          latency: float, mitigation: str) -> bool:
    payload = {
        "attack_type":           attack_type,
        "severity":              severity,
        "model_name":            model_name,
        "processing_latency_ms": latency,
        "mitigation":            mitigation
    }
    try:
        r = requests.post(f"{API_BASE}/detection-events", json=payload, timeout=5)
        r.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Failed to post detection event: {e}")
        return False


def post_traffic_features(src_ip: str, dst_ip: str, flow_id: str,
                           features: dict, classification: str,
                           ml: bool, dl: bool, timestamp: str,
                           event_id: str) -> bool:
    payload = {
        "src_ip":         src_ip,
        "dst_ip":         dst_ip,
        "protocol":       "TCP" if flow_id.endswith("/6") else "UDP" if flow_id.endswith("/17") else "OTHER",
        "byte_count":     int(features.get('byte_count', 0)),
        "packet_size":    float(features.get('avg_packet_size', 0)),
        "ttl":            float(features.get('ttl_value', 0)),
        "timestamp":      timestamp,
        "classification": classification,
        "ml":             ml,
        "dl":             dl,
        "event_id":       event_id
    }
    try:
        r = requests.post(f"{API_BASE}/traffic-features", json=payload, timeout=5)
        r.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"  ✗ Failed to post traffic features: {e}")
        return False

# ============================================================================
# MAIN PROCESSING CYCLE
# ============================================================================

def process_cycle():
    # Step 1 — rotate both files atomically
    feat_path = rotate_file(FEATURES_FILE)
    det_path  = rotate_file(DETECTIONS_FILE)

    if not feat_path and not det_path:
        return  # nothing to process this cycle

    # Step 2 — read records
    feat_records = read_and_delete(feat_path) if feat_path else []
    det_records  = read_and_delete(det_path)  if det_path  else []

    if not feat_records and not det_records:
        return

    print(f"\n[{datetime.utcnow().strftime('%H:%M:%S')}] Processing {len(feat_records)} features, {len(det_records)} detections")

    # Step 3 — index features by flow_id
    features_by_flow = {r['flow_id']: r for r in feat_records}

    # Step 4 — process each detection
    processed = set()
    for det in det_records:
        flow_id    = det.get('flow_id', 'unknown')
        is_threat  = det.get('is_threat', False)
        src_ip     = det.get('src_ip', '0.0.0.0')
        dst_ip     = det.get('dst_ip', '0.0.0.0')
        latency    = det.get('inference_time_ms', 0.0)
        timestamp  = det.get('timestamp', datetime.utcnow().isoformat())
        threats    = det.get('threats', [])
        attack_type = threats[0].get('attack_type', 'None') if threats else 'None'

        classification = normalize_attack(attack_type, is_threat)

        # Get matching features
        feat_data = features_by_flow.get(flow_id, {})
        features  = feat_data.get('features', {})

        # Run DL inference if features available
        dl_result    = None
        dl_is_threat = False
        if features:
            try:
                dl_result    = run_dl(features)
                dl_is_threat = dl_result['is_threat']
                print(f"  ✓ DL [{flow_id}]: {dl_result['predicted_class']} ({dl_result['confidence']*100:.1f}%)")
            except Exception as e:
                print(f"  ✗ DL inference failed for {flow_id}: {e}")

        # Post ML detection event
        event_id = str(uuid.uuid4())
        post_detection_event(
            attack_type=classification,
            severity="High" if is_threat else "Normal",
            model_name="EdgeML",
            latency=latency,
            mitigation="blocked" if is_threat else "none"
        )

        # Post DL detection event if threat detected
        if dl_result and dl_is_threat:
            post_detection_event(
                attack_type=dl_result['predicted_class'],
                severity="High",
                model_name="DL_ResNet_v3",
                latency=0.0,
                mitigation="blocked"
            )

        # Post traffic features with both ml and dl flags
        post_traffic_features(
            src_ip=src_ip,
            dst_ip=dst_ip,
            flow_id=flow_id,
            features=features,
            classification=classification,
            ml=is_threat,
            dl=dl_is_threat,
            timestamp=timestamp,
            event_id=event_id
        )

        processed.add(flow_id)

    # Step 5 — handle any feature records with no matching detection
    unmatched = [r for r in feat_records if r['flow_id'] not in processed]
    if unmatched:
        print(f"  ⚠ {len(unmatched)} feature records had no matching detection — skipped")

    print(f"  ✓ Cycle complete: {len(processed)} flows processed")


# ============================================================================
# MAIN LOOP
# ============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Batch Processor started — polling every 5s")
    print("=" * 60)
    while True:
        try:
            process_cycle()
        except Exception as e:
            print(f"Cycle error: {e}")
        time.sleep(POLL_INTERVAL)
