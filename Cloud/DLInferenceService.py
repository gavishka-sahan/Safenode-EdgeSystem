"""
DL Inference Service - Cloud Side
===================================
Accepts either:
  - JSON feature dict (from cloud/metadata topic) via handle_dl_inference_from_json()
  - Binary payload (legacy) via handle_dl_inference()

Pipeline:
  named feature dict
  → Feature engineering (3 derived features → 29 total)
  → log1p transform
  → StandardScaler (scaler_final_v3.pkl)
  → ResNet model inference (cloud_security_model_final_v3.h5)
  → POST result to FastAPI

Author: Generated for Phantom's Research Pipeline
"""

import struct
import numpy as np
import joblib
import requests
import os
from tensorflow import keras

# ============================================================================
# CONFIG
# ============================================================================

MODEL_PATH   = "cloud_security_model_final_v3.h5"
SCALER_PATH  = "scaler_final_v3.pkl"
ENCODER_PATH = "encoder_final_v3.pkl"
API_BASE     = "http://localhost:8000/api/v1"

CLASS_NAMES  = ["Benign", "Mirai", "Spoof", "Scan", "DoS"]

# 26 unique feature names (flow_iat_std excluded — duplicate of iat_variance)
FEATURE_ORDER = [
    'ttl_value',
    'ip_header_len',
    'Init_Win_bytes_Fwd',
    'packet_count',
    'byte_count',
    'packets_per_sec',
    'bytes_per_sec',
    'fwd_packet_count',
    'bwd_packet_count',
    'fwd_byte_count',
    'bwd_byte_count',
    'avg_packet_size',
    'packet_size_variance',
    'bwd_packet_len_mean',
    'fwd_packet_len_mean',
    'flow_duration',
    'avg_iat',
    'min_iat',
    'max_iat',
    'iat_variance',
    'syn_flag_count',
    'ack_flag_count',
    'rst_flag_count',
    'psh_flag_count',
    'fin_flag_count',
    'urg_flag_count',
]

# ============================================================================
# LOAD ARTIFACTS (once at startup)
# ============================================================================

print("Loading DL model artifacts...")

model   = keras.models.load_model(MODEL_PATH, compile=False)
scaler  = joblib.load(SCALER_PATH)
encoder = joblib.load(ENCODER_PATH)

print(f"✓ Model loaded     : {MODEL_PATH}")
print(f"✓ Scaler loaded    : {SCALER_PATH}")
print(f"✓ Encoder loaded   : {ENCODER_PATH}")
print(f"✓ Classes          : {CLASS_NAMES}")

# ============================================================================
# PREPROCESSING
# ============================================================================

def extract_from_json(features: dict) -> dict:
    """
    Extract the 26 required features from a named feature dict
    (as received from cloud/metadata → metadata.features).
    Missing features default to 0.0.
    """
    return {name: float(features.get(name, 0.0)) for name in FEATURE_ORDER}


def extract_from_binary(payload: bytes) -> dict:
    """
    Unpack 27 packed floats from legacy binary payload.
    flow_iat_std (duplicate of iat_variance) is discarded.
    """
    if len(payload) != 27 * 4:
        raise ValueError(f"Expected 108 bytes, got {len(payload)}")

    ALL_FEATURE_NAMES = [
        'ttl_value', 'ip_header_len', 'Init_Win_bytes_Fwd',
        'packet_count', 'byte_count', 'packets_per_sec', 'bytes_per_sec',
        'fwd_packet_count', 'bwd_packet_count', 'fwd_byte_count', 'bwd_byte_count',
        'avg_packet_size', 'packet_size_variance', 'bwd_packet_len_mean', 'fwd_packet_len_mean',
        'flow_duration', 'avg_iat', 'min_iat', 'max_iat', 'iat_variance',
        'flow_iat_std',  # duplicate — discarded
        'syn_flag_count', 'ack_flag_count', 'rst_flag_count',
        'psh_flag_count', 'fin_flag_count', 'urg_flag_count',
    ]
    values = struct.unpack('27f', payload)
    all_features = dict(zip(ALL_FEATURE_NAMES, values))
    return {k: v for k, v in all_features.items() if k != 'flow_iat_std'}


def engineer_features(f: dict) -> dict:
    """
    Compute 3 derived features used during training.
    Must be added before log1p and scaling.
    26 originals + 3 engineered = 29 total (matches scaler).
    """
    eps = 1e-6
    f['packet_size_cv']  = f['packet_size_variance'] / (f['avg_packet_size'] + eps)
    f['payload_density'] = f['byte_count']            / (f['packet_count']    + eps)
    f['fwd_bwd_ratio']   = f['fwd_packet_count']      / (f['bwd_packet_count'] + eps)
    return f


def build_feature_vector(f: dict) -> np.ndarray:
    """Build 29-feature numpy array in training column order."""
    ordered_keys = FEATURE_ORDER + ['packet_size_cv', 'payload_density', 'fwd_bwd_ratio']
    return np.array([f[k] for k in ordered_keys], dtype=np.float32)


def preprocess_features(f: dict) -> np.ndarray:
    """
    Shared preprocessing pipeline:
      feature engineering → log1p → StandardScaler
    """
    f = engineer_features(f)
    vec = build_feature_vector(f)
    vec = np.log1p(vec)
    vec = scaler.transform(vec.reshape(1, -1))  # shape: (1, 29)
    return vec

# ============================================================================
# INFERENCE
# ============================================================================

def _run_inference(f: dict) -> dict:
    """Core inference on a named feature dict. Returns result dict."""
    X = preprocess_features(f)
    probs = model.predict(X, verbose=0)[0]
    class_index = int(np.argmax(probs))
    predicted_class = CLASS_NAMES[class_index]
    confidence = float(probs[class_index])
    is_threat = predicted_class != "Benign"

    return {
        "predicted_class": predicted_class,
        "class_index": class_index,
        "confidence": round(confidence, 4),
        "probabilities": {
            CLASS_NAMES[i]: round(float(probs[i]), 4) for i in range(len(CLASS_NAMES))
        },
        "is_threat": is_threat
    }

# ============================================================================
# POST TO FASTAPI
# ============================================================================

def post_dl_result(result: dict):
    """Post DL inference result to FastAPI /detection-events."""
    db_payload = {
        "attack_type":           result["predicted_class"],
        "severity":              "High" if result["is_threat"] else "Normal",
        "model_name":            "DL_ResNet_v3",
        "processing_latency_ms": 0.0,
        "mitigation":            "blocked" if result["is_threat"] else "none"
    }
    try:
        response = requests.post(f"{API_BASE}/detection-events", json=db_payload)
        response.raise_for_status()
        print(f"✓ Posted DL result: {result['predicted_class']} ({result['confidence']*100:.1f}%)")
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to post DL result: {e}")

# ============================================================================
# PUBLIC ENTRY POINTS
# ============================================================================

def handle_dl_inference_from_json(features: dict):
    """
    Main entry point for JSON-based pipeline (current architecture).
    Call this from CloudSubscriber's TOPIC_METADATA handler.

    Args:
        features: dict from metadata.features (named keys, float values)

    Example usage in CloudSubscriber.py:
        from DLInferenceService import handle_dl_inference_from_json
        ...
        elif topic == TOPIC_METADATA:
            meta = json.loads(payload.decode())
            features = meta.get('metadata', {}).get('features', {})
            if features:
                handle_dl_inference_from_json(features)
    """
    try:
        f = extract_from_json(features)
        result = _run_inference(f)

        print(f"\n── DL Inference Result ──────────────────")
        print(f"   Predicted : {result['predicted_class']}")
        print(f"   Confidence: {result['confidence']*100:.1f}%")
        print(f"   Is Threat : {result['is_threat']}")
        print(f"   Probs     : {result['probabilities']}")
        print(f"─────────────────────────────────────────\n")

        post_dl_result(result)
        return result

    except Exception as e:
        print(f"✗ DL Inference error: {e}")
        return None


def handle_dl_inference(payload: bytes):
    """
    Legacy entry point for binary payload pipeline.
    Kept for backwards compatibility.
    """
    try:
        f = extract_from_binary(payload)
        result = _run_inference(f)

        print(f"\n── DL Inference Result ──────────────────")
        print(f"   Predicted : {result['predicted_class']}")
        print(f"   Confidence: {result['confidence']*100:.1f}%")
        print(f"   Is Threat : {result['is_threat']}")
        print(f"─────────────────────────────────────────\n")

        post_dl_result(result)
        return result

    except Exception as e:
        print(f"✗ DL Inference error: {e}")
        return None

# ============================================================================
# STANDALONE TEST
# ============================================================================

if __name__ == "__main__":
    print("\nRunning standalone test with real-world-like feature values...")

    dummy_features = {
        'ttl_value': 64.0,
        'ip_header_len': 20.0,
        'Init_Win_bytes_Fwd': 502.0,
        'packet_count': 17.0,
        'byte_count': 5122.0,
        'packets_per_sec': 0.30292,
        'bytes_per_sec': 91.268068,
        'fwd_packet_count': 9.0,
        'bwd_packet_count': 8.0,
        'fwd_byte_count': 4592.0,
        'bwd_byte_count': 530.0,
        'avg_packet_size': 301.294118,
        'packet_size_variance': 101186.32526,
        'bwd_packet_len_mean': 66.25,
        'fwd_packet_len_mean': 510.222222,
        'flow_duration': 56.120394,
        'avg_iat': 3.507533,
        'min_iat': 0.00234,
        'max_iat': 11.179857,
        'iat_variance': 4.853809,
        'syn_flag_count': 0.0,
        'ack_flag_count': 17.0,
        'rst_flag_count': 0.0,
        'psh_flag_count': 8.0,
        'fin_flag_count': 0.0,
        'urg_flag_count': 0.0,
    }

    result = handle_dl_inference_from_json(dummy_features)
