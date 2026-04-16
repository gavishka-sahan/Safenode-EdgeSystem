import json
import os
import glob
import requests
import paho.mqtt.client as mqtt
import uuid
from datetime import datetime
# from DLInferenceService import handle_dl_inference_from_json

# ==========================================================
# PATHS — relative to this script's location
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "cloud_data_storage")
JSON_DIR = os.path.join(DATA_DIR, "json")
LOGS_DIR = os.path.join(DATA_DIR, "logs")
HEALTH_DIR = os.path.join(DATA_DIR, "health")
DETECTION_RESULTS_DIR = os.path.join(DATA_DIR, "detection_results")

os.makedirs(JSON_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(HEALTH_DIR, exist_ok=True)
os.makedirs(DETECTION_RESULTS_DIR, exist_ok=True)

# Maximum number of files to keep per directory (oldest removed first)
MAX_FILES = 10

# ==========================================================
# MQTT CLOUD BROKER CONFIG
# ==========================================================

BROKER_IP = "localhost"
BROKER_PORT = 1883

# ==========================================================
# MQTT TOPICS
# ==========================================================

TOPIC_EDGE_HEALTH = "telemetry/edge/health"
TOPIC_EXT_HEALTH = "telemetry/extractor/health"

TOPIC_EDGE_LOG = "telemetry/edge/log"
TOPIC_EXT_LOG = "telemetry/extractor/log"

TOPIC_FEATURES = "cloud/binary/features"   # carries JSON
TOPIC_ALERTS = "cloud/binary/alerts"       # carries JSON
TOPIC_METADATA = "cloud/metadata"

# ==========================================================
# FASTAPI BACKEND
# ==========================================================

# API_BASE = "http://localhost:8000"
API_BASE = "http://localhost:8000/api/v1"

# ==========================================================
# FEATURE-ALERT CORRELATION STORE
# Features always arrive before alerts for the same flow_id.
# Store features here when received, consume when alert arrives.
# ==========================================================

pending_features = {}


# ==========================================================
# FILE ROTATION HELPER
# Keeps only the MAX_FILES newest files in a directory,
# deleting the oldest when the limit is exceeded.
# ==========================================================

def rotate_files(directory, pattern="*", max_files=MAX_FILES):
    """Delete oldest files in directory if count exceeds max_files."""
    files = sorted(glob.glob(os.path.join(directory, pattern)), key=os.path.getmtime)
    while len(files) >= max_files:
        os.remove(files.pop(0))


# ==========================================================
# CLASSIFICATION HELPER
# ==========================================================

def map_classification(attack_type: str, is_threat: bool) -> str:
    if not is_threat:
        return 'Normal'
    lower = attack_type.lower()
    if 'mirai' in lower:
        return 'Mirai'
    if 'dos' in lower or 'ddos' in lower or 'flood' in lower:
        return 'DOS'
    if 'replay' in lower:
        return 'Replay'
    if 'spoof' in lower or 'sniff' in lower or lower == 'class_1':
        return 'Spoofing'
    return 'Spoofing'  # unknown threat, default to Spoofing so it shows in color


# ==========================================================
# MQTT CONNECT CALLBACK
# ==========================================================

def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print("✓ Connected to Cloud MQTT Broker")
        # QoS 0: periodic health snapshots — a missed one is superseded by the next in 30s
        client.subscribe(TOPIC_EDGE_HEALTH, qos=0)
        client.subscribe(TOPIC_EXT_HEALTH, qos=0)
        # QoS 1: log lines are non-recoverable; at-least-once prevents audit gaps
        client.subscribe(TOPIC_EDGE_LOG, qos=1)
        client.subscribe(TOPIC_EXT_LOG, qos=1)
        # QoS 1: features and alerts drive DB inserts; loss = missing detection record
        client.subscribe(TOPIC_FEATURES, qos=1)
        client.subscribe(TOPIC_ALERTS, qos=1)
        # QoS 0: raw metadata passthrough, file-only, not DB-critical
        client.subscribe(TOPIC_METADATA, qos=0)
        print("Subscribed to all topics")
    else:
        print("Connection failed with code", reason_code)


# ==========================================================
# MQTT MESSAGE HANDLER
# ==========================================================

def on_message(client, userdata, msg):
    print("Incoming topic:", msg.topic)
    try:
        topic = msg.topic
        payload = msg.payload
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

        # --------------------------------------------------
        # EDGE / EXTRACTOR HEALTH
        # --------------------------------------------------
        if topic == TOPIC_EDGE_HEALTH or topic == TOPIC_EXT_HEALTH:
            data = json.loads(payload.decode())

            source = "edge" if topic == TOPIC_EDGE_HEALTH else "extractor"
            rotate_files(HEALTH_DIR, pattern=f"*_{source}_health.json")
            filepath = os.path.join(HEALTH_DIR, f"{timestamp}_{source}_health.json")
            with open(filepath, "w") as f:
                f.write(payload.decode())

            if topic == TOPIC_EDGE_HEALTH:
                db_payload = {
                    "cpu_usage_percent": data.get("mqtt", {}).get("messages_received", 0),
                    "memory_usage_percent": 0,
                    "disk_usage_percent": 0,
                    "network_rx_bytes": data.get("bandwidth_bytes", 0),
                    "network_tx_bytes": 0
                }
            else:
                hw = data.get("hardware", {})
                db_payload = {
                    "cpu_usage_percent": hw.get("cpu_usage_percent", 0),
                    "memory_usage_percent": hw.get("memory", {}).get("percent", 0),
                    "disk_usage_percent": hw.get("disk_usage_percent", 0),
                    "network_rx_bytes": hw.get("network", {}).get("bytes_recv", 0),
                    "network_tx_bytes": hw.get("network", {}).get("bytes_sent", 0)
                }

            requests.post(f"{API_BASE}/device-health-logs", json=db_payload)
            print(f"Saved {source} health and inserted device health log")

        # --------------------------------------------------
        # LOG FILES
        # Single rotating log file — trimmed to last MAX_FILES lines
        # --------------------------------------------------
        elif topic == TOPIC_EDGE_LOG or topic == TOPIC_EXT_LOG:
            log_message = payload.decode()
            log_file = os.path.join(LOGS_DIR, "system_logs.log")

            # Append new line
            with open(log_file, "a") as f:
                f.write(log_message + "\n")

            # Trim to last MAX_FILES lines
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    lines = f.readlines()
                if len(lines) > MAX_FILES:
                    with open(log_file, "w") as f:
                        f.writelines(lines[-MAX_FILES:])

            db_payload = {
                "log_level": "INFO",
                "log_source": topic,
                "message": log_message
            }
            requests.post(f"{API_BASE}/system-logs", json=db_payload)
            print("Inserted system log")

        # --------------------------------------------------
        # JSON FEATURES
        # Store features keyed by flow_id and wait for the
        # matching alert before posting to /traffic-features.
        # --------------------------------------------------
        elif topic == TOPIC_FEATURES:
            data = json.loads(payload.decode())
            flow_id = data.get('flow_id', 'unknown')
            features = data.get('features', {})

            rotate_files(JSON_DIR, pattern="*_features.json")
            filepath = os.path.join(JSON_DIR, f"{timestamp}_features.json")
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Saved JSON features | flow={flow_id} src={data.get('src_ip', '?')}")

            # Store for correlation — alert will consume this
            pending_features[flow_id] = features

        # --------------------------------------------------
        # JSON ALERTS
        # Correlate with stored features to post a combined
        # /traffic-features record with correct classification.
        # --------------------------------------------------
        elif topic == TOPIC_ALERTS:
            data = json.loads(payload.decode())

            is_threat = data.get('is_threat', False)
            src_ip = data.get('src_ip', '0.0.0.0')
            dst_ip = data.get('dst_ip', '0.0.0.0')
            confidence = data.get('max_confidence', 0.0)
            latency = data.get('inference_time_ms', 0.0)
            threats = data.get('threats', [])
            flow_id = data.get('flow_id', 'unknown')
            device_id = data.get('device_id', 'unknown')
            attack_type = threats[0].get('attack_type', 'Unknown') if threats else 'None'

            # Save full detection result to file
            detection_record = {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "flow_id": flow_id,
                "device_id": device_id,
                "is_threat": is_threat,
                "threat_count": data.get('threat_count', 0),
                "max_confidence": confidence,
                "inference_time_ms": latency,
                "attack_type": attack_type,
                "threats": threats,
                "severity": "High" if is_threat else "Normal",
                "mitigation": "blocked" if is_threat else "none",
                "edge_timestamp": data.get('edge_timestamp')
            }
            rotate_files(DETECTION_RESULTS_DIR, pattern="*_detection.json")
            filepath = os.path.join(DETECTION_RESULTS_DIR, f"{timestamp}_detection.json")
            with open(filepath, "w") as f:
                json.dump(detection_record, f, indent=2)
            print(f"Saved detection result: src={src_ip} dst={dst_ip} threat={is_threat} attack={attack_type}")

            # Post detection event to API
            db_payload = {
                "attack_type": map_classification(attack_type, is_threat),
                "severity": "High" if is_threat else "Normal",
                "model_name": "EdgeML",
                "processing_latency_ms": latency,
                "mitigation": "blocked" if is_threat else "none"
            }
            requests.post(f"{API_BASE}/detection-events", json=db_payload)
            print("Inserted detection event")

            # Correlate with stored features and post /traffic-features
            # with the correct classification label
            features = pending_features.pop(flow_id, {})

            # ── DL INFERENCE ────────────────────────────────
            dl_is_threat = False
            try:
                if features:
                    dl_result = handle_dl_inference_from_json(features)
                    if dl_result:
                        dl_is_threat = dl_result["is_threat"]
            except Exception as dl_e:
                print(f"DL inference error: {dl_e}")

            traffic_db_payload = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TCP" if flow_id.endswith("/6") else "UDP" if flow_id.endswith("/17") else "OTHER",
                "byte_count": int(features.get('byte_count', 0)),
                "packet_size": float(features.get('avg_packet_size', 0)),
                "ttl": float(features.get('ttl_value', 0)),
                "timestamp": data.get('timestamp'),
                "classification": map_classification(attack_type, is_threat),
                "ml": is_threat,
                "dl": dl_is_threat,
                "event_id": str(uuid.uuid4())
            }
            requests.post(f"{API_BASE}/traffic-features", json=traffic_db_payload)
            print(f"Inserted traffic features | classification={traffic_db_payload['classification']}")

        # --------------------------------------------------
        # JSON METADATA (raw passthrough)
        # --------------------------------------------------
        elif topic == TOPIC_METADATA:
            json_data = payload.decode()
            rotate_files(JSON_DIR, pattern="*_metadata.json")
            filepath = os.path.join(JSON_DIR, f"{timestamp}_metadata.json")
            with open(filepath, "w") as f:
                f.write(json_data)
            print("Stored JSON metadata")

    except Exception as e:
        print("Error processing message:", e)


# ==========================================================
# MQTT CLIENT SETUP
# ==========================================================

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="CloudSubscriber",
    clean_session=True,
    protocol=mqtt.MQTTv311
)

client.on_connect = on_connect
client.on_message = on_message

print("Connecting to cloud broker...")

client.connect(BROKER_IP, BROKER_PORT, 60)

client.loop_forever()
