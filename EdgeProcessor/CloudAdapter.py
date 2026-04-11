import json
import time
import os
import threading
import paho.mqtt.client as mqtt
from DLFeatureSelector import CLOUD_FEATURE_INDICES


# Local Broker (The Raspberry Pi running EdgeML.py)
LOCAL_BROKER_IP = "localhost"
LOCAL_BROKER_PORT = 1883

# Cloud Broker (The VM)
CLOUD_BROKER_IP = "217.217.248.193"
CLOUD_BROKER_PORT = 1883  # Standard MQTT-over-TLS port

# Certificates for Cloud Connection
# CA_CERTS = "/home/nomad/shared/EgdeProcessor-simplified/ca.crt"

# --- Topics ---
LOCAL_JSON_TOPIC = "cloud/metadata"
CLOUD_JSON_FEATURES = "cloud/binary/features"   # same topic name, now carries JSON
CLOUD_JSON_ALERTS = "cloud/binary/alerts"     # same topic name, now carries JSON

TOPIC_EDGE_HEALTH = "telemetry/edge/health"
TOPIC_EXT_HEALTH = "telemetry/extractor/health"
TOPIC_EDGE_LOG = "telemetry/edge/log"
TOPIC_EXT_LOG = "telemetry/extractor/log"

# --- FlowExtractor MQTT Topics (subscribe on local broker) ---
TOPIC_EXT_LOG_MQTT = "FlowExtractor/log"
TOPIC_EXT_STAT_MQTT = "FlowExtractor/SystemStat"

# --- File Paths ---
FILE_EDGE_HEALTH = "/opt/EdgeHealth/health_storage/edge_ml_health.json"
FILE_EXT_HEALTH = "/opt/EdgeHealth/health_storage/feature_health.json"
FILE_EDGE_LOG = "/opt/EdgeML/logs/edge_ml.log"
FILE_EXT_LOG = "/opt/FeatureLogReceiver/feature_extractor_received.log"

FEATURE_ORDER = list(CLOUD_FEATURE_INDICES.keys())


def tail_log_file(filepath, topic, cloud_client):
    """Monitors a log file and sends ONLY newly appended lines."""
    print(f"Starting log monitor for: {filepath}")
    while not os.path.exists(filepath):
        time.sleep(5)

    with open(filepath, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            cloud_client.publish(topic, line.strip(), qos=1)


def monitor_health_files(cloud_client):
    """Reads and sends the complete JSON health files every 30 seconds."""
    print("Starting health JSON monitor...")
    while True:
        if os.path.exists(FILE_EDGE_HEALTH):
            try:
                with open(FILE_EDGE_HEALTH, 'r') as f:
                    cloud_client.publish(TOPIC_EDGE_HEALTH, f.read(), qos=0)
            except Exception as e:
                print(f"Could not read Edge health: {e}")

        if os.path.exists(FILE_EXT_HEALTH):
            try:
                with open(FILE_EXT_HEALTH, 'r') as f:
                    cloud_client.publish(TOPIC_EXT_HEALTH, f.read(), qos=0)
            except Exception as e:
                print(f"Could not read Extractor health: {e}")

        time.sleep(30)


# --- Create the two clients ---
local_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="LocalAdapter")
cloud_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="CloudBridgeUplink")

# --- Cloud Connection Callbacks ---


def on_cloud_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"SECURELY connected to Cloud Broker ({CLOUD_BROKER_IP})")
    else:
        print(f"Cloud connection failed with code {rc}")


cloud_client.on_connect = on_cloud_connect

# Configure TLS/SSL for the Cloud Client
# try:
#    cloud_client.tls_set(ca_certs=CA_CERTS, tls_version=ssl.PROTOCOL_TLSv1_2)
#    cloud_client.username_pw_set("your_username", "your_password")
# except Exception as e:
#    print(f"Failed to configure TLS: {e}. Check your CA_CERTS path.")

# --- Local Connection Callbacks ---


def on_local_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print(f"Connected to Local Broker ({LOCAL_BROKER_IP})")
        client.subscribe(LOCAL_JSON_TOPIC)
        client.subscribe(TOPIC_EXT_LOG_MQTT)
        client.subscribe(TOPIC_EXT_STAT_MQTT)
    else:
        print(f"Local connection failed with code {rc}")


def on_local_message(client, userdata, msg):
    try:
        if msg.topic == TOPIC_EXT_LOG_MQTT:
            cloud_client.publish(TOPIC_EXT_LOG, msg.payload.decode(), qos=1)
            return

        if msg.topic == TOPIC_EXT_STAT_MQTT:
            cloud_client.publish(TOPIC_EXT_HEALTH, msg.payload.decode(), qos=0)
            return

        payload = json.loads(msg.payload.decode())
        meta = payload.get('metadata', {})
        indexed_features = meta.get('features', {})
        detection = payload.get('detection', {})

        src_ip = payload.get('src_ip', '0.0.0.0')
        dst_ip = payload.get('dst_ip', '0.0.0.0')

        # --- Task 1: JSON Features ---
        feature_values = {}
        for feature_name in FEATURE_ORDER:
            val = float(indexed_features.get(feature_name, 0.0))
            # index = CLOUD_FEATURE_INDICES[feature_name]
            # val = float(indexed_features.get(str(index), indexed_features.get(index, 0.0)))
            feature_values[feature_name] = val

        json_features = {
            'features': feature_values,
            'feature_id': meta.get('feature_id', 'unknown'),
            'flow_id': meta.get('flow_id', 'unknown'),
            'device_id': meta.get('device_id', 'unknown'),
            'device_mac': meta.get('device_mac', 'unknown'),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'timestamp': meta.get('timestamp'),
            'edge_timestamp': payload.get('edge_timestamp')
        }
        cloud_client.publish(CLOUD_JSON_FEATURES, json.dumps(json_features), qos=1)

        # --- Task 2: JSON Alerts ---
        is_threat = detection.get('is_threat', False)
        threats_list = detection.get('threats_detected', [])
        inference_time = float(detection.get('total_inference_time_ms', 0.0))
        max_conf = max(t.get('confidence', 0.0) for t in threats_list) if threats_list else 0.0

        json_alerts = {
            'is_threat': is_threat,
            'threat_count': len(threats_list),
            'max_confidence': max_conf,
            'inference_time_ms': inference_time,
            'threats': threats_list,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'feature_id': meta.get('feature_id', 'unknown'),
            'flow_id': meta.get('flow_id', 'unknown'),
            'device_id': meta.get('device_id', 'unknown'),
            'device_mac': meta.get('device_mac', 'unknown'),
            'timestamp': meta.get('timestamp'),
            'edge_timestamp': payload.get('edge_timestamp')
        }
        cloud_client.publish(CLOUD_JSON_ALERTS, json.dumps(json_alerts), qos=1)

    except Exception as e:
        print(f"Error processing message: {e}")


local_client.on_connect = on_local_connect
local_client.on_message = on_local_message

if __name__ == "__main__":
    print("Starting Cloud Adapter Service...")

    # Start the Cloud connection loop in the background
    cloud_client.connect(CLOUD_BROKER_IP, CLOUD_BROKER_PORT, 60)
    cloud_client.loop_start()
    time.sleep(3)

    # Start File Monitoring Threads
    threading.Thread(target=tail_log_file, args=(FILE_EDGE_LOG, TOPIC_EDGE_LOG, cloud_client), daemon=True).start()
    threading.Thread(target=tail_log_file, args=(FILE_EXT_LOG, TOPIC_EXT_LOG, cloud_client), daemon=True).start()
    threading.Thread(target=monitor_health_files, args=(cloud_client,), daemon=True).start()

    # Connect and run the Local loop in the main thread
    local_client.connect(LOCAL_BROKER_IP, LOCAL_BROKER_PORT, 60)
    local_client.loop_forever()
