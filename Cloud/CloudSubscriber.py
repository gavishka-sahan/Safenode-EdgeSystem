import json
import os
import paho.mqtt.client as mqtt
from datetime import datetime

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

TOPIC_FEATURES = "cloud/binary/features"
TOPIC_ALERTS = "cloud/binary/alerts"
TOPIC_METADATA = "cloud/metadata"


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
        # QoS 1: features and alerts feed the batch DB loader; loss = missing detection record
        client.subscribe(TOPIC_FEATURES, qos=1)
        client.subscribe(TOPIC_ALERTS, qos=1)
        # QoS 0: raw metadata passthrough, file-only
        client.subscribe(TOPIC_METADATA, qos=0)
        print("Subscribed to all topics")
    else:
        print("Connection failed with code", reason_code)


# ==========================================================
# MQTT MESSAGE HANDLER
# Files only — batch loaders handle DB inserts and cleanup
# ==========================================================

def on_message(client, userdata, msg):
    print("Incoming topic:", msg.topic)
    try:
        topic = msg.topic
        payload = msg.payload
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

        # --------------------------------------------------
        # HEALTH (edge + extractor)
        # --------------------------------------------------
        if topic == TOPIC_EDGE_HEALTH or topic == TOPIC_EXT_HEALTH:
            source = "edge" if topic == TOPIC_EDGE_HEALTH else "extractor"
            filepath = os.path.join(HEALTH_DIR, f"{timestamp}_{source}_health.json")
            with open(filepath, "w") as f:
                f.write(payload.decode())
            print(f"Saved {source} health to {filepath}")

        # --------------------------------------------------
        # LOG LINES (appended to single rolling log file)
        # log_to_db.py truncates this file after successful ingest
        # --------------------------------------------------
        elif topic == TOPIC_EDGE_LOG or topic == TOPIC_EXT_LOG:
            log_message = payload.decode()
            log_file = os.path.join(LOGS_DIR, "system_logs.log")
            # Tag each line with its source topic so the batch loader can set log_source
            with open(log_file, "a") as f:
                f.write(f"{topic}\t{log_message}\n")

        # --------------------------------------------------
        # JSON FEATURES (per-flow, paired with alert by flow_id)
        # --------------------------------------------------
        elif topic == TOPIC_FEATURES:
            data = json.loads(payload.decode())
            flow_id = data.get('flow_id', 'unknown')
            filepath = os.path.join(JSON_DIR, f"{timestamp}_features.json")
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Saved features | flow={flow_id} src={data.get('src_ip', '?')}")

        # --------------------------------------------------
        # JSON ALERTS (per-flow detection result)
        # --------------------------------------------------
        elif topic == TOPIC_ALERTS:
            data = json.loads(payload.decode())
            flow_id = data.get('flow_id', 'unknown')
            filepath = os.path.join(DETECTION_RESULTS_DIR, f"{timestamp}_detection.json")
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            print(f"Saved detection | flow={flow_id} threat={data.get('is_threat', False)}")

        # --------------------------------------------------
        # RAW METADATA PASSTHROUGH (file-only, no DB target)
        # --------------------------------------------------
        elif topic == TOPIC_METADATA:
            filepath = os.path.join(JSON_DIR, f"{timestamp}_metadata.json")
            with open(filepath, "w") as f:
                f.write(payload.decode())
            print("Stored raw metadata")

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
