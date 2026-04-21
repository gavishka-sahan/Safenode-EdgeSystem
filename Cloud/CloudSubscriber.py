import json
import os
import paho.mqtt.client as mqtt
from datetime import datetime

# ==========================================================
# PATHS — relative to this script's location
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "cloud_data_storage")
os.makedirs(DATA_DIR, exist_ok=True)

# Per-topic append-only JSONL files
FEATURES_FILE = os.path.join(DATA_DIR, "features.jsonl")
DETECTIONS_FILE = os.path.join(DATA_DIR, "detections.jsonl")
EDGE_HEALTH_FILE = os.path.join(DATA_DIR, "edge_health.jsonl")
EXTRACTOR_HEALTH_FILE = os.path.join(DATA_DIR, "extractor_health.jsonl")
EDGE_LOG_FILE = os.path.join(DATA_DIR, "edge_log.jsonl")
EXTRACTOR_LOG_FILE = os.path.join(DATA_DIR, "extractor_log.jsonl")
METADATA_FILE = os.path.join(DATA_DIR, "metadata.jsonl")

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
# APPEND HELPER
# Opens, writes one line, closes — allows rename-based
# rotation to work safely from the batch loader.
# ==========================================================

def append_line(filepath, line):
    """Append a single line (without trailing newline) to a file."""
    with open(filepath, "a") as f:
        f.write(line + "\n")


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
# Appends one JSONL line per message; batch loaders consume
# these files via atomic rename-and-process rotation.
# ==========================================================

def on_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode()
        received_at = datetime.utcnow().isoformat()

        # --------------------------------------------------
        # FEATURES
        # --------------------------------------------------
        if topic == TOPIC_FEATURES:
            # Validate JSON before writing so malformed payloads
            # don't poison the file
            json.loads(payload)
            append_line(FEATURES_FILE, payload)

        # --------------------------------------------------
        # DETECTIONS (ALERTS)
        # --------------------------------------------------
        elif topic == TOPIC_ALERTS:
            json.loads(payload)
            append_line(DETECTIONS_FILE, payload)

        # --------------------------------------------------
        # EDGE HEALTH
        # --------------------------------------------------
        elif topic == TOPIC_EDGE_HEALTH:
            json.loads(payload)
            append_line(EDGE_HEALTH_FILE, payload)

        # --------------------------------------------------
        # EXTRACTOR HEALTH
        # --------------------------------------------------
        elif topic == TOPIC_EXT_HEALTH:
            json.loads(payload)
            append_line(EXTRACTOR_HEALTH_FILE, payload)

        # --------------------------------------------------
        # EDGE LOG (wrap plain text line into JSON for uniform parsing)
        # --------------------------------------------------
        elif topic == TOPIC_EDGE_LOG:
            wrapped = json.dumps({"received_at": received_at, "message": payload})
            append_line(EDGE_LOG_FILE, wrapped)

        # --------------------------------------------------
        # EXTRACTOR LOG
        # --------------------------------------------------
        elif topic == TOPIC_EXT_LOG:
            wrapped = json.dumps({"received_at": received_at, "message": payload})
            append_line(EXTRACTOR_LOG_FILE, wrapped)

        # --------------------------------------------------
        # RAW METADATA PASSTHROUGH (no DB target; cleared on schedule)
        # --------------------------------------------------
        elif topic == TOPIC_METADATA:
            append_line(METADATA_FILE, payload)

    except json.JSONDecodeError as e:
        print(f"Dropped malformed JSON on {msg.topic}: {e}")
    except Exception as e:
        print(f"Error processing message on {msg.topic}: {e}")


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
