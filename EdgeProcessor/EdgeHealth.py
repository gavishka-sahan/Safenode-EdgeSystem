#!/usr/bin/env python3

import json
import time
import psutil
from datetime import datetime, timezone
from pathlib import Path
import paho.mqtt.client as mqtt
from ping3 import ping

# Configuration
BROKER = "localhost"
STORE_PATH = Path("./health_storage")
MODELS_DIR = Path("./models")

# State
received_count = 0
last_message_time = None


def check_models() -> dict:
    models = {
        "mirai": "mirai_model.onnx",
        "dos": "dos_model.onnx",
        "spoof": "spoof_model.onnx",
        "replay": "replay_model.json"
    }
    return {name: (MODELS_DIR / f).exists() for name, f in models.items()}


def check_cloud() -> dict:
    try:
        latency = ping("8.8.8.8", timeout=2)
        return {"reachable": latency is not None, "latency_ms": latency * 1000 if latency else None}
    except BaseException:
        return {"reachable": False, "latency_ms": None}


def on_message(client, userdata, msg):
    global received_count, last_message_time
    received_count += 1
    last_message_time = datetime.now(timezone.utc).isoformat()

    STORE_PATH.mkdir(exist_ok=True)
    (STORE_PATH / "feature_health.json").write_text(msg.payload.decode())
    print(f"[{datetime.now():%H:%M:%S}] Health from Feature Extractor (#{received_count})")


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print(" Connected to MQTT broker")
        # Subscribe to FlowExtractor health so on_message fires and updates feature_health.json
        client.subscribe("FlowExtractor/SystemStat", qos=0)
    else:
        print(f" Connection failed (rc={reason_code})")


def generate_health(client):
    net = psutil.net_io_counters()

    health = {
        "module": "edge_ml",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mqtt": {"connected": client.is_connected(), "messages_received": received_count},
        "cloud": check_cloud(),
        "models": check_models(),
        "bandwidth_bytes": net.bytes_sent + net.bytes_recv
    }

    STORE_PATH.mkdir(exist_ok=True)
    (STORE_PATH / "edge_ml_health.json").write_text(json.dumps(health, indent=2))


def main():
    print("=" * 60)
    print("EDGE ML HEALTH MONITOR")
    print("=" * 60)

    # Create directories
    STORE_PATH.mkdir(exist_ok=True)
    MODELS_DIR.mkdir(exist_ok=True)

    # MQTT setup
    try:
        client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    except BaseException:
        client = mqtt.Client()

    client.on_message = on_message
    client.on_connect = on_connect

    try:
        client.connect(BROKER, 1883, 60)
        client.loop_start()
    except Exception as e:
        print(f" MQTT connection failed: {e}")
        return

    print(" Health monitor running")
    # print("Press Ctrl+C to stop\n")

    try:
        while True:
            generate_health(client)
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n Stopped. Messages received: {received_count}")
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
