#!/usr/bin/env python3

import json
import time
import psutil
from datetime import datetime
import paho.mqtt.client as mqtt

BROKER = "192.168.8.135"       
PORT = 1883
TOPIC = "health/log"
INTERFACE = "wlan0"             # Network interface to monitor
INTERVAL = 10                   # Seconds between health reports

# Processes to monitor (key services on Feature Extractor Pi)
MONITORED_PROCESSES = {
    "feature_extractor": "FlowExtractor.py",
    "health_monitor": "FlowSystemMonitor.py",
    "mqtt_broker": "mosquitto",
}

sent_count = 0
last_success_timestamp = None

def get_cpu_temperature():
    #Read CPU temperature (Raspberry Pi specific)
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            return round(int(f.read()) / 1000, 1)
    except (FileNotFoundError, ValueError):
        return None


def get_hardware_health():
    #Collect hardware metrics: CPU, memory, disk, network
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters(pernic=True)

    # Get network stats for specified interface
    if INTERFACE in net:
        net_stats = net[INTERFACE]
    else:
        fallback = list(net.keys())[0] if net else None
        if fallback:
            net_stats = net[fallback]
            print(f"Warning: Interface {INTERFACE} not found, using {fallback}")
        else:
            net_stats = psutil.net_io_counters()

    return {
        "cpu_usage_percent": psutil.cpu_percent(interval=1),
        "cpu_temperature_c": get_cpu_temperature(),
        "memory": {
            "used_mb": round(mem.used / (1024 * 1024), 1),
            "available_mb": round(mem.available / (1024 * 1024), 1),
            "percent": mem.percent
        },
        "disk_usage_percent": disk.percent,
        "network": {
            "interface": INTERFACE,
            "bytes_sent": net_stats.bytes_sent,
            "bytes_recv": net_stats.bytes_recv,
            "packets_sent": net_stats.packets_sent,
            "packets_recv": net_stats.packets_recv,
            "errin": net_stats.errin,
            "errout": net_stats.errout,
            "dropin": net_stats.dropin,
            "dropout": net_stats.dropout
        },
        "uptime_seconds": int(time.time() - psutil.boot_time())
    }


def check_process(name):
    #Check if a process is running by name or cmdline match
    for proc in psutil.process_iter(['name', 'cmdline']):
        try:
            if name in str(proc.info):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False


def get_software_health(client):
    #Check running services and MQTT connectivity
    services = {}
    for label, proc_name in MONITORED_PROCESSES.items():
        services[label] = check_process(proc_name)

    return {
        "services": services,
        "mqtt_connected": client.is_connected(),
        "last_success_timestamp": last_success_timestamp
    }


def on_publish(client, userdata, mid):
    #Track successful MQTT publishes
    global last_success_timestamp
    last_success_timestamp = datetime.utcnow().isoformat()

try:
    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
    print("[INIT] Using paho-mqtt v2.x")
except (TypeError, AttributeError):
    client = mqtt.Client()
    print("[INIT] Using paho-mqtt v1.x")

client.on_publish = on_publish

try:
    client.connect(BROKER, PORT, 60)
    client.loop_start()
    print(f"[INIT] Connected to MQTT broker at {BROKER}:{PORT}")
except Exception as e:
    print(f"[ERROR] Failed to connect to MQTT broker: {e}")
    exit(1)


print(f"[INIT] Topic: {TOPIC} | Interface: {INTERFACE} | Interval: {INTERVAL}s")
print("Press Ctrl+C to stop\n")

try:
    while True:
        sent_count += 1

        health = {
            "module": "feature_extractor",
            "timestamp": datetime.utcnow().isoformat(),
            "hardware": get_hardware_health(),
            "software": get_software_health(client),
            "sent_count": sent_count
        }

        result = client.publish(TOPIC, json.dumps(health))

        ts = datetime.now().strftime('%H:%M:%S')
        hw = health['hardware']
        if result.rc == mqtt.MQTT_ERR_SUCCESS:
            temp = f" | Temp: {hw['cpu_temperature_c']}°C" if hw['cpu_temperature_c'] else ""
            print(f"[{ts}] Sent #{sent_count} | CPU: {hw['cpu_usage_percent']:.1f}% | Mem: {hw['memory']['percent']:.1f}%{temp}")
        else:
            print(f"[{ts}] Failed to send (rc={result.rc})")

        time.sleep(INTERVAL)

except KeyboardInterrupt:
    print(f"\n[STOP] Shutting down... Total reports sent: {sent_count}")
    client.loop_stop()
    client.disconnect()
    print("[STOP] Disconnected from MQTT broker")
