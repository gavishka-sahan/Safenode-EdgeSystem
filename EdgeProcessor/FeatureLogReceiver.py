#!/usr/bin/env python3

import json
import time
import signal
from datetime import datetime
import paho.mqtt.client as mqtt
from EdgeLog import setup_feature_log_receiver_logger, get_log_directory_size

# Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "metadata/log"
LOG_FILE = "feature_extractor_received.log"

# State
running = True
logs_received = 0
logs_saved = 0


def signal_handler(sig, frame):
    global running
    running = False


class FeatureLogReceiver:
    def __init__(self):
        self.logger = setup_feature_log_receiver_logger(LOG_FILE)
        self.client = self._create_client()
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.connected = False
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _create_client(self):
        try:
            return mqtt.Client(client_id="edge_feature_log", callback_api_version=mqtt.CallbackAPIVersion.VERSION1)
        except:
            return mqtt.Client(client_id="edge_feature_log")
    
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
            print(f"Connected to {MQTT_BROKER}:{MQTT_PORT}")
            client.subscribe(MQTT_TOPIC)
            print(f"Subscribed to {MQTT_TOPIC}")
        else:
            print(f"Connection failed (rc={rc})")
    
    def on_message(self, client, userdata, msg):
        global logs_received, logs_saved
        try:
            logs_received += 1
            data = json.loads(msg.payload.decode())
            
            # Format log entry
            ts = data.get('timestamp', 'UNKNOWN')
            level = data.get('level', 'INFO')
            module = data.get('module', '')
            message = data.get('message', '')
            
            self.logger.info(f"{ts} | {level} | {module} | {message}")
            logs_saved += 1
            
            # Print errors/warnings
            if level == 'ERROR':
                print(f" {message}")
            elif level == 'WARNING':
                print(f" {message}")
                
        except Exception as e:
            print(f" Error: {e}")
    
    def run(self):
        print("=" * 60)
        print("FEATURE LOG RECEIVER")
        print(f"Broker: {MQTT_BROKER}:{MQTT_PORT}")
        print(f"Topic: {MQTT_TOPIC}")
        print(f"Log: {LOG_FILE}")
        print("=" * 60)
        
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
            self.client.loop_start()
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return
        
        # Wait for connection
        for _ in range(100):
            if self.connected:
                break
            time.sleep(0.1)
        
        if not self.connected:
            print(" Connection timeout")
            return
        
        print("\n Receiving logs... Press Ctrl+C to stop\n")
        
        while running:
            time.sleep(1)
        
        # Shutdown
        print(f"\n Stopped. Received: {logs_received}, Saved: {logs_saved}")
        print(f" Log size: {get_log_directory_size(LOG_FILE) / 1024 / 1024:.2f} MB")
        self.client.loop_stop()
        self.client.disconnect()


if __name__ == "__main__":
    FeatureLogReceiver().run()

