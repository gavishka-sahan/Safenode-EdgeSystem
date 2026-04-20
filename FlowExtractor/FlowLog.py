#!/usr/bin/env python3

import re
import json
import time
import argparse
import uuid
from datetime import datetime
from typing import Dict, Optional, List
import paho.mqtt.client as mqtt


def create_mqtt_client(client_id: str):
    try:
        return mqtt.Client(
            client_id=client_id,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2
        )
    except (TypeError, AttributeError):
        return mqtt.Client(client_id=client_id)


class Config:
    # LOG_FILE = "/opt/FlowExtractor/feature_extractor.log"
    LOG_FILE = "/home/nomad/Safenode-EdgeSystem/FlowExtractor/feature_extractor.log"
    # MQTT_BROKER = "192.168.8.135"
    MQTT_BROKER = "192.168.1.11"
    MQTT_PORT = 1883
    MQTT_TOPIC = "FlowExtractor/log"
    MQTT_CLIENT_ID = f"log_parser_{uuid.uuid4().hex[:8]}"
    MQTT_QOS = 0

    # Processing configuration
    CHECK_INTERVAL = 1.0  # Check for new logs every second
    BATCH_SIZE = 50       # Send logs in batches


class LogPatterns:

    # Base log pattern: 2026-02-11 10:30:00 | INFO | __main__ | function:123 | message
    BASE = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)?) \| '
        r'(?P<level>\w+)\s+\| '
        r'(?P<function>\w+):(?P<line>\d+) \| '
        r'(?P<message>.*)'
    )

    # Specific message patterns
    FLOW_CREATED = re.compile(
        r'New flow: '
        r'(?P<src_ip>[\d.]+):(?P<src_port>\d+) <-> '
        r'(?P<dst_ip>[\d.]+):(?P<dst_port>\d+) '
        r'proto=(?P<protocol>\d+) \(total=(?P<total_flows>\d+)\)'
    )

    BATCH_EXPORTED = re.compile(
        r'Exported (?P<flow_count>\d+) flows '
        r'\(Packets: (?P<packets>\d+), Flows: (?P<flows>\d+), '
        r'MQTT: (?P<mqtt_published>\d+) published, '
        r'(?P<success_rate>[\d.]+)% success\)'
    )

    FLOW_CLEANUP = re.compile(
        r'Cleaned up (?P<expired>\d+) expired flows'
    )

    PACKET_COUNT = re.compile(
        r'Processed (?P<count>\d+) packets, active flows: (?P<active>\d+)'
    )

    MAX_CAPACITY = re.compile(
        r'Maximum flow capacity reached \((?P<max>\d+)\)'
    )

    MQTT_CONNECTION = re.compile(
        r'MQTT (?P<status>connection|disconnection) (?P<result>\w+)'
    )

    MQTT_PUBLISH = re.compile(
        r'(?P<action>Published|Failed to publish) (?P<count>\d+)? ?(?P<what>.*?) to (?P<topic>\S+)'
    )

    SYSTEM_STARTUP = re.compile(
        r'(?P<component>IoT Security Feature Extractor|FlowManager) (?P<action>initialized|starting)'
    )


class LogParser:

    STATE_FILE = str(__import__('pathlib').Path(__file__).parent / "flowlog.state")

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.file_position = self._load_position()
        self.log_count = 0

    def _load_position(self) -> int:
        try:
            with open(self.STATE_FILE, 'r') as f:
                return int(f.read().strip())
        except (FileNotFoundError, ValueError):
            return 0

    def _save_position(self):
        try:
            with open(self.STATE_FILE, 'w') as f:
                f.write(str(self.file_position))
        except Exception as e:
            print(f"Warning: could not save file position: {e}")

    def parse_log_entry(self, line: str) -> Optional[Dict]:
        # Parse base log structure
        match = LogPatterns.BASE.match(line)
        if not match:
            return None

        base_data = match.groupdict()

        # Create base structure
        log_entry = {
            "log_id": self.log_count,
            "timestamp": self._convert_timestamp(base_data['timestamp']),
            "level": base_data['level'].strip(),
            "function": base_data['function'],
            "line": int(base_data['line']),
            "message": base_data['message'],
            "event_type": "unknown",
            "context": {}
        }

        # Parse specific message types and extract context
        message = base_data['message']

        # Flow created
        match = LogPatterns.FLOW_CREATED.search(message)
        if match:
            log_entry['event_type'] = 'flow_created'
            log_entry['context'] = {
                'src_ip': match.group('src_ip'),
                'src_port': int(match.group('src_port')),
                'dst_ip': match.group('dst_ip'),
                'dst_port': int(match.group('dst_port')),
                'protocol': int(match.group('protocol')),
                'total_flows': int(match.group('total_flows'))
            }
            return log_entry

        # Batch exported
        match = LogPatterns.BATCH_EXPORTED.search(message)
        if match:
            log_entry['event_type'] = 'batch_exported'
            log_entry['context'] = {
                'flow_count': int(match.group('flow_count')),
                'total_packets': int(match.group('packets')),
                'total_flows': int(match.group('flows')),
                'mqtt_published': int(match.group('mqtt_published')),
                'success_rate': float(match.group('success_rate'))
            }
            return log_entry

        # Flow cleanup
        match = LogPatterns.FLOW_CLEANUP.search(message)
        if match:
            log_entry['event_type'] = 'flow_cleanup'
            log_entry['context'] = {
                'expired_flows': int(match.group('expired'))
            }
            return log_entry

        # Packet count
        match = LogPatterns.PACKET_COUNT.search(message)
        if match:
            log_entry['event_type'] = 'packet_count'
            log_entry['context'] = {
                'packets_processed': int(match.group('count')),
                'active_flows': int(match.group('active'))
            }
            return log_entry

        # Max capacity
        match = LogPatterns.MAX_CAPACITY.search(message)
        if match:
            log_entry['event_type'] = 'max_capacity_reached'
            log_entry['context'] = {
                'max_flows': int(match.group('max'))
            }
            return log_entry

        # MQTT connection
        match = LogPatterns.MQTT_CONNECTION.search(message)
        if match:
            log_entry['event_type'] = f"mqtt_{match.group('status')}"
            log_entry['context'] = {
                'result': match.group('result')
            }
            return log_entry

        # MQTT publish
        match = LogPatterns.MQTT_PUBLISH.search(message)
        if match:
            log_entry['event_type'] = 'mqtt_publish'
            log_entry['context'] = {
                'success': match.group('action') == 'Published',
                'topic': match.group('topic'),
                'count': int(match.group('count')) if match.group('count') else 1
            }
            return log_entry

        # System startup
        match = LogPatterns.SYSTEM_STARTUP.search(message)
        if match:
            log_entry['event_type'] = 'system_startup'
            log_entry['context'] = {
                'component': match.group('component'),
                'action': match.group('action')
            }
            return log_entry

        # Generic error detection
        if 'error' in message.lower() or 'exception' in message.lower():
            log_entry['event_type'] = 'error'
            log_entry['context'] = {'error_message': message}
            return log_entry

        # Generic warning detection
        if log_entry['level'] == 'WARNING':
            log_entry['event_type'] = 'warning'

        # Generic info
        if log_entry['level'] == 'INFO':
            log_entry['event_type'] = 'info'

        # Generic debug
        if log_entry['level'] == 'DEBUG':
            log_entry['event_type'] = 'debug'

        return log_entry

    def read_new_logs(self) -> List[Dict]:
        new_entries = []

        try:
            with open(self.log_file, 'r') as f:
                # Seek to last position
                f.seek(self.file_position)

                # Read new lines
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Parse log entry
                    entry = self.parse_log_entry(line)
                    if entry:
                        new_entries.append(entry)
                        self.log_count += 1

                # Update position
                self.file_position = f.tell()
                self._save_position()

        except FileNotFoundError:
            # Log file doesn't exist yet
            pass
        except Exception as e:
            print(f"Error reading log file: {e}")

        return new_entries

    @staticmethod
    def _convert_timestamp(timestamp_str: str) -> str:
        # Convert log timestamp to ISO format
        try:
            # Strip the milliseconds off before converting
            clean_time = timestamp_str.split(',')[0]
            dt = datetime.strptime(clean_time, '%Y-%m-%d %H:%M:%S')
            return dt.isoformat() + 'Z'
        except BaseException:
            return timestamp_str


class MQTTLogPublisher:

    def __init__(self, broker: str, port: int, topic: str):
        self.broker = broker
        self.port = port
        self.topic = topic
        self.is_connected = False

        # Create MQTT client (compatible with v1.x and v2.x)
        self.client = create_mqtt_client(Config.MQTT_CLIENT_ID)
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect

        # Statistics
        self.published_count = 0
        self.failed_count = 0

    def on_connect(self, client, userdata, flags, reason_code, properties):
        # MQTT connection callback
        if reason_code == 0:
            self.is_connected = True
            print(f"     Connected to MQTT broker {self.broker}:{self.port}")
        else:
            self.is_connected = False
            print(f"     MQTT connection failed (rc={reason_code})")

    def on_disconnect(self, client, userdata, flags, reason_code, properties):
        # MQTT disconnection callback
        self.is_connected = False
        if reason_code != 0:
            print(f"Unexpected MQTT disconnection (rc={reason_code})")

    def connect(self) -> bool:
        # Connect to MQTT broker
        try:
            self.client.connect(self.broker, self.port, 60)
            self.client.loop_start()
            time.sleep(1)
            return self.is_connected
        except Exception as e:
            print(f"     Failed to connect to MQTT: {e}")
            return False

    def publish_log(self, log_entry: Dict) -> bool:
        if not self.is_connected:
            self.failed_count += 1
            return False

        try:
            payload = json.dumps(log_entry)
            result = self.client.publish(
                self.topic,
                payload,
                qos=Config.MQTT_QOS
            )

            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.published_count += 1
                return True
            else:
                self.failed_count += 1
                return False

        except Exception as e:
            print(f"Error publishing log: {e}")
            self.failed_count += 1
            return False

    def publish_batch(self, log_entries: List[Dict]) -> int:

        if not self.is_connected or not log_entries:
            return 0

        success_count = 0
        for entry in log_entries:
            if self.publish_log(entry):
                success_count += 1

        return success_count

    def disconnect(self):
        # Disconnect from MQTT broker
        if self.client:
            self.client.loop_stop()
            self.client.disconnect()

    def get_statistics(self) -> Dict:
        # Get publishing statistics
        total = self.published_count + self.failed_count
        success_rate = (self.published_count / total * 100) if total > 0 else 0

        return {
            'published': self.published_count,
            'failed': self.failed_count,
            'success_rate': round(success_rate, 2)
        }


class LogParserApp:
    def __init__(self, log_file: str, broker: str, port: int, topic: str):
        self.parser = LogParser(log_file)
        self.publisher = MQTTLogPublisher(broker, port, topic)
        self.start_time = time.time()

        print("=" * 80)
        print("FEATURE EXTRACTOR LOG PARSER")
        print("=" * 80)
        print(f"Log file: {log_file}")
        print(f"MQTT broker: {broker}:{port}")
        print(f"MQTT topic: {topic}")
        print(f"Check interval: {Config.CHECK_INTERVAL}s")
        print(f"Batch size: {Config.BATCH_SIZE}")
        print("=" * 80)

    def run(self):
        # Connect to MQTT
        print("Connecting to MQTT broker...")
        if not self.publisher.connect():
            print("     Failed to connect to MQTT, exiting")
            return

        print("Starting log processing...")
        print("Press Ctrl+C to stop")
        print("=" * 80 + "\n")

        last_report = time.time()
        last_publish = time.time()
        pending_entries = []

        try:
            while True:
                # Read new log entries into buffer
                new_entries = self.parser.read_new_logs()
                if new_entries:
                    pending_entries.extend(new_entries)

                # Publish buffered entries every 10 seconds
                if time.time() - last_publish >= 10:
                    if pending_entries:
                        success_count = self.publisher.publish_batch(pending_entries)
                        print(f"Published {success_count}/{len(pending_entries)} log entries "
                              f"to {Config.MQTT_TOPIC}")
                        pending_entries = []
                    last_publish = time.time()

                # Periodic statistics report (every 60 seconds)
                if time.time() - last_report >= 60:
                    self.print_statistics()
                    last_report = time.time()

                # Sleep
                time.sleep(Config.CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n\nStopping log parser...")
            self.shutdown()

        except Exception as e:
            print(f"\n✗ Fatal error: {e}")
            self.shutdown()
            raise

    def print_statistics(self):
        """Print current statistics"""
        stats = self.publisher.get_statistics()
        uptime = time.time() - self.start_time

        print("\n" + "-" * 80)
        print("STATISTICS")
        print("-" * 80)
        print(f"Uptime: {uptime / 3600:.2f} hours")
        print(f"Logs parsed: {self.parser.log_count}")
        print(f"MQTT published: {stats['published']}")
        print(f"MQTT failed: {stats['failed']}")
        print(f"Success rate: {stats['success_rate']}%")
        print("-" * 80 + "\n")

    def shutdown(self):
        """Graceful shutdown"""
        print("\n" + "=" * 80)
        print("FINAL STATISTICS")
        print("=" * 80)

        stats = self.publisher.get_statistics()
        uptime = time.time() - self.start_time

        print(f"Uptime: {uptime / 3600:.2f} hours")
        print(f"Logs parsed: {self.parser.log_count}")
        print(f"MQTT published: {stats['published']}")
        print(f"MQTT failed: {stats['failed']}")
        print(f"Success rate: {stats['success_rate']}%")
        print("=" * 80)

        self.publisher.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description='Parse feature extractor logs and publish to MQTT as structured JSON'
    )
    parser.add_argument(
        '--log-file',
        default=Config.LOG_FILE,
        help=f'Path to log file (default: {Config.LOG_FILE})'
    )
    parser.add_argument(
        '--broker',
        default=Config.MQTT_BROKER,
        help=f'MQTT broker address (default: {Config.MQTT_BROKER})'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=Config.MQTT_PORT,
        help=f'MQTT broker port (default: {Config.MQTT_PORT})'
    )
    parser.add_argument(
        '--topic',
        default=Config.MQTT_TOPIC,
        help=f'MQTT topic (default: {Config.MQTT_TOPIC})'
    )
    parser.add_argument(
        '--interval',
        type=float,
        default=Config.CHECK_INTERVAL,
        help=f'Check interval in seconds (default: {Config.CHECK_INTERVAL})'
    )

    args = parser.parse_args()

    # Update config
    Config.LOG_FILE = args.log_file
    Config.MQTT_BROKER = args.broker
    Config.MQTT_PORT = args.port
    Config.MQTT_TOPIC = args.topic
    Config.CHECK_INTERVAL = args.interval

    # Create and run application
    app = LogParserApp(
        log_file=args.log_file,
        broker=args.broker,
        port=args.port,
        topic=args.topic
    )

    app.run()


if __name__ == "__main__":
    main()
