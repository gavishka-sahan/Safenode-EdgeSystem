#!/usr/bin/env python3

import sys
import os
import time
import json
import logging
import logging.handlers
import numpy as np
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, GRE, Raw
import paho.mqtt.client as mqtt


class Config:
    INTERFACE = "wlan0"

    # Flow Management
    FLOW_TIMEOUT = 120
    FLOW_EXPORT_INTERVAL = 10
    MAX_FLOWS = 10000
    CLEANUP_INTERVAL = 30
    FLOW_MAX_AGE = 30

    # MQTT
    MQTT_ENABLED = True
    MQTT_BROKER = "192.168.8.135"
    # MQTT_BROKER = "192.168.1.11"
    MQTT_PORT = 1883
    MQTT_TOPIC_EDGE = "metadata/extracted"
    MQTT_QOS = 1
    MQTT_CLIENT_ID = "feature_extractor_pi4"
    MQTT_KEEPALIVE = 60
    MQTT_USERNAME = None
    MQTT_PASSWORD = None

    # Feature Extraction
    ENABLE_MQTT_PARSING = True
    ENABLE_PROTOCOL_DETECTION = True
    CALCULATION_PRECISION = 6

    # frame_time_delta_bin threshold (seconds)
    FRAME_TIME_DELTA_BIN_THRESHOLD = 0.1

    # Log shipping to EdgeProcessor
    MQTT_TOPIC_LOG = "FlowExtractor/log"
    LOG_SHIP_INTERVAL = 10          # seconds between log publishes
    LOG_SHIP_QOS = 0                # fire-and-forget for log lines


# Protocol & Port Constants
PROTOCOL_TCP, PROTOCOL_UDP, PROTOCOL_ICMP, PROTOCOL_GRE = 6, 17, 1, 47
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

APP_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 23: "Telnet",
    25: "SMTP", 22: "SSH", 194: "IRC", 6667: "IRC",
    67: "DHCP", 68: "DHCP", 1883: "MQTT", 8883: "MQTT"
}

# logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

_console_fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(_console_fmt)

logger.addHandler(_ch)

_LOG_PATH = "/home/nomad/flowextractor.log"
os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)

_fh = logging.handlers.RotatingFileHandler(
    _LOG_PATH,
    maxBytes=5 * 1024 * 1024,   # 5 MB per file
    backupCount=5               # keep .log + 5 rotated = 30 MB max
)
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(_console_fmt)

logger.addHandler(_fh)


class LogShipper:
    """
    Reads only NEW lines from the log file every LOG_SHIP_INTERVAL seconds
    and publishes them to FlowExtractor/log on the local MQTT broker (QoS 0).
    Tracks the file byte offset so already-sent lines are never re-sent,
    even across log rotations (detects rotation by inode change).
    """

    def __init__(self, mqtt_client_ref):
        self._mqtt = mqtt_client_ref   # reference to MQTTPublisher set after it's created
        self._offset = 0
        self._inode = None
        self._thread = None
        self._stop = False

    def set_mqtt(self, mqtt_publisher):
        """Called once the MQTTPublisher instance is ready."""
        self._mqtt = mqtt_publisher

    def _read_new_lines(self):
        """Return list of new log lines since last read, handling rotation."""
        try:
            stat = os.stat(_LOG_PATH)
            current_inode = stat.st_ino

            # Detect log rotation (RotatingFileHandler renamed the file)
            if self._inode is not None and current_inode != self._inode:
                self._offset = 0

            self._inode = current_inode

            with open(_LOG_PATH, 'r') as f:
                f.seek(self._offset)
                lines = f.readlines()
                self._offset = f.tell()

            return [line.rstrip('\n') for line in lines if line.strip()]
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.debug(f"LogShipper read error: {e}")
            return []

    def _ship(self):
        """Background loop: every LOG_SHIP_INTERVAL, read new lines and publish."""
        while not self._stop:
            time.sleep(Config.LOG_SHIP_INTERVAL)
            if self._stop:
                break

            lines = self._read_new_lines()
            if not lines or not self._mqtt or not self._mqtt.is_connected:
                continue

            payload = json.dumps({
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'source': 'FlowExtractor',
                'lines': lines
            })

            try:
                self._mqtt.client.publish(
                    Config.MQTT_TOPIC_LOG,
                    payload,
                    qos=Config.LOG_SHIP_QOS   # QoS 0 — fire and forget
                )
            except Exception as e:
                logger.debug(f"LogShipper publish error: {e}")

    def start(self):
        self._stop = False
        # Initialise offset to current end-of-file so we only ship future lines
        try:
            self._offset = os.path.getsize(_LOG_PATH)
            self._inode = os.stat(_LOG_PATH).st_ino
        except FileNotFoundError:
            self._offset = 0
            self._inode = None

        self._thread = __import__('threading').Thread(
            target=self._ship, name="LogShipper", daemon=True
        )
        self._thread.start()
        logger.info(f"LogShipper started — publishing to {Config.MQTT_TOPIC_LOG} every {Config.LOG_SHIP_INTERVAL}s (QoS {Config.LOG_SHIP_QOS})")

    def stop(self):
        self._stop = True


# MQTT
class MQTTParser:
    """Parse MQTT protocol features from TCP payload bytes."""

    @staticmethod
    def parse(payload):
        result = {'msgtype': 0, 'qos': 0, 'dupflag': 0, 'retain': 0, 'len': 0, 'topic_len': 0}
        if not payload or len(payload) < 2:
            return result
        try:
            first = payload[0]
            result['msgtype'] = (first >> 4) & 0x0F
            result['dupflag'] = (first >> 3) & 0x01
            result['qos'] = (first >> 1) & 0x03
            result['retain'] = first & 0x01

            remaining, multiplier, pos = 0, 1, 1
            while pos < len(payload):
                b = payload[pos]
                remaining += (b & 0x7F) * multiplier
                multiplier *= 128
                pos += 1
                if (b & 0x80) == 0:
                    break
            result['len'] = remaining

            if result['msgtype'] == 3 and pos + 2 <= len(payload):
                result['topic_len'] = (payload[pos] << 8) | payload[pos + 1]
        except Exception as e:
            logger.debug(f"MQTT parse error: {e}")
        return result


class Flow:

    def __init__(self, flow_key):
        self.flow_key = flow_key
        self.start_time = time.time()
        self.last_seen = self.start_time

        # Initiator for fwd/bwd separation
        self.initiator_ip = ""
        self.initiator_port = 0

        # Timestamps
        self.packet_times = []
        self.fwd_packet_times = []
        self.bwd_packet_times = []

        # Directional counters
        self.fwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_pkts = 0
        self.bwd_bytes = 0

        # Packet lengths per direction
        self.fwd_lengths = []
        self.bwd_lengths = []

        # TCP flags
        self.syn = 0
        self.ack = 0
        self.rst = 0
        self.urg = 0
        self.psh = 0
        self.fin = 0
        self.ece = 0
        self.cwr = 0

        # Protocol flags
        self.is_tcp = False
        self.is_udp = False
        self.is_icmp = False
        self.is_arp = False
        self.is_ipv4 = False
        self.is_llc = False
        self.is_http = False
        self.is_https = False
        self.is_dns = False
        self.is_telnet = False
        self.is_smtp = False
        self.is_ssh = False
        self.is_irc = False
        self.is_dhcp = False
        self.protocol_type = 0

        # Frame / TCP detail lists
        self.frame_lengths = []
        self.frame_cap_lengths = []
        self.frame_time_deltas = []
        self.tcp_lengths = []
        self.tcp_time_deltas = []
        self.tcp_window_sizes = []
        self.tcp_flags_values = []
        self.ttl_values = []
        self.ip_header_lengths = []
        self.init_win_bytes_fwd = None

        # MQTT accumulators
        self.mqtt_msgtype = []
        self.mqtt_qos = []
        self.mqtt_dupflag = []
        self.mqtt_retain = []
        self.mqtt_len = []
        self.mqtt_topic_len = []

        # Track last TCP packet time for tcp.time_delta
        self._last_tcp_time = None

        # Export state tracking
        self.exported_once = False
        self.packet_count_at_last_export = 0
        self.tcp_completed = False

        # New features (61-65)
        self.gre_inner_protocols = []   # inner proto numbers seen inside GRE packets
        self.ip_lengths = []            # ip.len values (IP total length field)
        self.payload_sizes = []         # TCP/UDP application payload bytes per packet

        # New features (66-70) are computed from existing accumulators — no new lists needed
    def update(self, pkt, timestamp):
        """Update flow with a new packet."""
        self.last_seen = timestamp
        self.packet_times.append(timestamp)

        if IP not in pkt:
            if pkt.haslayer('ARP'):
                self.is_arp = True
            if pkt.haslayer('LLC'):
                self.is_llc = True
            return

        ip = pkt[IP]
        pkt_len = len(pkt)
        ip_hdr_len = ip.ihl * 4

        self.is_ipv4 = True
        if not self.protocol_type:
            self.protocol_type = ip.proto
        self.ttl_values.append(ip.ttl)
        self.ip_header_lengths.append(ip_hdr_len)
        self.frame_lengths.append(pkt_len)
        self.ip_lengths.append(ip.len)

        wl = getattr(pkt, 'wirelen', None)
        self.frame_cap_lengths.append(wl if wl is not None else pkt_len)

        if len(self.packet_times) > 1:
            self.frame_time_deltas.append(timestamp - self.packet_times[-2])

        is_fwd = (ip.src == self.initiator_ip)
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
            self.fwd_lengths.append(pkt_len)
            self.fwd_packet_times.append(timestamp)
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len
            self.bwd_lengths.append(pkt_len)
            self.bwd_packet_times.append(timestamp)

        if self.init_win_bytes_fwd is None and TCP in pkt:
            self.init_win_bytes_fwd = pkt[TCP].window

        # GRE
        if ip.proto == PROTOCOL_GRE and GRE in pkt:
            gre = pkt[GRE]
            if IP in gre:
                self.gre_inner_protocols.append(gre[IP].proto)
            else:
                self.gre_inner_protocols.append(0)

        # TCP
        if TCP in pkt:
            self.is_tcp = True
            tcp = pkt[TCP]
            tcp_payload_len = len(tcp.payload) if tcp.payload else 0
            self.tcp_lengths.append(tcp_payload_len)
            self.payload_sizes.append(tcp_payload_len)
            self.tcp_window_sizes.append(tcp.window)
            f = int(tcp.flags)
            self.tcp_flags_values.append(f)

            if f & TCP_SYN:
                self.syn += 1
            if f & TCP_ACK:
                self.ack += 1
            if f & TCP_RST:
                self.rst += 1
            if f & TCP_PSH:
                self.psh += 1
            if f & TCP_URG:
                self.urg += 1
            if f & TCP_FIN:
                self.fin += 1
            if f & TCP_ECE:
                self.ece += 1
            if f & TCP_CWR:
                self.cwr += 1

            if f & (TCP_FIN | TCP_RST):
                self.tcp_completed = True

            if self._last_tcp_time is not None:
                self.tcp_time_deltas.append(timestamp - self._last_tcp_time)
            self._last_tcp_time = timestamp

            if Config.ENABLE_PROTOCOL_DETECTION:
                self._detect_app_protocol(tcp.sport, tcp.dport, pkt)

        # UDP
        elif UDP in pkt:
            self.is_udp = True
            udp = pkt[UDP]
            self.payload_sizes.append(len(udp.payload) if udp.payload else 0)
            if Config.ENABLE_PROTOCOL_DETECTION:
                for p in (udp.sport, udp.dport):
                    proto = APP_PORTS.get(p)
                    if proto == "DNS":
                        self.is_dns = True
                    elif proto == "DHCP":
                        self.is_dhcp = True

        # ICMP
        elif ICMP in pkt:
            self.is_icmp = True

        if pkt.haslayer('ARP'):
            self.is_arp = True
        if pkt.haslayer('LLC'):
            self.is_llc = True

    def _detect_app_protocol(self, sport, dport, pkt):
        """Detect application-layer protocol by port and parse MQTT if found."""
        for port in (sport, dport):
            proto = APP_PORTS.get(port)
            if not proto:
                continue
            if proto == "HTTP":
                self.is_http = True
            elif proto == "HTTPS":
                self.is_https = True
            elif proto == "DNS":
                self.is_dns = True
            elif proto == "Telnet":
                self.is_telnet = True
            elif proto == "SMTP":
                self.is_smtp = True
            elif proto == "SSH":
                self.is_ssh = True
            elif proto == "IRC":
                self.is_irc = True
            elif proto == "DHCP":
                self.is_dhcp = True
            elif proto == "MQTT":
                if Config.ENABLE_MQTT_PARSING and Raw in pkt:
                    m = MQTTParser.parse(bytes(pkt[Raw]))
                    if m['msgtype'] > 0:
                        self.mqtt_msgtype.append(m['msgtype'])
                        self.mqtt_qos.append(m['qos'])
                        self.mqtt_dupflag.append(m['dupflag'])
                        self.mqtt_retain.append(m['retain'])
                        self.mqtt_len.append(m['len'])
                        self.mqtt_topic_len.append(m['topic_len'])

    def calculate_features(self):
        duration = self.last_seen - self.start_time
        dur_s = max(duration, 0.001)
        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_bytes = self.fwd_bytes + self.bwd_bytes

        def sdiv(a, b): return a / b if b else 0.0
        def avg(lst): return float(np.mean(lst)) if lst else 0.0
        def std(lst): return float(np.std(lst)) if lst else 0.0
        def var(lst): return float(np.var(lst)) if lst else 0.0
        def mn(lst): return float(np.min(lst)) if lst else 0.0
        def mx(lst): return float(np.max(lst)) if lst else 0.0
        def sm(lst): return float(np.sum(lst)) if lst else 0.0

        iats = list(np.diff(self.packet_times)) if len(self.packet_times) > 1 else []

        frame_time_delta_bin = int(
            any(d > Config.FRAME_TIME_DELTA_BIN_THRESHOLD for d in self.frame_time_deltas)
        )

        features = {
            # Flow metrics (0-2)
            0: duration,
            1: sdiv(total_pkts, dur_s),
            2: sdiv(total_bytes, dur_s),

            # TCP flag counts (3-9)
            3: self.syn, 4: self.ack, 5: self.rst,
            6: self.urg, 7: self.psh, 8: self.fin,
            9: avg(self.tcp_flags_values),


            # Protocol binary flags
            10: int(self.is_tcp), 11: int(self.is_udp), 12: int(self.is_icmp),
            13: int(self.is_arp), 14: int(self.is_dns), 15: int(self.is_http),
            16: int(self.is_https), 17: int(self.is_telnet), 18: int(self.is_smtp),
            19: int(self.is_ssh), 20: int(self.is_irc), 21: int(self.is_dhcp),
            22: int(self.is_ipv4), 23: int(self.is_llc),

            # IP protocol number (24)
            24: self.protocol_type,

            # Packet size stats (25-26)
            25: avg(self.frame_lengths),
            26: var(self.frame_lengths),

            # Counts
            27: total_pkts, 28: total_bytes,
            29: self.fwd_pkts, 30: self.bwd_pkts,
            31: self.fwd_bytes, 32: self.bwd_bytes,

            # Directional means (33-34)
            33: sdiv(self.fwd_bytes, self.fwd_pkts),
            34: sdiv(self.bwd_bytes, self.bwd_pkts),

            # Aggregate sizes (35-38)
            35: sm(self.frame_lengths),
            36: total_bytes,
            37: avg(self.frame_lengths),
            38: std(self.frame_lengths),

            # IAT (39-43)
            39: avg(iats), 40: std(iats), 41: mn(iats), 42: mx(iats), 43: sm(iats),

            # Frame / TCP time deltas (44-45)
            44: avg(self.frame_time_deltas),
            45: avg(self.tcp_time_deltas),

            # Frame / TCP metrics (46-49)
            46: avg(self.tcp_lengths),
            47: avg(self.frame_lengths),
            48: avg(self.frame_cap_lengths),
            49: avg(self.tcp_window_sizes),


            # MQTT
            50: avg(self.mqtt_msgtype), 51: avg(self.mqtt_qos),
            52: avg(self.mqtt_dupflag), 53: avg(self.mqtt_retain),
            54: avg(self.mqtt_len), 55: avg(self.mqtt_topic_len),

            # IP metadata (56-58)
            56: avg(self.ttl_values),
            57: avg(self.ip_header_lengths),
            58: self.init_win_bytes_fwd if self.init_win_bytes_fwd is not None else 0,

            # IPs (59-60)
            59: self.flow_key[0],
            60: self.flow_key[1],

            # New features round 1 (61-65)
            61: avg(self.gre_inner_protocols),        # gre_inner_protocol
            62: sdiv(self.fwd_pkts, self.bwd_pkts),   # fwd_bwd_ratio
            63: frame_time_delta_bin,                 # frame_time_delta_bin
            64: avg(self.ip_lengths),                 # ip_len
            65: avg(self.payload_sizes),              # payload_size

            # New features round 2 (66-70) — DoS model
            66: mx(self.frame_lengths),               # Max (max frame size)
            67: mn(self.frame_lengths),               # Min (min frame size)
            68: sdiv(self.psh, total_pkts),           # psh_flag_number (ratio)
            69: sdiv(self.syn, total_pkts),           # syn_flag_number (ratio)
            70: sdiv(self.ack, total_pkts),           # ack_flag_number (ratio)
        }

        # Round floats
        for k in features:
            if isinstance(features[k], float):
                features[k] = round(features[k], Config.CALCULATION_PRECISION)

        return features


class MQTTPublisher:
    """Handles MQTT publishing to Edge ML and Cloud."""

    def __init__(self):
        self.is_connected = False
        self.publish_count = 0
        self.failed = 0
        self.client = None

        if not Config.MQTT_ENABLED:
            return

        try:
            self.client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=Config.MQTT_CLIENT_ID,
                clean_session=True,
                protocol=mqtt.MQTTv311
            )
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_publish = self._on_publish

            if Config.MQTT_USERNAME and Config.MQTT_PASSWORD:
                self.client.username_pw_set(Config.MQTT_USERNAME, Config.MQTT_PASSWORD)

            logger.info(f"MQTT client initialized for {Config.MQTT_BROKER}:{Config.MQTT_PORT}")
        except Exception as e:
            logger.error(f"MQTT init failed: {e}")

    def _on_connect(self, client, userdata, flags, rc, properties):
        if rc == 0:
            self.is_connected = True
            logger.info(f"Connected to MQTT broker at {Config.MQTT_BROKER}:{Config.MQTT_PORT}")
        else:
            self.is_connected = False
            logger.error(f"MQTT connect failed, code: {rc}")

    def _on_disconnect(self, client, userdata, flags, rc, properties):
        self.is_connected = False
        if rc != 0:
            logger.warning("Unexpected MQTT disconnect, will try reconnect")
        else:
            logger.info("MQTT disconnected cleanly")

    def _on_publish(self, client, userdata, mid, rc, properties):
        self.publish_count += 1

    def connect(self):
        if not Config.MQTT_ENABLED or not self.client:
            return False
        try:
            self.client.connect(Config.MQTT_BROKER, Config.MQTT_PORT, Config.MQTT_KEEPALIVE)
            self.client.loop_start()
            deadline = time.time() + 5
            while not self.is_connected and time.time() < deadline:
                time.sleep(0.1)
            if self.is_connected:
                logger.info("MQTT connection established")
            else:
                logger.error("MQTT connection timeout")
            return self.is_connected
        except Exception as e:
            logger.error(f"MQTT connect error: {e}")
            return False

    def disconnect(self):
        if self.client and self.is_connected:
            self.client.loop_stop()
            self.client.disconnect()
            logger.info("MQTT disconnected")

    def publish_flow(self, flow_data):
        if not self.is_connected:
            return
        try:
            result = self.client.publish(Config.MQTT_TOPIC_EDGE, json.dumps(flow_data), qos=Config.MQTT_QOS)
            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                self.failed += 1
                logger.warning(f"MQTT publish failed: {result.rc}")
        except Exception as e:
            self.failed += 1
            logger.error(f"MQTT publish error: {e}")

    def stats(self):
        total = self.publish_count + self.failed
        return {
            'total_published': self.publish_count,
            'failed': self.failed,
            'success_rate': (self.publish_count / max(total, 1)) * 100
        }


class FlowManager:
    """Manages active flows, periodic export, and cleanup."""

    def __init__(self):
        self.flows = {}
        self.packet_count = 0
        self.flow_count = 0
        self.last_cleanup = time.time()
        self.last_export = time.time()
        self.mqtt = MQTTPublisher()
        logger.info("FlowManager initialized")

    def _make_key(self, pkt):
        """Generate bidirectional 5-tuple flow key."""
        if IP not in pkt:
            return None
        src, dst, proto = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
        sp, dp = 0, 0
        if TCP in pkt:
            sp, dp = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sp, dp = pkt[UDP].sport, pkt[UDP].dport

        if (src, sp) < (dst, dp):
            return (src, dst, sp, dp, proto)
        return (dst, src, dp, sp, proto)

    def process_packet(self, pkt):
        """Process a single captured packet."""
        try:
            now = time.time()
            self.packet_count += 1

            if self.packet_count % 1000 == 0:
                logger.debug(f"Processed {self.packet_count} packets, active flows: {len(self.flows)}")

            key = self._make_key(pkt)
            if not key:
                return

            if key not in self.flows:
                if len(self.flows) >= Config.MAX_FLOWS:
                    logger.warning(f"Max flows ({Config.MAX_FLOWS}) reached, forcing cleanup")
                    self._cleanup(force=True)

                flow = Flow(flow_key=key)
                if IP in pkt:
                    flow.initiator_ip = pkt[IP].src
                    if TCP in pkt:
                        flow.initiator_port = pkt[TCP].sport
                    elif UDP in pkt:
                        flow.initiator_port = pkt[UDP].sport
                self.flows[key] = flow
                self.flow_count += 1
                logger.info(f"New flow: {key[0]}:{key[2]} <-> {key[1]}:{key[3]} proto={key[4]} (total={self.flow_count})")

            self.flows[key].update(pkt, now)

            if now - self.last_cleanup > Config.CLEANUP_INTERVAL:
                self._cleanup()
                self.last_cleanup = now

            if now - self.last_export >= Config.FLOW_EXPORT_INTERVAL:
                self.export_flows()
                self.last_export = now

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)

    def _cleanup(self, force=False):
        """Remove expired flows and flows that hit the hard age cap."""
        now = time.time()
        expired_keys = []
        age_capped_keys = []

        for key, flow in self.flows.items():
            inactivity = now - flow.last_seen
            age = now - flow.start_time

            if force or inactivity > Config.FLOW_TIMEOUT:
                expired_keys.append(key)
            elif age > Config.FLOW_MAX_AGE:
                age_capped_keys.append(key)

        if age_capped_keys:
            self._export_specific_flows(age_capped_keys, export_reason="age_cap", is_final=True)
            for key in age_capped_keys:
                del self.flows[key]

        for key in expired_keys:
            del self.flows[key]

        total_removed = len(expired_keys) + len(age_capped_keys)
        if total_removed:
            logger.info(f"Cleaned up {len(expired_keys)} timed-out, {len(age_capped_keys)} age-capped flows (remaining: {len(self.flows)})")

    def _export_specific_flows(self, flow_keys, export_reason="interval", is_final=False):
        if not flow_keys:
            return

        exported = 0

        try:
            for key in flow_keys:
                flow = self.flows.get(key)
                if not flow:
                    continue

                features = flow.calculate_features()
                current_pkt_count = flow.fwd_pkts + flow.bwd_pkts

                flow_data = {
                    'flow_id': f"{key[0]}:{key[2]}-{key[1]}:{key[3]}/{key[4]}",
                    'src_ip': key[0], 'dst_ip': key[1],
                    'src_port': key[2], 'dst_port': key[3],
                    'protocol': key[4],
                    'timestamp': datetime.fromtimestamp(flow.start_time).isoformat(),
                    'is_final': is_final,
                    'export_reason': export_reason,
                    'features': features
                }

                if self.mqtt.is_connected:
                    self.mqtt.publish_flow(flow_data)

                flow.exported_once = True
                flow.packet_count_at_last_export = current_pkt_count
                exported += 1

            logger.debug(f"_export_specific_flows: {exported} flows, reason={export_reason}, is_final={is_final}")

        except Exception as e:
            logger.error(f"Error in _export_specific_flows: {e}", exc_info=True)

    def export_flows(self):
        if not self.flows:
            return

        first_export_keys = []
        new_packets_keys = []
        completed_keys = []

        for key, flow in list(self.flows.items()):
            current_pkt_count = flow.fwd_pkts + flow.bwd_pkts

            if flow.tcp_completed and flow.is_tcp:
                completed_keys.append(key)
            elif not flow.exported_once:
                first_export_keys.append(key)
            elif current_pkt_count > flow.packet_count_at_last_export:
                new_packets_keys.append(key)

        self._export_specific_flows(first_export_keys, export_reason="first", is_final=False)
        self._export_specific_flows(new_packets_keys, export_reason="new_packets", is_final=False)
        self._export_specific_flows(completed_keys, export_reason="completed", is_final=True)

        for key in completed_keys:
            if key in self.flows:
                del self.flows[key]

        total_exported = len(first_export_keys) + len(new_packets_keys) + len(completed_keys)
        mq = self.mqtt.stats()
        logger.info(
            f"Exported {total_exported} flows (first={len(first_export_keys)}, new={len(new_packets_keys)}, "
            f"completed={len(completed_keys)}, skipped={max(0, len(self.flows))} unchanged) | "
            f"pkts={self.packet_count}, mqtt={mq['total_published']} ok"
        )

    def get_stats(self):
        return {
            'total_packets': self.packet_count,
            'total_flows': self.flow_count,
            'active_flows': len(self.flows),
            'uptime': time.time() - self.last_export
        }


EXCLUSIONS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "exclusions.json"
)


def build_bpf_filter():
    """
    Read exclusions.json and build a BPF filter that drops packets matching
    any of the listed IPs (as either source or destination) or ports before
    they reach the Python capture loop.

    Schema of exclusions.json:
        {
          "exclude_ips":   ["192.168.1.11", ...],
          "exclude_ports": [41641, ...]
        }

    Used in deployment to exclude infrastructure traffic (the Pis themselves,
    the gateway, management-plane VPNs like Tailscale) from analysis without
    code changes — operator edits exclusions.json and restarts the service.

    Fail-open: if the file is missing or malformed we capture everything
    rather than refuse to start. An always-on security service that stops
    capturing on a typo is worse than one that captures too much.

    Returns the BPF filter string, or None if no filter should be applied.
    """
    if not os.path.exists(EXCLUSIONS_FILE):
        logger.info(f"No exclusions file at {EXCLUSIONS_FILE} - capturing all traffic")
        return None

    try:
        with open(EXCLUSIONS_FILE) as f:
            cfg = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Could not read {EXCLUSIONS_FILE}: {e} - capturing all traffic")
        return None

    parts = []

    ips = cfg.get("exclude_ips") or []
    if ips:
        # `host X` matches packets where X is either src or dst
        host_clause = " or ".join(f"host {ip}" for ip in ips)
        parts.append(f"not ({host_clause})")

    ports = cfg.get("exclude_ports") or []
    if ports:
        port_clause = " or ".join(f"port {p}" for p in ports)
        parts.append(f"not ({port_clause})")

    if not parts:
        logger.info("Exclusions file is empty - capturing all traffic")
        return None

    bpf = " and ".join(parts)
    logger.info(f"Loaded exclusions from {EXCLUSIONS_FILE}")
    logger.info(f"  Excluded IPs:   {ips}")
    logger.info(f"  Excluded ports: {ports}")
    logger.info(f"  BPF filter:     {bpf}")
    return bpf


def main():
    logger.info("=" * 70)
    logger.info("IoT Security Feature Extractor (71 Features)")
    logger.info("=" * 70)
    logger.info(f"Interface: {Config.INTERFACE}")
    logger.info(f"Flow timeout: {Config.FLOW_TIMEOUT}s | Export interval: {Config.FLOW_EXPORT_INTERVAL}s")
    logger.info(f"MQTT: {Config.MQTT_BROKER}:{Config.MQTT_PORT} | Topic: {Config.MQTT_TOPIC_EDGE}")
    logger.info(f"Protocol detection: {Config.ENABLE_PROTOCOL_DETECTION} | MQTT parsing: {Config.ENABLE_MQTT_PARSING}")
    logger.info("=" * 70)

    fm = FlowManager()

    log_shipper = LogShipper(None)

    if Config.MQTT_ENABLED:
        logger.info("Connecting to MQTT broker...")
        if fm.mqtt.connect():
            logger.info("MQTT ready")
            log_shipper.set_mqtt(fm.mqtt)
            log_shipper.start()
        else:
            logger.warning("MQTT connection failed, continuing without MQTT")

    logger.info("Starting packet capture...")

    bpf = build_bpf_filter()
    sniff_kwargs = {
        "iface": Config.INTERFACE,
        "prn": lambda pkt: fm.process_packet(pkt),
        "store": False,
    }
    if bpf:
        sniff_kwargs["filter"] = bpf

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        logger.info("\n" + "=" * 70)
        logger.info("SHUTTING DOWN")
        logger.info("=" * 70)

        log_shipper.stop()
        fm.export_flows()

        if Config.MQTT_ENABLED:
            fm.mqtt.disconnect()

        s = fm.get_stats()
        mq = fm.mqtt.stats()
        logger.info(f"  Packets processed: {s['total_packets']}")
        logger.info(f"  Flows created:     {s['total_flows']}")
        logger.info(f"  Active at exit:    {s['active_flows']}")
        if Config.MQTT_ENABLED:
            logger.info(f"  MQTT published:    {mq['total_published']}")
            logger.info(f"  MQTT failed:       {mq['failed']}")
            logger.info(f"  MQTT success:      {mq['success_rate']:.1f}%")
        logger.info("=" * 70)
        logger.info("Feature Extractor stopped")

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        log_shipper.stop()
        if Config.MQTT_ENABLED:
            fm.mqtt.disconnect()
        raise


if __name__ == "__main__":
    if len(sys.argv) > 1:
        Config.INTERFACE = sys.argv[1]
    main()

