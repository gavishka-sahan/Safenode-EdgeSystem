#!/usr/bin/env python3

import sys
import json
import time
import uuid
import logging
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
import onnxruntime as ort
import xgboost as xgb
import paho.mqtt.client as mqtt

from FeatureIndexMap import (
    get_feature_indices_for_model,
    get_feature_name,
    validate_indices,
    get_model_info,
    convert_named_to_indexed,
    TOTAL_FEATURES
)

# Import cloud feature selector
from DLFeatureSelector import (
    select_cloud_features,
    TOTAL_CLOUD_FEATURES,
)

# Import Severity Manager
from ThresholdSet import (
    ThreatSeverityManager,
    ActionType,
    SeverityConfig
)


class Config:
    # System configuration

    # MQTT Settings
    MQTT_BROKER = "localhost"
    MQTT_PORT = 1883
    MQTT_KEEPALIVE = 60

    # Topics
    TOPIC_METADATA_IN = "metadata/extracted"
    #TOPIC_DETECTION_OUT = "detection/alerts"
    TOPIC_CLOUD_OUT = "cloud/metadata"
    #TOPIC_ADMIN_ALERTS = "admin/alerts"  # New: for admin notifications
    #TOPIC_ADMIN_COMMANDS = "admin/commands"  # New: for admin commands

    # Model Paths
    MODEL_DIR = Path("models")
    MIRAI_MODEL = MODEL_DIR / "mirai_model.onnx"
    DOS_MODEL = MODEL_DIR / "dos_model.onnx"
    REPLAY_MODEL = MODEL_DIR / "replay_model.onnx"
    SPOOF_MODEL = MODEL_DIR / "spoof_model.onnx"

    # Detection Thresholds
    THREAT_THRESHOLD = 0.5

    # System Settings
    ISOLATION_ENABLED = True
    CLOUD_FORWARD_ENABLED = True
    BATCH_SIZE = 1

    # Logging
    LOG_LEVEL = logging.INFO
    LOG_FILE = Path("logs/edge_ml.log")

    # Performance monitoring
    LOG_INFERENCE_TIME = True
    STATS_LOG_INTERVAL = 100


def setup_logging():
    """Configure logging system"""
    Config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=Config.LOG_LEVEL,
        format='%(asctime)s | %(levelname)-8s | %(message)s',
        handlers=[
            logging.FileHandler(Config.LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


logger = setup_logging()


class MLModelManager:

    def __init__(self):
        self.models: Dict[str, any] = {}
        self.model_types: Dict[str, str] = {}
        self.model_inputs: Dict[str, str] = {}
        self.model_outputs: Dict[str, str] = {}
        self.feature_indices: Dict[str, List[int]] = {}
        self.feature_names: Dict[str, List[str]] = {}
        self.model_info: Dict[str, Dict] = {}
        self.inference_times: Dict[str, List[float]] = defaultdict(list)

    def load_models(self):
        logger.info("=" * 80)
        logger.info("LOADING ML MODELS")
        logger.info("=" * 80)

        model_configs = {
            'mirai': Config.MIRAI_MODEL,
            'dos': Config.DOS_MODEL,
            'replay': Config.REPLAY_MODEL,
            'spoof': Config.SPOOF_MODEL
        }

        for model_name, model_path in model_configs.items():
            try:
                if not model_path.exists():
                    logger.warning(f"Model not found: {model_path}")
                    logger.warning(f"  Skipping {model_name} model")
                    continue

                model_info = get_model_info(model_name)
                model_type = 'xgboost' if model_path.suffix == '.json' else 'onnx'

                if model_type == 'onnx':
                    session = ort.InferenceSession(
                        str(model_path),
                        providers=['CPUExecutionProvider']
                    )
                    input_name = session.get_inputs()[0].name
#                   output_name = session.get_outputs()[0].name
                    output_names = [o.name for o in session.get_outputs()]
                    output_name = 'probabilities' if 'probabilities' in output_names else output_names[0]
                    input_shape = session.get_inputs()[0].shape

                    self.model_inputs[model_name] = input_name
                    self.model_outputs[model_name] = output_name
                    self.models[model_name] = session

                else:
                    booster = xgb.Booster()
                    booster.load_model(str(model_path))

                    feature_names = booster.feature_names
                    if feature_names:
                        self.feature_names[model_name] = feature_names

                    input_shape = (1, len(get_feature_indices_for_model(model_name)))
                    self.models[model_name] = booster

                # Get feature indices for this model
                indices = get_feature_indices_for_model(model_name)

                if not validate_indices(indices):
                    logger.error(f"✗ {model_name}: Invalid feature indices!")
                    continue

                expected_features = len(indices)
                if input_shape[1] != expected_features:
                    logger.warning(
                        f"  {model_name}: Shape mismatch! "
                        f"Model expects {input_shape[1]}, config has {expected_features}"
                    )

                self.model_types[model_name] = model_type
                self.feature_indices[model_name] = indices
                self.model_info[model_name] = model_info

                logger.info(f"\nLoaded: {model_info.get('full_name', model_name.upper())}")
                logger.info(f"  File: {model_path.name}")
                logger.info(f"  Format: {model_type.upper()}")
                if model_type == 'onnx':
                    logger.info(f"  Input: {input_name}, Shape: {input_shape}")
                    logger.info(f"  Output: {output_name}")
                else:
                    logger.info(f"  Input Shape: {input_shape}")
                logger.info(f"  Features: {len(indices)}")

                if 'accuracy' in model_info:
                    logger.info(f"  Expected accuracy: {model_info['accuracy'] * 100:.2f}%")
                if 'inference_time_ms' in model_info:
                    logger.info(f"  Target inference time: {model_info['inference_time_ms']:.2f}ms")

                logger.info("  Key features:")
                for idx in indices[:5]:
                    logger.info(f"    [{idx}] {get_feature_name(idx)}")
                if len(indices) > 5:
                    logger.info(f"    ... and {len(indices) - 5} more")

            except Exception as e:
                logger.error(f"Failed to load {model_name}: {e}")
                import traceback
                logger.error(traceback.format_exc())

        if not self.models:
            logger.error("No models loaded! System cannot operate.")
            logger.error("Please ensure at least one model file is in the models/ directory")
            sys.exit(1)

        logger.info(f"\n{'=' * 80}")
        logger.info(f"Successfully loaded {len(self.models)} model(s)")
        logger.info(f"Active models: {', '.join(self.models.keys())}")
        logger.info("=" * 80)

    def select_features(self, all_features: Dict[int, float], model_name: str) -> np.ndarray:

        indices = self.feature_indices[model_name]
        # selected = [all_features.get(i, 0.0) for i in indices]
        selected = [all_features.get(i, all_features.get(str(i), 0.0)) for i in indices]
        return np.array([selected], dtype=np.float32)

    def get_model_threshold(self, model_name: str) -> float:
        model_thresholds = {
            'spoof': 0.92,
            'mirai': 0.3,
            'dos': 0.2,
            'replay': 0.8
        }
        return model_thresholds.get(model_name, Config.THREAT_THRESHOLD)

    def predict(self, model_name: str, features: np.ndarray) -> Tuple[bool, float, int, float]:

        try:
            model = self.models[model_name]
            model_type = self.model_types[model_name]

            start_time = time.time()

            if model_type == 'onnx':
                input_name = self.model_inputs[model_name]
                output_name = self.model_outputs[model_name]
                result = model.run([output_name], {input_name: features})
                output = result[0]
            else:
                if model_name in self.feature_names and self.feature_names[model_name]:
                    df = pd.DataFrame(features, columns=self.feature_names[model_name])
                    dmatrix = xgb.DMatrix(df)
                else:
                    dmatrix = xgb.DMatrix(features)
                output = model.predict(dmatrix)
                if len(output.shape) == 1:
                    output = output.reshape(1, -1)

            inference_time_ms = (time.time() - start_time) * 1000
            self.inference_times[model_name].append(inference_time_ms)

            # Parse output
            if isinstance(output, list) and len(output) > 0 and isinstance(output[0], dict):
                threat_prob = float(output[0].get(1, 0.0))
                threshold = self.get_model_threshold(model_name)
                is_threat = threat_prob > threshold
                confidence = threat_prob
                predicted_class = 1 if is_threat else 0
            elif output.shape == (1,):
                predicted_class = int(output[0])
                is_threat = (predicted_class != 0)
                confidence = 1.0 if is_threat else 0.0

            elif len(output.shape) == 2 and output.shape[1] == 1:
                probability = float(output[0][0])
                threshold = self.get_model_threshold(model_name)
                is_threat = probability > threshold
                confidence = probability if is_threat else (1 - probability)
                predicted_class = 1 if is_threat else 0

            elif len(output.shape) == 2 and output.shape[1] == 2:
                threat_prob = float(output[0][1])
                threshold = self.get_model_threshold(model_name)
                is_threat = threat_prob > threshold
                confidence = threat_prob
                predicted_class = 1 if is_threat else 0

            elif len(output.shape) == 2 and output.shape[1] > 2:
                predicted_class = int(np.argmax(output[0]))
                confidence = float(np.max(output[0]))
                is_threat = (predicted_class != 0)

            else:
                logger.warning(f"Unexpected output shape from {model_name}: {output.shape}")
                return False, 0.0, 0, inference_time_ms

            if Config.LOG_INFERENCE_TIME:
                logger.debug(
                    f"{model_name}: {inference_time_ms:.2f}ms | "
                    f"Class={predicted_class} | Conf={confidence:.3f}"
                )

            return is_threat, confidence, predicted_class, inference_time_ms

        except Exception as e:
            logger.error(f"Error in {model_name} inference: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False, 0.0, 0, 0.0

    def get_class_name(self, model_name: str, class_id: int) -> str:
        """Get human-readable class name"""
        model_info = self.model_info.get(model_name, {})
        classes = model_info.get('classes', {})
        return classes.get(class_id, f"class_{class_id}")

    def get_avg_inference_time(self, model_name: str) -> float:
        """Get average inference time for a model"""
        times = self.inference_times.get(model_name, [])
        return np.mean(times) if times else 0.0


class ThreatDetector:
    """Coordinates multiple ML models for threat detection"""

    def __init__(self, model_manager: MLModelManager):
        self.models = model_manager
        self.detection_stats = defaultdict(int)
        self.total_detections = 0

    def detect_threats(self, metadata: Dict) -> Dict:
        device_id = metadata.get('device_id', 'unknown')
        timestamp = metadata.get('timestamp', time.time())
        # feature_id = metadata.get('feature_id', 'unknown')
        feature_id = metadata.get('feature_id') or metadata.get('flow_id', 'unknown')
        features = metadata.get('features', {})

        # Validate feature count
        if len(features) < 1:
            logger.warning("No features received")
            return self._create_error_result(device_id, timestamp, "No features received")

        # Run each model
        results = {}
        threats_detected = []
        total_inference_time = 0.0

        for model_name in self.models.models.keys():
            model_features = self.models.select_features(features, model_name)

            is_threat, confidence, predicted_class, inference_time = self.models.predict(
                model_name, model_features
            )

            total_inference_time += inference_time
            class_name = self.models.get_class_name(model_name, predicted_class)

            results[model_name] = {
                'is_threat': is_threat,
                'confidence': confidence,
                'predicted_class': predicted_class,
                'class_name': class_name,
                'inference_time_ms': inference_time
            }

            if is_threat:
                threats_detected.append({
                    'model': model_name,
                    'attack_type': class_name,
                    'confidence': confidence
                })
                self.detection_stats[model_name] += 1

        self.total_detections += 1

        if self.total_detections % Config.STATS_LOG_INTERVAL == 0:
            self._log_statistics()

        overall_threat = len(threats_detected) > 0

        # Generate event_id only when threat is detected
        event_id = str(uuid.uuid4()) if overall_threat else None

        detection_result = {
            'feature_id': feature_id,
            'event_id': event_id,
            'device_id': device_id,
            'timestamp': timestamp,
            'is_threat': overall_threat,
            'threats_detected': threats_detected,
            'model_results': results,
            'total_inference_time_ms': total_inference_time,
            'system_status': 'operational'
        }

        if overall_threat:
            threat_summary = ', '.join([
                f"{t['model']}({t['attack_type']})" for t in threats_detected
            ])
            logger.info(
                f"L DETECTION | Event: {event_id[:8]} | Feature: {feature_id} | "
                f"Device: {device_id} | Attacks: {threat_summary} | "
                f"Time: {total_inference_time:.2f}ms"
            )
        else:
            logger.debug(
                f"✓ Benign | Device: {device_id} | Time: {total_inference_time:.2f}ms"
            )

        return detection_result

    def _log_statistics(self):
        """Log detection statistics"""
        logger.info("\n" + "=" * 80)
        logger.info(f"DETECTION STATISTICS (after {self.total_detections} detections)")
        logger.info("=" * 80)

        if self.detection_stats:
            logger.info("Threats detected by model:")
            for model, count in sorted(self.detection_stats.items()):
                avg_time = self.models.get_avg_inference_time(model)
                logger.info(f"  {model:12s}: {count:6d} threats | Avg: {avg_time:.2f}ms")
        else:
            logger.info("  No threats detected yet")

        logger.info("\nModel performance:")
        for model_name in self.models.models.keys():
            avg_time = self.models.get_avg_inference_time(model_name)
            logger.info(f"  {model_name:12s}: Avg inference {avg_time:.2f}ms")

        logger.info("=" * 80 + "\n")

    def _create_error_result(self, device_id: str, timestamp: float, error_msg: str) -> Dict:
        """Create error result for invalid input"""
        return {
            'device_id': device_id,
            'timestamp': timestamp,
            'is_threat': False,
            'severity': 'none',
            'threats_detected': [],
            'model_results': {},
            'requires_isolation': False,
            'error': error_msg,
            'system_status': 'error'
        }

    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_detections': self.total_detections,
            'threats_by_model': dict(self.detection_stats),
            'avg_inference_times': {
                model: self.models.get_avg_inference_time(model)
                for model in self.models.models.keys()
            }
        }


class MQTTHandler:

    def __init__(self, detector: ThreatDetector):
        self.detector = detector
        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id="edge_ml_processor",
            protocol=mqtt.MQTTv311
        )
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.connected = False

        # Initialize Severity Manager
        self.severity_manager = ThreatSeverityManager()

        # Statistics
        self.stats = {
            'messages_received': 0,
            'threats_detected': 0,
            'isolations_triggered': 0,
            'alerts_sent': 0
        }

    def _on_connect(self, client, userdata, connect_flags, reason_code, properties):
        if reason_code == 0:
            logger.info("Connected to MQTT broker")
            client.subscribe(Config.TOPIC_METADATA_IN)
            logger.info(f"Subscribed to {Config.TOPIC_METADATA_IN}")

            # Subscribe to admin commands
            client.subscribe(Config.TOPIC_ADMIN_COMMANDS)
            logger.info(f"Subscribed to {Config.TOPIC_ADMIN_COMMANDS}")

            self.connected = True
        else:
            logger.error(f"MQTT connection failed with code {reason_code}")

    def _on_message(self, client, userdata, msg):
        try:
            # Route messages based on topic
            if msg.topic == Config.TOPIC_ADMIN_COMMANDS:
                self._handle_admin_command(msg)
                return

            payload = json.loads(msg.payload.decode())

            if isinstance(payload, list):
                for flow_data in payload:
                    self._process_single_flow(flow_data, client)
            else:
                self._process_single_flow(payload, client)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON message: {e}")
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _process_single_flow(self, flow_data: dict, client):
        """Process a single flow's metadata with severity-based isolation"""

        self.stats['messages_received'] += 1

        # Parse features from the message
        if 'features' in flow_data and isinstance(flow_data['features'], dict):
            features_raw = flow_data['features']
            sample_keys = list(features_raw.keys())[:5]

            if sample_keys and all(isinstance(k, str) and k.isdigit() for k in sample_keys):
                indexed_features = {int(k): v for k, v in features_raw.items()}
            elif sample_keys and all(isinstance(k, int) for k in sample_keys):
                indexed_features = features_raw
            else:
                indexed_features = convert_named_to_indexed(features_raw)
        else:
            indexed_features = convert_named_to_indexed(flow_data)

        # Get device identifier for severity tracking.
        # FlowExtractor does not send MAC addresses — use src_ip as the
        # per-device key instead. This ensures the severity manager tracks
        # each source IP independently rather than lumping all flows into
        # the 'unknown' bucket.
        device_mac = (
            flow_data.get('src_mac')                          # real MAC if ever added
            or flow_data.get('device_info', {}).get('src_mac')
            or flow_data.get('src_ip')                        # primary fallback
            or flow_data.get('device_id')
            or 'unknown'
        )

        metadata = {
            'features': indexed_features,
            # 'feature_id': flow_data.get('feature_id', 'unknown'),
            'feature_id': flow_data.get('feature_id') or flow_data.get('flow_id', 'unknown'),
            'device_id': flow_data.get('device_id', flow_data.get('src_ip', 'unknown')),
            'device_mac': device_mac,
            'flow_id': flow_data.get('flow_id', 'unknown'),
            'timestamp': flow_data.get('timestamp', time.time())
        }

        # Run ML detection
        result = self.detector.detect_threats(metadata)

        # If threat detected, use severity manager
        if result['is_threat']:
            self.stats['threats_detected'] += 1
            self._handle_threat_with_severity(result, metadata, client)

        # Forward to cloud (all flows, not just threats)
        if Config.CLOUD_FORWARD_ENABLED:
            # Extract only the 27 cloud features from 61 edge features
            cloud_features = select_cloud_features(indexed_features)

            cloud_message = {
                'metadata': {
                    'features': cloud_features,  # Only 27 features
                    'feature_id': flow_data.get('feature_id', 'unknown'),
                    'device_id': flow_data.get('device_id', flow_data.get('src_ip', 'unknown')),
                    'device_mac': device_mac,
                    'flow_id': flow_data.get('flow_id', 'unknown'),
                    'timestamp': flow_data.get('timestamp', time.time())
                },
                'detection': result,
                'src_ip': flow_data.get('src_ip', '0.0.0.0'),
                'dst_ip': flow_data.get('dst_ip', '0.0.0.0'),
                'edge_timestamp': time.time()
            }
            client.publish(
                Config.TOPIC_CLOUD_OUT,
                json.dumps(cloud_message),
                qos=0
            )

    def _handle_threat_with_severity(self, result: Dict, metadata: Dict, client):
        device_mac = metadata.get('device_mac', 'unknown')

        for threat in result.get('threats_detected', []):
            model_name = threat['model']
            confidence = threat['confidence']
            attack_type = threat['attack_type']

            # Record detection in severity manager
            decision = self.severity_manager.record_detection(
                device_mac=device_mac,
                threat_type=model_name,
                confidence=confidence,
                model_name=model_name,
                features_summary={
                    'attack_type': attack_type,
                    'device_id': metadata.get('device_id'),
                    'feature_id': metadata.get('feature_id')
                }
            )

            # Take action based on severity decision
            self._execute_severity_decision(decision, result, metadata, client)

    def _execute_severity_decision(self, decision, result: Dict, metadata: Dict, client):
        """Execute action based on severity decision"""

        device_mac = metadata.get('device_mac', 'unknown')

        if decision.action == ActionType.ISOLATE:
            # CRITICAL: Auto-isolate immediately
            if not self.severity_manager.is_already_isolated(device_mac):
                logger.warning(
                    f"CRITICAL | {device_mac} | "
                    f"{decision.detection_count} detections in {decision.window_seconds}s | "
                    "AUTO-ISOLATING"
                )

                self._trigger_isolation(device_mac, result, decision)
                self.severity_manager.mark_as_isolated(device_mac)
                self.stats['isolations_triggered'] += 1

        elif decision.action == ActionType.ISOLATE_AND_ALERT:
            # HIGH: Auto-isolate + alert admin
            if not self.severity_manager.is_already_isolated(device_mac):
                logger.warning(
                    f"HIGH | {device_mac} | "
                    f"{decision.detection_count} detections | "
                    "ISOLATING + ALERT"
                )

                self._trigger_isolation(device_mac, result, decision)
                self.severity_manager.mark_as_isolated(device_mac)
                self._send_admin_alert(decision, result, client)
                self.stats['isolations_triggered'] += 1
                self.stats['alerts_sent'] += 1

        elif decision.action == ActionType.ALERT_ONLY:
            # MEDIUM: Alert only, no isolation
            logger.info(
                f"MEDIUM | {device_mac} | "
                f"{decision.detection_count} detections | "
                "ALERT ONLY (no isolation)"
            )
            self._send_admin_alert(decision, result, client)
            self.stats['alerts_sent'] += 1

        elif decision.action == ActionType.LOG_ONLY:
            # LOW: Just log
            logger.debug(
                f"LOW | {device_mac} | "
                "1 detection | Logged (need more to escalate)"
            )

    def _trigger_isolation(self, device_mac: str, result: Dict, decision):
        """Trigger device isolation"""

        # Prepare isolation command
        isolation_command = {
            'action': 'isolate',
            'device_mac': device_mac,
            'device_id': result.get('device_id', 'unknown'),
            'event_id': result.get('event_id'),
            'severity': decision.severity.value,
            'detection_count': decision.detection_count,
            'threat_types': decision.threat_types,
            'confidence': decision.average_confidence,
            'timestamp': time.time(),
            'reason': decision.reason
        }

        # Publish to isolation topic
        self.client.publish(
            Config.TOPIC_DETECTION_OUT,
            json.dumps(isolation_command),
            qos=1
        )

        logger.info(f"Isolation command sent for {device_mac}")

    def _send_admin_alert(self, decision, result: Dict, client):
        """Send alert to admin dashboard"""

        alert = {
            'type': 'THREAT_ALERT',
            'timestamp': time.time(),
            'device_mac': decision.device_mac,
            'device_id': result.get('device_id', 'unknown'),
            'severity': decision.severity.value,
            'action_taken': decision.action.value,
            'detection_count': decision.detection_count,
            'threat_types': decision.threat_types,
            'average_confidence': decision.average_confidence,
            'reason': decision.reason,
            'is_critical_device': decision.is_critical_device,
            'requires_review': decision.action in [ActionType.ISOLATE_AND_ALERT, ActionType.ALERT_ONLY]
        }

        client.publish(
            Config.TOPIC_ADMIN_ALERTS,
            json.dumps(alert),
            qos=1
        )

        logger.info(f"Admin alert sent for {decision.device_mac}")

    def _handle_admin_command(self, msg):
        """Handle commands from admin dashboard"""
        try:
            command = json.loads(msg.payload.decode())
            action = command.get('action')
            device_mac = command.get('device_mac')

            logger.info(f"Admin command: {action} for {device_mac}")

            if action == 'restore':
                # Admin restores device
                self.severity_manager.mark_as_restored(device_mac)
                logger.info(f"Device {device_mac} restored by admin")

            elif action == 'false_positive':
                # Admin marks as false positive
                self.severity_manager.mark_as_false_positive(device_mac)
                logger.info(f"Device {device_mac} marked as false positive")

            elif action == 'manual_isolate':
                # Admin manually isolates
                self.severity_manager.mark_as_isolated(device_mac)
                logger.info(f"Device {device_mac} manually isolated by admin")

            else:
                logger.warning(f"Unknown admin command: {action}")

        except Exception as e:
            logger.error(f"Error handling admin command: {e}")

    def connect(self):
        """Connect to MQTT broker"""
        try:
            logger.info(f"Connecting to MQTT broker at {Config.MQTT_BROKER}:{Config.MQTT_PORT}")
            self.client.connect(Config.MQTT_BROKER, Config.MQTT_PORT, Config.MQTT_KEEPALIVE)
        except Exception as e:
            logger.error(f"Failed to connect to MQTT broker: {e}")
            logger.error("  Make sure Mosquitto MQTT broker is running:")
            logger.error("  sudo systemctl start mosquitto")
            sys.exit(1)

    def start(self):
        """Start MQTT loop"""
        self.client.loop_forever()

    def get_stats(self) -> Dict:
        """Get handler statistics"""
        return {
            **self.stats,
            'severity_stats': self.severity_manager.get_stats()
        }


def main():
    """Main entry point"""

    logger.info("=" * 80)
    logger.info("EDGE ML MODULE - SEVERITY-BASED THREAT DETECTION v4.0")
    logger.info("=" * 80)
    logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Python: {sys.version}")
    logger.info(f"ONNX Runtime: {ort.__version__}")
    logger.info(f"Edge features: {TOTAL_FEATURES}")
    logger.info(f"Cloud features: {TOTAL_CLOUD_FEATURES}")
    logger.info("")

    Config.MODEL_DIR.mkdir(parents=True, exist_ok=True)

    model_manager = MLModelManager()
    model_manager.load_models()

    detector = ThreatDetector(model_manager)

    mqtt_handler = MQTTHandler(detector)
    mqtt_handler.connect()

    logger.info("")
    logger.info("=" * 80)
    logger.info("SEVERITY-BASED ISOLATION THRESHOLDS")
    logger.info("=" * 80)
    logger.info(f"  Time Window: {SeverityConfig.WINDOW_SECONDS} seconds")
    logger.info(f"  CRITICAL: ≥{SeverityConfig.CRITICAL_THRESHOLD} detections → Auto-Isolate")
    logger.info(f"  HIGH:     ≥{SeverityConfig.HIGH_THRESHOLD} detections → Isolate + Alert")
    logger.info(f"  MEDIUM:   ≥{SeverityConfig.MEDIUM_THRESHOLD} detections → Alert Only")
    logger.info("  LOW:      1 detection → Log Only")
    logger.info("")
    logger.info("=" * 80)
    logger.info("✓ EDGE ML SYSTEM READY")
    logger.info("=" * 80)
    logger.info(f"Listening on: {Config.TOPIC_METADATA_IN}")
    logger.info(f"Alert topic:  {Config.TOPIC_DETECTION_OUT}")
    logger.info(f"Cloud topic:  {Config.TOPIC_CLOUD_OUT}")
    logger.info(f"Admin alerts: {Config.TOPIC_ADMIN_ALERTS}")
    logger.info(f"Admin commands: {Config.TOPIC_ADMIN_COMMANDS}")
    logger.info("")
    logger.info("Active Models:")
    for model_name in model_manager.models.keys():
        info = model_manager.model_info[model_name]
        logger.info(f"  • {info.get('full_name', model_name.upper())}")
    logger.info("")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 80)
    logger.info("")

    try:
        mqtt_handler.start()
    except KeyboardInterrupt:
        logger.info("\n\nShutdown requested by user")

        # Get all statistics
        handler_stats = mqtt_handler.get_stats()
        detector_stats = detector.get_stats()

        logger.info("\n" + "=" * 80)
        logger.info("FINAL STATISTICS")
        logger.info("=" * 80)

        logger.info("\nMessage Processing:")
        logger.info(f"  Messages received: {handler_stats['messages_received']}")
        logger.info(f"  Threats detected: {handler_stats['threats_detected']}")
        logger.info(f"  Isolations triggered: {handler_stats['isolations_triggered']}")
        logger.info(f"  Alerts sent: {handler_stats['alerts_sent']}")

        logger.info("\nML Detection Stats:")
        logger.info(f"  Total flows processed: {detector_stats['total_detections']}")
        if detector_stats['threats_by_model']:
            logger.info("  Threats by model:")
            for model, count in sorted(detector_stats['threats_by_model'].items()):
                logger.info(f"    {model:12s}: {count} threats")

        logger.info("\nSeverity Stats:")
        severity_stats = handler_stats['severity_stats']
        logger.info(f"  Total detections recorded: {severity_stats['total_detections']}")
        logger.info(f"  CRITICAL events: {severity_stats['critical_count']}")
        logger.info(f"  HIGH events: {severity_stats['high_count']}")
        logger.info(f"  MEDIUM events: {severity_stats['medium_count']}")
        logger.info(f"  LOW events: {severity_stats['low_count']}")
        logger.info(f"  False positives marked: {severity_stats['false_positive_overrides']}")

        logger.info("\nAverage inference times:")
        for model, avg_time in detector_stats['avg_inference_times'].items():
            logger.info(f"  {model:12s}: {avg_time:.2f}ms")

        logger.info("\n" + "=" * 80)
        logger.info("Edge ML system stopped cleanly")
        logger.info("=" * 80)


if __name__ == "__main__":
    main()
