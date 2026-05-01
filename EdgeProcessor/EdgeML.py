#!/usr/bin/env python3

import sys
import json
import time
import uuid
import ipaddress
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
    TOPIC_CLOUD_OUT = "cloud/metadata"

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

    # Early-export filtering.
    # FlowExtractor publishes each flow multiple times (first, new_packets,
    # completed). The very first export often fires on only 2-5 packets, which
    # is statistically unreliable: IAT std, avg packet size, and flag ratios
    # haven't stabilized. Training was done on mature flow statistics, so these
    # early exports are a significant FP source. We skip inference on "first"
    # exports that have fewer than MIN_PACKETS_FOR_FIRST_EXPORT packets and
    # let the next export (with more packets) be the one that's scored.
    # Completed and new_packets exports are always scored regardless of count.
    MIN_PACKETS_FOR_FIRST_EXPORT = 10

    # Statistical-stability gate. Any flow with fewer than this many packets
    # has unstable feature statistics regardless of export reason: IAT std,
    # packet size variance, and flag ratios are not meaningful. Such flows
    # are skipped for inference (still forwarded to cloud as normal traffic).
    MIN_PACKETS_FOR_INFERENCE = 5

    # Logging
    LOG_LEVEL = logging.INFO
    LOG_FILE = Path("/home/nomad/edge_ml.log")

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


def is_out_of_scope_target(dst_ip: str) -> bool:
    """
    Return True if dst_ip is an out-of-scope target for ML inference.

    The four detection models (mirai, dos, replay, spoof) are trained on
    direct host-to-host attack flows from CICIoT2023. Broadcast, multicast,
    loopback, and unspecified addresses fall outside this designed scope.
    Asking the models about flows with these destinations produces unreliable
    extrapolations (high-confidence false positives in practice).

    Flows with these destinations are filtered at the inference boundary;
    they are still captured, exported, and forwarded to the cloud as normal
    traffic for visibility.
    """
    if not dst_ip:
        return False
    try:
        addr = ipaddress.ip_address(dst_ip)
    except (ValueError, TypeError):
        return False

    # 224.0.0.0/4 (multicast), 127.0.0.0/8 (loopback), 0.0.0.0
    if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        return True

    # Limited broadcast (255.255.255.255) and subnet-directed broadcast (x.x.x.255).
    # is_unspecified handles 0.0.0.0; .255 handles directed broadcasts the
    # ipaddress module does not classify as broadcast on its own.
    if dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
        return True

    return False


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
        # Missing-feature tracking for visibility into FP causes
        self.missing_feature_events: Dict[str, int] = defaultdict(int)

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
        """
        Build the feature vector for a given model.

        Previously this silently substituted 0.0 for any missing feature. That
        hid real feature-extraction bugs and, because models (e.g. mirai) can
        predict high-confidence attack on all-zero input, turned one missing
        feature into a false positive at runtime.

        Now: missing features are still substituted with 0.0 to keep inference
        running (better than a crash in a detection loop), but every occurrence
        is logged as a warning and counted, so they are visible and actionable.
        """
        indices = self.feature_indices[model_name]
        selected = []
        missing = []

        for i in indices:
            # Accept either int or str keys, matching the JSON-over-MQTT path
            val = all_features.get(i)
            if val is None:
                val = all_features.get(str(i))
            if val is None:
                missing.append(i)
                val = 0.0
            selected.append(val)

        if missing:
            self.missing_feature_events[model_name] += 1
            # Log once per occurrence with the specific indices so a pattern
            # (always the same feature missing) is easy to spot in logs.
            missing_names = [f"{i}({get_feature_name(i)})" for i in missing]
            logger.warning(
                f"{model_name}: {len(missing)} feature(s) missing, substituted 0.0 "
                f"(possible FP risk). Missing: {missing_names}"
            )

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
                # Multi-class (>2) output — previously used raw argmax and
                # ignored get_model_threshold(), which meant any attack class
                # winning the argmax became a threat even at low confidence
                # (e.g. P(benign)=0.45, P(greip)=0.28 still flagged as threat).
                #
                # Fix: gate on benign probability. Flag as threat only if
                # P(benign) < (1 - threshold). With mirai threshold=0.3, this
                # means "only flag if P(benign) < 0.7" — benign-leaning but
                # ambiguous predictions now stay benign.
                probs = output[0]
                benign_prob = float(probs[0])
                threshold = self.get_model_threshold(model_name)
                benign_cutoff = 1.0 - threshold

                is_threat = benign_prob < benign_cutoff
                if is_threat:
                    # Pick the most likely attack class among classes 1..N
                    attack_idx = int(np.argmax(probs[1:])) + 1
                    predicted_class = attack_idx
                    confidence = float(probs[attack_idx])
                else:
                    predicted_class = 0
                    confidence = benign_prob

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

        # Statistics. flows_inferenced distinguishes flows actually scored
        # by the models from raw MQTT messages received — needed because the
        # inference-boundary filters may skip some flows. Real FP rate is
        # threats_detected / flows_inferenced, not / messages_received.
        #
        # Skip reasons are tracked separately so the paper's methodology
        # section can quantify each filter's contribution:
        #   flows_skipped_early_export  : first export with too few packets
        #   flows_skipped_low_packet    : any export with < MIN_PACKETS_FOR_INFERENCE
        #   flows_skipped_invalid_target: broadcast/multicast/loopback/unspecified dst
        self.stats = {
            'messages_received': 0,
            'flows_inferenced': 0,
            'flows_skipped_early_export': 0,
            'flows_skipped_low_packet': 0,
            'flows_skipped_invalid_target': 0,
            'threats_detected': 0,
            'isolations_triggered': 0
        }

    def _on_connect(self, client, userdata, connect_flags, reason_code, properties):
        if reason_code == 0:
            logger.info("Connected to MQTT broker")
            client.subscribe(Config.TOPIC_METADATA_IN)
            logger.info(f"Subscribed to {Config.TOPIC_METADATA_IN}")
            self.connected = True
        else:
            logger.error(f"MQTT connection failed with code {reason_code}")

    def _on_message(self, client, userdata, msg):
        try:
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

        # ----------------------------------------------------------------
        # Inference-boundary filters.
        #
        # Each filter routes the flow around ML inference but lets it through
        # to cloud forwarding as normal traffic (is_threat=False, no event).
        # The filters are evaluated in order; the first match wins so each
        # skip is attributed to a single, specific reason in the stats.
        #
        #   1. early-export      : first export of an immature flow
        #   2. low-packet        : any flow below the statistical-stability floor
        #   3. invalid-target    : destination outside the models' designed scope
        # ----------------------------------------------------------------
        export_reason = flow_data.get('export_reason', 'unknown')
        # feature 27 == packet_count (total fwd+bwd)
        packet_count = indexed_features.get(27, indexed_features.get('27', 0)) or 0
        dst_ip = flow_data.get('dst_ip', '') or ''

        skip_inference = False
        skip_reason_text = None
        skip_stat_key = None

        if (export_reason == 'first'
                and packet_count < Config.MIN_PACKETS_FOR_FIRST_EXPORT):
            skip_inference = True
            skip_stat_key = 'flows_skipped_early_export'
            skip_reason_text = (
                f"first export with {packet_count} packets "
                f"(< {Config.MIN_PACKETS_FOR_FIRST_EXPORT})"
            )
        elif packet_count < Config.MIN_PACKETS_FOR_INFERENCE:
            # Any export — first, new_packets, completed, age_cap — with too
            # few packets to have stable feature statistics.
            skip_inference = True
            skip_stat_key = 'flows_skipped_low_packet'
            skip_reason_text = (
                f"flow has {packet_count} packets "
                f"(< {Config.MIN_PACKETS_FOR_INFERENCE} for stable features)"
            )
        elif is_out_of_scope_target(dst_ip):
            # Broadcast / multicast / loopback / unspecified destinations are
            # not in any model's training scope. Flow is treated as normal
            # traffic for cloud visibility.
            skip_inference = True
            skip_stat_key = 'flows_skipped_invalid_target'
            skip_reason_text = (
                f"destination {dst_ip} is broadcast/multicast/loopback "
                f"(out of model scope)"
            )

        # Get device identifier for severity tracking.
        # FlowExtractor does not currently send MAC addresses — fall back to
        # src_ip. This groups all flows from one host under one key, which is
        # acceptable now that severity dedups by (flow_id, model_name) and
        # thresholds have been relaxed. Revisit when FlowExtractor is updated
        # to emit MACs (see outstanding bugs list).
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

        # Run ML detection unless an inference-boundary filter skipped this flow.
        # Skipped flows produce a benign result with system_status='operational'
        # so the dashboard treats them as normal traffic. The skip reason is
        # preserved in inference_skipped_reason for forensic visibility, but is
        # not used by any threat-handling logic.
        if skip_inference:
            self.stats[skip_stat_key] += 1
            result = {
                'feature_id': metadata['feature_id'],
                'event_id': None,
                'device_id': metadata['device_id'],
                'timestamp': metadata['timestamp'],
                'is_threat': False,
                'threats_detected': [],
                'model_results': {},
                'total_inference_time_ms': 0.0,
                'system_status': 'operational',
                'inference_skipped_reason': skip_reason_text
            }
        else:
            self.stats['flows_inferenced'] += 1
            result = self.detector.detect_threats(metadata)

        # If threat detected, use severity manager
        if result['is_threat']:
            self.stats['threats_detected'] += 1
            self._emit_threat_trace(flow_data, metadata, result, indexed_features)
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

    def _emit_threat_trace(self, flow_data: dict, metadata: dict,
                           result: dict, indexed_features: dict):
        """
        Emit a single-line JSON trace of every threat detection, with enough
        context to reconstruct what happened during FP forensics.
        Grep-friendly prefix 'THREAT_TRACE' makes it easy to extract from logs.
        """
        try:
            trace = {
                'ts': time.time(),
                'flow_id': flow_data.get('flow_id'),
                'export_reason': flow_data.get('export_reason'),
                'src_ip': flow_data.get('src_ip'),
                'dst_ip': flow_data.get('dst_ip'),
                'src_port': flow_data.get('src_port'),
                'dst_port': flow_data.get('dst_port'),
                'protocol': flow_data.get('protocol'),
                # feature 27 = packet_count, 0 = flow_duration, 1 = rate
                'packet_count': indexed_features.get(27, indexed_features.get('27', 0)),
                'flow_duration': indexed_features.get(0, indexed_features.get('0', 0)),
                'rate': indexed_features.get(1, indexed_features.get('1', 0)),
                'models_fired': [t['model'] for t in result.get('threats_detected', [])],
                'confidences': {
                    t['model']: round(t['confidence'], 4)
                    for t in result.get('threats_detected', [])
                },
                'attack_types': {
                    t['model']: t['attack_type']
                    for t in result.get('threats_detected', [])
                },
            }
            logger.info(f"THREAT_TRACE | {json.dumps(trace)}")
        except Exception as e:
            # Never let trace logging break detection flow
            logger.debug(f"THREAT_TRACE emit failed: {e}")

    def _handle_threat_with_severity(self, result: Dict, metadata: Dict, client):
        device_mac = metadata.get('device_mac', 'unknown')
        flow_id = metadata.get('flow_id', '')

        for threat in result.get('threats_detected', []):
            model_name = threat['model']
            confidence = threat['confidence']
            attack_type = threat['attack_type']

            # Record detection in severity manager. flow_id is passed so the
            # manager can dedup repeated exports of the same flow by the same
            # model. Different models firing on the same flow count separately.
            decision = self.severity_manager.record_detection(
                device_mac=device_mac,
                threat_type=model_name,
                confidence=confidence,
                model_name=model_name,
                flow_id=flow_id,
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
                self.stats['isolations_triggered'] += 1

        elif decision.action == ActionType.ALERT_ONLY:
            # MEDIUM: Alert only, no isolation
            logger.info(
                f"MEDIUM | {device_mac} | "
                f"{decision.detection_count} detections | "
                "ALERT ONLY (no isolation)"
            )

        elif decision.action == ActionType.LOG_ONLY:
            # LOW: Just log
            logger.debug(
                f"LOW | {device_mac} | "
                "1 detection | Logged (need more to escalate)"
            )

    def _trigger_isolation(self, device_mac: str, result: Dict, decision):
        """Trigger device isolation"""
        logger.info(f"Isolation triggered for {device_mac} | severity={decision.severity.value} | reason={decision.reason}")

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
            'severity_stats': self.severity_manager.get_stats(),
            'missing_feature_events': dict(self.detector.models.missing_feature_events),
        }


def main():
    """Main entry point"""

    logger.info("=" * 80)
    logger.info("EDGE ML MODULE - SEVERITY-BASED THREAT DETECTION v4.2")
    logger.info("=" * 80)
    logger.info(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Python: {sys.version}")
    logger.info(f"ONNX Runtime: {ort.__version__}")
    logger.info(f"Edge features: {TOTAL_FEATURES}")
    logger.info(f"Cloud features: {TOTAL_CLOUD_FEATURES}")
    logger.info(f"Min packets for first export inference: {Config.MIN_PACKETS_FOR_FIRST_EXPORT}")
    logger.info(f"Min packets for any inference:         {Config.MIN_PACKETS_FOR_INFERENCE}")
    logger.info("Out-of-scope dst filter: broadcast / multicast / loopback / unspecified")
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
    logger.info(f"Cloud topic:  {Config.TOPIC_CLOUD_OUT}")
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
        logger.info(f"  Messages received:               {handler_stats['messages_received']}")
        logger.info(f"  Flows inferenced:                {handler_stats['flows_inferenced']}")
        logger.info(f"  Flows skipped (early export):    {handler_stats['flows_skipped_early_export']}")
        logger.info(f"  Flows skipped (low packet):      {handler_stats['flows_skipped_low_packet']}")
        logger.info(f"  Flows skipped (invalid target):  {handler_stats['flows_skipped_invalid_target']}")
        logger.info(f"  Threats detected:                {handler_stats['threats_detected']}")
        logger.info(f"  Isolations triggered:            {handler_stats['isolations_triggered']}")

        # Derived FP-diagnostic ratio: only meaningful against flows actually scored
        if handler_stats['flows_inferenced']:
            threat_rate = (
                handler_stats['threats_detected'] / handler_stats['flows_inferenced'] * 100
            )
            logger.info(f"  Threat rate (of inferenced):     {threat_rate:.2f}%")

        logger.info("\nML Detection Stats:")
        logger.info(f"  Total flows processed: {detector_stats['total_detections']}")
        if detector_stats['threats_by_model']:
            logger.info("  Threats by model:")
            for model, count in sorted(detector_stats['threats_by_model'].items()):
                logger.info(f"    {model:12s}: {count} threats")

        # Missing-feature visibility — non-zero values indicate a FlowExtractor
        # feature-population bug that could be inflating FP counts.
        mfe = handler_stats.get('missing_feature_events') or {}
        if mfe:
            logger.info("\nMissing-feature events (per model):")
            for model, count in sorted(mfe.items()):
                logger.info(f"  {model:12s}: {count} inference(s) with missing features")

        logger.info("\nSeverity Stats:")
        severity_stats = handler_stats['severity_stats']
        logger.info(f"  Total detections recorded: {severity_stats['total_detections']}")
        logger.info(f"  Deduped detections:        {severity_stats.get('deduped_detections', 0)}")
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
