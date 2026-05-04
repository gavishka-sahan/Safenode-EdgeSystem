#!/usr/bin/env python3

import time
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class SeverityConfig:
    WINDOW_SECONDS = 60
    CRITICAL_THRESHOLD = 5
    HIGH_THRESHOLD = 3
    MEDIUM_THRESHOLD = 2
    MIN_CONFIDENCE = 0.70
    MODEL_THRESHOLDS = {
        'mirai': {'critical': 5, 'high': 3, 'medium': 2},
        'dos': {'critical': 5, 'high': 3, 'medium': 2},
        'replay': {'critical': 5, 'high': 3, 'medium': 2},
        'spoof': {'critical': 5, 'high': 3, 'medium': 2},
    }

    CRITICAL_DEVICES: Dict[str, str] = {}  # MAC -> Name


class SeverityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class ActionType(Enum):
    ISOLATE = "ISOLATE"
    ISOLATE_AND_ALERT = "ISOLATE_AND_ALERT"
    ALERT_ONLY = "ALERT_ONLY"
    LOG_ONLY = "LOG_ONLY"
    PASS = "PASS"


@dataclass
class Detection:
    timestamp: float
    threat_type: str
    confidence: float
    model_name: str
    flow_id: str = ""  # used for dedup: same (flow_id, model_name) updates in place


@dataclass
class SeverityDecision:
    device_mac: str
    severity: SeverityLevel
    action: ActionType
    detection_count: int
    window_seconds: int
    threat_types: List[str]
    average_confidence: float
    reason: str
    is_critical_device: bool = False

    def to_dict(self) -> Dict:
        return {
            'device_mac': self.device_mac,
            'severity': self.severity.value,
            'action': self.action.value,
            'detection_count': self.detection_count,
            'threat_types': self.threat_types,
            'average_confidence': round(self.average_confidence, 4),
            'reason': self.reason,
        }


class ThreatSeverityManager:
    """Manages threat detection accumulation and severity classification"""

    def __init__(self):
        self.config = SeverityConfig()
        self.detection_history: Dict[str, List[Detection]] = defaultdict(list)
        self.isolated_devices: Dict[str, float] = {}
        self.stats = {
            'total_detections': 0,
            'deduped_detections': 0,  # repeat detections merged into existing entry
            'critical_count': 0, 'high_count': 0,
            'medium_count': 0, 'low_count': 0, 'false_positive_overrides': 0
        }

    def record_detection(self, device_mac: str, threat_type: str,
                         confidence: float, model_name: str,
                         flow_id: str = "",
                         features_summary: dict = None) -> SeverityDecision:
        now = time.time()

        # Check confidence threshold
        if confidence < self.config.MIN_CONFIDENCE:
            return SeverityDecision(
                device_mac=device_mac, severity=SeverityLevel.NONE,
                action=ActionType.LOG_ONLY, detection_count=0,
                window_seconds=self.config.WINDOW_SECONDS,
                threat_types=[threat_type], average_confidence=confidence,
                reason=f"Confidence {confidence:.2f} < {self.config.MIN_CONFIDENCE}"
            )

        # Prune old detections first, so dedup search only considers active window
        cutoff = now - self.config.WINDOW_SECONDS
        self.detection_history[device_mac] = [
            d for d in self.detection_history[device_mac] if d.timestamp > cutoff
        ]

        # Dedup: look for an existing entry with same flow_id + model_name
        existing = self._find_existing_detection(device_mac, flow_id, model_name)
        if existing is not None:
            # Refresh in place — do NOT increment total_detections
            existing.timestamp = now
            existing.confidence = max(existing.confidence, confidence)
            self.stats['deduped_detections'] += 1
        else:
            self.detection_history[device_mac].append(
                Detection(
                    timestamp=now,
                    threat_type=threat_type,
                    confidence=confidence,
                    model_name=model_name,
                    flow_id=flow_id,
                )
            )
            self.stats['total_detections'] += 1

        recent = self.detection_history[device_mac]
        count = len(recent)
        avg_conf = sum(d.confidence for d in recent) / count
        types = list(set(d.threat_type for d in recent))
        is_critical = device_mac in self.config.CRITICAL_DEVICES

        # Classify severity
        severity, action, reason = self._classify(
            device_mac, count, model_name, avg_conf, is_critical
        )

        # Update stats
        stat_key = f"{severity.value.lower()}_count"
        if stat_key in self.stats:
            self.stats[stat_key] += 1

        return SeverityDecision(
            device_mac=device_mac, severity=severity, action=action,
            detection_count=count, window_seconds=self.config.WINDOW_SECONDS,
            threat_types=types, average_confidence=avg_conf,
            reason=reason, is_critical_device=is_critical
        )

    def _find_existing_detection(self, device_mac: str, flow_id: str,
                                 model_name: str) -> Optional[Detection]:
        if not flow_id:
            return None
        for d in self.detection_history[device_mac]:
            if d.flow_id == flow_id and d.model_name == model_name:
                return d
        return None

    def _classify(self, mac: str, count: int, model: str,
                  conf: float, is_critical: bool) -> tuple:
        """Classify severity based on detection count"""
        t = self.config.MODEL_THRESHOLDS.get(model, {
            'critical': self.config.CRITICAL_THRESHOLD,
            'high': self.config.HIGH_THRESHOLD,
            'medium': self.config.MEDIUM_THRESHOLD
        })

        # Critical devices never auto-isolate
        if is_critical:
            name = self.config.CRITICAL_DEVICES.get(mac, 'Critical Device')
            return (SeverityLevel.CRITICAL, ActionType.ALERT_ONLY,
                    f"CRITICAL DEVICE ({name}): {count} detections - MANUAL REVIEW")

        if count >= t.get('critical', 5):
            return (SeverityLevel.CRITICAL, ActionType.ISOLATE,
                    f"{count} detections - AUTO ISOLATE")
        elif count >= t.get('high', 3):
            return (SeverityLevel.HIGH, ActionType.ISOLATE_AND_ALERT,
                    f"{count} detections - ISOLATE + ALERT")
        elif count >= t.get('medium', 2):
            return (SeverityLevel.MEDIUM, ActionType.ALERT_ONLY,
                    f"{count} detections - ALERT ONLY")
        else:
            return (SeverityLevel.LOW, ActionType.LOG_ONLY,
                    "Single detection - logging only")

    def mark_as_isolated(self, mac: str):
        self.isolated_devices[mac] = time.time()

    def is_already_isolated(self, mac: str) -> bool:
        return mac in self.isolated_devices

    def mark_as_restored(self, mac: str):
        self.isolated_devices.pop(mac, None)
        self.detection_history.pop(mac, None)

    def mark_as_false_positive(self, mac: str):
        self.detection_history.pop(mac, None)
        self.isolated_devices.pop(mac, None)
        self.stats['false_positive_overrides'] += 1

    def get_stats(self) -> Dict:
        return {**self.stats, 'isolated_devices': len(self.isolated_devices)}
