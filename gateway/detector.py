import math
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from gateway.schemas import TelemetryMessage, OSLogMessage, AlertMessage


class AnomalyDetector:
    """
    Real-time Statistical & Rule-Based Anomaly Detector for OT/IIoT Telemetry and OS Logs.
    Maintains sliding windows for continuous metrics (calculating Z-scores)
    and enforces semantic rules for state changes and security audit events.
    """
    def __init__(self, window_size: int = 20, z_threshold: float = 3.0):
        self.window_size = window_size
        self.z_threshold = z_threshold
        # Sliding windows for continuous numeric metrics: {metric_key: deque}
        self.windows: Dict[str, deque] = {}
        self.alert_counter = 0

    def _next_alert_id(self) -> str:
        self.alert_counter += 1
        return f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{self.alert_counter:04d}"

    def process_telemetry(self, msg: TelemetryMessage) -> List[AlertMessage]:
        alerts = []
        metrics = msg.metrics
        dev_id = msg.device_id

        # 1. Statistical Z-Score Detection on Continuous Metrics
        for key, val in metrics.items():
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                metric_key = f"{dev_id}.{key}"
                if metric_key not in self.windows:
                    self.windows[metric_key] = deque(maxlen=self.window_size)
                window = self.windows[metric_key]

                if len(window) >= 8:
                    mean = sum(window) / len(window)
                    variance = sum((x - mean) ** 2 for x in window) / len(window)
                    std_dev = math.sqrt(variance)

                    if std_dev > 0.001:
                        z_score = abs(val - mean) / std_dev
                        if z_score >= self.z_threshold:
                            alerts.append(AlertMessage(
                                alert_id=self._next_alert_id(),
                                device_id=dev_id,
                                device_name=dev_id,
                                severity="HIGH",
                                rule=f"Z-Score Anomaly on {key}",
                                details={
                                    "metric": key,
                                    "current_value": val,
                                    "window_mean": round(mean, 2),
                                    "std_dev": round(std_dev, 2),
                                    "z_score": round(z_score, 2),
                                    "threshold": self.z_threshold
                                }
                            ))
                window.append(val)

        # 2. Hard Semantic Rules for Industrial Telemetry
        # Modbus PLC Register limits
        reg40001 = metrics.get("holding_register_40001")
        if reg40001 is not None and reg40001 > 1000:
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=dev_id,
                device_name="PLC Modbus",
                severity="CRITICAL",
                rule="Modbus Register Overwrite Violation",
                details={
                    "holding_register_40001": reg40001,
                    "expected_nominal_range": "100-200",
                    "violation": "Value exceeds safe operational ceiling"
                }
            ))

        # Frigider Temperature Critical Spoilage Threshold
        temp = metrics.get("temperature_celsius")
        compressor = metrics.get("compressor_relay")
        if temp is not None and temp > 0.0:
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=dev_id,
                device_name="Frigider Industrial",
                severity="CRITICAL",
                rule="Industrial Cold Storage Temperature Breach",
                details={
                    "current_temperature": temp,
                    "safe_limit": "-18.0 C",
                    "compressor_relay": compressor,
                    "condition": "Critical spoilage risk"
                }
            ))

        # Cargo Access Violation
        unauthorized = metrics.get("unauthorized_access_alert")
        if unauthorized == 1:
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=dev_id,
                device_name="Poarta Acces Cargo",
                severity="HIGH",
                rule="Unauthorized Physical Access Detected",
                details={"status": "Access latch forced without RFID badge"}
            ))

        return alerts

    def process_os_log(self, msg: OSLogMessage) -> List[AlertMessage]:
        alerts = []
        event = msg.event_type

        if event == "ssh_accepted":
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=msg.device_id,
                device_name=msg.device_id,
                severity="HIGH",
                rule="Successful SSH Authentication after anomalies",
                details={
                    "source_ip": msg.source_ip,
                    "user": msg.user,
                    "message": msg.message
                }
            ))
        elif event == "privilege_escalation":
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=msg.device_id,
                device_name=msg.device_id,
                severity="CRITICAL",
                rule="Privilege Escalation (sudo to root) Detected",
                details={
                    "user": msg.user,
                    "source_ip": msg.source_ip,
                    "message": msg.message
                }
            ))
        elif event == "network_recon":
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=msg.device_id,
                device_name=msg.device_id,
                severity="ALERT",
                rule="Internal Port Scan (Reconnaissance) Detected",
                details={
                    "source_ip": msg.source_ip,
                    "target_ip": msg.target_ip,
                    "message": msg.message
                }
            ))
        elif event == "modbus_tampering":
            alerts.append(AlertMessage(
                alert_id=self._next_alert_id(),
                device_id=msg.device_id,
                device_name=msg.device_id,
                severity="CRITICAL",
                rule="OT Modbus Function Code Tampering",
                details={
                    "source_ip": msg.source_ip,
                    "target_ip": msg.target_ip,
                    "message": msg.message
                }
            ))

        return alerts
