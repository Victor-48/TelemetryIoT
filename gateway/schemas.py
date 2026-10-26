from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


def current_iso_time() -> str:
    return datetime.now(timezone.utc).isoformat()


class TelemetryMessage(BaseModel):
    timestamp: str = Field(default_factory=current_iso_time)
    node_id: str
    device_id: str
    device_type: str
    ip_address: str
    metrics: Dict[str, Any]
    status: str = "OK"


class OSLogMessage(BaseModel):
    timestamp: str = Field(default_factory=current_iso_time)
    node_id: str
    device_id: str
    log_type: str = "auth"
    event_type: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    user: Optional[str] = None
    message: str
    severity: str = "INFO"


class AlertMessage(BaseModel):
    alert_id: str
    timestamp: str = Field(default_factory=current_iso_time)
    device_id: str
    device_name: str
    severity: str
    rule: str
    details: Dict[str, Any]
    resolved: bool = False
