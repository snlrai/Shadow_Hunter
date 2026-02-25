"""
Shadow Hunter — Unified Data Models
Pydantic models shared across all services in the event-driven architecture.

These replace the scattered dataclasses from the original MVP while remaining
backward-compatible (same field names where possible).
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    BLOCKED = "BLOCKED"
    RESOLVED = "RESOLVED"


# ---------------------------------------------------------------------------
# Core Event: every flow through the system becomes one of these
# ---------------------------------------------------------------------------

class NetworkFlowEvent(BaseModel):
    """
    Unified flow record combining fields from both projects.

    Original fields: timestamp through connection_duration, label, service_type
    v3 fields:       ja3_hash, metadata
    """
    # --- Core flow fields (from Original) ---
    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str
    destination_ip: str
    destination_port: int = 443
    protocol: str = "TCP"
    bytes_sent: int = 0
    bytes_received: int = 0
    packet_count: int = 1
    connection_duration: float = 0.0

    # --- Classification labels (from Original, used in sim mode) ---
    label: Optional[str] = None           # "normal" | "shadow_ai"
    service_type: Optional[str] = None    # "Internal API" | "Unauthorized LLM API" etc.

    # --- v3 Active Defense fields ---
    ja3_hash: Optional[str] = None        # MD5 of TLS ClientHello parameters
    metadata: Dict = Field(default_factory=dict)  # Extensible: probe_result, etc.


# ---------------------------------------------------------------------------
# Detection Signal: one scored indicator
# ---------------------------------------------------------------------------

class DetectionSignal(BaseModel):
    """A single heuristic signal with score and explanation."""
    name: str
    value: float
    threshold: float
    score: int
    max_score: int
    explanation: str
    triggered: bool


# ---------------------------------------------------------------------------
# Alert: the output of the analysis engine for one source IP
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """Full detection result for a single source IP."""
    # --- Identity ---
    alert_id: str = ""
    source_ip: str
    timestamp: datetime = Field(default_factory=datetime.now)

    # --- Scoring (from Original's heuristic system) ---
    total_score: int = 0
    is_shadow_ai: bool = False
    confidence: str = "Low"             # "High" | "Medium" | "Low"
    signals: List[DetectionSignal] = Field(default_factory=list)

    # --- Full metrics dict (backward-compat with Original dashboard) ---
    metrics: Dict = Field(default_factory=dict)
    recommendation: str = ""

    # --- ML results ---
    ml_anomaly_score: Optional[float] = None
    ml_is_anomaly: bool = False
    ae_reconstruction_error: Optional[float] = None
    ae_is_anomaly: bool = False
    shap_values: Optional[Dict[str, float]] = None

    # --- Threat Intel ---
    threat_intel_provider: Optional[str] = None
    threat_intel_service: Optional[str] = None
    threat_intel_risk: Optional[str] = None

    # --- JA3 (v3) ---
    ja3_match_type: Optional[str] = None  # "MALWARE" | "SPOOFING" | None
    ja3_match_detail: Optional[str] = None

    # --- Active Defense (v3) ---
    probe_result: Optional[Dict] = None
    severity: Severity = Severity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN

    # --- Graph ---
    destination_ips: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Block Record: audit trail for auto-response
# ---------------------------------------------------------------------------

class BlockRecord(BaseModel):
    """Record of an IP being blocked by the ResponseManager."""
    ip: str
    blocked_at: datetime = Field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    reason: str = ""
    severity: Severity = Severity.CRITICAL
    auto_blocked: bool = True


# ---------------------------------------------------------------------------
# Probe Result: output of active interrogation
# ---------------------------------------------------------------------------

class ProbeResult(BaseModel):
    """Result from the ActiveProbe interrogator."""
    target_ip: str
    probed_at: datetime = Field(default_factory=datetime.now)
    http_options_status: Optional[int] = None
    http_options_server: Optional[str] = None
    ai_endpoint_detected: bool = False
    ai_endpoint_response: Optional[str] = None
    is_confirmed_ai: bool = False
    error: Optional[str] = None
