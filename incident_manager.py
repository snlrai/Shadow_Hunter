"""
Incident Correlation Engine
Groups individual detection alerts into logical incidents (attack storylines).

An Incident represents a correlated set of alerts that tell a coherent story:
- Same source IP triggering multiple signals over time
- Multiple IPs exhibiting coordinated behaviour
- Progression through Kill Chain stages
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import pandas as pd


@dataclass
class Alert:
    """A single detection alert snapshot."""
    source_ip: str
    timestamp: datetime
    score: int
    confidence: str
    service_type: str
    triggered_signals: List[str]
    threat_intel_provider: Optional[str] = None
    ml_is_anomaly: bool = False
    ae_is_anomaly: bool = False


@dataclass
class Incident:
    """A correlated group of alerts forming an attack narrative."""
    incident_id: str
    title: str
    severity: str                # CRITICAL, HIGH, MEDIUM, LOW
    status: str                  # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    created_at: datetime
    updated_at: datetime
    source_ips: List[str]
    alerts: List[Alert]
    kill_chain_stages: List[str]
    ioc_summary: str             # Indicator of Compromise summary
    recommended_actions: List[str]
    tags: List[str] = field(default_factory=list)


class IncidentManager:
    """
    Correlates individual alerts into Incidents.

    Correlation rules:
    1. IP Clustering       — Multiple alerts from same IP → single incident
    2. Score Escalation    — Score ≥ 90 with ML+AE agreement → CRITICAL
    3. Kill Chain Mapping  — Multi-signal triggers map to attack stages
    4. Threat Intel Boost  — Known AI provider → severity bump
    """

    KILL_CHAIN_MAP = {
        "External HTTPS":      "Reconnaissance",
        "RX/TX Ratio":         "Exploitation",
        "Response Volume":     "Exploitation",
        "Connection Duration": "Command & Control",
        "Packet Rate":         "Command & Control",
        "Timing Regularity":   "Persistence",
    }

    def __init__(self):
        self.incidents: List[Incident] = []
        self._counter = 0

    def correlate(self, results_df: pd.DataFrame, flow_df: pd.DataFrame) -> List[Incident]:
        """
        Build incidents from a results DataFrame.

        Args:
            results_df: DataFrame with detection results (one row per IP).
            flow_df:    Raw flow data for enrichment.
        Returns:
            List of Incident objects sorted by severity.
        """
        self.incidents = []

        # ── Only care about detected threats ──────────────────────────────
        threats = results_df[results_df['detected']].copy()
        if threats.empty:
            return []

        for _, row in threats.iterrows():
            self._counter += 1
            ip = row['source_ip']
            result_obj = row['result_object']

            # Collect triggered signal names
            triggered = [s.name for s in result_obj.signals if s.triggered]

            # Map signals → Kill Chain stages
            stages = sorted({
                self.KILL_CHAIN_MAP[sig]
                for sig in triggered
                if sig in self.KILL_CHAIN_MAP
            })

            # Build alert
            alert = Alert(
                source_ip=ip,
                timestamp=result_obj.timestamp,
                score=result_obj.total_score,
                confidence=result_obj.confidence,
                service_type=row['service_type'],
                triggered_signals=triggered,
                threat_intel_provider=row.get('threat_intel_provider'),
                ml_is_anomaly=bool(row.get('ml_is_anomaly', False)),
                ae_is_anomaly=bool(row.get('ae_is_anomaly', False)),
            )

            # ── Determine severity ────────────────────────────────────────
            severity = self._compute_severity(row, stages)

            # ── Determine title ───────────────────────────────────────────
            provider = row.get('threat_intel_provider') or "Unknown AI Service"
            title = f"Unauthorized {provider} Access from {ip}"

            # ── IoC summary ───────────────────────────────────────────────
            ip_flows = flow_df[flow_df['source_ip'] == ip]
            ext_dests = ip_flows[~ip_flows['destination_ip'].str.startswith('10.')]['destination_ip'].unique()
            ioc = (
                f"Source {ip} made {len(ip_flows)} connections to "
                f"{len(ext_dests)} external endpoint(s). "
                f"RX/TX ratio {row['rx_tx_ratio']:.1f}:1. "
                f"Detection score {row['score']}/100."
            )

            # ── Recommended actions ───────────────────────────────────────
            actions = self._recommend_actions(severity, provider, ip)

            # ── Tags ──────────────────────────────────────────────────────
            tags = []
            if row.get('ml_is_anomaly'):
                tags.append("ML-Confirmed")
            if row.get('ae_is_anomaly'):
                tags.append("DL-Confirmed")
            if row.get('threat_intel_provider'):
                tags.append("ThreatIntel-Match")
            if len(stages) >= 3:
                tags.append("Kill-Chain-Progression")

            incident = Incident(
                incident_id=f"INC-{self._counter:04d}",
                title=title,
                severity=severity,
                status="OPEN",
                created_at=result_obj.timestamp,
                updated_at=result_obj.timestamp,
                source_ips=[ip],
                alerts=[alert],
                kill_chain_stages=stages,
                ioc_summary=ioc,
                recommended_actions=actions,
                tags=tags,
            )
            self.incidents.append(incident)

        # ── Merge incidents from the same IP ──────────────────────────────
        self.incidents = self._merge_by_ip(self.incidents)

        # Sort: CRITICAL first
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.incidents.sort(key=lambda i: severity_order.get(i.severity, 9))

        return self.incidents

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _compute_severity(self, row: pd.Series, stages: List[str]) -> str:
        score = row['score']
        ml_anomaly = bool(row.get('ml_is_anomaly', False))
        ae_anomaly = bool(row.get('ae_is_anomaly', False))
        has_intel = bool(row.get('threat_intel_provider'))

        if score >= 90 and (ml_anomaly and ae_anomaly) and has_intel:
            return "CRITICAL"
        if score >= 90 or (ml_anomaly and ae_anomaly):
            return "CRITICAL"
        if score >= 80 or has_intel:
            return "HIGH"
        if score >= 70:
            return "MEDIUM"
        return "LOW"

    def _recommend_actions(self, severity: str, provider: str, ip: str) -> List[str]:
        actions = [
            f"Investigate all traffic from {ip} in the last 24 hours",
            f"Verify if {provider} usage is authorized by security policy",
        ]
        if severity in ("CRITICAL", "HIGH"):
            actions.insert(0, f"🚨 IMMEDIATE: Block {ip} via firewall rules")
            actions.append("Escalate to SOC Level 3 for forensic analysis")
            actions.append("Check for data exfiltration in outbound payloads")
        if severity == "CRITICAL":
            actions.insert(1, "🔴 Notify CISO within 15 minutes (SLA requirement)")
        actions.append("Document findings in incident tracking system")
        return actions

    def _merge_by_ip(self, incidents: List[Incident]) -> List[Incident]:
        """Merge multiple incidents from the same IP into one."""
        ip_map: Dict[str, Incident] = {}
        for inc in incidents:
            key = tuple(sorted(inc.source_ips))
            k = str(key)
            if k in ip_map:
                existing = ip_map[k]
                existing.alerts.extend(inc.alerts)
                existing.kill_chain_stages = sorted(
                    set(existing.kill_chain_stages + inc.kill_chain_stages)
                )
                existing.tags = sorted(set(existing.tags + inc.tags))
                # Escalate severity
                sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                if sev_order.get(inc.severity, 9) < sev_order.get(existing.severity, 9):
                    existing.severity = inc.severity
                existing.updated_at = max(existing.updated_at, inc.updated_at)
            else:
                ip_map[k] = inc
        return list(ip_map.values())
