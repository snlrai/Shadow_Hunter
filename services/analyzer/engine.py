"""
Shadow Hunter — Hybrid Analyzer Engine (Event-Driven)

The core analysis service that combines:
  - JA3 fingerprint matching (fast path, from v3)
  - 6-signal heuristic scoring (from Original)
  - Isolation Forest ML anomaly detection (from Original)
  - Autoencoder deep learning detection (from Original)
  - Threat Intelligence enrichment (from Original)
  - SHAP explainability (from Original)
  - Graph topology updates (from v3)
  - Active Probe triggering (from v3)

This is a service that subscribes to "traffic.flow" events via the EventBroker,
processes them through the full pipeline, and publishes alerts.

Usage::

    engine = AnalyzerEngine(broker, store)
    engine.initialize(df)     # Train ML models on initial dataset
    # Thereafter, events arrive via broker subscription.
"""

import logging
import sys
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import numpy as np

# Add project root to path for imports from existing modules
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from pkg.core.interfaces import EventBroker, GraphStore
from pkg.models.events import (
    NetworkFlowEvent,
    Alert,
    DetectionSignal,
    Severity,
    AlertStatus,
)
from services.analyzer.plugins.ja3_plugin import JA3Plugin

# Import existing Original modules (unchanged)
from model import ShadowAnomalyDetector, AnomalyResult
from autoencoder_model import ShadowAutoencoder, AutoencoderResult
from threat_intel import ThreatIntelEnricher
from detection_engine import FeatureExtractor, DetectionConfig

logger = logging.getLogger("shadow_hunter.analyzer")


class AnalyzerEngine:
    """
    The Hybrid Brain — event-driven analysis service.

    Subscribes to "traffic.flow" events, runs the full detection pipeline,
    and publishes alerts. Also updates the graph store with topology data.
    """

    def __init__(
        self,
        broker: EventBroker,
        store: GraphStore,
        config: DetectionConfig = None,
        active_defense: bool = True,
    ):
        self.broker = broker
        self.store = store
        self.config = config or DetectionConfig()
        self.active_defense = active_defense

        # Analysis components (from Original)
        self.extractor = FeatureExtractor()
        self.ml_detector = ShadowAnomalyDetector()
        self.autoencoder = ShadowAutoencoder()
        self.threat_intel = ThreatIntelEnricher()

        # v3 component
        self.ja3_plugin = JA3Plugin()

        # Training state
        self._ml_trained = False
        self._ae_trained = False
        self.baseline_stats = None

        # Accumulated flow data (for feature extraction across multiple events)
        self._flow_buffer: List[Dict] = []

        # Subscribe to traffic events
        self.broker.subscribe("traffic.flow", self._handle_flow)

        # Statistics
        self._stats = {
            "flows_processed": 0,
            "alerts_generated": 0,
            "ja3_blocks": 0,
            "auto_blocks_triggered": 0,
        }

        logger.info(
            "AnalyzerEngine initialized (active_defense=%s)", active_defense
        )

    # ------------------------------------------------------------------
    # Initialization — train ML models on historical data
    # ------------------------------------------------------------------

    def initialize(self, df: pd.DataFrame) -> Dict:
        """
        Train ML models on an initial dataset (e.g., from simulator).

        This is necessary before the engine can provide ML scores.
        The heuristic scoring works without training.

        Args:
            df: DataFrame with flow records (from traffic_simulator).

        Returns:
            Dict of training statistics.
        """
        stats = {}

        # Compute baseline from normal IPs (if labels exist)
        if "label" in df.columns:
            normal_ips = df[df["label"] == "normal"]["source_ip"].unique().tolist()
            self._compute_baseline(df, normal_ips)
            stats["baseline_ips"] = len(normal_ips)

        # Train ML (Isolation Forest)
        all_ips = df["source_ip"].unique().tolist()
        feature_dicts = self._extract_all_features(df, all_ips)

        if len(feature_dicts) >= 3:
            self.ml_detector.train(feature_dicts)
            self._ml_trained = True
            stats["ml_trained"] = True
            stats["ml_samples"] = len(feature_dicts)
            logger.info("ML model trained on %d IPs", len(feature_dicts))
        else:
            stats["ml_trained"] = False
            logger.warning("Not enough data for ML training (need >= 3)")

        # Train Autoencoder
        if len(feature_dicts) >= 3:
            ae_stats = self.autoencoder.train(feature_dicts)
            self._ae_trained = True
            stats["ae_trained"] = True
            if ae_stats:
                stats.update({f"ae_{k}": v for k, v in ae_stats.items()})
            logger.info("Autoencoder trained on %d IPs", len(feature_dicts))
        else:
            stats["ae_trained"] = False

        # Buffer the DataFrame for feature extraction on incoming events
        for _, row in df.iterrows():
            self._flow_buffer.append(row.to_dict())

        logger.info("Engine initialized: %s", stats)
        return stats

    # ------------------------------------------------------------------
    # Event handler — the main pipeline
    # ------------------------------------------------------------------

    def _handle_flow(self, event) -> None:
        """
        Process a single traffic flow event through the full pipeline.

        This is called by the EventBroker when a "traffic.flow" event arrives.

        Pipeline:
          1. JA3 fast path (malware/spoofing check)
          2. Buffer flow for feature extraction
          3. Feature extraction (aggregates all flows for this IP)
          4. Heuristic scoring (6 signals, 100-point scale)
          5. ML inference (Isolation Forest + SHAP)
          6. Autoencoder inference
          7. Threat Intelligence enrichment
          8. Graph update (nodes + edges)
          9. Publish alert if threshold met
        """
        self._stats["flows_processed"] += 1

        # Normalize event to dict
        if isinstance(event, NetworkFlowEvent):
            flow = event.model_dump()
        elif isinstance(event, dict):
            flow = event
        else:
            logger.warning("Unknown event type: %s", type(event))
            return

        source_ip = flow.get("source_ip", "")
        dest_ip = flow.get("destination_ip", "")

        # ---- Step 1: JA3 Fast Path ----
        ja3_result = self.ja3_plugin.check(
            flow.get("ja3_hash"),
            flow.get("metadata", {}).get("user_agent"),
        )

        if ja3_result.match_type == "MALWARE":
            self._stats["ja3_blocks"] += 1
            alert = self._build_alert(
                source_ip=source_ip,
                total_score=100,
                is_shadow_ai=True,
                confidence="High",
                signals=[],
                metrics={"ja3_match": ja3_result.name},
                recommendation=f"🚨 C2 MALWARE DETECTED: {ja3_result.detail}",
                severity=Severity.CRITICAL,
                ja3_match_type="MALWARE",
                ja3_match_detail=ja3_result.detail,
                destination_ips=[dest_ip],
            )
            self._publish_alert(alert)
            self._update_graph(source_ip, dest_ip, flow, risk_score=1.0)
            self.store.store_event("alert", alert.model_dump())
            return  # Short-circuit — no need for further analysis

        # ---- Step 2: Buffer flow ----
        self._flow_buffer.append(flow)

        # ---- Step 3: Feature extraction ----
        buffer_df = pd.DataFrame(self._flow_buffer)
        # Ensure timestamp column is proper datetime
        if "timestamp" in buffer_df.columns:
            buffer_df["timestamp"] = pd.to_datetime(buffer_df["timestamp"])

        metrics = self.extractor.extract_features(buffer_df, source_ip)
        if not metrics:
            self._update_graph(source_ip, dest_ip, flow, risk_score=0.0)
            return

        # ---- Step 4: DB Port Whitelist ----
        ip_traffic = buffer_df[buffer_df["source_ip"] == source_ip]
        if len(ip_traffic) > 0:
            db_ratio = len(
                ip_traffic[ip_traffic["destination_port"].isin(
                    self.config.whitelisted_db_ports
                )]
            ) / len(ip_traffic)
            if db_ratio > 0.8:
                self._update_graph(source_ip, dest_ip, flow, risk_score=0.0)
                return  # Whitelisted DB traffic

        # ---- Step 5: Heuristic Scoring (6 signals, 100-point scale) ----
        signals, total_score = self._score_heuristics(metrics)
        is_shadow_ai = total_score >= self.config.alert_threshold

        # Confidence level
        if total_score >= 90:
            confidence = "High"
        elif total_score >= 70:
            confidence = "Medium"
        else:
            confidence = "Low"

        # ---- Step 6: ML Inference ----
        ml_anomaly_result = None
        if self._ml_trained:
            ml_anomaly_result = self.ml_detector.predict_single(source_ip, metrics)
            # ML boost: +15 points if ML flags but heuristics didn't reach threshold
            if ml_anomaly_result.is_anomaly and not is_shadow_ai:
                total_score = min(100, total_score + 15)
                is_shadow_ai = total_score >= self.config.alert_threshold

            metrics["ml_anomaly_score"] = ml_anomaly_result.anomaly_score
            metrics["ml_is_anomaly"] = ml_anomaly_result.is_anomaly
            metrics["ml_top_features"] = ml_anomaly_result.top_contributing_features
            metrics["ml_feature_contributions"] = ml_anomaly_result.feature_contributions
        else:
            metrics["ml_anomaly_score"] = None
            metrics["ml_is_anomaly"] = None
            metrics["ml_top_features"] = []
            metrics["ml_feature_contributions"] = {}

        # ---- Step 7: Autoencoder ----
        ae_result = None
        if self._ae_trained:
            ae_result = self.autoencoder.predict_single(source_ip, metrics)
            metrics["ae_reconstruction_error"] = ae_result.reconstruction_error
            metrics["ae_is_anomaly"] = ae_result.is_anomaly
            metrics["ae_threshold"] = ae_result.error_threshold
            metrics["ae_percentile"] = ae_result.anomaly_percentile
            metrics["ae_top_features"] = ae_result.top_anomalous_features
            metrics["ae_feature_errors"] = ae_result.feature_errors
        else:
            metrics["ae_reconstruction_error"] = None
            metrics["ae_is_anomaly"] = None
            metrics["ae_threshold"] = None
            metrics["ae_percentile"] = None
            metrics["ae_top_features"] = []
            metrics["ae_feature_errors"] = {}

        # ---- Step 8: Threat Intelligence ----
        dest_ips = ip_traffic["destination_ip"].unique().tolist()
        ti_matches = self.threat_intel.enrich_destinations(dest_ips)
        ti_provider = ti_service = ti_risk = None

        if ti_matches:
            best = max(
                ti_matches.values(),
                key=lambda m: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(m.risk_level, 0),
            )
            ti_provider = best.provider
            ti_service = best.service
            ti_risk = best.risk_level

        metrics["threat_intel_provider"] = ti_provider
        metrics["threat_intel_service"] = ti_service
        metrics["threat_intel_risk"] = ti_risk

        # ---- Step 9: SHAP values ----
        if ml_anomaly_result and ml_anomaly_result.shap_values:
            metrics["shap_values"] = ml_anomaly_result.shap_values
        else:
            metrics["shap_values"] = None

        # ---- Step 10: JA3 enrichment (non-malware matches) ----
        if ja3_result.match_type == "SPOOFING":
            metrics["ja3_match"] = ja3_result.name
            total_score = min(100, total_score + 10)
            is_shadow_ai = total_score >= self.config.alert_threshold

        # ---- Recommendation ----
        recommendation = self._build_recommendation(
            is_shadow_ai, source_ip, signals, ti_provider, ti_service, ti_risk
        )

        # ---- Step 11: Determine severity ----
        severity = self._compute_severity(
            total_score, ml_anomaly_result, ae_result, ti_provider
        )

        # ---- Step 12: Update Graph ----
        risk_score = total_score / 100.0
        self._update_graph(source_ip, dest_ip, flow, risk_score)

        # ---- Step 13: Publish alert (if threshold met) ----
        if is_shadow_ai or total_score >= 60:
            alert = self._build_alert(
                source_ip=source_ip,
                total_score=total_score,
                is_shadow_ai=is_shadow_ai,
                confidence=confidence,
                signals=signals,
                metrics=metrics,
                recommendation=recommendation,
                severity=severity,
                ja3_match_type=ja3_result.match_type if ja3_result.match_type != "CLEAN" else None,
                ja3_match_detail=ja3_result.detail if ja3_result.match_type != "CLEAN" else None,
                destination_ips=dest_ips,
                ml_anomaly_score=metrics.get("ml_anomaly_score"),
                ml_is_anomaly=metrics.get("ml_is_anomaly", False),
                ae_reconstruction_error=metrics.get("ae_reconstruction_error"),
                ae_is_anomaly=metrics.get("ae_is_anomaly", False),
                shap_values=metrics.get("shap_values"),
                threat_intel_provider=ti_provider,
                threat_intel_service=ti_service,
                threat_intel_risk=ti_risk,
            )
            self._publish_alert(alert)
            self.store.store_event("alert", alert.model_dump())
            self._stats["alerts_generated"] += 1

        # Store flow event in DB
        self.store.store_event("flow", flow)

    # ------------------------------------------------------------------
    # Heuristic scoring — ported exactly from Original
    # ------------------------------------------------------------------

    def _score_heuristics(self, metrics: Dict) -> tuple:
        """
        Apply the 6-signal scoring system from the Original project.
        Returns (signals_list, total_score).
        """
        signals = []
        total_score = 0
        config = self.config

        # Signal 1: RX/TX Ratio (40 pts)
        rx_tx = metrics.get("rx_tx_ratio", 0)
        triggered = config.rx_tx_ratio_min <= rx_tx <= config.rx_tx_ratio_max
        score = 40 if triggered else 0
        comparison = ""
        if self.baseline_stats:
            comparison = f" (normal: {self.baseline_stats['rx_tx_ratio_mean']:.1f}:1)"
        signals.append(DetectionSignal(
            name="RX/TX Ratio", value=rx_tx, threshold=config.rx_tx_ratio_min,
            score=score, max_score=40,
            explanation=f"Response {rx_tx:.1f}x larger than request{comparison}",
            triggered=triggered,
        ))
        total_score += score

        # Signal 2: Response Volume (20 pts)
        avg_recv = metrics.get("avg_bytes_received", 0)
        triggered = config.min_bytes_received <= avg_recv <= config.max_bytes_received
        score = 20 if triggered else 0
        signals.append(DetectionSignal(
            name="Response Volume", value=avg_recv, threshold=config.min_bytes_received,
            score=score, max_score=20,
            explanation=f"Avg response {avg_recv:.0f} bytes (LLM range: 2KB-100KB)",
            triggered=triggered,
        ))
        total_score += score

        # Signal 3: Connection Duration (15 pts)
        duration = metrics.get("avg_connection_duration", 0)
        triggered = config.connection_duration_min <= duration <= config.connection_duration_max
        score = 15 if triggered else 0
        signals.append(DetectionSignal(
            name="Connection Duration", value=duration, threshold=config.connection_duration_min,
            score=score, max_score=15,
            explanation=f"Avg {duration:.1f}s connections (streaming range: 1-30s)",
            triggered=triggered,
        ))
        total_score += score

        # Signal 4: Packet Rate (10 pts)
        pps = metrics.get("packets_per_second", 0)
        triggered = config.packets_per_second_min <= pps <= config.packets_per_second_max
        score = 10 if triggered else 0
        signals.append(DetectionSignal(
            name="Packet Rate", value=pps, threshold=config.packets_per_second_min,
            score=score, max_score=10,
            explanation=f"{pps:.1f} packets/sec (steady streaming)",
            triggered=triggered,
        ))
        total_score += score

        # Signal 5: Timing Regularity (10 pts)
        reg = metrics.get("timing_regularity", 0)
        triggered = reg >= config.timing_regularity_threshold
        score = 10 if triggered else 0
        signals.append(DetectionSignal(
            name="Timing Regularity", value=reg, threshold=config.timing_regularity_threshold,
            score=score, max_score=10,
            explanation=f"Regularity {reg:.2f} (automated pattern)",
            triggered=triggered,
        ))
        total_score += score

        # Signal 6: External HTTPS (5 pts)
        ext = metrics.get("external_https_ratio", 0)
        triggered = ext > 0.5
        score = 5 if triggered else 0
        signals.append(DetectionSignal(
            name="External HTTPS", value=ext, threshold=0.5,
            score=score, max_score=5,
            explanation=f"{ext*100:.0f}% external HTTPS traffic",
            triggered=triggered,
        ))
        total_score += score

        return signals, total_score

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compute_baseline(self, df: pd.DataFrame, normal_ips: List[str]):
        """Compute population-level baseline stats from normal traffic."""
        features = []
        for ip in normal_ips:
            f = self.extractor.extract_features(df, ip)
            if f:
                features.append(f)
        if features:
            bdf = pd.DataFrame(features)
            self.baseline_stats = {
                "rx_tx_ratio_mean": bdf["rx_tx_ratio"].mean(),
                "rx_tx_ratio_std": bdf["rx_tx_ratio"].std(),
                "pps_mean": bdf["packets_per_second"].mean(),
                "pps_std": bdf["packets_per_second"].std(),
                "duration_mean": bdf["avg_connection_duration"].mean(),
            }
            logger.info("Baseline computed from %d normal IPs", len(normal_ips))

    def _extract_all_features(self, df: pd.DataFrame, ips: List[str]) -> List[Dict]:
        """Extract features for all IPs in a DataFrame."""
        result = []
        for ip in ips:
            f = self.extractor.extract_features(df, ip)
            if f:
                result.append(f)
        return result

    def _compute_severity(self, score, ml_result, ae_result, ti_provider) -> Severity:
        """Compute alert severity using multi-factor logic from incident_manager."""
        ml_flag = ml_result.is_anomaly if ml_result else False
        ae_flag = ae_result.is_anomaly if ae_result else False

        # CRITICAL: score >= 90 with any corroboration, or 85+ with both ML/AE
        if score >= 90 and (ml_flag or ae_flag or ti_provider):
            return Severity.CRITICAL
        if score >= 85 and ml_flag and ae_flag:
            return Severity.CRITICAL
        # HIGH: strong heuristic score or threat intel match
        if score >= 80 or (score >= 70 and ti_provider):
            return Severity.HIGH
        if score >= 70 or (ml_flag and ae_flag):
            return Severity.MEDIUM
        return Severity.LOW

    def _build_recommendation(self, is_shadow_ai, source_ip, signals,
                              ti_provider, ti_service, ti_risk) -> str:
        """Generate human-readable recommendation string."""
        if is_shadow_ai:
            triggered = [s.name for s in signals if s.triggered]
            if ti_provider:
                return (
                    f"🚨 CONFIRMED: Unauthorized **{ti_provider}** ({ti_service}) "
                    f"access from {source_ip}. "
                    f"Triggered: {', '.join(triggered[:3])}"
                )
            return (
                f"⚠️ INVESTIGATE: {len(triggered)} signals match Shadow AI. "
                f"Check if {source_ip} is authorized. "
                f"Review: {', '.join(triggered[:3])}"
            )
        return "✅ Traffic appears normal - no action needed"

    def _build_alert(self, **kwargs) -> Alert:
        """Build an Alert object from keyword args."""
        kwargs.setdefault("alert_id", str(uuid.uuid4())[:8])
        kwargs.setdefault("timestamp", datetime.now())
        kwargs.setdefault("status", AlertStatus.OPEN)
        return Alert(**kwargs)

    def _publish_alert(self, alert: Alert) -> None:
        """Publish alert to appropriate topics based on severity."""
        self.broker.publish("alert.new", alert)

        if alert.severity == Severity.CRITICAL:
            self.broker.publish("alert.critical", alert)
            logger.warning(
                "🚨 CRITICAL ALERT: %s (score=%d)", alert.source_ip, alert.total_score
            )
        elif alert.severity == Severity.HIGH:
            self.broker.publish("alert.high", alert)
            logger.warning(
                "⚠️ HIGH ALERT: %s (score=%d)", alert.source_ip, alert.total_score
            )

    def _update_graph(self, source_ip: str, dest_ip: str,
                      flow: Dict, risk_score: float) -> None:
        """Update the graph store with node + edge data."""
        # Source node
        src_type = "internal" if source_ip.startswith(("10.", "192.168.", "172.")) else "external"
        self.store.upsert_node(source_ip, ["Node"], {
            "type": src_type,
            "risk_score": risk_score,
            "last_seen": datetime.now().isoformat(),
        })

        # Destination node
        if dest_ip:
            dst_type = "internal" if dest_ip.startswith(("10.", "192.168.", "172.")) else "external"
            self.store.upsert_node(dest_ip, ["Node"], {
                "type": dst_type,
                "last_seen": datetime.now().isoformat(),
            })

            # Edge
            self.store.upsert_edge(source_ip, dest_ip, "TALKS_TO", {
                "protocol": flow.get("protocol", "TCP"),
                "dst_port": flow.get("destination_port", 0),
                "byte_count": flow.get("bytes_sent", 0) + flow.get("bytes_received", 0),
                "last_seen": datetime.now().isoformat(),
            })

    # ------------------------------------------------------------------
    # Batch analysis (for dashboard compatibility)
    # ------------------------------------------------------------------

    def analyze_batch(self, df: pd.DataFrame) -> List[Alert]:
        """
        Analyze all IPs in a DataFrame (batch mode).
        This is for backward compatibility with the Streamlit dashboard.

        Returns a list of Alert objects for all IPs.
        """
        results = []
        all_ips = df["source_ip"].unique().tolist()

        for ip in all_ips:
            traffic = df[df["source_ip"] == ip]
            for _, row in traffic.iterrows():
                flow = row.to_dict()
                self.broker.publish("traffic.flow", flow)

            # Get the latest alert for this IP from history
            alerts = self.broker.get_history("alert.new")
            ip_alerts = [a for a in alerts if isinstance(a, Alert) and a.source_ip == ip]
            if ip_alerts:
                results.append(ip_alerts[-1])

        return results

    @property
    def stats(self) -> Dict:
        return {**self._stats, "ml_trained": self._ml_trained, "ae_trained": self._ae_trained}
