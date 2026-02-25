"""
Shadow AI Detection Engine
Multi-signal behavioral analysis with explainable scoring

Key Design Principles:
1. Multi-signal detection (not single-condition)
2. Configurable thresholds for tuning
3. Explainable output (shows WHY traffic was flagged)
4. Baseline comparison against normal traffic
5. RX/TX ratio as primary signal
"""

import pandas as pd
import numpy as np
from dataclasses import dataclass
from typing import List, Dict, Tuple
from datetime import datetime
import json
from model import ShadowAnomalyDetector, AnomalyResult
from autoencoder_model import ShadowAutoencoder, AutoencoderResult
from threat_intel import ThreatIntelEnricher


@dataclass
class DetectionConfig:
    """Configurable thresholds for detection tuning"""
    
    # Primary signal: RX/TX ratio
    # Shadow AI typically has 10:1 to 50:1 ratio (small prompts, large responses)
    # Set to 12.0 based on comparison: DB ratio ~6.3, AI ratio ~22.9
    rx_tx_ratio_min: float = 12.0
    rx_tx_ratio_max: float = 100.0  # Video streaming goes higher
    
    # Traffic volume constraints
    # Ensures we're looking at meaningful traffic, not noise
    min_bytes_received: int = 2000  # At least 2KB response
    max_bytes_received: int = 100000  # Less than 100KB (video is much higher)
    
    # Connection timing
    # LLM inference takes time (streaming), but not too long
    connection_duration_min: float = 1.0  # At least 1 second
    connection_duration_max: float = 30.0  # Less than 30 seconds
    
    # Packet behavior
    # Moderate, steady packet rate indicates streaming
    packets_per_second_min: float = 3.0
    packets_per_second_max: float = 100.0
    
    # Timing regularity (0-1, where 1 is perfectly regular)
    # LLM calls tend to be semi-regular (automated agent behavior)
    timing_regularity_threshold: float = 0.4
    
    # External traffic indicator
    external_https_port: int = 443
    
    # Scoring thresholds
    alert_threshold: int = 85  # Total score to trigger alert (raised for precision)
    
    # Known safe services (whitelist)
    approved_destinations: List[str] = None
    
    # Database ports to whitelist (reduce noise from legitimate DB traffic)
    whitelisted_db_ports: List[int] = None
    
    def __post_init__(self):
        if self.approved_destinations is None:
            self.approved_destinations = [
                # Internal ranges
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                # Approved SaaS (example)
                "salesforce.com",
                "github.com"
            ]
        
        if self.whitelisted_db_ports is None:
            self.whitelisted_db_ports = [
                3306,   # MySQL
                5432,   # PostgreSQL
                1433,   # SQL Server
                27017,  # MongoDB
                6379,   # Redis
                9042,   # Cassandra
                5984,   # CouchDB
                7000,   # Cassandra inter-node
            ]


@dataclass
class DetectionSignal:
    """Individual signal with score and explanation"""
    name: str
    value: float
    threshold: float
    score: int
    explanation: str
    triggered: bool


@dataclass
class DetectionResult:
    """Complete detection result with explanations"""
    source_ip: str
    timestamp: datetime
    total_score: int
    is_shadow_ai: bool
    confidence: str  # "High", "Medium", "Low"
    signals: List[DetectionSignal]
    metrics: Dict[str, float]
    recommendation: str


class FeatureExtractor:
    """Extracts behavioral features from raw flow logs"""
    
    @staticmethod
    def extract_features(df: pd.DataFrame, source_ip: str, time_window_minutes: int = 60) -> Dict[str, float]:
        """
        Aggregate traffic for a source IP over time window
        Returns derived metrics for detection
        """
        # Filter to this source
        traffic = df[df['source_ip'] == source_ip].copy()
        
        if len(traffic) == 0:
            return {}
        
        # Ensure timestamp is datetime (handles both generated and uploaded CSV data)
        if 'timestamp' in traffic.columns:
            traffic['timestamp'] = pd.to_datetime(traffic['timestamp'])
        
        # Basic aggregations
        total_sent = traffic['bytes_sent'].sum()
        total_received = traffic['bytes_received'].sum()
        total_packets = traffic['packet_count'].sum()
        total_duration = traffic['connection_duration'].sum()
        
        # Derived metrics
        features = {
            # PRIMARY SIGNAL: RX/TX ratio
            'rx_tx_ratio': total_received / total_sent if total_sent > 0 else 0,
            
            # Traffic volume
            'total_bytes_sent': total_sent,
            'total_bytes_received': total_received,
            'avg_bytes_sent': traffic['bytes_sent'].mean(),
            'avg_bytes_received': traffic['bytes_received'].mean(),
            
            # Connection behavior
            'avg_connection_duration': traffic['connection_duration'].mean(),
            'max_connection_duration': traffic['connection_duration'].max(),
            
            # Packet patterns
            'packets_per_second': total_packets / total_duration if total_duration > 0 else 0,
            'avg_packet_size': (total_sent + total_received) / total_packets if total_packets > 0 else 0,
            
            # Timing analysis
            'request_count': len(traffic),
            'requests_per_minute': len(traffic) / time_window_minutes,
            
            # Destination diversity
            'unique_destinations': traffic['destination_ip'].nunique(),
            'unique_ports': traffic['destination_port'].nunique(),
            
            # External traffic indicator
            'external_https_ratio': len(traffic[
                (traffic['destination_port'] == 443) & 
                (~traffic['destination_ip'].str.startswith('10.'))
            ]) / len(traffic) if len(traffic) > 0 else 0,
        }
        
        # Timing regularity (coefficient of variation)
        if len(traffic) > 1:
            traffic_sorted = traffic.sort_values('timestamp')
            intervals = traffic_sorted['timestamp'].diff().dt.total_seconds().dropna()
            if len(intervals) > 0 and intervals.mean() > 0:
                cv = intervals.std() / intervals.mean()
                # Convert to regularity score (inverse of CV, bounded 0-1)
                features['timing_regularity'] = 1 / (1 + cv)
            else:
                features['timing_regularity'] = 0
        else:
            features['timing_regularity'] = 0
            
        return features


class ShadowAIDetector:
    """Multi-signal behavioral detector with explainable output"""
    
    def __init__(self, config: DetectionConfig = None):
        self.config = config or DetectionConfig()
        self.baseline_stats = None
        self.ml_detector = ShadowAnomalyDetector()
        self.autoencoder = ShadowAutoencoder()
        self.threat_intel = ThreatIntelEnricher()
        self._ml_trained = False
        self._ae_trained = False
        
    def compute_baseline(self, df: pd.DataFrame, normal_ips: List[str]):
        """
        Compute baseline statistics from known normal traffic
        Used for comparison and context in alerts
        """
        normal_traffic = df[df['source_ip'].isin(normal_ips)]
        
        extractor = FeatureExtractor()
        baseline_features = []
        
        for ip in normal_ips:
            features = extractor.extract_features(df, ip)
            if features:
                baseline_features.append(features)
        
        if baseline_features:
            baseline_df = pd.DataFrame(baseline_features)
            self.baseline_stats = {
                'rx_tx_ratio_mean': baseline_df['rx_tx_ratio'].mean(),
                'rx_tx_ratio_std': baseline_df['rx_tx_ratio'].std(),
                'pps_mean': baseline_df['packets_per_second'].mean(),
                'pps_std': baseline_df['packets_per_second'].std(),
                'duration_mean': baseline_df['avg_connection_duration'].mean(),
            }
            print(f"[SUCCESS] Baseline computed from {len(normal_ips)} normal services")
            print(f"   Normal RX/TX ratio: {self.baseline_stats['rx_tx_ratio_mean']:.2f} ± {self.baseline_stats['rx_tx_ratio_std']:.2f}")
        
    def analyze_traffic(self, df: pd.DataFrame, source_ip: str) -> DetectionResult:
        """
        Analyze traffic from a source IP using multi-signal detection
        Returns detailed results with explanations
        """
        # FILTERING: Skip whitelisted database ports to reduce noise
        traffic = df[df['source_ip'] == source_ip].copy()
        if len(traffic) > 0:
            # Check if majority of traffic is to whitelisted DB ports
            db_port_traffic = traffic[traffic['destination_port'].isin(self.config.whitelisted_db_ports)]
            db_traffic_ratio = len(db_port_traffic) / len(traffic)
            
            # If >80% of traffic is to DB ports, skip detection (likely legitimate DB traffic)
            if db_traffic_ratio > 0.8:
                return DetectionResult(
                    source_ip=source_ip,
                    timestamp=datetime.now(),
                    total_score=0,
                    is_shadow_ai=False,
                    confidence="N/A",
                    signals=[],
                    metrics={
                        'rx_tx_ratio': 0,
                        'avg_bytes_received': 0,
                        'timing_regularity': 0,
                        'total_bytes_sent': 0,
                        'total_bytes_received': 0,
                        'avg_bytes_sent': 0,
                        'avg_connection_duration': 0,
                        'max_connection_duration': 0,
                        'packets_per_second': 0,
                        'avg_packet_size': 0,
                        'request_count': 0,
                        'requests_per_minute': 0,
                        'unique_destinations': 0,
                        'unique_ports': 0,
                        'external_https_ratio': 0
                    },
                    recommendation=f"[OK] Whitelisted - {db_traffic_ratio*100:.0f}% traffic to database ports (likely legitimate)"
                )
        
        # Extract features
        extractor = FeatureExtractor()
        metrics = extractor.extract_features(df, source_ip)
        
        if not metrics:
            return None
        
        # Collect all signals
        signals = []
        total_score = 0
        
        # SIGNAL 1: High RX/TX Ratio (PRIMARY)
        # This is the strongest indicator of LLM inference
        rx_tx_ratio = metrics['rx_tx_ratio']
        rx_tx_triggered = (
            self.config.rx_tx_ratio_min <= rx_tx_ratio <= self.config.rx_tx_ratio_max
        )
        rx_tx_score = 40 if rx_tx_triggered else 0
        
        comparison = ""
        if self.baseline_stats:
            normal_ratio = self.baseline_stats['rx_tx_ratio_mean']
            comparison = f" (normal services: {normal_ratio:.1f}:1)"
        
        signals.append(DetectionSignal(
            name="RX/TX Ratio",
            value=rx_tx_ratio,
            threshold=self.config.rx_tx_ratio_min,
            score=rx_tx_score,
            explanation=f"Response {rx_tx_ratio:.1f}x larger than request{comparison}",
            triggered=rx_tx_triggered
        ))
        total_score += rx_tx_score
        
        # SIGNAL 2: Response Volume Range
        # LLM responses are large but not as large as video
        bytes_received = metrics['avg_bytes_received']
        volume_triggered = (
            self.config.min_bytes_received <= bytes_received <= self.config.max_bytes_received
        )
        volume_score = 20 if volume_triggered else 0
        
        signals.append(DetectionSignal(
            name="Response Volume",
            value=bytes_received,
            threshold=self.config.min_bytes_received,
            score=volume_score,
            explanation=f"Avg response {bytes_received:.0f} bytes (LLM range: 2KB-100KB)",
            triggered=volume_triggered
        ))
        total_score += volume_score
        
        # SIGNAL 3: Connection Duration
        # LLM streaming takes time but not too long
        duration = metrics['avg_connection_duration']
        duration_triggered = (
            self.config.connection_duration_min <= duration <= self.config.connection_duration_max
        )
        duration_score = 15 if duration_triggered else 0
        
        signals.append(DetectionSignal(
            name="Connection Duration",
            value=duration,
            threshold=self.config.connection_duration_min,
            score=duration_score,
            explanation=f"Avg {duration:.1f}s connections (streaming range: 1-30s)",
            triggered=duration_triggered
        ))
        total_score += duration_score
        
        # SIGNAL 4: Moderate, Steady Packet Rate
        # LLM streaming has consistent packet flow
        pps = metrics['packets_per_second']
        pps_triggered = (
            self.config.packets_per_second_min <= pps <= self.config.packets_per_second_max
        )
        pps_score = 10 if pps_triggered else 0
        
        signals.append(DetectionSignal(
            name="Packet Rate",
            value=pps,
            threshold=self.config.packets_per_second_min,
            score=pps_score,
            explanation=f"{pps:.1f} packets/sec (steady streaming pattern)",
            triggered=pps_triggered
        ))
        total_score += pps_score
        
        # SIGNAL 5: Timing Regularity
        # Autonomous agents make regular API calls
        regularity = metrics['timing_regularity']
        regularity_triggered = regularity >= self.config.timing_regularity_threshold
        regularity_score = 10 if regularity_triggered else 0
        
        signals.append(DetectionSignal(
            name="Timing Regularity",
            value=regularity,
            threshold=self.config.timing_regularity_threshold,
            score=regularity_score,
            explanation=f"Regularity {regularity:.2f} (automated pattern)",
            triggered=regularity_triggered
        ))
        total_score += regularity_score
        
        # SIGNAL 6: External HTTPS Traffic
        # Many Shadow AI calls go to external APIs
        ext_https_ratio = metrics['external_https_ratio']
        ext_https_triggered = ext_https_ratio > 0.5
        ext_https_score = 5 if ext_https_triggered else 0
        
        signals.append(DetectionSignal(
            name="External HTTPS",
            value=ext_https_ratio,
            threshold=0.5,
            score=ext_https_score,
            explanation=f"{ext_https_ratio*100:.0f}% external HTTPS traffic",
            triggered=ext_https_triggered
        ))
        total_score += ext_https_score
        
        # Determine if this is Shadow AI
        is_shadow_ai = total_score >= self.config.alert_threshold
        
        # Confidence level
        if total_score >= 90:
            confidence = "High"
        elif total_score >= 70:
            confidence = "Medium"
        else:
            confidence = "Low"
        
        # Recommendation
        if is_shadow_ai:
            triggered_signals = [s.name for s in signals if s.triggered]
            recommendation = (
                f"[ALERT] INVESTIGATE: {len(triggered_signals)} signals match Shadow AI pattern. "
                f"Check if {source_ip} is authorized to call external AI APIs. "
                f"Review: {', '.join(triggered_signals[:3])}"
            )
        else:
            recommendation = "[OK] Traffic appears normal - no action needed"
        
        # ---- ML Anomaly Score (if model is trained) ----
        ml_anomaly_result = None
        if self._ml_trained:
            ml_anomaly_result = self.ml_detector.predict_single(source_ip, metrics)
            # Boost score by up to 15 pts if ML also flags it but heuristics didn't
            if ml_anomaly_result.is_anomaly and not is_shadow_ai:
                total_score = min(100, total_score + 15)
                is_shadow_ai = total_score >= self.config.alert_threshold
                if is_shadow_ai:
                    confidence = "Medium"
                    recommendation = (
                        f"[ANOMALY] ML ANOMALY: Heuristics scored {total_score - 15}, but ML model "
                        f"flagged unusual behavior. Top signals: "
                        f"{', '.join(ml_anomaly_result.top_contributing_features)}"
                    )
        
        # Store ML result in metrics for dashboard access
        if ml_anomaly_result:
            metrics['ml_anomaly_score'] = ml_anomaly_result.anomaly_score
            metrics['ml_is_anomaly'] = ml_anomaly_result.is_anomaly
            metrics['ml_top_features'] = ml_anomaly_result.top_contributing_features
            metrics['ml_feature_contributions'] = ml_anomaly_result.feature_contributions
        else:
            metrics['ml_anomaly_score'] = None
            metrics['ml_is_anomaly'] = None
            metrics['ml_top_features'] = []
            metrics['ml_feature_contributions'] = {}

        # ---- Autoencoder Anomaly Score ----
        ae_result = None
        if self._ae_trained:
            ae_result = self.autoencoder.predict_single(source_ip, metrics)
            metrics['ae_reconstruction_error'] = ae_result.reconstruction_error
            metrics['ae_is_anomaly'] = ae_result.is_anomaly
            metrics['ae_threshold'] = ae_result.error_threshold
            metrics['ae_percentile'] = ae_result.anomaly_percentile
            metrics['ae_top_features'] = ae_result.top_anomalous_features
            metrics['ae_feature_errors'] = ae_result.feature_errors
        else:
            metrics['ae_reconstruction_error'] = None
            metrics['ae_is_anomaly'] = None
            metrics['ae_threshold'] = None
            metrics['ae_percentile'] = None
            metrics['ae_top_features'] = []
            metrics['ae_feature_errors'] = {}

        # ---- Threat Intelligence Enrichment ----
        traffic = df[df['source_ip'] == source_ip]
        dest_ips = traffic['destination_ip'].unique().tolist()
        ti_matches = self.threat_intel.enrich_destinations(dest_ips)

        ti_provider = None
        ti_service = None
        ti_risk = None
        ti_data_risk = None
        ti_compliance = []
        if ti_matches:
            # Use the highest-risk match
            best = max(ti_matches.values(), key=lambda m: {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1}.get(m.risk_level, 0))
            ti_provider = best.provider
            ti_service = best.service
            ti_risk = best.risk_level
            ti_data_risk = best.data_risk
            ti_compliance = best.compliance_tags
            # Update recommendation with specific provider info
            if is_shadow_ai:
                recommendation = (
                    f"[CRITICAL] CONFIRMED: Unauthorized **{ti_provider}** ({ti_service}) access detected from {source_ip}. "
                    f"Data risk: {ti_data_risk}. "
                    f"Compliance impact: {', '.join(ti_compliance)}. "
                    f"Triggered signals: {', '.join([s.name for s in signals if s.triggered][:3])}"
                )

        metrics['threat_intel_provider'] = ti_provider
        metrics['threat_intel_service'] = ti_service
        metrics['threat_intel_risk'] = ti_risk
        metrics['threat_intel_data_risk'] = ti_data_risk
        metrics['threat_intel_compliance'] = ti_compliance
        metrics['threat_intel_matches'] = {
            ip: {'provider': m.provider, 'service': m.service, 'risk': m.risk_level}
            for ip, m in ti_matches.items()
        } if ti_matches else {}

        # ---- SHAP values (from ML model) ----
        if ml_anomaly_result and ml_anomaly_result.shap_values:
            metrics['shap_values'] = ml_anomaly_result.shap_values
        else:
            metrics['shap_values'] = None

        return DetectionResult(
            source_ip=source_ip,
            timestamp=datetime.now(),
            total_score=total_score,
            is_shadow_ai=is_shadow_ai,
            confidence=confidence,
            signals=signals,
            metrics=metrics,
            recommendation=recommendation
        )
    
    def explain_result(self, result: DetectionResult) -> str:
        """Generate human-readable explanation of detection result"""
        
        output = []
        output.append("=" * 80)
        output.append(f"SHADOW AI DETECTION REPORT")
        output.append("=" * 80)
        output.append(f"Source IP: {result.source_ip}")
        output.append(f"Timestamp: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Total Score: {result.total_score}/100")
        output.append(f"Classification: {'[ALERT] SHADOW AI DETECTED' if result.is_shadow_ai else '[OK] Normal Traffic'}")
        output.append(f"Confidence: {result.confidence}")
        output.append("")
        
        output.append("SIGNAL BREAKDOWN:")
        output.append("-" * 80)
        for signal in result.signals:
            status = "[Yes]" if signal.triggered else "[No]"
            output.append(f"{status} {signal.name:20} | Score: {signal.score:3}/100 | {signal.explanation}")
        
        output.append("")
        output.append("KEY METRICS:")
        output.append("-" * 80)
        output.append(f"  RX/TX Ratio: {result.metrics['rx_tx_ratio']:.2f}:1")
        output.append(f"  Avg Response Size: {result.metrics['avg_bytes_received']:.0f} bytes")
        output.append(f"  Avg Connection Duration: {result.metrics['avg_connection_duration']:.2f} seconds")
        output.append(f"  Packets per Second: {result.metrics['packets_per_second']:.1f}")
        output.append(f"  Timing Regularity: {result.metrics['timing_regularity']:.2f}")
        output.append(f"  Request Count: {result.metrics['request_count']:.0f}")
        output.append(f"  Unique Destinations: {result.metrics['unique_destinations']:.0f}")
        
        output.append("")
        output.append("RECOMMENDATION:")
        output.append("-" * 80)
        output.append(result.recommendation)
        output.append("=" * 80)
        
        return "\n".join(output)

    def train_ml_model(self, df: pd.DataFrame, all_ips: List[str]):
        """
        Train the ML anomaly detector on feature vectors from all IPs.
        Call this after compute_baseline().
        """
        extractor = FeatureExtractor()
        feature_dicts = []
        for ip in all_ips:
            features = extractor.extract_features(df, ip)
            if features:
                feature_dicts.append(features)
        
        if len(feature_dicts) >= 3:  # Need minimum data
            self.ml_detector.train(feature_dicts)
            self._ml_trained = True
            print(f"[SUCCESS] ML model trained on {len(feature_dicts)} sources")
        else:
            print("[WARNING] Not enough data to train ML model (need >= 3 sources)")

    def train_autoencoder(self, df: pd.DataFrame, all_ips: List[str]):
        """
        Train the autoencoder anomaly detector on feature vectors from all IPs.
        """
        extractor = FeatureExtractor()
        feature_dicts = []
        for ip in all_ips:
            features = extractor.extract_features(df, ip)
            if features:
                feature_dicts.append(features)

        if len(feature_dicts) >= 3:
            stats = self.autoencoder.train(feature_dicts)
            self._ae_trained = True
            return stats
        else:
            print("[WARNING] Not enough data to train autoencoder (need >= 3 sources)")
            return None


if __name__ == "__main__":
    # This will be imported by the main analysis script
    pass