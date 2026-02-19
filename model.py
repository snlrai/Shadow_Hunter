"""
Shadow AI Anomaly Detection - ML Model Layer
Uses Isolation Forest for unsupervised anomaly detection on VPC flow features.

Design:
  - Trains on ALL traffic (unsupervised) — no labels needed.
  - Anomaly score range: -1 (most anomalous) to +1 (most normal).
  - Integrates with the existing heuristic engine as a hybrid signal.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


# Features the model operates on (must match FeatureExtractor output keys)
MODEL_FEATURES = [
    'rx_tx_ratio',
    'avg_bytes_sent',
    'avg_bytes_received',
    'avg_connection_duration',
    'packets_per_second',
    'timing_regularity',
    'external_https_ratio',
    'requests_per_minute',
    'unique_destinations',
]


@dataclass
class AnomalyResult:
    """Result from the ML anomaly detector for a single source IP."""
    source_ip: str
    anomaly_score: float          # sklearn score: lower = more anomalous
    is_anomaly: bool              # True if Isolation Forest labels it -1
    feature_contributions: Dict[str, float]  # Per-feature deviation from mean
    top_contributing_features: List[str]      # Sorted by contribution
    shap_values: Optional[Dict[str, float]] = None  # SHAP feature attributions


class ShadowAnomalyDetector:
    """
    Wraps sklearn IsolationForest for Shadow AI anomaly detection.
    
    Usage:
        detector = ShadowAnomalyDetector()
        detector.train(feature_matrix)
        result = detector.predict_single(ip, feature_dict)
    """

    def __init__(
        self,
        contamination: float = 0.15,
        n_estimators: int = 200,
        random_state: int = 42,
    ):
        """
        Args:
            contamination: Expected proportion of anomalies (0.15 = 15%).
            n_estimators: Number of trees in the forest.
            random_state: For reproducibility.
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = MODEL_FEATURES
        self.training_means: Optional[np.ndarray] = None
        self.training_stds: Optional[np.ndarray] = None
        self.is_trained: bool = False
        self._shap_explainer = None
        self._shap_background = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train(self, feature_dicts: List[Dict[str, float]]) -> None:
        """
        Train the Isolation Forest on a list of feature dictionaries
        (one per source IP).
        """
        df = pd.DataFrame(feature_dicts)[self.feature_names]
        X = df.values.astype(np.float64)

        # Scale features so that no single feature dominates
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.training_means = self.scaler.mean_
        self.training_stds = self.scaler.scale_

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        # Initialize SHAP explainer (TreeExplainer for IsolationForest)
        if SHAP_AVAILABLE:
            try:
                self._shap_background = X_scaled[:min(50, len(X_scaled))]
                self._shap_explainer = shap.TreeExplainer(
                    self.model,
                    data=self._shap_background,
                    feature_names=self.feature_names,
                )
            except Exception:
                self._shap_explainer = None

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------
    def predict_single(
        self, source_ip: str, feature_dict: Dict[str, float]
    ) -> AnomalyResult:
        """
        Predict whether a single source IP's features are anomalous.
        Returns an AnomalyResult with score, label, and feature contributions.
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() first.")

        # Build feature vector
        x = np.array([[feature_dict.get(f, 0.0) for f in self.feature_names]])
        x_scaled = self.scaler.transform(x)

        # Isolation Forest prediction
        label = self.model.predict(x_scaled)[0]       # -1 = anomaly, 1 = normal
        score = self.model.decision_function(x_scaled)[0]  # lower = more anomalous

        # Feature contributions (z-score based explanation)
        contributions = self._compute_contributions(x_scaled[0])

        # SHAP values (exact feature attributions)
        shap_dict = self.get_shap_values(x_scaled)

        # Sort features by absolute contribution (descending)
        sorted_features = sorted(
            contributions.keys(),
            key=lambda f: abs(contributions[f]),
            reverse=True,
        )

        return AnomalyResult(
            source_ip=source_ip,
            anomaly_score=round(float(score), 4),
            is_anomaly=(label == -1),
            feature_contributions=contributions,
            top_contributing_features=sorted_features[:3],
            shap_values=shap_dict,
        )

    def predict_batch(
        self, feature_dicts: List[Dict[str, float]], source_ips: List[str]
    ) -> List[AnomalyResult]:
        """Predict for multiple IPs at once."""
        return [
            self.predict_single(ip, fd)
            for ip, fd in zip(source_ips, feature_dicts)
        ]

    # ------------------------------------------------------------------
    # Explainability
    # ------------------------------------------------------------------
    def _compute_contributions(self, x_scaled: np.ndarray) -> Dict[str, float]:
        """
        Approximate feature contributions using z-score deviation.
        A feature with |z| > 2 is a strong contributor to anomaly status.
        """
        contributions = {}
        for i, name in enumerate(self.feature_names):
            z = float(x_scaled[i])
            contributions[name] = round(z, 4)
        return contributions

    def get_shap_values(self, x_scaled: np.ndarray) -> Optional[Dict[str, float]]:
        """
        Compute SHAP values for a single (scaled) feature vector.
        Returns a dict mapping feature name → SHAP value, or None if unavailable.
        """
        if self._shap_explainer is None:
            return None
        try:
            sv = self._shap_explainer.shap_values(x_scaled)
            # sv may be a list (multi-output) or 2-D array
            if isinstance(sv, list):
                sv = sv[0]
            vals = sv[0] if sv.ndim == 2 else sv
            return {
                name: round(float(vals[i]), 6)
                for i, name in enumerate(self.feature_names)
            }
        except Exception:
            return None

    def explain_anomaly(self, result: AnomalyResult) -> str:
        """Generate a human-readable explanation for an anomaly result."""
        if not result.is_anomaly:
            return f"✅ {result.source_ip}: Normal traffic (score: {result.anomaly_score:.3f})"

        top = result.top_contributing_features
        explanations = []
        for feat in top:
            z = result.feature_contributions[feat]
            direction = "unusually high" if z > 0 else "unusually low"
            readable = feat.replace('_', ' ').title()
            explanations.append(f"{readable} is {direction} (z={z:.2f})")

        reason_str = "; ".join(explanations)
        return (
            f"⚠️ {result.source_ip}: ANOMALY detected (score: {result.anomaly_score:.3f}). "
            f"Top signals: {reason_str}"
        )
