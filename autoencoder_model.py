"""
Deep Autoencoder for Shadow AI Anomaly Detection
Uses PyTorch-style architecture implemented in pure NumPy + sklearn
to avoid heavy framework dependencies while demonstrating the concept.

How it works:
  1. Train on ALL traffic features (unsupervised)
  2. The autoencoder learns to compress and reconstruct "normal" patterns
  3. Anomalies have HIGH reconstruction error (the model can't reproduce them)

This is more sophisticated than Isolation Forest because it captures
non-linear feature interactions.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPRegressor
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


AUTOENCODER_FEATURES = [
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
class AutoencoderResult:
    """Result from the autoencoder anomaly detector."""
    source_ip: str
    reconstruction_error: float
    is_anomaly: bool
    error_threshold: float
    feature_errors: Dict[str, float]  # Per-feature reconstruction error
    top_anomalous_features: List[str]
    anomaly_percentile: float  # Where this error falls in the distribution


class ShadowAutoencoder:
    """
    Autoencoder-based anomaly detector using sklearn MLPRegressor
    as the reconstruction model.

    Architecture: Input(9) -> Dense(64) -> Dense(16) -> Dense(4) -> Dense(16) -> Dense(64) -> Output(9)
    The bottleneck (4 neurons) forces the model to learn a compressed representation.
    Normal traffic compresses well; Shadow AI does not.
    """

    def __init__(
        self,
        hidden_layers: Tuple[int, ...] = (64, 16, 4, 16, 64),
        contamination: float = 0.15,
        max_iter: int = 500,
        random_state: int = 42,
    ):
        self.hidden_layers = hidden_layers
        self.contamination = contamination
        self.max_iter = max_iter
        self.random_state = random_state

        self.model: Optional[MLPRegressor] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = AUTOENCODER_FEATURES
        self.error_threshold: float = 0.0
        self.training_errors: Optional[np.ndarray] = None
        self.is_trained: bool = False

    def train(self, feature_dicts: List[Dict[str, float]]) -> Dict[str, float]:
        """
        Train the autoencoder on feature vectors from all IPs.
        Returns training statistics.
        """
        df = pd.DataFrame(feature_dicts)[self.feature_names]
        X = df.values.astype(np.float64)

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Disable early_stopping for small datasets (need at least 2 val samples)
        use_early_stopping = len(X_scaled) >= 14  # 14 * 0.15 = 2.1
        
        # Train autoencoder (input = output for reconstruction)
        self.model = MLPRegressor(
            hidden_layer_sizes=self.hidden_layers,
            activation='relu',
            solver='adam',
            max_iter=self.max_iter,
            random_state=self.random_state,
            early_stopping=use_early_stopping,
            validation_fraction=0.15 if use_early_stopping else 0.0,
            n_iter_no_change=20,
            learning_rate='adaptive',
            learning_rate_init=0.001,
        )

        # Target = Input (autoencoder reconstructs its input)
        self.model.fit(X_scaled, X_scaled)

        # Compute reconstruction errors on training set
        X_reconstructed = self.model.predict(X_scaled)
        self.training_errors = np.mean((X_scaled - X_reconstructed) ** 2, axis=1)

        # Set threshold at the (1 - contamination) percentile
        self.error_threshold = float(np.percentile(
            self.training_errors, (1 - self.contamination) * 100
        ))

        self.is_trained = True

        stats = {
            'n_samples': len(X),
            'mean_error': float(np.mean(self.training_errors)),
            'std_error': float(np.std(self.training_errors)),
            'threshold': self.error_threshold,
            'max_error': float(np.max(self.training_errors)),
            'min_error': float(np.min(self.training_errors)),
            'n_anomalies_in_training': int(np.sum(self.training_errors > self.error_threshold)),
            'architecture': f"Input({len(self.feature_names)}) -> {' -> '.join(map(str, self.hidden_layers))} -> Output({len(self.feature_names)})",
        }

        print(f"✅ Autoencoder trained: {stats['architecture']}")
        print(f"   Threshold: {self.error_threshold:.6f} | Mean error: {stats['mean_error']:.6f}")
        print(f"   Anomalies in training: {stats['n_anomalies_in_training']}/{stats['n_samples']}")

        return stats

    def predict_single(
        self, source_ip: str, feature_dict: Dict[str, float]
    ) -> AutoencoderResult:
        """Predict whether a single source IP is anomalous."""
        if not self.is_trained:
            raise RuntimeError("Autoencoder not trained. Call train() first.")

        # Build feature vector
        x = np.array([[feature_dict.get(f, 0.0) for f in self.feature_names]])
        x_scaled = self.scaler.transform(x)

        # Reconstruct
        x_reconstructed = self.model.predict(x_scaled)

        # Per-feature reconstruction error
        feature_errors = {}
        raw_errors = (x_scaled[0] - x_reconstructed[0]) ** 2
        for i, name in enumerate(self.feature_names):
            feature_errors[name] = float(raw_errors[i])

        # Total reconstruction error (MSE)
        total_error = float(np.mean(raw_errors))

        # Is anomaly?
        is_anomaly = total_error > self.error_threshold

        # Percentile ranking
        if self.training_errors is not None:
            percentile = float(np.mean(self.training_errors < total_error) * 100)
        else:
            percentile = 0.0

        # Top anomalous features (sorted by reconstruction error)
        sorted_features = sorted(
            feature_errors.keys(),
            key=lambda f: feature_errors[f],
            reverse=True
        )

        return AutoencoderResult(
            source_ip=source_ip,
            reconstruction_error=round(total_error, 6),
            is_anomaly=is_anomaly,
            error_threshold=round(self.error_threshold, 6),
            feature_errors={k: round(v, 6) for k, v in feature_errors.items()},
            top_anomalous_features=sorted_features[:3],
            anomaly_percentile=round(percentile, 1),
        )

    def predict_batch(
        self, feature_dicts: List[Dict[str, float]], source_ips: List[str]
    ) -> List[AutoencoderResult]:
        """Predict for multiple IPs."""
        return [
            self.predict_single(ip, fd)
            for ip, fd in zip(source_ips, feature_dicts)
        ]

    def explain_anomaly(self, result: AutoencoderResult) -> str:
        """Human-readable explanation."""
        if not result.is_anomaly:
            return (
                f"✅ {result.source_ip}: Normal (error: {result.reconstruction_error:.6f}, "
                f"threshold: {result.error_threshold:.6f}, "
                f"percentile: {result.anomaly_percentile:.1f}%)"
            )

        top = result.top_anomalous_features
        explanations = []
        for feat in top:
            err = result.feature_errors[feat]
            readable = feat.replace('_', ' ').title()
            explanations.append(f"{readable} (error: {err:.4f})")

        return (
            f"⚠️ {result.source_ip}: ANOMALY (error: {result.reconstruction_error:.6f}, "
            f"threshold: {result.error_threshold:.6f}, "
            f"percentile: {result.anomaly_percentile:.1f}%). "
            f"Top deviations: {'; '.join(explanations)}"
        )
