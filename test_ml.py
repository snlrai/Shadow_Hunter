"""Quick smoke test for the ML integration."""
from traffic_simulator import generate_dataset
from detection_engine import ShadowAIDetector, DetectionConfig

df = generate_dataset()
config = DetectionConfig()
det = ShadowAIDetector(config)

# Baseline
normal_ips = df[df['label'] == 'normal']['source_ip'].unique().tolist()
det.compute_baseline(df, normal_ips)

# Train ML
all_ips = df['source_ip'].unique().tolist()
det.train_ml_model(df, all_ips)

# Detect
for ip in all_ips:
    result = det.analyze_traffic(df, ip)
    if result:
        ml_score = result.metrics.get('ml_anomaly_score', 'N/A')
        ml_anomaly = result.metrics.get('ml_is_anomaly', 'N/A')
        print(f"{ip}: score={result.total_score}, shadow_ai={result.is_shadow_ai}, "
              f"ml_score={ml_score}, ml_anomaly={ml_anomaly}")

print("\nDone!")
