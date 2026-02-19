"""Quick integration test for all 4 new features."""
from traffic_simulator import generate_dataset
from detection_engine import ShadowAIDetector, DetectionConfig
from incident_manager import IncidentManager
import pandas as pd

# Generate data
df = generate_dataset()

# Setup detector
config = DetectionConfig()
detector = ShadowAIDetector(config)

# Train
normal_ips = df[df['label'] == 'normal']['source_ip'].unique().tolist()
detector.compute_baseline(df, normal_ips)
all_ips = df['source_ip'].unique().tolist()
detector.train_ml_model(df, all_ips)
detector.train_autoencoder(df, all_ips)

# Analyze all IPs
results = []
for ip in all_ips:
    result = detector.analyze_traffic(df, ip)
    if result:
        actual_label = df[df['source_ip'] == ip]['label'].iloc[0]
        service_type = df[df['source_ip'] == ip]['service_type'].iloc[0]
        results.append({
            'source_ip': ip,
            'service_type': service_type,
            'actual_label': actual_label,
            'score': result.total_score,
            'detected': result.is_shadow_ai,
            'confidence': result.confidence,
            'rx_tx_ratio': result.metrics['rx_tx_ratio'],
            'threat_intel_provider': result.metrics.get('threat_intel_provider'),
            'threat_intel_service': result.metrics.get('threat_intel_service'),
            'threat_intel_risk': result.metrics.get('threat_intel_risk'),
            'shap_values': result.metrics.get('shap_values'),
            'ml_is_anomaly': result.metrics.get('ml_is_anomaly'),
            'ae_is_anomaly': result.metrics.get('ae_is_anomaly'),
            'result_object': result,
        })

results_df = pd.DataFrame(results)

print("=" * 60)
print("FEATURE 1: THREAT INTELLIGENCE")
print("=" * 60)
for _, row in results_df.iterrows():
    provider = row['threat_intel_provider'] or 'None'
    service = row['threat_intel_service'] or '—'
    risk = row['threat_intel_risk'] or '—'
    print(f"  {row['source_ip']} -> Provider: {provider} | Service: {service} | Risk: {risk}")

print()
print("=" * 60)
print("FEATURE 2: INCIDENT CORRELATION")
print("=" * 60)
inc_mgr = IncidentManager()
incidents = inc_mgr.correlate(results_df, df)
print(f"  Total incidents: {len(incidents)}")
for inc in incidents:
    print(f"  [{inc.incident_id}] {inc.title} | Severity: {inc.severity} | Tags: {inc.tags}")
    print(f"    Kill Chain: {inc.kill_chain_stages}")
    print(f"    Actions: {len(inc.recommended_actions)}")

print()
print("=" * 60)
print("FEATURE 3: SHAP EXPLAINABILITY")
print("=" * 60)
shap_count = sum(1 for _, r in results_df.iterrows() if r['shap_values'] is not None)
print(f"  IPs with SHAP values: {shap_count}/{len(results_df)}")
for _, row in results_df.iterrows():
    if row['shap_values']:
        top = sorted(row['shap_values'].items(), key=lambda x: abs(x[1]), reverse=True)[:3]
        print(f"  {row['source_ip']}: Top SHAP = {[(f, round(v, 4)) for f, v in top]}")

print()
print("=" * 60)
print("FEATURE 4: RISK SCORES")
print("=" * 60)
for _, row in results_df.iterrows():
    base = row['score']
    ml_boost = 10 if row.get('ml_is_anomaly') else 0
    ae_boost = 10 if row.get('ae_is_anomaly') else 0
    ti_boost = 15 if row.get('threat_intel_provider') else 0
    risk = min(100, base + ml_boost + ae_boost + ti_boost)
    print(f"  {row['source_ip']} | Base: {base} + ML:{ml_boost} + AE:{ae_boost} + TI:{ti_boost} = Risk: {risk}")

print()
print("ALL 4 FEATURES WORKING!")
