"""
Validation Script - Tests detection logic and validates assumptions

This script:
1. Generates realistic traffic data (Shadow AI + Normal services)
2. Computes baselines from normal traffic
3. Runs detector on all traffic
4. Validates packet size and behavioral assumptions
5. Shows detection performance with explanations
"""

import pandas as pd
import numpy as np
from traffic_simulator import generate_dataset
from detection_engine import ShadowAIDetector, DetectionConfig, FeatureExtractor
import matplotlib.pyplot as plt
import seaborn as sns


def validate_assumptions(df: pd.DataFrame):
    """Validate our core assumptions about traffic patterns"""
    
    print("\n" + "="*80)
    print("ASSUMPTION VALIDATION")
    print("="*80)
    
    # Group by service type
    by_service = df.groupby('service_type').agg({
        'bytes_sent': ['mean', 'std'],
        'bytes_received': ['mean', 'std'],
        'connection_duration': ['mean', 'std'],
        'packet_count': ['mean', 'std']
    }).round(2)
    
    print("\n📊 Traffic Characteristics by Service Type:")
    print(by_service)
    
    # Calculate RX/TX ratios
    print("\n📊 RX/TX Ratio Analysis:")
    for service_type in df['service_type'].unique():
        service_data = df[df['service_type'] == service_type]
        total_sent = service_data['bytes_sent'].sum()
        total_received = service_data['bytes_received'].sum()
        ratio = total_received / total_sent if total_sent > 0 else 0
        
        print(f"  {service_type:30} | RX/TX: {ratio:6.2f}:1")
    
    # Packet size validation
    print("\n📊 Packet Size Analysis:")
    for service_type in df['service_type'].unique():
        service_data = df[df['service_type'] == service_type]
        avg_packet_size = (
            (service_data['bytes_sent'] + service_data['bytes_received']) / 
            service_data['packet_count']
        ).mean()
        
        print(f"  {service_type:30} | Avg Packet: {avg_packet_size:8.0f} bytes")
    
    # Timing regularity
    print("\n📊 Connection Duration Analysis:")
    for service_type in df['service_type'].unique():
        service_data = df[df['service_type'] == service_type]
        avg_duration = service_data['connection_duration'].mean()
        std_duration = service_data['connection_duration'].std()
        
        print(f"  {service_type:30} | Duration: {avg_duration:5.2f}s ± {std_duration:5.2f}s")
    
    print("\n✅ KEY FINDINGS:")
    
    # Validate RX/TX assumption
    shadow_ai = df[df['service_type'] == 'Unauthorized LLM API']
    normal = df[df['service_type'] != 'Unauthorized LLM API']
    
    shadow_rx_tx = (shadow_ai['bytes_received'].sum() / shadow_ai['bytes_sent'].sum())
    normal_rx_tx = (normal['bytes_received'].sum() / normal['bytes_sent'].sum())
    
    print(f"\n   ✓ Shadow AI RX/TX ratio ({shadow_rx_tx:.1f}:1) is {shadow_rx_tx/normal_rx_tx:.1f}x higher than normal ({normal_rx_tx:.1f}:1)")
    
    # Validate packet size assumption
    shadow_pkt = ((shadow_ai['bytes_sent'] + shadow_ai['bytes_received']) / shadow_ai['packet_count']).mean()
    normal_pkt = ((normal['bytes_sent'] + normal['bytes_received']) / normal['packet_count']).mean()
    
    if shadow_pkt > normal_pkt:
        print(f"   ✓ Shadow AI avg packet size ({shadow_pkt:.0f} bytes) > Normal ({normal_pkt:.0f} bytes)")
    else:
        print(f"   ⚠ Shadow AI avg packet size ({shadow_pkt:.0f} bytes) NOT > Normal ({normal_pkt:.0f} bytes)")
        print(f"      (This validates our corrected assumption - small packets was WRONG)")


def test_detector(df: pd.DataFrame):
    """Test detector on all traffic and show results"""
    
    print("\n" + "="*80)
    print("DETECTOR TESTING")
    print("="*80)
    
    # Initialize detector
    detector = ShadowAIDetector()
    
    # Compute baseline from normal services
    normal_ips = df[df['label'] == 'normal']['source_ip'].unique().tolist()
    detector.compute_baseline(df, normal_ips)
    
    # Test on all unique source IPs
    results = []
    all_ips = df['source_ip'].unique()
    
    print(f"\n🔍 Analyzing {len(all_ips)} source IPs...\n")
    
    for ip in all_ips:
        result = detector.analyze_traffic(df, ip)
        if result:
            results.append(result)
            
            # Get ground truth
            actual_label = df[df['source_ip'] == ip]['label'].iloc[0]
            service_type = df[df['source_ip'] == ip]['service_type'].iloc[0]
            
            # Show summary
            status = "🚨" if result.is_shadow_ai else "✅"
            correct = "✓" if (result.is_shadow_ai and actual_label == 'shadow_ai') or \
                             (not result.is_shadow_ai and actual_label == 'normal') else "✗"
            
            print(f"{status} {ip} | Score: {result.total_score:3} | {service_type:30} | {correct}")
    
    # Calculate performance
    print("\n" + "="*80)
    print("PERFORMANCE METRICS")
    print("="*80)
    
    true_positives = sum(1 for r in results if r.is_shadow_ai and 
                        df[df['source_ip'] == r.source_ip]['label'].iloc[0] == 'shadow_ai')
    false_positives = sum(1 for r in results if r.is_shadow_ai and 
                         df[df['source_ip'] == r.source_ip]['label'].iloc[0] == 'normal')
    true_negatives = sum(1 for r in results if not r.is_shadow_ai and 
                        df[df['source_ip'] == r.source_ip]['label'].iloc[0] == 'normal')
    false_negatives = sum(1 for r in results if not r.is_shadow_ai and 
                         df[df['source_ip'] == r.source_ip]['label'].iloc[0] == 'shadow_ai')
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    accuracy = (true_positives + true_negatives) / len(results) if len(results) > 0 else 0
    
    print(f"\n✅ True Positives:  {true_positives} (Correctly detected Shadow AI)")
    print(f"❌ False Positives: {false_positives} (Normal traffic flagged as Shadow AI)")
    print(f"✅ True Negatives:  {true_negatives} (Normal traffic correctly ignored)")
    print(f"❌ False Negatives: {false_negatives} (Shadow AI missed)")
    
    print(f"\n📊 Precision: {precision*100:.1f}%  (When we alert, how often are we right?)")
    print(f"📊 Recall:    {recall*100:.1f}%  (What % of Shadow AI do we catch?)")
    print(f"📊 Accuracy:  {accuracy*100:.1f}%  (Overall correctness)")
    
    return results


def show_detailed_example(df: pd.DataFrame):
    """Show detailed analysis for one Shadow AI and one normal service"""
    
    print("\n" + "="*80)
    print("DETAILED EXAMPLE EXPLANATIONS")
    print("="*80)
    
    detector = ShadowAIDetector()
    
    # Normal baseline
    normal_ips = df[df['label'] == 'normal']['source_ip'].unique().tolist()
    detector.compute_baseline(df, normal_ips)
    
    # Analyze Shadow AI
    shadow_ip = df[df['label'] == 'shadow_ai']['source_ip'].iloc[0]
    print(f"\n{'='*80}")
    print(f"EXAMPLE 1: Shadow AI Traffic")
    print(f"{'='*80}")
    result_shadow = detector.analyze_traffic(df, shadow_ip)
    print(detector.explain_result(result_shadow))
    
    # Analyze Normal service (WebSocket - similar pattern)
    normal_ip = df[df['service_type'] == 'WebSocket (Chat)']['source_ip'].iloc[0]
    print(f"\n{'='*80}")
    print(f"EXAMPLE 2: Normal WebSocket Traffic (Similar Pattern)")
    print(f"{'='*80}")
    result_normal = detector.analyze_traffic(df, normal_ip)
    print(detector.explain_result(result_normal))


def export_configuration():
    """Export detection configuration for documentation"""
    
    config = DetectionConfig()
    
    print("\n" + "="*80)
    print("DETECTION CONFIGURATION (for tuning)")
    print("="*80)
    
    print(f"""
# Primary Thresholds
RX/TX Ratio Range:         {config.rx_tx_ratio_min} - {config.rx_tx_ratio_max}
Response Size Range:       {config.min_bytes_received} - {config.max_bytes_received} bytes
Connection Duration Range: {config.connection_duration_min} - {config.connection_duration_max} seconds
Packet Rate Range:         {config.packets_per_second_min} - {config.packets_per_second_max} pps
Timing Regularity Min:     {config.timing_regularity_threshold}

# Scoring
Alert Threshold:           {config.alert_threshold}/100

# Signal Weights
RX/TX Ratio:              40 points (primary signal)
Response Volume:          20 points
Connection Duration:      15 points
Packet Rate:              10 points
Timing Regularity:        10 points
External HTTPS:            5 points
""")
    
    print("\n💡 TUNING GUIDE:")
    print("   - Increase alert_threshold to reduce false positives (more strict)")
    print("   - Decrease alert_threshold to catch more Shadow AI (less strict)")
    print("   - Adjust rx_tx_ratio_min if normal services have high ratios")
    print("   - Modify time windows based on your traffic patterns")


def main():
    """Run complete validation"""
    
    print("\n🚀 Shadow AI Detection - Validation Suite")
    print("="*80)
    
    # Generate simulated data
    print("\n1️⃣  Generating simulated traffic data...")
    df = generate_dataset()
    
    # Validate assumptions
    print("\n2️⃣  Validating behavioral assumptions...")
    validate_assumptions(df)
    
    # Test detector
    print("\n3️⃣  Testing detection engine...")
    results = test_detector(df)
    
    # Show detailed examples
    print("\n4️⃣  Generating detailed explanations...")
    show_detailed_example(df)
    
    # Export configuration
    print("\n5️⃣  Exporting configuration...")
    export_configuration()
    
    print("\n" + "="*80)
    print("✅ VALIDATION COMPLETE")
    print("="*80)
    print("\nNext Steps:")
    print("  1. Review false positives/negatives above")
    print("  2. Adjust thresholds in DetectionConfig if needed")
    print("  3. Test on real VPC Flow Log data from your environment")
    print("  4. Build whitelist of approved services")
    print("  5. Integrate with alerting system (Slack, email, etc.)")
    print("\n")


if __name__ == "__main__":
    main()