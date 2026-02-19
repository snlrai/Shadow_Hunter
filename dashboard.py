# dashboard.py
"""
Shadow AI Detection Dashboard - Enterprise Edition
Multi-signal behavioral detection with ML, topology mapping, and agentic response.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import json
import os
import time
from traffic_simulator import TrafficSimulator, generate_dataset
from detection_engine import ShadowAIDetector, DetectionConfig
from threat_intel import ThreatIntelEnricher
from incident_manager import IncidentManager
from datetime import datetime, timedelta

# Page config
st.set_page_config(
    page_title="Shadow AI Hunter",
    page_icon="🕵️",
    layout="wide"
)

# Title
st.title("🕵️ Shadow AI Detection Engine")
st.markdown("Multi-signal behavioral detector for unauthorized AI agents")

# Sidebar - Configuration
st.sidebar.header("⚙️ Detection Configuration")

alert_threshold = st.sidebar.slider(
    "Alert Threshold",
    min_value=50,
    max_value=100,
    value=85,
    help="Minimum score to trigger alert"
)

rx_tx_min = st.sidebar.slider(
    "Min RX/TX Ratio",
    min_value=1.0,
    max_value=20.0,
    value=12.0,
    step=0.5,
    help="Minimum response-to-request ratio"
)

# Generate or upload data
st.sidebar.header("📊 Data Source")
data_source = st.sidebar.radio(
    "Choose data source:",
    ["Generate Simulated", "Upload CSV"]
)

if data_source == "Generate Simulated":
    if st.sidebar.button("🎲 Generate New Data"):
        with st.spinner("Generating traffic data..."):
            df = generate_dataset()
            st.session_state['data'] = df
            st.success(f"✅ Generated {len(df)} flow records from {df['source_ip'].nunique()} unique IPs")
else:
    uploaded_file = st.sidebar.file_uploader("Upload VPC Flow Logs CSV", type=['csv'])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.session_state['data'] = df

# Initialize detector
config = DetectionConfig(
    alert_threshold=alert_threshold,
    rx_tx_ratio_min=rx_tx_min
)
detector = ShadowAIDetector(config)

# Main content
if 'data' not in st.session_state:
    st.info("👈 Generate simulated data or upload CSV to begin")
    st.stop()

df = st.session_state['data']

# Compute baseline
normal_ips = df[df['label'] == 'normal']['source_ip'].unique().tolist()
detector.compute_baseline(df, normal_ips)

# Train ML model on all IPs
all_ips_for_training = df['source_ip'].unique().tolist()
detector.train_ml_model(df, all_ips_for_training)

# Train Autoencoder
ae_stats = detector.train_autoencoder(df, all_ips_for_training)

# Run detection on all sources
results = []
all_ips = df['source_ip'].unique()

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
            'avg_bytes_received': result.metrics['avg_bytes_received'],
            'timing_regularity': result.metrics['timing_regularity'],
            'ml_anomaly_score': result.metrics.get('ml_anomaly_score'),
            'ml_is_anomaly': result.metrics.get('ml_is_anomaly'),
            'ml_top_features': result.metrics.get('ml_top_features', []),
            'ml_feature_contributions': result.metrics.get('ml_feature_contributions', {}),
            'ae_reconstruction_error': result.metrics.get('ae_reconstruction_error'),
            'ae_is_anomaly': result.metrics.get('ae_is_anomaly'),
            'ae_percentile': result.metrics.get('ae_percentile'),
            'ae_top_features': result.metrics.get('ae_top_features', []),
            'ae_feature_errors': result.metrics.get('ae_feature_errors', {}),
            'threat_intel_provider': result.metrics.get('threat_intel_provider'),
            'threat_intel_service': result.metrics.get('threat_intel_service'),
            'threat_intel_risk': result.metrics.get('threat_intel_risk'),
            'threat_intel_data_risk': result.metrics.get('threat_intel_data_risk'),
            'threat_intel_compliance': result.metrics.get('threat_intel_compliance', []),
            'threat_intel_matches': result.metrics.get('threat_intel_matches', {}),
            'shap_values': result.metrics.get('shap_values'),
            'result_object': result
        })

results_df = pd.DataFrame(results)

# Key Metrics Row
col1, col2, col3, col4 = st.columns(4)

shadow_ai_count = len(results_df[results_df['detected']])
total_sources = len(results_df)
true_positives = len(results_df[(results_df['detected']) & (results_df['actual_label'] == 'shadow_ai')])
false_positives = len(results_df[(results_df['detected']) & (results_df['actual_label'] == 'normal')])

col1.metric("🚨 Shadow AI Detected", shadow_ai_count)
col2.metric("📊 Total Sources", total_sources)
col3.metric("✅ True Positives", true_positives)
col4.metric("❌ False Positives", false_positives)

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab_ti, tab_inc, tab_shap, tab_heatmap = st.tabs([
    "🎯 Detections", "📊 Analysis", "🔍 Details", "⚙️ Signals", "🧠 ML Insights",
    "🌐 Topology", "⚔️ Kill Chain", "🛡️ Response", "🧩 Deep Learning", "💬 Analyst",
    "🔍 Threat Intel", "🚨 Incidents", "📊 SHAP Explainability", "🗺️ Risk Heatmap"
])

with tab1:
    st.subheader("Detection Results")
    
    # Filter
    show_filter = st.radio(
        "Show:",
        ["All", "Shadow AI Only", "Normal Only"],
        horizontal=True
    )
    
    if show_filter == "Shadow AI Only":
        display_df = results_df[results_df['detected']]
    elif show_filter == "Normal Only":
        display_df = results_df[~results_df['detected']]
    else:
        display_df = results_df
    
    # Results table
    for _, row in display_df.iterrows():
        status_icon = "🚨" if row['detected'] else "✅"
        correct = "✓" if (row['detected'] and row['actual_label'] == 'shadow_ai') or \
                         (not row['detected'] and row['actual_label'] == 'normal') else "✗"
        
        with st.expander(f"{status_icon} {row['source_ip']} - {row['service_type']} | Score: {row['score']} | {correct}"):
            # Show signal breakdown
            result_obj = row['result_object']
            
            col_a, col_b = st.columns(2)
            
            with col_a:
                st.markdown("**Signal Breakdown:**")
                if result_obj.signals:
                    for signal in result_obj.signals:
                        status = "✓" if signal.triggered else "✗"
                        st.markdown(f"{status} **{signal.name}**: {signal.score} pts")
                        st.caption(signal.explanation)
                else:
                    st.info("Traffic whitelisted - no signal analysis performed")
            
            with col_b:
                st.markdown("**Key Metrics:**")
                st.metric("RX/TX Ratio", f"{result_obj.metrics['rx_tx_ratio']:.2f}:1")
                st.metric("Avg Response", f"{result_obj.metrics['avg_bytes_received']:.0f} bytes")
                st.metric("Regularity", f"{result_obj.metrics['timing_regularity']:.2f}")
                
            st.markdown("**Recommendation:**")
            st.info(result_obj.recommendation)

with tab2:
    st.subheader("Traffic Analysis")
    
    # Score distribution
    fig_score = px.histogram(
        results_df,
        x='score',
        color='actual_label',
        nbins=20,
        title="Score Distribution by Actual Label",
        labels={'score': 'Detection Score', 'actual_label': 'Actual Label'}
    )
    fig_score.add_vline(x=alert_threshold, line_dash="dash", line_color="red",
                        annotation_text="Alert Threshold")
    st.plotly_chart(fig_score, use_container_width=True)
    
    # NEW: Traffic Timeline Visualization
    st.markdown("### 📈 Traffic Timeline")
    col_timeline1, col_timeline2 = st.columns(2)
    
    with col_timeline1:
        # Prepare timeline data
        df_timeline = df.copy()
        df_timeline['timestamp'] = pd.to_datetime(df_timeline['timestamp'])
        
        fig_timeline = px.line(
            df_timeline,
            x='timestamp',
            y='bytes_received',
            color='service_type',
            title="Bytes Received Over Time by Service Type",
            labels={'bytes_received': 'Bytes Received', 'timestamp': 'Time'}
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    
    with col_timeline2:
        fig_timeline_sent = px.line(
            df_timeline,
            x='timestamp',
            y='bytes_sent',
            color='service_type',
            title="Bytes Sent Over Time by Service Type",
            labels={'bytes_sent': 'Bytes Sent', 'timestamp': 'Time'}
        )
        st.plotly_chart(fig_timeline_sent, use_container_width=True)
    
    # NEW: Connection Duration Distribution
    st.markdown("### ⏱️ Connection Duration Patterns")
    col_duration1, col_duration2 = st.columns(2)
    
    with col_duration1:
        fig_duration = px.box(
            df,
            x='service_type',
            y='connection_duration',
            color='service_type',
            title="Connection Duration Distribution by Service Type",
            labels={'connection_duration': 'Duration (seconds)', 'service_type': 'Service Type'}
        )
        fig_duration.add_hline(y=config.connection_duration_min, line_dash="dash", 
                              line_color="orange", annotation_text="Min Threshold")
        fig_duration.add_hline(y=config.connection_duration_max, line_dash="dash", 
                              line_color="red", annotation_text="Max Threshold")
        st.plotly_chart(fig_duration, use_container_width=True)
    
    with col_duration2:
        # Packet count distribution
        fig_packets = px.box(
            df,
            x='service_type',
            y='packet_count',
            color='service_type',
            title="Packet Count Distribution by Service Type",
            labels={'packet_count': 'Packet Count', 'service_type': 'Service Type'}
        )
        st.plotly_chart(fig_packets, use_container_width=True)
    
    # NEW: Behavioral Pattern Comparison
    st.markdown("### 🔬 Behavioral Pattern Comparison")
    
    # Compute statistics by label
    shadow_ai_df = df[df['label'] == 'shadow_ai']
    normal_df = df[df['label'] == 'normal']
    
    comparison_data = {
        'Metric': ['Avg Bytes Sent', 'Avg Bytes Received', 'Avg RX/TX Ratio', 
                   'Avg Connection Duration', 'Avg Packet Count'],
        'Shadow AI': [
            shadow_ai_df['bytes_sent'].mean(),
            shadow_ai_df['bytes_received'].mean(),
            (shadow_ai_df['bytes_received'].sum() / shadow_ai_df['bytes_sent'].sum()) if shadow_ai_df['bytes_sent'].sum() > 0 else 0,
            shadow_ai_df['connection_duration'].mean(),
            shadow_ai_df['packet_count'].mean()
        ],
        'Normal Traffic': [
            normal_df['bytes_sent'].mean(),
            normal_df['bytes_received'].mean(),
            (normal_df['bytes_received'].sum() / normal_df['bytes_sent'].sum()) if normal_df['bytes_sent'].sum() > 0 else 0,
            normal_df['connection_duration'].mean(),
            normal_df['packet_count'].mean()
        ]
    }
    
    comparison_df = pd.DataFrame(comparison_data)
    
    col_comp1, col_comp2 = st.columns([2, 1])
    
    with col_comp1:
        fig_comparison = go.Figure()
        fig_comparison.add_trace(go.Bar(
            name='Shadow AI',
            x=comparison_df['Metric'],
            y=comparison_df['Shadow AI'],
            marker_color='rgb(239, 85, 59)'
        ))
        fig_comparison.add_trace(go.Bar(
            name='Normal Traffic',
            x=comparison_df['Metric'],
            y=comparison_df['Normal Traffic'],
            marker_color='rgb(99, 110, 250)'
        ))
        fig_comparison.update_layout(
            title="Shadow AI vs Normal Traffic - Key Metrics",
            barmode='group',
            xaxis_title="Metric",
            yaxis_title="Value"
        )
        st.plotly_chart(fig_comparison, use_container_width=True)
    
    with col_comp2:
        st.markdown("**Key Differences:**")
        st.metric("RX/TX Ratio Difference", 
                 f"{comparison_df.loc[2, 'Shadow AI'] - comparison_df.loc[2, 'Normal Traffic']:.1f}x",
                 delta=f"{((comparison_df.loc[2, 'Shadow AI'] / comparison_df.loc[2, 'Normal Traffic']) - 1) * 100:.0f}%")
        st.metric("Avg Bytes Received Diff", 
                 f"{comparison_df.loc[1, 'Shadow AI'] - comparison_df.loc[1, 'Normal Traffic']:.0f}",
                 delta=f"{((comparison_df.loc[1, 'Shadow AI'] / comparison_df.loc[1, 'Normal Traffic']) - 1) * 100:.0f}%")
        st.metric("Duration Difference", 
                 f"{comparison_df.loc[3, 'Shadow AI'] - comparison_df.loc[3, 'Normal Traffic']:.1f}s")
    
    # RX/TX Ratio comparison (existing, enhanced)
    st.markdown("### 🎯 RX/TX Ratio Analysis")
    fig_rxtx = px.scatter(
        results_df,
        x='source_ip',
        y='rx_tx_ratio',
        color='detected',
        size='score',
        hover_data=['service_type', 'score'],
        title="RX/TX Ratio by Source (Primary Signal)",
        labels={'rx_tx_ratio': 'RX/TX Ratio', 'source_ip': 'Source IP'}
    )
    fig_rxtx.add_hline(y=rx_tx_min, line_dash="dash", line_color="orange",
                       annotation_text=f"Threshold: {rx_tx_min}")
    st.plotly_chart(fig_rxtx, use_container_width=True)
    
    # NEW: RX/TX Ratio Heatmap
    st.markdown("### 🌡️ RX/TX Ratio Heatmap Over Time")
    
    # Create time bins
    df_heatmap = df.copy()
    df_heatmap['timestamp'] = pd.to_datetime(df_heatmap['timestamp'])
    df_heatmap['time_bin'] = df_heatmap['timestamp'].dt.floor('5min')
    
    # Calculate RX/TX ratio per source per time bin
    heatmap_data = df_heatmap.groupby(['source_ip', 'time_bin']).apply(
        lambda x: x['bytes_received'].sum() / x['bytes_sent'].sum() if x['bytes_sent'].sum() > 0 else 0
    ).reset_index(name='rx_tx_ratio')
    
    # Pivot for heatmap
    heatmap_pivot = heatmap_data.pivot(index='source_ip', columns='time_bin', values='rx_tx_ratio')
    
    fig_heatmap = px.imshow(
        heatmap_pivot,
        labels=dict(x="Time", y="Source IP", color="RX/TX Ratio"),
        title="RX/TX Ratio Heatmap (5-minute bins)",
        color_continuous_scale="RdYlGn_r",
        aspect="auto"
    )
    st.plotly_chart(fig_heatmap, use_container_width=True)
    
    # NEW: Packet Rate Analysis
    st.markdown("### 📦 Packet Rate vs Bytes Analysis")
    
    # Calculate packet rate for each flow
    df_packet_analysis = df.copy()
    df_packet_analysis['packet_rate'] = df_packet_analysis['packet_count'] / df_packet_analysis['connection_duration']
    df_packet_analysis['packet_rate'] = df_packet_analysis['packet_rate'].replace([float('inf'), -float('inf')], 0)
    
    fig_packet_rate = px.scatter(
        df_packet_analysis,
        x='packet_rate',
        y='bytes_received',
        color='service_type',
        size='connection_duration',
        hover_data=['source_ip', 'bytes_sent'],
        title="Packet Rate vs Bytes Received (size = connection duration)",
        labels={'packet_rate': 'Packets per Second', 'bytes_received': 'Bytes Received'}
    )
    st.plotly_chart(fig_packet_rate, use_container_width=True)
    
    # Service type breakdown and Traffic Volume Metrics
    st.markdown("### 📊 Service Breakdown & Traffic Volume")
    col1, col2 = st.columns(2)
    
    with col1:
        service_counts = results_df['service_type'].value_counts()
        fig_services = px.pie(
            values=service_counts.values,
            names=service_counts.index,
            title="Traffic by Service Type"
        )
        st.plotly_chart(fig_services, use_container_width=True)
    
    with col2:
        # NEW: Traffic Volume Metrics
        st.markdown("**Traffic Volume Metrics:**")
        
        volume_by_service = df.groupby('service_type').agg({
            'bytes_sent': 'sum',
            'bytes_received': 'sum',
            'connection_duration': 'mean',
            'packet_count': 'sum'
        }).round(2)
        
        volume_by_service.columns = ['Total Sent (bytes)', 'Total Received (bytes)', 
                                     'Avg Duration (s)', 'Total Packets']
        
        st.dataframe(volume_by_service, use_container_width=True)
        
        # Detection summary
        st.markdown("**Detections by Service Type:**")
        detection_by_service = results_df.groupby('service_type')['detected'].apply(
            lambda x: (x.sum(), len(x))
        ).apply(pd.Series)
        detection_by_service.columns = ['Detected', 'Total']
        st.dataframe(detection_by_service)

with tab3:
    st.subheader("Detailed Flow Data")
    
    # Show underlying flow data
    selected_ip = st.selectbox("Select Source IP:", df['source_ip'].unique())
    
    ip_flows = df[df['source_ip'] == selected_ip]
    
    st.markdown(f"**{len(ip_flows)} flows from {selected_ip}**")
    st.dataframe(ip_flows)
    
    # Flow timeline
    if 'timestamp' in ip_flows.columns:
        ip_flows['timestamp'] = pd.to_datetime(ip_flows['timestamp'])
        fig_timeline = px.scatter(
            ip_flows,
            x='timestamp',
            y='bytes_received',
            title=f"Traffic Timeline for {selected_ip}",
            labels={'bytes_received': 'Bytes Received', 'timestamp': 'Time'}
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

with tab4:
    st.subheader("Signal Configuration")
    
    st.markdown("""
    ### Detection Signals (Weighted Scoring)
    
    The detector combines 6 signals to identify Shadow AI:
    """)
    
    signal_data = {
        'Signal': ['RX/TX Ratio', 'Response Volume', 'Connection Duration', 
                   'Packet Rate', 'Timing Regularity', 'External HTTPS'],
        'Weight': [40, 20, 15, 10, 10, 5],
        'Threshold': [
            f"{config.rx_tx_ratio_min} - {config.rx_tx_ratio_max}",
            f"{config.min_bytes_received} - {config.max_bytes_received} bytes",
            f"{config.connection_duration_min} - {config.connection_duration_max} sec",
            f"{config.packets_per_second_min} - {config.packets_per_second_max} pps",
            f"≥ {config.timing_regularity_threshold}",
            "> 50%"
        ],
        'Description': [
            'Response much larger than request',
            'Response in LLM size range',
            'Streaming response time',
            'Steady packet flow',
            'Automated agent pattern',
            'External API calls'
        ]
    }
    
    signal_df = pd.DataFrame(signal_data)
    st.dataframe(signal_df, use_container_width=True)
    
    # Signal importance chart
    fig_weights = px.bar(
        signal_df,
        x='Signal',
        y='Weight',
        title="Signal Weights in Detection Algorithm",
        color='Weight',
        color_continuous_scale='Reds'
    )
    st.plotly_chart(fig_weights, use_container_width=True)

# Performance summary
st.divider()
st.subheader("📈 Performance Summary")

col1, col2, col3 = st.columns(3)

precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
recall = true_positives / len(results_df[results_df['actual_label'] == 'shadow_ai'])
accuracy = (true_positives + len(results_df[(~results_df['detected']) & (results_df['actual_label'] == 'normal')])) / len(results_df)

col1.metric("Precision", f"{precision*100:.1f}%", help="When we alert, how often are we right?")
col2.metric("Recall", f"{recall*100:.1f}%", help="What % of Shadow AI do we catch?")
col3.metric("Accuracy", f"{accuracy*100:.1f}%", help="Overall correctness")

# ============================
# TAB 5: ML Insights
# ============================
with tab5:
    st.subheader("🧠 ML Anomaly Detection Insights")
    st.markdown("Isolation Forest unsupervised anomaly detection results.")
    
    # ML Score Distribution
    ml_scores = results_df[results_df['ml_anomaly_score'].notna()]
    
    if len(ml_scores) > 0:
        col_ml1, col_ml2 = st.columns(2)
        
        with col_ml1:
            fig_ml_dist = px.histogram(
                ml_scores,
                x='ml_anomaly_score',
                color='actual_label',
                nbins=15,
                title="ML Anomaly Score Distribution",
                labels={'ml_anomaly_score': 'Anomaly Score (lower = more anomalous)', 'actual_label': 'Actual Label'},
                color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'}
            )
            fig_ml_dist.add_vline(x=0, line_dash="dash", line_color="red",
                                  annotation_text="Decision Boundary")
            st.plotly_chart(fig_ml_dist, use_container_width=True)
        
        with col_ml2:
            fig_ml_scatter = px.scatter(
                ml_scores,
                x='score',
                y='ml_anomaly_score',
                color='actual_label',
                size='rx_tx_ratio',
                hover_data=['source_ip', 'service_type'],
                title="Heuristic Score vs ML Anomaly Score",
                labels={'score': 'Heuristic Score', 'ml_anomaly_score': 'ML Score'},
                color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'}
            )
            fig_ml_scatter.add_hline(y=0, line_dash="dash", line_color="red", annotation_text="ML boundary")
            fig_ml_scatter.add_vline(x=alert_threshold, line_dash="dash", line_color="orange", annotation_text="Heuristic threshold")
            st.plotly_chart(fig_ml_scatter, use_container_width=True)
        
        # Feature Contributions for detected anomalies
        st.markdown("### 🔬 Feature Contributions (Why was it flagged?)")
        
        anomaly_rows = ml_scores[ml_scores['ml_is_anomaly'] == True]
        if len(anomaly_rows) > 0:
            for _, row in anomaly_rows.iterrows():
                contributions = row['ml_feature_contributions']
                if contributions:
                    with st.expander(f"⚠️ {row['source_ip']} — {row['service_type']} (ML Score: {row['ml_anomaly_score']:.3f})"):
                        # Bar chart of feature contributions
                        contrib_df = pd.DataFrame([
                            {'Feature': k.replace('_', ' ').title(), 'Z-Score': v}
                            for k, v in contributions.items()
                        ]).sort_values('Z-Score', key=abs, ascending=False)
                        
                        fig_contrib = px.bar(
                            contrib_df,
                            x='Feature',
                            y='Z-Score',
                            title=f"Feature Deviation from Normal (z-score)",
                            color='Z-Score',
                            color_continuous_scale='RdBu_r',
                            color_continuous_midpoint=0
                        )
                        st.plotly_chart(fig_contrib, use_container_width=True)
                        
                        top_feats = row['ml_top_features']
                        if top_feats:
                            st.markdown(f"**Top contributing features:** {', '.join([f.replace('_', ' ').title() for f in top_feats])}")
        else:
            st.info("No ML anomalies detected in the current dataset.")
    else:
        st.warning("ML model has not been trained yet. Generate or upload data first.")

# ============================
# TAB 6: Network Topology
# ============================
with tab6:
    st.subheader("🌐 Network Topology Map")
    st.markdown("Interactive graph showing traffic relationships between hosts. **Red nodes** are detected shadow AI.")

    # Build the graph
    G = nx.DiGraph()

    # Collect edges from raw flow data
    edge_data = df.groupby(['source_ip', 'destination_ip']).agg(
        total_bytes=('bytes_received', 'sum'),
        flow_count=('bytes_received', 'count'),
        avg_duration=('connection_duration', 'mean')
    ).reset_index()

    detected_ips = set(results_df[results_df['detected']]['source_ip'].tolist())

    for _, row in edge_data.iterrows():
        G.add_edge(row['source_ip'], row['destination_ip'], weight=row['total_bytes'], flows=row['flow_count'])

    # Layout
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    # Node traces
    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        # Determine node properties
        if node in detected_ips:
            node_color.append('#EF553B')  # Red for detected
            node_size.append(35)
            label = f"🚨 {node} (SHADOW AI)"
        elif node.startswith('10.'):
            node_color.append('#636EFA')  # Blue for internal
            node_size.append(20)
            label = f"🏢 {node} (Internal)"
        else:
            node_color.append('#00CC96')  # Green for external
            node_size.append(25)
            label = f"🌐 {node} (External)"

        # Add degree info
        in_deg = G.in_degree(node)
        out_deg = G.out_degree(node)
        label += f"<br>In: {in_deg} | Out: {out_deg}"
        node_text.append(label)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[n.split('.')[-1] for n in G.nodes()],
        textposition='top center',
        hovertext=node_text,
        marker=dict(size=node_size, color=node_color, line=dict(width=2, color='white')),
    )

    # Edge traces
    edge_x, edge_y = [], []
    edge_hover = []
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    fig_topo = go.Figure(data=[edge_trace, node_trace],
                         layout=go.Layout(
                             title='Network Traffic Topology',
                             showlegend=False,
                             hovermode='closest',
                             xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                             yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                             height=600,
                             template='plotly_dark'
                         ))
    st.plotly_chart(fig_topo, use_container_width=True)

    # Topology stats
    col_t1, col_t2, col_t3, col_t4 = st.columns(4)
    col_t1.metric("Total Nodes", G.number_of_nodes())
    col_t2.metric("Total Edges", G.number_of_edges())
    col_t3.metric("Suspicious Nodes", len(detected_ips))
    internal_nodes = len([n for n in G.nodes() if n.startswith('10.')])
    col_t4.metric("External Endpoints", G.number_of_nodes() - internal_nodes)

    # Highlight suspicious connections
    st.markdown("### 🔗 Suspicious Connections")
    for ip in detected_ips:
        if ip in G:
            neighbors = list(G.successors(ip))
            external_neighbors = [n for n in neighbors if not n.startswith('10.')]
            if external_neighbors:
                st.warning(f"**{ip}** connects to {len(external_neighbors)} external endpoint(s): {', '.join(external_neighbors)}")

# ============================
# TAB 7: Kill Chain Analysis
# ============================
with tab7:
    st.subheader("⚔️ Kill Chain Analysis")
    st.markdown("Maps detected threats to the **Cyber Kill Chain** lifecycle stages.")

    if len(results_df[results_df['detected']]) > 0:
        for _, row in results_df[results_df['detected']].iterrows():
            ip = row['source_ip']
            result_obj = row['result_object']
            ip_flows = df[df['source_ip'] == ip]

            st.markdown(f"---")
            st.markdown(f"### 🚨 {ip} — {row['service_type']}")

            # Compute kill chain stages
            unique_dests = ip_flows['destination_ip'].nunique()
            unique_ports = ip_flows['destination_port'].nunique()
            total_received = ip_flows['bytes_received'].sum()
            total_sent = ip_flows['bytes_sent'].sum()
            ext_ratio = len(ip_flows[~ip_flows['destination_ip'].str.startswith('10.')]) / len(ip_flows)

            # Stage 1: Reconnaissance
            recon_score = min(100, unique_dests * 15 + unique_ports * 10)
            # Stage 2: Weaponization (external HTTPS)
            weapon_score = min(100, int(ext_ratio * 100))
            # Stage 3: Delivery (connection established)
            delivery_score = min(100, len(ip_flows) * 2)
            # Stage 4: Exploitation (actual API calls — high RX/TX)
            exploit_score = min(100, int(row['rx_tx_ratio'] * 4))
            # Stage 5: Command & Control (timing regularity)
            c2_score = min(100, int(row['timing_regularity'] * 150))
            # Stage 6: Exfiltration (large data received)
            exfil_score = min(100, int(total_received / 5000))

            stages = [
                ("🔍 Reconnaissance", recon_score, f"{unique_dests} destinations, {unique_ports} ports scanned"),
                ("🔧 Weaponization", weapon_score, f"{ext_ratio*100:.0f}% traffic to external endpoints"),
                ("📦 Delivery", delivery_score, f"{len(ip_flows)} connections established"),
                ("💥 Exploitation", exploit_score, f"RX/TX ratio: {row['rx_tx_ratio']:.1f}:1 (LLM inference)"),
                ("📡 C2 Channel", c2_score, f"Timing regularity: {row['timing_regularity']:.2f} (automated)"),
                ("📤 Exfiltration", exfil_score, f"{total_received:,.0f} bytes received from external API"),
            ]

            for stage_name, score, detail in stages:
                col_kc1, col_kc2 = st.columns([3, 2])
                with col_kc1:
                    if score >= 70:
                        color = "🔴"
                    elif score >= 40:
                        color = "🟡"
                    else:
                        color = "🟢"
                    st.markdown(f"{color} **{stage_name}** — Confidence: **{score}%**")
                    st.progress(score / 100)
                with col_kc2:
                    st.caption(detail)

            # Overall threat level
            avg_score = sum(s[1] for s in stages) / len(stages)
            if avg_score >= 70:
                st.error(f"🔴 **CRITICAL**: Active Shadow AI intrusion detected (avg: {avg_score:.0f}%)")
            elif avg_score >= 40:
                st.warning(f"🟡 **ELEVATED**: Suspicious activity detected (avg: {avg_score:.0f}%)")
            else:
                st.info(f"🟢 **LOW**: Minimal threat indicators (avg: {avg_score:.0f}%)")
    else:
        st.success("✅ No threats detected — all traffic appears normal.")

# ============================
# TAB 8: SOAR Response
# ============================
with tab8:
    st.subheader("🛡️ Automated Response (SOAR)")
    st.markdown("Security Orchestration, Automation, and Response — take action on detected threats.")

    FIREWALL_FILE = os.path.join(os.path.dirname(__file__), 'firewall_rules.json')

    # Load existing rules
    if os.path.exists(FIREWALL_FILE):
        with open(FIREWALL_FILE, 'r') as f:
            firewall_rules = json.load(f)
    else:
        firewall_rules = {"blocked_ips": [], "rules": []}

    col_r1, col_r2 = st.columns(2)

    with col_r1:
        st.markdown("### 🚫 Block Suspicious IPs")

        detected_threats = results_df[results_df['detected']]
        if len(detected_threats) > 0:
            for _, row in detected_threats.iterrows():
                ip = row['source_ip']
                is_blocked = ip in firewall_rules.get('blocked_ips', [])

                col_ip, col_btn = st.columns([2, 1])
                with col_ip:
                    status = "🔒 BLOCKED" if is_blocked else "⚠️ ACTIVE THREAT"
                    st.markdown(f"**{ip}** — {row['service_type']} | Score: {row['score']} | {status}")

                with col_btn:
                    if is_blocked:
                        if st.button(f"🔓 Unblock", key=f"unblock_{ip}"):
                            firewall_rules['blocked_ips'].remove(ip)
                            firewall_rules['rules'] = [
                                r for r in firewall_rules['rules'] if r.get('ip') != ip
                            ]
                            with open(FIREWALL_FILE, 'w') as f:
                                json.dump(firewall_rules, f, indent=2)
                            st.rerun()
                    else:
                        if st.button(f"🚫 Block", key=f"block_{ip}"):
                            firewall_rules['blocked_ips'].append(ip)
                            firewall_rules['rules'].append({
                                'ip': ip,
                                'action': 'DENY',
                                'reason': f'Shadow AI detected - Score {row["score"]}',
                                'timestamp': datetime.now().isoformat(),
                                'service_type': row['service_type'],
                                'auto_generated': True
                            })
                            with open(FIREWALL_FILE, 'w') as f:
                                json.dump(firewall_rules, f, indent=2)
                            st.success(f"✅ Blocked {ip} — firewall rule created")
                            st.rerun()
        else:
            st.success("No active threats to block.")

    with col_r2:
        st.markdown("### 📋 Active Firewall Rules")

        if firewall_rules.get('rules'):
            for rule in firewall_rules['rules']:
                st.markdown(f"""
                **{rule['action']}** `{rule['ip']}`
                - Reason: {rule['reason']}
                - Created: {rule['timestamp']}
                """)
        else:
            st.info("No firewall rules configured.")

        # One-click block all
        if len(detected_threats) > 0:
            unblocked = [ip for ip in detected_threats['source_ip']
                         if ip not in firewall_rules.get('blocked_ips', [])]
            if unblocked:
                st.markdown("---")
                if st.button("🚫 Block All Detected Threats", type="primary"):
                    for ip in unblocked:
                        row = detected_threats[detected_threats['source_ip'] == ip].iloc[0]
                        firewall_rules['blocked_ips'].append(ip)
                        firewall_rules['rules'].append({
                            'ip': ip,
                            'action': 'DENY',
                            'reason': f'Shadow AI detected - Score {row["score"]}',
                            'timestamp': datetime.now().isoformat(),
                            'service_type': row['service_type'],
                            'auto_generated': True
                        })
                    with open(FIREWALL_FILE, 'w') as f:
                        json.dump(firewall_rules, f, indent=2)
                    st.success(f"✅ Blocked {len(unblocked)} threats")
                    st.rerun()

    # Incident Report Generation
    st.markdown("---")
    st.markdown("### 📄 Generate Incident Report")

    if st.button("📝 Generate Report", type="primary"):
        report_lines = []
        report_lines.append("# Shadow AI Incident Report")
        report_lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"**Engine Version:** v2.0 Enterprise")
        report_lines.append("")
        report_lines.append("## Executive Summary")
        report_lines.append(f"- **Total Sources Analyzed:** {total_sources}")
        report_lines.append(f"- **Shadow AI Detected:** {shadow_ai_count}")
        report_lines.append(f"- **True Positives:** {true_positives}")
        report_lines.append(f"- **False Positives:** {false_positives}")
        report_lines.append(f"- **Detection Precision:** {precision*100:.1f}%")
        report_lines.append(f"- **Detection Recall:** {recall*100:.1f}%")
        report_lines.append("")
        report_lines.append("## Detected Threats")

        for _, row in results_df[results_df['detected']].iterrows():
            report_lines.append(f"")
            report_lines.append(f"### {row['source_ip']} — {row['service_type']}")
            report_lines.append(f"- **Detection Score:** {row['score']}/100")
            report_lines.append(f"- **Confidence:** {row['confidence']}")
            report_lines.append(f"- **RX/TX Ratio:** {row['rx_tx_ratio']:.2f}:1")
            report_lines.append(f"- **Avg Bytes Received:** {row['avg_bytes_received']:.0f}")

            result_obj = row['result_object']
            report_lines.append(f"- **Recommendation:** {result_obj.recommendation}")
            report_lines.append("")
            report_lines.append("**Triggered Signals:**")
            for sig in result_obj.signals:
                if sig.triggered:
                    report_lines.append(f"  - ✓ {sig.name}: {sig.explanation}")

        report_lines.append("")
        report_lines.append("## Remediation Steps")
        report_lines.append("1. Verify if flagged IPs are authorized to access external AI APIs")
        report_lines.append("2. Review data governance policies for AI tool usage")
        report_lines.append("3. Implement network segmentation for AI-authorized workloads")
        report_lines.append("4. Deploy DLP (Data Loss Prevention) on flagged endpoints")
        report_lines.append("5. Conduct employee awareness training on Shadow AI risks")

        report_text = "\n".join(report_lines)

        st.download_button(
            label="📥 Download Report (Markdown)",
            data=report_text,
            file_name=f"shadow_ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown"
        )
        st.markdown(report_text)

# ============================
# TAB 9: Deep Learning (Autoencoder)
# ============================
with tab9:
    st.subheader("🧩 Deep Autoencoder Insights")
    st.markdown("Neural network autoencoder for non-linear anomaly detection. High reconstruction error = anomaly.")

    ae_scores = results_df[results_df['ae_reconstruction_error'].notna()]

    if len(ae_scores) > 0 and ae_stats:
        # Architecture display
        st.markdown(f"**Architecture:** `{ae_stats.get('architecture', 'N/A')}`")

        col_ae1, col_ae2, col_ae3, col_ae4 = st.columns(4)
        col_ae1.metric("Threshold", f"{ae_stats['threshold']:.6f}")
        col_ae2.metric("Mean Error", f"{ae_stats['mean_error']:.6f}")
        col_ae3.metric("Anomalies Detected", f"{ae_stats['n_anomalies_in_training']}")
        col_ae4.metric("Training Samples", f"{ae_stats['n_samples']}")

        col_dl1, col_dl2 = st.columns(2)

        with col_dl1:
            # Reconstruction error distribution
            fig_ae_dist = px.histogram(
                ae_scores,
                x='ae_reconstruction_error',
                color='actual_label',
                nbins=15,
                title="Autoencoder Reconstruction Error Distribution",
                labels={'ae_reconstruction_error': 'Reconstruction Error (MSE)', 'actual_label': 'Actual Label'},
                color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'}
            )
            fig_ae_dist.add_vline(x=ae_stats['threshold'], line_dash="dash", line_color="red",
                                  annotation_text="Anomaly Threshold")
            st.plotly_chart(fig_ae_dist, use_container_width=True)

        with col_dl2:
            # Heuristic Score vs AE error
            fig_ae_scatter = px.scatter(
                ae_scores,
                x='score',
                y='ae_reconstruction_error',
                color='actual_label',
                size='rx_tx_ratio',
                hover_data=['source_ip', 'service_type', 'ae_percentile'],
                title="Heuristic Score vs Autoencoder Error",
                labels={'score': 'Heuristic Score', 'ae_reconstruction_error': 'Reconstruction Error'},
                color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'}
            )
            fig_ae_scatter.add_hline(y=ae_stats['threshold'], line_dash="dash", line_color="red",
                                     annotation_text="AE Threshold")
            fig_ae_scatter.add_vline(x=alert_threshold, line_dash="dash", line_color="orange",
                                     annotation_text="Heuristic Threshold")
            st.plotly_chart(fig_ae_scatter, use_container_width=True)

        # Per-feature reconstruction errors for anomalies
        st.markdown("### 🔬 Feature Reconstruction Errors (Anomalies)")
        ae_anomalies = ae_scores[ae_scores['ae_is_anomaly'] == True]

        if len(ae_anomalies) > 0:
            for _, row in ae_anomalies.iterrows():
                feat_errors = row['ae_feature_errors']
                if feat_errors:
                    with st.expander(f"⚠️ {row['source_ip']} — {row['service_type']} (Error: {row['ae_reconstruction_error']:.6f} | Percentile: {row['ae_percentile']:.1f}%)"):
                        err_df = pd.DataFrame([
                            {'Feature': k.replace('_', ' ').title(), 'Reconstruction Error': v}
                            for k, v in feat_errors.items()
                        ]).sort_values('Reconstruction Error', ascending=False)

                        fig_feat_err = px.bar(
                            err_df,
                            x='Feature',
                            y='Reconstruction Error',
                            title="Per-Feature Reconstruction Error",
                            color='Reconstruction Error',
                            color_continuous_scale='Reds'
                        )
                        st.plotly_chart(fig_feat_err, use_container_width=True)

                        top_feats = row['ae_top_features']
                        if top_feats:
                            st.markdown(f"**Top deviating features:** {', '.join([f.replace('_', ' ').title() for f in top_feats])}")
        else:
            st.info("No autoencoder anomalies detected.")

        # Model comparison: Isolation Forest vs Autoencoder
        st.markdown("### ⚖️ Model Agreement Analysis")
        if 'ml_is_anomaly' in ae_scores.columns:
            both_anomaly = len(ae_scores[(ae_scores['ml_is_anomaly'] == True) & (ae_scores['ae_is_anomaly'] == True)])
            only_ml = len(ae_scores[(ae_scores['ml_is_anomaly'] == True) & (ae_scores['ae_is_anomaly'] != True)])
            only_ae = len(ae_scores[(ae_scores['ml_is_anomaly'] != True) & (ae_scores['ae_is_anomaly'] == True)])
            neither = len(ae_scores[(ae_scores['ml_is_anomaly'] != True) & (ae_scores['ae_is_anomaly'] != True)])

            col_ag1, col_ag2, col_ag3, col_ag4 = st.columns(4)
            col_ag1.metric("🔴 Both Agree: Anomaly", both_anomaly)
            col_ag2.metric("🟡 Only Isolation Forest", only_ml)
            col_ag3.metric("🟡 Only Autoencoder", only_ae)
            col_ag4.metric("🟢 Both Agree: Normal", neither)

            agreement_rate = (both_anomaly + neither) / len(ae_scores) * 100 if len(ae_scores) > 0 else 0
            st.progress(agreement_rate / 100)
            st.caption(f"Model agreement rate: **{agreement_rate:.1f}%**")
    else:
        st.warning("Autoencoder has not been trained yet. Generate or upload data first.")

# ============================
# TAB 10: GenAI Shadow Analyst
# ============================
with tab10:
    st.subheader("💬 Shadow Analyst (AI-Powered)")
    st.markdown("Ask questions about detected threats. The analyst uses detection results and flow data to provide expert-level security analysis.")

    # Build context for the analyst
    def build_analyst_context():
        """Build a structured context string from current detection results."""
        context_parts = []
        context_parts.append("=== SHADOW AI DETECTION REPORT ===")
        context_parts.append(f"Total Sources: {total_sources}")
        context_parts.append(f"Shadow AI Detected: {shadow_ai_count}")
        context_parts.append(f"Precision: {precision*100:.1f}% | Recall: {recall*100:.1f}% | Accuracy: {accuracy*100:.1f}%")
        context_parts.append("")

        for _, row in results_df.iterrows():
            status = "🚨 DETECTED" if row['detected'] else "✅ Normal"
            context_parts.append(f"--- {row['source_ip']} ({row['service_type']}) ---")
            context_parts.append(f"Status: {status} | Score: {row['score']}/100 | Confidence: {row['confidence']}")
            context_parts.append(f"RX/TX Ratio: {row['rx_tx_ratio']:.2f}:1 | Avg Bytes Received: {row['avg_bytes_received']:.0f}")
            context_parts.append(f"Timing Regularity: {row['timing_regularity']:.2f}")

            if row.get('ml_anomaly_score') is not None:
                context_parts.append(f"ML Score: {row['ml_anomaly_score']:.4f} | ML Anomaly: {row['ml_is_anomaly']}")
            if row.get('ae_reconstruction_error') is not None:
                context_parts.append(f"AE Error: {row['ae_reconstruction_error']:.6f} | AE Anomaly: {row['ae_is_anomaly']}")

            result_obj = row['result_object']
            if result_obj.signals:
                triggered = [s for s in result_obj.signals if s.triggered]
                if triggered:
                    context_parts.append(f"Triggered Signals: {', '.join([f'{s.name}({s.score}pts)' for s in triggered])}")
            context_parts.append(f"Recommendation: {result_obj.recommendation}")
            context_parts.append("")

        return "\n".join(context_parts)

    # Initialize chat
    if 'analyst_messages' not in st.session_state:
        st.session_state.analyst_messages = [
            {"role": "assistant", "content": "👋 I'm the Shadow Analyst. I've analyzed your traffic data and I'm ready to answer questions.\n\nTry asking:\n- *Why is 10.0.1.100 suspicious?*\n- *What's the difference between the ML and autoencoder models?*\n- *Summarize the threats for my manager*\n- *What remediation steps should we take?*"}
        ]

    # Display chat messages
    for msg in st.session_state.analyst_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    user_question = st.chat_input("Ask the Shadow Analyst...")

    if user_question:
        # Add user message
        st.session_state.analyst_messages.append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.markdown(user_question)

        # Build response using detection context
        context = build_analyst_context()

        # Try to use Gemini API if available
        analyst_response = None
        try:
            import google.generativeai as genai

            api_key = os.environ.get('GOOGLE_API_KEY') or os.environ.get('GEMINI_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel('gemini-2.0-flash')

                system_prompt = f"""You are a Level 3 SOC (Security Operations Center) Analyst specializing in Shadow AI detection.
You are examining VPC Flow Log data from a corporate network. Your job is to explain findings clearly.

CURRENT DETECTION DATA:
{context}

RULES:
- Be concise but thorough
- Use security terminology correctly
- Reference specific IPs, scores, and signals from the data
- When asked about an IP, reference its specific metrics
- Suggest concrete remediation steps
- Format responses with markdown for readability"""

                response = model.generate_content(f"{system_prompt}\n\nUser question: {user_question}")
                analyst_response = response.text
        except Exception:
            pass

        # Fallback: rule-based analyst if no API key
        if not analyst_response:
            analyst_response = generate_local_analysis(user_question, results_df, df)

        st.session_state.analyst_messages.append({"role": "assistant", "content": analyst_response})
        with st.chat_message("assistant"):
            st.markdown(analyst_response)


def generate_local_analysis(question: str, results_df: pd.DataFrame, flow_df: pd.DataFrame) -> str:
    """Rule-based fallback analyst when no LLM API is available."""
    question_lower = question.lower()

    # Check if asking about a specific IP
    for _, row in results_df.iterrows():
        if row['source_ip'] in question:
            ip = row['source_ip']
            ip_flows = flow_df[flow_df['source_ip'] == ip]
            status = "**DETECTED as Shadow AI**" if row['detected'] else "classified as **normal**"

            signals_text = ""
            result_obj = row['result_object']
            if result_obj.signals:
                triggered = [s for s in result_obj.signals if s.triggered]
                if triggered:
                    signals_text = "\n**Triggered Signals:**\n" + "\n".join(
                        [f"- ✓ **{s.name}** ({s.score} pts): {s.explanation}" for s in triggered]
                    )

            return f"""### Analysis of `{ip}`

**Status:** {status} with a score of **{row['score']}/100** ({row['confidence']} confidence)

**Key Metrics:**
| Metric | Value |
|---|---|
| Service Type | {row['service_type']} |
| RX/TX Ratio | {row['rx_tx_ratio']:.2f}:1 |
| Avg Bytes Received | {row['avg_bytes_received']:.0f} |
| Timing Regularity | {row['timing_regularity']:.2f} |
| Total Flows | {len(ip_flows)} |
{signals_text}

**Recommendation:** {result_obj.recommendation}"""

    # General questions
    if any(word in question_lower for word in ['summarize', 'summary', 'overview', 'manager', 'ciso']):
        detected = results_df[results_df['detected']]
        return f"""### 📋 Executive Summary

**Shadow AI Detection Results:**
- **{len(results_df)}** network sources analyzed
- **{len(detected)}** Shadow AI instances detected
- **Detection Precision:** {precision*100:.1f}%
- **Detection Recall:** {recall*100:.1f}%

**Detected Threats:**
""" + "\n".join([f"- 🚨 `{r['source_ip']}` ({r['service_type']}) — Score: {r['score']}/100" for _, r in detected.iterrows()]) + """

**Risk Assessment:** Unauthorized AI API usage detected in the network. These endpoints are communicating with external AI services, potentially exposing proprietary data.

**Recommended Actions:**
1. Investigate flagged IPs to verify authorization status
2. Implement network-level controls for AI API endpoints
3. Review data governance policies
4. Deploy DLP on flagged endpoints"""

    if any(word in question_lower for word in ['remediat', 'fix', 'action', 'respond', 'mitigat']):
        return """### 🛡️ Remediation Steps

1. **Immediate:** Block detected Shadow AI IPs via the Response tab
2. **Short-term:** Audit which employees/services are using unauthorized AI tools
3. **Policy:** Create an approved AI usage policy with sanctioned tools
4. **Technical:** Deploy API gateway to monitor and control AI API access
5. **Network:** Implement egress filtering for known AI provider IP ranges
6. **Training:** Conduct security awareness training on Shadow AI risks
7. **Monitoring:** Set up continuous monitoring with this detection engine"""

    if any(word in question_lower for word in ['model', 'autoencoder', 'isolation', 'ml', 'machine learning']):
        return """### 🧠 Detection Models Comparison

| Feature | Isolation Forest | Deep Autoencoder |
|---|---|---|
| **Type** | Tree-based ensemble | Neural network |
| **Approach** | Isolates anomalies via random splits | Learns to reconstruct normal patterns |
| **Strength** | Fast, interpretable | Captures non-linear relationships |
| **Signal** | Anomaly score (lower = anomalous) | Reconstruction error (higher = anomalous) |
| **Explainability** | Feature z-scores | Per-feature reconstruction error |

Both models run **unsupervised** (no labels needed) and are combined with the **6-signal heuristic engine** for maximum detection accuracy. Check the **Model Agreement** section in the Deep Learning tab to see where they agree and disagree."""

    return f"""I can help with specific questions about your traffic data. Try asking:
- **About a specific IP:** "Why is 10.0.1.100 suspicious?"
- **Summaries:** "Summarize findings for my manager"
- **Models:** "Explain the difference between detection models"
- **Actions:** "What remediation steps should we take?"

💡 *Tip: Set `GOOGLE_API_KEY` or `GEMINI_API_KEY` environment variable to enable AI-powered analysis with Google Gemini.*"""


# ============================
# TAB 11: Threat Intelligence
# ============================
with tab_ti:
    st.subheader("🔍 Threat Intelligence Enrichment")
    st.markdown("Cross-references destination IPs against a database of **known AI service providers** to identify exactly which AI service is being used.")

    # Enrichment summary
    enriched = results_df[results_df['threat_intel_provider'].notna()]
    not_enriched = results_df[results_df['threat_intel_provider'].isna()]

    col_ti1, col_ti2, col_ti3 = st.columns(3)
    col_ti1.metric("🔴 AI Services Identified", len(enriched))
    col_ti2.metric("🟢 No AI Match", len(not_enriched))
    col_ti3.metric("📡 Unique Providers", enriched['threat_intel_provider'].nunique() if len(enriched) > 0 else 0)

    if len(enriched) > 0:
        st.markdown("### 🚨 Identified AI Service Usage")
        for _, row in enriched.iterrows():
            risk = row['threat_intel_risk']
            risk_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(risk, "⚪")
            detected_badge = "🚨 DETECTED" if row['detected'] else "✅ NORMAL"
            
            with st.expander(f"{risk_color} {row['source_ip']} → **{row['threat_intel_provider']}** ({row['threat_intel_service']}) | {detected_badge}"):
                col_a, col_b = st.columns(2)
                with col_a:
                    st.markdown(f"**Provider:** {row['threat_intel_provider']}")
                    st.markdown(f"**Service:** {row['threat_intel_service']}")
                    st.markdown(f"**Risk Level:** {risk_color} {risk}")
                    st.markdown(f"**Category:** AI API")
                    st.markdown(f"**Detection Score:** {row['score']}/100")
                with col_b:
                    st.markdown(f"**Data Risk:**")
                    st.warning(row.get('threat_intel_data_risk', 'Unknown'))
                    compliance = row.get('threat_intel_compliance', [])
                    if compliance:
                        st.markdown(f"**Compliance Impact:** {', '.join(compliance)}")

                # Show matched IP destinations
                ti_matches = row.get('threat_intel_matches', {})
                if ti_matches:
                    st.markdown("**Matched Destination IPs:**")
                    for dest_ip, info in ti_matches.items():
                        st.code(f"{dest_ip} → {info['provider']} ({info['service']}) [{info['risk']}]")

        # Provider breakdown chart
        st.markdown("### 📊 AI Provider Distribution")
        provider_counts = enriched['threat_intel_provider'].value_counts()
        fig_providers = px.pie(
            values=provider_counts.values,
            names=provider_counts.index,
            title="Detected AI Service Providers",
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        st.plotly_chart(fig_providers, use_container_width=True)

        # Risk level distribution
        risk_counts = enriched['threat_intel_risk'].value_counts()
        fig_risk = px.bar(
            x=risk_counts.index,
            y=risk_counts.values,
            title="Threat Intelligence Risk Levels",
            labels={'x': 'Risk Level', 'y': 'Count'},
            color=risk_counts.index,
            color_discrete_map={'CRITICAL': '#EF553B', 'HIGH': '#FFA15A', 'MEDIUM': '#FECB52'}
        )
        st.plotly_chart(fig_risk, use_container_width=True)
    else:
        st.success("✅ No traffic matched known AI service provider IP ranges.")

    # Show the database
    with st.expander("📋 Threat Intelligence Database (Known AI Providers)"):
        enricher = ThreatIntelEnricher()
        providers = enricher.get_all_providers()
        st.markdown(f"**{len(providers)} providers tracked:** {', '.join(providers)}")
        st.caption("IP ranges are matched using CIDR notation. In production, this would be a continuously updated threat feed.")

# ============================
# TAB 12: Incidents
# ============================
with tab_inc:
    st.subheader("🚨 Incident Correlation")
    st.markdown("Groups individual alerts into **correlated incidents** — showing connected attack chains rather than isolated events.")

    # Run correlation
    inc_manager = IncidentManager()
    incidents = inc_manager.correlate(results_df, df)

    if incidents:
        # Summary metrics
        col_i1, col_i2, col_i3, col_i4 = st.columns(4)
        critical_count = len([i for i in incidents if i.severity == "CRITICAL"])
        high_count = len([i for i in incidents if i.severity == "HIGH"])
        col_i1.metric("🔴 Critical Incidents", critical_count)
        col_i2.metric("🟠 High Incidents", high_count)
        col_i3.metric("📋 Total Incidents", len(incidents))
        col_i4.metric("⚔️ Kill Chain Matches", len([i for i in incidents if "Kill-Chain-Progression" in i.tags]))

        for inc in incidents:
            sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(inc.severity, "⚪")
            with st.expander(f"{sev_icon} [{inc.incident_id}] {inc.title} | Severity: {inc.severity}", expanded=(inc.severity == "CRITICAL")):
                # Header
                col_h1, col_h2, col_h3 = st.columns(3)
                col_h1.markdown(f"**Status:** {inc.status}")
                col_h2.markdown(f"**Created:** {inc.created_at.strftime('%H:%M:%S')}")
                col_h3.markdown(f"**Tags:** {', '.join([f'`{t}`' for t in inc.tags])}" if inc.tags else "")

                # IoC Summary
                st.markdown("#### 📋 Indicator of Compromise")
                st.info(inc.ioc_summary)

                # Kill Chain Stages
                if inc.kill_chain_stages:
                    st.markdown("#### ⚔️ Kill Chain Stages Detected")
                    all_stages = ["Reconnaissance", "Exploitation", "Command & Control", "Persistence"]
                    for stage in all_stages:
                        if stage in inc.kill_chain_stages:
                            st.markdown(f"  🔴 **{stage}** — Confirmed")
                        else:
                            st.markdown(f"  ⚪ {stage} — Not detected")

                # Alerts
                st.markdown("#### 🔔 Associated Alerts")
                for alert in inc.alerts:
                    st.markdown(f"- **{alert.source_ip}** | Score: {alert.score} | {alert.service_type} | Signals: {', '.join(alert.triggered_signals)}")

                # Recommended Actions
                st.markdown("#### 🛡️ Recommended Actions")
                for i, action in enumerate(inc.recommended_actions, 1):
                    st.markdown(f"{i}. {action}")
    else:
        st.success("✅ No incidents detected — all traffic appears normal.")

# ============================
# TAB 13: SHAP Explainability
# ============================
with tab_shap:
    st.subheader("📊 SHAP Explainability")
    st.markdown("**SHAP (SHapley Additive exPlanations)** provides mathematically exact feature attributions for each ML prediction. Unlike z-scores, SHAP values show the *actual contribution* of each feature to the model's decision.")

    # Check if any SHAP values are available
    shap_rows = results_df[results_df['shap_values'].apply(lambda x: x is not None)]

    if len(shap_rows) > 0:
        # Global SHAP summary
        st.markdown("### 🌍 Global Feature Importance (SHAP)")
        st.markdown("Average |SHAP value| across all predictions — shows which features matter most.")

        # Aggregate SHAP values
        all_shap = pd.DataFrame([row['shap_values'] for _, row in shap_rows.iterrows()])
        mean_abs_shap = all_shap.abs().mean().sort_values(ascending=True)

        fig_global = px.bar(
            x=mean_abs_shap.values,
            y=[f.replace('_', ' ').title() for f in mean_abs_shap.index],
            orientation='h',
            title="Mean |SHAP Value| — Global Feature Importance",
            labels={'x': 'Mean |SHAP Value|', 'y': 'Feature'},
            color=mean_abs_shap.values,
            color_continuous_scale='Reds'
        )
        fig_global.update_layout(height=400)
        st.plotly_chart(fig_global, use_container_width=True)

        # Per-IP SHAP waterfall
        st.markdown("### 🔬 Per-IP SHAP Waterfall")
        st.markdown("Select an IP to see exactly **why** the ML model made its decision.")

        anomaly_shap = shap_rows[shap_rows['ml_is_anomaly'] == True]
        if len(anomaly_shap) > 0:
            for _, row in anomaly_shap.iterrows():
                shap_vals = row['shap_values']
                if shap_vals:
                    with st.expander(f"⚠️ {row['source_ip']} — {row['service_type']} (ML Score: {row['ml_anomaly_score']:.3f})"):
                        # Waterfall chart
                        sorted_feats = sorted(shap_vals.items(), key=lambda x: abs(x[1]), reverse=True)
                        feat_names = [f[0].replace('_', ' ').title() for f in sorted_feats]
                        feat_vals = [f[1] for f in sorted_feats]

                        colors = ['#EF553B' if v > 0 else '#636EFA' for v in feat_vals]

                        fig_waterfall = go.Figure(go.Bar(
                            x=feat_vals,
                            y=feat_names,
                            orientation='h',
                            marker_color=colors,
                            text=[f"{v:+.4f}" for v in feat_vals],
                            textposition='outside'
                        ))
                        fig_waterfall.update_layout(
                            title=f"SHAP Values for {row['source_ip']}",
                            xaxis_title="SHAP Value (impact on model output)",
                            yaxis_title="Feature",
                            height=400,
                            showlegend=False
                        )
                        fig_waterfall.add_vline(x=0, line_dash="solid", line_color="gray")
                        st.plotly_chart(fig_waterfall, use_container_width=True)

                        st.markdown("**Interpretation:**")
                        st.markdown("- 🔴 **Red bars** push the prediction toward *anomaly*")
                        st.markdown("- 🔵 **Blue bars** push the prediction toward *normal*")
                        st.markdown(f"- **Top driver:** {sorted_feats[0][0].replace('_', ' ').title()} (SHAP = {sorted_feats[0][1]:+.4f})")
        else:
            st.info("No ML anomalies found in this dataset. SHAP values are most informative for detected anomalies.")

        # SHAP: Detected vs Normal comparison
        st.markdown("### ⚖️ SHAP: Detected vs Normal")
        detected_shap = shap_rows[shap_rows['detected']]
        normal_shap = shap_rows[~shap_rows['detected']]

        if len(detected_shap) > 0 and len(normal_shap) > 0:
            det_avg = pd.DataFrame([r['shap_values'] for _, r in detected_shap.iterrows()]).mean()
            norm_avg = pd.DataFrame([r['shap_values'] for _, r in normal_shap.iterrows()]).mean()

            comparison = pd.DataFrame({
                'Feature': [f.replace('_', ' ').title() for f in det_avg.index],
                'Detected (avg SHAP)': det_avg.values,
                'Normal (avg SHAP)': norm_avg.values
            })

            fig_comp = go.Figure()
            fig_comp.add_trace(go.Bar(name='Detected', x=comparison['Feature'], y=comparison['Detected (avg SHAP)'], marker_color='#EF553B'))
            fig_comp.add_trace(go.Bar(name='Normal', x=comparison['Feature'], y=comparison['Normal (avg SHAP)'], marker_color='#636EFA'))
            fig_comp.update_layout(title="Average SHAP Values: Detected vs Normal", barmode='group', xaxis_title="Feature", yaxis_title="Avg SHAP Value")
            st.plotly_chart(fig_comp, use_container_width=True)
    else:
        st.warning("⚠️ SHAP values not available. Install the `shap` package (`pip install shap`) and regenerate data.")

# ============================
# TAB 14: Risk Heatmap
# ============================
with tab_heatmap:
    st.subheader("🗺️ Enterprise Risk Heatmap")
    st.markdown("A **CISO-level overview** showing risk across all monitored IPs at a glance. Red = high risk, Green = low risk.")

    # Compute risk score for each IP
    risk_data = []
    for _, row in results_df.iterrows():
        # Multi-dimensional risk score (0-100)
        base_score = row['score']
        
        # Boost for ML/AE agreement
        ml_boost = 10 if row.get('ml_is_anomaly') else 0
        ae_boost = 10 if row.get('ae_is_anomaly') else 0
        
        # Boost for threat intel match
        ti_boost = 15 if row.get('threat_intel_provider') else 0
        
        risk_score = min(100, base_score + ml_boost + ae_boost + ti_boost)
        
        risk_data.append({
            'Source IP': row['source_ip'],
            'Service Type': row['service_type'],
            'Detection Score': row['score'],
            'ML Anomaly': '✓' if row.get('ml_is_anomaly') else '✗',
            'DL Anomaly': '✓' if row.get('ae_is_anomaly') else '✗',
            'Threat Intel': row.get('threat_intel_provider', '—') or '—',
            'Risk Score': risk_score,
            'RX/TX Ratio': round(row['rx_tx_ratio'], 1),
            'Timing Regularity': round(row['timing_regularity'], 2),
        })

    risk_df = pd.DataFrame(risk_data)

    # Risk summary
    col_r1, col_r2, col_r3, col_r4 = st.columns(4)
    critical_risk = len(risk_df[risk_df['Risk Score'] >= 90])
    high_risk = len(risk_df[(risk_df['Risk Score'] >= 70) & (risk_df['Risk Score'] < 90)])
    medium_risk = len(risk_df[(risk_df['Risk Score'] >= 40) & (risk_df['Risk Score'] < 70)])
    low_risk = len(risk_df[risk_df['Risk Score'] < 40])

    col_r1.metric("🔴 Critical Risk", critical_risk)
    col_r2.metric("🟠 High Risk", high_risk)
    col_r3.metric("🟡 Medium Risk", medium_risk)
    col_r4.metric("🟢 Low Risk", low_risk)

    # Heatmap: IP vs Risk Dimensions
    st.markdown("### 🌡️ Multi-Dimensional Risk Matrix")

    # Build the matrix for heatmap
    heatmap_features = ['Detection Score', 'RX/TX Ratio', 'Timing Regularity', 'Risk Score']
    heatmap_matrix = risk_df.set_index('Source IP')[heatmap_features]
    
    # Normalize each column to 0-1 for visual consistency
    heatmap_normalized = heatmap_matrix.copy()
    for col in heatmap_features:
        col_max = heatmap_normalized[col].max()
        if col_max > 0:
            heatmap_normalized[col] = heatmap_normalized[col] / col_max

    fig_heatmap = px.imshow(
        heatmap_normalized.values,
        x=[f.replace('_', ' ') for f in heatmap_features],
        y=heatmap_normalized.index,
        labels=dict(x="Risk Dimension", y="Source IP", color="Risk Level"),
        title="IP Risk Heatmap (normalized 0-1)",
        color_continuous_scale="RdYlGn_r",
        aspect="auto",
        text_auto=".2f"
    )
    fig_heatmap.update_layout(height=max(300, len(risk_df) * 60))
    st.plotly_chart(fig_heatmap, use_container_width=True)

    # Risk Score bar chart
    st.markdown("### 📊 Risk Score Ranking")
    risk_sorted = risk_df.sort_values('Risk Score', ascending=True)
    
    fig_risk_bar = px.bar(
        risk_sorted,
        x='Risk Score',
        y='Source IP',
        orientation='h',
        color='Risk Score',
        color_continuous_scale='RdYlGn_r',
        hover_data=['Service Type', 'Threat Intel', 'ML Anomaly', 'DL Anomaly'],
        title="Risk Score by Source IP"
    )
    fig_risk_bar.add_vline(x=90, line_dash="dash", line_color="red", annotation_text="Critical")
    fig_risk_bar.add_vline(x=70, line_dash="dash", line_color="orange", annotation_text="High")
    fig_risk_bar.update_layout(height=max(300, len(risk_df) * 50))
    st.plotly_chart(fig_risk_bar, use_container_width=True)

    # Detailed table
    st.markdown("### 📋 Full Risk Assessment Table")
    st.dataframe(
        risk_df.sort_values('Risk Score', ascending=False),
        use_container_width=True,
        hide_index=True
    )


# Footer
st.divider()
st.caption("Shadow AI Detection Engine v3.0 Enterprise | Built with Streamlit + ML + Deep Learning + SHAP + Threat Intel + SOAR")
