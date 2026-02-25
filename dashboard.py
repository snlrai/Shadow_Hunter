# dashboard.py
"""
Shadow AI Detection Dashboard - Consolidated Edition
5-tab layout: Operations | Investigation | AI Models | Strategic Risk | Analyst
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import json
import os
import time
import sqlite3
from traffic_simulator import TrafficSimulator, generate_dataset
from detection_engine import ShadowAIDetector, DetectionConfig
from threat_intel import ThreatIntelEnricher
from incident_manager import IncidentManager
from datetime import datetime, timedelta

# Page config
st.set_page_config(page_title="Shadow AI Hunter", layout="wide")
st.title("Shadow AI Detection Engine")
st.markdown("Multi-signal behavioral detector for unauthorized AI agents")

# Sidebar - Configuration
st.sidebar.header("Detection Configuration")
alert_threshold = st.sidebar.slider("Alert Threshold", min_value=50, max_value=100, value=85, help="Minimum score to trigger alert")
rx_tx_min = st.sidebar.slider("Min RX/TX Ratio", min_value=1.0, max_value=20.0, value=12.0, step=0.5, help="Minimum response-to-request ratio")

# Data Source
st.sidebar.header("Data Source")
_DB_PATH = os.path.join(os.path.dirname(__file__), 'shadow_hunter.db')
_DB_EXISTS = os.path.exists(_DB_PATH)
data_source = st.sidebar.radio("Choose data source:", ["Generate Simulated", "Upload CSV", "Load from Database"], index=2 if _DB_EXISTS else 0)

if data_source == "Generate Simulated":
    if st.sidebar.button("Generate New Data"):
        with st.spinner("Generating traffic data..."):
            df = generate_dataset()
            st.session_state['data'] = df
            st.session_state['data_mode'] = 'simulated'
            st.success(f"[SUCCESS] Generated {len(df)} flow records from {df['source_ip'].nunique()} unique IPs")
elif data_source == "Upload CSV":
    uploaded_file = st.sidebar.file_uploader("Upload VPC Flow Logs CSV", type=['csv'])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.session_state['data'] = df
        st.session_state['data_mode'] = 'csv'
elif data_source == "Load from Database":
    if not _DB_EXISTS:
        st.sidebar.warning("[WARNING] No database found. Run `python run_local.py --sim` first.")
    else:
        if st.sidebar.button("Load from DB") or 'data' not in st.session_state:
            try:
                conn = sqlite3.connect(_DB_PATH)
                events_rows = conn.execute("SELECT data FROM events WHERE event_type = 'flow' ORDER BY timestamp DESC LIMIT 10000").fetchall()
                if events_rows:
                    flows = [json.loads(row[0]) for row in events_rows]
                    df = pd.DataFrame(flows)
                    for col in ['label', 'service_type']:
                        if col not in df.columns:
                            df[col] = 'unknown'
                    st.session_state['data'] = df
                    st.session_state['data_mode'] = 'database'
                    alert_rows = conn.execute("SELECT data FROM events WHERE event_type = 'alert' ORDER BY timestamp DESC LIMIT 500").fetchall()
                    st.session_state['db_alerts'] = [json.loads(r[0]) for r in alert_rows]
                    nodes = conn.execute("SELECT id, labels, properties FROM nodes").fetchall()
                    edges = conn.execute("SELECT source, target, relation, properties FROM edges").fetchall()
                    st.session_state['db_nodes'] = [{"id": n[0], "labels": json.loads(n[1]), "properties": json.loads(n[2])} for n in nodes]
                    st.session_state['db_edges'] = [{"source": e[0], "target": e[1], "relation": e[2], "properties": json.loads(e[3])} for e in edges]
                    conn.close()
                    st.sidebar.success(f"[SUCCESS] Loaded {len(df)} flows, {len(st.session_state['db_alerts'])} alerts from DB")
                else:
                    conn.close()
                    st.sidebar.warning("[WARNING] Database is empty. Run `python run_local.py --sim` first.")
            except Exception as e:
                st.sidebar.error(f"[ERROR] DB Error: {e}")

# Initialize detector
config = DetectionConfig(alert_threshold=alert_threshold, rx_tx_ratio_min=rx_tx_min)
detector = ShadowAIDetector(config)

if 'data' not in st.session_state:
    st.info("Generate simulated data or upload CSV to begin")
    st.stop()

df = st.session_state['data']
normal_ips = df[df['label'] == 'normal']['source_ip'].unique().tolist()
detector.compute_baseline(df, normal_ips)
all_ips_for_training = df['source_ip'].unique().tolist()
detector.train_ml_model(df, all_ips_for_training)
ae_stats = detector.train_autoencoder(df, all_ips_for_training)

# Run detection
results = []
for ip in df['source_ip'].unique():
    result = detector.analyze_traffic(df, ip)
    if result:
        actual_label = df[df['source_ip'] == ip]['label'].iloc[0]
        service_type = df[df['source_ip'] == ip]['service_type'].iloc[0]
        results.append({
            'source_ip': ip, 'service_type': service_type,
            'actual_label': actual_label, 'score': result.total_score,
            'detected': result.is_shadow_ai, 'confidence': result.confidence,
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
col1.metric("Shadow AI Detected", shadow_ai_count)
col2.metric("Total Sources", total_sources)
col3.metric("True Positives", true_positives)
col4.metric("False Positives", false_positives)

precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
recall = true_positives / len(results_df[results_df['actual_label'] == 'shadow_ai']) if len(results_df[results_df['actual_label'] == 'shadow_ai']) > 0 else 0
accuracy = (true_positives + len(results_df[(~results_df['detected']) & (results_df['actual_label'] == 'normal')])) / len(results_df) if len(results_df) > 0 else 0

FIREWALL_FILE = os.path.join(os.path.dirname(__file__), 'firewall_rules.json')

# ============================================================
# 5-TAB LAYOUT
# ============================================================
tab_ops, tab_invest, tab_ai, tab_risk, tab_analyst = st.tabs([
    "Operations Center", "Deep Dive Investigation",
    "AI & Model Internals", "Strategic Risk Overview", "AI Analyst"
])

# ============================================================
# TAB 1: OPERATIONS CENTER
# Merges: Detections, Incidents, Response, Active Defense
# ============================================================
with tab_ops:
    st.subheader("Operations Center")

    # --- Incident Feed ---
    st.markdown("### Incident Feed")
    inc_manager = IncidentManager()
    incidents = inc_manager.correlate(results_df, df)

    if incidents:
        col_i1, col_i2, col_i3 = st.columns(3)
        critical_count = len([i for i in incidents if i.severity == "CRITICAL"])
        high_count = len([i for i in incidents if i.severity == "HIGH"])
        col_i1.metric("Critical Incidents", critical_count)
        col_i2.metric("High Incidents", high_count)
        col_i3.metric("Total Incidents", len(incidents))

        for inc in incidents:
            sev_icon = {"CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}.get(inc.severity, "[INFO]")
            with st.expander(f"{sev_icon} [{inc.incident_id}] {inc.title} | {inc.severity}", expanded=(inc.severity == "CRITICAL")):
                col_h1, col_h2 = st.columns(2)
                col_h1.markdown(f"**Status:** {inc.status} | **Created:** {inc.created_at.strftime('%H:%M:%S')}")
                col_h2.markdown(f"**Tags:** {', '.join([f'`{t}`' for t in inc.tags])}" if inc.tags else "")
                st.info(inc.ioc_summary)
                if inc.kill_chain_stages:
                    st.markdown("**Kill Chain:** " + " → ".join([f"**{s}**" if s in inc.kill_chain_stages else s for s in ["Reconnaissance", "Exploitation", "Command & Control", "Persistence"]]))
                for alert in inc.alerts:
                    st.markdown(f"- **{alert.source_ip}** | Score: {alert.score} | {alert.service_type} | Signals: {', '.join(alert.triggered_signals)}")
                st.markdown("**Actions:** " + " | ".join([f"{i}. {a}" for i, a in enumerate(inc.recommended_actions, 1)]))
    else:
        st.success("[OK] No incidents detected — all traffic appears normal.")

    # --- Detection Results ---
    st.markdown("---")
    st.markdown("### Detection Results")
    show_filter = st.radio("Show:", ["All", "Shadow AI Only", "Normal Only"], horizontal=True)
    if show_filter == "Shadow AI Only":
        display_df = results_df[results_df['detected']]
    elif show_filter == "Normal Only":
        display_df = results_df[~results_df['detected']]
    else:
        display_df = results_df

    for _, row in display_df.iterrows():
        status_icon = "[ALERT]" if row['detected'] else "[OK]"
        correct = "[Correct]" if (row['detected'] and row['actual_label'] == 'shadow_ai') or \
                                 (not row['detected'] and row['actual_label'] == 'normal') else "[Incorrect]"
        with st.expander(f"{status_icon} {row['source_ip']} - {row['service_type']} | Score: {row['score']} | {correct}"):
            result_obj = row['result_object']
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**Signal Breakdown:**")
                if result_obj.signals:
                    for signal in result_obj.signals:
                        status = "[Yes]" if signal.triggered else "[No]"
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

    # --- Response Actions ---
    st.markdown("---")
    st.markdown("### Response Actions")
    if os.path.exists(FIREWALL_FILE):
        with open(FIREWALL_FILE, 'r') as f:
            firewall_rules = json.load(f)
    else:
        firewall_rules = {"blocked_ips": [], "rules": []}

    col_r1, col_r2 = st.columns(2)
    with col_r1:
        st.markdown("#### Block Suspicious IPs")
        detected_threats = results_df[results_df['detected']]
        if len(detected_threats) > 0:
            for _, row in detected_threats.iterrows():
                ip = row['source_ip']
                is_blocked = ip in firewall_rules.get('blocked_ips', [])
                col_ip, col_btn = st.columns([2, 1])
                with col_ip:
                    status = "[BLOCKED] BLOCKED" if is_blocked else "[THREAT] ACTIVE THREAT"
                    st.markdown(f"**{ip}** — {row['service_type']} | Score: {row['score']} | {status}")
                with col_btn:
                    if is_blocked:
                        if st.button(f"Unblock", key=f"unblock_{ip}"):
                            firewall_rules['blocked_ips'].remove(ip)
                            firewall_rules['rules'] = [r for r in firewall_rules['rules'] if r.get('ip') != ip]
                            with open(FIREWALL_FILE, 'w') as f:
                                json.dump(firewall_rules, f, indent=2)
                            st.rerun()
                    else:
                        if st.button(f"Block", key=f"block_{ip}"):
                            firewall_rules['blocked_ips'].append(ip)
                            firewall_rules['rules'].append({
                                'ip': ip, 'action': 'DENY',
                                'reason': f'Shadow AI detected - Score {row["score"]}',
                                'timestamp': datetime.now().isoformat(),
                                'service_type': row['service_type'], 'auto_generated': True
                            })
                            with open(FIREWALL_FILE, 'w') as f:
                                json.dump(firewall_rules, f, indent=2)
                            st.success(f"[SUCCESS] Blocked {ip}")
                            st.rerun()
            unblocked = [ip for ip in detected_threats['source_ip'] if ip not in firewall_rules.get('blocked_ips', [])]
            if unblocked:
                if st.button("Block All Detected Threats", type="primary"):
                    for ip in unblocked:
                        row = detected_threats[detected_threats['source_ip'] == ip].iloc[0]
                        firewall_rules['blocked_ips'].append(ip)
                        firewall_rules['rules'].append({
                            'ip': ip, 'action': 'DENY',
                            'reason': f'Shadow AI detected - Score {row["score"]}',
                            'timestamp': datetime.now().isoformat(),
                            'service_type': row['service_type'], 'auto_generated': True
                        })
                    with open(FIREWALL_FILE, 'w') as f:
                        json.dump(firewall_rules, f, indent=2)
                    st.success(f"[SUCCESS] Blocked {len(unblocked)} threats")
                    st.rerun()
        else:
            st.success("No active threats to block.")

    with col_r2:
        st.markdown("#### Active Firewall Rules")
        if firewall_rules.get('rules'):
            for rule in firewall_rules['rules']:
                action = rule.get('action', 'BLOCK')
                timestamp = rule.get('timestamp', rule.get('blocked_at', 'N/A'))
                st.markdown(f"**{action}** `{rule['ip']}` — {rule.get('reason', 'N/A')} — {timestamp}")
        else:
            st.info("No firewall rules configured.")

    # --- Report Generation ---
    st.markdown("---")
    st.markdown("### Generate Incident Report")
    if st.button("Generate Report", type="primary"):
        report_lines = [
            "# Shadow AI Incident Report",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Engine Version:** v4.0 Consolidated", "",
            "## Executive Summary",
            f"- **Total Sources Analyzed:** {total_sources}",
            f"- **Shadow AI Detected:** {shadow_ai_count}",
            f"- **True Positives:** {true_positives} | **False Positives:** {false_positives}",
            f"- **Precision:** {precision*100:.1f}% | **Recall:** {recall*100:.1f}%", "",
            "## Detected Threats"
        ]
        for _, row in results_df[results_df['detected']].iterrows():
            result_obj = row['result_object']
            report_lines += [
                f"### {row['source_ip']} — {row['service_type']}",
                f"- Score: {row['score']}/100 | Confidence: {row['confidence']}",
                f"- RX/TX: {row['rx_tx_ratio']:.2f}:1 | Avg Received: {row['avg_bytes_received']:.0f}",
                f"- Recommendation: {result_obj.recommendation}", ""
            ]
        report_lines += ["## Remediation", "1. Verify flagged IPs", "2. Review data governance", "3. Segment AI workloads", "4. Deploy DLP", "5. Security awareness training"]
        report_text = "\n".join(report_lines)
        st.download_button("Download Report (Markdown)", data=report_text, file_name=f"shadow_ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", mime="text/markdown")
        st.markdown(report_text)

# ============================================================
# TAB 2: DEEP DIVE INVESTIGATION
# Merges: Analysis, Details, Topology, Kill Chain, Threat Intel
# ============================================================
with tab_invest:
    st.subheader("Deep Dive Investigation")

    # Entity selector
    selected_ip = st.selectbox("Select Source IP to investigate:", results_df['source_ip'].unique())
    ip_result = results_df[results_df['source_ip'] == selected_ip].iloc[0]
    ip_flows = df[df['source_ip'] == selected_ip]
    result_obj = ip_result['result_object']

    # --- Entity Score Card ---
    st.markdown("### Entity Score Card")
    col_s1, col_s2, col_s3, col_s4, col_s5 = st.columns(5)
    col_s1.metric("Detection Score", f"{ip_result['score']}/100")
    col_s2.metric("RX/TX Ratio", f"{ip_result['rx_tx_ratio']:.2f}:1")
    col_s3.metric("Confidence", ip_result['confidence'])
    col_s4.metric("Service", ip_result['service_type'])
    ti_label = ip_result.get('threat_intel_provider') or '—'
    col_s5.metric("Threat Intel", ti_label)

    if ip_result['detected']:
        st.error(f"[ALERT] **SHADOW AI DETECTED** — Score {ip_result['score']}/100")
    else:
        st.success(f"[OK] Normal traffic — Score {ip_result['score']}/100")

    # --- Traffic Analysis ---
    st.markdown("### Traffic Analysis")
    col_t1, col_t2 = st.columns(2)
    with col_t1:
        if 'timestamp' in ip_flows.columns:
            ip_flows_copy = ip_flows.copy()
            ip_flows_copy['timestamp'] = pd.to_datetime(ip_flows_copy['timestamp'])
            fig_timeline = px.scatter(ip_flows_copy, x='timestamp', y='bytes_received', title=f"Traffic Timeline for {selected_ip}", labels={'bytes_received': 'Bytes Received', 'timestamp': 'Time'})
            st.plotly_chart(fig_timeline, use_container_width=True)
    with col_t2:
        fig_rxtx = px.scatter(results_df, x='source_ip', y='rx_tx_ratio', color='detected', size='score', hover_data=['service_type'], title="RX/TX Ratio by Source", labels={'rx_tx_ratio': 'RX/TX Ratio', 'source_ip': 'Source IP'})
        fig_rxtx.add_hline(y=rx_tx_min, line_dash="dash", line_color="orange", annotation_text=f"Threshold: {rx_tx_min}")
        st.plotly_chart(fig_rxtx, use_container_width=True)

    # --- Network Topology (focused on selected IP) ---
    st.markdown("### Network Topology")
    import math

    # Build full graph
    edge_data = df.groupby(['source_ip', 'destination_ip']).agg(
        total_bytes=('bytes_received', 'sum'),
        flow_count=('bytes_received', 'count')
    ).reset_index()
    detected_ips = set(results_df[results_df['detected']]['source_ip'].tolist())

    # Focus mode: show only the selected IP's neighborhood
    focus_mode = st.checkbox("Focus on selected IP only", value=True, key="topo_focus")
    if focus_mode:
        focus_edges = edge_data[
            (edge_data['source_ip'] == selected_ip) |
            (edge_data['destination_ip'] == selected_ip)
        ]
    else:
        focus_edges = edge_data

    G = nx.DiGraph()
    for _, row in focus_edges.iterrows():
        G.add_edge(
            row['source_ip'], row['destination_ip'],
            weight=row['total_bytes'], flows=row['flow_count']
        )

    if G.number_of_nodes() == 0:
        st.info("No connections found for this IP.")
    else:
        # --- Hierarchical layout: sources on left, destinations on right ---
        all_sources = set(focus_edges['source_ip'])
        all_dests = set(focus_edges['destination_ip'])
        only_sources = all_sources - all_dests
        only_dests = all_dests - all_sources
        both = all_sources & all_dests

        pos = {}
        # Place source-only nodes on the left
        src_list = sorted(only_sources)
        for i, node in enumerate(src_list):
            pos[node] = (-1.0, 1.0 - (2.0 * i / max(len(src_list) - 1, 1)))
        # Place destination-only nodes on the right
        dst_list = sorted(only_dests)
        for i, node in enumerate(dst_list):
            pos[node] = (1.0, 1.0 - (2.0 * i / max(len(dst_list) - 1, 1)))
        # Place bidirectional nodes in the center
        both_list = sorted(both)
        for i, node in enumerate(both_list):
            pos[node] = (0.0, 1.0 - (2.0 * i / max(len(both_list) - 1, 1)))

        # --- Build node traces by category for a proper legend ---
        categories = {
            'Shadow AI': {'color': '#EF553B', 'symbol': 'diamond', 'nodes': []},
            'Internal': {'color': '#636EFA', 'symbol': 'circle', 'nodes': []},
            'External': {'color': '#00CC96', 'symbol': 'square', 'nodes': []},
        }
        for node in G.nodes():
            if node in detected_ips:
                categories['Shadow AI']['nodes'].append(node)
            elif node.startswith('10.'):
                categories['Internal']['nodes'].append(node)
            else:
                categories['External']['nodes'].append(node)

        fig_topo = go.Figure()

        # --- Draw edges with width proportional to traffic volume ---
        max_bytes = focus_edges['total_bytes'].max() if len(focus_edges) > 0 else 1
        for _, erow in focus_edges.iterrows():
            src, dst = erow['source_ip'], erow['destination_ip']
            if src not in pos or dst not in pos:
                continue
            x0, y0 = pos[src]
            x1, y1 = pos[dst]
            # Width: 1 to 6 based on log-scaled traffic
            w = 1 + 5 * (math.log1p(erow['total_bytes']) / math.log1p(max_bytes)) if max_bytes > 0 else 2
            fig_topo.add_trace(go.Scatter(
                x=[x0, x1, None], y=[y0, y1, None],
                mode='lines',
                line=dict(width=w, color='rgba(150,150,150,0.4)'),
                hoverinfo='text',
                hovertext=f"{src} -> {dst}<br>{erow['total_bytes']:,.0f} bytes | {erow['flow_count']} flows",
                showlegend=False,
            ))
            # Arrowhead via annotation
            fig_topo.add_annotation(
                x=x1, y=y1, ax=x0, ay=y0,
                xref='x', yref='y', axref='x', ayref='y',
                showarrow=True,
                arrowhead=3, arrowsize=1.2, arrowwidth=max(1, w * 0.6),
                arrowcolor='rgba(150,150,150,0.5)',
                standoff=12,
            )

        # --- Draw nodes by category (gives us a legend) ---
        for cat_name, cat_info in categories.items():
            if not cat_info['nodes']:
                continue
            nx_list = cat_info['nodes']
            n_x = [pos[n][0] for n in nx_list]
            n_y = [pos[n][1] for n in nx_list]
            sizes = [max(18, 10 + G.degree(n) * 5) for n in nx_list]
            hover = []
            for n in nx_list:
                deg_in, deg_out = G.in_degree(n), G.out_degree(n)
                hover.append(
                    f"<b>{n}</b><br>"
                    f"Type: {cat_name}<br>"
                    f"Connections In: {deg_in} | Out: {deg_out}"
                )
            fig_topo.add_trace(go.Scatter(
                x=n_x, y=n_y,
                mode='markers+text',
                marker=dict(
                    size=sizes,
                    color=cat_info['color'],
                    symbol=cat_info['symbol'],
                    line=dict(width=2, color='white'),
                ),
                text=nx_list,
                textposition='top center',
                textfont=dict(size=10, color='white'),
                hoverinfo='text',
                hovertext=hover,
                name=cat_name,
            ))

        fig_topo.update_layout(
            title='Network Traffic Topology',
            showlegend=True,
            legend=dict(
                orientation='h', yanchor='bottom', y=1.02,
                xanchor='center', x=0.5,
                font=dict(size=12),
            ),
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=600,
            template='plotly_dark',
            margin=dict(l=20, r=20, t=60, b=20),
        )
        st.plotly_chart(fig_topo, use_container_width=True)

    col_t1, col_t2, col_t3, col_t4 = st.columns(4)
    col_t1.metric("Total Nodes", G.number_of_nodes())
    col_t2.metric("Total Edges", G.number_of_edges())
    col_t3.metric("Suspicious Nodes", len(detected_ips))
    col_t4.metric("External Endpoints", G.number_of_nodes() - len([n for n in G.nodes() if n.startswith('10.')]))

    # --- Kill Chain (for selected IP if detected) ---
    if ip_result['detected']:
        st.markdown("### Kill Chain Analysis")
        unique_dests = ip_flows['destination_ip'].nunique()
        unique_ports = ip_flows['destination_port'].nunique()
        total_received = ip_flows['bytes_received'].sum()
        ext_ratio = len(ip_flows[~ip_flows['destination_ip'].str.startswith('10.')]) / len(ip_flows) if len(ip_flows) > 0 else 0

        stages = [
            ("Reconnaissance", min(100, unique_dests * 15 + unique_ports * 10), f"{unique_dests} destinations, {unique_ports} ports"),
            ("Weaponization", min(100, int(ext_ratio * 100)), f"{ext_ratio*100:.0f}% external traffic"),
            ("Delivery", min(100, len(ip_flows) * 2), f"{len(ip_flows)} connections"),
            ("Exploitation", min(100, int(ip_result['rx_tx_ratio'] * 4)), f"RX/TX: {ip_result['rx_tx_ratio']:.1f}:1"),
            ("C2 Channel", min(100, int(ip_result['timing_regularity'] * 150)), f"Regularity: {ip_result['timing_regularity']:.2f}"),
            ("Exfiltration", min(100, int(total_received / 5000)), f"{total_received:,.0f} bytes received"),
        ]
        for stage_name, score, detail in stages:
            col_kc1, col_kc2 = st.columns([3, 2])
            with col_kc1:
                st.markdown(f"**{stage_name}** — Confidence: **{score}%**")
                st.progress(score / 100)
            with col_kc2:
                st.caption(detail)
        avg_score = sum(s[1] for s in stages) / len(stages)
        if avg_score >= 70:
            st.error(f"[CRITICAL] Active Shadow AI intrusion (avg: {avg_score:.0f}%)")
        elif avg_score >= 40:
            st.warning(f"[ELEVATED] Suspicious activity (avg: {avg_score:.0f}%)")
        else:
            st.info(f"[LOW] Minimal threat (avg: {avg_score:.0f}%)")

    # --- Threat Intel (for selected IP) ---
    if ip_result.get('threat_intel_provider'):
        st.markdown("### Threat Intelligence")
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown(f"**Provider:** {ip_result['threat_intel_provider']}")
            st.markdown(f"**Service:** {ip_result['threat_intel_service']}")
            st.markdown(f"**Risk Level:** {ip_result['threat_intel_risk']}")
        with col_b:
            st.markdown(f"**Data Risk:**")
            st.warning(ip_result.get('threat_intel_data_risk', 'Unknown'))
            compliance = ip_result.get('threat_intel_compliance', [])
            if compliance:
                st.markdown(f"**Compliance Impact:** {', '.join(compliance)}")
        ti_matches = ip_result.get('threat_intel_matches', {})
        if ti_matches:
            st.markdown("**Matched Destination IPs:**")
            for dest_ip, info in ti_matches.items():
                st.code(f"{dest_ip} → {info['provider']} ({info['service']}) [{info['risk']}]")

    # --- Raw Flow Data ---
    st.markdown("### Raw Flow Data")
    st.markdown(f"**{len(ip_flows)} flows from {selected_ip}**")
    st.dataframe(ip_flows, use_container_width=True)


# ============================================================
# TAB 3: AI & MODEL INTERNALS
# Merges: ML Insights, Deep Learning, SHAP, Signals
# ============================================================
with tab_ai:
    st.subheader("AI & Model Internals")

    # Performance summary
    col_p1, col_p2, col_p3 = st.columns(3)
    col_p1.metric("Precision", f"{precision*100:.1f}%", help="When we alert, how often are we right?")
    col_p2.metric("Recall", f"{recall*100:.1f}%", help="What % of Shadow AI do we catch?")
    col_p3.metric("Accuracy", f"{accuracy*100:.1f}%", help="Overall correctness")

    # --- Signal Configuration ---
    with st.expander("Detection Signal Configuration (Heuristic Engine)"):
        signal_data = {
            'Signal': ['RX/TX Ratio', 'Response Volume', 'Connection Duration', 'Packet Rate', 'Timing Regularity', 'External HTTPS'],
            'Weight': [40, 20, 15, 10, 10, 5],
            'Threshold': [
                f"{config.rx_tx_ratio_min} - {config.rx_tx_ratio_max}",
                f"{config.min_bytes_received} - {config.max_bytes_received} bytes",
                f"{config.connection_duration_min} - {config.connection_duration_max} sec",
                f"{config.packets_per_second_min} - {config.packets_per_second_max} pps",
                f"≥ {config.timing_regularity_threshold}", "> 50%"
            ],
            'Description': ['Response much larger than request', 'Response in LLM size range', 'Streaming response time', 'Steady packet flow', 'Automated agent pattern', 'External API calls']
        }
        signal_df = pd.DataFrame(signal_data)
        st.dataframe(signal_df, use_container_width=True)
        fig_weights = px.bar(signal_df, x='Signal', y='Weight', title="Signal Weights", color='Weight', color_continuous_scale='Reds')
        st.plotly_chart(fig_weights, use_container_width=True)

    # --- Isolation Forest ---
    st.markdown("### Isolation Forest (ML)")
    ml_scores = results_df[results_df['ml_anomaly_score'].notna()]
    if len(ml_scores) > 0:
        col_ml1, col_ml2 = st.columns(2)
        with col_ml1:
            fig_ml_dist = px.histogram(ml_scores, x='ml_anomaly_score', color='actual_label', nbins=15, title="ML Anomaly Score Distribution", labels={'ml_anomaly_score': 'Anomaly Score (lower = more anomalous)'}, color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'})
            fig_ml_dist.add_vline(x=0, line_dash="dash", line_color="red", annotation_text="Decision Boundary")
            st.plotly_chart(fig_ml_dist, use_container_width=True)
        with col_ml2:
            fig_ml_scatter = px.scatter(ml_scores, x='score', y='ml_anomaly_score', color='actual_label', size='rx_tx_ratio', hover_data=['source_ip', 'service_type'], title="Heuristic Score vs ML Score", labels={'score': 'Heuristic Score', 'ml_anomaly_score': 'ML Score'}, color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'})
            fig_ml_scatter.add_hline(y=0, line_dash="dash", line_color="red", annotation_text="ML boundary")
            fig_ml_scatter.add_vline(x=alert_threshold, line_dash="dash", line_color="orange", annotation_text="Heuristic threshold")
            st.plotly_chart(fig_ml_scatter, use_container_width=True)

        # Feature contributions for anomalies
        anomaly_rows = ml_scores[ml_scores['ml_is_anomaly'] == True]
        if len(anomaly_rows) > 0:
            st.markdown("#### ML Feature Contributions (Anomalies)")
            for _, row in anomaly_rows.iterrows():
                contributions = row['ml_feature_contributions']
                if contributions:
                    with st.expander(f"[ANOMALY] {row['source_ip']} — {row['service_type']} (ML Score: {row['ml_anomaly_score']:.3f})"):
                        contrib_df = pd.DataFrame([{'Feature': k.replace('_', ' ').title(), 'Z-Score': v} for k, v in contributions.items()]).sort_values('Z-Score', key=abs, ascending=False)
                        fig_contrib = px.bar(contrib_df, x='Feature', y='Z-Score', title="Feature Deviation (z-score)", color='Z-Score', color_continuous_scale='RdBu_r', color_continuous_midpoint=0)
                        st.plotly_chart(fig_contrib, use_container_width=True)
    else:
        st.warning("ML model not trained yet.")

    # --- Autoencoder ---
    st.markdown("### Deep Autoencoder")
    ae_scores = results_df[results_df['ae_reconstruction_error'].notna()]
    if len(ae_scores) > 0 and ae_stats:
        st.markdown(f"**Architecture:** `{ae_stats.get('architecture', 'N/A')}`")
        col_ae1, col_ae2, col_ae3, col_ae4 = st.columns(4)
        col_ae1.metric("Threshold", f"{ae_stats['threshold']:.6f}")
        col_ae2.metric("Mean Error", f"{ae_stats['mean_error']:.6f}")
        col_ae3.metric("Anomalies", f"{ae_stats['n_anomalies_in_training']}")
        col_ae4.metric("Samples", f"{ae_stats['n_samples']}")

        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            fig_ae_dist = px.histogram(ae_scores, x='ae_reconstruction_error', color='actual_label', nbins=15, title="Autoencoder Reconstruction Error", labels={'ae_reconstruction_error': 'Reconstruction Error (MSE)'}, color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'})
            fig_ae_dist.add_vline(x=ae_stats['threshold'], line_dash="dash", line_color="red", annotation_text="Threshold")
            st.plotly_chart(fig_ae_dist, use_container_width=True)
        with col_dl2:
            fig_ae_scatter = px.scatter(ae_scores, x='score', y='ae_reconstruction_error', color='actual_label', size='rx_tx_ratio', hover_data=['source_ip', 'ae_percentile'], title="Heuristic Score vs AE Error", labels={'score': 'Heuristic Score', 'ae_reconstruction_error': 'Reconstruction Error'}, color_discrete_map={'shadow_ai': '#EF553B', 'normal': '#636EFA'})
            fig_ae_scatter.add_hline(y=ae_stats['threshold'], line_dash="dash", line_color="red", annotation_text="AE Threshold")
            st.plotly_chart(fig_ae_scatter, use_container_width=True)

        # AE feature errors for anomalies
        ae_anomalies = ae_scores[ae_scores['ae_is_anomaly'] == True]
        if len(ae_anomalies) > 0:
            st.markdown("#### AE Feature Reconstruction Errors (Anomalies)")
            for _, row in ae_anomalies.iterrows():
                feat_errors = row['ae_feature_errors']
                if feat_errors:
                    with st.expander(f"[ANOMALY] {row['source_ip']} — {row['service_type']} (Error: {row['ae_reconstruction_error']:.6f} | P{row['ae_percentile']:.1f})"):
                        err_df = pd.DataFrame([{'Feature': k.replace('_', ' ').title(), 'Reconstruction Error': v} for k, v in feat_errors.items()]).sort_values('Reconstruction Error', ascending=False)
                        fig_feat_err = px.bar(err_df, x='Feature', y='Reconstruction Error', title="Per-Feature Error", color='Reconstruction Error', color_continuous_scale='Reds')
                        st.plotly_chart(fig_feat_err, use_container_width=True)

        # Model Agreement
        st.markdown("#### Model Agreement: Isolation Forest vs Autoencoder")
        if 'ml_is_anomaly' in ae_scores.columns:
            both = len(ae_scores[(ae_scores['ml_is_anomaly'] == True) & (ae_scores['ae_is_anomaly'] == True)])
            only_ml = len(ae_scores[(ae_scores['ml_is_anomaly'] == True) & (ae_scores['ae_is_anomaly'] != True)])
            only_ae = len(ae_scores[(ae_scores['ml_is_anomaly'] != True) & (ae_scores['ae_is_anomaly'] == True)])
            neither = len(ae_scores[(ae_scores['ml_is_anomaly'] != True) & (ae_scores['ae_is_anomaly'] != True)])
            col_ag1, col_ag2, col_ag3, col_ag4 = st.columns(4)
            col_ag1.metric("Both: Anomaly", both)
            col_ag2.metric("Only Isolation Forest", only_ml)
            col_ag3.metric("Only Autoencoder", only_ae)
            col_ag4.metric("Both: Normal", neither)
            agreement_rate = (both + neither) / len(ae_scores) * 100 if len(ae_scores) > 0 else 0
            st.progress(agreement_rate / 100)
            st.caption(f"Model agreement rate: **{agreement_rate:.1f}%**")
    else:
        st.warning("Autoencoder not trained yet.")

    # --- SHAP Explainability ---
    st.markdown("### SHAP Explainability")
    shap_rows = results_df[results_df['shap_values'].apply(lambda x: x is not None)]
    if len(shap_rows) > 0:
        st.markdown("#### Global Feature Importance")
        all_shap = pd.DataFrame([row['shap_values'] for _, row in shap_rows.iterrows()])
        mean_abs_shap = all_shap.abs().mean().sort_values(ascending=True)
        fig_global = px.bar(x=mean_abs_shap.values, y=[f.replace('_', ' ').title() for f in mean_abs_shap.index], orientation='h', title="Mean |SHAP Value| — Global Feature Importance", labels={'x': 'Mean |SHAP Value|', 'y': 'Feature'}, color=mean_abs_shap.values, color_continuous_scale='Reds')
        fig_global.update_layout(height=400)
        st.plotly_chart(fig_global, use_container_width=True)

        anomaly_shap = shap_rows[shap_rows['ml_is_anomaly'] == True]
        if len(anomaly_shap) > 0:
            st.markdown("#### Per-IP SHAP Waterfall (Anomalies)")
            for _, row in anomaly_shap.iterrows():
                shap_vals = row['shap_values']
                if shap_vals:
                    with st.expander(f"[ANOMALY] {row['source_ip']} — {row['service_type']} (ML: {row['ml_anomaly_score']:.3f})"):
                        sorted_feats = sorted(shap_vals.items(), key=lambda x: abs(x[1]), reverse=True)
                        feat_names = [f[0].replace('_', ' ').title() for f in sorted_feats]
                        feat_vals = [f[1] for f in sorted_feats]
                        colors = ['#EF553B' if v > 0 else '#636EFA' for v in feat_vals]
                        fig_wf = go.Figure(go.Bar(x=feat_vals, y=feat_names, orientation='h', marker_color=colors, text=[f"{v:+.4f}" for v in feat_vals], textposition='outside'))
                        fig_wf.update_layout(title=f"SHAP for {row['source_ip']}", xaxis_title="SHAP Value", height=400, showlegend=False)
                        fig_wf.add_vline(x=0, line_dash="solid", line_color="gray")
                        st.plotly_chart(fig_wf, use_container_width=True)
                        st.markdown(f"**Top driver:** {sorted_feats[0][0].replace('_', ' ').title()} (SHAP = {sorted_feats[0][1]:+.4f})")

        detected_shap = shap_rows[shap_rows['detected']]
        normal_shap = shap_rows[~shap_rows['detected']]
        if len(detected_shap) > 0 and len(normal_shap) > 0:
            st.markdown("#### SHAP: Detected vs Normal")
            det_avg = pd.DataFrame([r['shap_values'] for _, r in detected_shap.iterrows()]).mean()
            norm_avg = pd.DataFrame([r['shap_values'] for _, r in normal_shap.iterrows()]).mean()
            comp = pd.DataFrame({'Feature': [f.replace('_', ' ').title() for f in det_avg.index], 'Detected': det_avg.values, 'Normal': norm_avg.values})
            fig_comp = go.Figure()
            fig_comp.add_trace(go.Bar(name='Detected', x=comp['Feature'], y=comp['Detected'], marker_color='#EF553B'))
            fig_comp.add_trace(go.Bar(name='Normal', x=comp['Feature'], y=comp['Normal'], marker_color='#636EFA'))
            fig_comp.update_layout(title="Avg SHAP: Detected vs Normal", barmode='group')
            st.plotly_chart(fig_comp, use_container_width=True)
    else:
        st.warning("[WARNING] SHAP values not available. Install `shap` and regenerate data.")


# ============================================================
# TAB 4: STRATEGIC RISK OVERVIEW
# Merges: Risk Heatmap + aggregate analysis
# ============================================================
with tab_risk:
    st.subheader("Strategic Risk Overview")
    st.markdown("CISO-level view of enterprise risk posture across all monitored endpoints.")

    # Compute risk
    risk_data = []
    for _, row in results_df.iterrows():
        base_score = row['score']
        ml_boost = 10 if row.get('ml_is_anomaly') else 0
        ae_boost = 10 if row.get('ae_is_anomaly') else 0
        ti_boost = 15 if row.get('threat_intel_provider') else 0
        risk_score = min(100, base_score + ml_boost + ae_boost + ti_boost)
        risk_data.append({
            'Source IP': row['source_ip'], 'Service Type': row['service_type'],
            'Detection Score': row['score'],
            'ML Anomaly': '[Yes]' if row.get('ml_is_anomaly') else '[No]',
            'DL Anomaly': '[Yes]' if row.get('ae_is_anomaly') else '[No]',
            'Threat Intel': row.get('threat_intel_provider', '—') or '—',
            'Risk Score': risk_score,
            'RX/TX Ratio': round(row['rx_tx_ratio'], 1),
            'Timing Regularity': round(row['timing_regularity'], 2),
        })
    risk_df = pd.DataFrame(risk_data)

    col_r1, col_r2, col_r3, col_r4 = st.columns(4)
    col_r1.metric("Critical Risk (≥90)", len(risk_df[risk_df['Risk Score'] >= 90]))
    col_r2.metric("High Risk (70-89)", len(risk_df[(risk_df['Risk Score'] >= 70) & (risk_df['Risk Score'] < 90)]))
    col_r3.metric("Medium Risk (40-69)", len(risk_df[(risk_df['Risk Score'] >= 40) & (risk_df['Risk Score'] < 70)]))
    col_r4.metric("Low Risk (<40)", len(risk_df[risk_df['Risk Score'] < 40]))

    # Multi-Dimensional Risk Heatmap
    st.markdown("### Multi-Dimensional Risk Matrix")
    heatmap_features = ['Detection Score', 'RX/TX Ratio', 'Timing Regularity', 'Risk Score']
    heatmap_matrix = risk_df.set_index('Source IP')[heatmap_features]
    heatmap_normalized = heatmap_matrix.copy()
    for col in heatmap_features:
        col_max = heatmap_normalized[col].max()
        if col_max > 0:
            heatmap_normalized[col] = heatmap_normalized[col] / col_max
    fig_heatmap = px.imshow(heatmap_normalized.values, x=[f.replace('_', ' ') for f in heatmap_features], y=heatmap_normalized.index, labels=dict(x="Risk Dimension", y="Source IP", color="Risk Level"), title="IP Risk Heatmap (normalized 0-1)", color_continuous_scale="RdYlGn_r", aspect="auto", text_auto=".2f")
    fig_heatmap.update_layout(height=max(300, len(risk_df) * 60))
    st.plotly_chart(fig_heatmap, use_container_width=True)

    # Risk Score Ranking
    st.markdown("### Risk Score Ranking")
    risk_sorted = risk_df.sort_values('Risk Score', ascending=True)
    fig_risk_bar = px.bar(risk_sorted, x='Risk Score', y='Source IP', orientation='h', color='Risk Score', color_continuous_scale='RdYlGn_r', hover_data=['Service Type', 'Threat Intel', 'ML Anomaly', 'DL Anomaly'], title="Risk Score by Source IP")
    fig_risk_bar.add_vline(x=90, line_dash="dash", line_color="red", annotation_text="Critical")
    fig_risk_bar.add_vline(x=70, line_dash="dash", line_color="orange", annotation_text="High")
    fig_risk_bar.update_layout(height=max(300, len(risk_df) * 50))
    st.plotly_chart(fig_risk_bar, use_container_width=True)

    # Score Distribution + Service Breakdown
    st.markdown("### Aggregate Analysis")
    col_agg1, col_agg2 = st.columns(2)
    with col_agg1:
        fig_score = px.histogram(results_df, x='score', color='actual_label', nbins=20, title="Score Distribution by Label", labels={'score': 'Detection Score', 'actual_label': 'Actual Label'})
        fig_score.add_vline(x=alert_threshold, line_dash="dash", line_color="red", annotation_text="Alert Threshold")
        st.plotly_chart(fig_score, use_container_width=True)
    with col_agg2:
        service_counts = results_df['service_type'].value_counts()
        fig_services = px.pie(values=service_counts.values, names=service_counts.index, title="Traffic by Service Type")
        st.plotly_chart(fig_services, use_container_width=True)

    # Threat Intel Provider Distribution (if any enriched)
    enriched = results_df[results_df['threat_intel_provider'].notna()]
    if len(enriched) > 0:
        st.markdown("### AI Provider Distribution")
        col_ti1, col_ti2 = st.columns(2)
        with col_ti1:
            provider_counts = enriched['threat_intel_provider'].value_counts()
            fig_providers = px.pie(values=provider_counts.values, names=provider_counts.index, title="Detected AI Providers", color_discrete_sequence=px.colors.qualitative.Set2)
            st.plotly_chart(fig_providers, use_container_width=True)
        with col_ti2:
            risk_counts = enriched['threat_intel_risk'].value_counts()
            fig_risk_ti = px.bar(x=risk_counts.index, y=risk_counts.values, title="Threat Intel Risk Levels", labels={'x': 'Risk Level', 'y': 'Count'}, color=risk_counts.index, color_discrete_map={'CRITICAL': '#EF553B', 'HIGH': '#FFA15A', 'MEDIUM': '#FECB52'})
            st.plotly_chart(fig_risk_ti, use_container_width=True)

    # Full Risk Table
    st.markdown("### Full Risk Assessment Table")
    st.dataframe(risk_df.sort_values('Risk Score', ascending=False), use_container_width=True, hide_index=True)


# ============================================================
# TAB 5: AI ANALYST
# ============================================================
with tab_analyst:
    st.subheader("Shadow Analyst (AI-Powered)")
    st.markdown("Ask questions about detected threats. The analyst uses detection results and flow data to provide expert-level security analysis.")

    def build_analyst_context():
        context_parts = [
            "=== SHADOW AI DETECTION REPORT ===",
            f"Total Sources: {total_sources} | Detected: {shadow_ai_count}",
            f"Precision: {precision*100:.1f}% | Recall: {recall*100:.1f}% | Accuracy: {accuracy*100:.1f}%", ""
        ]
        for _, row in results_df.iterrows():
            status = "[ALERT] DETECTED" if row['detected'] else "[OK] Normal"
            context_parts.append(f"--- {row['source_ip']} ({row['service_type']}) ---")
            context_parts.append(f"Status: {status} | Score: {row['score']}/100 | Confidence: {row['confidence']}")
            context_parts.append(f"RX/TX: {row['rx_tx_ratio']:.2f}:1 | Avg Recv: {row['avg_bytes_received']:.0f} | Regularity: {row['timing_regularity']:.2f}")
            if row.get('ml_anomaly_score') is not None:
                context_parts.append(f"ML Score: {row['ml_anomaly_score']:.4f} | ML Anomaly: {row['ml_is_anomaly']}")
            if row.get('ae_reconstruction_error') is not None:
                context_parts.append(f"AE Error: {row['ae_reconstruction_error']:.6f} | AE Anomaly: {row['ae_is_anomaly']}")
            result_obj = row['result_object']
            if result_obj.signals:
                triggered = [s for s in result_obj.signals if s.triggered]
                if triggered:
                    context_parts.append(f"Triggered: {', '.join([f'{s.name}({s.score}pts)' for s in triggered])}")
            context_parts.append(f"Recommendation: {result_obj.recommendation}")
            context_parts.append("")
        return "\n".join(context_parts)

    if 'analyst_messages' not in st.session_state:
        st.session_state.analyst_messages = [
            {"role": "assistant", "content": "I'm the Shadow Analyst. I've analyzed your traffic data and I'm ready to answer questions.\n\nTry asking:\n- *Why is 10.0.1.100 suspicious?*\n- *What's the difference between the ML and autoencoder models?*\n- *Summarize the threats for my manager*\n- *What remediation steps should we take?*"}
        ]

    for msg in st.session_state.analyst_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_question = st.chat_input("Ask the Shadow Analyst...")
    if user_question:
        st.session_state.analyst_messages.append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.markdown(user_question)

        context = build_analyst_context()
        analyst_response = None
        try:
            import google.generativeai as genai
            api_key = os.environ.get('GOOGLE_API_KEY') or os.environ.get('GEMINI_API_KEY')
            if api_key:
                genai.configure(api_key=api_key)
                model = genai.GenerativeModel('gemini-2.0-flash')
                system_prompt = f"""You are a Level 3 SOC Analyst specializing in Shadow AI detection.
You are examining VPC Flow Log data. Be concise, use security terminology, reference specific IPs and scores.

CURRENT DATA:
{context}"""
                response = model.generate_content(f"{system_prompt}\n\nUser: {user_question}")
                analyst_response = response.text
        except Exception:
            pass

        if not analyst_response:
            analyst_response = generate_local_analysis(user_question, results_df, df, precision, recall)

        st.session_state.analyst_messages.append({"role": "assistant", "content": analyst_response})
        with st.chat_message("assistant"):
            st.markdown(analyst_response)


def generate_local_analysis(question: str, results_df: pd.DataFrame, flow_df: pd.DataFrame, precision: float, recall: float) -> str:
    question_lower = question.lower()
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
                    signals_text = "\n**Triggered Signals:**\n" + "\n".join([f"- **{s.name}** ({s.score} pts): {s.explanation}" for s in triggered])
            return f"""### Analysis of `{ip}`\n\n**Status:** {status} — Score **{row['score']}/100** ({row['confidence']})\n\n| Metric | Value |\n|---|---|\n| Service | {row['service_type']} |\n| RX/TX Ratio | {row['rx_tx_ratio']:.2f}:1 |\n| Avg Bytes Received | {row['avg_bytes_received']:.0f} |\n| Timing Regularity | {row['timing_regularity']:.2f} |\n| Flows | {len(ip_flows)} |\n{signals_text}\n\n**Recommendation:** {result_obj.recommendation}"""

    if any(w in question_lower for w in ['summarize', 'summary', 'overview', 'manager', 'ciso']):
        detected = results_df[results_df['detected']]
        return f"""### Executive Summary\n\n- **{len(results_df)}** sources analyzed, **{len(detected)}** Shadow AI detected\n- Precision: {precision*100:.1f}% | Recall: {recall*100:.1f}%\n\n**Threats:**\n""" + "\n".join([f"- `{r['source_ip']}` ({r['service_type']}) — Score: {r['score']}" for _, r in detected.iterrows()])

    if any(w in question_lower for w in ['remediat', 'fix', 'action', 'respond', 'mitigat']):
        return """### Remediation Steps\n\n1. Block detected Shadow AI IPs via Operations Center\n2. Audit unauthorized AI tool usage\n3. Create approved AI usage policy\n4. Deploy API gateway for AI API access\n5. Implement egress filtering\n6. Security awareness training\n7. Set up continuous monitoring"""

    if any(w in question_lower for w in ['model', 'autoencoder', 'isolation', 'ml', 'machine learning']):
        return """### Detection Models\n\n| Feature | Isolation Forest | Autoencoder |\n|---|---|---|\n| Type | Tree-based | Neural network |\n| Approach | Isolate anomalies | Reconstruct normal |\n| Signal | Lower = anomalous | Higher error = anomalous |\n| Explainability | Feature z-scores | Per-feature error |\n\nBoth run unsupervised. Check Model Agreement in AI & Model Internals tab."""

    return "Try asking about a specific IP, a summary for your manager, remediation steps, or model comparisons.\n\n*Set `GOOGLE_API_KEY` for AI-powered analysis.*"


# Footer
st.divider()
st.caption("Shadow AI Detection Engine v5.0 Consolidated | Operations • Investigation • AI Models • Strategic Risk • Analyst")

