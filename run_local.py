"""
Shadow Hunter — Unified Local Entry Point
Bootstraps the entire event-driven architecture for local development.

This is the "one command to run everything" entry point that wires up:
  - MemoryBroker (Pub/Sub)
  - SQLiteGraphStore (Persistence)
  - AnalyzerEngine (Hybrid Brain)
  - ActiveProbe (Active Defense)
  - ResponseManager (Auto-Response)
  - Data Ingestion (Simulation or Live)

Usage:
    python run_local.py --sim          # Simulate traffic from CSV
    python run_local.py --sim --reset  # Reset DB and re-simulate
    python run_local.py --live         # Live packet capture (needs Npcap)
"""

import argparse
import logging
import sys
import time
from datetime import datetime

# ── Logging ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-32s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("shadow_hunter.main")

# ── Infrastructure ─────────────────────────────────────────────────────
from pkg.infra.local.broker import MemoryBroker
from pkg.infra.local.sqlite_store import SQLiteGraphStore

# ── Services ───────────────────────────────────────────────────────────
from services.analyzer.engine import AnalyzerEngine
from services.active_defense.interrogator import ActiveProbe
from services.response.manager import ResponseManager

# ── Data Sources ───────────────────────────────────────────────────────
from traffic_simulator import generate_dataset


def banner():
    """Print startup banner."""
    print("""
 ┌──────────────────────────────────────────────────────────┐
 │           SHADOW HUNTER — Unified Architecture         │
 │          Event-Driven • ML • Active Defense              │
 ├──────────────────────────────────────────────────────────┤
 │  Heuristics + Isolation Forest + Autoencoder + JA3       │
 │  SHAP Explainability + Threat Intel + Active Probing     │
 │  Auto-Response + SQLite Graph DB + Streamlit Dashboard   │
 └──────────────────────────────────────────────────────────┘
""")


def run_simulation(broker, engine):
    """
    Generate simulated traffic and push through the event pipeline.

    This exercises the full system: generate → analyze → alert → block.
    """
    logger.info("━━━ PHASE 1: Generating simulated traffic ━━━")
    df = generate_dataset(num_normal_users=20, num_shadow_users=5)
    logger.info("Generated %d flow records from %d IPs",
                len(df), df["source_ip"].nunique())

    # Train ML models on the dataset
    logger.info("━━━ PHASE 2: Training ML models ━━━")
    train_stats = engine.initialize(df)
    logger.info("Training complete: %s", train_stats)

    # Push each flow through the event pipeline
    logger.info("━━━ PHASE 3: Processing flows through event pipeline ━━━")
    all_ips = df["source_ip"].unique().tolist()
    total_flows = 0

    for ip in all_ips:
        ip_traffic = df[df["source_ip"] == ip]
        for _, row in ip_traffic.iterrows():
            flow = row.to_dict()
            # Ensure timestamp is string (JSON-safe)
            if hasattr(flow.get("timestamp"), "isoformat"):
                flow["timestamp"] = flow["timestamp"].isoformat()
            broker.publish("traffic.flow", flow)
            total_flows += 1

        if total_flows % 200 == 0:
            logger.info("Processed %d / %d flows...", total_flows, len(df))

    logger.info("━━━ COMPLETE: %d flows processed ━━━", total_flows)
    return df


def print_summary(engine, probe, response, store):
    """Print a summary of the pipeline run."""
    print("\n" + "=" * 60)
    print("             PIPELINE SUMMARY")
    print("=" * 60)

    e = engine.stats
    print(f"\n   Analyzer Engine")
    print(f"     Flows processed:    {e['flows_processed']}")
    print(f"     Alerts generated:   {e['alerts_generated']}")
    print(f"     JA3 blocks:         {e['ja3_blocks']}")
    print(f"     ML trained:         {e['ml_trained']}")
    print(f"     AE trained:         {e['ae_trained']}")

    p = probe.stats
    print(f"\n   Active Probe")
    print(f"     Probes sent:        {p['probes_sent']}")
    print(f"     AI confirmed:       {p['ai_confirmed']}")
    print(f"     Cached probes:      {p['cached_probes']}")

    r = response.stats
    print(f"\n   Response Manager")
    print(f"     IPs blocked:        {r['blocked_count']}")
    print(f"     Audit entries:      {r['audit_entries']}")
    if r['blocked_ips']:
        for ip in r['blocked_ips']:
            print(f"       ├── {ip}")

    s = store.stats()
    print(f"\n   Graph Store (SQLite)")
    print(f"     Nodes:              {s['nodes']}")
    print(f"     Edges:              {s['edges']}")
    print(f"     Events:             {s['events']}")

    b = broker_ref.stats()
    print(f"\n   Event Broker")
    print(f"     Active topics:      {b['topics']}")
    for topic, count in b['history_sizes'].items():
        print(f"       ├── {topic}: {count} events")

    print("\n" + "=" * 60)
    print(f"    Pipeline finished at {datetime.now().strftime('%H:%M:%S')}")
    print(f"    Database: shadow_hunter.db")
    print(f"    Dashboard: streamlit run dashboard.py")
    print("=" * 60 + "\n")


# Global ref for summary printing
broker_ref = None


def main():
    global broker_ref

    parser = argparse.ArgumentParser(
        description="Shadow Hunter — Unified Architecture Runner"
    )
    parser.add_argument(
        "--sim", action="store_true",
        help="Run with simulated traffic (default if no mode specified)",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Run with live packet capture (requires Npcap/Scapy)",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Reset database before running",
    )
    parser.add_argument(
        "--no-defense", action="store_true",
        help="Disable active probing and auto-response",
    )
    args = parser.parse_args()

    # Default to sim mode
    if not args.sim and not args.live:
        args.sim = True

    banner()

    # ── Step 1: Infrastructure ──────────────────────────────────────
    logger.info("Initializing infrastructure...")
    broker = MemoryBroker(history_size=10000)
    broker_ref = broker

    store = SQLiteGraphStore(db_path="shadow_hunter.db", reset=args.reset)

    # ── Step 2: Services ────────────────────────────────────────────
    logger.info("Initializing services...")
    engine = AnalyzerEngine(
        broker=broker,
        store=store,
        active_defense=not args.no_defense,
    )

    probe = ActiveProbe(
        broker=broker,
        enabled=not args.no_defense,
    )

    response = ResponseManager(
        broker=broker,
        ttl_seconds=3600,
        enabled=not args.no_defense,
    )

    logger.info("All services initialized ✓")

    # ── Step 3: Ingestion ───────────────────────────────────────────
    if args.sim:
        logger.info("Mode: SIMULATION")
        df = run_simulation(broker, engine)
    elif args.live:
        logger.info("Mode: LIVE CAPTURE")
        try:
            from scapy.all import sniff, IP, TCP
            logger.info("Scapy loaded — starting live capture...")
            print("🔴 Live capture not yet wired. Use --sim for now.")
            sys.exit(1)
        except ImportError:
            logger.error("Scapy not installed. Install with: pip install scapy")
            logger.error("Also need Npcap: https://npcap.com")
            sys.exit(1)

    # ── Step 4: Summary ─────────────────────────────────────────────
    print_summary(engine, probe, response, store)

    # Cleanup
    store.close()


if __name__ == "__main__":
    main()
