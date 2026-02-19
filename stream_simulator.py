"""
Real-Time Traffic Stream Simulator
Writes batches of flow logs to stream.json every interval,
simulating a live VPC Flow Log feed.

Usage:
    python stream_simulator.py            # Default: 0.5s interval
    python stream_simulator.py --attack   # Inject attack halfway through

The dashboard reads this file to show live-updating charts.
"""

import json
import time
import random
import os
import argparse
from datetime import datetime, timedelta
from traffic_simulator import TrafficSimulator


STREAM_FILE = os.path.join(os.path.dirname(__file__), 'stream.json')
FIREWALL_FILE = os.path.join(os.path.dirname(__file__), 'firewall_rules.json')


def get_blocked_ips():
    """Read current firewall rules to skip blocked IPs."""
    if os.path.exists(FIREWALL_FILE):
        with open(FIREWALL_FILE, 'r') as f:
            rules = json.load(f)
            return set(rules.get('blocked_ips', []))
    return set()


def run_stream(interval: float = 0.5, duration: int = 120, inject_attack: bool = False):
    """
    Simulate a real-time flow log stream.

    Args:
        interval: seconds between each batch write
        duration: total seconds to run
        inject_attack: if True, introduce Shadow AI traffic at the midpoint
    """
    print(f"🔴 LIVE STREAM STARTED — writing to {STREAM_FILE}")
    print(f"   Interval: {interval}s | Duration: {duration}s | Attack mode: {inject_attack}")
    print(f"   Press Ctrl+C to stop\n")

    sim = TrafficSimulator(datetime.now(), duration // 60 + 1)

    # Pre-generate pools of traffic
    normal_pool = sim.generate_normal_api_traffic("10.0.1.101", count=200)
    websocket_pool = sim.generate_websocket_traffic("10.0.1.103", count=200)

    if inject_attack:
        sim.current_time = datetime.now()
        attack_pool = sim.generate_shadow_ai_traffic("10.0.1.200", count=200)
    else:
        attack_pool = []

    stream_data = {"flows": [], "metadata": {"start_time": datetime.now().isoformat(), "status": "LIVE"}}
    batch_num = 0
    midpoint = duration // 2
    start_time = time.time()
    attack_started = False

    try:
        while (time.time() - start_time) < duration:
            blocked = get_blocked_ips()
            batch = []
            elapsed = time.time() - start_time

            # Normal traffic every tick
            if "10.0.1.101" not in blocked and normal_pool:
                flow = normal_pool.pop(0)
                flow['timestamp'] = datetime.now().isoformat()
                flow['label'] = 'normal'
                flow['service_type'] = 'Internal API'
                batch.append(flow)

            if "10.0.1.103" not in blocked and websocket_pool and batch_num % 3 == 0:
                flow = websocket_pool.pop(0)
                flow['timestamp'] = datetime.now().isoformat()
                flow['label'] = 'normal'
                flow['service_type'] = 'WebSocket (Chat)'
                batch.append(flow)

            # Inject attack at midpoint
            if inject_attack and elapsed >= midpoint and attack_pool:
                if not attack_started:
                    print(f"\n🚨 ATTACK INJECTED at {elapsed:.0f}s — Shadow AI traffic from 10.0.1.200")
                    attack_started = True

                if "10.0.1.200" not in blocked:
                    flow = attack_pool.pop(0)
                    flow['timestamp'] = datetime.now().isoformat()
                    flow['label'] = 'shadow_ai'
                    flow['service_type'] = 'Unauthorized LLM API'
                    batch.append(flow)
                else:
                    print(f"   🔒 10.0.1.200 is BLOCKED by firewall — skipping attack traffic")

            # Append to stream
            stream_data['flows'].extend(batch)
            stream_data['metadata']['last_update'] = datetime.now().isoformat()
            stream_data['metadata']['total_flows'] = len(stream_data['flows'])
            stream_data['metadata']['batch'] = batch_num

            # Write atomically
            with open(STREAM_FILE, 'w') as f:
                json.dump(stream_data, f, default=str)

            batch_num += 1
            indicator = "🟢" if not attack_started else ("🔴" if "10.0.1.200" not in blocked else "🔒")
            print(f"  {indicator} Batch {batch_num:04d} | Flows: {len(stream_data['flows']):5d} | "
                  f"+{len(batch)} new | Elapsed: {elapsed:.0f}s", end='\r')

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n⏹️  Stream stopped by user.")

    stream_data['metadata']['status'] = 'STOPPED'
    stream_data['metadata']['end_time'] = datetime.now().isoformat()
    with open(STREAM_FILE, 'w') as f:
        json.dump(stream_data, f, default=str)

    print(f"\n✅ Stream complete — {len(stream_data['flows'])} total flows written to {STREAM_FILE}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time VPC flow stream simulator")
    parser.add_argument('--interval', type=float, default=0.5, help='Seconds between batches')
    parser.add_argument('--duration', type=int, default=120, help='Total duration in seconds')
    parser.add_argument('--attack', action='store_true', help='Inject Shadow AI attack at midpoint')
    args = parser.parse_args()

    run_stream(interval=args.interval, duration=args.duration, inject_attack=args.attack)
