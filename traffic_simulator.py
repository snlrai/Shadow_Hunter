"""
Traffic Simulator - Generates realistic VPC Flow Log data
Purpose: Validate packet size and behavioral assumptions before building detector
"""

import random
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict
import numpy as np


class TrafficSimulator:
    """Simulates various types of network traffic patterns"""
    
    def __init__(self, start_time: datetime, duration_minutes: int):
        self.start_time = start_time
        self.duration_minutes = duration_minutes
        self.current_time = start_time
        
    def generate_shadow_ai_traffic(self, source_ip: str, count: int = 100) -> List[Dict]:
        """
        Simulates LLM inference traffic (OpenAI API, Anthropic Claude, etc.)
        
        Characteristics:
        - Small requests (prompt + metadata): 500-2000 bytes
        - Large streaming responses: 5000-50000 bytes
        - Regular intervals: 8-15 seconds between calls
        - Long-lived HTTPS connections
        - High RX/TX ratio (10:1 to 50:1)
        """
        flows = []
        destinations = [
            "13.107.42.14",  # Simulated OpenAI API
            "34.102.136.180"  # Simulated Anthropic API
        ]
        
        for i in range(count):
            # LLM API call timing - regular with slight jitter
            interval = random.uniform(8, 15)
            self.current_time += timedelta(seconds=interval)
            
            # Request: small (prompt)
            bytes_sent = random.randint(500, 2000)
            
            # Response: large (streaming completion)
            # Token streaming creates large, chunked responses
            bytes_received = random.randint(5000, 50000)
            
            # Connection duration: moderate (streaming response time)
            duration = random.uniform(2, 8)
            
            # Packet count reflects streaming behavior
            # Response has many packets due to chunking
            packets = random.randint(20, 100)
            
            flows.append({
                'timestamp': self.current_time,
                'source_ip': source_ip,
                'destination_ip': random.choice(destinations),
                'destination_port': 443,
                'protocol': 'TCP',
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_count': packets,
                'connection_duration': duration
            })
            
        return flows
    
    def generate_normal_api_traffic(self, source_ip: str, count: int = 100) -> List[Dict]:
        """
        Simulates normal REST API traffic (CRUD operations)
        
        Characteristics:
        - Balanced request/response sizes
        - Bursty timing (user-driven)
        - Short connections
        - RX/TX ratio close to 1:1 or 1:3
        """
        flows = []
        
        for i in range(count):
            # Bursty behavior - irregular intervals
            interval = random.choice([
                random.uniform(1, 5),    # Busy period
                random.uniform(30, 120)  # Idle period
            ])
            self.current_time += timedelta(seconds=interval)
            
            # Balanced traffic
            bytes_sent = random.randint(800, 5000)
            bytes_received = random.randint(1000, 8000)  # Similar magnitude
            
            # Short connections
            duration = random.uniform(0.1, 2)
            
            packets = random.randint(5, 20)
            
            flows.append({
                'timestamp': self.current_time,
                'source_ip': source_ip,
                'destination_ip': f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
                'destination_port': random.choice([80, 443, 8080]),
                'protocol': 'TCP',
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_count': packets,
                'connection_duration': duration
            })
            
        return flows
    
    def generate_video_streaming(self, source_ip: str, count: int = 50) -> List[Dict]:
        """
        Simulates video streaming (Netflix, YouTube, Zoom)
        
        Characteristics:
        - Very high bandwidth
        - Long-lived connections
        - Minimal sent, massive received
        - But RX/TX ratio AND total bytes are much higher than LLM
        """
        flows = []
        
        for i in range(count):
            interval = random.uniform(0.5, 2)  # Continuous
            self.current_time += timedelta(seconds=interval)
            
            # Tiny requests (buffering)
            bytes_sent = random.randint(100, 500)
            
            # MASSIVE responses (video data)
            bytes_received = random.randint(100000, 1000000)  # 100KB-1MB per flow
            
            # Long connections
            duration = random.uniform(1, 10)
            
            packets = random.randint(100, 500)
            
            flows.append({
                'timestamp': self.current_time,
                'source_ip': source_ip,
                'destination_ip': f"151.101.{random.randint(1,255)}.{random.randint(1,255)}",
                'destination_port': 443,
                'protocol': 'TCP',
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_count': packets,
                'connection_duration': duration
            })
            
        return flows
    
    def generate_websocket_traffic(self, source_ip: str, count: int = 100) -> List[Dict]:
        """
        Simulates WebSocket traffic (Slack, chat apps)
        
        Characteristics:
        - Bidirectional traffic
        - Long-lived connections
        - Small, frequent packets
        - Balanced RX/TX
        """
        flows = []
        
        for i in range(count):
            interval = random.uniform(5, 20)  # Regular heartbeats/messages
            self.current_time += timedelta(seconds=interval)
            
            # Bidirectional, small messages
            bytes_sent = random.randint(200, 1000)
            bytes_received = random.randint(200, 1000)
            
            # Long-lived
            duration = random.uniform(0.5, 5)
            
            packets = random.randint(2, 10)
            
            flows.append({
                'timestamp': self.current_time,
                'source_ip': source_ip,
                'destination_ip': "34.56.78.90",  # Slack servers
                'destination_port': 443,
                'protocol': 'TCP',
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_count': packets,
                'connection_duration': duration
            })
            
        return flows
    
    def generate_database_traffic(self, source_ip: str, count: int = 100) -> List[Dict]:
        """
        Simulates database queries
        
        Characteristics:
        - Short connections
        - Small queries, variable responses
        - High frequency during business hours
        """
        flows = []
        
        for i in range(count):
            interval = random.uniform(0.1, 5)
            self.current_time += timedelta(seconds=interval)
            
            # Query
            bytes_sent = random.randint(200, 1500)
            
            # Result set (variable)
            bytes_received = random.randint(500, 10000)
            
            # Fast
            duration = random.uniform(0.01, 0.5)
            
            packets = random.randint(3, 15)
            
            flows.append({
                'timestamp': self.current_time,
                'source_ip': source_ip,
                'destination_ip': "10.0.100.50",  # Internal DB
                'destination_port': 5432,  # PostgreSQL
                'protocol': 'TCP',
                'bytes_sent': bytes_sent,
                'bytes_received': bytes_received,
                'packet_count': packets,
                'connection_duration': duration
            })
            
        return flows


def generate_dataset(num_normal_users: int = 50, num_shadow_users: int = 8) -> pd.DataFrame:
    """
    Generate a fleet-scale dataset with many unique source IPs.

    This creates enough unique training samples for ML models (Isolation Forest,
    Autoencoder, SHAP) to learn meaningful patterns.  Each normal user is
    assigned a random "persona" so the model sees realistic diversity.

    Args:
        num_normal_users: Number of distinct normal users to simulate.
        num_shadow_users: Number of distinct shadow AI users to simulate.
    """

    start_time = datetime.now() - timedelta(hours=1)
    all_flows = []

    # ── Persona definitions ──────────────────────────────────────────────
    PERSONAS = {
        'api_heavy': {
            'generator': 'generate_normal_api_traffic',
            'service_type': 'Internal API',
            'count_range': (80, 150),
        },
        'video_watcher': {
            'generator': 'generate_video_streaming',
            'service_type': 'Video Streaming',
            'count_range': (20, 50),
        },
        'chatter': {
            'generator': 'generate_websocket_traffic',
            'service_type': 'WebSocket (Chat)',
            'count_range': (60, 120),
        },
        'db_heavy': {
            'generator': 'generate_database_traffic',
            'service_type': 'Database',
            'count_range': (100, 200),
        },
        'mixed': {  # generates two traffic types
            'generators': [
                ('generate_normal_api_traffic', 'Internal API', (40, 80)),
                ('generate_websocket_traffic', 'WebSocket (Chat)', (30, 60)),
            ],
        },
    }

    persona_names = list(PERSONAS.keys())

    # ── 1. Normal users (varied personas) ────────────────────────────────
    print(f"🏢 Generating {num_normal_users} normal users across {len(PERSONAS)} personas...")

    for i in range(num_normal_users):
        ip = f"10.0.1.{i + 10}"  # 10.0.1.10 .. 10.0.1.59 (or higher)
        sim = TrafficSimulator(start_time, 60)

        persona = random.choice(persona_names)
        cfg = PERSONAS[persona]

        if persona == 'mixed':
            # Two traffic types from the same IP
            for gen_name, svc_type, (lo, hi) in cfg['generators']:
                gen_fn = getattr(sim, gen_name)
                flows = gen_fn(ip, count=random.randint(lo, hi))
                for f in flows:
                    f['label'] = 'normal'
                    f['service_type'] = svc_type
                all_flows.extend(flows)
        else:
            gen_fn = getattr(sim, cfg['generator'])
            lo, hi = cfg['count_range']
            flows = gen_fn(ip, count=random.randint(lo, hi))
            for f in flows:
                f['label'] = 'normal'
                f['service_type'] = cfg['service_type']
            all_flows.extend(flows)

    # ── 2. Shadow AI users ───────────────────────────────────────────────
    print(f"🚨 Generating {num_shadow_users} shadow AI users...")

    for i in range(num_shadow_users):
        ip = f"10.0.2.{i + 10}"  # 10.0.2.10 .. 10.0.2.17
        sim = TrafficSimulator(start_time, 60)
        count = random.randint(60, 120)
        flows = sim.generate_shadow_ai_traffic(ip, count=count)
        for f in flows:
            f['label'] = 'shadow_ai'
            f['service_type'] = 'Unauthorized LLM API'
        all_flows.extend(flows)

    # ── Build DataFrame ──────────────────────────────────────────────────
    df = pd.DataFrame(all_flows)

    n_shadow = len(df[df['label'] == 'shadow_ai'])
    n_normal = len(df[df['label'] == 'normal'])
    n_ips = df['source_ip'].nunique()

    print(f"\n✅ Generated {len(df)} flow records from {n_ips} unique IPs")
    print(f"   Shadow AI: {n_shadow} flows ({num_shadow_users} IPs)")
    print(f"   Normal:    {n_normal} flows ({num_normal_users} IPs)")

    return df


if __name__ == "__main__":
    df = generate_dataset()

    # Save for use in detector
    df.to_csv('simulated_vpc_flows.csv', index=False)
    print(f"\n💾 Saved to simulated_vpc_flows.csv")

    # Quick validation
    print("\n📊 Traffic Statistics by Type:")
    print(df.groupby('service_type').agg({
        'bytes_sent': 'mean',
        'bytes_received': 'mean',
        'connection_duration': 'mean',
        'packet_count': 'mean'
    }).round(2))

    print(f"\n📊 Unique IPs per label:")
    print(df.groupby('label')['source_ip'].nunique())