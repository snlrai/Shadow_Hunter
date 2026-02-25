"""
Shadow Hunter — SQLite Graph + Event Store
Persistent storage for network topology and audit events.

Tables:
  - nodes:  IP addresses / domains with risk scores and metadata.
  - edges:  Traffic flows between nodes (protocol, bytes, timestamps).
  - events: Raw audit log of all flows, alerts, probes, and blocks.

This replaces the in-memory-only approach of the Original MVP,
giving the dashboard something to query even when the engine isn't running.
"""

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from pkg.core.interfaces import GraphStore

logger = logging.getLogger("shadow_hunter.store")

# Default DB path — next to run_local.py
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "shadow_hunter.db",
)


class SQLiteGraphStore(GraphStore):
    """
    SQLite-backed graph + event store.

    Usage::

        store = SQLiteGraphStore("shadow_hunter.db")
        store.upsert_node("192.168.1.5", ["Node"], {"type": "internal", "risk_score": 0.2})
        store.upsert_edge("192.168.1.5", "13.107.42.14", "TALKS_TO", {"protocol": "TCP"})
        nodes = store.get_nodes()
    """

    def __init__(self, db_path: str = None, reset: bool = False):
        self.db_path = os.path.normpath(db_path or DEFAULT_DB_PATH)

        if reset and os.path.exists(self.db_path):
            os.remove(self.db_path)
            logger.info("Reset: deleted existing DB at %s", self.db_path)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()
        logger.info("SQLiteGraphStore ready at %s", self.db_path)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_tables(self):
        cur = self._conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (
                id          TEXT PRIMARY KEY,
                labels      TEXT NOT NULL DEFAULT '["Node"]',
                properties  TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS edges (
                source      TEXT NOT NULL,
                target      TEXT NOT NULL,
                relation    TEXT NOT NULL DEFAULT 'TALKS_TO',
                properties  TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY (source, target, relation)
            );

            CREATE TABLE IF NOT EXISTS events (
                id          TEXT PRIMARY KEY,
                event_type  TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                data        TEXT NOT NULL DEFAULT '{}'
            );

            CREATE INDEX IF NOT EXISTS idx_events_type
                ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_ts
                ON events(timestamp);
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # GraphStore interface — Nodes
    # ------------------------------------------------------------------

    def upsert_node(self, node_id: str, labels: List[str],
                    properties: Dict) -> None:
        """Insert or update a node. Properties are merged on conflict."""
        cur = self._conn.cursor()

        # Try to read existing properties for merge
        row = cur.execute(
            "SELECT properties FROM nodes WHERE id = ?", (node_id,)
        ).fetchone()

        if row:
            existing = json.loads(row["properties"])
            existing.update(properties)
            cur.execute(
                "UPDATE nodes SET labels = ?, properties = ? WHERE id = ?",
                (json.dumps(labels), json.dumps(existing, default=str), node_id),
            )
        else:
            cur.execute(
                "INSERT INTO nodes (id, labels, properties) VALUES (?, ?, ?)",
                (node_id, json.dumps(labels), json.dumps(properties, default=str)),
            )
        self._conn.commit()

    def get_nodes(self) -> List[Dict]:
        cur = self._conn.cursor()
        rows = cur.execute("SELECT id, labels, properties FROM nodes").fetchall()
        return [
            {
                "id": r["id"],
                "labels": json.loads(r["labels"]),
                "properties": json.loads(r["properties"]),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # GraphStore interface — Edges
    # ------------------------------------------------------------------

    def upsert_edge(self, source: str, target: str, relation: str,
                    properties: Dict) -> None:
        """Insert or update an edge. Properties are merged on conflict."""
        cur = self._conn.cursor()

        row = cur.execute(
            "SELECT properties FROM edges WHERE source=? AND target=? AND relation=?",
            (source, target, relation),
        ).fetchone()

        if row:
            existing = json.loads(row["properties"])
            # Accumulate byte_count instead of overwriting
            if "byte_count" in properties and "byte_count" in existing:
                properties["byte_count"] = (
                    existing["byte_count"] + properties["byte_count"]
                )
            existing.update(properties)
            cur.execute(
                """UPDATE edges SET properties = ?
                   WHERE source=? AND target=? AND relation=?""",
                (json.dumps(existing, default=str), source, target, relation),
            )
        else:
            cur.execute(
                """INSERT INTO edges (source, target, relation, properties)
                   VALUES (?, ?, ?, ?)""",
                (source, target, relation,
                 json.dumps(properties, default=str)),
            )
        self._conn.commit()

    def get_edges(self) -> List[Dict]:
        cur = self._conn.cursor()
        rows = cur.execute(
            "SELECT source, target, relation, properties FROM edges"
        ).fetchall()
        return [
            {
                "source": r["source"],
                "target": r["target"],
                "relation": r["relation"],
                "properties": json.loads(r["properties"]),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # GraphStore interface — Events (audit log)
    # ------------------------------------------------------------------

    def store_event(self, event_type: str, data: Dict) -> None:
        event_id = str(uuid.uuid4())[:8]
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO events (id, event_type, timestamp, data) VALUES (?, ?, ?, ?)",
            (event_id, event_type, datetime.now().isoformat(),
             json.dumps(data, default=str)),
        )
        self._conn.commit()

    def get_events(self, event_type: Optional[str] = None,
                   limit: int = 1000) -> List[Dict]:
        cur = self._conn.cursor()
        if event_type:
            rows = cur.execute(
                """SELECT id, event_type, timestamp, data FROM events
                   WHERE event_type = ? ORDER BY timestamp DESC LIMIT ?""",
                (event_type, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """SELECT id, event_type, timestamp, data FROM events
                   ORDER BY timestamp DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "event_type": r["event_type"],
                "timestamp": r["timestamp"],
                "data": json.loads(r["data"]),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # GraphStore interface — Clear
    # ------------------------------------------------------------------

    def clear(self) -> None:
        cur = self._conn.cursor()
        cur.executescript("DELETE FROM nodes; DELETE FROM edges; DELETE FROM events;")
        self._conn.commit()
        logger.info("Store cleared — all nodes, edges, and events deleted")

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def stats(self) -> Dict:
        """Quick summary of store contents."""
        cur = self._conn.cursor()
        nodes = cur.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        edges = cur.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        events = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return {"nodes": nodes, "edges": edges, "events": events}

    def close(self):
        self._conn.close()
