"""
Shadow Hunter — Clean Architecture Interfaces
Abstract base classes defining the contracts between services.

These interfaces allow swapping implementations without changing business logic:
  - EventBroker: could be in-memory, Redis, Kafka, etc.
  - GraphStore:  could be in-memory (NetworkX), SQLite, Neo4j, etc.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional


class EventBroker(ABC):
    """
    Publish/Subscribe message bus.

    Services publish events to named topics, and other services subscribe
    to those topics to react asynchronously.

    Topics used in Shadow Hunter:
      - "traffic.flow"    : Raw network flow events
      - "alert.new"       : Any new alert generated
      - "alert.high"      : High-risk alerts (triggers probing)
      - "alert.critical"  : Critical alerts (triggers auto-block)
      - "probe.result"    : Result from active interrogation
      - "block.action"    : IP blocked/unblocked events
    """

    @abstractmethod
    def publish(self, topic: str, event: Any) -> None:
        """Publish an event to a topic. All subscribers are notified."""
        ...

    @abstractmethod
    def subscribe(self, topic: str, handler: Callable[[Any], None]) -> None:
        """Subscribe a handler function to a topic."""
        ...

    @abstractmethod
    def get_history(self, topic: str, limit: int = 100) -> List[Any]:
        """Retrieve recent events from a topic (for dashboard queries)."""
        ...


class GraphStore(ABC):
    """
    Persistent graph database for network topology.

    Stores nodes (IPs/domains) and edges (traffic flows) with
    JSON-serialized properties for flexible metadata.
    """

    @abstractmethod
    def upsert_node(self, node_id: str, labels: List[str],
                    properties: Dict) -> None:
        """Insert or update a node. Properties are merged on update."""
        ...

    @abstractmethod
    def upsert_edge(self, source: str, target: str, relation: str,
                    properties: Dict) -> None:
        """Insert or update an edge between two nodes."""
        ...

    @abstractmethod
    def get_nodes(self) -> List[Dict]:
        """Return all nodes as dicts with id, labels, properties."""
        ...

    @abstractmethod
    def get_edges(self) -> List[Dict]:
        """Return all edges as dicts with source, target, relation, properties."""
        ...

    @abstractmethod
    def clear(self) -> None:
        """Remove all nodes and edges."""
        ...

    @abstractmethod
    def store_event(self, event_type: str, data: Dict) -> None:
        """Store a raw event (flow, alert, probe result) for audit."""
        ...

    @abstractmethod
    def get_events(self, event_type: Optional[str] = None,
                   limit: int = 1000) -> List[Dict]:
        """Retrieve stored events, optionally filtered by type."""
        ...
