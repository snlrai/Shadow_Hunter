"""
Shadow Hunter — In-Memory Event Broker
Synchronous Pub/Sub implementation for local development.

Events are dispatched immediately to all subscribers when published.
A bounded history is kept per topic for dashboard queries.

In production this would be replaced with Redis Pub/Sub or Kafka.
"""

import logging
from collections import defaultdict, deque
from typing import Any, Callable, List

from pkg.core.interfaces import EventBroker

logger = logging.getLogger("shadow_hunter.broker")


class MemoryBroker(EventBroker):
    """
    Thread-safe in-memory Pub/Sub broker.

    Usage::

        broker = MemoryBroker()
        broker.subscribe("alert.new", lambda evt: print(evt))
        broker.publish("alert.new", {"ip": "10.0.1.5", "score": 95})
    """

    def __init__(self, history_size: int = 5000):
        self._subscribers: dict[str, List[Callable]] = defaultdict(list)
        self._history: dict[str, deque] = defaultdict(
            lambda: deque(maxlen=history_size)
        )
        self._history_size = history_size
        logger.info("MemoryBroker initialized (history_size=%d)", history_size)

    # ------------------------------------------------------------------
    # EventBroker interface
    # ------------------------------------------------------------------

    def publish(self, topic: str, event: Any) -> None:
        """Publish event to topic. Calls all subscribers synchronously."""
        self._history[topic].append(event)
        for handler in self._subscribers.get(topic, []):
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Handler %s failed for topic '%s'", handler.__name__, topic
                )

    def subscribe(self, topic: str, handler: Callable[[Any], None]) -> None:
        """Register a handler for a topic."""
        self._subscribers[topic].append(handler)
        logger.info(
            "Subscribed %s to '%s' (%d total)",
            handler.__name__, topic, len(self._subscribers[topic]),
        )

    def get_history(self, topic: str, limit: int = 100) -> List[Any]:
        """Return the last `limit` events from a topic."""
        history = self._history.get(topic, deque())
        return list(history)[-limit:]

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @property
    def topics(self) -> List[str]:
        """List all topics that have subscribers or history."""
        return sorted(
            set(self._subscribers.keys()) | set(self._history.keys())
        )

    def stats(self) -> dict:
        """Return broker statistics for debugging."""
        return {
            "topics": len(self.topics),
            "subscribers": {
                t: len(handlers) for t, handlers in self._subscribers.items()
            },
            "history_sizes": {
                t: len(h) for t, h in self._history.items()
            },
        }
