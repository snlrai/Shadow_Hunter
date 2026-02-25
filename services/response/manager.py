"""
Shadow Hunter — Automated Response Manager (v3 Feature)
Auto-blocks CRITICAL threats and maintains a quarantine list with TTL.

This is the SOAR (Security Orchestration, Automation & Response) component
that closes the loop: detect → block → audit → expire.

Safety Mechanisms:
  1. Whitelist: DNS servers and gateway IPs are NEVER blocked.
  2. TTL: All blocks expire after a configurable duration (default: 1 hour).
  3. Audit Trail: Every block/unblock is logged with timestamp and reason.
  4. Manual Override: Analyst can unblock IPs before TTL expires.

Usage::

    manager = ResponseManager(broker)
    # Automatically blocks IPs from CRITICAL alerts.
    # Or manually:
    manager.block_ip("10.0.1.200", reason="Confirmed C2")
    manager.unblock_ip("10.0.1.200", reason="False positive")
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from pkg.core.interfaces import EventBroker
from pkg.models.events import Alert, BlockRecord, Severity

logger = logging.getLogger("shadow_hunter.response")

# Default firewall rules file (backward compat with stream_simulator)
FIREWALL_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "firewall_rules.json",
)


class ResponseManager:
    """
    Automated IP blocking and quarantine manager.

    Subscribes to "alert.critical" events and auto-blocks the source IP.
    Maintains an in-memory blocklist with TTL, plus writes to
    firewall_rules.json for backward compatibility.
    """

    # IPs that must NEVER be blocked
    DEFAULT_WHITELIST = {
        "8.8.8.8",          # Google DNS
        "8.8.4.4",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS
        "1.0.0.1",          # Cloudflare DNS
    }

    # Gateway suffix — any IP ending in .1 is protected
    GATEWAY_SUFFIX = ".1"

    def __init__(
        self,
        broker: EventBroker,
        ttl_seconds: int = 3600,
        firewall_file: str = None,
        enabled: bool = True,
    ):
        self.broker = broker
        self.ttl_seconds = ttl_seconds
        self.firewall_file = firewall_file or FIREWALL_FILE
        self.enabled = enabled

        # State
        self._blocked: Dict[str, BlockRecord] = {}   # IP -> BlockRecord
        self._audit_log: List[Dict] = []
        self._whitelist: Set[str] = set(self.DEFAULT_WHITELIST)

        # Subscribe
        if enabled:
            self.broker.subscribe("alert.critical", self._on_critical_alert)
            logger.info(
                "ResponseManager initialized (TTL=%ds, firewall=%s)",
                ttl_seconds, self.firewall_file,
            )
        else:
            logger.info("ResponseManager initialized but DISABLED")

    # ------------------------------------------------------------------
    # Event handler
    # ------------------------------------------------------------------

    def _on_critical_alert(self, alert) -> None:
        """Auto-block the source IP of a CRITICAL alert."""
        if not self.enabled:
            return

        if isinstance(alert, Alert):
            ip = alert.source_ip
            reason = f"Auto-blocked: {alert.recommendation[:100]}"
        elif isinstance(alert, dict):
            ip = alert.get("source_ip", "")
            reason = f"Auto-blocked: {alert.get('recommendation', 'CRITICAL alert')[:100]}"
        else:
            return

        self.block_ip(ip, reason=reason, auto=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block_ip(self, ip: str, reason: str = "", auto: bool = True) -> bool:
        """
        Block an IP address.

        Args:
            ip: IP to block.
            reason: Human-readable reason for the block.
            auto: Whether this was an automated or manual block.

        Returns:
            True if blocked, False if whitelisted or already blocked.
        """
        # Cleanup expired blocks first
        self._cleanup_expired()

        # Whitelist check
        if self._is_whitelisted(ip):
            logger.info("Refused to block whitelisted IP: %s", ip)
            self._log_audit(ip, "BLOCK_REFUSED", f"Whitelisted: {reason}")
            return False

        # Already blocked?
        if ip in self._blocked:
            logger.debug("IP already blocked: %s", ip)
            return False

        # Block it
        record = BlockRecord(
            ip=ip,
            blocked_at=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=self.ttl_seconds),
            reason=reason,
            severity=Severity.CRITICAL,
            auto_blocked=auto,
        )
        self._blocked[ip] = record

        # Audit
        self._log_audit(ip, "BLOCKED", reason)

        # Publish event
        self.broker.publish("block.action", {
            "action": "BLOCK",
            "ip": ip,
            "reason": reason,
            "auto": auto,
            "timestamp": datetime.now().isoformat(),
            "expires_at": record.expires_at.isoformat(),
        })

        # Write to firewall_rules.json (backward compat)
        self._sync_firewall_file()

        logger.warning(
            "🔒 BLOCKED %s (auto=%s, TTL=%ds): %s",
            ip, auto, self.ttl_seconds, reason,
        )
        return True

    def unblock_ip(self, ip: str, reason: str = "Manual override") -> bool:
        """
        Manually unblock an IP.

        Returns:
            True if unblocked, False if wasn't blocked.
        """
        if ip not in self._blocked:
            return False

        del self._blocked[ip]
        self._log_audit(ip, "UNBLOCKED", reason)

        self.broker.publish("block.action", {
            "action": "UNBLOCK",
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        })

        self._sync_firewall_file()

        logger.info("🔓 UNBLOCKED %s: %s", ip, reason)
        return True

    def get_blocked_ips(self) -> List[BlockRecord]:
        """Return all currently blocked IPs (after cleanup)."""
        self._cleanup_expired()
        return list(self._blocked.values())

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        self._cleanup_expired()
        return ip in self._blocked

    def get_audit_log(self) -> List[Dict]:
        """Return the full audit trail."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is protected from blocking."""
        if ip in self._whitelist:
            return True
        if ip.endswith(self.GATEWAY_SUFFIX):
            return True
        return False

    def _cleanup_expired(self) -> None:
        """Remove blocks that have exceeded their TTL."""
        now = datetime.now()
        expired = [
            ip for ip, rec in self._blocked.items()
            if rec.expires_at and rec.expires_at <= now
        ]
        for ip in expired:
            del self._blocked[ip]
            self._log_audit(ip, "EXPIRED", f"TTL of {self.ttl_seconds}s reached")
            logger.info("⏰ Block expired for %s", ip)

        if expired:
            self._sync_firewall_file()

    def _log_audit(self, ip: str, action: str, reason: str) -> None:
        """Record an action in the audit trail."""
        self._audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "action": action,
            "reason": reason,
        })

    def _sync_firewall_file(self) -> None:
        """Write current blocked IPs to firewall_rules.json."""
        try:
            data = {
                "blocked_ips": list(self._blocked.keys()),
                "updated_at": datetime.now().isoformat(),
                "rules": [
                    {
                        "ip": rec.ip,
                        "reason": rec.reason,
                        "blocked_at": rec.blocked_at.isoformat(),
                        "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
                        "auto": rec.auto_blocked,
                    }
                    for rec in self._blocked.values()
                ],
            }
            with open(self.firewall_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            logger.exception("Failed to sync firewall file")

    @property
    def stats(self) -> dict:
        self._cleanup_expired()
        return {
            "blocked_count": len(self._blocked),
            "audit_entries": len(self._audit_log),
            "blocked_ips": list(self._blocked.keys()),
        }
