"""
Shadow Hunter — Active Defense Interrogator (v3 Feature)
Probes suspicious external hosts to verify if they're hosting AI APIs.

Safety Mechanisms:
  1. NEVER probes internal IPs (RFC1918 guard).
  2. Rate-limited to max 10 probes per minute.
  3. Lightweight: only HTTP OPTIONS and a single GET request.
  4. Non-destructive: no writes, no auth, no data sent.

This service subscribes to "alert.high" events and publishes "probe.result" events.

Usage::

    probe = ActiveProbe(broker)
    # Thereafter, automatically probes when high-risk alerts arrive.
"""

import logging
import time
from collections import deque
from datetime import datetime
from typing import Optional

from pkg.core.interfaces import EventBroker
from pkg.models.events import Alert, ProbeResult, Severity

logger = logging.getLogger("shadow_hunter.active_probe")


def _is_internal(ip: str) -> bool:
    """Check if an IP is in RFC1918 private ranges."""
    return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                          "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                          "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                          "172.29.", "172.30.", "172.31.", "127."))


class ActiveProbe:
    """
    Active interrogation service that probes suspicious external hosts.

    When a HIGH-risk alert arrives, this service:
      1. Checks if the destination is external (safety guard)
      2. Sends an HTTP OPTIONS request to read the Server header
      3. Sends a GET /v1/models request (OpenAI API signature)
      4. Publishes the probe result back to the broker

    If the probe confirms an AI API endpoint, the alert's risk is escalated
    to CRITICAL, which triggers auto-blocking by the ResponseManager.
    """

    MAX_PROBES_PER_MINUTE = 10
    PROBE_TIMEOUT_SECONDS = 5

    def __init__(self, broker: EventBroker, enabled: bool = True):
        self.broker = broker
        self.enabled = enabled
        self._probe_timestamps: deque = deque(maxlen=self.MAX_PROBES_PER_MINUTE)
        self._probe_cache: dict = {}  # IP -> last ProbeResult (avoid re-probing)
        self._stats = {"probes_sent": 0, "ai_confirmed": 0, "rate_limited": 0}

        if enabled:
            self.broker.subscribe("alert.high", self._on_high_alert)
            logger.info("ActiveProbe initialized and subscribed to alert.high")
        else:
            logger.info("ActiveProbe initialized but DISABLED")

    def _on_high_alert(self, alert) -> None:
        """Handle a high-risk alert by probing destination IPs."""
        if not self.enabled:
            return

        if isinstance(alert, Alert):
            dest_ips = alert.destination_ips
        elif isinstance(alert, dict):
            dest_ips = alert.get("destination_ips", [])
        else:
            return

        for ip in dest_ips:
            result = self.probe_host(ip)
            if result:
                self.broker.publish("probe.result", result)

                # If AI confirmed, escalate to CRITICAL for auto-blocking
                if result.is_confirmed_ai:
                    escalated = alert if isinstance(alert, Alert) else Alert(**alert)
                    escalated.severity = Severity.CRITICAL
                    escalated.probe_result = result.model_dump()
                    escalated.total_score = 100
                    escalated.recommendation = (
                        f"🚨 PROBE CONFIRMED: {ip} is hosting an AI API "
                        f"(Server: {result.http_options_server or 'unknown'}). "
                        f"Auto-escalating to CRITICAL."
                    )
                    self.broker.publish("alert.critical", escalated)
                    logger.warning("PROBE CONFIRMED AI at %s — escalated to CRITICAL", ip)

    def probe_host(self, ip: str) -> Optional[ProbeResult]:
        """
        Probe an external host to check for AI API signatures.

        Args:
            ip: Target IP address.

        Returns:
            ProbeResult, or None if probe was skipped (internal/rate-limited).
        """
        # Safety guard: never probe internal IPs
        if _is_internal(ip):
            logger.debug("Skipping probe for internal IP: %s", ip)
            return None

        # Rate limiting
        now = time.time()
        if len(self._probe_timestamps) >= self.MAX_PROBES_PER_MINUTE:
            oldest = self._probe_timestamps[0]
            if now - oldest < 60:
                self._stats["rate_limited"] += 1
                logger.debug("Rate limited — skipping probe for %s", ip)
                return None

        # Check cache (don't re-probe the same IP within 5 minutes)
        if ip in self._probe_cache:
            cached = self._probe_cache[ip]
            cache_age = (datetime.now() - cached.probed_at).total_seconds()
            if cache_age < 300:
                return cached

        # Record probe timestamp
        self._probe_timestamps.append(now)
        self._stats["probes_sent"] += 1

        result = ProbeResult(target_ip=ip)

        # ---- Probe 1: HTTP OPTIONS ----
        options_status, options_server = self._http_options(ip)
        result.http_options_status = options_status
        result.http_options_server = options_server

        # ---- Probe 2: AI endpoint check ----
        ai_detected, ai_response = self._ai_endpoint_check(ip)
        result.ai_endpoint_detected = ai_detected
        result.ai_endpoint_response = ai_response

        # Final determination
        result.is_confirmed_ai = ai_detected or self._server_looks_like_ai(options_server)

        if result.is_confirmed_ai:
            self._stats["ai_confirmed"] += 1

        # Cache result
        self._probe_cache[ip] = result

        logger.info(
            "Probe %s: OPTIONS=%s, Server=%s, AI=%s",
            ip, options_status, options_server, result.is_confirmed_ai,
        )
        return result

    def _http_options(self, ip: str) -> tuple:
        """
        Send HTTP OPTIONS request to read Server header.

        Returns:
            (status_code, server_header) or (None, None) on failure.
        """
        try:
            import urllib.request

            url = f"http://{ip}/"
            req = urllib.request.Request(url, method="OPTIONS")
            req.add_header("User-Agent", "ShadowHunter/1.0 ActiveProbe")

            with urllib.request.urlopen(
                req, timeout=self.PROBE_TIMEOUT_SECONDS
            ) as response:
                status = response.status
                server = response.headers.get("Server", "")
                return status, server

        except Exception as e:
            logger.debug("OPTIONS probe failed for %s: %s", ip, e)
            return None, None

    def _ai_endpoint_check(self, ip: str) -> tuple:
        """
        Check for OpenAI-compatible /v1/models endpoint.

        Returns:
            (detected: bool, response_snippet: str)
        """
        try:
            import urllib.request
            import json

            url = f"http://{ip}/v1/models"
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "ShadowHunter/1.0 ActiveProbe")

            with urllib.request.urlopen(
                req, timeout=self.PROBE_TIMEOUT_SECONDS
            ) as response:
                body = response.read(4096).decode("utf-8", errors="replace")
                # Check for OpenAI-style response
                try:
                    data = json.loads(body)
                    if "data" in data or "models" in data:
                        return True, body[:200]
                except json.JSONDecodeError:
                    pass
                # Check for other AI-related keywords
                ai_keywords = ["model", "inference", "gpt", "claude", "llm", "embedding"]
                if any(kw in body.lower() for kw in ai_keywords):
                    return True, body[:200]

                return False, body[:200]

        except Exception as e:
            logger.debug("AI endpoint check failed for %s: %s", ip, e)
            return False, str(e)

    @staticmethod
    def _server_looks_like_ai(server: str) -> bool:
        """Heuristic: does the Server header suggest an AI platform?"""
        if not server:
            return False
        server_lower = server.lower()
        ai_servers = ["openai", "anthropic", "fastapi", "uvicorn", "gunicorn", "starlette"]
        return any(s in server_lower for s in ai_servers)

    @property
    def stats(self) -> dict:
        return {**self._stats, "cached_probes": len(self._probe_cache)}
