"""
Shadow Hunter — JA3 Fingerprint Matching Plugin
Detects malware C2 frameworks and tool spoofing based on TLS fingerprints.

Detection Logic:
  1. MALWARE:  Exact JA3 hash match against known C2 tools → CRITICAL alert.
  2. SPOOFING: JA3 fingerprint says "Python" but User-Agent says "Chrome" → HIGH alert.
  3. CLEAN:    No match or legitimate browser fingerprint → no action.

This plugin runs as the FIRST check in the analysis pipeline (fast path)
because a malware C2 match is an immediate CRITICAL regardless of traffic patterns.
"""

import logging
from typing import Optional, Tuple

from pkg.data.ja3_intel import (
    lookup_ja3,
    CATEGORY_MALWARE,
    CATEGORY_SCRIPTING,
    CATEGORY_BROWSER,
)

logger = logging.getLogger("shadow_hunter.ja3_plugin")


# User-Agent substrings that indicate a browser
_BROWSER_UA_KEYWORDS = ["chrome", "firefox", "safari", "edge", "opera", "brave", "mozilla"]


class JA3MatchResult:
    """Result of a JA3 fingerprint check."""

    def __init__(self, match_type: str, detail: str, risk: str, name: str = ""):
        self.match_type = match_type   # "MALWARE" | "SPOOFING" | "SUSPICIOUS" | "CLEAN"
        self.detail = detail           # Human-readable explanation
        self.risk = risk               # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE"
        self.name = name               # Matched tool name

    def __repr__(self):
        return f"JA3MatchResult({self.match_type}, {self.name}, {self.risk})"


class JA3Plugin:
    """
    JA3 fingerprint matching plugin for the analyzer engine.

    Usage::

        plugin = JA3Plugin()
        result = plugin.check("a0e9f5d64349fb13191bc781f81f42e1", "Mozilla/5.0 ...")
        if result.match_type == "MALWARE":
            print("C2 DETECTED!")
    """

    def check(self, ja3_hash: Optional[str],
              user_agent: Optional[str] = None) -> JA3MatchResult:
        """
        Check a JA3 hash against the intelligence database.

        Args:
            ja3_hash:   MD5 hash from TLS ClientHello.
            user_agent: HTTP User-Agent header (if available).

        Returns:
            JA3MatchResult with match_type, detail, and risk.
        """
        if not ja3_hash:
            return JA3MatchResult("CLEAN", "No JA3 hash available", "SAFE")

        info = lookup_ja3(ja3_hash)

        # ---- Case 1: Known malware C2 ----
        if info and info["category"] == CATEGORY_MALWARE:
            logger.warning(
                "MALWARE JA3 MATCH: %s (%s)", info["name"], ja3_hash[:12]
            )
            return JA3MatchResult(
                match_type="MALWARE",
                detail=f"JA3 fingerprint matches known C2: {info['name']}. "
                       f"{info['description']}",
                risk="CRITICAL",
                name=info["name"],
            )

        # ---- Case 2: Scripting tool with browser User-Agent (spoofing) ----
        if info and info["category"] == CATEGORY_SCRIPTING and user_agent:
            ua_lower = user_agent.lower()
            if any(kw in ua_lower for kw in _BROWSER_UA_KEYWORDS):
                logger.warning(
                    "SPOOFING DETECTED: JA3=%s (%s) but UA claims browser",
                    info["name"], ja3_hash[:12],
                )
                return JA3MatchResult(
                    match_type="SPOOFING",
                    detail=f"JA3 fingerprint is {info['name']} but User-Agent "
                           f"claims to be a browser. Likely automated tool "
                           f"disguising as legitimate traffic.",
                    risk="HIGH",
                    name=info["name"],
                )

        # ---- Case 3: Known scripting tool (no spoofing) ----
        if info and info["category"] == CATEGORY_SCRIPTING:
            return JA3MatchResult(
                match_type="SUSPICIOUS",
                detail=f"Traffic from scripting tool: {info['name']}. "
                       f"May be legitimate automation or unauthorized script.",
                risk=info["risk"],
                name=info["name"],
            )

        # ---- Case 4: Known browser (clean) ----
        if info and info["category"] == CATEGORY_BROWSER:
            return JA3MatchResult(
                match_type="CLEAN",
                detail=f"Legitimate browser: {info['name']}",
                risk="SAFE",
                name=info["name"],
            )

        # ---- Case 5: Unknown JA3 hash ----
        return JA3MatchResult(
            match_type="CLEAN",
            detail="JA3 hash not in database — unknown client",
            risk="LOW",
        )
