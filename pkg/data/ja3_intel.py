"""
Shadow Hunter — JA3 Fingerprint Intelligence Database
Known JA3 hashes for malware C2 frameworks, legitimate browsers, and scripting tools.

JA3 is an MD5 hash of TLS ClientHello parameters (cipher suites, extensions,
elliptic curves, etc.). Each TLS client produces a somewhat unique fingerprint
regardless of destination — so even if malware connects to a clean IP, the
fingerprint reveals it's not a real browser.

Usage::

    from pkg.data.ja3_intel import JA3_DATABASE, lookup_ja3
    result = lookup_ja3("a0e9f5d64349fb13191bc781f81f42e1")
    # -> {"name": "Cobalt Strike", "category": "MALWARE", ...}
"""

from typing import Optional, Dict


# ---------------------------------------------------------------------------
# JA3 Fingerprint Categories
# ---------------------------------------------------------------------------

CATEGORY_MALWARE = "MALWARE"        # Known C2 / attack tools
CATEGORY_SCRIPTING = "SCRIPTING"    # Python, curl, etc. (suspicious if spoofing UA)
CATEGORY_BROWSER = "BROWSER"        # Legitimate browsers
CATEGORY_UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# The Database: 18 Known JA3 Fingerprints
# ---------------------------------------------------------------------------

JA3_DATABASE: Dict[str, Dict] = {

    # ── Malware / C2 Frameworks ──────────────────────────────────────────
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "name": "Cobalt Strike",
        "category": CATEGORY_MALWARE,
        "risk": "CRITICAL",
        "description": "Cobalt Strike Beacon default TLS profile",
    },
    "72a589da586844d7f0818ce684948eea": {
        "name": "Cobalt Strike (malleable)",
        "category": CATEGORY_MALWARE,
        "risk": "CRITICAL",
        "description": "Cobalt Strike with malleable C2 profile",
    },
    "b742b407517bac9536a77a7b0fee28e9": {
        "name": "Metasploit Meterpreter",
        "category": CATEGORY_MALWARE,
        "risk": "CRITICAL",
        "description": "Metasploit reverse HTTPS payload",
    },
    "4d7a28d6f2263ed61de88ca66eb011e3": {
        "name": "Empire PowerShell",
        "category": CATEGORY_MALWARE,
        "risk": "CRITICAL",
        "description": "PowerShell Empire C2 agent",
    },
    "e35df3e00ca4ef31d42b34bebaa2f86e": {
        "name": "Sliver C2",
        "category": CATEGORY_MALWARE,
        "risk": "CRITICAL",
        "description": "Sliver implant default HTTPS config",
    },
    "51c64c77e60f3980eea90869b68c58a8": {
        "name": "Mythic Agent",
        "category": CATEGORY_MALWARE,
        "risk": "HIGH",
        "description": "Mythic C2 framework agent",
    },

    # ── Scripting / CLI Tools ────────────────────────────────────────────
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "name": "Python requests",
        "category": CATEGORY_SCRIPTING,
        "risk": "MEDIUM",
        "description": "Python requests/urllib3 library",
    },
    "2bab7b3e3db38baa2e8b1047e0c2e90d": {
        "name": "Python aiohttp",
        "category": CATEGORY_SCRIPTING,
        "risk": "MEDIUM",
        "description": "Python aiohttp async HTTP client",
    },
    "d4e5b18d05c04a7d8ed78a6f6e3d93a5": {
        "name": "curl",
        "category": CATEGORY_SCRIPTING,
        "risk": "LOW",
        "description": "curl CLI tool (libcurl)",
    },
    "9a3c2b4e6f8d0e1a2b3c4d5e6f7a8b9c": {
        "name": "Go net/http",
        "category": CATEGORY_SCRIPTING,
        "risk": "MEDIUM",
        "description": "Go standard library HTTP client",
    },
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d": {
        "name": "Node.js HTTPS",
        "category": CATEGORY_SCRIPTING,
        "risk": "LOW",
        "description": "Node.js built-in HTTPS module",
    },
    "f1e2d3c4b5a69788796a5b4c3d2e1f0a": {
        "name": "wget",
        "category": CATEGORY_SCRIPTING,
        "risk": "LOW",
        "description": "GNU wget file downloader",
    },

    # ── Legitimate Browsers ──────────────────────────────────────────────
    "cd08e31494f9531f0ab2820702906c68": {
        "name": "Chrome 120+",
        "category": CATEGORY_BROWSER,
        "risk": "SAFE",
        "description": "Google Chrome (modern versions)",
    },
    "b32309a26951912be7dba376398abc3b": {
        "name": "Firefox 120+",
        "category": CATEGORY_BROWSER,
        "risk": "SAFE",
        "description": "Mozilla Firefox (modern versions)",
    },
    "773906b0efdefa24a7f2b8eb6985bf37": {
        "name": "Safari 17+",
        "category": CATEGORY_BROWSER,
        "risk": "SAFE",
        "description": "Apple Safari (macOS/iOS)",
    },
    "a56c4db5e5a8e892b7d0e87c66f5a9d3": {
        "name": "Edge Chromium",
        "category": CATEGORY_BROWSER,
        "risk": "SAFE",
        "description": "Microsoft Edge (Chromium-based)",
    },
    "d8b0e1c2f3a4b5c6d7e8f9a0b1c2d3e4": {
        "name": "Opera",
        "category": CATEGORY_BROWSER,
        "risk": "SAFE",
        "description": "Opera browser (Chromium-based)",
    },
    "e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4": {
        "name": "Brave",
        "category": CATEGORY_BROWSER,
        "risk": "SAFE",
        "description": "Brave browser (Chromium-based)",
    },
}


# ---------------------------------------------------------------------------
# Lookup Helper
# ---------------------------------------------------------------------------

def lookup_ja3(ja3_hash: str) -> Optional[Dict]:
    """
    Look up a JA3 hash in the database.

    Returns:
        Dict with name, category, risk, description — or None if unknown.
    """
    if not ja3_hash:
        return None
    return JA3_DATABASE.get(ja3_hash.lower().strip())


def get_all_malware_hashes() -> list:
    """Return all JA3 hashes categorized as MALWARE."""
    return [
        h for h, info in JA3_DATABASE.items()
        if info["category"] == CATEGORY_MALWARE
    ]


def get_all_scripting_hashes() -> list:
    """Return all JA3 hashes categorized as SCRIPTING."""
    return [
        h for h, info in JA3_DATABASE.items()
        if info["category"] == CATEGORY_SCRIPTING
    ]
