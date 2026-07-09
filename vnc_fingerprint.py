#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Client Fingerprinting & CVE Detection
=======================================================
VNCClientFingerprinter — identifies VNC client from handshake.
CVEExploitDetector — detects patterns of known exploits.
"""

import logging
from typing import Optional

logger = logging.getLogger("vnc_honeypot.fingerprint")


# ══════════════════════════════════════════════════════════════════════════════
# VNC CLIENT FINGERPRINTER
# ══════════════════════════════════════════════════════════════════════════════

# RFB version string → client info mapping
# Note: same version may be sent by different clients —
# fingerprinting is probabilistic, not deterministic.
_CLIENT_SIGNATURES: dict = {
    b"RFB 003.003\n": {"client_name": "RealVNC/x11vnc/Android VNC",  "client_version": "3.3", "client_type": "mixed",    "vendor": "Various"},
    b"RFB 003.005\n": {"client_name": "RealVNC",          "client_version": "3.5", "client_type": "desktop",  "vendor": "RealVNC Ltd"},
    b"RFB 003.006\n": {"client_name": "UltraVNC",         "client_version": "1.0.x","client_type": "desktop", "vendor": "UltraVNC Team"},
    b"RFB 003.007\n": {"client_name": "RealVNC/UltraVNC", "client_version": "3.7", "client_type": "desktop",  "vendor": "Various"},
    b"RFB 003.008\n": {"client_name": "RealVNC/TigerVNC", "client_version": "3.8", "client_type": "desktop",  "vendor": "Various"},
    b"RFB 003.889\n": {"client_name": "TightVNC/Apple",   "client_version": "1.3", "client_type": "mixed",    "vendor": "TightVNC/Apple"},
    b"RFB 004.000\n": {"client_name": "RealVNC/TigerVNC", "client_version": "4.x", "client_type": "enterprise","vendor": "Various"},
    b"RFB 004.001\n": {"client_name": "TightVNC",         "client_version": "2.x", "client_type": "desktop",  "vendor": "TightVNC Team"},
    b"RFB 005.000\n": {"client_name": "TigerVNC",         "client_version": "1.12+","client_type": "desktop", "vendor": "TigerVNC Team"},
    b"RFB 005.001\n": {"client_name": "TigerVNC",         "client_version": "1.12+","client_type": "desktop", "vendor": "TigerVNC Team"},
    b"RFB 000.000\n": {"client_name": "Generic Scanner",  "client_version": "n/a", "client_type": "scanner",  "vendor": "Unknown"},
    b"RFB 003.000\n": {"client_name": "Test Client",      "client_version": "test","client_type": "scanner",  "vendor": "Test"},
}


class VNCClientFingerprinter:
    """
    Identifies VNC client from hello bytes and analyses the response.
    Fingerprinting is probabilistic — the same RFB version may be
    sent by different clients (RealVNC, TigerVNC, etc.).
    """

    def fingerprint(self, client_hello: bytes,
                    auth_response: bytes = b"") -> dict:
        """Identifies VNC client from hello bytes + analyses response."""
        """
        Returns a dict with client information.

        client_hello  — first bytes received from client (contains "RFB X.Y")
        auth_response — DES response to challenge (16 bytes, optional)
        """
        fp: dict = {
            "client_name":          "unknown",
            "client_version":       "unknown",
            "client_type":          "unknown",
            "vendor":               "unknown",
            "confidence":           0,
            "enterprise_indicators": [],
            "response_analysis":    {},
        }

        # Exact match on first 12 bytes (RFB X.Y\n)
        for sig, info in _CLIENT_SIGNATURES.items():
            if client_hello.startswith(sig):
                fp.update(info)
                fp["confidence"] = 80
                break

        # Fallback: parse any "RFB X.Y"
        if fp["confidence"] == 0:
            try:
                proto = client_hello.decode("ascii", errors="ignore").strip()
                if proto.startswith("RFB "):
                    parts = proto.split()
                    if len(parts) >= 2:
                        fp.update({
                            "client_name":    f"VNC Client {parts[1]}",
                            "client_version": parts[1],
                            "client_type":    "unregistered",
                            "vendor":         "Unknown",
                            "confidence":     50,
                        })
            except Exception:
                pass

        # Analyse response (if present)
        if auth_response and len(auth_response) == 16:
            analysis = self._analyze_response(auth_response)
            fp["response_analysis"] = analysis

            if analysis.get("is_null"):
                fp["enterprise_indicators"].append("null_password")
                fp["confidence"] = max(fp["confidence"], 95)
            if analysis.get("is_ff"):
                fp["enterprise_indicators"].append("all_ff_password")
                fp["confidence"] = max(fp["confidence"], 85)
            if analysis.get("is_repeating"):
                fp["enterprise_indicators"].append("repeating_pattern")
                fp["confidence"] = max(fp["confidence"], 75)

        return fp

    def _analyze_response(self, response: bytes) -> dict:
        """Analyses patterns in the 16-byte DES response."""
        """Analyses patterns in the authentication response."""
        return {
            "length":       len(response),
            "hex":          response.hex(),
            "is_null":      response == b"\x00" * 16,
            "is_ff":        response == b"\xff" * 16,
            "is_repeating": len(set(response)) == 1,
            "first_bytes":  response[:4].hex(),
            "entropy":      len(set(response)) / 16.0,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CVE EXPLOIT DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

_VNC_CVES: dict = {
    "CVE-2006-2369": {
        "name":    "RealVNC Buffer Overflow",
        "pattern": b"A" * 5000,
        "ports":   [5900],
        "risk":    "critical",
        "desc":    "Buffer overflow in RealVNC 4.1.1 and earlier",
    },
    "CVE-2014-8242": {
        "name":    "TightVNC Auth Bypass",
        "pattern": b"\x00" * 16,
        "ports":   [5900, 5800],
        "risk":    "high",
        "desc":    "Authentication bypass via null response",
    },
    "CVE-2019-15680": {
        "name":    "UltraVNC Path Traversal",
        "pattern": b"../" * 100,
        "ports":   [5800],
        "risk":    "high",
        "desc":    "Path traversal in UltraVNC file transfer",
    },
    "CVE-2019-8287": {
        "name":    "LibVNCServer Heap Overflow",
        "pattern": b"\xff\xfe" * 50,
        "ports":   [5900],
        "risk":    "high",
        "desc":    "Heap overflow in LibVNCServer HandleCursorShape",
    },
}


class CVEExploitDetector:
    """Detects known VNC exploit patterns in raw traffic."""

    def check_for_exploits(self, data: bytes, port: int) -> list:
        """Searches for CVE signatures in raw received data."""
        """
        Searches for CVE patterns in received data.
        Returns the list of detected exploits.
        """
        detected = []
        for cve_id, info in _VNC_CVES.items():
            if port in info["ports"] and info["pattern"] in data:
                detected.append({
                    "cve":      cve_id,
                    "name":     info["name"],
                    "risk":     info["risk"],
                    "desc":     info["desc"],
                    "evidence": data[:100].hex(),
                })
        return detected


__all__ = ["VNCClientFingerprinter", "CVEExploitDetector"]
