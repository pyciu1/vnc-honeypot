#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — GeoIP & Bot Signature
=======================================
Lookup țară/ASN per IP + clasificare bot.

MaxMind GeoLite2 integration (optional).
If GeoLite2-City.mmdb is not available,
falls back to a static table of known prefixes.
"""

import ipaddress
import logging
import sqlite3
from typing import Optional, Tuple

logger = logging.getLogger("vnc_honeypot.geo")

# ── MaxMind optional ──────────────────────────────────────────────────────────
try:
    import geoip2.database
    _HAS_GEOIP2 = True
except ImportError:
    _HAS_GEOIP2 = False

_geoip_reader: Optional[object] = None


def setup_geoip(db_path: str) -> bool:
    """Initializes MaxMind reader. Returns True on success."""
    """
    Initializes MaxMind reader.
    Returns True on success.
    """
    global _geoip_reader
    if not _HAS_GEOIP2:
        logger.info("[geo] geoip2 not installed — using offline fallback")
        return False
    try:
        _geoip_reader = geoip2.database.Reader(db_path)
        logger.info(f"[geo] MaxMind GeoLite2 loaded: {db_path}")
        return True
    except Exception as e:
        logger.warning(f"[geo] MaxMind load failed: {e} — using offline fallback")
        return False


# ── Prefixe cunoscute (fallback) ──────────────────────────────────────────────
_KNOWN_PREFIXES: list = [
    ("134.199.", "DE", "AS24940", "Hetzner",      "Cloud/Hosting"),
    ("88.198.",  "DE", "AS24940", "Hetzner",      "Cloud/Hosting"),
    ("165.232.", "NL", "AS14061", "DigitalOcean", "Cloud/Hosting"),
    ("167.71.",  "NL", "AS14061", "DigitalOcean", "Cloud/Hosting"),
    ("68.183.",  "US", "AS14061", "DigitalOcean", "Cloud/Hosting"),
    ("128.199.", "SG", "AS14061", "DigitalOcean", "Cloud/Hosting"),
    ("162.243.", "US", "AS14061", "DigitalOcean", "Cloud/Hosting"),
    ("179.43.",  "CH", "AS51852", "PrivateLayer", "Hosting"),
    ("185.220.", "DE", "AS207960","Tor Exit",     "Tor/Proxy"),
    ("45.33.",   "US", "AS63949", "Linode",       "Cloud/Hosting"),
    ("139.59.",  "IN", "AS14061", "DigitalOcean", "Cloud/Hosting"),
    ("192.241.", "US", "AS14061", "DigitalOcean", "Cloud/Hosting"),
]

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def geoip_lookup(ip: str) -> Tuple[str, str, str, str]:
    """Returns (country_code, asn, as_name, net_type) for an IP."""
    """
    Returns (country_code, asn, as_name, net_type).
    Priority: MaxMind → prefix table → fallback.
    """
    if _is_private(ip):
        return "PR", "-", "Private", "Private"

    # Try MaxMind
    if _geoip_reader and _HAS_GEOIP2:
        try:
            resp = _geoip_reader.city(ip)
            country = resp.country.iso_code or "ZZ"
            return country, "-", resp.city.name or "Unknown", "Public"
        except Exception:
            pass

    # Fallback prefix table
    for prefix, ctry, asn, aname, ntype in _KNOWN_PREFIXES:
        if ip.startswith(prefix):
            return ctry, asn, aname, ntype

    return "ZZ", "-", "Public/Unknown", "Public/Unknown"


def compute_bot_signature(conn: sqlite3.Connection, ip: str) -> str:
    """Classifies IP behavior based on history in DB."""
    """
    Classifies IP behavior based on history in DB.
    Returns a descriptive string: BruteForce-Client, Mass-Scanner, etc.
    """
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM connections WHERE ip=?", (ip,))
    total_conn = c.fetchone()[0] or 0

    c.execute("SELECT COUNT(*) FROM captures WHERE ip=?", (ip,))
    total_caps = c.fetchone()[0] or 0

    c.execute("SELECT COUNT(DISTINCT port) FROM connections WHERE ip=?", (ip,))
    ports = c.fetchone()[0] or 0

    c.execute("""
        SELECT status, COUNT(*) FROM connections
        WHERE ip=? GROUP BY status
    """, (ip,))
    status_counts = {row[0]: row[1] for row in c.fetchall()}

    if total_caps >= 3:
        return "BruteForce-Client"

    handshake_only = status_counts.get("handshake_only", 0)
    if total_conn >= 20 and handshake_only >= total_conn * 0.8:
        return "Mass-Scanner"

    http_scans = (
        status_counts.get("http_probe", 0)
        + status_counts.get("http_vnc_web", 0)
        + status_counts.get("http_vnc_probe", 0)
    )
    if total_conn >= 5 and http_scans >= total_conn * 0.8:
        return "HTTP-Scanner"

    if status_counts.get("http_exploit", 0) >= 1:
        return "HTTP-Exploitor"

    if ports >= 5:
        return "Port-Sweeper"

    if total_conn <= 3 and total_caps == 0:
        return "Single-Shot-Scanner"

    return "Unknown"


def ensure_ip_enriched(conn: sqlite3.Connection, ip: str) -> None:
    """Fills in GeoIP data and bot_signature for an IP if missing."""
    """
    Fills in GeoIP data and bot_signature for an IP
    if not already in DB.
    """
    c = conn.cursor()
    c.execute("""
        SELECT country, asn, as_name, net_type,
               bot_signature, risk_level, risk_score
        FROM ip_stats WHERE ip=?
    """, (ip,))
    row = c.fetchone()
    if not row:
        return

    country, asn, as_name, net_type, bot_sig, risk_level, risk_score = row

    if not all([country, asn, as_name, net_type]):
        g_country, g_asn, g_asname, g_ntype = geoip_lookup(ip)
        c.execute("""
            UPDATE ip_stats
            SET country=?, asn=?, as_name=?, net_type=?
            WHERE ip=?
        """, (g_country, g_asn, g_asname, g_ntype, ip))

    if not bot_sig:
        sig = compute_bot_signature(conn, ip)
        c.execute(
            "UPDATE ip_stats SET bot_signature=? WHERE ip=?",
            (sig, ip)
        )

    if risk_level is None or risk_score is None:
        c.execute("""
            UPDATE ip_stats SET risk_level=?, risk_score=? WHERE ip=?
        """, ("unknown", 0, ip))


__all__ = [
    "setup_geoip", "geoip_lookup",
    "compute_bot_signature", "ensure_ip_enriched",
]
