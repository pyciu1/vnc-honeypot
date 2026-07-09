#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Configuration
==============================
Central configuration — all constants and settings.
"""
import os

# ── Analytic mode ─────────────────────────────────────────────────────────────
ANALYTIC_FIXED_CHALLENGE: bool = True
FIXED_VNC_CHALLENGE: bytes = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08"
    b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
)

# ── Config principal ──────────────────────────────────────────────────────────
CONFIG: dict = {
    "vnc_ports":          list(range(5900, 5911)),
    "http_port":          5800,
    "db_file":            "vnc_honeypot.db",
    "max_workers":        200,
    "socket_timeout":     3.0,
    "bucket_rate":        5,
    "bucket_capacity":    50,
    "max_conn_per_ip":    100,
    "window_seconds":     60,
    "batch_size":         50,
    "batch_flush_timeout": 5.0,
    "recent_events_size": 400,
    "timeline_minutes":   60,
    "timeline_hours":     24,
    "geoip_db":           os.getenv("VNC_GEOIP_DB", None),
}

# ── VNC Protocol constants ────────────────────────────────────────────────────
VNC_SECURITY_NONE       = 1
VNC_SECURITY_VNC_AUTH   = 2
VNC_SECURITY_TLS        = 18
VNC_SECURITY_VENCRYPT   = 19
VNC_AUTH_OK             = 0
VNC_AUTH_FAIL           = 1
RFB_VERSIONS_CLASSIC    = {"003.003"}
RFB_VERSIONS_MODERN     = {"003.007","003.008","003.889","004.000","004.001","005.000","005.001"}

__all__ = [
    "ANALYTIC_FIXED_CHALLENGE", "FIXED_VNC_CHALLENGE", "CONFIG",
    "VNC_SECURITY_NONE", "VNC_SECURITY_VNC_AUTH",
    "VNC_SECURITY_TLS", "VNC_SECURITY_VENCRYPT",
    "VNC_AUTH_OK", "VNC_AUTH_FAIL",
    "RFB_VERSIONS_CLASSIC", "RFB_VERSIONS_MODERN",
]
