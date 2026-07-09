#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Central Dashboard
==================================
Standalone HTTP server on port 49100.
Reads from vnc_honeypot.db and serves a real-time web UI.

Usage:
  python3 vnc_dashboard.py
  python3 vnc_dashboard.py --db vnc_honeypot.db --port 49100
  python3 vnc_dashboard.py --api-key secret123
"""

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("vnc_dashboard")

# ── Startup time ──────────────────────────────────────────────────────────────
_START_TIME = time.time()


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE LAYER
# ══════════════════════════════════════════════════════════════════════════════

class DashboardDB:
    """Read-only access to vnc_honeypot.db for dashboard queries."""

    def __init__(self, db_path: str) -> None:
        self._path = db_path

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA query_only=ON")
        return conn

    def overview(self) -> dict:
        """Aggregate stats for the overview tab."""
        with self._conn() as c:
            # Global counters from stats table
            stats = {r["key"]: r["value"]
                     for r in c.execute("SELECT key, value FROM stats")}

            total_conn     = c.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            total_captures = c.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
            total_raw      = c.execute("SELECT COUNT(*) FROM raw_vnc_captures").fetchone()[0]
            unique_ips     = c.execute("SELECT COUNT(DISTINCT ip) FROM connections").fetchone()[0]
            cve_alerts     = c.execute("SELECT COUNT(*) FROM cve_alerts").fetchone()[0]
            plain_passwords= c.execute(
                "SELECT COUNT(*) FROM raw_vnc_captures WHERE auth_type=18"
            ).fetchone()[0]

            # Risk distribution
            risk_dist = {r[0]: r[1] for r in c.execute(
                "SELECT risk_level, COUNT(*) FROM ip_stats GROUP BY risk_level"
            )}

            # Top client tags
            top_clients = [dict(r) for r in c.execute("""
                SELECT client_tag, COUNT(*) as count
                FROM connections
                WHERE client_tag IS NOT NULL AND client_tag != ''
                GROUP BY client_tag ORDER BY count DESC LIMIT 8
            """)]

            # Top countries
            top_countries = [dict(r) for r in c.execute("""
                SELECT country, COUNT(*) as count
                FROM ip_stats
                WHERE country IS NOT NULL AND country NOT IN ('', 'ZZ', 'PR')
                GROUP BY country ORDER BY count DESC LIMIT 10
            """)]

        return {
            "total_connections":  total_conn,
            "total_captures":     total_captures,
            "total_raw":          total_raw,
            "unique_ips":         unique_ips,
            "cve_alerts":         cve_alerts,
            "plain_passwords":    plain_passwords,
            "dual_captures":      stats.get("dual_captures", 0),
            "risk_distribution":  risk_dist,
            "top_clients":        top_clients,
            "top_countries":      top_countries,
            "uptime_seconds":     int(time.time() - _START_TIME),
            "db_path":            self._path,
            "db_size_kb":         int(os.path.getsize(self._path) / 1024)
                                  if os.path.exists(self._path) else 0,
        }

    def live_feed(self, limit: int = 100) -> list:
        """Most recent events across all tables, merged and sorted."""
        with self._conn() as c:
            events = []

            # Connections
            for r in c.execute(f"""
                SELECT timestamp, ip, port, status, info, proto, client_tag
                FROM connections ORDER BY timestamp DESC LIMIT {limit}
            """):
                events.append({
                    "ts":     r["timestamp"],
                    "type":   "connection",
                    "ip":     r["ip"],
                    "port":   r["port"],
                    "status": r["status"],
                    "detail": r["info"] or r["client_tag"] or "",
                    "proto":  r["proto"] or "VNC",
                })

            # Challenge-response captures
            for r in c.execute(f"""
                SELECT timestamp, ip, port, response, proto
                FROM captures ORDER BY timestamp DESC LIMIT {limit // 2}
            """):
                events.append({
                    "ts":     r["timestamp"],
                    "type":   "capture",
                    "ip":     r["ip"],
                    "port":   r["port"],
                    "status": "challenge_response",
                    "detail": f"response: {(r['response'] or '')[:16]}...",
                    "proto":  r["proto"] or "VNC",
                })

            # Plain auth (Type 18)
            for r in c.execute(f"""
                SELECT timestamp, ip, port, auth_data
                FROM raw_vnc_captures WHERE auth_type=18
                ORDER BY timestamp DESC LIMIT {limit // 4}
            """):
                auth = {}
                try:
                    auth = json.loads(r["auth_data"] or "{}")
                except Exception:
                    pass
                events.append({
                    "ts":     r["timestamp"],
                    "type":   "plain_auth",
                    "ip":     r["ip"],
                    "port":   r["port"],
                    "status": "plain_password",
                    "detail": f"user: {auth.get('user', '?')}",
                    "proto":  "VeNCrypt",
                })

            # CVE alerts
            for r in c.execute(f"""
                SELECT timestamp, ip, port, cve_id, name, risk
                FROM cve_alerts ORDER BY timestamp DESC LIMIT 30
            """):
                events.append({
                    "ts":     r["timestamp"],
                    "type":   "cve",
                    "ip":     r["ip"],
                    "port":   r["port"],
                    "status": f"CVE:{r['risk'].upper()}",
                    "detail": f"{r['cve_id']} — {r['name']}",
                    "proto":  "VNC",
                })

        # Sort all events by timestamp descending
        events.sort(key=lambda x: x["ts"] or "", reverse=True)
        return events[:limit]

    def attackers(self, limit: int = 50) -> list:
        """Top attacker IPs with full profile."""
        with self._conn() as c:
            rows = c.execute(f"""
                SELECT
                    s.ip,
                    s.first_seen, s.last_seen,
                    s.conn_count, s.capture_count,
                    s.country, s.asn, s.as_name, s.net_type,
                    s.bot_signature, s.risk_level, s.risk_score,
                    b.data_json as behavior_json
                FROM ip_stats s
                LEFT JOIN behavior b ON b.ip = s.ip
                ORDER BY s.risk_score DESC, s.conn_count DESC
                LIMIT {limit}
            """).fetchall()

        result = []
        for r in rows:
            behavior = {}
            try:
                behavior = json.loads(r["behavior_json"] or "{}")
            except Exception:
                pass
            result.append({
                "ip":           r["ip"],
                "first_seen":   r["first_seen"],
                "last_seen":    r["last_seen"],
                "conn_count":   r["conn_count"],
                "capture_count":r["capture_count"],
                "country":      r["country"] or "?",
                "asn":          r["asn"] or "",
                "as_name":      r["as_name"] or "",
                "net_type":     r["net_type"] or "",
                "bot_signature":r["bot_signature"] or "Unknown",
                "risk_level":   r["risk_level"] or "none",
                "risk_score":   r["risk_score"] or 0,
                "tags":         behavior.get("tags", []),
            })
        return result

    def captures(self, limit: int = 100, offset: int = 0) -> dict:
        """Paginated credential captures."""
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
            rows  = c.execute(f"""
                SELECT timestamp, ip, port, challenge, response, proto
                FROM captures ORDER BY timestamp DESC
                LIMIT {limit} OFFSET {offset}
            """).fetchall()

            # Plain auth separately
            plain = c.execute(f"""
                SELECT timestamp, ip, port, auth_data
                FROM raw_vnc_captures WHERE auth_type=18
                ORDER BY timestamp DESC LIMIT 50
            """).fetchall()

        challenge_response = [{
            "ts":        r["timestamp"],
            "ip":        r["ip"],
            "port":      r["port"],
            "challenge": r["challenge"],
            "response":  r["response"],
            "proto":     r["proto"],
        } for r in rows]

        plain_auth = []
        for r in plain:
            try:
                auth = json.loads(r["auth_data"] or "{}")
                plain_auth.append({
                    "ts":       r["timestamp"],
                    "ip":       r["ip"],
                    "port":     r["port"],
                    "username": auth.get("user", ""),
                    "password": auth.get("password", ""),
                })
            except Exception:
                pass

        return {
            "total":              total,
            "offset":             offset,
            "challenge_response": challenge_response,
            "plain_auth":         plain_auth,
        }

    def timeline(self, hours: int = 24) -> list:
        """Connections per hour for the last N hours."""
        with self._conn() as c:
            cutoff = (datetime.now(timezone.utc)
                      - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
            rows = c.execute("""
                SELECT
                    strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                    COUNT(*) as connections,
                    SUM(CASE WHEN status LIKE '%capture%' THEN 1 ELSE 0 END) as captures
                FROM connections
                WHERE timestamp >= ?
                GROUP BY hour ORDER BY hour
            """, (cutoff,)).fetchall()

        return [{"hour": r["hour"],
                 "connections": r["connections"],
                 "captures": r["captures"]} for r in rows]

    def geo(self) -> list:
        """Geographic distribution of attackers."""
        with self._conn() as c:
            rows = c.execute("""
                SELECT
                    country, COUNT(*) as ip_count,
                    SUM(conn_count) as total_connections,
                    SUM(capture_count) as total_captures
                FROM ip_stats
                WHERE country IS NOT NULL AND country NOT IN ('', 'ZZ', 'PR')
                GROUP BY country
                ORDER BY total_connections DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def cve_alerts(self, limit: int = 100) -> list:
        """CVE exploit attempts."""
        with self._conn() as c:
            rows = c.execute(f"""
                SELECT timestamp, ip, port, cve_id, name, risk
                FROM cve_alerts ORDER BY timestamp DESC LIMIT {limit}
            """).fetchall()
        return [dict(r) for r in rows]

    def status(self) -> dict:
        """Health check endpoint."""
        db_ok = os.path.exists(self._path)
        try:
            with self._conn() as c:
                c.execute("SELECT 1").fetchone()
            db_ok = True
        except Exception:
            db_ok = False
        return {
            "status":         "ok" if db_ok else "db_error",
            "uptime_seconds": int(time.time() - _START_TIME),
            "db_path":        self._path,
            "db_ok":          db_ok,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# HTTP REQUEST HANDLER
# ══════════════════════════════════════════════════════════════════════════════

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for dashboard and API requests."""

    db:      "DashboardDB"
    api_key: Optional[str] = None

    def log_message(self, format, *args) -> None:
        logger.debug(f"[http] {self.address_string()} — {format % args}")

    def _check_auth(self) -> bool:
        if not self.api_key:
            return True
        key = self.headers.get("X-API-Key") or ""
        if not key:
            parsed = urlparse(self.path)
            key = parse_qs(parsed.query).get("api_key", [""])[0]
        return key == self.api_key

    def _json(self, data: object, status: int = 200) -> None:
        body = json.dumps(data, default=str, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, msg: str) -> None:
        self._json({"error": msg}, status)

    def do_GET(self) -> None:
        try:
            parsed = urlparse(self.path)
            path   = parsed.path.rstrip("/") or "/"
            params = parse_qs(parsed.query)

            # Health check — no auth
            if path == "/api/status":
                self._json(self.db.status())
                return

            # Auth for everything else
            if not self._check_auth():
                self._error(401, "Unauthorized — provide X-API-Key header")
                return

            # Dashboard HTML
            if path in ("/", "/dashboard"):
                self._html(_DASHBOARD_HTML.encode("utf-8"))
                return

            # API endpoints
            if path == "/api/overview":
                self._json(self.db.overview())

            elif path == "/api/live":
                limit = min(int(params.get("limit", ["100"])[0]), 500)
                self._json(self.db.live_feed(limit))

            elif path == "/api/attackers":
                limit = min(int(params.get("limit", ["50"])[0]), 200)
                self._json(self.db.attackers(limit))

            elif path == "/api/captures":
                limit  = min(int(params.get("limit",  ["100"])[0]), 500)
                offset = max(0, int(params.get("offset", ["0"])[0]))
                self._json(self.db.captures(limit, offset))

            elif path == "/api/timeline":
                hours = min(int(params.get("hours", ["24"])[0]), 168)
                self._json(self.db.timeline(hours))

            elif path == "/api/geo":
                self._json(self.db.geo())

            elif path == "/api/cve":
                self._json(self.db.cve_alerts())

            else:
                self._error(404, f"Unknown endpoint: {path}")

        except (ValueError, TypeError) as e:
            self._error(400, f"Bad request: {e}")
        except Exception as e:
            logger.error(f"[handler] {e}")
            self._error(500, "Internal server error")


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD HTML
# ══════════════════════════════════════════════════════════════════════════════

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VNC Honeypot Dashboard</title>
<style>
  :root {
    --bg:       #0d1117;
    --bg2:      #161b22;
    --bg3:      #21262d;
    --border:   #30363d;
    --text:     #e6edf3;
    --muted:    #8b949e;
    --accent:   #58a6ff;
    --green:    #3fb950;
    --yellow:   #d29922;
    --red:      #f85149;
    --orange:   #e3b341;
    --purple:   #bc8cff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }

  /* ── Header ── */
  header {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 12px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky; top: 0; z-index: 100;
  }
  header h1 { font-size: 18px; font-weight: 600; color: var(--accent); }
  header h1 span { color: var(--muted); font-weight: 400; font-size: 13px; margin-left: 8px; }
  #uptime { color: var(--muted); font-size: 12px; }
  #refresh-badge {
    background: var(--green); color: #000; font-size: 11px; font-weight: 600;
    padding: 2px 8px; border-radius: 10px; margin-left: 8px;
  }

  /* ── Tabs ── */
  nav {
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex; gap: 4px;
  }
  nav button {
    background: none; border: none; color: var(--muted);
    padding: 10px 16px; cursor: pointer; font-size: 13px;
    border-bottom: 2px solid transparent; transition: color .15s;
  }
  nav button:hover { color: var(--text); }
  nav button.active { color: var(--accent); border-bottom-color: var(--accent); }

  /* ── Main ── */
  main { padding: 20px 24px; max-width: 1400px; margin: 0 auto; }

  /* ── Stat cards ── */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card {
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
  }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
  .card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .card .value.green  { color: var(--green); }
  .card .value.blue   { color: var(--accent); }
  .card .value.yellow { color: var(--yellow); }
  .card .value.red    { color: var(--red); }
  .card .value.purple { color: var(--purple); }

  /* ── Tables ── */
  .table-wrap { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
  .table-wrap h3 { padding: 12px 16px; font-size: 13px; color: var(--muted); border-bottom: 1px solid var(--border); text-transform: uppercase; letter-spacing: .5px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: var(--bg3); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; padding: 8px 12px; text-align: left; }
  td { padding: 8px 12px; border-top: 1px solid var(--border); font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 280px; }
  tr:hover td { background: var(--bg3); }

  /* ── Badges ── */
  .badge {
    display: inline-block; font-size: 11px; font-weight: 600;
    padding: 2px 7px; border-radius: 10px; text-transform: uppercase;
  }
  .badge.high    { background: #3d1a1a; color: var(--red); }
  .badge.medium  { background: #3d2d00; color: var(--yellow); }
  .badge.low     { background: #1a2d1a; color: var(--green); }
  .badge.none    { background: var(--bg3); color: var(--muted); }
  .badge.capture { background: #1a2d3d; color: var(--accent); }
  .badge.cve     { background: #3d1a2d; color: var(--purple); }
  .badge.plain   { background: #3d2d00; color: var(--orange); }

  /* ── Timeline chart ── */
  #timeline-chart { width: 100%; height: 180px; background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 12px; }

  /* ── Two-col layout ── */
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
  @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }

  /* ── Mini bar chart ── */
  .bar-row { display: flex; align-items: center; gap: 8px; margin: 4px 0; font-size: 12px; }
  .bar-row .label { width: 80px; color: var(--muted); text-align: right; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; }
  .bar-row .bar   { flex: 1; height: 14px; background: var(--bg3); border-radius: 3px; overflow: hidden; }
  .bar-row .fill  { height: 100%; background: var(--accent); border-radius: 3px; transition: width .3s; }
  .bar-row .count { width: 40px; color: var(--muted); text-align: right; flex-shrink: 0; }

  /* ── Tag chips ── */
  .tag { background: var(--bg3); color: var(--muted); font-size: 11px; padding: 1px 6px; border-radius: 4px; margin: 1px; display: inline-block; }

  /* ── Pagination ── */
  .pagination { display: flex; gap: 8px; margin-top: 12px; justify-content: flex-end; }
  .pagination button { background: var(--bg3); border: 1px solid var(--border); color: var(--text); padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
  .pagination button:disabled { opacity: .4; cursor: default; }

  .hidden { display: none !important; }
  .mono { font-family: 'Consolas', 'SF Mono', monospace; font-size: 12px; }
</style>
</head>
<body>

<header>
  <div>
    <h1>VNC Honeypot <span>Dashboard</span></h1>
  </div>
  <div style="display:flex;align-items:center;gap:12px">
    <span id="uptime">Loading...</span>
    <span id="refresh-badge">LIVE</span>
  </div>
</header>

<nav>
  <button class="active" onclick="showTab('overview')">Overview</button>
  <button onclick="showTab('live')">Live Feed</button>
  <button onclick="showTab('attackers')">Attackers</button>
  <button onclick="showTab('captures')">Captures</button>
  <button onclick="showTab('timeline')">Timeline</button>
  <button onclick="showTab('geo')">Geo</button>
  <button onclick="showTab('cve')">CVE Alerts</button>
</nav>

<main>

<!-- ── Overview ── -->
<div id="tab-overview">
  <div class="cards" id="stat-cards">
    <div class="card"><div class="label">Connections</div><div class="value blue" id="s-conn">—</div></div>
    <div class="card"><div class="label">Captures</div><div class="value green" id="s-cap">—</div></div>
    <div class="card"><div class="label">Plain Auth</div><div class="value yellow" id="s-plain">—</div></div>
    <div class="card"><div class="label">Unique IPs</div><div class="value blue" id="s-ips">—</div></div>
    <div class="card"><div class="label">CVE Alerts</div><div class="value red" id="s-cve">—</div></div>
    <div class="card"><div class="label">Dual Captures</div><div class="value purple" id="s-dual">—</div></div>
  </div>

  <div class="two-col">
    <div class="table-wrap">
      <h3>Top Client Types</h3>
      <div id="client-bars" style="padding:12px"></div>
    </div>
    <div class="table-wrap">
      <h3>Top Countries</h3>
      <div id="country-bars" style="padding:12px"></div>
    </div>
  </div>

  <div class="two-col">
    <div class="table-wrap">
      <h3>Risk Distribution</h3>
      <div id="risk-bars" style="padding:12px"></div>
    </div>
    <div class="table-wrap">
      <h3>Database</h3>
      <div style="padding:12px;color:var(--muted);font-size:13px" id="db-info">—</div>
    </div>
  </div>
</div>

<!-- ── Live Feed ── -->
<div id="tab-live" class="hidden">
  <div class="table-wrap">
    <h3>Live Events (last 100)</h3>
    <table>
      <thead><tr>
        <th>Time</th><th>Type</th><th>IP</th><th>Port</th><th>Status</th><th>Detail</th><th>Protocol</th>
      </tr></thead>
      <tbody id="live-body"></tbody>
    </table>
  </div>
</div>

<!-- ── Attackers ── -->
<div id="tab-attackers" class="hidden">
  <div class="table-wrap">
    <h3>Top Attackers by Risk Score</h3>
    <table>
      <thead><tr>
        <th>IP</th><th>Country</th><th>Risk</th><th>Score</th>
        <th>Connections</th><th>Captures</th><th>Bot Type</th><th>Tags</th><th>Last Seen</th>
      </tr></thead>
      <tbody id="attackers-body"></tbody>
    </table>
  </div>
</div>

<!-- ── Captures ── -->
<div id="tab-captures" class="hidden">
  <div class="table-wrap">
    <h3>Challenge-Response Captures</h3>
    <table>
      <thead><tr>
        <th>Time</th><th>IP</th><th>Port</th><th>Challenge</th><th>Response</th><th>Protocol</th>
      </tr></thead>
      <tbody id="captures-cr-body"></tbody>
    </table>
  </div>
  <div class="pagination">
    <button id="prev-btn" onclick="changePage(-1)" disabled>← Prev</button>
    <span id="page-info" style="padding:4px 8px;color:var(--muted);font-size:12px"></span>
    <button id="next-btn" onclick="changePage(1)">Next →</button>
  </div>

  <div class="table-wrap" style="margin-top:16px">
    <h3>Plain Auth Captures (SecurityType 18)</h3>
    <table>
      <thead><tr>
        <th>Time</th><th>IP</th><th>Port</th><th>Username</th><th>Password</th>
      </tr></thead>
      <tbody id="captures-plain-body"></tbody>
    </table>
  </div>
</div>

<!-- ── Timeline ── -->
<div id="tab-timeline" class="hidden">
  <div class="table-wrap" style="padding:16px">
    <h3 style="margin-bottom:12px">Activity Timeline — Last 24 Hours</h3>
    <canvas id="timeline-chart"></canvas>
  </div>
</div>

<!-- ── Geo ── -->
<div id="tab-geo" class="hidden">
  <div class="table-wrap">
    <h3>Geographic Distribution</h3>
    <table>
      <thead><tr>
        <th>Country</th><th>Unique IPs</th><th>Total Connections</th><th>Captures</th>
      </tr></thead>
      <tbody id="geo-body"></tbody>
    </table>
  </div>
</div>

<!-- ── CVE ── -->
<div id="tab-cve" class="hidden">
  <div class="table-wrap">
    <h3>CVE Exploit Attempts</h3>
    <table>
      <thead><tr>
        <th>Time</th><th>IP</th><th>Port</th><th>CVE ID</th><th>Name</th><th>Risk</th>
      </tr></thead>
      <tbody id="cve-body"></tbody>
    </table>
  </div>
</div>

</main>

<script>
// ── State ──────────────────────────────────────────────────────────────────
let activeTab    = 'overview';
let capturesPage = 0;
const PAGE_SIZE  = 50;
let timelineData = [];

// ── Tab switching ──────────────────────────────────────────────────────────
function showTab(name) {
  activeTab = name;
  document.querySelectorAll('main > div').forEach(d => d.classList.add('hidden'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.remove('hidden');
  document.querySelector(`nav button[onclick="showTab('${name}')"]`).classList.add('active');
  refreshTab(name);
}

// ── Fetch helpers ──────────────────────────────────────────────────────────
async function api(endpoint) {
  try {
    const r = await fetch(endpoint);
    if (!r.ok) throw new Error(r.status);
    return await r.json();
  } catch(e) {
    console.error('API error:', endpoint, e);
    return null;
  }
}

function ts(iso) {
  if (!iso) return '—';
  return iso.replace('T', ' ').substring(0, 19);
}

function riskBadge(level) {
  return `<span class="badge ${level||'none'}">${level||'none'}</span>`;
}

function typeBadge(type) {
  const cls = type === 'capture' ? 'capture' : type === 'cve' ? 'cve' : type === 'plain_auth' ? 'plain' : 'none';
  return `<span class="badge ${cls}">${type}</span>`;
}

// ── Bar chart helper ───────────────────────────────────────────────────────
function renderBars(containerId, items, labelKey, valueKey, color) {
  const el  = document.getElementById(containerId);
  if (!items || !items.length) { el.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:4px">No data yet</div>'; return; }
  const max = Math.max(...items.map(i => i[valueKey]), 1);
  el.innerHTML = items.map(i => `
    <div class="bar-row">
      <div class="label" title="${i[labelKey]}">${i[labelKey]}</div>
      <div class="bar"><div class="fill" style="width:${Math.round(i[valueKey]/max*100)}%;background:${color||'var(--accent)'}"></div></div>
      <div class="count">${i[valueKey]}</div>
    </div>
  `).join('');
}

// ── Overview ───────────────────────────────────────────────────────────────
async function loadOverview() {
  const d = await api('/api/overview');
  if (!d) return;

  document.getElementById('s-conn').textContent  = d.total_connections.toLocaleString();
  document.getElementById('s-cap').textContent   = d.total_captures.toLocaleString();
  document.getElementById('s-plain').textContent = d.plain_passwords.toLocaleString();
  document.getElementById('s-ips').textContent   = d.unique_ips.toLocaleString();
  document.getElementById('s-cve').textContent   = d.cve_alerts.toLocaleString();
  document.getElementById('s-dual').textContent  = (d.dual_captures||0).toLocaleString();

  renderBars('client-bars',  d.top_clients,   'client_tag', 'count', 'var(--accent)');
  renderBars('country-bars', d.top_countries, 'country',    'count', 'var(--green)');

  // Risk distribution
  const risk = d.risk_distribution || {};
  const riskEl = document.getElementById('risk-bars');
  const riskItems = ['high','medium','low','none'].map(k => ({label: k, value: risk[k]||0}));
  const riskColors = {high:'var(--red)',medium:'var(--yellow)',low:'var(--green)',none:'var(--muted)'};
  const riskMax = Math.max(...riskItems.map(r => r.value), 1);
  riskEl.innerHTML = riskItems.map(r => `
    <div class="bar-row">
      <div class="label">${r.label}</div>
      <div class="bar"><div class="fill" style="width:${Math.round(r.value/riskMax*100)}%;background:${riskColors[r.label]}"></div></div>
      <div class="count">${r.value}</div>
    </div>
  `).join('');

  document.getElementById('db-info').innerHTML = `
    <div style="margin-bottom:6px"><span style="color:var(--muted)">Path:</span> <span class="mono">${d.db_path}</span></div>
    <div style="margin-bottom:6px"><span style="color:var(--muted)">Size:</span> ${d.db_size_kb} KB</div>
    <div><span style="color:var(--muted)">Uptime:</span> ${formatUptime(d.uptime_seconds)}</div>
  `;
}

// ── Live Feed ──────────────────────────────────────────────────────────────
async function loadLive() {
  const events = await api('/api/live?limit=100');
  if (!events) return;
  const tbody = document.getElementById('live-body');
  tbody.innerHTML = events.map(e => `
    <tr>
      <td class="mono">${ts(e.ts)}</td>
      <td>${typeBadge(e.type)}</td>
      <td class="mono">${e.ip}</td>
      <td>${e.port||'—'}</td>
      <td><span class="mono" style="font-size:11px">${e.status||'—'}</span></td>
      <td style="color:var(--muted)">${e.detail||'—'}</td>
      <td>${e.proto||'VNC'}</td>
    </tr>
  `).join('') || '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">No events yet</td></tr>';
}

// ── Attackers ──────────────────────────────────────────────────────────────
async function loadAttackers() {
  const rows = await api('/api/attackers?limit=50');
  if (!rows) return;
  const tbody = document.getElementById('attackers-body');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${r.ip}</td>
      <td>${r.country}</td>
      <td>${riskBadge(r.risk_level)}</td>
      <td style="color:var(--yellow)">${r.risk_score}</td>
      <td>${r.conn_count.toLocaleString()}</td>
      <td>${r.capture_count.toLocaleString()}</td>
      <td>${r.bot_signature}</td>
      <td>${(r.tags||[]).map(t=>`<span class="tag">${t}</span>`).join('')}</td>
      <td class="mono" style="color:var(--muted)">${ts(r.last_seen)}</td>
    </tr>
  `).join('') || '<tr><td colspan="9" style="color:var(--muted);text-align:center;padding:20px">No attackers profiled yet</td></tr>';
}

// ── Captures ──────────────────────────────────────────────────────────────
async function loadCaptures() {
  const d = await api(`/api/captures?limit=${PAGE_SIZE}&offset=${capturesPage * PAGE_SIZE}`);
  if (!d) return;

  const crBody = document.getElementById('captures-cr-body');
  crBody.innerHTML = d.challenge_response.map(r => `
    <tr>
      <td class="mono">${ts(r.ts)}</td>
      <td class="mono">${r.ip}</td>
      <td>${r.port}</td>
      <td class="mono" style="color:var(--muted)">${(r.challenge||'').substring(0,16)}…</td>
      <td class="mono" style="color:var(--accent)">${(r.response||'').substring(0,16)}…</td>
      <td>${r.proto||'VNC'}</td>
    </tr>
  `).join('') || '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No captures yet</td></tr>';

  const total = d.total;
  const totalPages = Math.ceil(total / PAGE_SIZE);
  document.getElementById('page-info').textContent =
    `Page ${capturesPage+1} of ${totalPages||1} (${total.toLocaleString()} total)`;
  document.getElementById('prev-btn').disabled = capturesPage === 0;
  document.getElementById('next-btn').disabled = capturesPage >= totalPages - 1;

  const plainBody = document.getElementById('captures-plain-body');
  plainBody.innerHTML = (d.plain_auth||[]).map(r => `
    <tr>
      <td class="mono">${ts(r.ts)}</td>
      <td class="mono">${r.ip}</td>
      <td>${r.port}</td>
      <td style="color:var(--yellow)">${r.username||'—'}</td>
      <td style="color:var(--red)">${r.password||'—'}</td>
    </tr>
  `).join('') || '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No plain auth captures yet</td></tr>';
}

function changePage(delta) {
  capturesPage = Math.max(0, capturesPage + delta);
  loadCaptures();
}

// ── Timeline ──────────────────────────────────────────────────────────────
async function loadTimeline() {
  const data = await api('/api/timeline?hours=24');
  if (!data) return;
  timelineData = data;
  drawTimeline(data);
}

function drawTimeline(data) {
  const canvas = document.getElementById('timeline-chart');
  const ctx    = canvas.getContext('2d');
  const W = canvas.offsetWidth;
  const H = canvas.offsetHeight || 180;
  canvas.width  = W;
  canvas.height = H;

  ctx.clearRect(0, 0, W, H);

  if (!data.length) {
    ctx.fillStyle = '#8b949e';
    ctx.font = '14px system-ui';
    ctx.textAlign = 'center';
    ctx.fillText('No timeline data yet', W/2, H/2);
    return;
  }

  const maxConn = Math.max(...data.map(d => d.connections), 1);
  const pad = { left: 40, right: 16, top: 16, bottom: 28 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top  - pad.bottom;
  const barW   = Math.max(2, chartW / data.length - 2);

  // Grid lines
  ctx.strokeStyle = '#21262d';
  ctx.lineWidth   = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + chartH * (1 - i/4);
    ctx.beginPath();
    ctx.moveTo(pad.left, y);
    ctx.lineTo(W - pad.right, y);
    ctx.stroke();
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxConn * i/4), pad.left - 4, y + 3);
  }

  // Bars — connections
  data.forEach((d, i) => {
    const x = pad.left + i * (chartW / data.length);
    const h = (d.connections / maxConn) * chartH;
    const y = pad.top + chartH - h;
    ctx.fillStyle = '#1f3a5f';
    ctx.fillRect(x, y, barW, h);

    // Captures overlay
    if (d.captures > 0) {
      const hc = (d.captures / maxConn) * chartH;
      const yc = pad.top + chartH - hc;
      ctx.fillStyle = '#58a6ff';
      ctx.fillRect(x, yc, barW, hc);
    }
  });

  // X labels — every 4 hours
  ctx.fillStyle = '#8b949e';
  ctx.font = '10px monospace';
  ctx.textAlign = 'center';
  data.forEach((d, i) => {
    if (i % 4 === 0 && d.hour) {
      const x = pad.left + i * (chartW / data.length) + barW/2;
      const label = d.hour.substring(11, 16);
      ctx.fillText(label, x, H - 4);
    }
  });

  // Legend
  ctx.fillStyle = '#1f3a5f';
  ctx.fillRect(pad.left, 4, 12, 8);
  ctx.fillStyle = '#8b949e';
  ctx.font = '10px system-ui';
  ctx.textAlign = 'left';
  ctx.fillText('Connections', pad.left + 16, 12);

  ctx.fillStyle = '#58a6ff';
  ctx.fillRect(pad.left + 110, 4, 12, 8);
  ctx.fillStyle = '#8b949e';
  ctx.fillText('Captures', pad.left + 126, 12);
}

// ── Geo ───────────────────────────────────────────────────────────────────
async function loadGeo() {
  const rows = await api('/api/geo');
  if (!rows) return;
  const tbody = document.getElementById('geo-body');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td><strong>${r.country}</strong></td>
      <td>${r.ip_count.toLocaleString()}</td>
      <td>${r.total_connections.toLocaleString()}</td>
      <td>${(r.total_captures||0).toLocaleString()}</td>
    </tr>
  `).join('') || '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No geo data yet</td></tr>';
}

// ── CVE ───────────────────────────────────────────────────────────────────
async function loadCve() {
  const rows = await api('/api/cve');
  if (!rows) return;
  const tbody = document.getElementById('cve-body');
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="mono">${ts(r.timestamp)}</td>
      <td class="mono">${r.ip}</td>
      <td>${r.port}</td>
      <td class="mono" style="color:var(--purple)">${r.cve_id}</td>
      <td>${r.name}</td>
      <td>${riskBadge(r.risk)}</td>
    </tr>
  `).join('') || '<tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No CVE alerts yet</td></tr>';
}

// ── Uptime ─────────────────────────────────────────────────────────────────
function formatUptime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

async function updateUptime() {
  const d = await api('/api/status');
  if (d) {
    document.getElementById('uptime').textContent =
      `Uptime: ${formatUptime(d.uptime_seconds)}`;
  }
}

// ── Auto-refresh ──────────────────────────────────────────────────────────
function refreshTab(tab) {
  tab = tab || activeTab;
  if (tab === 'overview')   loadOverview();
  else if (tab === 'live')  loadLive();
  else if (tab === 'attackers') loadAttackers();
  else if (tab === 'captures')  loadCaptures();
  else if (tab === 'timeline')  loadTimeline();
  else if (tab === 'geo')   loadGeo();
  else if (tab === 'cve')   loadCve();
}

// Initial load + auto-refresh every 15 seconds
refreshTab('overview');
updateUptime();
setInterval(() => { refreshTab(); updateUptime(); }, 15000);
window.addEventListener('resize', () => {
  if (activeTab === 'timeline') drawTimeline(timelineData);
});
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# SERVER
# ══════════════════════════════════════════════════════════════════════════════

def run_server(db_path: str, port: int, api_key: Optional[str] = None) -> None:
    """Start the dashboard HTTP server."""

    class Handler(DashboardHandler):
        pass

    Handler.db      = DashboardDB(db_path)
    Handler.api_key = api_key

    server = HTTPServer(("0.0.0.0", port), Handler)
    logger.info(f"[dashboard] VNC Honeypot Dashboard on http://0.0.0.0:{port}")
    logger.info(f"[dashboard] Database: {db_path}")
    if api_key:
        logger.info(f"[dashboard] Auth enabled — X-API-Key required")
    else:
        logger.info(f"[dashboard] No auth — open access (use --api-key in production)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("[dashboard] Shutting down...")
        server.server_close()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="VNC Honeypot Dashboard — port 49100",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("--db",      default="vnc_honeypot.db",
                    help="Path to vnc_honeypot.db")
    ap.add_argument("--port",    type=int, default=49100,
                    help="Dashboard port")
    ap.add_argument("--api-key", default=None, metavar="KEY",
                    help="Optional API key for authentication")
    ap.add_argument("--verbose", action="store_true",
                    help="Debug logging")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if not os.path.exists(args.db):
        logger.warning(f"[dashboard] DB not found: {args.db} — will retry on each request")

    run_server(args.db, args.port, args.api_key)


if __name__ == "__main__":
    main()
