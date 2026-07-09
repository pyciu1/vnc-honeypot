#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Connection Handler
=====================================
ConnectionHandler — handles every incoming TCP connection.
Unified from handle_vnc() + handle_vnc_dual_capture() from original.
"""

import json
import logging
import socket
import struct
import threading
import traceback
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from vnc_db import SQLiteConnectionPool, DBWriter
from vnc_rate import RateLimiter
from vnc_geo import ensure_ip_enriched
from vnc_protocol import vnc_capture_session, decode_plain_auth, recv_http
from vnc_fingerprint import VNCClientFingerprinter, CVEExploitDetector
from vnc_intel import PersonaEngine, BehaviorModel, CounterIntel
from vnc_scenario import ScenarioManager
from vnc_config import CONFIG

logger = logging.getLogger("vnc_honeypot.handler")


class ConnectionHandler:
    """
    Central processing point for all TCP connections.
    Handles VNC (5900-5910) and HTTP (5800).
    """

    def __init__(
        self,
        db_pool:         SQLiteConnectionPool,
        rate_limiter:    RateLimiter,
        db_writer:       DBWriter,
        persona_engine:  PersonaEngine,
        behavior_model:  BehaviorModel,
        counterintel:    CounterIntel,
        scenario_manager: ScenarioManager,
    ) -> None:
        self._db             = db_pool
        self._rate           = rate_limiter
        self._writer         = db_writer
        self._persona        = persona_engine
        self._behavior       = behavior_model
        self._intel          = counterintel
        self._scenario       = scenario_manager
        self._fp             = VNCClientFingerprinter()
        self._cve            = CVEExploitDetector()

        # In-memory stats (fast, no DB lock)
        self._stats_lock     = threading.Lock()
        self._stats: dict    = {
            "connections": 0, "captures": 0, "invalid": 0,
            "errors": 0, "ratelimited": 0, "dual_captures": 0,
            "raw_security": 0, "plain_passwords": 0,
        }

        # In-memory events for live dashboard
        self._events_lock    = threading.Lock()
        self._events: deque  = deque(maxlen=CONFIG["recent_events_size"])

    # ── Stats ────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)

    def _inc(self, key: str, n: int = 1) -> None:
        with self._stats_lock:
            self._stats[key] = self._stats.get(key, 0) + n

    def _db_inc(self, key: str, n: int = 1) -> None:
        try:
            with self._db.get() as conn:
                conn.cursor().execute(
                    "UPDATE stats SET value=value+? WHERE key=?", (n, key)
                )
        except Exception:
            pass

    # ── Events ───────────────────────────────────────────────────────────────

    def _add_event(self, ip: str, port: int, status: str,
                   info: str, proto: str,
                   conn_class: str, raw_preview: str) -> None:
        evt = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip, "port": port, "status": status,
            "info": info, "proto": proto,
            "class": conn_class, "raw": raw_preview,
        }
        with self._events_lock:
            self._events.appendleft(evt)

    def get_recent_events(self, limit: int = 50) -> list:
        with self._events_lock:
            return list(self._events)[:limit]

    def get_timeline_stats(self, minutes: int = 60) -> list:
        from datetime import timedelta
        cutoff  = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        buckets: dict = {}
        with self._events_lock:
            for e in self._events:
                try:
                    ts = datetime.fromisoformat(e["timestamp"])
                except Exception:
                    continue
                if ts < cutoff:
                    break
                key = ts.replace(second=0, microsecond=0).isoformat()
                b   = buckets.setdefault(key, {"total": 0, "captures": 0, "errors": 0})
                b["total"] += 1
                if e["class"] == "capture":
                    b["captures"] += 1
                if e["class"] == "error":
                    b["errors"]   += 1
        return [{"ts": k, **v} for k in sorted(buckets)]

    # ── DB helpers ────────────────────────────────────────────────────────────

    def _db_log_connection(self, ts: str, ip: str, port: int,
                           status: str, proto: str, info: str,
                           client_tag: str, raw_preview: str) -> None:
        try:
            with self._db.get() as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO connections
                        (timestamp,ip,port,status,info,proto,client_tag,raw_preview)
                    VALUES(?,?,?,?,?,?,?,?)
                """, (ts, ip, port, status, info, proto, client_tag, raw_preview))
                c.execute("""
                    INSERT INTO ip_stats(ip,first_seen,last_seen,conn_count,capture_count)
                    VALUES(?,?,?,1,?)
                    ON CONFLICT(ip) DO UPDATE SET
                        last_seen     = excluded.last_seen,
                        conn_count    = ip_stats.conn_count + 1,
                        capture_count = ip_stats.capture_count + excluded.capture_count
                """, (ip, ts, ts, 1 if status == "capture" else 0))
        except Exception as e:
            logger.debug(f"[handler] db_log_connection error: {e}")

    def _db_log_cve(self, ip: str, port: int,
                    cve_id: str, name: str, risk: str) -> None:
        try:
            with self._db.get() as conn:
                conn.cursor().execute("""
                    INSERT INTO cve_alerts(timestamp,ip,port,cve_id,name,risk)
                    VALUES(?,?,?,?,?,?)
                """, (datetime.now(timezone.utc).isoformat(),
                      ip, port, cve_id, name, risk))
        except Exception as e:
            logger.debug(f"[handler] cve log error: {e}")

    def _db_save_dual_capture(self, ip: str, port: int,
                               cr_data: Optional[dict],
                               raw_data: Optional[dict]) -> None:
        """Saves both capture types to DB."""
        ts = datetime.now(timezone.utc).isoformat()
        try:
            with self._db.get() as conn:
                c = conn.cursor()

                # Challenge-response
                if cr_data:
                    c.execute("""
                        INSERT INTO captures
                            (timestamp,ip,port,challenge,response,proto)
                        VALUES(?,?,?,?,?,?)
                    """, (ts, ip, port,
                          cr_data.get("challenge", ""),
                          cr_data.get("response", ""),
                          cr_data.get("protocol", "VNC")))

                # RAW security
                if raw_data:
                    auth_type = raw_data.get("security_type", -1)
                    auth_data = ""

                    # Plain Auth (Type 18) — extrage user+parola
                    if auth_type == 18:
                        data_hex = (raw_data.get("raw_data")
                                    or raw_data.get("extra_data") or "")
                        if data_hex:
                            try:
                                raw_bytes = bytes.fromhex(data_hex)
                                user, pwd = decode_plain_auth(raw_bytes)
                                if user or pwd:
                                    auth_data = json.dumps({
                                        "user":     user or "",
                                        "password": pwd  or "",
                                    })
                                    if pwd:
                                        self._inc("plain_passwords")
                                        self._db_inc("plain_passwords")
                            except Exception as e:
                                logger.debug(f"[handler] plain auth decode: {e}")
                    elif "extra_data" in raw_data:
                        auth_data = str(raw_data["extra_data"])[:500]
                    elif "raw_data" in raw_data:
                        auth_data = str(raw_data["raw_data"])[:500]

                    c.execute("""
                        INSERT INTO raw_vnc_captures
                            (timestamp,ip,port,proto,auth_type,auth_data,raw_json)
                        VALUES(?,?,?,?,?,?,?)
                    """, (ts, ip, port,
                          raw_data.get("protocol", "VNC"),
                          auth_type, auth_data,
                          json.dumps(raw_data.get("traffic", []))))
        except Exception as e:
            logger.error(f"[handler] save_dual_capture error {ip}:{port}: {e}")

    # ── Entry point ───────────────────────────────────────────────────────────

    def handle_connection(self, sock: socket.socket,
                          addr: tuple, port: int) -> None:
        """Dispatches based on port — VNC or HTTP."""
        ip       = addr[0]
        ts_start = datetime.now(timezone.utc).isoformat()

        self._inc("connections")
        self._db_inc("connections")

        # Rate limiting
        if not self._rate.allow(ip):
            self._inc("ratelimited")
            self._db_inc("ratelimited")
            self._add_event(ip, port, "ratelimited", "rate limit", "TCP", "ratelimited", "")
            try:
                sock.close()
            except Exception:
                pass
            return

        # Read first bytes for routing
        try:
            first = sock.recv(32)
        except Exception:
            first = b""

        if port in CONFIG["vnc_ports"]:
            self._handle_vnc(sock, ip, port, first, ts_start)
        elif port == CONFIG["http_port"]:
            self._handle_http(sock, ip, port, first, ts_start)
        else:
            raw_preview = (first or b"")[:32].hex()
            self._add_event(ip, port, "unknown_proto", "unknown protocol",
                            "TCP", "unknown", raw_preview)
            self._db_log_connection(ts_start, ip, port, "unknown_proto",
                                    "TCP", "unknown protocol", "unknown", raw_preview)
            try:
                sock.close()
            except Exception:
                pass

    # ── VNC handler ───────────────────────────────────────────────────────────

    def _handle_vnc(self, sock: socket.socket, ip: str, port: int,
                    first: bytes, ts_start: str) -> None:
        """Handles a VNC connection — full dual capture."""
        try:
            cr_data, raw_data = vnc_capture_session(sock, ip, port, first)

            # Statistici
            if cr_data:
                self._inc("captures")
                self._db_inc("captures")
                resp_hex = cr_data.get("response", "")
                self._add_event(ip, port, "capture",
                                f"challenge-response | {resp_hex[:16]}...",
                                cr_data.get("protocol", "VNC"),
                                "capture", resp_hex[:32])
                logger.info(f"[handler] {ip}:{port} VNC capture OK")

            if raw_data:
                self._inc("raw_security")
                self._db_inc("raw_security")
                sec_type = raw_data.get("security_type", -1)
                self._add_event(ip, port, "raw_security",
                                f"RAW type:{sec_type}",
                                raw_data.get("protocol", "VNC"),
                                "raw", "")

            if cr_data and raw_data:
                self._inc("dual_captures")
                self._db_inc("dual_captures")

            # Salvare DB
            if cr_data or raw_data:
                self._db_save_dual_capture(ip, port, cr_data, raw_data)

            # Fingerprint (if we have challenge-response)
            client_tag = "vnc_client"
            if cr_data:
                try:
                    client_hello = (first if first.startswith(b"RFB")
                                    else b"RFB " + cr_data.get("rfb_version", "003.008").encode() + b"\n")
                    resp_bytes   = bytes.fromhex(cr_data.get("response", ""))
                    fp           = self._fp.fingerprint(client_hello, resp_bytes)
                    client_tag   = fp.get("client_name", "vnc_client")
                except Exception:
                    pass

            # Log connection
            status = ("dual_capture"     if cr_data and raw_data else
                      "challenge_response" if cr_data else
                      "raw_security"       if raw_data else
                      "no_capture")
            self._db_log_connection(
                ts_start, ip, port, status,
                cr_data.get("protocol", "VNC") if cr_data else "VNC",
                status, client_tag,
                (first or b"")[:32].hex(),
            )

            # Behavior model + GeoIP
            self._behavior.analyze_ip(ip)
            with self._db.get() as conn:
                ensure_ip_enriched(conn, ip)

        except Exception as e:
            self._inc("errors")
            self._db_inc("errors")
            logger.debug(f"[handler] VNC error {ip}:{port}: {e}")
            self._add_event(ip, port, "error", str(e), "VNC", "error", "")
            self._db_log_connection(ts_start, ip, port, "error",
                                    "VNC", str(e)[:200], "", "")
            try:
                sock.close()
            except Exception:
                pass

    # ── HTTP handler ──────────────────────────────────────────────────────────

    def _handle_http(self, sock: socket.socket, ip: str, port: int,
                     first: bytes, ts_start: str) -> None:
        """Handles an HTTP connection (noVNC/Guacamole scanners)."""
        try:
            rest = recv_http(sock, max_len=8192, timeout=2.0)
            raw  = (first or b"") + rest
            raw_preview = raw[:64].hex()

            # Parsăm request line
            method, path = "GET", "/"
            try:
                head  = raw.split(b"\r\n\r\n", 1)[0]
                lines = head.split(b"\r\n")
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        method = parts[0].decode(errors="ignore")
                        path   = parts[1].decode(errors="ignore")
            except Exception:
                pass

            decoded = raw.decode(errors="ignore").lower()
            if path.lower().startswith("/vnc.html") or "novnc" in decoded:
                status   = "http_vnc_web"
                info     = f"{method} {path} (noVNC)"
            elif "guacamole" in decoded:
                status   = "http_guac_probe"
                info     = f"{method} {path} (Guacamole)"
            else:
                status   = "http_probe"
                info     = f"{method} {path}"

            # CVE check
            exploits = self._cve.check_for_exploits(raw, port)
            if exploits:
                status = "http_exploit"
                info  += " | CVEs: " + ",".join(e["cve"] for e in exploits)
                for e in exploits:
                    self._db_log_cve(ip, port, e["cve"], e["name"], e["risk"])

            self._add_event(ip, port, status, info, "HTTP", status, raw_preview)
            self._db_log_connection(ts_start, ip, port, status,
                                    "HTTP", info, "http_scanner", raw_preview)

            # Response
            body = (
                b"<html><body><h1>VNC Service</h1>"
                b"<p>Service available via native VNC client.</p></body></html>"
            )
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: VNC-Gateway\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            ) + body
            try:
                sock.sendall(resp)
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"[handler] HTTP error {ip}:{port}: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass


__all__ = ["ConnectionHandler"]
