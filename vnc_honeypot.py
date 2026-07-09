#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Entry Point
============================
main() with argparse, start_listeners(), graceful shutdown.

Quick start:
  sudo python3 vnc_honeypot.py
  sudo python3 vnc_honeypot.py --db /data/vnc.db --ports 5900-5910 --http-port 5800

Start with alerting (shared with RDP honeypot):
  sudo python3 vnc_honeypot.py \
      --telegram-token "TOKEN" \
      --telegram-chat-id "CHAT_ID" \
      --geoip-db /data/GeoLite2-City.mmdb
"""

import argparse
import logging
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
import socket

from vnc_config import CONFIG
from vnc_db import SQLiteConnectionPool, DBWriter, init_db
from vnc_rate import RateLimiter
from vnc_geo import setup_geoip
from vnc_intel import PersonaEngine, BehaviorModel, CounterIntel
from vnc_scenario import ScenarioManager, GridManager
from vnc_handler import ConnectionHandler

logger = logging.getLogger("vnc_honeypot")


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    fmt   = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=level, format=fmt)
    # Reduce noise from libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("geoip2").setLevel(logging.WARNING)


# ══════════════════════════════════════════════════════════════════════════════
# LISTENERS
# ══════════════════════════════════════════════════════════════════════════════

def vnc_listener_worker(bind_ip: str, port: int,
                        handler: ConnectionHandler) -> None:
    """Thread worker — listens on a VNC port and dispatches connections."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_ip, port))
    except OSError as e:
        logger.error(f"[main] Cannot bind {bind_ip}:{port}: {e}")
        return
    srv.listen(200)
    srv.settimeout(2.0)
    logger.info(f"[main] VNC listening on {bind_ip}:{port}")

    with ThreadPoolExecutor(max_workers=CONFIG["max_workers"],
                            thread_name_prefix=f"vnc-{port}") as pool:
        while not _shutdown.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            client_sock.settimeout(CONFIG["socket_timeout"])
            pool.submit(handler.handle_connection, client_sock, addr, port)

    srv.close()


def http_listener_worker(bind_ip: str, port: int,
                         handler: ConnectionHandler) -> None:
    """Thread worker — listens on the HTTP honeypot port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind_ip, port))
    except OSError as e:
        logger.error(f"[main] Cannot bind HTTP {bind_ip}:{port}: {e}")
        return
    srv.listen(200)
    srv.settimeout(2.0)
    logger.info(f"[main] HTTP honeypot on {bind_ip}:{port}")

    with ThreadPoolExecutor(max_workers=50,
                            thread_name_prefix="http-honey") as pool:
        while not _shutdown.is_set():
            try:
                client_sock, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            client_sock.settimeout(CONFIG["socket_timeout"])
            pool.submit(handler.handle_connection, client_sock, addr, port)

    srv.close()


def start_listeners(handler: ConnectionHandler,
                    vnc_ports: list,
                    http_port: int,
                    bind_ip: str = "0.0.0.0") -> list:
    """Starts all listeners in daemon threads."""
    threads = []

    # HTTP honeypot
    t = threading.Thread(
        target=http_listener_worker,
        args=(bind_ip, http_port, handler),
        daemon=True, name=f"http-{http_port}",
    )
    t.start()
    threads.append(t)

    # VNC ports
    for port in vnc_ports:
        t = threading.Thread(
            target=vnc_listener_worker,
            args=(bind_ip, port, handler),
            daemon=True, name=f"vnc-{port}",
        )
        t.start()
        threads.append(t)

    return threads


# ══════════════════════════════════════════════════════════════════════════════
# ARGPARSE
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="VNC Honeypot — Dual Capture + Intelligence",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # ── Porturi ──────────────────────────────────────────────────────────────
    ap.add_argument("--ports",      default="5900-5910", metavar="RANGE",
                    help="VNC ports (e.g. 5900-5910 or 5900,5901,5902)")
    ap.add_argument("--http-port",  type=int, default=5800,
                    help="Port HTTP honeypot (noVNC/Guacamole scanners)")
    ap.add_argument("--bind",       default="0.0.0.0", metavar="IP",
                    help="Bind IP address")

    # ── Baza de date ──────────────────────────────────────────────────────────
    ap.add_argument("--db",         default="vnc_honeypot.db", metavar="PATH",
                    help="Cale SQLite database")

    # ── GeoIP ─────────────────────────────────────────────────────────────────
    ap.add_argument("--geoip-db",   default=None, metavar="PATH",
                    help="Cale GeoLite2-City.mmdb (MaxMind, optional)")

    # ── Alerting (shared cu RDP honeypot) ─────────────────────────────────────
    ap.add_argument("--telegram-token",   default=None, metavar="TOKEN",
                    help="Telegram Bot API token for alerts")
    ap.add_argument("--telegram-chat-id", default=None, metavar="ID",
                    help="Telegram chat ID for alerts")
    ap.add_argument("--smtp-host",        default=None, metavar="HOST",
                    help="SMTP server for email alerts")
    ap.add_argument("--smtp-port",        type=int, default=587,
                    help="SMTP port")
    ap.add_argument("--smtp-user",        default=None, metavar="USER")
    ap.add_argument("--smtp-pass",        default=None, metavar="PASS")
    ap.add_argument("--email-to",         default=None, metavar="ADDR",
                    help="Adresa destinatar alerte email")

    # ── Logging ───────────────────────────────────────────────────────────────
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Logging verbose (DEBUG)")
    ap.add_argument("--quiet",   "-q", action="store_true",
                    help="Logging minimal (WARNING)")

    # ── Self-test ─────────────────────────────────────────────────────────────
    ap.add_argument("--self-test", action="store_true",
                    help="Run self-test and exit")

    return ap.parse_args()


def parse_ports(ports_str: str) -> list:
    """Parses '5900-5910' or '5900,5901,5902' into a list of ints."""
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


# ══════════════════════════════════════════════════════════════════════════════
# SELF TEST
# ══════════════════════════════════════════════════════════════════════════════

def run_self_test() -> bool:
    """Runs basic tests and returns True if everything is OK."""
    import tempfile, os
    print("[self-test] Starting VNC Honeypot self-test...")
    ok = True

    # Test 1: Config
    from vnc_config import CONFIG, FIXED_VNC_CHALLENGE
    assert len(FIXED_VNC_CHALLENGE) == 16, "Challenge must be 16 bytes"
    assert CONFIG["batch_size"] > 0
    print("[self-test] ✓ Config OK")

    # Test 2: Protocol
    from vnc_protocol import get_vnc_challenge, decode_plain_auth, detect_rfb_mode
    ch = get_vnc_challenge()
    assert len(ch) == 16
    mode, ver = detect_rfb_mode("RFB 003.003\n")
    assert mode == "RFB33"
    mode2, _ = detect_rfb_mode("RFB 003.008\n")
    assert mode2 == "RFB38"
    user, pwd = decode_plain_auth(b"\x00\x00\x00\x05\x00\x00\x00\x08admin123456789")
    print("[self-test] ✓ Protocol OK")

    # Test 3: Rate limiter
    from vnc_rate import TokenBucket, SlidingWindowLimiter
    tb = TokenBucket(rate=10, capacity=5)
    for _ in range(5):
        assert tb.allow("1.2.3.4") == True
    assert tb.allow("1.2.3.4") == False
    print("[self-test] ✓ Rate limiter OK")

    # Test 4: DB
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        init_db(db_path)
        pool = SQLiteConnectionPool(db_path, size=2)
        with pool.get() as conn:
            n = conn.cursor().execute(
                "SELECT COUNT(*) FROM stats"
            ).fetchone()[0]
        assert n > 0
        pool.close_all()
    print("[self-test] ✓ Database OK")

    # Test 5: Fingerprinting
    from vnc_fingerprint import VNCClientFingerprinter, CVEExploitDetector
    fp  = VNCClientFingerprinter()
    res = fp.fingerprint(b"RFB 003.008\n", b"\x00" * 16)
    assert res["confidence"] > 0
    assert "null_password" in res["enterprise_indicators"]
    cve = CVEExploitDetector()
    hits = cve.check_for_exploits(b"../" * 100, 5800)
    assert any(h["cve"] == "CVE-2019-15680" for h in hits)
    print("[self-test] ✓ Fingerprinting OK")

    # Test 6: GeoIP fallback
    from vnc_geo import geoip_lookup
    cc, asn, _, _ = geoip_lookup("192.168.1.1")
    assert cc == "PR"
    cc2, _, _, _ = geoip_lookup("1.2.3.4")
    assert cc2 in ("ZZ", "CN", "US", "DE", "NL", "SG", "CH")
    print("[self-test] ✓ GeoIP OK")

    print(f"\n[self-test] {'✅ ALL TESTS PASSED' if ok else '❌ SOME TESTS FAILED'}")
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# SHUTDOWN
# ══════════════════════════════════════════════════════════════════════════════

_shutdown = threading.Event()


def _signal_handler(sig, frame) -> None:
    logger.info(f"[main] Signal {sig} received — shutting down...")
    _shutdown.set()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    args = parse_args()
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    if args.self_test:
        ok = run_self_test()
        sys.exit(0 if ok else 1)

    logger.info("[main] Starting VNC Honeypot")

    # ── Parse ports ──────────────────────────────────────────────────────────
    try:
        vnc_ports = parse_ports(args.ports)
    except ValueError as e:
        logger.error(f"[main] Invalid ports: {e}")
        sys.exit(1)

    # ── Update CONFIG ─────────────────────────────────────────────────────────
    CONFIG["db_file"]   = args.db
    CONFIG["vnc_ports"] = vnc_ports
    CONFIG["http_port"] = args.http_port

    # ── GeoIP ─────────────────────────────────────────────────────────────────
    if args.geoip_db:
        setup_geoip(args.geoip_db)

    # ── Database ──────────────────────────────────────────────────────────────
    logger.info(f"[main] Database: {args.db}")
    init_db(args.db)
    db_pool = SQLiteConnectionPool(args.db, size=10)

    # ── Modules ───────────────────────────────────────────────────────────────
    rate_limiter     = RateLimiter()
    db_writer        = DBWriter(
        db_pool,
        batch_size    = CONFIG["batch_size"],
        flush_timeout = CONFIG["batch_flush_timeout"],
    )
    persona_engine   = PersonaEngine(db_pool)
    behavior_model   = BehaviorModel(db_pool)
    counterintel     = CounterIntel(db_pool)
    scenario_manager = ScenarioManager(db_pool)
    grid_manager     = GridManager(db_pool)

    # Seed default scenarios
    scenario_manager.seed_defaults()
    grid_manager.register_local(CONFIG)

    # ── Alerting (shared cu RDP honeypot) ─────────────────────────────────────
    # Import alerts.py from RDP honeypot if available
    alerts_mgr = None
    try:
        import os as _os
        # Look for alerts.py in RDP honeypot directory or current dir
        for path in [".", "..", "../rdp-honeypot-v54"]:
            if _os.path.exists(_os.path.join(path, "alerts.py")):
                sys.path.insert(0, path)
                break
        import alerts as _alerts
        alerts_mgr = _alerts.get_manager()
        if (args.telegram_token and args.telegram_chat_id) or args.smtp_host:
            _alerts.setup(args=args)
            logger.info("[main] Shared alerting enabled (RDP + VNC)")
    except ImportError:
        logger.info("[main] alerts.py not found — alerting disabled")

    # ── Connection handler ────────────────────────────────────────────────────
    handler = ConnectionHandler(
        db_pool          = db_pool,
        rate_limiter     = rate_limiter,
        db_writer        = db_writer,
        persona_engine   = persona_engine,
        behavior_model   = behavior_model,
        counterintel     = counterintel,
        scenario_manager = scenario_manager,
    )

    # ── Signal handlers ───────────────────────────────────────────────────────
    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # ── Start listeners ───────────────────────────────────────────────────────
    threads = start_listeners(handler, vnc_ports, args.http_port, args.bind)

    logger.info(f"[main] VNC ports:    {vnc_ports}")
    logger.info(f"[main] HTTP port:    {args.http_port}")
    logger.info(f"[main] Database:     {args.db}")
    logger.info(f"[main] All systems online — waiting for attackers...")
    logger.info(f"[main] API data available for central dashboard")

    # ── Main loop ─────────────────────────────────────────────────────────────
    try:
        while not _shutdown.is_set():
            _shutdown.wait(timeout=1.0)
    except KeyboardInterrupt:
        pass

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    logger.info("[main] Shutdown initiated...")
    _shutdown.set()

    # Flush all batch data before closing DB
    db_writer.stop()
    logger.info("[main] DBWriter flushed")

    db_pool.close_all()
    logger.info("[main] Database connections closed")
    logger.info("[main] VNC Honeypot stopped cleanly")


if __name__ == "__main__":
    main()
