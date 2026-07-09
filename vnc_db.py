#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Database Layer
================================
SQLiteConnectionPool, init_db, DBWriter.

Fixes vs original:
  - DBWriter flushes on shutdown (no data loss)
  - DBWriter periodic flush with timeout (not only at batch_size)
  - Clean imports
"""

import logging
import queue
import sqlite3
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("vnc_honeypot.db")


# ══════════════════════════════════════════════════════════════════════════════
# CONNECTION POOL
# ══════════════════════════════════════════════════════════════════════════════

class SQLiteConnectionPool:
    """
    Thread-safe SQLite connection pool.
    Each get() call returns a connection from the pool
    and returns it automatically after use (context manager).
    """

    def __init__(self, db_file: str, size: int = 10) -> None:
        self._db_file = db_file
        self._pool    = queue.Queue(size)
        for _ in range(size):
            conn = sqlite3.connect(db_file, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._pool.put(conn)

    @contextmanager
    def get(self) -> "sqlite3.Connection":
        """Context manager — returns a connection from the pool."""
        """Context manager — returns a connection and puts it back in the pool."""
        conn = self._pool.get()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.put(conn)

    def close_all(self) -> None:
        """Closes all connections in the pool (on shutdown)."""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Exception:
                break


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA
# ══════════════════════════════════════════════════════════════════════════════

def init_db(db_file: str) -> None:
    """
    Creates all tables on first start.
    Idempotent — safe to call multiple times.
    """
    conn = sqlite3.connect(db_file)
    c    = conn.cursor()

    # ── Statistici globale ────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL DEFAULT 0
        )
    """)
    for k in [
        "connections", "captures", "invalid", "errors",
        "ratelimited", "dual_captures", "raw_security", "plain_passwords",
    ]:
        c.execute("INSERT OR IGNORE INTO stats(key,value) VALUES(?,0)", (k,))

    # ── Connections (all sessions) ────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            ip          TEXT,
            port        INTEGER,
            status      TEXT,
            info        TEXT,
            proto       TEXT,
            client_tag  TEXT,
            raw_preview TEXT
        )
    """)

    # ── Capturi challenge-response ────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip        TEXT,
            port      INTEGER,
            challenge TEXT,
            response  TEXT,
            proto     TEXT
        )
    """)

    # ── Statistici per IP ─────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_stats (
            ip            TEXT PRIMARY KEY,
            first_seen    TEXT,
            last_seen     TEXT,
            conn_count    INTEGER DEFAULT 0,
            capture_count INTEGER DEFAULT 0,
            country       TEXT,
            asn           TEXT,
            as_name       TEXT,
            net_type      TEXT,
            bot_signature TEXT,
            risk_level    TEXT,
            risk_score    INTEGER
        )
    """)

    # ── CVE alerts ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS cve_alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip        TEXT,
            port      INTEGER,
            cve_id    TEXT,
            name      TEXT,
            risk      TEXT
        )
    """)

    # ── Persona per IP ────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS persona (
            ip           TEXT PRIMARY KEY,
            created_at   TEXT,
            persona_json TEXT
        )
    """)

    # ── Grid nodes ────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS grid_nodes (
            node_id       TEXT PRIMARY KEY,
            registered_at TEXT,
            data_json     TEXT
        )
    """)

    # ── Behavior model ────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS behavior (
            ip         TEXT PRIMARY KEY,
            updated_at TEXT,
            data_json  TEXT
        )
    """)

    # ── Counter intel / tracking ──────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS tracking (
            tracking_id  TEXT PRIMARY KEY,
            attacker_ip  TEXT,
            created_at   TEXT,
            meta_json    TEXT
        )
    """)

    # ── Scenarios ─────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scenarios (
            id         TEXT PRIMARY KEY,
            created_at TEXT,
            data_json  TEXT
        )
    """)

    # ── Capturi RAW VNC (dual capture + plain auth) ───────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS raw_vnc_captures (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip        TEXT,
            port      INTEGER,
            proto     TEXT,
            auth_type INTEGER,
            auth_data TEXT,
            raw_json  TEXT
        )
    """)

    # ── Indexuri ──────────────────────────────────────────────────────────────
    c.execute("CREATE INDEX IF NOT EXISTS i_conn_ip  ON connections(ip)")
    c.execute("CREATE INDEX IF NOT EXISTS i_conn_ts  ON connections(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS i_cap_ip   ON captures(ip)")
    c.execute("CREATE INDEX IF NOT EXISTS i_raw_ip   ON raw_vnc_captures(ip)")
    c.execute("CREATE INDEX IF NOT EXISTS i_raw_auth ON raw_vnc_captures(auth_type)")

    conn.commit()
    conn.close()
    logger.info(f"[db] Database initialized: {db_file}")


# ══════════════════════════════════════════════════════════════════════════════
# DB WRITER — batched async writes
# ══════════════════════════════════════════════════════════════════════════════

class DBWriter:
    """
    Writes captures to DB in batches for performance.

    Fixes vs original:
      - flush periodic la fiecare batch_flush_timeout secunde
        (nu doar la batch_size) → date nu se pierd la shutdown
      - explicit flush() callable from outside on shutdown
    """

    def __init__(self, db_pool: SQLiteConnectionPool,
                 batch_size: int = 50,
                 flush_timeout: float = 5.0) -> None:
        self._pool          = db_pool
        self._batch_size    = batch_size
        self._flush_timeout = flush_timeout
        self._queue: queue.Queue = queue.Queue()
        self._stop          = threading.Event()
        self._thread        = threading.Thread(
            target=self._worker, daemon=True, name="db-writer"
        )
        self._thread.start()

    def add_capture(self, ip: str, port: int,
                    chal_hex: str, resp_hex: str, proto: str) -> None:
        """Adds a capture to the async write queue."""
        """Adds a capture to the write queue."""
        self._queue.put({
            "type": "capture",
            "ts":   datetime.now(timezone.utc).isoformat(),
            "ip":   ip, "port": port,
            "chal": chal_hex, "resp": resp_hex, "proto": proto,
        })

    def flush(self) -> None:
        """Explicit flush — called on shutdown to prevent data loss."""
        """Explicit flush — called on shutdown to prevent data loss."""
        items = []
        while not self._queue.empty():
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if items:
            self._flush(items)

    def stop(self) -> None:
        """Stops the writer and flushes everything remaining in the queue."""
        """Stops the writer and flushes everything remaining in the queue."""
        self._stop.set()
        self.flush()

    def _worker(self) -> None:
        """Thread worker — collects and flushes periodically."""
        batch = []
        last_flush = time.monotonic()

        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=1.0)
                batch.append(item)
            except queue.Empty:
                pass

            # Flush if batch is full OR timeout has expired
            now = time.monotonic()
            if (len(batch) >= self._batch_size or
                    (batch and now - last_flush >= self._flush_timeout)):
                self._flush(batch)
                batch      = []
                last_flush = now

        # Final flush on shutdown
        if batch:
            self._flush(batch)

    def _flush(self, items: list) -> None:
        """Writes the batch to DB."""
        if not items:
            return
        try:
            with self._pool.get() as conn:
                c = conn.cursor()
                for it in items:
                    if it.get("type") == "capture":
                        c.execute("""
                            INSERT INTO captures
                                (timestamp, ip, port, challenge, response, proto)
                            VALUES (?,?,?,?,?,?)
                        """, (it["ts"], it["ip"], it["port"],
                              it["chal"], it["resp"], it["proto"]))
        except Exception as e:
            logger.error(f"[db] DBWriter flush error: {e}")
            traceback.print_exc()


__all__ = ["SQLiteConnectionPool", "init_db", "DBWriter"]
