#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Intelligence Modules
=======================================
PersonaEngine  — generates fake server identities per IP
BehaviorModel  — analyses and scores attacker behaviour
CounterIntel   — honeytokens and tracking tokens
"""

import hashlib
import json
import logging
import random
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from vnc_db import SQLiteConnectionPool

logger = logging.getLogger("vnc_honeypot.intel")


# ══════════════════════════════════════════════════════════════════════════════
# PERSONA ENGINE — fake OS / FS / Processes per IP
# ══════════════════════════════════════════════════════════════════════════════

class PersonaEngine:
    """
    Generates a fake server identity per attacker IP.
    Same IP sees the same server on every reconnect (hashed on IP).
    """

    PERSONAS: dict = {
        "careless_admin": {
            "role": "IT Admin",
            "behavior": "leaves_sensitive_data",
            "os_family": "windows",
        },
        "security_analyst": {
            "role": "Security Analyst",
            "behavior": "paranoid_but_messy",
            "os_family": "windows",
        },
        "developer": {
            "role": "Developer",
            "behavior": "commits_secrets_to_git",
            "os_family": "linux",
        },
        "db_admin": {
            "role": "DBA",
            "behavior": "schema_dumps_everywhere",
            "os_family": "linux",
        },
    }

    def __init__(self, db_pool: SQLiteConnectionPool) -> None:
        self._db = db_pool

    def generate_for_ip(self, ip: str,
                        scenario: Optional[dict] = None) -> dict:
        """Returns persona for IP — generated once and cached in DB."""
        """
        Returns persona for an IP.
        If previously generated, returns it from DB (consistent).
        """
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("SELECT persona_json FROM persona WHERE ip=?", (ip,))
            row = c.fetchone()
            if row:
                return json.loads(row[0])

        ip_hash   = hashlib.md5(ip.encode()).hexdigest()
        keys      = list(self.PERSONAS.keys())
        persona_k = keys[int(ip_hash[:2], 16) % len(keys)]

        # Scenariu explicit suprascrie hash-ul
        if scenario and scenario.get("persona_hint") in keys:
            persona_k = scenario["persona_hint"]

        base      = self.PERSONAS[persona_k]
        fake_fs   = self._build_fake_fs(persona_k, ip_hash)
        fake_proc = self._build_fake_processes(persona_k)

        persona = {
            "persona_key": persona_k,
            "role":        base["role"],
            "behavior":    base["behavior"],
            "os_family":   base["os_family"],
            "hostname":    f"WS-{ip_hash[:4].upper()}",
            "ip":          ip,
            "fake_fs":     fake_fs,
            "fake_procs":  fake_proc,
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }

        with self._db.get() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT OR REPLACE INTO persona(ip,created_at,persona_json)"
                " VALUES(?,?,?)",
                (ip, persona["created_at"], json.dumps(persona)),
            )

        return persona

    def _build_fake_fs(self, key: str, seed: str) -> dict:
        """Builds a fake filesystem based on persona and seed."""
        rnd  = int(seed[:2], 16)
        user = ["admin", "john", "maria", "ituser"][rnd % 4]
        win  = self.PERSONAS[key]["os_family"] == "windows"

        if win:
            base = f"C:/Users/{user}"
            docs = [
                f"{base}/Desktop/PasswordList_{seed[:4]}.txt",
                f"{base}/Documents/Finance_{seed[4:8]}.xlsx",
                f"{base}/Downloads/VPN_Config_{seed[2:6]}.ovpn",
            ]
        else:
            base = f"/home/{user}"
            docs = [
                f"{base}/.ssh/id_rsa",
                f"{base}/projects/config_{seed[:4]}.env",
                f"{base}/backups/db_dump_{seed[4:8]}.sql",
            ]
        return {
            "base":      base,
            "documents": docs,
            "logs": [
                "/var/log/auth.log" if not win
                else "C:/Windows/System32/LogFiles/Security.evtx"
            ],
        }

    def _build_fake_processes(self, key: str) -> list:
        """Builds a fake process list based on persona."""
        win = self.PERSONAS[key]["os_family"] == "windows"
        base = (
            [
                {"name": "winlogon.exe", "pid": 120, "user": "SYSTEM"},
                {"name": "svchost.exe",  "pid": 456, "user": "SYSTEM"},
                {"name": "explorer.exe", "pid": 234, "user": "user"},
            ]
            if win else
            [
                {"name": "systemd", "pid": 1,   "user": "root"},
                {"name": "sshd",    "pid": 101, "user": "root"},
                {"name": "bash",    "pid": 567, "user": "user"},
            ]
        )
        extra: list = []
        if key == "developer":
            extra += [
                {"name": "vscode",  "pid": 777, "user": "dev"},
                {"name": "docker",  "pid": 778, "user": "root"},
            ]
        elif key == "db_admin":
            extra.append({"name": "postgres", "pid": 880, "user": "postgres"})
        elif key == "security_analyst":
            extra.append({"name": "wireshark", "pid": 660, "user": "secops"})
        return base + extra


# ══════════════════════════════════════════════════════════════════════════════
# BEHAVIOR MODEL — risk scoring per IP
# ══════════════════════════════════════════════════════════════════════════════

class BehaviorModel:
    """
    Analyses IP behaviour and calculates a risk score.
    Saves the result in DB for future reference.
    """

    def __init__(self, db_pool: SQLiteConnectionPool) -> None:
        self._db = db_pool

    def analyze_ip(self, ip: str) -> dict:
        """Calculates risk score for IP based on history in DB."""
        """
        Calculates risk score for IP based on history.
        Returns dict with score, level, tags.
        """
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT timestamp, port, status, proto
                FROM connections WHERE ip=? ORDER BY timestamp DESC LIMIT 200
            """, (ip,))
            rows = c.fetchall()

            c.execute("SELECT COUNT(*) FROM captures WHERE ip=?", (ip,))
            cap_count = c.fetchone()[0] or 0

        if not rows:
            return {"ip": ip, "risk_score": 0, "risk_level": "none",
                    "tags": ["no_activity"]}

        ports    = [r[1] for r in rows]
        statuses = [r[2] or "" for r in rows]
        protos   = [r[3] or "" for r in rows]

        unique_ports   = len(set(ports))
        handshake_only = sum(1 for s in statuses if "handshake_only" in s)
        http_scans     = sum(1 for s in statuses if s.startswith("http_"))

        score = 0
        tags:  list = []

        if unique_ports >= 5:
            score += 20; tags.append("multi_port_scan")
        if handshake_only >= len(rows) * 0.8:
            score += 15; tags.append("banner_scanner")
        if cap_count >= 3:
            score += 40; tags.append("bruteforce")
        if http_scans >= len(rows) * 0.2:
            score += 15; tags.append("http_scanner")
        if any("003.003" in p for p in protos):
            tags.append("legacy_vnc_probe")
        if any("003.008" in p for p in protos):
            tags.append("modern_vnc_probe")

        level = (
            "high"   if score >= 60 else
            "medium" if score >= 30 else
            "low"    if score > 0   else
            "none"
        )

        result = {
            "ip": ip, "risk_score": score, "risk_level": level,
            "tags": sorted(set(tags)), "sample_count": len(rows),
            "captures": cap_count,
        }

        ts = datetime.now(timezone.utc).isoformat()
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO behavior(ip, updated_at, data_json)
                VALUES(?,?,?)
            """, (ip, ts, json.dumps(result)))
            c.execute("""
                INSERT INTO ip_stats(ip, first_seen, last_seen, conn_count,
                    capture_count, risk_level, risk_score)
                VALUES(?,?,?,0,0,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen  = excluded.last_seen,
                    risk_level = excluded.risk_level,
                    risk_score = excluded.risk_score
            """, (ip, ts, ts, level, score))

        return result

    def get_for_ip(self, ip: str) -> Optional[dict]:
        """Returns cached behaviour data for an IP."""
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("SELECT data_json FROM behavior WHERE ip=?", (ip,))
            row = c.fetchone()
            return json.loads(row[0]) if row else None


# ══════════════════════════════════════════════════════════════════════════════
# COUNTER INTEL — honeytokens and tracking tokens
# ══════════════════════════════════════════════════════════════════════════════

class CounterIntel:
    """
    Generates and manages tracking tokens per attacker IP.
    Tokens are fake credentials, fake files, web bugs
    that can be planted in the honeypot environment.
    """

    def __init__(self, db_pool: SQLiteConnectionPool) -> None:
        self._db = db_pool

    def _gen_id(self, ip: str) -> str:
        base = f"{ip}-{time.time()}"
        return hashlib.md5(base.encode()).hexdigest()[:16]

    def deploy_for_ip(self, ip: str) -> dict:
        """Generates and saves tracking tokens for an IP."""
        """Generates and saves tracking tokens for an IP."""
        tid  = self._gen_id(ip)
        meta = {
            "tracking_id": tid,
            "ip":          ip,
            "web_bug":     f'<img src="http://track.honeypot.local/b/{tid}" width="1" height="1">',
            "credentials": {
                "username": f"svc_{tid[:8]}",
                "password": f"Track{random.randint(10000, 99999)}!",
                "email":    f"{tid[:8]}@internal.local",
            },
            "files": [
                f"passwords_{tid}.txt",
                f"vpn_config_{tid}.ovpn",
                f"db_backup_{tid}.sql",
            ],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        ts = datetime.now(timezone.utc).isoformat()
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO
                    tracking(tracking_id, attacker_ip, created_at, meta_json)
                VALUES(?,?,?,?)
            """, (tid, ip, ts, json.dumps(meta)))
        return meta

    def list_for_ip(self, ip: str) -> list:
        """Lists all tracking tokens for an IP."""
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT meta_json FROM tracking
                WHERE attacker_ip=? ORDER BY created_at DESC
            """, (ip,))
            return [json.loads(r[0]) for r in c.fetchall()]

    def get_by_id(self, tid: str) -> Optional[dict]:
        """Returns token by tracking_id."""
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT meta_json FROM tracking WHERE tracking_id=?", (tid,)
            )
            row = c.fetchone()
            return json.loads(row[0]) if row else None


__all__ = ["PersonaEngine", "BehaviorModel", "CounterIntel"]
