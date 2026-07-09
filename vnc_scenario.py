#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Scenario & Grid Management
============================================
ScenarioManager — CyberRange scenarios (deception context)
GridManager     — honeypot node registration and listing
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from vnc_db import SQLiteConnectionPool

logger = logging.getLogger("vnc_honeypot.scenario")


class ScenarioManager:
    """
    Manages deception scenarios — the fake context
    shown to attackers (what role the fake victim plays).
    """

    def __init__(self, db_pool: SQLiteConnectionPool) -> None:
        self._db = db_pool

    def define_scenario(self, scenario_id: str, data: dict) -> None:
        """Saves or overwrites a deception scenario."""
        """Saves or overwrites a scenario."""
        doc = {
            "id":         scenario_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "data":       data,
        }
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO scenarios(id, created_at, data_json)
                VALUES(?,?,?)
            """, (scenario_id, doc["created_at"], json.dumps(doc)))

    def list_scenarios(self) -> list:
        """Returns all defined scenarios."""
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("SELECT data_json FROM scenarios")
            return [json.loads(r[0]) for r in c.fetchall()]

    def get_scenario(self, scenario_id: str) -> Optional[dict]:
        """Returns a scenario by ID."""
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT data_json FROM scenarios WHERE id=?", (scenario_id,)
            )
            row = c.fetchone()
            return json.loads(row[0]) if row else None

    def get_active_for_ip(self, ip: str) -> Optional[dict]:
        """Returns the active scenario for an IP (deterministic on last octet)."""
        """
        Returns the active scenario for an IP.
        Deterministic selection based on the last octet of the IP.
        """
        scenarios = self.list_scenarios()
        if not scenarios:
            return None
        try:
            idx = int(ip.split(".")[-1]) % len(scenarios)
        except Exception:
            idx = 0
        return scenarios[idx].get("data")

    def seed_defaults(self) -> None:
        """Creates default scenarios if they don't exist."""
        """Creates default scenarios on first start."""
        defaults = [
            ("basic-deception",  {"persona_hint": "careless_admin",    "description": "Careless admin with exposed sensitive files"}),
            ("developer-leak",   {"persona_hint": "developer",          "description": "Developer with secrets in .env"}),
            ("security-analyst", {"persona_hint": "security_analyst",   "description": "SecOps workstation with active processes"}),
            ("db-admin",         {"persona_hint": "db_admin",           "description": "DBA with exposed SQL dumps"}),
        ]
        for sid, data in defaults:
            if not self.get_scenario(sid):
                self.define_scenario(sid, data)
        logger.info("[scenario] Default scenarios seeded")


class GridManager:
    """Registers and manages honeypot nodes (for multi-VPS deployments)."""

    def __init__(self, db_pool: SQLiteConnectionPool,
                 node_id: str = "local-node-001") -> None:
        self._db      = db_pool
        self._node_id = node_id

    def register_local(self, config: dict) -> str:
        """Registers the current node in DB."""
        """Registers the current node in DB."""
        data = {
            "node_id":       self._node_id,
            "config":        config,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "role":          "standalone",
        }
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO
                    grid_nodes(node_id, registered_at, data_json)
                VALUES(?,?,?)
            """, (self._node_id, data["registered_at"], json.dumps(data)))
        return self._node_id

    def list_nodes(self) -> list:
        """Lists all registered nodes."""
        with self._db.get() as conn:
            c = conn.cursor()
            c.execute("SELECT data_json FROM grid_nodes")
            return [json.loads(r[0]) for r in c.fetchall()]


__all__ = ["ScenarioManager", "GridManager"]
