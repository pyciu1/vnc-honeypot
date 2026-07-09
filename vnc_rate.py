#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Rate Limiting
==============================
TokenBucket + SlidingWindowLimiter + RateLimiter.

Fixes vs original:
  - deque imported at top-level (not inside allow())
  - complete type hints
"""

import logging
import threading
import time
from collections import deque
from typing import Dict

from vnc_config import CONFIG

logger = logging.getLogger("vnc_honeypot.rate")


class TokenBucket:
    """
    Token bucket rate limiter.
    Each IP receives tokens at `rate`/sec, max `capacity`.
    """

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate       = rate
        self.capacity   = capacity
        self._tokens:     Dict[str, float] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock        = threading.Lock()

    def allow(self, ip: str) -> bool:
        """Allows or blocks IP based on token bucket."""
        now = time.time()
        with self._lock:
            last   = self._timestamps.get(ip, now)
            tokens = self._tokens.get(ip, float(self.capacity))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            self._timestamps[ip] = now
            if tokens < 1:
                self._tokens[ip] = tokens
                return False
            self._tokens[ip] = tokens - 1
            return True


class SlidingWindowLimiter:
    """
    Sliding window rate limiter.
    Max `max_conn` connections from the same IP within `window_sec` seconds.
    """

    def __init__(self, max_conn: int, window_sec: int) -> None:
        self.max_conn   = max_conn
        self.window_sec = window_sec
        self._data: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        """Allows or blocks IP based on sliding window."""
        now = time.time()
        with self._lock:
            if ip not in self._data:
                self._data[ip] = deque()
            dq = self._data[ip]

            # Clean up old entries
            while dq and now - dq[0] > self.window_sec:
                dq.popleft()

            if len(dq) >= self.max_conn:
                return False

            dq.append(now)
            return True


class RateLimiter:
    """Combines TokenBucket + SlidingWindow for dual-layer protection."""

    def __init__(self) -> None:
        self._bucket = TokenBucket(
            CONFIG["bucket_rate"],
            CONFIG["bucket_capacity"],
        )
        self._window = SlidingWindowLimiter(
            CONFIG["max_conn_per_ip"],
            CONFIG["window_seconds"],
        )

    def allow(self, ip: str) -> bool:
        """Allows connection if it passes both checks (bucket + window)."""
        return self._bucket.allow(ip) and self._window.allow(ip)


__all__ = ["TokenBucket", "SlidingWindowLimiter", "RateLimiter"]
