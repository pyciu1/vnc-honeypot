#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VNC Honeypot — Protocol Layer
================================
VNC protocol functions: challenge, recv, handshake, decode plain auth.

Unified from original: handle_vnc() + handle_vnc_dual_capture()
combined into a single clean vnc_capture_session() function.
"""

import logging
import os
import socket
import struct
from typing import Optional, Tuple

from vnc_config import (
    ANALYTIC_FIXED_CHALLENGE, FIXED_VNC_CHALLENGE,
    VNC_SECURITY_VNC_AUTH, VNC_AUTH_FAIL,
    RFB_VERSIONS_CLASSIC,
)

logger = logging.getLogger("vnc_honeypot.protocol")


# ══════════════════════════════════════════════════════════════════════════════
# CHALLENGE
# ══════════════════════════════════════════════════════════════════════════════

def get_vnc_challenge() -> bytes:
    """
    Returns the 16-byte VNC challenge.
    FIXED if ANALYTIC_FIXED_CHALLENGE=True (for offline analysis),
    RANDOM otherwise.
    """
    if ANALYTIC_FIXED_CHALLENGE:
        return FIXED_VNC_CHALLENGE
    return os.urandom(16)


# ══════════════════════════════════════════════════════════════════════════════
# SOCKET RECV HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def recv_some(sock: socket.socket, n: int,
              timeout: float = 1.0) -> bytes:
    """Receives up to n bytes with timeout — returns b"" on error."""
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except Exception:
        return b""


def recv_exact(sock: socket.socket, n: int,
               timeout: float = 1.0) -> bytes:
    """
    Receives exactly n bytes with timeout.
    Returns b"" if not all bytes were received within timeout.
    """
    sock.settimeout(timeout)
    chunks:    list  = []
    remaining: int   = n
    start:     float = __import__("time").time()

    while remaining > 0:
        if __import__("time").time() - start > timeout:
            break
        try:
            data = sock.recv(remaining)
            if not data:
                break
            chunks.append(data)
            remaining -= len(data)
        except (socket.timeout, Exception):
            break

    buf = b"".join(chunks)
    return buf if len(buf) == n else b""


def recv_http(sock: socket.socket,
              max_len: int = 8192,
              timeout: float = 2.0) -> bytes:
    """Receives a complete HTTP request (until CRLFCRLF)."""
    sock.settimeout(timeout)
    data: bytes = b""
    start: float = __import__("time").time()

    while b"\r\n\r\n" not in data and len(data) < max_len:
        if __import__("time").time() - start > timeout:
            break
        try:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
        except (socket.timeout, Exception):
            break
    return data


# ══════════════════════════════════════════════════════════════════════════════
# RFB VERSION DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_rfb_mode(proto_str: str) -> Tuple[str, str]:
    """
    From the 'RFB xxx.xxx' string, detects the handshake mode:
      RFB33 → RFB 3.3 (int32 security type, fără alegere client)
      RFB38 → RFB 3.7/3.8/Apple/4.x/5.x (listă security types)

    Returns (mode, version_string).
    """
    version = "unknown"
    try:
        if proto_str.startswith("RFB "):
            parts = proto_str.split()
            if len(parts) >= 2:
                version = parts[1]
    except Exception:
        pass

    if "003.003" in proto_str:
        return "RFB33", version

    if any(v in proto_str for v in ("003.007", "003.008", "003.889", "004.", "005.")):
        return "RFB38", version

    return "RFB38", version


# ══════════════════════════════════════════════════════════════════════════════
# PLAIN AUTH DECODER (SecurityType 18)
# ══════════════════════════════════════════════════════════════════════════════

def decode_plain_auth(handshake_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts username and password from bytes for SecurityType 18 (Plain Auth).

    VeNCrypt Plain Auth format:
      4 bytes  → length of username (big-endian uint32)
      4 bytes  → length of password (big-endian uint32)
      N bytes  → username
      M bytes  → password

    Heuristic fallback if format does not match:
      Searches for printable ASCII sequences.

    Returns (username, password) or (None, None) if extraction fails.
    """
    if not handshake_bytes or len(handshake_bytes) < 2:
        return None, None

    # Try VeNCrypt Plain format: 4+4+N+M
    if len(handshake_bytes) >= 8:
        try:
            ulen = struct.unpack("!I", handshake_bytes[:4])[0]
            plen = struct.unpack("!I", handshake_bytes[4:8])[0]
            if (ulen < 256 and plen < 256
                    and 8 + ulen + plen <= len(handshake_bytes)):
                username = handshake_bytes[8:8+ulen].decode("utf-8", errors="replace")
                password = handshake_bytes[8+ulen:8+ulen+plen].decode("utf-8", errors="replace")
                if username or password:
                    return username, password
        except Exception:
            pass

    # Fallback heuristic: extrage siruri ASCII printabile
    strings: list = []
    current = bytearray()
    for ch in handshake_bytes:
        if 32 <= ch <= 126:
            current.append(ch)
        else:
            if len(current) >= 2:
                try:
                    s = current.decode("ascii", errors="ignore")
                    if s:
                        strings.append(s)
                except Exception:
                    pass
            current = bytearray()
    if len(current) >= 2:
        try:
            s = current.decode("ascii", errors="ignore")
            if s:
                strings.append(s)
        except Exception:
            pass

    if not strings:
        return None, None

    username = strings[0]
    password = strings[1] if len(strings) >= 2 else strings[0]
    return username, password


# ══════════════════════════════════════════════════════════════════════════════
# VNC SESSION CAPTURE — unified function
# ══════════════════════════════════════════════════════════════════════════════

def vnc_capture_session(
    sock: socket.socket,
    ip: str,
    port: int,
    initial_data: bytes = b"",
) -> Tuple[Optional[dict], Optional[dict]]:
    """
    Executes the full VNC handshake and captures:
      1. Challenge-response (SecurityType 2, VNC Auth)
      2. RAW security data (any other type / extra data)

    Unified from handle_vnc() + handle_vnc_dual_capture() from original.
    Eliminates duplicate code (≈80% overlap in original).

    Returns:
      (challenge_response_data, raw_security_data)
      Either can be None if nothing was captured.
    """
    traffic_log: list = []

    def _record(direction: str, data: bytes) -> None:
        if data:
            traffic_log.append({
                "direction": direction,
                "data": data.hex(),
                "length": len(data),
            })

    def _send(data: bytes) -> bool:
        try:
            sock.sendall(data)
            _record("SEND", data)
            return True
        except Exception:
            return False

    def _recv(n: int, timeout: float = 2.0) -> bytes:
        data = recv_some(sock, n, timeout)
        _record("RECV", data)
        return data

    # Save initial data
    if initial_data:
        _record("INITIAL", initial_data)

    challenge_response: Optional[dict] = None
    raw_security:       Optional[dict] = None

    try:
        # ── Faza 1: Client hello ─────────────────────────────────────────────
        client_hello = b""
        if initial_data.startswith(b"RFB"):
            client_hello = initial_data
        else:
            _send(b"RFB 003.008\n")
            client_hello = _recv(64, timeout=2.0)

        if not client_hello or not client_hello.startswith(b"RFB"):
            raw_security = {"error": "not_vnc", "traffic": traffic_log}
            return None, raw_security

        proto_str = client_hello.decode("ascii", errors="ignore").strip()
        mode, rfb_version = detect_rfb_mode(proto_str)

        logger.debug(f"[protocol] {ip}:{port} → {mode} ({rfb_version})")

        # ── Faza 2: Security negotiation ─────────────────────────────────────
        if mode == "RFB33":
            # RFB 3.3: server sends int32 security type directly
            _send(struct.pack("!I", VNC_SECURITY_VNC_AUTH))
            sec_choice = b"\x02"   # default — client does not choose
        else:
            # RFB 3.7+: server sends list, client chooses
            _send(b"\x01\x02")     # 1 type: Type 2 (VNC Auth)
            sec_choice = _recv(1, timeout=3.0)

        # ── Faza 3A: Client acceptă Type 2 → challenge-response ──────────────
        if sec_choice == b"\x02":
            challenge = get_vnc_challenge()
            _send(challenge)
            response  = _recv(16, timeout=3.0)

            if response and len(response) == 16:
                challenge_response = {
                    "protocol":  proto_str,
                    "rfb_mode":  mode,
                    "rfb_version": rfb_version,
                    "challenge": challenge.hex(),
                    "response":  response.hex(),
                }

            # Send auth fail (no real login allowed)
            _send(struct.pack("!I", VNC_AUTH_FAIL))

            # Listen for extra data (VeNCrypt, Plain Auth, etc.)
            extra = b""
            import time as _time
            t0 = _time.time()
            while _time.time() - t0 < 5.0:
                chunk = _recv(4096, timeout=1.0)
                if not chunk:
                    break
                extra += chunk
                if len(extra) > 10_000:
                    break

            if extra:
                raw_security = {
                    "protocol":          proto_str,
                    "security_type":     2,
                    "extra_data":        extra.hex(),
                    "extra_data_length": len(extra),
                    "traffic":           traffic_log,
                }

        # ── Faza 3B: Client refuză Type 2 → RAW capture ──────────────────────
        else:
            if mode == "RFB33":
                _send(struct.pack("!I", VNC_AUTH_FAIL))

            all_data = sec_choice if sec_choice else b""
            import time as _time
            t0 = _time.time()
            while _time.time() - t0 < 8.0:
                chunk = _recv(4096, timeout=1.0)
                if not chunk:
                    break
                all_data += chunk
                if len(all_data) > 15_000:
                    break

            sec_type = ord(sec_choice) if sec_choice else -1
            raw_security = {
                "protocol":        proto_str,
                "security_type":   sec_type,
                "raw_data":        all_data.hex(),
                "raw_data_length": len(all_data),
                "traffic":         traffic_log,
            }

    except Exception as e:
        logger.debug(f"[protocol] capture error {ip}:{port}: {e}")
        raw_security = {
            "error":   str(e),
            "traffic": traffic_log,
            "partial": True,
        }
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return challenge_response, raw_security


__all__ = [
    "get_vnc_challenge",
    "recv_some", "recv_exact", "recv_http",
    "detect_rfb_mode", "decode_plain_auth",
    "vnc_capture_session",
]
