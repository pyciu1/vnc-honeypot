# VNC Honeypot

A high-fidelity VNC honeypot designed for threat intelligence and security research. Captures VNC challenge-response hashes, Plain Authentication credentials, client fingerprints, and attacker telemetry in real time.

Part of an open-source **Honeypot Suite** (RDP + VNC + SSH) with a unified central dashboard.

---

## Features

### Protocol
- **Full RFB stack** — 3.3 / 3.7 / 3.8 / Apple / 4.x / 5.x
- **Dual capture** — challenge-response (Type 2) + RAW security data in the same session
- **Plain Auth** — extracts username and password from SecurityType 18 (VeNCrypt Plain)
- **HTTP honeypot** — captures noVNC and Guacamole scanners on port 5800

### Intelligence
- **Client fingerprinting** — identifies 12+ VNC clients (RealVNC, TightVNC, TigerVNC, UltraVNC, LibVNC...)
- **CVE detection** — detects 4 known exploit patterns (CVE-2006-2369, CVE-2014-8242, CVE-2019-15680, CVE-2019-8287)
- **Behavior scoring** — risk score 0–100 per IP with tags (bruteforce, scanner, multi_port_scan...)
- **Persona engine** — consistent fake server identity per attacker IP (careless_admin, developer, db_admin, security_analyst)
- **Counter intel** — tracking tokens per attacker IP

### Infrastructure
- **GeoIP** — MaxMind GeoLite2 (optional) with offline prefix table fallback
- **SQLite WAL** — zero data loss on crash, async batch writer
- **Rate limiter** — dual layer: TokenBucket + SlidingWindow
- **Alerting** — Telegram + Email (shared with RDP and SSH honeypots)
- **80 unit tests**

### Dashboard
Standalone web UI on port 49100 — 7 tabs, auto-refresh every 15 seconds.

```bash
python3 vnc_dashboard.py --db vnc_honeypot.db
# Open: http://YOUR_VPS_IP:49100
```

| Tab | Content |
|-----|---------|
| Overview | Aggregate stats, top clients, top countries, risk distribution |
| Live Feed | Last 100 events — connections, captures, CVE alerts, plain auth |
| Attackers | Top IPs by risk score with behavior tags |
| Captures | Challenge-response + Plain Auth credentials |
| Timeline | Connections and captures per hour (last 24h) |
| Geo | Geographic distribution of attackers |
| CVE Alerts | Detected exploit attempts |

---

## Quick start

```bash
# Install optional dependencies
pip install -r requirements.txt

# Self-test
python3 vnc_honeypot.py --self-test

# Start (root required for ports < 1024)
sudo python3 vnc_honeypot.py

# Full options
sudo python3 vnc_honeypot.py \
    --ports 5900-5910 \
    --http-port 5800 \
    --db /data/vnc_honeypot.db \
    --geoip-db /data/GeoLite2-City.mmdb \
    --telegram-token "TOKEN" \
    --telegram-chat-id "CHAT_ID"

# Start dashboard (separate terminal)
python3 vnc_dashboard.py --db /data/vnc_honeypot.db
```

---

## Docker

```bash
cp .env.example .env
# Edit .env with your settings
docker compose up -d
docker compose logs -f
```

---

## Architecture

```
vnc_config.py       ← CONFIG + protocol constants
vnc_db.py           ← SQLiteConnectionPool + init_db + DBWriter
vnc_rate.py         ← TokenBucket + SlidingWindow + RateLimiter
vnc_geo.py          ← GeoIP lookup + bot signature classification
vnc_protocol.py     ← Unified VNC handshake + Plain Auth decoder
vnc_fingerprint.py  ← Client fingerprinting + CVE detection
vnc_intel.py        ← PersonaEngine + BehaviorModel + CounterIntel
vnc_scenario.py     ← ScenarioManager + GridManager
vnc_handler.py      ← ConnectionHandler (VNC + HTTP)
vnc_honeypot.py     ← main() + argparse + graceful shutdown
vnc_dashboard.py    ← Standalone dashboard server (port 49100)
```

---

## API Endpoints

The dashboard exposes a REST API on port 49100:

| Endpoint | Description |
|----------|-------------|
| `GET /api/status` | Health check (no auth required) |
| `GET /api/overview` | Aggregate statistics |
| `GET /api/live` | Last 100 events |
| `GET /api/attackers` | Top attacker IPs by risk score |
| `GET /api/captures` | Credentials (paginated) |
| `GET /api/timeline` | Hourly activity data (last 24h) |
| `GET /api/geo` | Geographic distribution |
| `GET /api/cve` | CVE exploit attempts |

Optional authentication via `X-API-Key` header:
```bash
python3 vnc_dashboard.py --api-key your-secret-key
curl -H "X-API-Key: your-secret-key" http://localhost:49100/api/overview
```

---

## GeoIP setup (optional)

1. Register for a free MaxMind account: https://dev.maxmind.com
2. Download `GeoLite2-City.mmdb`
3. Pass to honeypot: `--geoip-db /path/to/GeoLite2-City.mmdb`

Without GeoIP the honeypot works fully — country/city/ISP fields will be empty.

---

## Integration with other honeypots

All three honeypots in the suite share the same `alerts.py` for Telegram and Email notifications. If `alerts.py` from the RDP honeypot is in the same directory or at `../rdp-honeypot-v54/`, the VNC honeypot imports it automatically.

A central dashboard aggregating RDP + VNC + SSH data is planned for v1.1.0.

---

## Tests

```bash
pytest tests/ -v
# 80 tests, ~2 seconds
```

---

## Legal

This software is intended for use on systems you own or have explicit written permission to monitor.

---

## License

MIT — see `LICENSE` for details.
