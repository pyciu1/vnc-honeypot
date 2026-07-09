# Changelog

All notable changes to VNC Honeypot are documented here.

---

## [v1.0] — Initial release

### Protocol
- Full RFB protocol: 3.3 / 3.7 / 3.8 / 3.889 / 4.x / 5.x
- Dual capture: challenge-response (Type 2) + RAW security in one session
- SecurityType 18 (VeNCrypt Plain Auth) — username + password in cleartext
- HTTP honeypot on port 5800 — captures noVNC and Guacamole scanners

### Intelligence
- VNCClientFingerprinter — 12+ client signatures (RealVNC, TightVNC, TigerVNC, etc.)
- CVEExploitDetector — 4 CVE patterns (CVE-2006-2369, CVE-2014-8242, CVE-2019-15680, CVE-2019-8287)
- BehaviorModel — risk scoring 0–100, tags (bruteforce, scanner, multi_port_scan)
- PersonaEngine — 4 fake personas per IP (careless_admin, developer, db_admin, security_analyst)
- CounterIntel — tracking tokens per attacker IP

### Dashboard
- `vnc_dashboard.py` — standalone HTTP server on port 49100
- 7 tabs: Overview, Live Feed, Attackers, Captures, Timeline, Geo, CVE Alerts
- REST API with 8 endpoints — all pure stdlib, no dependencies
- Dark theme UI with auto-refresh every 15 seconds
- Authentication via `X-API-Key` header (optional)

### Infrastructure
- SQLiteConnectionPool — WAL mode, 10 concurrent connections
- DBWriter — batched async writes with flush-on-shutdown (no data loss)
- RateLimiter — dual layer: TokenBucket + SlidingWindowLimiter
- GeoIP — MaxMind GeoLite2 optional, offline prefix table fallback

### Quality
- 10 clean modules (from single 4111-line file)
- 80 unit tests
- Zero bare `except:` — all `except Exception:`
- Zero `print()` outside self-test — all `logging`
- Graceful shutdown with DBWriter flush
- argparse CLI — `--ports`, `--db`, `--geoip-db`, `--telegram-*`

### Integration
- Shared alerting with RDP honeypot (same alerts.py, Telegram + Email)
- Compatible with central dashboard (aggregates RDP + VNC data)

### Bugs fixed vs original
- `dashboard_html()` defined twice — second definition silently overrode first (neon dashboard never shown)
- `SlidingWindowLimiter` imported `deque` inside `allow()` on every call — moved to top-level
- `DBWriter` only flushed at `batch_size` — data lost on shutdown; now flushes periodically + on stop
- All init code ran at module level (on import) — moved to `main()`
- 8 bare `except:` catching SystemExit/KeyboardInterrupt — fixed to `except Exception:`
