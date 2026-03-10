"""
scanner.py — Lupa Municipal · Orchestrator
Reads targets.txt, runs SSL + legacy + port recon per host concurrently,
outputs results.json and results.js.

Usage:
    python scanner.py [--targets targets.txt] [--workers 40] [--timeout 10] [--no-recon]
"""

import argparse
import concurrent.futures
import datetime
import json
import re
from pathlib import Path

from lupa import check_ssl, audit_legacy, scan_ports


# ── Config defaults ────────────────────────────────────────────────────────────
DEFAULT_TARGETS = "targets.txt"
DEFAULT_WORKERS = 40
DEFAULT_TIMEOUT = 10   # seconds, HTTP + SSL
RECON_TIMEOUT   = 3.0  # seconds, per-port TCP connect
OUTPUT_JSON     = "results.json"
OUTPUT_JS       = "results.js"


# ── Per-host job ───────────────────────────────────────────────────────────────

def scan_host(hostname: str, timeout: int, run_recon: bool) -> dict:
    """
    Run SSL check, legacy audit, and optional port recon for a single hostname.

    Args:
        hostname:   Bare hostname string.
        timeout:    HTTP/SSL timeout in seconds.
        run_recon:  Whether to run port scanning (can be skipped for speed).

    Returns:
        Dict with keys: hostname, ssl, legacy, recon.
    """
    ssl_result    = check_ssl(hostname, timeout)
    legacy_result = audit_legacy(hostname, timeout)
    recon_result  = scan_ports(hostname, RECON_TIMEOUT) if run_recon else None

    return {
        "hostname": hostname,
        "ssl":      ssl_result,
        "legacy":   legacy_result,
        "recon":    recon_result,
    }


def _empty_result(hostname: str, error: str) -> dict:
    """Return a zeroed-out result dict for a host that threw an unexpected exception."""
    return {
        "hostname": hostname,
        "ssl": {"valid": False, "expired": False, "days_left": None,
                "not_after": None, "error": error},
        "legacy": {
            "copyright_year": None, "cms": None, "cms_version": None,
            "years_outdated": None, "raw_generator": None,
            "server": None, "php_version": None,
            "last_modified": None, "days_since_update": None,
            "response_time_ms": None, "broken_nav_links": [],
            "ga_ids": [], "error": error,
        },
        "recon": None,
    }


# ── Targets loader ─────────────────────────────────────────────────────────────

def load_targets(path: str) -> list[str]:
    """
    Parse targets file: one hostname per line, strip comments and blanks.
    Strips leading https?:// and trailing slashes.

    Args:
        path: Path to the targets .txt file.

    Returns:
        List of clean hostname strings.
    """
    targets = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        line = re.sub(r'^https?://', '', line).rstrip('/')
        targets.append(line)
    return targets


# ── Summary builder ────────────────────────────────────────────────────────────

def build_summary(results: list[dict]) -> dict:
    """
    Compute aggregate stats over all scanned hosts.

    Shared GA ID detection: same Google Analytics ID on multiple municipality
    sites is a procurement fraud signal — one contractor likely billed each
    municipality separately for identical work.

    Args:
        results: List of per-host result dicts from scan_host().

    Returns:
        Summary dict suitable for the index.html stats bar.
    """
    total = len(results)

    ssl_expired   = sum(1 for r in results if r["ssl"]["expired"])
    ssl_invalid   = sum(1 for r in results if not r["ssl"]["valid"])
    ssl_no_cert   = sum(1 for r in results if r["ssl"]["error"] and not r["ssl"]["expired"])

    legacy_sites  = sum(1 for r in results
                        if (r["legacy"]["years_outdated"] or 0) >= 5)
    cms_detected  = sum(1 for r in results if r["legacy"]["cms"])
    old_copyright = [r for r in results if (r["legacy"]["years_outdated"] or 0) >= 5]
    worst_year    = min((r["legacy"]["copyright_year"] for r in old_copyright), default=None)

    slow_sites    = sum(1 for r in results
                        if r["legacy"]["response_time_ms"] is not None
                        and r["legacy"]["response_time_ms"] > 5000)
    stale_sites   = sum(1 for r in results
                        if r["legacy"]["days_since_update"] is not None
                        and r["legacy"]["days_since_update"] > 730)
    broken_nav    = sum(1 for r in results if r["legacy"]["broken_nav_links"])
    php_exposed   = sum(1 for r in results if r["legacy"]["php_version"])

    # Exposed high-risk ports (DB, RDP, Redis, etc.)
    exposed_db    = sum(1 for r in results
                        if r["recon"] and r["recon"]["high_risk"])

    # Shared GA IDs → potential procurement fraud
    ga_map: dict[str, list[str]] = {}
    for r in results:
        for ga_id in r["legacy"].get("ga_ids", []):
            ga_map.setdefault(ga_id, []).append(r["hostname"])
    shared_ga = {ga_id: hosts for ga_id, hosts in ga_map.items() if len(hosts) > 1}

    return {
        "total_audited":         total,
        "ssl_expired":           ssl_expired,
        "ssl_invalid":           ssl_invalid,
        "ssl_no_cert":           ssl_no_cert,
        "legacy_sites":          legacy_sites,
        "cms_detected":          cms_detected,
        "oldest_copyright_year": worst_year,
        "slow_sites":            slow_sites,
        "stale_sites":           stale_sites,
        "broken_nav_sites":      broken_nav,
        "php_exposed":           php_exposed,
        "exposed_db_ports":      exposed_db,
        "shared_ga_ids":         shared_ga,
        "generated_at":          datetime.datetime.utcnow().isoformat() + "Z",
    }


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    """Parse CLI args, scan all targets concurrently, write JSON + JS output."""
    parser = argparse.ArgumentParser(description="Lupa Municipal — Auditoría Digital")
    parser.add_argument("--targets",   default=DEFAULT_TARGETS)
    parser.add_argument("--workers",   type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout",   type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--output",    default=OUTPUT_JSON)
    parser.add_argument("--no-recon",  action="store_true",
                        help="Skip port scanning (faster, no socket noise)")
    args = parser.parse_args()

    run_recon = not args.no_recon
    targets   = load_targets(args.targets)
    n         = len(targets)
    print(f"[lupa] {n} targets · {args.workers} workers · recon={'on' if run_recon else 'off'}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_host, h, args.timeout, run_recon): h
            for h in targets
        }
        done = 0
        for future in concurrent.futures.as_completed(futures):
            hostname = futures[future]
            done += 1
            try:
                result = future.result()
                results.append(result)
                ssl_ok  = "✓" if result["ssl"]["valid"] else "✗"
                yr      = result["legacy"]["copyright_year"] or "?"
                ports   = len(result["recon"]["open_ports"]) if result["recon"] else "-"
                print(f"  [{done:>3}/{n}] {ssl_ok} SSL  © {yr}  ports={ports}  {hostname}")
            except Exception as e:
                print(f"  [{done:>3}/{n}] ERROR {hostname}: {e}")
                results.append(_empty_result(hostname, str(e)))

    summary = build_summary(results)
    payload = {"summary": summary, "results": results}

    # Write results.json
    out_path = Path(args.output)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[lupa] Wrote {out_path}  ({len(results)} entries)")

    # Write results.js (works from file:// without a local server)
    js_path = out_path.with_suffix(".js")
    js_path.write_text(
        "const AUDIT_DATA = " + json.dumps(payload, ensure_ascii=False) + ";",
        encoding="utf-8",
    )
    print(f"[lupa] Wrote {js_path}")

    # ── Headline stats ─────────────────────────────────────────────────────────
    s = summary
    print(f"\n── Headline stats ──────────────────────────────────────────")
    print(f"  SSL expirado/inválido  : {s['ssl_invalid']} / {s['total_audited']}")
    print(f"  Sin certificado SSL    : {s['ssl_no_cert']} / {s['total_audited']}")
    print(f"  © desactualizado ≥5a   : {s['legacy_sites']} / {s['total_audited']}")
    print(f"  PHP expuesto en header : {s['php_exposed']} / {s['total_audited']}")
    print(f"  Sin actualizar ≥2 años : {s['stale_sites']} / {s['total_audited']}")
    print(f"  Respuesta lenta >5s    : {s['slow_sites']} / {s['total_audited']}")
    print(f"  Links nav rotos        : {s['broken_nav_sites']} / {s['total_audited']}")
    if run_recon:
        print(f"  Puertos DB/admin exp.  : {s['exposed_db_ports']} / {s['total_audited']}")
    if s['oldest_copyright_year']:
        print(f"  © más antiguo          : {s['oldest_copyright_year']}")
    if s['shared_ga_ids']:
        print(f"\n── ⚠  GA IDs compartidos ({len(s['shared_ga_ids'])} IDs) ─────────────")
        for ga_id, hosts in s['shared_ga_ids'].items():
            print(f"  {ga_id} → {', '.join(hosts)}")


if __name__ == "__main__":
    main()
