"""
lupa/recon.py — Lightweight port scanner for Lupa Municipal.

Socket logic is intentionally self-contained — copied from the port-scanner
project rather than imported, so this library has no path dependency on it.
Only scans PORTS_OF_INTEREST (not top-100) to keep per-host time under ~3s.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# Ports that are interesting from a public-sector negligence angle.
# Exposed DB / admin ports on a municipality are a publishable finding on their own.
PORTS_OF_INTEREST = [
    21,    # FTP      — credentials in plaintext
    22,    # SSH      — brute-force surface
    80,    # HTTP     — reachability
    443,   # HTTPS    — reachability + SSL
    2083,  # cPanel   — hosting control panel exposed
    2222,  # SSH-alt
    3306,  # MySQL    — database exposed to internet
    3389,  # RDP      — remote desktop exposed
    5432,  # PostgreSQL
    6379,  # Redis    — often auth-free
    8080,  # HTTP-alt
    9200,  # Elasticsearch — often auth-free
    27017, # MongoDB  — often auth-free
]

PORT_LABELS = {
    21:    "FTP",
    22:    "SSH",
    80:    "HTTP",
    443:   "HTTPS",
    2083:  "cPanel",
    2222:  "SSH-alt",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    6379:  "Redis",
    8080:  "HTTP-alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

RISK_LABELS = {
    21:    "HIGH",
    22:    "LOW",
    80:    "LOW",
    443:   "LOW",
    2083:  "HIGH",
    2222:  "HIGH",
    3306:  "HIGH",
    3389:  "HIGH",
    5432:  "HIGH",
    6379:  "CRITICAL",
    8080:  "LOW",
    9200:  "HIGH",
    27017: "HIGH",
}


def _probe(ip: str, port: int, timeout: float) -> dict | None:
    """
    Attempt a TCP connect to ip:port.

    Args:
        ip:      Target IP address string.
        port:    Port number.
        timeout: Socket timeout in seconds.

    Returns:
        Dict with port/service/risk if open, None if closed or unreachable.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return {
                "port":    port,
                "service": PORT_LABELS.get(port, "Unknown"),
                "risk":    RISK_LABELS.get(port, "LOW"),
            }
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_ports(hostname: str, timeout: float = 3.0) -> dict:
    """
    Resolve hostname and scan PORTS_OF_INTEREST concurrently.

    Args:
        hostname: Bare hostname, e.g. 'municipalidadantofagasta.cl'.
        timeout:  Per-port TCP connect timeout in seconds.

    Returns:
        dict with keys:
            ip          (str | None)  — Resolved IP address.
            open_ports  (list[dict])  — List of {port, service, risk} dicts, sorted by port.
            high_risk   (list[dict])  — Subset of open_ports with risk HIGH or CRITICAL.
            error       (str | None)  — Error message if DNS resolution failed.
    """
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        return {"ip": None, "open_ports": [], "high_risk": [], "error": str(e)}

    open_ports: list[dict] = []

    with ThreadPoolExecutor(max_workers=len(PORTS_OF_INTEREST)) as pool:
        futures = {pool.submit(_probe, ip, port, timeout): port
                   for port in PORTS_OF_INTEREST}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    high_risk = [p for p in open_ports if p["risk"] in ("HIGH", "CRITICAL")]

    return {
        "ip":         ip,
        "open_ports": open_ports,
        "high_risk":  high_risk,
        "error":      None,
    }
