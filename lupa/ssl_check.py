"""
lupa/ssl_check.py — SSL certificate expiry check (Windows-compatible).

Tries the direct ssl+socket approach first (works on Linux/WSL), then falls
back to httpx with verify=True whose exception messages carry expiry info.
"""

import datetime
import ssl as _ssl
import socket as _socket

import httpx


def check_ssl(hostname: str, timeout: int) -> dict:
    """
    Check SSL certificate expiry for a hostname on port 443.

    Attempts a direct TLS connection first to read the notAfter field from
    the certificate. Falls back to httpx on Windows where getpeercert() often
    returns an empty dict for non-default CA chains.

    Args:
        hostname: Bare hostname, e.g. 'municipalidadantofagasta.cl'.
        timeout:  Connection timeout in seconds.

    Returns:
        dict with keys:
            valid      (bool)        — True if cert exists and is not expired.
            expired    (bool)        — True if cert existed but is past notAfter.
            days_left  (int | None)  — Positive = days until expiry; negative = days since.
            not_after  (str | None)  — ISO date string of cert expiry.
            error      (str | None)  — Human-readable error if check failed.
    """
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE

    # ── Attempt 1: direct TLS (Linux / WSL) ───────────────────────────────────
    try:
        with _socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    raise ValueError("getpeercert() returned empty dict")

                not_after_str = cert.get("notAfter")
                if not not_after_str:
                    raise ValueError("Missing notAfter field in cert")

                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_left = (not_after - now).days

                return {
                    "valid":     days_left > 0,
                    "expired":   days_left <= 0,
                    "days_left": days_left,
                    "not_after": not_after.strftime("%Y-%m-%d"),
                    "error":     None,
                }
    except Exception:
        pass  # fall through to httpx fallback

    # ── Attempt 2: httpx with verify=True (Windows-safe) ──────────────────────
    # A valid cert → request succeeds.
    # An expired/invalid cert → httpx raises ConnectError with "expired" in msg.
    try:
        with httpx.Client(verify=True, timeout=timeout,
                          headers={"User-Agent": "Mozilla/5.0 (LupaMunicipal/1.0)"}) as client:
            client.head(f"https://{hostname}/")
        return {"valid": True, "expired": False, "days_left": None,
                "not_after": None, "error": None}

    except httpx.ConnectError as e:
        err = str(e).lower()
        if "expired" in err or "certificate" in err:
            return {"valid": False, "expired": True, "days_left": None,
                    "not_after": None,
                    "error": "Certificado vencido (fecha exacta no disponible en Windows)"}
        return {"valid": False, "expired": False, "days_left": None,
                "not_after": None, "error": str(e)[:120]}

    except httpx.RemoteProtocolError:
        return {"valid": False, "expired": False, "days_left": None,
                "not_after": None, "error": "No SSL (HTTP only)"}

    except Exception as e:
        err = str(e).lower()
        if "expired" in err or "certificate" in err:
            return {"valid": False, "expired": True, "days_left": None,
                    "not_after": None, "error": "Certificado vencido"}
        return {"valid": False, "expired": False, "days_left": None,
                "not_after": None, "error": str(e)[:120]}
