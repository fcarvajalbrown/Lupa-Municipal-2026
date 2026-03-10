"""
lupa/legacy.py — Homepage scraper for copyright year, CMS version, server headers,
Last-Modified date, response time, broken nav links, and Google Analytics IDs.

All data is collected from a single HTTP GET request to avoid hammering the target.
"""

import datetime
import re

import httpx
from selectolax.parser import HTMLParser


# ── Compiled patterns ──────────────────────────────────────────────────────────

# Copyright year: "Copyright © 2014", "© 2014", "2014 ©", etc.
_COPYRIGHT_RE = re.compile(r'(?:©|copyright)[^\d]*(\d{4})', re.IGNORECASE)

# CMS fingerprints checked against meta[name=generator] and first 50 KB of HTML.
_CMS_PATTERNS = {
    "WordPress":   re.compile(r'wordpress',   re.IGNORECASE),
    "Joomla":      re.compile(r'joomla',      re.IGNORECASE),
    "Drupal":      re.compile(r'drupal',      re.IGNORECASE),
    "TYPO3":       re.compile(r'typo3',       re.IGNORECASE),
    "Wix":         re.compile(r'wix\.com',    re.IGNORECASE),
    "Squarespace": re.compile(r'squarespace', re.IGNORECASE),
    "Plone":       re.compile(r'plone',       re.IGNORECASE),
}

_WP_VERSION_RE  = re.compile(r'wordpress[\s/]+(\d+\.\d+[\.\d]*)', re.IGNORECASE)
_GEN_VERSION_RE = re.compile(r'(\d+\.\d+[\.\d]*)')

# Google Analytics: UA-XXXXXXX-X (Universal Analytics) or G-XXXXXXXXXX (GA4)
_GA_RE = re.compile(r'\b(UA-\d{4,12}-\d{1,4}|G-[A-Z0-9]{6,12})\b')

# PHP version from X-Powered-By header
_PHP_RE = re.compile(r'PHP/([\d.]+)', re.IGNORECASE)

_EMPTY = {
    "copyright_year": None, "cms": None, "cms_version": None,
    "years_outdated": None, "raw_generator": None,
    "server": None, "php_version": None,
    "last_modified": None, "days_since_update": None,
    "response_time_ms": None, "broken_nav_links": [],
    "ga_ids": [], "error": None,
}


def audit_legacy(hostname: str, timeout: int) -> dict:
    """
    Fetch the homepage of hostname (HTTPS first, HTTP fallback) and extract
    all press-relevant legacy and hygiene signals from a single request.

    Args:
        hostname: Bare hostname, e.g. 'municipalidadantofagasta.cl'.
        timeout:  HTTP request timeout in seconds.

    Returns:
        dict with keys:
            copyright_year   (int | None)   — Oldest © year found in footer/page.
            cms              (str | None)   — Detected CMS name.
            cms_version      (str | None)   — Detected CMS version if available.
            years_outdated   (int | None)   — current_year - copyright_year.
            raw_generator    (str | None)   — Raw <meta name="generator"> content.
            server           (str | None)   — Server response header.
            php_version      (str | None)   — PHP version from X-Powered-By.
            last_modified    (str | None)   — Last-Modified header as ISO date.
            days_since_update (int | None)  — Days since Last-Modified.
            response_time_ms (int | None)   — Total request time in ms.
            broken_nav_links (list[str])    — Nav hrefs returning 4xx/5xx/timeout.
            ga_ids           (list[str])    — Google Analytics IDs in page source.
            error            (str | None)   — Error message if homepage unreachable.
    """
    resp = None
    html = ""
    last_error = "Unreachable"
    response_time_ms = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        try:
            t0 = datetime.datetime.utcnow()
            with httpx.Client(verify=False, timeout=timeout,
                              follow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0 (LupaMunicipal/1.0)"}) as client:
                resp = client.get(url)
                html = resp.text
            response_time_ms = int((datetime.datetime.utcnow() - t0).total_seconds() * 1000)
            break
        except Exception as e:
            last_error = str(e)
    else:
        return {**_EMPTY, "error": last_error}

    headers = resp.headers

    # ── Server / PHP version ───────────────────────────────────────────────────
    server = headers.get("server") or None
    powered_by = headers.get("x-powered-by") or ""
    php_match = _PHP_RE.search(powered_by)
    php_version = php_match.group(1) if php_match else None

    # ── Last-Modified ──────────────────────────────────────────────────────────
    last_modified = None
    days_since_update = None
    lm_raw = headers.get("last-modified")
    if lm_raw:
        try:
            lm = datetime.datetime.strptime(lm_raw, "%a, %d %b %Y %H:%M:%S %Z")
            lm = lm.replace(tzinfo=datetime.timezone.utc)
            last_modified = lm.strftime("%Y-%m-%d")
            days_since_update = (datetime.datetime.now(datetime.timezone.utc) - lm).days
        except ValueError:
            pass

    # ── Meta generator + CMS ──────────────────────────────────────────────────
    tree = HTMLParser(html)
    gen_node = tree.css_first('meta[name="generator"]')
    raw_generator = gen_node.attributes.get("content", "").strip() if gen_node else None

    cms = None
    cms_version = None
    haystack = (raw_generator or "") + " " + html[:50_000]
    for name, pattern in _CMS_PATTERNS.items():
        if pattern.search(haystack):
            cms = name
            if name == "WordPress":
                m = _WP_VERSION_RE.search(haystack)
                cms_version = m.group(1) if m else None
            elif raw_generator:
                m = _GEN_VERSION_RE.search(raw_generator)
                cms_version = m.group(1) if m else None
            break

    # ── Copyright year ─────────────────────────────────────────────────────────
    footer = (tree.css_first("footer") or
              tree.css_first('[id*="footer"]') or
              tree.css_first('[class*="footer"]'))
    footer_text = footer.text() if footer else ""
    today = datetime.date.today()
    years = [int(y) for y in _COPYRIGHT_RE.findall(footer_text + " " + html)
             if 1990 <= int(y) <= today.year]
    copyright_year = min(years) if years else None
    years_outdated = (today.year - copyright_year) if copyright_year else None

    # ── Broken nav links ───────────────────────────────────────────────────────
    broken_nav_links = []
    nav = (tree.css_first("nav") or
           tree.css_first('[id*="nav"]') or
           tree.css_first('[class*="nav"]'))
    if nav:
        hrefs = [
            (a.attributes.get("href") or "")
            for a in nav.css("a")
            if (a.attributes.get("href") or "").startswith(("http", "/"))
        ][:10]  # cap to avoid blowing timeout budget
        base = f"https://{hostname}"
        for href in hrefs:
            full = href if href.startswith("http") else base + href
            try:
                with httpx.Client(verify=False, timeout=5, follow_redirects=True,
                                  headers={"User-Agent": "Mozilla/5.0 (LupaMunicipal/1.0)"}) as client:
                    r = client.head(full)
                    if r.status_code >= 400:
                        broken_nav_links.append(href)
            except Exception:
                broken_nav_links.append(href)

    # ── Google Analytics IDs ───────────────────────────────────────────────────
    ga_ids = list(set(_GA_RE.findall(html[:100_000])))

    return {
        "copyright_year":    copyright_year,
        "cms":               cms,
        "cms_version":       cms_version,
        "years_outdated":    years_outdated,
        "raw_generator":     raw_generator,
        "server":            server,
        "php_version":       php_version,
        "last_modified":     last_modified,
        "days_since_update": days_since_update,
        "response_time_ms":  response_time_ms,
        "broken_nav_links":  broken_nav_links,
        "ga_ids":            ga_ids,
        "error":             None,
    }
