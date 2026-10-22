#!/usr/bin/env python3
"""
PHPVERSE — PHP presence & version fingerprint scanner.

Companion to WEBVERSE. Given a website, detects whether PHP is running and
tries to determine the version from several independent signals (headers,
cookies, exposed phpinfo(), the expose_php easter egg, error pages, CMS
fingerprints), then flags the branch against PHP's support lifecycle and a
few well-known issues. Also checks for an exposed php-fpm (FastCGI) port.

Authorized use only. Only scan hosts you own or have written permission
to test.
"""
from __future__ import annotations

import argparse
import difflib
import http.client
import json
import random
import re
import socket
import ssl
import string
import struct
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


# ----------------------------------------------------------------------------
# Colors (same palette as webverse)
# ----------------------------------------------------------------------------
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[38;5;196m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[38;5;226m"
    GREEN  = "\033[38;5;46m"
    CYAN   = "\033[38;5;51m"
    GREY   = "\033[38;5;245m"
    PHP    = ["\033[38;5;27m", "\033[38;5;33m", "\033[38;5;63m",
              "\033[38;5;99m", "\033[38;5;105m"]

    @classmethod
    def strip(cls):
        for name in ("RESET", "BOLD", "DIM", "RED", "ORANGE",
                     "YELLOW", "GREEN", "CYAN", "GREY"):
            setattr(cls, name, "")
        cls.PHP = [""] * 5


BANNER = r"""
 ____  _   _ ______     _______ ____  ____  _____
|  _ \| | | |  _ \ \   / / ____|  _ \/ ___|| ____|
| |_) | |_| | |_) \ \ / /|  _| | |_) \___ \|  _|
|  __/|  _  |  __/ \ V / | |___|  _ < ___) | |___
|_|   |_| |_|_|     \_/  |_____|_| \_\____/|_____|
"""


def print_banner():
    lines = BANNER.strip("\n").splitlines()
    # PHP blue/purple gradient (256-color)
    palette = [C.PHP[0], C.PHP[1], C.PHP[2], C.PHP[3], C.PHP[4], C.PHP[4]]
    for i, line in enumerate(lines):
        print(f"{palette[i % len(palette)]}{C.BOLD}{line}{C.RESET}")
    print(f"{C.GREY}      PHP presence & version scanner"
          f"  ·  authorized use only{C.RESET}\n")


SEV_COLOR = {"HIGH": "RED", "MEDIUM": "ORANGE", "LOW": "YELLOW", "INFO": "CYAN"}


def sev(level, msg):
    col = getattr(C, SEV_COLOR.get(level, "GREY"))
    return f"{col}[{level}]{C.RESET} {msg}"


# ----------------------------------------------------------------------------
# PHP lifecycle. branch -> (end of active support, end of security support).
# Dates from php.net/supported-versions. Update when new branches ship.
# ----------------------------------------------------------------------------
LIFECYCLE = {
    (5, 6): ("2016-12-31", "2018-12-31"),
    (7, 0): ("2017-12-03", "2018-12-03"),
    (7, 1): ("2018-12-01", "2019-12-01"),
    (7, 2): ("2019-11-30", "2020-11-30"),
    (7, 3): ("2020-12-06", "2021-12-06"),
    (7, 4): ("2021-11-28", "2022-11-28"),
    (8, 0): ("2022-11-26", "2023-11-26"),
    (8, 1): ("2023-11-25", "2025-12-31"),
    (8, 2): ("2024-12-31", "2026-12-31"),
    (8, 3): ("2025-12-31", "2027-12-31"),
    (8, 4): ("2026-12-31", "2028-12-31"),
    (8, 5): ("2027-12-31", "2029-12-31"),
}
TODAY = __import__("datetime").date.today().isoformat()


def _vt(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


# Notable PHP CVEs: (id, severity, summary, [(lo, hi), ...]) with hi exclusive.
# Ranges are exact (major, minor, patch) tuples. Heuristic: distro packages
# backport fixes without changing the version string.
CVES = [
    ("CVE-2012-1823", "HIGH", "php-cgi query-string RCE",
     [((0, 0, 0), (5, 3, 12)), ((5, 4, 0), (5, 4, 2))]),
    ("CVE-2019-11043", "HIGH", "php-fpm + nginx path_info RCE",
     [((7, 1, 0), (7, 1, 33)), ((7, 2, 0), (7, 2, 24)), ((7, 3, 0), (7, 3, 11))]),
    ("CVE-2021-21703", "MEDIUM", "php-fpm local privilege escalation",
     [((7, 3, 0), (7, 3, 32)), ((7, 4, 0), (7, 4, 25)), ((8, 0, 0), (8, 0, 12))]),
    ("CVE-2022-31625", "MEDIUM", "pgsql prepared-statement use-after-free",
     [((7, 4, 0), (7, 4, 30)), ((8, 0, 0), (8, 0, 20)), ((8, 1, 0), (8, 1, 7))]),
    ("CVE-2023-3824", "HIGH", "phar stack buffer overflow",
     [((8, 0, 0), (8, 0, 30)), ((8, 1, 0), (8, 1, 22)), ((8, 2, 0), (8, 2, 9))]),
    ("CVE-2024-1874", "MEDIUM", "proc_open command injection (Windows)",
     [((8, 1, 0), (8, 1, 28)), ((8, 2, 0), (8, 2, 18)), ((8, 3, 0), (8, 3, 5))]),
    ("CVE-2024-4577", "MEDIUM", "PHP-CGI argument injection (Windows)",
     [((8, 1, 0), (8, 1, 29)), ((8, 2, 0), (8, 2, 20)), ((8, 3, 0), (8, 3, 8))]),
]


def version_findings(version, packaged=False, windows=False):
    """Lifecycle + known-issue hints for an exact or partial PHP version.

    CVEs tagged "(Windows)" are only reported when a Windows stack was seen."""
    out = []
    vt = _vt(version)
    if len(vt) < 2:
        return out
    branch = vt[:2]
    if branch[0] < 5 or branch in [(5, i) for i in range(0, 6)]:
        out.append(("HIGH", f"PHP {version} is ancient (pre-5.6) — "
                            "unsupported for many years"))
    elif branch in LIFECYCLE:
        _, sec_end = LIFECYCLE[branch]
        if sec_end < TODAY:
            out.append(("HIGH", f"PHP {branch[0]}.{branch[1]} reached END OF LIFE "
                                f"({sec_end}) — no more security fixes"))
        else:
            out.append(("INFO", f"PHP {branch[0]}.{branch[1]} security support "
                                f"until {sec_end}"))
    elif branch > max(LIFECYCLE):
        out.append(("INFO", f"PHP {branch[0]}.{branch[1]} is newer than this "
                            "tool's lifecycle table — check php.net"))
    if len(vt) >= 3:
        for cve, level, summary, ranges in CVES:
            if "(Windows)" in summary and not windows:
                continue
            if any(lo <= vt < hi for lo, hi in ranges):
                out.append((level, f"PHP {version}: {cve} — {summary}"))
        if packaged:
            out.append(("INFO", "distro-packaged PHP backports security fixes "
                                "without bumping the version: CVE hits above "
                                "may be false positives"))
    return out


# Default PHP of common distro releases, keyed by the Server header the web
# server sends (Apache/nginx version + distro tag). Low confidence by design:
# admins often install PHP from other repositories (e.g. ondrej/sury).
DISTRO_PHP = [
    # (regex on Server header, description, probable PHP branch(es))
    (r"Apache/2\.4\.58 \(Ubuntu\)", "Ubuntu 24.04", ["8.3"]),
    (r"nginx/1\.24\.0 \(Ubuntu\)", "Ubuntu 24.04", ["8.3"]),
    (r"Apache/2\.4\.52 \(Ubuntu\)", "Ubuntu 22.04", ["8.1"]),
    (r"nginx/1\.18\.0 \(Ubuntu\)", "Ubuntu 20.04/22.04", ["7.4", "8.1"]),
    (r"Apache/2\.4\.41 \(Ubuntu\)", "Ubuntu 20.04", ["7.4"]),
    (r"Apache/2\.4\.29 \(Ubuntu\)", "Ubuntu 18.04", ["7.2"]),
    (r"nginx/1\.14\.0 \(Ubuntu\)", "Ubuntu 18.04", ["7.2"]),
    (r"Apache/2\.4\.18 \(Ubuntu\)", "Ubuntu 16.04", ["7.0"]),
    (r"nginx/1\.10\.3 \(Ubuntu\)", "Ubuntu 16.04", ["7.0"]),
    (r"Apache/2\.4\.38 \(Debian\)", "Debian 10", ["7.3"]),
    (r"nginx/1\.18\.0 \(Debian\)", "Debian 11", ["7.4"]),
    (r"nginx/1\.22\.1 \(Debian\)|nginx/1\.22\.1$", "Debian 12", ["8.2"]),
    (r"Apache/2\.4\.62 \(Debian\)", "Debian 12", ["8.2"]),
    (r"Apache/2\.4\.65 \(Debian\)", "Debian 13", ["8.4"]),
]

# WordPress core -> minimum PHP it supports (lower bound on the PHP version).
WP_MIN_PHP = [((6, 6), "7.2.24"), ((6, 3), "7.0.0"), ((5, 2), "5.6.20"),
              ((0, 0), "5.2.4")]


# ----------------------------------------------------------------------------
# HTTP helper
# ----------------------------------------------------------------------------
UA = "Mozilla/5.0 (compatible; phpverse/1.0)"
_CTX = ssl._create_unverified_context()


def fetch(host, port, tls, vhost, path, timeout, method="GET"):
    """One request, no redirects. Returns (status, headers_dict_lower,
    set_cookies_list, body_str) or None on failure."""
    try:
        if tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=_CTX)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", vhost)
        conn.putheader("User-Agent", UA)
        conn.putheader("Accept", "*/*")
        conn.putheader("Connection", "close")
        conn.endheaders()
        r = conn.getresponse()
        body = r.read(262144).decode("latin-1", "replace")
        heads = {}
        for k, v in r.getheaders():
            if k.lower() != "set-cookie":
                heads[k.lower()] = v
        cookies = r.msg.get_all("Set-Cookie") or []
        status = r.status
        conn.close()
        return status, heads, cookies, body
    except Exception:
        return None


def fetch_follow(host, port, tls, vhost, path, timeout, hops=3):
    """GET with a few same-host redirects (http->https, www, trailing slash)."""
    base = vhost.lower().removeprefix("www.")
    for _ in range(hops + 1):
        res = fetch(host, port, tls, vhost, path, timeout)
        if not res:
            return None, (host, port, tls, vhost)
        status, heads, _, _ = res
        loc = heads.get("location")
        if status // 100 != 3 or not loc:
            return res, (host, port, tls, vhost)
        u = urlparse(loc if "://" in loc else f"//{vhost}{loc}", "http")
        nh = u.hostname or vhost
        # Stay in scope: only same host (or its www. variant), http/https.
        if (u.scheme not in ("http", "https")
                or nh.lower().removeprefix("www.") != base):
            return res, (host, port, tls, vhost)
        ntls = u.scheme == "https"
        nport = u.port or (443 if ntls else 80)
        try:
            host = socket.gethostbyname(nh)
        except Exception:
            return res, (host, port, tls, vhost)
        port, tls, vhost = nport, ntls, nh
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return res, (host, port, tls, vhost)


# ----------------------------------------------------------------------------
# Signal collection
# ----------------------------------------------------------------------------
TLS_PORTS = (443, 4443, 8443, 9443)
PHP_LOGO_EGG = "/?=PHPE9568F34-D428-11d2-A769-00AA001ACF42"

# Paths that commonly expose phpinfo() or PHP-specific behaviour.
INFO_PATHS = ["/phpinfo.php", "/info.php", "/php.php", "/test.php",
              "/i.php", "/pi.php", "/php_info.php", "/_profiler/phpinfo",
              "/phpinfo", "/info"]

# Exposed files that leak PHP info. (path, content regex, severity, label).
# A content regex is required so catch-all sites don't create false hits.
SENSITIVE = [
    ("/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "HIGH", ".env file exposed"),
    ("/.git/HEAD", r"^ref:\s*refs/", "HIGH", ".git directory exposed"),
    ("/composer.json", r'"require"\s*:', "LOW", "composer.json exposed"),
    ("/composer.lock", r'"packages"\s*:', "MEDIUM",
     "composer.lock exposed (full dependency versions)"),
    ("/wp-config.php.bak", r"DB_PASSWORD|DB_NAME", "HIGH",
     "wp-config backup exposed"),
    ("/wp-config.php~", r"DB_PASSWORD|DB_NAME", "HIGH",
     "wp-config backup exposed"),
    ("/wp-config.php.old", r"DB_PASSWORD|DB_NAME", "HIGH",
     "wp-config backup exposed"),
    ("/phpmyadmin/", r"phpMyAdmin", "MEDIUM", "phpMyAdmin reachable"),
    ("/pma/", r"phpMyAdmin", "MEDIUM", "phpMyAdmin reachable"),
    ("/adminer.php", r"Adminer", "MEDIUM", "Adminer reachable"),
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", None, "HIGH",
     "PHPUnit eval-stdin.php present (CVE-2017-9841 RCE)"),
    ("/storage/logs/laravel.log", r"local\.(?:ERROR|INFO)|production\.ERROR",
     "HIGH", "Laravel log exposed"),
    ("/_profiler/", r"Symfony Profiler", "HIGH", "Symfony profiler exposed"),
    ("/_ignition/health-check", r"can_execute_commands", "HIGH",
     "Laravel Ignition debug endpoint exposed"),
    ("/server-status", r"Apache Server Status", "MEDIUM",
     "Apache server-status exposed"),
    ("/php-fpm-status", r"pool:|process manager:", "MEDIUM",
     "php-fpm status page exposed"),
]

CMS_SIGNS = [
    # (name, regex on body, path to also probe or None)
    ("WordPress", r"wp-content/|wp-includes/|<meta name=\"generator\" content=\"WordPress", "/wp-login.php"),
    ("Drupal", r"<meta name=\"Generator\" content=\"Drupal|sites/(?:default|all)/(?:files|themes|modules)/", "/core/install.php"),
    ("Joomla", r"<meta name=\"generator\" content=\"Joomla|/media/jui/|/templates/system/", "/administrator/"),
    ("Magento", r"Mage\.Cookies|/static/frontend/|/skin/frontend/", None),
    ("PrestaShop", r"<meta name=\"generator\" content=\"PrestaShop|/modules/ps_", None),
    ("phpBB", r"phpBB|viewtopic\.php\?", None),
    ("MediaWiki", r"<meta name=\"generator\" content=\"MediaWiki", None),
    ("Laravel", r"laravel_session|XSRF-TOKEN", None),
    ("Symfony", r"sf_redirect|_sf2_attributes|symfony", None),
    ("phpMyAdmin", r"phpMyAdmin|pma_", "/phpmyadmin/"),
    ("Nextcloud", r"nextcloud|ownCloud", None),
]

GENERATOR_RE = re.compile(
    r"<meta\s+name=[\"']generator[\"']\s+content=[\"']([^\"']+)[\"']", re.I)

# Server header patterns that expose PHP.
PHP_VER_RE = re.compile(r"PHP/?\s?(\d+\.\d+(?:\.\d+)?(?:[-+~\w.]*)?)", re.I)


class Evidence:
    """Collects (signal, detail, version|None, confidence) tuples."""

    def __init__(self):
        self.items = []
        self.findings = []
        self.landing = ""
        self.baseline = None      # body of a random-path 404-probe
        self.packaged = False     # distro-packaged stack detected
        self.windows = False      # Windows / IIS stack detected

    def add(self, signal, detail, version=None, conf="medium"):
        key = (signal, detail)
        if all((s, d) != key for s, d, _, _ in self.items):
            self.items.append((signal, detail, version, conf))

    def note(self, level, msg):
        if (level, msg) not in self.findings:
            self.findings.append((level, msg))

    @property
    def detected(self):
        # A distro-stack guess or an exposed dev file is a hint, not proof.
        return any(sig not in ("Distro stack", "Exposure")
                   for sig, _, _, _ in self.items)

    def best_version(self):
        rank = {"high": 0, "medium": 1, "low": 2}
        cands = [(rank[c], -len(v), v) for _, _, v, c in self.items if v]
        return min(cands)[2] if cands else None

    def best_conf(self):
        rank = {"high": 0, "medium": 1, "low": 2}
        cands = [(rank[c], -len(v), c) for _, _, v, c in self.items if v]
        return min(cands)[2] if cands else None

    def versions(self):
        return sorted({v for _, _, v, _ in self.items if v})


def analyze_response(ev, res, label):
    """Mine one HTTP response for PHP signals."""
    status, heads, cookies, body = res

    xpb = heads.get("x-powered-by", "")
    if re.search(r"php", xpb, re.I):
        m = PHP_VER_RE.search(xpb)
        ev.add("X-Powered-By", xpb, m.group(1) if m else None,
               "high" if m else "medium")
    srv = heads.get("server", "")
    if re.search(r"Win32|Win64|Windows|Microsoft-IIS", srv + " " + xpb, re.I):
        ev.windows = True
    if re.search(r"php|mod_php|phusion", srv, re.I):
        m = PHP_VER_RE.search(srv)
        ev.add("Server header", srv, m.group(1) if m else None,
               "high" if m else "medium")
    for rx, distro, branches in DISTRO_PHP:
        if re.search(rx, srv):
            ev.packaged = True
            ev.add("Distro stack", f"{srv} -> {distro}, default PHP "
                   f"{'/'.join(branches)} (low confidence)",
                   branches[0] if len(branches) == 1 else None, "low")
            break
    if "mod_php" in srv.lower() or "mod_fastcgi" in srv.lower():
        ev.add("SAPI", f"Server header hints {srv}", None, "low")

    for ck in cookies:
        if ck.lower().startswith("phpsessid="):
            ev.add("Cookie", "PHPSESSID session cookie", None, "high")
            if "httponly" not in ck.lower():
                ev.note("LOW", "PHPSESSID set without HttpOnly flag")
            if "secure" not in ck.lower() and label.startswith("https"):
                ev.note("LOW", "PHPSESSID set without Secure flag over HTTPS")

    # PHP error/warning text leaking into the page
    m = re.search(r"(?:Fatal error|Parse error|Warning|Notice|Deprecated)"
                  r"</b>:\s+(.{0,120}?) in <b>([^<]+)</b> on line", body)
    if m:
        ev.add("Error leak", f"display_errors on: {m.group(2)}", None, "high")
        ev.note("MEDIUM", f"PHP errors displayed to visitors "
                          f"(path leak: {m.group(2)})")
    elif re.search(r"(?:Fatal error|Parse error|Warning): .{0,200} in /\S+\.php "
                   r"on line \d+", body):
        ev.add("Error leak", "PHP error text in page", None, "high")
        ev.note("MEDIUM", "PHP errors displayed to visitors (display_errors on)")

    for m in re.finditer(r"""(?:href|src|action)=["'][^"'#]*?\.php(?:[?"'])""",
                         body):
        ev.add("Links", "page links to .php files", None, "low")
        break


def check_phpinfo(ev, ctx, timeout):
    for path in INFO_PATHS:
        res = fetch(*ctx, path, timeout)
        if not res:
            continue
        status, heads, _, body = res
        if status != 200:
            continue
        if re.search(r"PHP Version\s*</?[^>]*>?\s*(\d+\.\d+\.\d+)", body) or \
           "phpinfo()" in body or "PHP Credits" in body:
            m = re.search(r"PHP Version\s*(?:</[^>]+>\s*<[^>]+>\s*)?"
                          r"(\d+\.\d+\.\d+[-+~\w.]*)", body)
            ver = m.group(1) if m else None
            ev.add("phpinfo()", f"exposed at {path}", ver, "high")
            ev.note("HIGH", f"phpinfo() page exposed at {path} — leaks "
                            "config, paths, env and modules")
            for key, label in (("System", "OS/system"),
                               ("Server API", "SAPI"),
                               ("Loaded Configuration File", "php.ini"),
                               ("DOCUMENT_ROOT", "document root")):
                mm = re.search(rf"{re.escape(key)}\s*(?:</[^>]+>\s*<[^>]+>\s*)?"
                               r"([^<\n]{3,120})", body)
                if mm:
                    ev.note("INFO", f"{label}: {mm.group(1).strip()}")
            return


def check_error_page(ev, ctx, timeout):
    """A 404 for a .php file is rendered by PHP-FPM/mod_php ('File not found.')
    on misconfigured setups, which also confirms PHP is handled here."""
    res = fetch(*ctx, "/nonexistent-phpverse-check.php", timeout)
    if not res:
        return
    status, heads, cookies, body = res
    if status == 404 and body.strip() == "File not found.":
        ev.add("php-fpm 404", "bare 'File not found.' = php-fpm answered "
                              "for a missing .php file", None, "high")
    analyze_response(ev, res, "error")


def check_cms(ev, ctx, home_body, timeout):
    names = []
    for name, rx, probe in CMS_SIGNS:
        if re.search(rx, home_body, re.I):
            names.append((name, probe))
    for m in GENERATOR_RE.finditer(home_body):
        gen = m.group(1)
        if re.search(r"wordpress|drupal|joomla|prestashop|mediawiki|typo3|"
                     r"concrete|php", gen, re.I):
            ver = re.search(r"(\d+(?:\.\d+)+)", gen)
            ev.note("INFO", f"generator meta: {gen}")
            ev.add("CMS generator", gen, None, "low")
    for name, probe in names:
        ev.add("CMS", f"{name} fingerprint (PHP application)", None, "medium")
    return [n for n, _ in names]


def check_wordpress_versions(ev, ctx, timeout, home_body=""):
    """WordPress core version -> the minimum PHP it supports (lower bound)."""
    wpver = None
    m = re.search(r'content="WordPress (\d+\.\d+(?:\.\d+)?)', home_body)
    src = "generator meta"
    if m:
        wpver = m.group(1)
    if not wpver:
        res = fetch(*ctx, "/feed/", timeout)
        if res and res[0] == 200:
            m = re.search(r"wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)", res[3])
            if m:
                wpver, src = m.group(1), "RSS feed"
    if not wpver:
        res = fetch(*ctx, "/readme.html", timeout)
        if res and res[0] == 200 and not same_as_baseline(ev, res[3]):
            m = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)?)", res[3])
            if m:
                wpver, src = m.group(1), "readme.html"
    if wpver:
        ev.note("INFO", f"WordPress core {wpver} ({src})")
        vt = _vt(wpver)[:2]
        for ref, minphp in WP_MIN_PHP:
            if vt >= ref:
                ev.note("INFO", f"WordPress {wpver} needs PHP >= {minphp} "
                                "(lower bound)")
                break
    res = fetch(*ctx, "/xmlrpc.php", timeout)
    if res and res[0] in (200, 405) and \
       re.search(r"XML-RPC server accepts POST", res[3]):
        ev.note("LOW", "WordPress xmlrpc.php reachable (brute-force / "
                       "pingback abuse surface)")


# ----------------------------------------------------------------------------
# php-fpm / FastCGI exposure (TCP 9000 is the classic default)
# ----------------------------------------------------------------------------
def probe_fastcgi(host, port, timeout):
    """Send FCGI_GET_VALUES; a FastCGI app replies with a record of type 10."""
    def pair(k, v):
        return bytes([len(k), len(v)]) + k + v
    content = (pair(b"FCGI_MAX_CONNS", b"") + pair(b"FCGI_MAX_REQS", b"")
               + pair(b"FCGI_MPXS_CONNS", b""))
    # version=1, type=9 (GET_VALUES), requestId=0, len, padding=0
    rec = struct.pack(">BBHHBB", 1, 9, 0, len(content), 0, 0) + content
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(rec)
        data = s.recv(512)
        s.close()
    except Exception:
        return None
    if len(data) >= 8 and data[0] == 1 and data[1] == 10:
        return data[8:].decode("latin-1", "replace")
    return None


# ----------------------------------------------------------------------------
# Per-target scan
# ----------------------------------------------------------------------------
def parse_target(t):
    if "://" not in t:
        t = "//" + t
    u = urlparse(t, "")
    return u.hostname, u.port, u.scheme


def scan_target(target, timeout, workers, fpm_ports, web_ports=None):
    name, forced_port, scheme = parse_target(target)
    try:
        ip = socket.gethostbyname(name)
    except Exception:
        return None, name, None
    ev = Evidence()

    # Pick entry point: honour explicit scheme/port, else try https then http.
    attempts = []
    if scheme == "http":
        attempts.append((forced_port or 80, False))
    elif scheme == "https":
        attempts.append((forced_port or 443, True))
    elif forced_port:
        attempts.append((forced_port, forced_port in TLS_PORTS))
    elif web_ports:
        attempts += [(p, p in TLS_PORTS) for p in web_ports]
    else:
        attempts += [(443, True), (80, False)]

    home, ctx = None, None
    for port, tls in attempts:
        res, final = fetch_follow(ip, port, tls, name, "/", timeout)
        if res:
            home, ctx = res, final
            break
    if not home:
        return None, name, ip

    host_, port_, tls_, vhost_ = ctx
    label = ("https" if tls_ else "http") + f"://{vhost_}:{port_}"
    ev.landing = label
    analyze_response(ev, home, label)
    check_cms(ev, ctx, home[3], timeout)
    check_baseline(ev, ctx, timeout)   # must precede the path probes

    # Remaining probes run in parallel against the final landing host.
    jobs = [
        lambda: check_phpinfo(ev, ctx, timeout),
        lambda: check_error_page(ev, ctx, timeout),
        lambda: _probe_index(ev, ctx, timeout, label),
        lambda: _probe_egg(ev, ctx, timeout),
        lambda: check_sensitive(ev, ctx, timeout, workers),
    ]
    if any(s == "CMS" and "WordPress" in d for s, d, _, _ in ev.items):
        jobs.append(lambda: check_wordpress_versions(ev, ctx, timeout, home[3]))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda j: j(), jobs))

    # php-fpm exposed directly?
    fpm = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(probe_fastcgi, ip, p, timeout): p for p in fpm_ports}
        for f in as_completed(futs):
            r = f.result()
            if r is not None:
                fpm[futs[f]] = r
    for p in sorted(fpm):
        ev.add("FastCGI", f"php-fpm/FastCGI answering on {ip}:{p}", None, "high")
        ev.note("HIGH", f"FastCGI port {p} reachable from outside — "
                        "unauthenticated code execution risk if it is php-fpm")

    return ev, name, ip


def same_as_baseline(ev, body):
    """True when `body` looks like the site's generic 'unknown path' page."""
    if ev.baseline is None:
        return False
    a, b = ev.baseline[:4000], body[:4000]
    return difflib.SequenceMatcher(None, a, b).quick_ratio() > 0.95


def check_baseline(ev, ctx, timeout):
    """Fetch two random paths. If the server answers 200 for them, it is a
    catch-all (front controller / SPA) and path probes need extra care."""
    rnd = "".join(random.choices(string.ascii_lowercase, k=12))
    res = fetch(*ctx, f"/phpverse-{rnd}", timeout)
    if res and res[0] == 200:
        ev.baseline = res[3]
        ev.note("INFO", "site answers 200 for unknown paths (catch-all "
                        "router) — path probes filtered against that page")


def _probe_index(ev, ctx, timeout, label):
    res = fetch(*ctx, "/index.php", timeout)
    if res and res[0] == 200 and not same_as_baseline(ev, res[3]):
        analyze_response(ev, res, label)
        ev.add("index.php", "/index.php answers 200", None, "low")


def check_sensitive(ev, ctx, timeout, workers):
    def one(item):
        path, rx, level, label = item
        res = fetch(*ctx, path, timeout)
        if not res or res[0] != 200:
            return None
        if same_as_baseline(ev, res[3]):
            return None
        if rx is None:
            # eval-stdin.php answers an empty 200 to a bare GET
            return (level, label, path, res)
        if re.search(rx, res[3][:65536]):
            return (level, label, path, res)
        return None
    with ThreadPoolExecutor(max_workers=workers) as ex:
        hits = [h for h in ex.map(one, SENSITIVE) if h]
    seen = set()
    for level, label, path, res in hits:
        if label in seen:
            continue
        seen.add(label)
        ev.note(level, f"{label} at {path}")
        ev.add("Exposure", f"{path} -> {label}", None, "high")
        body = res[3]
        if path.endswith("composer.json"):
            m = re.search(r'"php"\s*:\s*"([^"]+)"', body)
            if m:
                ev.note("INFO", f"composer.json requires php {m.group(1)} "
                                "(lower bound on the PHP version)")
        if path.endswith("composer.lock"):
            m = re.search(r'"platform"\s*:\s*\{[^}]*"php"\s*:\s*"([^"]+)"', body)
            if m:
                ev.note("INFO", f"composer.lock platform php {m.group(1)}")


def _probe_egg(ev, ctx, timeout):
    res = fetch(*ctx, PHP_LOGO_EGG, timeout)
    if not res:
        return
    status, heads, _, _ = res
    ctype = heads.get("content-type", "").lower()
    if status == 200 and "image/gif" in ctype:
        ev.add("expose_php egg", "PHP logo served at magic query string",
               None, "high")
        ev.note("LOW", "expose_php=On (PHP logo easter egg reachable)")


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
CONF_COL = {"high": "GREEN", "medium": "YELLOW", "low": "GREY"}


def clean(s):
    """Neutralise control characters (ANSI escapes...) from server data."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(s))


def print_report(name, ip, ev):
    name, ip = clean(name), clean(ip)
    head = name if name == ip else f"{name} ({ip})"
    print(f"{C.BOLD}{C.CYAN}▸ {head}{C.RESET}"
          f"  {C.GREY}{clean(getattr(ev, 'landing', ''))}{C.RESET}")
    if not ev.detected:
        print(f"  {C.GREY}no PHP signal found — not PHP, or fully hidden "
              f"(expose_php off, headers stripped, clean URLs){C.RESET}\n")
        return
    ver = ev.best_version()
    if ver:
        guess = (f" {C.ORANGE}(inferred from distro stack — low confidence)"
                 f"{C.RESET}" if ev.best_conf() == "low" else "")
        print(f"  {C.GREEN}{C.BOLD}PHP detected{C.RESET} · version "
              f"{C.BOLD}{clean(ver)}{C.RESET}{guess}")
        others = [v for v in ev.versions() if v != ver]
        if others:
            print(f"  {C.GREY}other version strings seen: "
                  f"{clean(', '.join(others))}{C.RESET}")
    else:
        print(f"  {C.GREEN}{C.BOLD}PHP detected{C.RESET} · "
              f"{C.ORANGE}version not exposed{C.RESET}")
    for signal, detail, v, conf in ev.items:
        col = getattr(C, CONF_COL[conf])
        print(f"    {col}{conf:<6}{C.RESET} {C.GREY}{signal:<15}{C.RESET} {clean(detail)}")
    findings = list(ev.findings)
    if ver:
        findings = version_findings(ver, ev.packaged, ev.windows) + findings
    else:
        findings.append(("INFO", "PHP version not exposed "
                                 "(expose_php=Off / headers stripped)"))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    for level, note in sorted(findings, key=lambda x: order[x[0]]):
        print(f"      {sev(level, clean(note))}")
    print()


def to_dict(name, ip, ev):
    ver = ev.best_version()
    findings = list(ev.findings)
    if ver:
        findings = version_findings(ver, ev.packaged, ev.windows) + findings
    return {
        "target": name, "ip": ip, "landing": ev.landing,
        "php_detected": ev.detected, "version": ver,
        "versions_seen": ev.versions(),
        "evidence": [{"signal": s, "detail": d, "version": v, "confidence": c}
                     for s, d, v, c in ev.items],
        "findings": [{"severity": l, "message": m} for l, m in findings],
    }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Phpverse — PHP presence & version scanner "
                    "(authorized use only).")
    ap.add_argument("targets", nargs="*",
                    help="host, IP or URL (https://example.com)")
    ap.add_argument("-f", "--file",
                    help="file with one target per line (# comments allowed)")
    ap.add_argument("-p", "--ports",
                    help="comma-separated web ports to try (default 443,80)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0,
                    help="per-request timeout seconds (default 5)")
    ap.add_argument("-w", "--workers", type=int, default=8,
                    help="concurrent probes per host (default 8)")
    ap.add_argument("--fpm-ports", default="9000,9001",
                    help="ports to test for exposed php-fpm/FastCGI "
                         "(default 9000,9001; use '' to skip)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable JSON output (no banner/colors)")
    ap.add_argument("--no-color", action="store_true", help="disable colors")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [l.strip() for l in fh
                            if l.strip() and not l.lstrip().startswith("#")]
        except OSError as e:
            ap.error(f"cannot read {args.file}: {e}")
    if not targets:
        ap.error("give at least one target (or -f FILE)")

    if args.no_color or args.json or not sys.stdout.isatty():
        C.strip()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    if not args.json:
        print_banner()
        print(f"{C.GREY}Authorized use only — scan only hosts you own or have "
              f"permission to test.{C.RESET}\n")

    fpm_ports = [int(p) for p in args.fpm_ports.split(",") if p.strip().isdigit()]
    web_ports = [int(p) for p in (args.ports or "").split(",") if p.strip().isdigit()]
    rc = 0
    out = []
    for target in targets:
        ev, name, ip = scan_target(target, args.timeout, args.workers,
                                   fpm_ports, web_ports)
        if ip is None:
            rc = 1
            if args.json:
                out.append({"target": target, "error": "could not resolve"})
            else:
                print(f"{C.RED}✗ {target} — could not resolve{C.RESET}\n")
        elif ev is None:
            rc = 1
            if args.json:
                out.append({"target": target, "ip": ip,
                            "error": "no HTTP(S) response"})
            else:
                print(f"{C.RED}✗ {target} ({ip}) — no HTTP(S) response{C.RESET}\n")
        elif args.json:
            out.append(to_dict(name, ip, ev))
        else:
            print_report(name, ip, ev)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"{C.GREY}Findings are heuristics — verify manually before "
              f"acting.{C.RESET}")
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.RED}Interrupted.{C.RESET}")
        sys.exit(130)
