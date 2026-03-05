#!/usr/bin/env python3
"""
Wagtail CMS Detection & Version Enumeration Tool

Detects whether a target website is running Wagtail CMS and attempts
to enumerate the version through multiple fingerprinting techniques.

Usage:
    python wagtail_detect.py https://example.com
    python wagtail_detect.py https://example.com --json
    python wagtail_detect.py https://example.com --timeout 15 --no-verify
    python wagtail_detect.py https://example.com --verbose
"""

import argparse
import json
import re
import sys
from urllib.parse import urljoin

try:
    import requests
    from requests.exceptions import ConnectionError, ReadTimeout, SSLError
except ImportError:
    print("Error: 'requests' is required. Install with: pip install requests")
    sys.exit(1)


# ── ANSI colours ──────────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"

# Detection confidence weights
WEIGHT_ADMIN_LOGIN = 40
WEIGHT_API = 30
WEIGHT_STATIC_FILES = 25
WEIGHT_HOMEPAGE = 15
WEIGHT_DOCUMENTS = 10

# Confidence thresholds
CONFIDENCE_HIGH = 60
CONFIDENCE_MEDIUM = 30
CONFIDENCE_LOW = 10


class WagtailDetector:
    """Detects Wagtail CMS and enumerates version on a target URL."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    # Wagtail-specific static file paths to probe
    STATIC_PROBES = [
        "/static/wagtailadmin/css/core.css",
        "/static/wagtailadmin/js/wagtailadmin.js",
        "/static/wagtailadmin/js/vendor.js",
        "/static/wagtailadmin/images/wagtail-logo.svg",
        "/static/wagtailadmin/js/core.js",
        "/static/wagtailadmin/js/sidebar.js",
        "/static/wagtailadmin/js/modal-workflow.js",
    ]

    # API paths to probe (most common configurations)
    API_PROBES = [
        "/api/v2/pages/",
        "/api/pages/",
        "/api/",
    ]

    # Version-specific paths (path, min_version_hint)
    VERSION_PATHS = [
        ("/static/wagtailadmin/js/telepath/", "2.13+"),
        ("/static/wagtailadmin/js/sidebar.js", "4.0+"),
        ("/static/wagtailadmin/js/bulk-actions/", "4.0+"),
        ("/static/wagtailadmin/css/panels/", "3.0+"),
    ]

    # Image rendition regex pattern (Wagtail's image serving)
    RENDITION_PATTERN = re.compile(
        r"(?:original_images/[\w.-]+\.\w+|"
        r"images/[\w.-]+\."
        r"(?:fill-\d+x\d+(?:-c\d+)?|"
        r"(?:max|min|width|height|scale)-\d+|"
        r"original)"
        r"(?:\.\w+))",
        re.IGNORECASE,
    )

    def __init__(
        self,
        url: str,
        timeout: int = 10,
        verify_ssl: bool = True,
        verbose: bool = False,
    ):
        self.base_url = url.rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = f"https://{self.base_url}"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        self.request_count = 0
        self._cache: dict[str, requests.Response | None] = {}

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"  {DIM}[>] {msg}{RESET}")

    def _request(
        self, path: str, allow_redirects: bool = True
    ) -> requests.Response | None:
        cache_key = path
        if cache_key in self._cache:
            self._log(f"CACHE HIT {path}")
            return self._cache[cache_key]

        url = urljoin(self.base_url + "/", path.lstrip("/"))
        self._log(f"GET {url}")
        self.request_count += 1
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
            )
            self._log(f"  -> {resp.status_code} ({len(resp.content)} bytes)")
            self._cache[cache_key] = resp
            return resp
        except (ConnectionError, ReadTimeout, SSLError) as e:
            self._log(f"  -> ERROR: {e.__class__.__name__}")
            self._cache[cache_key] = None
            return None

    # ── Detection checks ──────────────────────────────────────────

    def _check_admin_login(self) -> dict:
        """Check /admin/login/ for Wagtail-specific indicators."""
        result = {
            "name": "Admin Login Page",
            "detected": False,
            "evidence": [],
            "weight": WEIGHT_ADMIN_LOGIN,
            "score": 0,
        }

        # Try /admin/login/ first, then /admin/ (which may redirect)
        resp = self._request("/admin/login/")
        if resp is None:
            resp = self._request("/admin/")
        if resp is None:
            return result

        html = resp.text.lower()

        checks = [
            ("wagtailadmin" in html, "wagtailadmin references in HTML"),
            ('class="login-form"' in html, 'login-form CSS class'),
            ('class="content-wrapper"' in html, 'content-wrapper CSS class'),
            ("sign in to wagtail" in html, '"Sign in to Wagtail" heading'),
            ("<title>" in html and "wagtail" in html.split("<title>")[1].split("</title>")[0] if "<title>" in html else False,
             "Wagtail in page title"),
            ('class="reset-password"' in html, 'reset-password CSS class'),
            ("w-progress" in html, "Stimulus w-progress controller (Wagtail 5.0+)"),
            ("wagtailadmin/js/" in html, "wagtailadmin JS asset paths"),
            ("wagtailadmin/css/" in html, "wagtailadmin CSS asset paths"),
        ]

        for found, desc in checks:
            if found:
                result["evidence"].append(desc)

        if result["evidence"]:
            result["detected"] = True
            # Scale score by number of indicators found
            ratio = min(len(result["evidence"]) / 3, 1.0)
            result["score"] = int(result["weight"] * ratio)

        return result

    def _check_api_endpoints(self) -> dict:
        """Check for Wagtail API endpoints."""
        result = {
            "name": "Wagtail API",
            "detected": False,
            "evidence": [],
            "weight": WEIGHT_API,
            "score": 0,
        }

        for path in self.API_PROBES:
            resp = self._request(path)
            if resp is None or resp.status_code not in (200, 301, 302):
                continue

            try:
                data = resp.json()
            except (ValueError, AttributeError):
                continue

            # Check for Wagtail API v2 pages listing structure
            if "meta" in data and "items" in data:
                if "total_count" in data.get("meta", {}):
                    result["evidence"].append(
                        f"Wagtail API v2 structure at {path} "
                        f"(meta.total_count={data['meta']['total_count']})"
                    )

            # Check for API root with endpoint discovery
            if "endpoints" in data:
                endpoints = data["endpoints"]
                wagtail_endpoints = {"pages", "images", "documents"}
                found = wagtail_endpoints & set(endpoints.keys())
                if found:
                    result["evidence"].append(
                        f"API root at {path} with Wagtail endpoints: "
                        + ", ".join(sorted(found))
                    )

            # Check for meta.version or meta.repository_url
            meta = data.get("meta", {})
            if isinstance(meta, dict):
                if "repository_url" in meta:
                    result["evidence"].append(
                        f"repository_url in API meta: {meta['repository_url']}"
                    )

        if result["evidence"]:
            result["detected"] = True
            ratio = min(len(result["evidence"]) / 2, 1.0)
            result["score"] = int(result["weight"] * ratio)

        return result

    def _check_static_files(self) -> dict:
        """Probe for Wagtail admin static files."""
        result = {
            "name": "Static Files",
            "detected": False,
            "evidence": [],
            "weight": WEIGHT_STATIC_FILES,
            "score": 0,
        }

        for path in self.STATIC_PROBES:
            resp = self._request(path)
            if resp is None:
                continue
            if resp.status_code in (200, 403):
                if resp.status_code == 200:
                    result["evidence"].append(f"{path} exists (200 OK)")
                else:
                    result["evidence"].append(f"{path} forbidden (403) — path exists")
                # One confirmed static file is enough
                break

        # Also check the static directory itself
        resp = self._request("/static/wagtailadmin/")
        if resp and resp.status_code in (200, 403):
            result["evidence"].append(
                f"/static/wagtailadmin/ returns {resp.status_code}"
            )

        if result["evidence"]:
            result["detected"] = True
            result["score"] = result["weight"]

        return result

    def _check_homepage(self) -> dict:
        """Analyse homepage HTML for Wagtail indicators."""
        result = {
            "name": "Homepage Indicators",
            "detected": False,
            "evidence": [],
            "weight": WEIGHT_HOMEPAGE,
            "score": 0,
        }

        resp = self._request("/")
        if resp is None:
            return result

        html = resp.text

        # Check for image rendition URL patterns
        renditions = self.RENDITION_PATTERN.findall(html)
        if renditions:
            examples = renditions[:3]
            result["evidence"].append(
                f"{len(renditions)} image rendition URL(s) found: "
                + ", ".join(examples)
            )

        # Check for richtext-image class
        if 'class="richtext-image' in html or "class='richtext-image" in html:
            result["evidence"].append('richtext-image CSS class (Wagtail rich text)')

        # Check for rich-text wrapper class
        if 'class="rich-text"' in html or 'class="rich-text ' in html:
            result["evidence"].append('rich-text CSS class (Wagtail rich text wrapper)')

        # Check for data-block-key (Wagtail StreamField)
        if "data-block-key" in html:
            count = html.count("data-block-key")
            result["evidence"].append(
                f"data-block-key attributes ({count}x) — Wagtail StreamField"
            )

        # Check for Wagtail userbar
        if "data-wagtail-userbar" in html:
            result["evidence"].append(
                "data-wagtail-userbar found (authenticated user rendering)"
            )

        # Check for wagtail references in source
        html_lower = html.lower()
        if "wagtail" in html_lower:
            # Narrow down — avoid false positives from content about wagtails (birds)
            wagtail_indicators = [
                "wagtailadmin",
                "wagtailcore",
                "wagtailimages",
                "wagtaildocs",
                "wagtail-userbar",
                "wagtailuserbar",
            ]
            found = [w for w in wagtail_indicators if w in html_lower]
            if found:
                result["evidence"].append(
                    f"Wagtail references in HTML: {', '.join(found)}"
                )

        if result["evidence"]:
            result["detected"] = True
            ratio = min(len(result["evidence"]) / 2, 1.0)
            result["score"] = int(result["weight"] * ratio)

        return result

    def _check_documents(self) -> dict:
        """Check for Wagtail document serving endpoint."""
        result = {
            "name": "Document Endpoint",
            "detected": False,
            "evidence": [],
            "weight": WEIGHT_DOCUMENTS,
            "score": 0,
        }

        resp = self._request("/documents/")
        if resp is None:
            return result

        # Wagtail's /documents/ endpoint typically returns 404 (not a listing)
        # but the 404 page may have Wagtail indicators
        # A redirect to login could also indicate Wagtail document management
        if resp.status_code == 404:
            # Check if the 404 page has Wagtail indicators
            if "wagtail" in resp.text.lower():
                result["evidence"].append(
                    "/documents/ returns 404 with Wagtail references"
                )
        elif resp.status_code in (200, 403):
            result["evidence"].append(
                f"/documents/ returns {resp.status_code} (Wagtail document endpoint)"
            )

        if result["evidence"]:
            result["detected"] = True
            result["score"] = result["weight"]

        return result

    # ── Version enumeration ───────────────────────────────────────

    def _check_api_version(self) -> dict:
        """Extract version from API meta responses."""
        result = {"method": "API Version Disclosure", "version": None, "evidence": []}

        for path in ["/api/", "/api/v2/pages/", "/api/health/"]:
            resp = self._request(path)
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except (ValueError, AttributeError):
                continue

            meta = data.get("meta", {})
            if isinstance(meta, dict) and "version" in meta:
                version = str(meta["version"])
                result["version"] = version
                result["evidence"].append(f"meta.version = {version} (from {path})")
                break

        return result

    def _check_static_hash(self) -> dict:
        """Extract version hash from static file query parameters."""
        result = {
            "method": "Static File Version Hash",
            "hash": None,
            "evidence": [],
        }

        # Get the admin login page and extract ?v= from static file URLs
        resp = self._request("/admin/login/")
        if resp is None:
            resp = self._request("/admin/")
        if resp is None:
            return result

        # Extract ?v=HASH patterns from wagtailadmin static URLs
        hash_pattern = re.compile(
            r'wagtailadmin/[^"\'?]+\?v=([a-f0-9]+)', re.IGNORECASE
        )
        hashes = hash_pattern.findall(resp.text)

        if hashes:
            # All hashes should be the same (tied to Wagtail version)
            unique_hashes = set(hashes)
            result["hash"] = list(unique_hashes)[0]
            result["evidence"].append(
                f"Static version hash(es): {', '.join(sorted(unique_hashes))}"
            )

        return result

    def _fingerprint_admin_assets(self) -> dict:
        """Analyse admin page assets for version-specific indicators."""
        result = {
            "method": "Admin Asset Fingerprinting",
            "indicators": [],
            "evidence": [],
        }

        resp = self._request("/admin/login/")
        if resp is None:
            resp = self._request("/admin/")
        if resp is None:
            return result

        html = resp.text

        # Stimulus controllers (Wagtail 5.0+)
        if "data-controller=" in html and "w-" in html:
            controllers = re.findall(r'data-controller="([^"]*w-[^"]*)"', html)
            if controllers:
                result["indicators"].append("Wagtail 5.0+")
                result["evidence"].append(
                    f"Stimulus controllers: {', '.join(set(controllers))}"
                )

        # Check for Wagtail slim sidebar (4.0+)
        if "wagtail-sidebar" in html or "sidebar" in html.lower():
            sidebar_refs = re.findall(
                r'wagtailadmin/js/sidebar[^"\']*', html, re.IGNORECASE
            )
            if sidebar_refs:
                result["indicators"].append("Wagtail 4.0+")
                result["evidence"].append(f"Sidebar JS: {sidebar_refs[0]}")

        # Check for telepath (2.13+)
        if "telepath" in html:
            result["indicators"].append("Wagtail 2.13+")
            result["evidence"].append("Telepath JS framework referenced")

        # Count JS/CSS assets loaded
        js_files = re.findall(r'src="[^"]*wagtailadmin/js/[^"]*"', html)
        css_files = re.findall(r'href="[^"]*wagtailadmin/css/[^"]*"', html)
        if js_files or css_files:
            result["evidence"].append(
                f"{len(js_files)} JS + {len(css_files)} CSS wagtailadmin assets loaded"
            )

        # Check for icon system (changed in Wagtail 4.1+)
        if "wagtailadmin/sprite" in html or "use href=" in html:
            result["indicators"].append("Wagtail 4.1+ (SVG sprite icons)")
            result["evidence"].append("SVG sprite icon system detected")

        return result

    def _check_version_specific_paths(self) -> dict:
        """Probe for files that exist only in certain Wagtail versions."""
        result = {
            "method": "Version-Specific Paths",
            "indicators": [],
            "evidence": [],
        }

        for path, version_hint in self.VERSION_PATHS:
            resp = self._request(path)
            if resp is None:
                continue
            if resp.status_code in (200, 403):
                result["indicators"].append(version_hint)
                result["evidence"].append(
                    f"{path} exists ({resp.status_code}) -> {version_hint}"
                )

        return result

    def _check_django_indicators(self) -> dict:
        """Check for Django framework indicators (supporting context)."""
        result = {
            "method": "Django Framework Detection",
            "detected": False,
            "evidence": [],
        }

        resp = self._request("/")
        if resp is None:
            return result

        # Check cookies
        cookies = self.session.cookies.get_dict()
        if "csrftoken" in cookies:
            result["evidence"].append("csrftoken cookie set (Django CSRF)")
            result["detected"] = True
        if "sessionid" in cookies:
            result["evidence"].append("sessionid cookie set (Django sessions)")
            result["detected"] = True

        # Check for Django in headers
        for header, value in resp.headers.items():
            if "django" in value.lower():
                result["evidence"].append(f"{header}: {value}")
                result["detected"] = True

        # Check for csrfmiddlewaretoken in HTML forms
        if "csrfmiddlewaretoken" in resp.text:
            result["evidence"].append("csrfmiddlewaretoken in form (Django CSRF)")
            result["detected"] = True

        return result

    def _check_response_headers(self) -> dict:
        """Analyse response headers for version/technology disclosure."""
        result = {
            "method": "Response Header Analysis",
            "evidence": [],
            "server": None,
        }

        resp = self._request("/")
        if resp is None:
            return result

        headers_of_interest = [
            "Server",
            "X-Powered-By",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Permissions-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
        ]

        for name in headers_of_interest:
            value = resp.headers.get(name)
            if value:
                result["evidence"].append(f"{name}: {value}")
                if name == "Server":
                    result["server"] = value

        # Check CORS on API
        api_resp = self._request("/api/")
        if api_resp and "Access-Control-Allow-Origin" in api_resp.headers:
            cors = api_resp.headers["Access-Control-Allow-Origin"]
            result["evidence"].append(f"CORS on /api/: {cors}")

        return result

    # ── Confidence scoring ────────────────────────────────────────

    def _calculate_confidence(self, detection_results: list[dict]) -> tuple[str, int]:
        total_score = sum(r["score"] for r in detection_results)
        if total_score >= CONFIDENCE_HIGH:
            return "HIGH", total_score
        if total_score >= CONFIDENCE_MEDIUM:
            return "MEDIUM", total_score
        if total_score >= CONFIDENCE_LOW:
            return "LOW", total_score
        return "NONE", total_score

    def _estimate_version(self, version_results: list[dict]) -> tuple[str, str]:
        """Combine version indicators into an estimate."""
        api_version = None
        indicators = []
        hashes = []

        for vr in version_results:
            if vr.get("version"):
                api_version = vr["version"]
            if vr.get("hash"):
                hashes.append(vr["hash"])
            indicators.extend(vr.get("indicators", []))

        # Prefer explicit API version
        if api_version:
            return api_version, "HIGH (API disclosure)"

        # Use version indicators to narrow down
        if indicators:
            # Find the most specific (highest version) indicator
            version_order = [
                "2.13+",
                "3.0+",
                "4.0+",
                "4.1+ (SVG sprite icons)",
                "Wagtail 2.13+",
                "Wagtail 4.0+",
                "Wagtail 4.1+ (SVG sprite icons)",
                "Wagtail 5.0+",
            ]
            best = None
            for v in version_order:
                if v in indicators:
                    best = v
            if best:
                # Clean up the indicator
                best = best.replace("Wagtail ", "").split(" (")[0]
                return best, "MEDIUM (asset fingerprinting)"

        if hashes:
            return f"hash:{hashes[0]}", "LOW (static hash only)"

        return "Unknown", "NONE"

    # ── Public interface ──────────────────────────────────────────

    def detect(self) -> list[dict]:
        """Run all detection checks."""
        return [
            self._check_admin_login(),
            self._check_api_endpoints(),
            self._check_static_files(),
            self._check_homepage(),
            self._check_documents(),
        ]

    def enumerate_version(self) -> list[dict]:
        """Run all version enumeration checks."""
        return [
            self._check_api_version(),
            self._check_static_hash(),
            self._fingerprint_admin_assets(),
            self._check_version_specific_paths(),
        ]

    def run(self) -> dict:
        """Full scan: detection + version enumeration + supporting info."""
        detection_results = self.detect()
        confidence_label, confidence_score = self._calculate_confidence(
            detection_results
        )

        is_wagtail = confidence_label in ("HIGH", "MEDIUM")

        version_results = []
        version_estimate = "N/A"
        version_confidence = "N/A"

        if is_wagtail or confidence_label == "LOW":
            version_results = self.enumerate_version()
            version_estimate, version_confidence = self._estimate_version(
                version_results
            )

        django = self._check_django_indicators()
        headers = self._check_response_headers()

        return {
            "target": self.base_url,
            "is_wagtail": is_wagtail,
            "confidence": confidence_label,
            "confidence_score": confidence_score,
            "detection": detection_results,
            "version_estimate": version_estimate,
            "version_confidence": version_confidence,
            "version_details": version_results,
            "django": django,
            "headers": headers,
            "requests_made": self.request_count,
        }


# ── Output formatting ────────────────────────────────────────────


def print_report(results: dict) -> None:
    """Print coloured terminal report."""
    print()
    print(f"  {BOLD}{CYAN}WAGTAIL CMS DETECTION SCAN{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")
    print(f"  {DIM}Target:{RESET}  {BOLD}{results['target']}{RESET}")
    print()

    # Detection results
    print(f"  {BOLD}DETECTION RESULTS{RESET}")
    print(f"  {DIM}{'─' * 50}{RESET}")

    for check in results["detection"]:
        name = check["name"].ljust(22)
        if check["detected"]:
            status = f"{GREEN}DETECTED{RESET}"
            evidence_summary = check["evidence"][0] if check["evidence"] else ""
            print(f"  {GREEN}[+]{RESET} {name} {status}")
            for ev in check["evidence"]:
                print(f"      {DIM}{ev}{RESET}")
        else:
            status = f"{DIM}NOT FOUND{RESET}"
            print(f"  {DIM}[-]{RESET} {name} {status}")

    print()

    # Verdict
    if results["is_wagtail"]:
        conf = results["confidence"]
        conf_color = GREEN if conf == "HIGH" else YELLOW
        print(
            f"  {BOLD}{GREEN}VERDICT: Wagtail CMS DETECTED{RESET} "
            f"(Confidence: {conf_color}{conf}{RESET}, "
            f"Score: {results['confidence_score']})"
        )
    elif results["confidence"] == "LOW":
        print(
            f"  {BOLD}{YELLOW}VERDICT: Wagtail CMS POSSIBLE{RESET} "
            f"(Confidence: {YELLOW}LOW{RESET}, "
            f"Score: {results['confidence_score']})"
        )
    else:
        print(
            f"  {BOLD}{DIM}VERDICT: Wagtail CMS NOT DETECTED{RESET} "
            f"(Score: {results['confidence_score']})"
        )

    # Version enumeration
    if results["version_details"]:
        print()
        print(f"  {BOLD}VERSION ENUMERATION{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")

        for vr in results["version_details"]:
            method = vr["method"].ljust(28)
            if vr.get("version"):
                print(f"  {GREEN}[+]{RESET} {method} {BOLD}{vr['version']}{RESET}")
            elif vr.get("hash"):
                print(f"  {YELLOW}[~]{RESET} {method} hash: {CYAN}{vr['hash']}{RESET}")
            elif vr.get("indicators"):
                indicator_str = ", ".join(vr["indicators"])
                print(
                    f"  {YELLOW}[~]{RESET} {method} {YELLOW}{indicator_str}{RESET}"
                )
            else:
                print(f"  {DIM}[-]{RESET} {method} {DIM}No data{RESET}")

            for ev in vr.get("evidence", []):
                print(f"      {DIM}{ev}{RESET}")

        print()
        ve = results["version_estimate"]
        vc = results["version_confidence"]
        if ve != "Unknown":
            print(
                f"  {BOLD}ESTIMATED VERSION:{RESET} {CYAN}{ve}{RESET} "
                f"({DIM}{vc}{RESET})"
            )
        else:
            print(
                f"  {BOLD}ESTIMATED VERSION:{RESET} {DIM}Could not determine{RESET}"
            )

    # Django detection
    django = results["django"]
    if django["detected"]:
        print()
        print(f"  {BOLD}DJANGO FRAMEWORK{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        print(f"  {GREEN}[+]{RESET} Django detected")
        for ev in django["evidence"]:
            print(f"      {DIM}{ev}{RESET}")

    # Response headers
    headers = results["headers"]
    if headers["evidence"]:
        print()
        print(f"  {BOLD}RESPONSE HEADERS{RESET}")
        print(f"  {DIM}{'─' * 50}{RESET}")
        for ev in headers["evidence"]:
            name, _, value = ev.partition(": ")
            print(f"  {DIM}{name}:{RESET} {value}")

    print()
    print(
        f"  {DIM}Completed {results['requests_made']} HTTP requests{RESET}"
    )
    print()


def json_report(results: dict) -> None:
    """Print JSON report to stdout."""
    # Clean up for JSON serialisation
    output = {
        "target": results["target"],
        "wagtail_detected": results["is_wagtail"],
        "confidence": results["confidence"],
        "confidence_score": results["confidence_score"],
        "version_estimate": results["version_estimate"],
        "version_confidence": results["version_confidence"],
        "detection_checks": [],
        "version_checks": [],
        "django_detected": results["django"]["detected"],
        "django_evidence": results["django"]["evidence"],
        "response_headers": results["headers"]["evidence"],
        "requests_made": results["requests_made"],
    }

    for check in results["detection"]:
        output["detection_checks"].append(
            {
                "name": check["name"],
                "detected": check["detected"],
                "evidence": check["evidence"],
                "score": check["score"],
            }
        )

    for vr in results.get("version_details", []):
        output["version_checks"].append(
            {
                "method": vr["method"],
                "version": vr.get("version"),
                "hash": vr.get("hash"),
                "indicators": vr.get("indicators", []),
                "evidence": vr.get("evidence", []),
            }
        )

    print(json.dumps(output, indent=2))


# ── CLI ───────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wagtail CMS Detection & Version Enumeration",
        epilog="Example: python wagtail_detect.py https://example.com --verbose",
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show all HTTP requests"
    )

    args = parser.parse_args()

    if not args.json_output:
        print()
        print(f"  {BOLD}{MAGENTA}wagtail_detect.py{RESET}")
        print(f"  {DIM}Wagtail CMS Detection & Version Enumeration{RESET}")
        print()

    detector = WagtailDetector(
        url=args.url,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        verbose=args.verbose,
    )

    results = detector.run()

    if args.json_output:
        json_report(results)
    else:
        print_report(results)


if __name__ == "__main__":
    main()
