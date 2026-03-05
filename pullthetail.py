#!/usr/bin/env python3
"""
pullthetail.py — Wagtail CMS Content Discovery & Forced Browsing Tool

Brute-forces paths, enumerates page/document/image IDs, and discovers
hidden endpoints on Wagtail CMS sites using built-in wordlists tuned
for Django and Wagtail.

Usage:
    python pullthetail.py https://example.com
    python pullthetail.py https://example.com --mode all
    python pullthetail.py https://example.com --mode ids --id-range 1-500
    python pullthetail.py https://example.com --wordlist custom.txt
    python pullthetail.py https://example.com --threads 20 --json
"""

import argparse
import json
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
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

STATUS_COLOURS = {
    200: GREEN,
    301: CYAN,
    302: CYAN,
    307: CYAN,
    308: CYAN,
    401: YELLOW,
    403: YELLOW,
    405: DIM,
    500: RED,
}


# ── Built-in wordlists ───────────────────────────────────────────

# Wagtail admin paths
WAGTAIL_ADMIN_PATHS = [
    "/admin/",
    "/admin/login/",
    "/admin/logout/",
    "/admin/pages/",
    "/admin/pages/search/",
    "/admin/documents/",
    "/admin/images/",
    "/admin/snippets/",
    "/admin/users/",
    "/admin/groups/",
    "/admin/sites/",
    "/admin/collections/",
    "/admin/workflows/",
    "/admin/workflow_tasks/",
    "/admin/reports/",
    "/admin/reports/audit/",
    "/admin/reports/locked/",
    "/admin/reports/aging-pages/",
    "/admin/reports/site-history/",
    "/admin/forms/",
    "/admin/redirects/",
    "/admin/searchpromotions/",
    "/admin/settings/",
    "/admin/modeladmin/",
    "/admin/styleguide/",
    "/admin/jsi18n/",
    "/admin/password_reset/",
    "/admin/account/",
    "/admin/account/change_password/",
    "/admin/account/notification_preferences/",
    "/admin/account/language_preferences/",
    "/admin/api/",
    "/admin/api/main/",
    "/admin/bulk/",
    "/admin/chooser/",
    "/admin/tag-autocomplete/",
]

# Django admin paths
DJANGO_ADMIN_PATHS = [
    "/django-admin/",
    "/django-admin/login/",
    "/django-admin/logout/",
    "/django-admin/password_change/",
    "/django-admin/jsi18n/",
    "/django-admin/auth/",
    "/django-admin/auth/user/",
    "/django-admin/auth/group/",
    "/django-admin/sites/",
    "/django-admin/sites/site/",
]

# Wagtail API paths
WAGTAIL_API_PATHS = [
    "/api/",
    "/api/v2/",
    "/api/v2/pages/",
    "/api/v2/images/",
    "/api/v2/documents/",
    "/api/pages/",
    "/api/images/",
    "/api/documents/",
    "/api/health/",
    "/api/externalcontent/",
    "/api/externalcontent/sources/",
    "/api/externalcontent/items/",
]

# Django / Python common paths
DJANGO_COMMON_PATHS = [
    "/accounts/",
    "/accounts/login/",
    "/accounts/logout/",
    "/accounts/signup/",
    "/accounts/password/reset/",
    "/accounts/profile/",
    "/accounts/social/",
    "/accounts/oidc/",
    "/accounts/oidc/login/",
    "/accounts/oidc/callback/",
    "/login/",
    "/logout/",
    "/_util/",
    "/_util/login/",
    "/_util/authenticate_with_password/",
]

# Well-known and meta paths
WELLKNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/.well-known/change-password",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/humans.txt",
]

# Static and media paths
STATIC_MEDIA_PATHS = [
    "/static/",
    "/static/wagtailadmin/",
    "/static/wagtailadmin/css/",
    "/static/wagtailadmin/js/",
    "/static/wagtailadmin/images/",
    "/static/admin/",
    "/static/admin/css/",
    "/static/admin/js/",
    "/static/rest_framework/",
    "/media/",
    "/media/images/",
    "/media/documents/",
    "/media/original_images/",
    "/assets/",
    "/gen/custom.css",
    "/gen/custom.js",
]

# Common hidden / debug paths
DEBUG_PATHS = [
    "/__debug__/",
    "/__debug__/sql/",
    "/debug/",
    "/_debug_toolbar/",
    "/silk/",
    "/profiling/",
    "/.env",
    "/.git/",
    "/.git/HEAD",
    "/.git/config",
    "/.gitignore",
    "/manage.py",
    "/settings.py",
    "/pyproject.toml",
    "/requirements.txt",
    "/Dockerfile",
    "/docker-compose.yml",
    "/.dockerignore",
    "/Procfile",
    "/wsgi.py",
    "/asgi.py",
    "/.htaccess",
    "/web.config",
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/server-status",
    "/server-info",
    "/status",
    "/health",
    "/healthcheck",
    "/readiness",
    "/liveness",
    "/ping",
    "/version",
    "/info",
]

# Path traversal / bypass variations on admin
ADMIN_BYPASS_PATHS = [
    "/Admin/",
    "/ADMIN/",
    "/%61dmin/",
    "/%41dmin/",
    "/admin;/",
    "/admin./",
    "/admin../",
    "//admin/",
    "/./admin/",
    "/admin%00/",
    "/admin%20/",
    "/admin..;/",
    "/admin/..;/",
    "/Admin/login/",
    "/%61dmin/login/",
    "/django-Admin/",
    "/Django-admin/",
    "/DJANGO-ADMIN/",
    "/%64jango-admin/",
]

# Wagtail document / page paths for forced browsing
CONTENT_PATHS = [
    "/documents/",
    "/search/",
    "/search/?query=test",
    "/search/?query=admin",
    "/search/?query=password",
    "/search/?query=internal",
    "/search/?query=draft",
    "/search/?query=private",
    "/feedback/",
    "/contact/",
    "/forms/",
]


def build_wordlist(mode: str) -> list[str]:
    """Build wordlist based on selected mode."""
    paths = []
    if mode in ("all", "admin"):
        paths += WAGTAIL_ADMIN_PATHS
        paths += DJANGO_ADMIN_PATHS
        paths += ADMIN_BYPASS_PATHS
    if mode in ("all", "api"):
        paths += WAGTAIL_API_PATHS
    if mode in ("all", "paths"):
        paths += DJANGO_COMMON_PATHS
        paths += WELLKNOWN_PATHS
        paths += STATIC_MEDIA_PATHS
        paths += DEBUG_PATHS
        paths += CONTENT_PATHS
    if mode == "admin":
        paths += ADMIN_BYPASS_PATHS
    # Deduplicate preserving order
    seen = set()
    deduped = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


# ── Scanner ───────────────────────────────────────────────────────


class PullTheTail:
    """Wagtail CMS content discovery and forced browsing scanner."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        url: str,
        threads: int = 10,
        timeout: int = 10,
        verify_ssl: bool = True,
        verbose: bool = False,
        quiet: bool = False,
        status_filter: set[int] | None = None,
        delay: float = 0,
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
        # Default: show everything except 404
        self.status_filter = status_filter or {
            200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500, 502, 503,
        }
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.USER_AGENT})
        self.results: list[dict] = []
        self._lock = threading.Lock()
        self._request_count = 0
        self._start_time = 0.0

    def _probe(self, path: str, method: str = "GET") -> dict | None:
        """Send a single request and return result if interesting."""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            if self.delay > 0:
                time.sleep(self.delay)
            resp = self.session.request(
                method,
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            with self._lock:
                self._request_count += 1

            status = resp.status_code
            length = len(resp.content)
            redirect = resp.headers.get("Location", "")

            if status not in self.status_filter:
                return None

            result = {
                "path": path,
                "url": url,
                "status": status,
                "length": length,
                "redirect": redirect,
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", ""),
            }

            # Print live
            self._print_hit(result)
            return result

        except (ConnectionError, ReadTimeout, SSLError):
            if self.verbose:
                self._print_error(path)
            return None

    def _print_hit(self, result: dict) -> None:
        """Print a discovered endpoint to terminal."""
        if self.quiet:
            return
        status = result["status"]
        colour = STATUS_COLOURS.get(status, DIM)
        path = result["path"]
        length = result["length"]
        redirect = result["redirect"]

        line = f"  {colour}[{status}]{RESET} {path:<50} {DIM}[{length} bytes]{RESET}"
        if redirect:
            line += f" {CYAN}-> {redirect}{RESET}"

        with self._lock:
            print(line)

    def _print_error(self, path: str) -> None:
        if self.quiet:
            return
        with self._lock:
            print(f"  {RED}[ERR]{RESET} {path:<50} {DIM}connection error{RESET}")

    # ── Scanning modes ────────────────────────────────────────────

    def scan_paths(self, paths: list[str]) -> list[dict]:
        """Brute-force a list of paths with thread pool."""
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe, p): p for p in paths}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        return results

    def scan_ids(
        self,
        endpoint: str,
        id_start: int,
        id_end: int,
        label: str = "",
    ) -> list[dict]:
        """Enumerate sequential IDs on an endpoint."""
        paths = [f"{endpoint}{i}/" for i in range(id_start, id_end + 1)]
        if not self.quiet:
            print(
                f"\n  {BOLD}{MAGENTA}ID ENUMERATION: {label or endpoint}{RESET}"
            )
            print(
                f"  {DIM}Range: {id_start}-{id_end} "
                f"({id_end - id_start + 1} requests){RESET}"
            )
            print(f"  {DIM}{'─' * 60}{RESET}")
        return self.scan_paths(paths)

    def scan_api_pages(self, id_start: int, id_end: int) -> list[dict]:
        """Enumerate Wagtail page IDs via the API."""
        return self.scan_ids("/api/pages/", id_start, id_end, "Wagtail Pages API")

    def scan_api_images(self, id_start: int, id_end: int) -> list[dict]:
        """Enumerate Wagtail image IDs via the API."""
        return self.scan_ids("/api/images/", id_start, id_end, "Wagtail Images API")

    def scan_api_documents(self, id_start: int, id_end: int) -> list[dict]:
        """Enumerate Wagtail document IDs via the API."""
        return self.scan_ids(
            "/api/documents/", id_start, id_end, "Wagtail Documents API"
        )

    def scan_documents_direct(self, id_start: int, id_end: int) -> list[dict]:
        """Enumerate document download IDs."""
        return self.scan_ids("/documents/", id_start, id_end, "Document Downloads")

    def scan_http_methods(self, paths: list[str] | None = None) -> list[dict]:
        """Test HTTP methods against key endpoints."""
        if paths is None:
            paths = ["/admin/", "/api/", "/api/pages/", "/", "/search/"]

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
        results = []

        if not self.quiet:
            print(f"\n  {BOLD}{MAGENTA}HTTP METHOD TESTING{RESET}")
            print(f"  {DIM}{'─' * 60}{RESET}")

        for path in paths:
            for method in methods:
                url = urljoin(self.base_url + "/", path.lstrip("/"))
                try:
                    if self.delay > 0:
                        time.sleep(self.delay)
                    resp = self.session.request(
                        method,
                        url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False,
                    )
                    with self._lock:
                        self._request_count += 1

                    status = resp.status_code
                    # Only report non-404 / non-405 (interesting responses)
                    if status not in (404, 405):
                        colour = STATUS_COLOURS.get(status, DIM)
                        result = {
                            "path": path,
                            "method": method,
                            "status": status,
                            "length": len(resp.content),
                        }
                        results.append(result)
                        if not self.quiet:
                            print(
                                f"  {colour}[{status}]{RESET} "
                                f"{method:<8} {path:<40} "
                                f"{DIM}[{result['length']} bytes]{RESET}"
                            )
                except (ConnectionError, ReadTimeout, SSLError):
                    pass

        return results

    # ── Full scan orchestration ───────────────────────────────────

    def run(
        self,
        mode: str = "all",
        id_start: int = 1,
        id_end: int = 100,
        custom_wordlist: list[str] | None = None,
    ) -> dict:
        """Run a full scan."""
        self._start_time = time.time()
        all_results = {
            "target": self.base_url,
            "mode": mode,
            "path_results": [],
            "id_results": [],
            "method_results": [],
            "summary": {},
        }

        # Path brute-forcing
        if mode in ("all", "paths", "admin", "api"):
            paths = custom_wordlist or build_wordlist(mode)
            if not self.quiet:
                print(f"\n  {BOLD}{MAGENTA}PATH DISCOVERY{RESET}")
                print(f"  {DIM}{len(paths)} paths to test{RESET}")
                print(f"  {DIM}{'─' * 60}{RESET}")
            all_results["path_results"] = self.scan_paths(paths)

        # ID enumeration
        if mode in ("all", "ids"):
            all_results["id_results"] = []
            all_results["id_results"] += self.scan_api_pages(id_start, id_end)
            all_results["id_results"] += self.scan_api_images(id_start, id_end)
            all_results["id_results"] += self.scan_api_documents(id_start, id_end)
            all_results["id_results"] += self.scan_documents_direct(id_start, id_end)

        # HTTP method testing
        if mode in ("all", "methods"):
            all_results["method_results"] = self.scan_http_methods()

        elapsed = time.time() - self._start_time
        all_results["summary"] = self._build_summary(all_results, elapsed)
        return all_results

    def _build_summary(self, results: dict, elapsed: float) -> dict:
        """Build summary statistics."""
        all_hits = (
            results["path_results"]
            + results["id_results"]
            + results["method_results"]
        )

        status_counts: dict[int, int] = defaultdict(int)
        for hit in all_hits:
            status_counts[hit["status"]] += 1

        return {
            "total_requests": self._request_count,
            "total_hits": len(all_hits),
            "elapsed_seconds": round(elapsed, 1),
            "requests_per_second": round(self._request_count / max(elapsed, 0.1), 1),
            "status_breakdown": dict(sorted(status_counts.items())),
            "unique_paths_found": len(
                {h["path"] for h in results["path_results"]}
            ),
            "unique_ids_found": len(
                {h["path"] for h in results["id_results"]}
            ),
        }


# ── Output ────────────────────────────────────────────────────────


def print_banner(url: str, mode: str, threads: int) -> None:
    print()
    print(f"  {BOLD}{MAGENTA}pullthetail.py{RESET}")
    print(f"  {DIM}Wagtail CMS Content Discovery & Forced Browsing{RESET}")
    print()
    print(f"  {DIM}Target:{RESET}   {BOLD}{url}{RESET}")
    print(f"  {DIM}Mode:{RESET}     {mode}")
    print(f"  {DIM}Threads:{RESET}  {threads}")


def print_summary(summary: dict) -> None:
    print()
    print(f"  {BOLD}SUMMARY{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print(
        f"  Requests:  {summary['total_requests']:<8}"
        f"Hits: {summary['total_hits']:<8}"
        f"Time: {summary['elapsed_seconds']}s"
    )
    print(
        f"  Speed:     {summary['requests_per_second']} req/s"
    )

    if summary["status_breakdown"]:
        parts = []
        for status, count in sorted(summary["status_breakdown"].items()):
            colour = STATUS_COLOURS.get(status, DIM)
            parts.append(f"{colour}{status}{RESET}:{count}")
        print(f"  Status:    {' | '.join(parts)}")

    if summary["unique_paths_found"]:
        print(f"  Paths:     {summary['unique_paths_found']} unique")
    if summary["unique_ids_found"]:
        print(f"  IDs:       {summary['unique_ids_found']} resources found")
    print()


def json_output(results: dict) -> None:
    print(json.dumps(results, indent=2, default=str))


# ── CLI ───────────────────────────────────────────────────────────


def parse_id_range(value: str) -> tuple[int, int]:
    """Parse '1-100' into (1, 100)."""
    if "-" in value:
        parts = value.split("-", 1)
        return int(parts[0]), int(parts[1])
    n = int(value)
    return 1, n


def load_wordlist(path: str) -> list[str]:
    """Load a wordlist file (one path per line)."""
    paths = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith("/"):
                    line = "/" + line
                paths.append(line)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wagtail CMS Content Discovery & Forced Browsing",
        epilog=(
            "Modes:\n"
            "  all     Full scan: paths + ID enum + HTTP methods (default)\n"
            "  paths   Path brute-forcing only (admin, API, static, debug)\n"
            "  admin   Admin paths + bypass variations only\n"
            "  api     API endpoint discovery only\n"
            "  ids     Page/image/document ID enumeration only\n"
            "  methods HTTP method testing only\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--mode",
        choices=["all", "paths", "admin", "api", "ids", "methods"],
        default="all",
        help="Scan mode (default: all)",
    )
    parser.add_argument(
        "--threads", "-t", type=int, default=10, help="Concurrent threads (default: 10)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--id-range",
        default="1-100",
        help="ID range for enumeration, e.g. 1-500 (default: 1-100)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay between requests in seconds (default: 0)",
    )
    parser.add_argument(
        "--wordlist", "-w", help="Custom wordlist file (one path per line)"
    )
    parser.add_argument(
        "--no-verify", action="store_true", help="Disable TLS certificate verification"
    )
    parser.add_argument(
        "--show-404",
        action="store_true",
        help="Include 404 responses in output",
    )
    parser.add_argument(
        "--status",
        help="Comma-separated status codes to show (e.g. 200,301,403)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--output", "-o", help="Write results to file"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output"
    )

    args = parser.parse_args()

    # Parse status filter
    status_filter = None
    if args.status:
        status_filter = {int(s.strip()) for s in args.status.split(",")}
    elif args.show_404:
        status_filter = {
            200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 404, 405, 500, 502, 503,
        }

    # Parse ID range
    id_start, id_end = parse_id_range(args.id_range)

    # Load custom wordlist
    custom_wordlist = None
    if args.wordlist:
        custom_wordlist = load_wordlist(args.wordlist)

    if not args.json_output:
        print_banner(args.url, args.mode, args.threads)

    scanner = PullTheTail(
        url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        verify_ssl=not args.no_verify,
        verbose=args.verbose,
        quiet=args.json_output,
        status_filter=status_filter,
        delay=args.delay,
    )

    results = scanner.run(
        mode=args.mode,
        id_start=id_start,
        id_end=id_end,
        custom_wordlist=custom_wordlist,
    )

    if args.json_output:
        json_output(results)
    else:
        print_summary(results["summary"])

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        if not args.json_output:
            print(f"  {DIM}Results written to {args.output}{RESET}\n")


if __name__ == "__main__":
    main()
