# pullthetail.py

Wagtail CMS content discovery and forced browsing tool. Brute-forces paths, enumerates page/document/image IDs, and discovers hidden endpoints using built-in wordlists tuned for Django and Wagtail.

## Requirements

- Python 3.10+
- `requests` library

```bash
pip install requests
```

## Quick Start

```bash
# Full scan (paths + ID enumeration + HTTP method testing)
python pullthetail.py https://target.com

# Admin-only scan with bypass variations
python pullthetail.py https://target.com --mode admin

# Enumerate page/document/image IDs 1-500
python pullthetail.py https://target.com --mode ids --id-range 1-500

# Rate-limited scan (0.1s delay between requests)
python pullthetail.py https://target.com --delay 0.1 --threads 5
```

## Scan Modes

| Mode | Description | What It Tests |
|---|---|---|
| `all` | Full scan (default) | Paths + ID enumeration + HTTP methods |
| `paths` | Path brute-forcing | Admin, API, static, debug, auth, well-known, content |
| `admin` | Admin discovery | Wagtail admin + Django admin + bypass variations |
| `api` | API endpoints | Wagtail API v2 and custom API paths |
| `ids` | ID enumeration | Sequential page, image, document, and download IDs |
| `methods` | HTTP methods | GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD/TRACE on key endpoints |

## Options

```
positional:
  url                    Target URL to scan

options:
  --mode MODE            Scan mode: all, paths, admin, api, ids, methods (default: all)
  --threads N, -t N      Concurrent threads (default: 10)
  --timeout N            HTTP timeout in seconds (default: 10)
  --id-range START-END   ID range for enumeration (default: 1-100)
  --delay SECONDS        Delay between requests (default: 0)
  --wordlist FILE, -w    Custom wordlist file (one path per line)
  --no-verify            Disable TLS certificate verification
  --show-404             Include 404 responses in output
  --status CODES         Comma-separated status codes to show (e.g. 200,301,403)
  --json                 Output results as JSON
  --output FILE, -o      Write results to JSON file
  --verbose, -v          Verbose output
```

## Built-in Wordlists

The tool ships with ~130 paths across 9 categories, all specific to Wagtail/Django:

### Wagtail Admin (35 paths)

```
/admin/                              /admin/reports/
/admin/login/                        /admin/reports/audit/
/admin/logout/                       /admin/reports/locked/
/admin/pages/                        /admin/reports/aging-pages/
/admin/pages/search/                 /admin/reports/site-history/
/admin/documents/                    /admin/forms/
/admin/images/                       /admin/redirects/
/admin/snippets/                     /admin/searchpromotions/
/admin/users/                        /admin/settings/
/admin/groups/                       /admin/modeladmin/
/admin/sites/                        /admin/styleguide/
/admin/collections/                  /admin/jsi18n/
/admin/workflows/                    /admin/password_reset/
/admin/workflow_tasks/               /admin/account/
/admin/api/                          /admin/account/change_password/
/admin/api/main/                     /admin/account/notification_preferences/
/admin/bulk/                         /admin/account/language_preferences/
/admin/chooser/
/admin/tag-autocomplete/
```

### Django Admin (10 paths)

```
/django-admin/                       /django-admin/auth/
/django-admin/login/                 /django-admin/auth/user/
/django-admin/logout/                /django-admin/auth/group/
/django-admin/password_change/       /django-admin/sites/
/django-admin/jsi18n/                /django-admin/sites/site/
```

### Admin Bypass Variations (19 paths)

Tests path normalisation and WAF bypass techniques:

```
/Admin/              /ADMIN/              /%61dmin/           /%41dmin/
/admin;/             /admin./             /admin../           //admin/
/./admin/            /admin%00/           /admin%20/          /admin..;/
/admin/..;/          /Admin/login/        /%61dmin/login/     /django-Admin/
/Django-admin/       /DJANGO-ADMIN/       /%64jango-admin/
```

### Wagtail API (12 paths)

```
/api/                                /api/pages/
/api/v2/                             /api/images/
/api/v2/pages/                       /api/documents/
/api/v2/images/                      /api/health/
/api/v2/documents/                   /api/externalcontent/
/api/externalcontent/sources/        /api/externalcontent/items/
```

### Django / Auth (15 paths)

```
/accounts/                           /accounts/oidc/
/accounts/login/                     /accounts/oidc/login/
/accounts/logout/                    /accounts/oidc/callback/
/accounts/signup/                    /login/
/accounts/password/reset/            /logout/
/accounts/profile/                   /_util/
/accounts/social/                    /_util/login/
/_util/authenticate_with_password/
```

### Well-Known / Meta (8 paths)

```
/.well-known/security.txt            /robots.txt
/.well-known/jwks.json               /sitemap.xml
/.well-known/openid-configuration    /favicon.ico
/.well-known/change-password         /humans.txt
```

### Static / Media (16 paths)

```
/static/                             /static/rest_framework/
/static/wagtailadmin/                /media/
/static/wagtailadmin/css/            /media/images/
/static/wagtailadmin/js/             /media/documents/
/static/wagtailadmin/images/         /media/original_images/
/static/admin/                       /assets/
/static/admin/css/                   /gen/custom.css
/static/admin/js/                    /gen/custom.js
```

### Debug / Sensitive Files (30 paths)

```
/__debug__/          /__debug__/sql/       /debug/
/_debug_toolbar/     /silk/                /profiling/
/.env                /.git/                /.git/HEAD
/.git/config         /.gitignore           /manage.py
/settings.py         /pyproject.toml       /requirements.txt
/Dockerfile          /docker-compose.yml   /.dockerignore
/Procfile            /wsgi.py              /asgi.py
/.htaccess           /web.config           /wp-login.php
/wp-admin/           /xmlrpc.php           /server-status
/server-info         /status               /health
/healthcheck         /readiness            /liveness
/ping                /version              /info
```

### Content / Search (11 paths)

```
/documents/                          /search/?query=password
/search/                             /search/?query=internal
/search/?query=test                  /search/?query=draft
/search/?query=admin                 /search/?query=private
/feedback/                           /contact/
/forms/
```

## ID Enumeration

When using `--mode ids` or `--mode all`, the tool enumerates sequential IDs across four endpoints:

| Endpoint | What It Finds |
|---|---|
| `/api/pages/{id}/` | Wagtail CMS pages (published, draft, restricted) |
| `/api/images/{id}/` | Uploaded images (may require auth) |
| `/api/documents/{id}/` | Document metadata (may require auth) |
| `/documents/{id}/` | Direct document downloads |

Use `--id-range` to control the range:

```bash
# Default: IDs 1-100
python pullthetail.py https://target.com --mode ids

# Extended range
python pullthetail.py https://target.com --mode ids --id-range 1-1000

# Specific range
python pullthetail.py https://target.com --mode ids --id-range 50-200
```

Key things to look for:
- **200** on `/api/pages/{id}/` — accessible page content (check for restricted/draft pages)
- **401** on `/api/images/{id}/` — image exists but requires authentication
- **200** on `/documents/{id}/` — downloadable document without auth
- **403** — resource exists but access is denied
- Different response sizes at 401 may indicate different error handling

## HTTP Method Testing

When using `--mode methods` or `--mode all`, the tool tests 8 HTTP methods against key endpoints:

```
GET  POST  PUT  PATCH  DELETE  OPTIONS  HEAD  TRACE
```

Default endpoints tested: `/admin/`, `/api/`, `/api/pages/`, `/`, `/search/`

Look for:
- **TRACE** returning 200 — potential XST (Cross-Site Tracing)
- **PUT/PATCH/DELETE** returning 200 on API endpoints — write access without auth
- **OPTIONS** revealing allowed methods and CORS configuration

## Output

### Terminal (default)

```
  pullthetail.py
  Wagtail CMS Content Discovery & Forced Browsing

  Target:   https://target.com
  Mode:     all
  Threads:  10

  PATH DISCOVERY
  ────────────────────────────────────────────────────────────
  [302] /admin/                            [0 bytes]   -> /admin/login/?next=/admin/
  [200] /admin/login/                      [12250 bytes]
  [200] /api/                              [770 bytes]
  [200] /api/health/                       [161 bytes]
  [401] /api/images/                       [196 bytes]
  [200] /robots.txt                        [74 bytes]
  [200] /search/                           [15894 bytes]
  [302] /%61dmin/                          [0 bytes]   -> /admin/login/?next=/admin/

  SUMMARY
  ────────────────────────────────────────────────────────────
  Requests:  130     Hits: 52      Time: 0.4s
  Speed:     325.0 req/s
  Status:    200:10 | 301:13 | 302:28 | 405:1
  Paths:     52 unique
```

### JSON (`--json`)

```bash
python pullthetail.py https://target.com --mode api --json | jq .
```

```json
{
  "target": "https://target.com",
  "mode": "api",
  "path_results": [
    {
      "path": "/api/",
      "url": "https://target.com/api/",
      "status": 200,
      "length": 770,
      "redirect": "",
      "server": "gunicorn",
      "content_type": "application/json"
    }
  ],
  "id_results": [],
  "method_results": [],
  "summary": {
    "total_requests": 12,
    "total_hits": 8,
    "elapsed_seconds": 0.3,
    "requests_per_second": 40.0,
    "status_breakdown": {"200": 4, "401": 4},
    "unique_paths_found": 8,
    "unique_ids_found": 0
  }
}
```

### File output (`--output`)

```bash
python pullthetail.py https://target.com -o results.json
```

## Examples

```bash
# Quick admin recon
python pullthetail.py https://target.com --mode admin

# Full scan with rate limiting for WAF-protected sites
python pullthetail.py https://target.com --delay 0.2 --threads 3

# Enumerate 500 pages, only show 200s and 403s
python pullthetail.py https://target.com --mode ids --id-range 1-500 --status 200,403

# Use with wagtail_detect.py for a full assessment
python wagtail_detect.py https://target.com
python pullthetail.py https://target.com --mode all --id-range 1-200

# Custom wordlist with JSON output to file
python pullthetail.py https://target.com -w custom_paths.txt --json -o scan.json

# Include 404s to see the full picture
python pullthetail.py https://target.com --mode api --show-404

# Self-signed cert / staging environment
python pullthetail.py https://staging.example.com --no-verify
```

## Custom Wordlists

Create a text file with one path per line. Lines starting with `#` are comments. Leading `/` is added automatically if missing.

```
# custom_paths.txt
/api/v3/
/internal/
/staff/
/preview/
dashboard
reports/export
```

```bash
python pullthetail.py https://target.com -w custom_paths.txt
```

## Status Code Reference

| Code | Colour | Meaning |
|---|---|---|
| **200** | Green | Accessible — content returned |
| **301/302** | Cyan | Redirect — check the `Location` header for information disclosure |
| **401** | Yellow | Unauthorized — resource exists, auth required |
| **403** | Yellow | Forbidden — resource exists, access denied |
| **405** | Grey | Method not allowed — endpoint exists but rejects this method |
| **500** | Red | Server error — may indicate vulnerability or misconfiguration |

## Limitations

- Default status filter excludes 404s (use `--show-404` to include)
- ID enumeration uses sequential probing, not binary search
- No cookie/session handling for authenticated scanning (unauthenticated only)
- Threading may trigger WAF rate limits — use `--delay` and lower `--threads` accordingly
- Custom wordlist replaces the built-in list (does not append to it)

## Legal

This tool is intended for authorised security assessments only. Ensure you have written permission before scanning any target. Unauthorised scanning may violate applicable laws.
