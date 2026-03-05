# wagtail_detect.py

Wagtail CMS detection and version enumeration tool. Fingerprints whether a target website is running [Wagtail CMS](https://wagtail.org/) and attempts to determine the version from externally observable indicators.

## Requirements

- Python 3.10+
- `requests` library

```bash
pip install requests
```

## Usage

```bash
# Basic scan
python wagtail_detect.py https://example.com

# JSON output (for piping to jq or other tools)
python wagtail_detect.py https://example.com --json

# Verbose mode (shows all HTTP requests)
python wagtail_detect.py https://example.com --verbose

# Skip TLS certificate verification
python wagtail_detect.py https://example.com --no-verify

# Custom timeout
python wagtail_detect.py https://example.com --timeout 15

# Combined
python wagtail_detect.py https://target.gov.uk --no-verify --timeout 20 --verbose
```

## What It Detects

### CMS Detection (5 checks)

| Check | Weight | What It Looks For |
|---|---|---|
| **Admin Login Page** | 40 | `wagtailadmin` refs in HTML, `login-form` / `content-wrapper` CSS classes, "Sign in to Wagtail" heading, Stimulus `w-progress` controller, `reset-password` class, wagtailadmin JS/CSS asset paths |
| **Wagtail API** | 30 | `/api/v2/pages/` or `/api/pages/` with `meta.total_count` + `items` structure, API root with `pages`/`images`/`documents` endpoints, `repository_url` in meta |
| **Static Files** | 25 | Probes for `/static/wagtailadmin/css/core.css`, `js/wagtailadmin.js`, `js/vendor.js`, `images/wagtail-logo.svg`, and other known asset paths |
| **Homepage Indicators** | 15 | Image rendition URL patterns (`.fill-NxN`, `.width-N`, `.max-N`, `.scale-N`), `richtext-image` class, `data-block-key` (StreamField), `data-wagtail-userbar` |
| **Document Endpoint** | 10 | `/documents/` path with Wagtail-specific response characteristics |

### Confidence Scoring

Each check contributes a weighted score. The total determines the confidence level:

| Score | Confidence | Verdict |
|---|---|---|
| 60+ | HIGH | Wagtail CMS DETECTED |
| 30-59 | MEDIUM | Wagtail CMS DETECTED |
| 10-29 | LOW | Wagtail CMS POSSIBLE |
| 0-9 | NONE | Not detected |

### Version Enumeration (4 methods)

| Method | Detail |
|---|---|
| **API Version Disclosure** | Extracts `meta.version` from `/api/`, `/api/v2/pages/`, or `/api/health/` JSON responses |
| **Static File Version Hash** | Extracts the `?v=HASH` cache-busting parameter from wagtailadmin CSS/JS URLs on the admin login page |
| **Admin Asset Fingerprinting** | Analyses loaded JS/CSS for version-specific features: Stimulus `w-*` controllers (5.0+), sidebar JS (4.0+), SVG sprite icons (4.1+), telepath framework (2.13+) |
| **Version-Specific Path Probing** | Checks for existence of files introduced in specific versions: `telepath/` (2.13+), `sidebar.js` (4.0+), `bulk-actions/` (4.0+) |

### Supporting Checks

- **Django Framework Detection** — `csrftoken`/`sessionid` cookies, `csrfmiddlewaretoken` in forms, Django references in headers
- **Response Header Analysis** — Server, CSP, HSTS, X-Frame-Options, Permissions-Policy, CORS configuration

## Output

### Terminal (default)

```
  WAGTAIL CMS DETECTION SCAN
  ──────────────────────────────────────────────────
  Target:  https://example.com

  DETECTION RESULTS
  ──────────────────────────────────────────────────
  [+] Admin Login Page       DETECTED
      wagtailadmin references in HTML
      login-form CSS class
      Stimulus w-progress controller (Wagtail 5.0+)
  [+] Wagtail API            DETECTED
      API root at /api/ with Wagtail endpoints: documents, images, pages
  [+] Static Files           DETECTED
      /static/wagtailadmin/css/core.css exists (200 OK)
  [-] Homepage Indicators    NOT FOUND
  [-] Document Endpoint      NOT FOUND

  VERDICT: Wagtail CMS DETECTED (Confidence: HIGH, Score: 95)

  VERSION ENUMERATION
  ──────────────────────────────────────────────────
  [+] API Version Disclosure       1.2.3
  [~] Static File Version Hash     hash: 43f1be7e
  [~] Admin Asset Fingerprinting   Wagtail 5.0+
  [~] Version-Specific Paths       4.0+

  ESTIMATED VERSION: 1.2.3 (HIGH (API disclosure))
```

### JSON (`--json`)

```json
{
  "target": "https://example.com",
  "wagtail_detected": true,
  "confidence": "HIGH",
  "confidence_score": 95,
  "version_estimate": "1.2.3",
  "version_confidence": "HIGH (API disclosure)",
  "detection_checks": [ ... ],
  "version_checks": [ ... ],
  "django_detected": true,
  "django_evidence": [ "csrftoken cookie set (Django CSRF)" ],
  "response_headers": [ ... ],
  "requests_made": 12
}
```

## How It Works

1. Sends ~12 HTTP requests (responses are cached to avoid duplicates)
2. Scores each detection check independently
3. If score exceeds the LOW threshold, proceeds to version enumeration
4. Combines version indicators into a best estimate with confidence rating

The tool uses a standard browser User-Agent and respects connection errors gracefully.

## Detection Indicators Reference

### Image Rendition URL Patterns

Wagtail serves images with distinctive rendition suffixes:

```
/media/images/photo.fill-960x540.jpg
/media/images/banner.width-1920.png
/media/images/icon.max-100x100.png
/media/images/thumb.scale-50.jpg
/media/original_images/upload.png
```

### Admin Login Page Indicators

The Wagtail admin login page (`/admin/login/`) contains:

- CSS classes: `content-wrapper`, `login-form`, `reset-password`
- Asset paths: `wagtailadmin/js/core.js`, `wagtailadmin/css/core.css`
- Stimulus data attributes: `data-controller="w-progress"`
- Default heading: "Sign in to Wagtail"

### Static File Version Hash

Wagtail appends `?v=HASH` to admin static files (since Wagtail 2.7). This hash is tied to the Wagtail version and can be used for fingerprinting. Can be disabled by site operators via `WAGTAILADMIN_STATIC_FILE_VERSION_STRINGS = False`.

## Limitations

- Sites behind WAF rules may block probing requests
- Admin paths may be restricted by IP allowlisting or geo-restriction
- Customised admin templates may remove default Wagtail branding
- Sites using `ManifestStaticFilesStorage` disable version hash strings
- The tool does not brute-force paths or attempt authentication
- Version estimation via asset fingerprinting provides ranges (e.g. "5.0+"), not exact versions

## Legal

This tool is intended for authorised security assessments only. Ensure you have written permission before scanning any target. Unauthorised scanning may violate applicable laws.
