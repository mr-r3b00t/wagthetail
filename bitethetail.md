# bitethetail.py

Wagtail/Django authentication testing tool. Performs username enumeration via response differential analysis and dictionary-based password attacks against login forms. Handles CSRF tokens automatically and detects OIDC-protected endpoints.

## Requirements

- Python 3.10+
- `requests` library

```bash
pip install requests
```

## Quick Start

```bash
# Full scan (enumerate usernames, then brute-force valid ones)
python bitethetail.py https://target.com

# Username enumeration only
python bitethetail.py https://target.com --mode enum

# Brute-force a single user with a single password
python bitethetail.py https://target.com --mode brute -u admin -p Password123

# Custom wordlists
python bitethetail.py https://target.com -U users.txt -P passwords.txt

# Rate-limited scan
python bitethetail.py https://target.com --delay 0.5 --threads 3
```

## Scan Modes

| Mode | Description | What It Does |
|---|---|---|
| `all` | Full scan (default) | Enumerate usernames, then brute-force valid ones |
| `enum` | Username enumeration | Login/reset/signup differential analysis |
| `brute` | Password attack | Dictionary attack against login forms |

In `all` mode, the tool runs enumeration first, then only brute-forces usernames flagged as likely valid (smart targeting).

## Options

```
positional:
  url                        Target URL

options:
  --mode MODE                Scan mode: all, enum, brute (default: all)
  --target-form PATH         Specific login form path (default: auto-detect)
  --userlist FILE, -U        Custom username/email wordlist file
  --passlist FILE, -P        Custom password wordlist file
  -u USER                    Single username to test
  -p PASS                    Single password to test
  --threads N, -t N          Concurrent threads (default: 5)
  --timeout N                HTTP timeout in seconds (default: 10)
  --delay SECONDS            Delay between requests (default: 0.1)
  --lockout-threshold N      Max failed attempts per user before stopping (default: 5)
  --no-verify                Disable TLS certificate verification
  --json                     Output results as JSON
  --output FILE, -o          Write results to JSON file
  --verbose, -v              Verbose output
```

## How It Works

### Phase 1: Login Form Detection

The tool probes five endpoints and classifies each:

| Endpoint | What It Checks |
|---|---|
| `/accounts/login/` | Django allauth login form |
| `/admin/login/` | Wagtail admin login form |
| `/login/` | Frontend login redirect |
| `/accounts/password/reset/` | Password reset form |
| `/accounts/signup/` | Registration form |

For each endpoint, the tool determines:

- **FORM FOUND** — Login form detected with extractable fields and CSRF token
- **OIDC REDIRECT** — Endpoint redirects to an external SSO provider (skipped for brute-force)
- **REDIRECT** — Non-OIDC redirect
- **NOT FOUND** — 404, endpoint doesn't exist

OIDC detection looks for `oidc`, `oauth`, `sso`, `openid`, or `saml` in redirect URLs. Endpoints that redirect to external identity providers are automatically excluded from brute-forcing.

### Phase 2: Username Enumeration

Three enumeration techniques, each using response differential analysis:

#### Login Form Differential

1. Establish a baseline by sending 5 login attempts with random UUID usernames and wrong passwords
2. Record baseline response status, content length, timing, and content hash
3. For each target username, submit a login with a wrong password
4. Compare the response against the baseline for differences

Differences detected:

| Indicator | What It Means |
|---|---|
| **Status code change** | Different HTTP status for valid vs invalid users |
| **Response length change** | Different error message content (>50 bytes or >10% difference) |
| **Timing differential** | Valid users trigger password hashing, taking measurably longer |
| **Content hash change** | Response body differs from baseline |
| **Redirect change** | Different redirect target for valid users |
| **Error message** | Specific messages like "account is inactive" or "account locked" |

#### Password Reset Differential

Submits password reset requests for email addresses and compares responses against a baseline of invalid emails. Some applications return different responses for registered vs unregistered emails.

#### Signup Differential

Attempts registration with email addresses and checks for explicit "already registered" messages:

- "already registered"
- "already exists"
- "already in use"
- "email is taken"
- "account already exists"

### Phase 3: Password Attack

For each username × password combination:

1. `GET` the login page to obtain a fresh CSRF token (cookie + form field)
2. `POST` credentials with the CSRF token
3. Check for success indicators:
   - **302 redirect** to a non-login page (e.g., `/admin/`, `/accounts/profile/`)
   - **Session cookie** set (`sessionid`)
4. Check for lockout indicators:
   - HTTP 429 (Too Many Requests)
   - Response pattern change after threshold attempts

In `all` mode, only usernames flagged as likely valid during enumeration are targeted.

## CSRF Handling

Django requires a valid CSRF token on every POST request. The tool:

1. Sends a `GET` request to the login page
2. Extracts `csrftoken` from the response cookie
3. Extracts `csrfmiddlewaretoken` from the hidden form field
4. Includes both in the `POST` request
5. Repeats this for every attempt (Django may rotate tokens)

## Lockout Detection

The tool tracks consecutive failed attempts per username. If the lockout threshold is reached (default: 5), it checks for:

- **HTTP 429** responses — explicit rate limiting
- **Response pattern change** — different status codes appearing, suggesting lockout

When lockout is detected, the tool stops attacking that username and moves to the next.

## Built-in Wordlists

### Usernames (30 entries)

```
admin          administrator    wagtail        cms            editor
moderator      webmaster        sysadmin       root           test
testuser       demo             guest          user           staff
manager        superadmin       developer      dev            staging
info           contact          support        helpdesk       service
noreply        content          publisher      author         reviewer
```

Domain-derived emails are generated automatically (e.g., `admin@target.com`, `editor@target.com`).

### Passwords (50 entries)

```
password       Password1        Password123    admin          Admin123
Welcome1       welcome1         Passw0rd       P@ssw0rd       P@ssword1
letmein        changeme         123456         12345678       qwerty
dragon         master           monkey         shadow         sunshine
princess       football         abc123         111111         trustno1
iloveyou       batman           access         hello          1234567890
password1      Wagtail1         wagtail        Django1        django
Summer2025     Winter2025       Spring2025     Autumn2025     Password!
Test1234       Qwerty123        Pa$$w0rd       !QAZ2wsx       Welcome123
Admin@123      Govuk123         govuk          Digital1       Security1
```

## Output

### Terminal (default)

```
  bitethetail.py
  Wagtail/Django Authentication Testing

  Target:   https://target.com
  Mode:     all
  Threads:  5

  LOGIN FORM DETECTION
  ────────────────────────────────────────────────────────────
  [~] /accounts/login/                    OIDC REDIRECT (redirects to /accounts/oidc/.../login/)
  [+] /admin/login/                       FORM FOUND    (fields: csrfmiddlewaretoken, username, password)
  [~] /login/                             OIDC REDIRECT (redirects to /accounts/oidc/.../login/)
  [+] /accounts/password/reset/           FORM FOUND    (form with 'email' field)
  [-] /accounts/signup/                   NOT FOUND

  USERNAME ENUMERATION
  ────────────────────────────────────────────────────────────
  Testing 30 usernames against /admin/login/ ...
  Establishing baseline...
  Baseline: status=200 length=12567 time=432ms (stdev=27ms)

  [!] admin                          LIKELY VALID   (response content differs from baseline)
  [!] editor                         LIKELY VALID   (timing 389ms vs baseline 12ms)

  Testing 30 emails via /accounts/password/reset/ ...
  Establishing baseline...

  VALID USERNAMES: admin, editor

  PASSWORD ATTACK
  ────────────────────────────────────────────────────────────
  Smart mode: targeting 2 enumerated user(s)
  Targeting 2 user(s) with 50 password(s) (100 attempts)
  Endpoint: /admin/login/

  [!!!] admin : Password123        SUCCESS (redirect to /admin/)
  [***] editor                     LOCKOUT DETECTED (429 rate limit)

  SUMMARY
  ────────────────────────────────────────────────────────────
  Requests:    180      Time: 45.2s     Speed: 4.0 req/s

  Enumeration:
    Usernames tested:  30
    Likely valid:      2
    Valid:             admin, editor

  Brute Force:
    Credentials tested:  65
    Successful logins:   1
    Lockouts detected:   1

  CREDENTIALS FOUND:
    admin : Password123
```

### JSON (`--json`)

```bash
python bitethetail.py https://target.com --mode brute -u admin -p admin --json | jq .
```

```json
{
  "target": "https://target.com",
  "mode": "brute",
  "login_forms": [
    {
      "path": "/admin/login/",
      "label": "Wagtail Admin Login",
      "status": "form_found",
      "usable": true,
      "username_field": "username",
      "password_field": "password",
      "fields": ["csrfmiddlewaretoken", "next", "username", "password", "remember"]
    }
  ],
  "enum_endpoints": [],
  "enumeration_results": [],
  "brute_results": [
    {
      "username": "admin",
      "password": "admin",
      "success": true,
      "endpoint": "/admin/login/",
      "evidence": "redirect to /admin/",
      "response_status": 302,
      "response_time_ms": 385.2,
      "redirect": "/admin/"
    }
  ],
  "lockouts": [],
  "credentials_found": [
    {"username": "admin", "password": "admin"}
  ],
  "valid_usernames": [],
  "summary": {
    "total_requests": 7,
    "elapsed_seconds": 1.1,
    "requests_per_second": 6.4,
    "credentials_tested": 1,
    "credentials_found": 1,
    "lockouts_detected": 0
  }
}
```

### File output (`--output`)

```bash
python bitethetail.py https://target.com -o results.json
```

## Examples

```bash
# Quick admin credential check
python bitethetail.py https://target.com --mode brute -u admin -p admin

# Enumerate users only, verbose output
python bitethetail.py https://target.com --mode enum -v

# Full scan with custom wordlists
python bitethetail.py https://target.com -U users.txt -P passwords.txt

# Rate-limited scan for WAF-protected sites
python bitethetail.py https://target.com --delay 0.5 --threads 3

# Target a specific login form
python bitethetail.py https://target.com --target-form /custom/login/

# JSON output to file
python bitethetail.py https://target.com --json -o scan.json

# Self-signed cert / staging environment
python bitethetail.py https://staging.example.com --no-verify

# Use with other tools for a full assessment
python wagtail_detect.py https://target.com
python pullthetail.py https://target.com --mode all
python bitethetail.py https://target.com --mode all
```

## Custom Wordlists

Create text files with one entry per line. Lines starting with `#` are comments.

### Username wordlist

```
# users.txt
admin
editor
cms-admin
john.smith
jane.doe
admin@example.com
editor@example.com
```

### Password wordlist

```
# passwords.txt
Password123
Welcome1
Company2025
Autumn2025!
```

```bash
python bitethetail.py https://target.com -U users.txt -P passwords.txt
```

## Limitations

- No cookie/session persistence between enumeration and brute-force phases
- Cannot brute-force OIDC/SSO-protected login endpoints (by design)
- Password reset enumeration requires a working email backend (may return 500 in dev)
- Signup enumeration may create accounts on misconfigured targets — use with caution
- Timing analysis accuracy depends on network latency and server load
- No CAPTCHA bypass — tool stops if CAPTCHA is detected
- Single login form per endpoint (uses first form with a password field)
- Threading is applied across users, not across passwords for a single user

## Legal

This tool is intended for authorised security assessments only. Ensure you have written permission before testing any target. Unauthorised authentication testing may violate applicable laws.
