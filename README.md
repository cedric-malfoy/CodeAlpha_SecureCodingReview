# CodeAlpha Secure Coding Review

A reproducible **CodeAlpha Cyber Security Task 3** project: review a Python/Flask notes app, explain its vulnerabilities, implement fixes, and verify the results.

**Start with the [audit report](reports/SECURITY_REVIEW.md) or [download its PDF](reports/SECURITY_REVIEW.pdf).** The repository includes a deliberately vulnerable teaching baseline, a corrected application, paired tests, static-analysis and dependency reports, and a video/submission guide.

This is an educational review of intentional weaknesses, not an independent audit of a third-party product. Both applications run locally with fictional data. No live website is deployed.

## What was reviewed

Private Notes supports registration, sign-in, sign-out, and creating, reading, editing, and deleting private notes. Both versions use SQLite and the same server-rendered interface.

| Finding | Baseline behavior | Corrected behavior |
| --- | --- | --- |
| SCR-01: SQL injection | Login SQL contains raw input | Parameterized lookup and password verification |
| SCR-02: Stored XSS | Stored text is marked as trusted HTML | Automatic output escaping and restrictive CSP |
| SCR-03: Broken authorization | Any signed-in user can access another user's note | Ownership checked for read, edit, and delete |
| SCR-04: Plaintext passwords | Registered and seeded passwords stored directly | Werkzeug scrypt password hashes |
| SCR-05: Missing CSRF protection | Mutations accepted without tokens | Flask-WTF protects all POST routes |
| SCR-06: Unsafe session configuration | Public signing key, debug enabled, weak cookie flags | Required external key, debug disabled, safer cookies |

The report documents severity, prerequisites, affected code, reproductions, remediation, limitations, and verification. Scanner findings are triaged rather than treated as the complete audit.

## Run the corrected application

Tested with **Python 3.12** on Linux. Windows users can use WSL. Runtime dependencies are pinned in `requirements.txt`; review and PDF tools are pinned in `requirements-dev.txt`.

```bash
git clone https://github.com/cedric-malfoy/CodeAlpha_SecureCodingReview.git
cd CodeAlpha_SecureCodingReview
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Generate a new local signing key in the same terminal, initialize the database, and start the corrected app:

```bash
export APP_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m flask --app secure.app init-db --seed
python run.py
```

Open **http://127.0.0.1:5000/**. The optional `--seed` creates fictional users **alice** and **bob**, both with the published lab password **LabPassword!2026**. Register a new fictional account to exercise the full flow. Initializing again preserves existing users and notes. Omit `--seed` for an empty application.

The key is required and must be at least 32 characters. Keep it in the terminal environment rather than source control. Changing it invalidates existing session cookies. New registrations require usernames of 3–30 letters, digits, or underscores, and passwords of 12–128 characters. Note titles accept 1–120 characters; note text accepts 1–10,000.

## Run the vulnerable baseline

Use fictional data on localhost only. In a second terminal with the same virtual environment activated:

```bash
python -m flask --app vulnerable.app init-db --seed
python run.py --vulnerable
```

Open **http://127.0.0.1:5001/**. The runner binds to loopback and requires `--vulnerable` to select the insecure implementation. Each version has a separate database and cookie name. Stop either server with Ctrl+C.

Data is created under ignored `instance/secure/` and `instance/vulnerable/` directories. A corrected database is initialized independently; the project does not migrate plaintext accounts from the baseline. Keep any existing demonstration database as evidence rather than importing it into the corrected version.

## Verify the review

Run the Python security and functional tests:

```bash
python -m pytest -q
python -m bandit -r secure labcore.py run.py
python -m pip_audit -r requirements-dev.txt --no-deps --disable-pip --strict \
  --cache-dir artifacts/pip-audit-cache --progress-spinner off
```

The paired tests **pass when the baseline weakness reproduces and the corrected application blocks it**. They are not a claim that the vulnerable app is safe. Test clients use isolated temporary databases and synthetic data.

For the four real-browser checks, install Node.js 22+ and the pinned Playwright development dependency:

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

An existing `/usr/bin/chromium` is used automatically; `CHROMIUM_PATH` selects another executable. On Linux, Playwright may require `npx playwright install --with-deps chromium`. `PYTHON` can select an interpreter; otherwise the browser tests use `.venv/bin/python`. Their loopback servers, generated secrets, and temporary databases are created and removed automatically.

Regenerate all machine-readable evidence after installing both Python and browser tools:

```bash
python tools/run_review.py
```

This writes `reports/evidence/`, records the source commit and SHA-256 hashes, captures test transcripts and scanner JSON, and exits nonzero for unexpected failures. Dependency auditing requires Internet access. Local caches and screenshots stay under ignored `artifacts/`. If this workspace's default npm cache is unwritable, use `npm ci --cache /tmp/codealpha-review-npm-cache`.

The raw Bandit outputs retain the warning about the public seed password. One specific `nosec B105` annotation documents that fictional fixture; no broad scanner exclusions hide application findings. GitHub Actions gates Python tests, the triaged corrected-code scan, dependency auditing, and browser checks.

## Read the evidence

- [Security review: Markdown](reports/SECURITY_REVIEW.md) and [PDF](reports/SECURITY_REVIEW.pdf).
- [Verification manifest](reports/evidence/verification.json), with commands, versions, commit, file hashes, and exit codes.
- [Paired test transcript](reports/evidence/pytest.txt), [browser observations](reports/evidence/browser-observations.json), and raw/triaged scanner JSON in the evidence directory.
- [References](SOURCES.md) and [video/submission guide](DEMO_AND_SUBMISSION.md).

The immutable baseline is commit `7d0102c450733cde23cac9be27a1d804bb4a628a`. The reviewed corrected source is recorded in the verification manifest. Later documentation commits preserve the reviewed application bytes.

To regenerate the PDF from its Markdown source:

```bash
python tools/build_report.py
```

## Practical limits

This lab does not implement login throttling, breached-password screening, MFA, account recovery, central session revocation, production TLS, a production WSGI server, or infrastructure hardening. Cookie `Secure` is disabled for local HTTP; a real HTTPS deployment needs it enabled. Signed client-side session cookies contain a user ID, not a password, and are not encrypted. Their 30-minute lifetime is rolling while the user remains active.

Passing tests and a clean triaged scan cover the documented cases at the recorded versions. They do not establish that every vulnerability has been found. The vulnerable implementation remains insecure by design. Tasks 1 and 2 are separate projects and are unchanged.
