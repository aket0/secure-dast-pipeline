# secure-dast-pipeline

Automated Dynamic Application Security Testing (DAST) with OWASP ZAP against an isolated, intentionally vulnerable target application.

## Problem Solved

DAST finds vulnerabilities that static analysis misses — XSS, IDOR, missing headers — by actually interacting with a running application. This project demonstrates how to run DAST safely in CI with: a controlled target, isolated networking, severity thresholds, and regression tests to verify fixes.

## Architecture

```
secure-dast-pipeline/
├── src/target_app/
│   └── app.py          # Intentionally vulnerable Flask app (localhost only)
├── tests/
│   └── test_target_app.py   # Functional + vulnerability-presence + regression tests
├── Dockerfile.target        # Container for the DAST target
├── docker-compose.yml       # Isolated ZAP + target (internal network only)
├── zap-config/
│   └── zap-rules.tsv        # Alert overrides with severity thresholds
├── docs/
│   └── dast-methodology.md  # Scope, methodology, protection against accidents
└── .github/workflows/
    └── dast.yml             # CI: unit tests + ZAP baseline scan
```

## Isolation Guarantees

- Target binds to `127.0.0.1` only when run locally.
- Docker Compose network is `internal: true` — no external reachability.
- CI target is accessible only on `127.0.0.1:5000`.
- The ZAP scan URL is hardcoded — no external target possible.
- The app refuses to start if `APP_ENV` is not `test`, `local`, or `development`.

## Technologies

| Tool           | Purpose                                    |
|----------------|--------------------------------------------|
| Python / Flask | Intentionally vulnerable target application |
| OWASP ZAP      | Dynamic application security testing        |
| Docker Compose | Isolated DAST environment                   |
| pytest         | Functional, vulnerability-presence, regression tests |
| GitHub Actions | CI pipeline                                 |

## Prerequisites

- Python 3.11+ (for local unit tests)
- Docker (for DAST scan)
- Docker Compose (for full DAST environment)

## Installation

```bash
git clone https://github.com/aket0/secure-dast-pipeline.git
cd secure-dast-pipeline

python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Unit Tests (no Docker required)

```bash
pytest --cov=src --cov-report=term-missing
```

## Running DAST Locally

```bash
# Build target image
docker build -f Dockerfile.target -t dast-target:local .

# Start target (localhost only)
docker run -d --name dast-target -e APP_ENV=test \
  -p 127.0.0.1:5000:5000 dast-target:local

# Wait for health
curl http://127.0.0.1:5000/health

# Run ZAP baseline scan
mkdir -p zap-reports
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v $(pwd)/zap-reports:/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000 \
    -r zap-report.html -J zap-report.json -l WARN

# Stop target
docker stop dast-target && docker rm dast-target
```

## Intentional Vulnerabilities

| Vulnerability       | Endpoint       | Purpose                   |
|---------------------|----------------|---------------------------|
| Reflected XSS       | /search?q=     | ZAP should detect it      |
| IDOR                | /user/<id>     | No auth check             |
| Missing sec headers | all            | Baseline header checks    |

## Regression Tests (fixed endpoints)

| Endpoint       | Fix            | Test                            |
|----------------|----------------|---------------------------------|
| /search/safe   | html.escape()  | test_xss_escaped_in_safe_search |

## Severity Thresholds

| Level  | Threshold | Action   |
|--------|-----------|----------|
| High   | > 0       | FAIL     |
| Medium | any       | WARN     |
| Low    | any       | WARN     |

## Known Limits

- OWASP ZAP requires Docker — not installed locally.
- ZAP baseline scan only (passive + active spider). Full active scan not run by default.
- IDOR is a logic flaw ZAP may not detect without context-aware scripts.
- Docker Compose v2 (plugin) required for `docker compose up`.

## Improvement Paths

- Add ZAP active scan with authentication context.
- Write ZAP automation scripts for IDOR detection.
- Add Nuclei for template-based vulnerability scanning.
- Implement fix verification workflow (scan → fix → rescan).
