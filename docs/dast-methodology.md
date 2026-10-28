# DAST Methodology

## Scope

The DAST scan targets **only** the local test application at `http://127.0.0.1:5000`.

It must never be pointed at:
- Production systems
- Staging systems owned by another team
- Any external third-party service

## Protection Against Accidental External Scanning

1. The target application only binds to `127.0.0.1` when run locally.
2. The Docker Compose network (`dast-net`) is `internal: true` — no external connectivity.
3. The CI workflow starts the target in Docker, accessible only on localhost.
4. The ZAP baseline scan URL is hardcoded to `http://127.0.0.1:5000`.

## Intentional Vulnerabilities (scan targets)

| Vulnerability        | Endpoint          | ZAP Rule ID |
|----------------------|-------------------|-------------|
| Reflected XSS        | /search?q=        | 40012       |
| IDOR                 | /user/<id>        | —           |
| Missing security hdrs| all               | 10020, 10021|

## Fixed Endpoints (regression tests)

| Endpoint         | Fix Applied               | Test                    |
|------------------|---------------------------|-------------------------|
| /search/safe     | html.escape() on input    | test_xss_escaped_...    |

## Severity Thresholds

| Risk Level | ZAP Code | Action      |
|------------|----------|-------------|
| High       | 3        | FAIL (block)|
| Medium     | 2        | WARN        |
| Low        | 1        | WARN        |
| Info       | 0        | PASS        |

## Running the DAST Scan Locally

```bash
# Build and start the target
docker build -f Dockerfile.target -t dast-target:local .
docker run -d --name dast-target -e APP_ENV=test -p 127.0.0.1:5000:5000 dast-target:local

# Run ZAP baseline scan (requires Docker)
docker run --rm \
  -v $(pwd)/zap-reports:/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:5000 -r zap-report.html

# Stop target
docker stop dast-target
```

## Interpreting Results

- `FAIL`: Blocking finding — must be fixed before merging.
- `WARN`: Non-blocking — must be reviewed and triaged.
- `PASS`: Known false positive or out-of-scope — documented in `zap-config/zap-rules.tsv`.

## Noise Reduction

Alert deduplication is handled by ZAP natively (same rule + same URL = one alert).
The `zap-rules.tsv` file documents all rule-level overrides with rationale.
