# CloudSentinel v1.0 Validation

## Clean installation

A clean copy of the repository was installed with `setup_kali.sh` using Python 3.13. The installer successfully:

- Created a new `.venv`.
- Installed all pinned direct dependencies.
- Created `.env` with a generated session secret.
- Initialized SQLite.
- Imported all policy files.
- Loaded the safe demo environment.

## Automated tests

```text
12 passed
```

Coverage includes:

1. Terraform HCL parsing and nested blocks.
2. Terraform plan JSON parsing.
3. Safe ZIP extraction.
4. ZIP path-traversal rejection.
5. Validation of all 35 YAML policies.
6. Administrative-port exposure detection.
7. Lambda secret-name detection.
8. End-to-end insecure infrastructure scan.
9. PDF, CSV, and JSON report generation.
10. Scan comparison and posture improvement.
11. Dashboard, API, pages, and reports smoke test.
12. CSRF-protected Terraform upload flow and repository score calculation.

## Demo results

```text
Policies:               35
Scans:                    1
Normalized resources:   21
Findings:                23
Repository assessments:  1
Security score:          75.5 (Grade C)
```

## Database integrity

```text
PRAGMA integrity_check: ok
```

## Runtime smoke checks

```text
GET /:           200
GET /api/health: 200
Service:         CloudSentinel
Version:         1.0.0
```

## Release hygiene

The release archive is checked to ensure it does not contain:

- `.env`
- `.venv`
- SQLite databases
- Terraform state or plan artifacts
- Python cache files
- Test cache
- Actual cloud credentials or API tokens
- `debug=True`

The project contains only synthetic demonstration infrastructure. CloudSentinel performs local static analysis and never executes uploaded Terraform.
