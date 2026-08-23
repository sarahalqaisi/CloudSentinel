# DevSecOps and SARIF integration

CloudSentinel can scan Terraform in CI and emit SARIF 2.1.0 for GitHub Code Scanning.

```bash
python scripts/scan_iac.py infrastructure/ --sarif reports/cloudsentinel.sarif
```

Use `--fail-on high` or `--fail-on critical` when a repository intentionally enforces a severity gate. The default is reporting-only so adoption does not unexpectedly block builds.

The `CloudSentinel IaC security` workflow scans the repository's synthetic sample Terraform, retains SARIF as a workflow artifact, and uploads it to Code Scanning on trusted pull requests and pushes. SARIF upload requires GitHub Code Scanning to be enabled and the workflow to receive `security-events: write`; forked pull requests skip upload. If Code Scanning is disabled or unavailable, the upload step is non-blocking and the SARIF artifact remains available. The job otherwise uses read-only repository access.

The report download endpoint is:

```text
GET /reports/scans/{scan_id}.sarif
```

SARIF results contain stable finding fingerprints, policy rule IDs, severity levels, risk scores, remediation help, and source locations when the parser can resolve them.
