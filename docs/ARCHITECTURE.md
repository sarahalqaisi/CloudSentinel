# CloudSentinel Architecture

```text
Terraform / Plan JSON / ZIP
            |
            v
      Safe local parser
            |
            v
 Normalized cloud resources
            |
            v
  YAML policy registry (35)
            |
            v
 Findings + risk scoring + compliance
            |
   +--------+---------+----------+
   |                  |          |
Dashboard         IAM Graph   Reports
   |                  |   PDF/CSV/JSON/SARIF
   +-------- SQLAlchemy -------+
           SQLite / PostgreSQL
```

## Components

- **FastAPI application:** HTTP routes, OpenAPI documentation, validation, middleware, and report downloads.
- **Parser:** Reads Terraform resource blocks, Terraform JSON, plan/state JSON, and protected ZIP archives without executing Terraform.
- **Policy engine:** Loads strictly validated, versioned YAML metadata and dispatches deterministic Python checks behind a small evaluator protocol for future engines.
- **Scanner:** Persists normalized resources, evaluates policies, calculates risk and security scores, and records audit events.
- **Analytics:** Dashboard charts, compliance calculations, repository maturity score, and IAM relationship graph.
- **Storage:** SQLite by default; PostgreSQL through Docker Compose.
- **Risk model:** Configurable deterministic scoring combines severity, exposure, confidence, blast radius, and exploitability; see [RISK_SCORING.md](RISK_SCORING.md).

## Trust boundaries

CloudSentinel performs static analysis only. It does not execute uploaded Terraform, contact cloud APIs, or require cloud credentials. Uploaded files are deleted after parsing. Real Terraform plans and state files can contain secrets and should be handled as sensitive data.
