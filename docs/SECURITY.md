# Security Notes

CloudSentinel is a defensive learning and portfolio project.

- Analysis is static and local; uploaded infrastructure is never executed.
- ZIP extraction rejects path traversal, encrypted members, excessive member counts, expanded sizes, and suspicious compression ratios.
- Uploads are size-limited and removed after the scan.
- Forms that change data use session-based CSRF tokens.
- Security headers include CSP, frame denial, MIME sniffing prevention, a restrictive permissions policy, and `Cache-Control: no-store`.
- Client upload errors are generic; detailed parser failures are retained in server logs.
- Production startup rejects known placeholder session secrets.
- The container build context excludes local environment files, databases, Terraform state/plans, uploads, and generated reports; the runtime uses an unprivileged user.
- `.env`, virtual environments, databases, Terraform state, and plan files are ignored by Git.
- Demo values are placeholders and must never be reused as credentials.

For internet-facing deployment, add authentication and authorization, HTTPS, reverse-proxy request limits, malware scanning for uploads, centralized secrets management, database backups, and production monitoring. Static analysis is not a sandbox or a substitute for reviewing sensitive Terraform plan/state handling.
