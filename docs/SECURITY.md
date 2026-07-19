# Security Notes

CloudSentinel is a defensive learning and portfolio project.

- Analysis is static and local; uploaded infrastructure is never executed.
- ZIP extraction rejects path traversal and oversized members.
- Uploads are size-limited and removed after the scan.
- Forms that change data use session-based CSRF tokens.
- Security headers include CSP, frame denial, MIME sniffing prevention, and a restrictive permissions policy.
- `.env`, virtual environments, databases, Terraform state, and plan files are ignored by Git.
- Demo values are placeholders and must never be reused as credentials.

For internet-facing deployment, add authentication, HTTPS, reverse-proxy request limits, malware scanning for uploads, centralized secrets management, database backups, and production monitoring.
