## 2026-06-26 - Establishing Security Baseline and Hygiene
**Vulnerability:** Potential information leakage through environment files and IDE metadata; lack of clear vulnerability reporting channel for security researchers.
**Learning:** Initializing a repository with fundamental security hygiene prevents common early-stage vulnerabilities. A comprehensive `.gitignore` protects against accidental secret commits, while `SECURITY.md` ensures that external security researchers have a clear path to report findings responsibly.
**Prevention:** Always establish `.gitignore`, `SECURITY.md`, and `.env.example` as a "security baseline" at the project's inception to ensure defense in depth and fail-secure defaults.
