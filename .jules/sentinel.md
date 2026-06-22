## 2026-06-22 - Establishing Security Baseline and Hygiene
**Vulnerability:** Information leakage through environment files and IDE metadata; lack of clear vulnerability reporting channel.
**Learning:** Initializing a repository with security hygiene in mind prevents common early-stage vulnerabilities. A comprehensive `.gitignore` protects against accidental secret commits, while `SECURITY.md` ensures that external security researchers have a clear path to report findings without public disclosure.
**Prevention:** Always establish `.gitignore`, `SECURITY.md`, and `.env.example` as a "security baseline" at the project's inception.
