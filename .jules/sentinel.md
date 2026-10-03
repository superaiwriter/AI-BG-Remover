# Sentinel Security Journal

## 2026-06-28 - Baseline Security & Secret Exclusion
**Vulnerability:** Absence of `.gitignore` and security policy could lead to accidental commitment of API keys, `.env` files, or local IDE secrets.
**Learning:** Establishing a security baseline early prevents secret exposure and clarifies responsible disclosure procedures.
**Prevention:** Always ensure `.gitignore` blocks sensitive file patterns (`.env*`, `*.key`, `*.pem`) and maintain a `SECURITY.md`.
