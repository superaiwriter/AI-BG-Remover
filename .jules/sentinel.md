# Sentinel Security Journal

This journal records critical security learnings and vulnerability patterns found in this codebase.

## 2026-07-12 - Establishing Security Baseline
**Vulnerability:** Lack of security hygiene and baseline configurations in a new project.
**Learning:** New projects often lack basic security protections like .gitignore, SECURITY.md, and .env.example, which can lead to accidental secret leakage and unclear vulnerability reporting processes.
**Prevention:** Always establish a security baseline early in the project lifecycle, including a comprehensive .gitignore, a clear security policy, and templates for environment variables.
