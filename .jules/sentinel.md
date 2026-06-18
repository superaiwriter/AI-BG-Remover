## 2026-06-17 - Lockfile Tracking and Minimalist Configuration
**Vulnerability:** Accidental leakage of environment-specific configuration and build artifacts.
**Learning:** While it's critical to ignore environment files (.env*) and secrets, lockfiles (pnpm-lock.yaml, package-lock.json, yarn.lock) should be tracked to ensure reproducible and deterministic builds, which is itself a security and stability requirement. Additionally, keeping .gitignore focused on the project's specific languages/tools helps keep the repository clean and stays within line count constraints.
**Prevention:** Always ensure lockfiles are NOT ignored in .gitignore. Prune generic templates to include only relevant patterns.

## 2026-06-18 - Protecting IDE and Local Environment State
**Vulnerability:** Information leakage through IDE metadata and local history files.
**Learning:** Common IDE directories like `.idea/` and local history trackers like `.history/` often contain developer-specific state, environment paths, and sometimes cached credentials or sensitive snippets. Excluding these is a crucial step in preventing accidental information disclosure as development begins.
**Prevention:** Always include common IDE and environment metadata patterns (e.g., `.idea/`, `.history/`, `.direnv/`) in the project's `.gitignore` from the very first commit.
