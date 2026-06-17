## 2026-06-17 - Lockfile Tracking and Minimalist Configuration
**Vulnerability:** Accidental leakage of environment-specific configuration and build artifacts.
**Learning:** While it's critical to ignore environment files (.env*) and secrets, lockfiles (pnpm-lock.yaml, package-lock.json, yarn.lock) should be tracked to ensure reproducible and deterministic builds, which is itself a security and stability requirement. Additionally, keeping .gitignore focused on the project's specific languages/tools helps keep the repository clean and stays within line count constraints.
**Prevention:** Always ensure lockfiles are NOT ignored in .gitignore. Prune generic templates to include only relevant patterns.
