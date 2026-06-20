## 2026-06-17 - Lockfile Tracking vs. Secret Leakage
**Vulnerability:** Information leakage through environment files and build artifacts.
**Learning:** Lockfiles (e.g., `pnpm-lock.yaml`) must be tracked for deterministic builds despite ignoring other environment-specific files. Focused `.gitignore` prevents secret leakage while maintaining build integrity.
**Prevention:** Explicitly exclude `.env*` and IDE metadata like `.history/` which can cache sensitive snippets.
