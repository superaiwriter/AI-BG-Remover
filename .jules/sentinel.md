## 2026-06-18 - Protecting IDE and Local Environment State
**Vulnerability:** Information leakage through IDE metadata and local history files.
**Learning:** Common IDE directories like `.idea/` and local history trackers like `.history/` often contain developer-specific state, environment paths, and sometimes cached credentials or sensitive snippets. Excluding these is a crucial step in preventing accidental information disclosure as development begins.
**Prevention:** Always include common IDE and environment metadata patterns (e.g., `.idea/`, `.history/`, `.direnv/`) in the project's `.gitignore` from the very first commit.
