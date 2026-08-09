# Sentinel Security Journal

## 2026-07-12 - Establishing Security Baseline

**Vulnerability:** Lack of security hygiene in a new project.
**Learning:** New projects lack basic protections like .gitignore and SECURITY.md.
**Prevention:** Establish a baseline early with essential patterns and a reporting policy.

## 2026-07-15 - NaN Comparison Bypass in Input Validation

**Vulnerability:** In JavaScript, comparing NaN against any value (e.g. `NaN <= 0` or `NaN > MAX`) always evaluates to false, allowing NaN size inputs to completely bypass range/boundary check validations.
**Learning:** Simple range checks are insufficient for validating untrusted numeric input in dynamically typed/implicitly cast environments unless type and integer safety checks are explicitly enforced.
**Prevention:** Always use `Number.isInteger(size)` or `typeof size === 'number' && !Number.isNaN(size)` before performing arithmetic boundary comparisons.

## 2026-07-15 - Double-Extension Validation Bypass via Whitespace

**Vulnerability:** Dangerous intermediate double-extensions could bypass list-based checks if they contained leading or trailing whitespace (such as `image.php .png`), because `.split('.')` splits the extensions verbatim and exact matching (e.g., `.has()`) is bypassed.
**Learning:** Filename components can be parsed loosely by web servers/OS while strict security checks fail to trim whitespace before matching against list boundaries.
**Prevention:** Always trim and normalize filename components (such as using `.trim()`) before evaluating them against restricted lists of dangerous intermediate extensions.
