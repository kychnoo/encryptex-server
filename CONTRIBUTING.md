# Contributing to Encryptex Server

Thank you for your interest in contributing to **Encryptex Server**! 

Before submitting contributions, please read through the guidelines below to ensure code quality, test stability, and license compliance.

---

## 📜 AGPL-3.0 Compliance

By contributing to this repository, you agree that your contributions will be licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. 

All public API additions, bug fixes, and feature modifications must remain fully open-source.

---

## 🛠️ Pull Request Checklist

Before submitting a Pull Request (PR), ensure your changes pass all local verification steps:

1. **Strict Error Handling Policy:**
   * Do **NOT** use `.expect()` or `.unwrap()` inside application handlers (`src/`).
   * `.expect()` / `.unwrap()` are allowed **only** inside tests (`tests/`).

2. **Database & Migrations:**
   * If you modify database schemas, create a new migration via `sqlx migrate add <name>`.
   * Never modify existing, applied migration files.

3. **Testing:**
   * All tests must pass locally before creating a PR:
     ```bash
     cargo test
     ```
   * Write tests for every new endpoint, authorization edge-case, or bug fix.

4. **Code Formatting:**
   * Format your code using `rustfmt`:
     ```bash
     cargo fmt --all -- --check
     ```
   * Run `clippy` to catch common code smells:
     ```bash
     cargo clippy -- -D warnings
     ```

---

## 🐛 Reporting Issues

If you find a security vulnerability or bug, please open a GitHub Issue detailing:
* Steps to reproduce the issue.
* Expected vs. actual behavior.
* Relevant system/environment details.

For critical security disclosures, please contact the maintainers directly instead of opening a public issue.