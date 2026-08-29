# Security Policy & Vulnerability Reporting

## 🛡️ Supported Versions

We take the security of Jia Framework extremely seriously. The following table outlines which versions are currently receiving security updates:

| Version | Supported          | Security Maintenance Status |
| ------- | ------------------ | --------------------------- |
| 1.x.x   | :white_check_mark: | Active Support              |
| < 1.0.0 | :x:                | Deprecated                  |

---

## 🔒 Reporting a Vulnerability

**Please DO NOT open public GitHub Issues for security vulnerabilities.**

If you discover a security vulnerability, zero-day flaw, memory safety issue, or cryptanalysis concern within Jia (including Gleam OTP modules or Vella Rust native sidecar), please report it responsibly:

### 📧 Contact Channel
- **Email**: `security@jia-framework.org` or `charlegutierrez@users.noreply.github.com`
- **PGP Encryption Key**: Available upon request for encrypted disclosure.

---

## ⏱️ Response & Disclosure SLA

We are committed to responding to security reports promptly:

1. **Initial Response**: Within 24 hours of receipt.
2. **Triage & Assessment**: Within 72 hours, confirming vulnerability validity, severity rating (CVSS v3.1), and impact scope.
3. **Patch Execution**: Critical vulnerabilities will be patched within 7 business days, followed by a point-release bump (`v1.x.x`).
4. **Public Advisory**: Published via GitHub Security Advisories once the fix is verified and deployed.

---

## 🏆 Bug Bounty & Recognition

Reporters of validated security vulnerabilities will:
- Be credited in the release notes and `SECURITY.md` Hall of Fame (unless anonymity is requested).
- Receive priority review on future contributions.

Thank you for helping keep Jia and its ecosystem safe!
