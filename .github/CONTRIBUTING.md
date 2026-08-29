# Contributing to Jia (家) Framework

Thank you for your interest in contributing to **Jia Framework**, the next-generation AI-native cyber defense system combining **Gleam (BEAM OTP)** and **Rust (Vella Engine)**.

We welcome contributions from developers, security researchers, and open-source enthusiasts of all skill levels!

---

## 📋 Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Project Architecture Overview](#project-architecture-overview)
- [Running Tests & Quality Checks](#running-tests--quality-checks)
- [Pull Request Process](#pull-request-process)
- [Style Guides & Conventions](#style-guides--conventions)

---

## 📜 Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to security@jia-framework.org.

---

## 🛠️ How Can I Contribute?

### 1. Reporting Bugs
- Check existing [GitHub Issues](https://github.com/CharleGutierrez/jia/issues) to avoid duplicates.
- Use our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml) and include:
  - Operating system & architecture
  - Gleam (`gleam --version`), Erlang/OTP (`erl -version`), and Rust (`rustc --version`) versions
  - Steps to reproduce & exact log outputs

### 2. Suggesting Features & Security Modules
- Open a [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) describing the proposed capability (e.g., new eBPF trapper policy, post-quantum algorithm, SIEM connector, or Rhai security playbook).

### 3. Writing Code
- Pick an unassigned issue labeled `good first issue` or `help wanted`.
- Create a feature branch: `git checkout -b feat/your-feature-name` or `fix/your-bug-fix`.

---

## 💻 Development Setup

### Prerequisites
- **Gleam Compiler**: `>= 1.18.0` ([install instructions](https://gleam.run/getting-started/))
- **Erlang/OTP**: `>= 26.0`
- **Rust Toolchain**: `>= 1.75.0` (`rustup update stable`)
- **Docker & Docker Compose** *(optional, for containerized testing)*

### Local Setup Steps
```bash
# 1. Clone the repository
git clone https://github.com/CharleGutierrez/jia.git
cd jia

# 2. Download Gleam dependencies
gleam deps download

# 3. Build & test Gleam OTP agent
gleam check
gleam test

# 4. Build & test Rust Vella Native Engine
cd native
cargo check
cargo test
cd ..
```

---

## 🏗️ Project Architecture Overview

Jia follows a hybrid **Dual-Engine Sidecar** architecture:

```
┌───────────────────────────────────────────────┐
│              Erlang BEAM Runtime              │
│  Gleam Agent Orchestrator (OTP Supervision)  │
└───────────────────────┬───────────────────────┘
                        │ HTTP / JSON
┌───────────────────────▼───────────────────────┐
│            Rust Vella Engine (Axum)           │
│  - eBPF Trapper   - Post-Quantum Crypto       │
│  - Rhai Playbooks - AI RAG Vector Engine      │
└───────────────────────────────────────────────┘
```

- `src/jia/`: Gleam OTP actors, risk classification, circuit breakers, honeypots, and purple team simulator.
- `native/src/`: Rust Vella sidecar server (Axum REST API, WebSocket streams, eBPF syscall trapper, ML-KEM/ML-DSA PQC).
- `test/`: Property-based and unit tests for Gleam logic.

---

## 🧪 Running Tests & Quality Checks

Before submitting a PR, ensure all quality gates pass cleanly:

```bash
# 1. Run Gleam Formatter & Tests
gleam format --check src test
gleam test

# 2. Run Rust Formatter, Clippy & Tests
cd native
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cd ..
```

---

## 🔀 Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure your changes follow existing code conventions and pass all tests.
3. Write property tests or unit tests for any new features or bug fixes.
4. Update relevant documentation (`README.md`, `docs/`, or docstrings).
5. Submit your PR using the provided [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md).
6. Address any feedback from maintainers promptly.

---

## 📐 Style Guides & Conventions

### Gleam Conventions
- Standard 2-space indentation.
- Run `gleam format` before committing.
- Use explicit type annotations on public functions.
- Prefer pattern matching over deep `case` nesting where possible.

### Rust Conventions
- Use `cargo fmt` formatting.
- Minimize `.unwrap()` calls in production code paths; return typed `Result<T, E>` errors.
- Ensure all public functions are documented with standard `///` docstrings.

---

## 💖 Community & Recognition

All contributors will be featured in our `CONTRIBUTORS.md` file and listed on the release notes. Thank you for making Jia safer for everyone!
