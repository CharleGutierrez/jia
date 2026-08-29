# 🏗️ Jia (家) System Architecture

Jia is an **AI-Native Cyber Defense System** designed around a high-performance **Dual-Engine Sidecar** paradigm. It bridges the fault tolerance and concurrency of Erlang/BEAM (via **Gleam**) with the raw memory safety, low latency, and cryptographic execution of **Rust (Vella Framework)**.

---

## 📐 Dual-Engine Core Design

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │                BEAM / Erlang OTP Runtime               │
                                  │                                                        │
┌───────────────────────────┐     │  ┌──────────────────────────────────────────────────┐  │
│ Security Log & Telemetry  │ ──> │  │ Gleam OTP Agent Orchestrator                     │  │
│ Input Streams             │     │  │  - Supervision Trees (One-For-One / Rest-For-One) │  │
└───────────────────────────┘     │  │  - Actor-Based Threat Stream Parsing             │  │
                                  │  │  - Adaptive Circuit Breaker & Rate Limiter       │  │
                                  │  │  - Gossip Threat Sync Across BEAM Nodes          │  │
                                  │  └────────────────────────┬─────────────────────────┘  │
                                  └───────────────────────────┼────────────────────────────┘
                                                              │
                                                     HTTP / JSON REST API
                                                              │
                                  ┌───────────────────────────▼────────────────────────────┐
                                  │               Rust Vella Engine Sidecar                │
                                  │  - Vella AI Anomaly Classifier & Zero-Day Engine      │
                                  │  - eBPF Kernel Syscall Trapper (`ebpf_trapper.rs`)    │
                                  │  - Post-Quantum Crypto Engine (ML-KEM-768 & ML-DSA-65) │
                                  │  - MITRE ATT&CK & CVE Vector RAG Engine               │
                                  │  - Dynamic Rhai SOAR Playbook Evaluator               │
                                  │  - Cryptographic WORM Audit Trail Ledger              │
                                  │  - Realtime WebSocket Telemetry Stream (`/ws/telemetry`)│
                                  └────────────────────────────────────────────────────────┘
```

---

## 1. Erlang / BEAM Concurrency Layer (`src/jia/`)

The Gleam layer runs on the Erlang BEAM virtual machine. BEAM process isolation guarantees that even if a malformed payload triggers a panic in an individual event handler process, Erlang's OTP Supervision tree catches the failure and restarts *only* that isolated process in under 1 microsecond.

### Key Components:
* **`actor.gleam`**: Manages event queue actors, receiving raw HTTP/network event tuples and dispatching classification jobs.
* **`cluster.gleam`**: Gossip protocol implementation allowing Jia nodes across multi-cloud regions (US-East, EU-Central, AP-East) to sync IP quarantine blacklists and threat signatures instantaneously.
* **`circuit_breaker.gleam`**: Sliding-window rate limiter (300 req/sec IP limit) and HTTP body size limiter (2MB) protecting downstream services from resource exhaustion.
* **`firewall.gleam`**: PII sanitization (redacting SSNs, credit cards, AWS keys) and AI prompt injection detection (DAN mode, system prompt override defense).
* **`honeypot.gleam`**: Traps scanning bots touching decoy routes (`/config/env`, `/api/v1/admin/db_backup`, `/root/ssh_keys`).
* **`red_team.gleam`**: Self-simulating adversarial Purple Team test suite that fires simulated attacks against Jia to verify defense readiness.

---

## 2. Rust Vella Engine Sidecar Layer (`native/src/`)

The Rust sidecar provides raw performance, direct operating system interaction, vector mathematics, and cryptographic guarantees.

### Key Components:
* **`ebpf_trapper.rs`**: Intercepts unauthorized process syscalls (`execve`, `ptrace`, `bpf_cmd`) and checks process RSS memory footprints to kill memory-injection attacks at the kernel level.
* **`pqc.rs`**: Implements Post-Quantum Cryptography compliant with NIST FIPS 203 (ML-KEM-768 key encapsulation) and FIPS 204 (ML-DSA-65 digital signatures) over SHAKE-256 KMAC.
* **`rag_agent.rs`**: Uses TF-IDF cosine similarity vector search over embedded CVE databases (Log4Shell, SQLi, ProxyLogon, Spring4Shell) to classify attack vectors.
* **`rag_poison_guard.rs`**: Sanitizes RAG context retrieved from vector stores to strip hidden zero-width unicode attacks (`\u{200B}`) and prompt override payloads.
* **`playbook.rs`**: Evaluates declarative `.rhai` automation scripts at runtime for dynamic SOAR response without recompilation.
* **`dashboard.rs`**: Renders an embedded glassmorphism HTML5 web UI served directly at `/dashboard`.

---

## 3. Zero-Trust WORM Audit Trail

Jia implements an immutable **Write-Once-Read-Many (WORM)** cryptographic audit log chain:

$$\text{Hash}_{n} = \text{SHA256}(\text{ID} \parallel \text{Timestamp} \parallel \text{Target} \parallel \text{Reason} \parallel \text{Action} \parallel \text{Hash}_{n-1})$$

Every quarantine action, IP block, or configuration change is signed with post-quantum ML-DSA-65 digital signatures, creating an unalterable forensic record for enterprise compliance (SOC2, HIPAA, ISO 27001, PCI-DSS).
