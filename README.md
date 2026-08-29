<div align="center">
  <img src="assets/jia_logo.jpg" alt="Jia Logo" width="320" />
  <h1>🛡️ Jia (家) Framework</h1>
  <p><strong>The Next-Generation AI-Native Cyber Defense System.</strong></p>
  <p>Bridging Gleam for Erlang/BEAM OTP Concurrency with Vella's Memory-Safe Rust SecOps Engine.</p>

  [![Build Passing](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](https://github.com/CharleGutierrez/jia/actions)
  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Gleam: 1.18+](https://img.shields.io/badge/Gleam-1.18%2B-ffaff3.svg)](https://gleam.run)
  [![Erlang/OTP: 26+](https://img.shields.io/badge/Erlang%2FOTP-BEAM-red.svg)](https://www.erlang.org/)
  [![Rust: 1.75+](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
  [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)
</div>

---

## 📌 Table of Contents
- [What is Jia?](#-what-is-jia)
- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
- [Quick Start](#-quick-start)
- [Interactive Dashboard](#-interactive-dashboard)
- [Tutorials & Setup Guides](#-tutorials--setup-guides)
  - [Simple Standalone Setup](#1-simple-standalone-setup)
  - [Enterprise Multi-Node Cluster Setup](#2-enterprise-multi-node-cluster-setup)
  - [AI Prompt Injection & PII Firewall Proxy](#3-ai-prompt-injection--pii-firewall-proxy)
  - [eBPF Kernel Syscall Inspection](#4-ebpf-kernel-syscall-inspection)
  - [Post-Quantum Cryptography (ML-KEM & ML-DSA)](#5-post-quantum-cryptography-ml-kem--ml-dsa)
  - [Enterprise SIEM Integration (Datadog / Splunk / Elastic)](#6-enterprise-siem-integration-datadog--splunk--elastic)
- [API Reference](#-api-reference)
- [Verification & Tests](#-verification--tests)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🌐 What is Jia?

**Jia (家)** is an advanced, production-ready **AI Cyber Security & Threat Defense Platform**. It combines the world-class fault tolerance and process isolation of the **Erlang/BEAM Virtual Machine** (via **Gleam**) with the raw computational performance, AI decision engines, and post-quantum cryptographic safety of the **Vella Rust Framework**.

Jia monitors system logs, API calls, network streams, kernel system calls, and AI prompt contexts in real-time, executing automated Zero-Trust containment, threat intelligence RAG searches, steganography scrubbing, and time-travel disaster rollbacks without ever bringing down your application.

---

## 🏗️ System Architecture

```
                               ┌─────────────────────────────────────────┐
                               │       BEAM / Erlang Runtime             │
                               │                                         │
┌──────────────────┐           │  ┌───────────────────────────────────┐  │
│ Security Logs &  │ ────────> │  │ Gleam Agent Orchestrator (OTP)    │  │
│ Telemetry Feed   │           │  │  - Supervision Trees              │  │
└──────────────────┘           │  │  - Concurrent Threat Classification│  │
                               │  │  - Anomaly Scoring & Rules Engine │  │
                               │  └─────────────────┬─────────────────┘  │
                               └────────────────────┼────────────────────┘
                                                    │
                                           HTTP / JSON REST API
                                                    │
                               ┌────────────────────▼────────────────────┐
                               │ Vella Engine Sidecar (`jia_native`)    │
                               │  - Vella AI Decision Engine             │
                               │  - eBPF Kernel Process Trapper          │
                               │  - Post-Quantum Crypto (ML-KEM/ML-DSA)  │
                               │  - MITRE ATT&CK & CVE Vector RAG        │
                               │  - Dynamic Rhai SOAR Playbooks          │
                               │  - Immutable WORM Audit Chain           │
                               │  - Realtime WebSocket Telemetry Stream  │
                               └─────────────────────────────────────────┘
```

---

## ⚡ Key Features

* **🤖 Erlang OTP Actor Supervision (`jia/actor.gleam`):** Spawns lightweight BEAM actor processes for concurrent security event streams. If an individual event payload is malformed or corrupted, Erlang restarts *only* that process.
* **🛡️ eBPF Kernel System Call Trapper (`ebpf_trapper.rs`):** Monitors low-level system calls (`execve`, `ptrace`, `bpf_cmd`) via `/proc` and process RSS memory tracking, executing POSIX signals (`SIGKILL`/`SIGTERM`) to kill memory injection & rootkit processes at the CPU level.
* **⚛️ Post-Quantum Cryptography Engine (`pqc.rs`):** Implements NIST ML-KEM-768 key encapsulation and ML-DSA-65 digital signatures over Write-Once-Read-Many (WORM) audit logs using SHAKE-256 KMAC.
* **🧠 MITRE ATT&CK & CVE Vector RAG Search (`rag_agent.rs`):** Calculates TF-IDF cosine similarity vectors to match attack payloads against CVE databases (Log4Shell, MOVEit SQLi, ProxyLogon, Spring4Shell).
* **📜 Dynamic Rhai Security Playbooks (`playbook.rs`):** Evaluates declarative `.rhai` playbooks (`quarantine.rhai`, `revoke_jwt.rhai`) dynamically at runtime without re-compiling the daemon.
* **🪤 AI Decoy & Honeypot Trap Network (`honeypot.rs`):** Serves decoy HTTP endpoints (`/api/v1/admin/db_backup`, `/config/env`, `/root/ssh_keys`) to trap scanning bots in a sandbox, extract payload signatures, and block IPs cluster-wide.
* **⚡ Adaptive DDoS & Memory Circuit Breaker (`circuit_breaker.rs`):** Axum sliding-window rate-limiter (300 req/sec IP limit) and body size limit (2MB) dropping malicious request floods at the edge with zero memory allocation.
* **⌛ 1-Click Time-Travel Disaster Recovery (`rollback.rs`):** Restores database snapshots and WORM audit log state back to exact millisecond timestamps.
* **📡 Enterprise SIEM Exporter (`siem_exporter.rs`):** Formats telemetry events into standard ArcSight CEF (Common Event Format) and RFC 5424 Syslog format for Datadog, Splunk, Elastic, and OpenTelemetry.
* **🔑 FIDO2 / WebAuthn Hardware Authenticator (`webauthn.rs`):** Implements WebAuthn protocol challenge-response parsing with constant-time nonces and authenticator presence (`UP`/`UV`) validation.

---

## 🚀 Quick Start

### Prerequisites
- **Gleam** (`>= 1.18.0`)
- **Rust & Cargo** (`>= 1.75.0`)
- **Erlang/OTP** (`>= 26.0`)

### 1-Line Execution
Run the unified startup script:
```bash
./start_jia.sh
```

### Manual Execution

```bash
# 1. Run Gleam Unit & Property Tests
gleam test

# 2. Run Gleam OTP Agent Main Daemon
gleam run

# 3. Run Vella Rust Engine Sidecar (Port 9090)
cd native
cargo run --release
```

---

## 📊 Interactive Dashboard

Jia includes an embedded HTML5/CSS3 glassmorphism **Cyber Command Dashboard** served directly from the native engine:

```text
http://127.0.0.1:9090/dashboard
```

Features:
- **Realtime Visual Waterfall:** Live threat feed stream powered by WebSockets.
- **Node Cluster Telemetry:** Active Erlang BEAM node status and CPU/memory metrics.
- **WORM Audit Trail Inspector:** Searchable, cryptographically signed audit log ledger.
- **Interactive Security Lab:** Live widgets for RAG CVE searches, PII scrubbing, Rhai playbook execution, and ZK proof generation.

---

## 📚 Tutorials & Setup Guides

### 1. Simple Standalone Setup
In a single-server setup, Jia runs alongside your main backend application as a sidecar:

```rust
// rust_app.rs
use jia_client::JiaSecurityClient;

#[tokio::main]
async fn main() {
    let jia = JiaSecurityClient::connect("http://127.0.0.1:9090");
    
    // Inspect request before processing
    let verdict = jia.analyze_event(req_payload, req_ip).await;
    if verdict.action == "quarantine" {
        return HttpResponse::Forbidden().body("Access Blocked by Jia Cyber Defense");
    }
}
```

---

### 2. Enterprise Multi-Node Cluster Setup
In a multi-region cloud setup, Gleam actor nodes form an Erlang cluster to gossip threat intelligence across US-East, EU-Central, and AP-East in microseconds:

```gleam
// src/jia.gleam
import jia/cluster.{RegisterNode, GossipSync, GetClusterStatus}

pub fn start_enterprise_cluster() {
  let assert Ok(cluster_actor) = cluster.start()
  
  // Register regional node
  let reply = process.new_subject()
  process.send(cluster_actor, RegisterNode("node_eu_1@cloud", "10.100.0.12", "EDGE_NODE", reply))
}
```

---

### 3. AI Prompt Injection & PII Firewall Proxy
Intercept LLM prompt requests and sanitize output completions:

```gleam
import jia/firewall

pub fn handle_llm_request(user_prompt: String) {
  // 1. Scrub PII
  let pii_result = firewall.scrub_pii(user_prompt)
  
  // 2. Check Prompt Safety Guardrails
  let guard_result = firewall.check_prompt_guardrails(pii_result.scrubbed_text)
  
  case guard_result.is_safe {
    True -> forward_to_gemini(pii_result.scrubbed_text)
    False -> reject_with_security_warning()
  }
}
```

---

### 4. eBPF Kernel Syscall Inspection
Query kernel process telemetry to block ptrace injections and unprivileged eBPF bytecode loads:

```rust
use jia_native::ebpf_trapper::EbpfTrapper;

// Inspect low-level system calls
let verdict = EbpfTrapper::inspect_syscall_with_target("ptrace", 1042, 1000, Some("/proc/target"));
if !verdict.allowed {
    println!("🚨 [eBPF Kill] Terminated unauthorized ptrace call from PID 1042");
}
```

---

### 5. Post-Quantum Cryptography (ML-KEM & ML-DSA)
Sign WORM audit log entries using quantum-resistant ML-DSA-65 signatures:

```rust
use jia_native::pqc::PqcEngine;

let worm_log = "AUDIT_ENTRY_#429: USER_QUARANTINE_IP_10.0.0.45";
let signature = PqcEngine::dilithium_sign_worm_log(worm_log);

assert!(PqcEngine::dilithium_verify_worm_log(worm_log, &signature.signature_hex, &signature.public_key_hex));
```

---

### 6. Enterprise SIEM Integration (Datadog / Splunk / Elastic)
Stream logs into SIEM format:

```bash
# Export ArcSight CEF format
curl "http://127.0.0.1:9090/api/v1/siem/export?format=cef"

# Export RFC 5424 Syslog format
curl "http://127.0.0.1:9090/api/v1/siem/export?format=syslog"
```

---

## 🔌 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Engine health status, uptime, WORM entry count |
| `POST` | `/api/v1/analyze_event` | Perform AI risk analysis & prompt injection detection |
| `POST` | `/api/v1/quarantine` | Execute target quarantine & generate SHA-256 WORM entry |
| `POST` | `/api/v1/rag/search` | Search MITRE ATT&CK & CVE Vector Database |
| `POST` | `/api/v1/firewall/scrub` | Scrub PII (SSN, credit card, API key) & check prompt safety |
| `POST` | `/api/v1/playbook/execute` | Run dynamic Rhai security playbook (`quarantine.rhai`) |
| `POST | `/api/v1/zk/export` | Export privacy-preserving Zero-Knowledge threat proof |
| `POST` | `/api/v1/ebpf/inspect` | Inspect eBPF kernel system call for rootkit/ptrace anomaly |
| `POST` | `/api/v1/pqc/sign` | Sign log payload with ML-DSA (Dilithium) quantum signature |
| `POST` | `/api/v1/rag/guard` | Neutralize steganography & prompt overrides in RAG chunks |
| `POST` | `/api/v1/self_heal/patch` | Generate AI AST patch diff & unit tests for vulnerability |
| `POST` | `/api/v1/red_team/simulate` | Execute multi-agent purple team attack simulation |
| `POST` | `/api/v1/rollback` | Perform 1-click time-travel state rollback |
| `POST` | `/api/v1/webauthn/challenge` | Generate FIDO2 / WebAuthn hardware security challenge |
| `POST` | `/api/v1/webauthn/verify` | Verify FIDO2 authenticator signature & presence flags |
| `GET` | `/api/v1/siem/export` | Export SIEM logs in CEF / Syslog format |
| `GET` | `/dashboard` | Serve interactive Glassmorphism Cyber Command Dashboard |
| `WS` | `/ws/telemetry` | Real-time WebSocket threat event stream |

---

## 🧪 Verification & Tests

Run all unit, integration, property boundary, and STRIDE threat verification tests:

```bash
# Gleam OTP Test Suite (13 tests)
gleam test

# Rust Native Test Suite (6 tests)
cd native && cargo test
```

All 19 test targets pass with **0 failures**.

---

## 🤝 Contributing

PRs are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on code style, Gleam OTP actor guidelines, and Rust safety patterns.

1. Fork the Repository
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
