---
marp: true
theme: default
paginate: true
backgroundColor: #0a0e27
color: #e8eaf6
style: |
  section {
    font-family: 'Segoe UI', 'Inter', sans-serif;
    background-color: #0a0e27;
    color: #e8eaf6;
  }
  h1 {
    color: #64b5f6;
    font-size: 2.2em;
    border-bottom: 2px solid #1a237e;
    padding-bottom: 8px;
  }
  h2 {
    color: #90caf9;
    font-size: 1.6em;
  }
  h3 {
    color: #ffd54f;
    font-size: 1.2em;
  }
  strong {
    color: #ffd54f;
  }
  em {
    color: #80cbc4;
  }
  table {
    font-size: 0.72em;
    border-collapse: collapse;
    width: 100%;
    border: 1px solid #3949ab;
    border-radius: 6px;
    overflow: hidden;
  }
  th {
    background-color: #1a237e;
    color: #ffd54f;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 2px solid #3949ab;
    font-weight: 700;
    letter-spacing: 0.02em;
  }
  td {
    background-color: #111638;
    color: #e8eaf6;
    border-bottom: 1px solid #283593;
    border-right: 1px solid #1a237e;
    padding: 8px 14px;
  }
  tr:nth-child(even) td {
    background-color: #161b45;
  }
  tr:hover td {
    background-color: #1e2761;
  }
  td:last-child {
    border-right: none;
  }
  code {
    background-color: #1a1e3a;
    color: #80cbc4;
    padding: 2px 6px;
    border-radius: 4px;
  }
  blockquote {
    border-left: 4px solid #ffd54f;
    background-color: rgba(255, 213, 79, 0.08);
    padding: 12px 20px;
    margin: 16px 0;
    font-size: 0.9em;
  }
  section.title {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
  }
  section.title h1 {
    font-size: 2.8em;
    border-bottom: none;
    margin-bottom: 0;
  }
  section.title h2 {
    font-size: 1.4em;
    color: #ffd54f;
    font-weight: 400;
  }
  section.title p {
    font-size: 0.95em;
    color: #90a4ae;
  }
  .highlight-box {
    background: linear-gradient(135deg, rgba(26,35,126,0.5), rgba(13,71,161,0.3));
    border: 1px solid #1a237e;
    border-radius: 12px;
    padding: 16px 20px;
    margin: 12px 0;
  }
  footer {
    color: #546e7a;
    font-size: 0.65em;
  }
  section::after {
    color: #546e7a;
    font-size: 0.7em;
  }
---

<!-- _class: title -->
<!-- _paginate: skip -->

# 🛡️ Jia (家) Framework

## AI-Native Cyber Defense for the Philippine Judiciary

Protecting the Digital Foundations of Justice
*Supreme Court • Court of Appeals • RTC • MeTC • MTC • MCTC*

---

# The Challenge

## Philippine Courts Are Under Digital Siege

The judiciary's digital transformation — eCourt, eFiling, virtual hearings — has created an **unprecedented attack surface**.

### Courts are uniquely high-value targets:

- 📁 **Sealed case records** — criminal, family, CICL, witness protection
- 🪪 **Sensitive PII** — litigants, minors, abuse victims, informants
- ⚖️ **Judicial integrity** — orders, decisions, deliberations must be tamper-proof
- 💰 **Financial records** — bail, fines, estate proceedings
- 🔗 **Evidence chains** — digital evidence must remain forensically intact

> A cyber breach in the judiciary doesn't just leak data — it **compromises the integrity of justice itself**.

---

# The Threat Landscape

## What Philippine Courts Face Today

| Threat Vector | Real-World Risk |
|---|---|
| **SQL Injection** | Attacker modifies case records directly in the eCourt database |
| **Credential Theft** | Stolen judge/clerk passwords → fraudulent court orders |
| **Ransomware** | Court operations halted; sealed records held hostage |
| **Insider Threats** | Unauthorized access to sealed family/CICL records |
| **Malicious eFiling** | Webshells disguised as court document uploads |
| **DDoS Attacks** | Filing portals disrupted during critical deadlines |
| **Quantum Harvest** | Encrypted records captured today, decrypted by future quantum computers |

### The cost of inaction:
**Loss of public trust in the judicial system**

---

# Introducing Jia (家)

## The Next-Generation AI Cyber Defense Platform

**Jia (家)** — meaning *"home"* in Chinese — protects your digital house.

### A dual-engine defense system purpose-built for critical infrastructure:

| Engine | Technology | Role |
|---|---|---|
| **OTP Orchestrator** | Gleam (Erlang/BEAM VM) | Fault-tolerant supervision, clustering, zero-downtime recovery |
| **Vella SecOps Engine** | Rust (Axum) | AI threat detection, kernel inspection, post-quantum cryptography |

### Key differentiators:
- ⚡ **148,500 requests/sec** — 6.7× faster than legacy WAFs
- 🛡️ **1.18ms P99 latency** — imperceptible to court users
- 💾 **24MB memory** — runs on any court hardware
- 🔓 **Open source (MIT)** — full judiciary control, zero vendor lock-in

---

# Performance Advantage

## Jia vs. Legacy Security Solutions

| Metric | 🛡️ **Jia** | Legacy WAF | Python/JS Proxy |
|---|---|---|---|
| **P99 Latency** | **1.18 ms** | 18.40 ms | 45.20 ms |
| **Throughput** | **148,500 req/s** | 22,100 req/s | 6,400 req/s |
| **Crash Recovery** | **< 0.001 ms** | 120 ms | 850 ms |
| **Memory** | **24 MB** | 180 MB | 310 MB |
| **PQC Signing** | **0.34 ms** | ❌ N/A | ❌ N/A |

> Jia processes an eFiling submission's security check in **under 2 milliseconds** — lawyers and clerks experience zero delay.

### Why this matters for courts:
- Zero perceived slowdown for eCourt users
- Handles peak filing deadline traffic without degradation
- Runs on existing municipal court hardware

---

# Defense in Depth

## The 4-Stage Security Pipeline

Every request passes through **four independent defense layers** before reaching court systems:

### Stage 1: YARA Signature Scanning
Detects known malware — shellcode, PHP webshells, SQL injection exfiltration

### Stage 2: AI Firewall & PII Guard
Regex-based PII redaction + LLM-as-a-Judge prompt safety classification

### Stage 3: AI Risk Assessment Engine
CyberCommand zero-day heuristics and pattern anomaly scoring

### Stage 4: Shannon Entropy Analysis
Detects packed/obfuscated malware payloads via information entropy

> **Fail-Closed Design:** If any layer encounters an error, the request is **blocked** — not silently passed through.

---

# PII Protection & Data Privacy

## Automatic Compliance with RA 10173

Jia's PII scrubbing engine **automatically detects and redacts** sensitive information:

| Data Type | Example | Action |
|---|---|---|
| Social Security / Government IDs | `12-3456789-0` | → `[REDACTED_PII]` |
| Credit Card Numbers | `4111-1111-1111-1111` | → `[REDACTED_PII]` |
| API Keys & Secrets | `AKIA...`, `ghp_...`, `sk_...` | → `[REDACTED_PII]` |
| Email Addresses | `judge@court.gov.ph` | → `[REDACTED_PII]` |
| Prompt Injection Attacks | `"ignore instructions"` | → `[FILTERED]` |

### Critical for Philippine courts:
- **A.M. No. 12-12-11-SC** — CICL records must remain strictly confidential
- **RA 10173 (Data Privacy Act)** — legal obligation to protect personal data
- **Witness Protection** — prevents accidental PII exposure in logs and APIs

> Jia enforces privacy at the **infrastructure level** — not through policy alone.

---

# The Digital Notary

## Immutable WORM Audit Chain

Jia maintains a **Write-Once-Read-Many (WORM)** audit ledger — a hash-chained, cryptographically signed record of every security event:

```
GENESIS → Entry 1 (SHA-256) → Entry 2 (SHA-256) → Entry 3 (SHA-256) → ...
                                                          ↓
                                                   ML-DSA-65 Quantum Signature
```

### Each entry records:
- **What** happened (quarantine, block, alert, rollback)
- **When** it happened (RFC 3339 timestamp)
- **Who/What** was involved (IP, target, user)
- **Cryptographic proof** it hasn't been altered

### Why this is Jia's strongest advantage for courts:
> The WORM chain functions as a **digital notary** — providing the same guarantees for digital records that a clerk of court provides for physical ones: **authenticity, integrity, and non-repudiation**.

---

# Post-Quantum Cryptography

## Protecting Court Records for Decades

### The "Harvest Now, Decrypt Later" Threat:

Adversaries can **capture encrypted court data today** and decrypt it when quantum computers become available (estimated 2030–2040).

A sealed family court record from **2025** must remain sealed in **2050**.

### Jia implements NIST-approved quantum-resistant algorithms:

| Algorithm | Standard | Purpose |
|---|---|---|
| **ML-KEM-768** | FIPS 203 (Kyber) | Quantum-safe key exchange for secure channels |
| **ML-DSA-65** | FIPS 204 (Dilithium) | Quantum-safe digital signatures on audit logs |

### No other security platform offers this.

> Jia is the **only open-source cyber defense system** combining post-quantum cryptography with AI threat detection — ready for the quantum era.

---

# Passwordless Judicial Authentication

## FIDO2 / WebAuthn Hardware Security

### The problem with passwords:
- Phished via fake login pages targeting court staff
- Shared among clerks in busy municipal courts
- Reused across personal and court accounts

### Jia's solution — eliminate passwords entirely:

- 🔑 **Hardware security keys** (YubiKey) for judges and senior staff
- 📱 **Biometric passkeys** (fingerprint/face) on court devices
- 🛡️ **Phishing-resistant** — no credential to steal
- ⏱️ **Constant-time verification** — immune to timing attacks
- 🆕 **Trust On First Use** — simple onboarding without PKI complexity

### Deployment scenario:
> A judge authenticates to the eCourt system by tapping their YubiKey. No password to remember, no credential to phish, no token to intercept.

---

# eCourt & eFiling Protection

## Shielding Internet-Facing Court Systems

Jia deploys as a **security sidecar** in front of eCourt application servers:

```
Lawyer's eFiling → Jia Sidecar (< 2ms) → eCourt Server → Case Database
                       ↓ (if malicious)
                   BLOCKED + WORM Log + Alert
```

### Protection against:
- ✅ SQL injection targeting case databases
- ✅ XSS in uploaded court documents
- ✅ Webshells disguised as PDF filings
- ✅ DDoS floods during filing deadlines (300 req/sec/IP limit)
- ✅ Oversized malicious uploads (2MB body cap)

### Honeypot trap network:
Decoy endpoints (`/admin/db_backup`, `/config/env`) **lure and trap** automated scanners, extract attack signatures, and quarantine source IPs — generating forensic evidence automatically.

---

# Threat Intelligence & Response

## MITRE ATT&CK + Automated SOAR

### Real-time threat matching:
Jia's RAG engine performs **vector similarity search** against known attack patterns:
- Log4Shell (CVE-2021-44228)
- ProxyLogon (CVE-2021-26855)
- MOVEit SQLi (CVE-2023-34362)
- Spring4Shell (CVE-2022-22965)
- LLM Prompt Injection patterns

### Automated incident response (SOAR):
When a threat is detected, Jia executes **Rhai security playbooks** in milliseconds:

| Playbook | Action |
|---|---|
| `quarantine.rhai` | Isolate compromised endpoint |
| `ip_block.rhai` | Block attacker IP via iptables |
| `revoke_jwt.rhai` | Invalidate compromised session tokens |
| *Custom* | Court-specific response scripts |

> Response time: **milliseconds** — not hours waiting for human SOC approval.

---

# Kernel-Level Protection

## eBPF System Call Monitoring

Jia monitors the **operating system kernel itself** via eBPF — catching threats that network-level tools completely miss:

### Monitored syscalls:
- `execve` — unauthorized program execution
- `ptrace` — memory inspection / debugging (rootkit technique)
- `bpf_cmd` — attempts to tamper with eBPF monitoring itself

### Detection targets:
- 🔍 Rootkit installation attempts
- 🔍 Privilege escalation exploits
- 🔍 Unauthorized SUID binary execution
- 🔍 Memory injection attacks
- 🔍 Attempts to disable Jia's own monitoring

> **Defense at the deepest level:** Even if an attacker bypasses the network firewall and application layer, Jia detects their activity at the kernel syscall level.

---

# Regulatory Compliance

## Alignment with Philippine Law

| Law / Regulation | Requirement | Jia Feature |
|---|---|---|
| **RA 10173** (Data Privacy Act) | Protect personal information | PII scrubbing, access logging, WORM audit |
| **RA 10175** (Cybercrime Prevention) | Digital evidence integrity | SHA-256 hash chains, ML-DSA-65 signatures |
| **A.M. No. 01-7-01-SC** (Electronic Evidence) | Digital evidence admissibility | Cryptographic integrity proofs, ZK sharing |
| **A.M. No. 12-12-11-SC** (CICL Rules) | Confidentiality of minor's records | Automated PII redaction |
| **NCSP 2023-2028** | Critical infrastructure protection | eBPF kernel monitoring, MITRE ATT&CK intelligence |
| **eCourt Circulars** | System security standards | Defense-in-depth, WebAuthn, rate limiting |

> Jia provides **technical enforcement** of legal requirements that are currently enforced only through administrative policy.

---

# Self-Testing & Continuous Verification

## Built-in Purple Team Simulation

Jia can **attack itself** to continuously verify defensive readiness:

### 5 automated attack vectors:
1. 💉 **Prompt Injection** — tests AI guardrail response
2. 🗃️ **SQL Injection** — tests database protection
3. 🪤 **Honeypot Violation** — tests trap detection
4. 🌊 **eBPF Syscall Flood** — tests kernel-level defense
5. ☠️ **RAG Poisoning** — tests document sanitization

### Output:
- Per-vector pass/fail results
- **Defensive Readiness Score** (0–100%)
- Detailed forensic telemetry

> Court IT staff can run `gleam run -- --red-team` at any time to verify the system is working — **no external pen-testing firm required** for routine checks.

---

# Real-Time Command Dashboard

## Glassmorphism Cyber Command Center

Jia includes an embedded, zero-dependency web dashboard at `http://localhost:9090/dashboard`:

### Dashboard capabilities:
- 📊 **Live Threat Feed** — real-time WebSocket telemetry stream
- 🖥️ **Node Cluster Status** — BEAM + Rust sidecar health
- 📜 **WORM Audit Inspector** — searchable, signed audit ledger
- 🔍 **RAG CVE Search** — interactive MITRE ATT&CK lookup
- 🧹 **PII Scrubber Lab** — test PII redaction in real-time
- 📜 **Playbook Runner** — execute SOAR scripts from the UI
- 🔐 **ZK Proof Generator** — create privacy-preserving threat proofs

> All telemetry is encrypted end-to-end via **ML-KEM-768 + AES-256-GCM** quantum-safe WebSocket channels.

---

# Deployment Strategy

## Tiered Rollout Across the Court Hierarchy

| Court Level | Deployment Model | Priority |
|---|---|---|
| **Supreme Court** | Full dual-engine, dedicated hardware, eBPF, PQC, central SIEM | Phase 1 |
| **Court of Appeals** | Full deployment, cluster gossip to SC SOC | Phase 1 |
| **RTC** (Regional) | Sidecar alongside eCourt infrastructure | Phase 2 |
| **MeTC** (Metropolitan) | Lightweight Rust engine, centrally managed | Phase 3 |
| **MTC / MCTC** (Municipal) | Cloud-hosted shared Jia instance | Phase 3 |

### Why this works at every level:
- **24MB memory** — runs on existing municipal court hardware
- **Sub-microsecond crash recovery** — stays online on unreliable infrastructure
- **Docker Compose deployment** — `docker compose up -d` and it's running
- **Cluster gossip** — all courts share threat intelligence automatically

---

# Pilot Program Proposal

## Recommended First Steps

### Phase 1 — Proof of Concept (3 months)

1. **Deploy** Jia sidecar alongside the Supreme Court eCourt system
2. **Monitor** — observe threat detection, PII redaction, and audit logging in passive mode
3. **Validate** — run purple team simulation, verify WORM chain integrity
4. **Report** — present findings to the Committee on Information Technology

### Phase 2 — Expansion (6 months)

4. **Activate** blocking mode at Supreme Court
5. **Deploy** to Court of Appeals and select RTC pilot sites
6. **Integrate** SIEM export with judiciary central monitoring
7. **Train** court IT staff on dashboard and playbook management

### Phase 3 — Nationwide (12 months)

8. **Scale** to all RTC, MeTC, MTC, and MCTC courts
9. **Enable** cluster gossip for judiciary-wide threat intelligence sharing
10. **Establish** continuous purple team verification schedule

---

# Why Jia

## The Case for Open-Source Judicial Cyber Defense

| Advantage | Impact |
|---|---|
| 🔒 **Immutable audit trail** | Proves court records haven't been tampered with |
| ⚛️ **Post-quantum cryptography** | Protects sealed records for decades |
| 🪪 **Automated PII protection** | Enforces RA 10173 at infrastructure level |
| ⚡ **Sub-2ms latency** | Zero impact on court operations |
| 🚫 **Fail-closed security** | Blocks threats even when AI services are offline |
| 🔑 **Passwordless auth** | Eliminates credential theft as an attack vector |
| 🧪 **Self-testing capability** | Continuous verification without external auditors |
| 💾 **24MB footprint** | Deployable from SC data centers to MTC offices |
| ♻️ **Zero-downtime recovery** | OTP supervision keeps courts online through failures |
| 🔓 **Open source (MIT)** | Full judiciary control — no foreign vendor dependency |

---

<!-- _class: title -->
<!-- _paginate: skip -->

# 🛡️ Jia (家)

## Protecting the Digital Foundations of Philippine Justice

**Open Source • Quantum-Ready • Built for Courts**

*Contact: github.com/CharleGutierrez/jia*

---
