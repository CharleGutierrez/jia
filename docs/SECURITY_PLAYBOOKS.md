# 📜 Jia Security Playbooks & Configuration Guide

Jia supports dynamic **SOAR (Security Orchestration, Automation, and Response)** playbooks powered by the embedded **Rhai** scripting language. Playbooks are evaluated at runtime in Rust without requiring daemon restarts.

---

## 📁 Playbook Structure

Security playbooks live in the `playbooks/` directory (or can be submitted dynamically via `/api/v1/playbook/execute`).

### Example 1: Critical Threat Quarantine (`quarantine.rhai`)
```rhai
// Automatically quarantine IP if risk level is CRITICAL
if risk_level == "CRITICAL_RISK" || confidence_score > 0.95 {
    quarantine_ip(source_ip);
    log_worm_audit(source_ip, "Automated quarantine via quarantine.rhai", "QUARANTINE");
    send_alert("slack", "🚨 Critical Threat Quarantined: " + source_ip);
} else if prompt_injection_detected {
    scrub_prompt();
    log_worm_audit(source_ip, "Prompt Injection scrubbed", "SANITIZE");
}
```

### Example 2: API Key Exfiltration Defense (`revoke_jwt.rhai`)
```rhai
if payload.contains("AKIA") || payload.contains("eyJhbGci") {
    flag_pii_leak();
    block_request();
    log_worm_audit(user_id, "Attempted API Key / JWT Exfiltration", "BLOCK");
}
```

---

## 🛡️ AI Prompt Firewall Rules (`src/jia/firewall.gleam`)

Jia's prompt firewall checks incoming LLM prompts for:
1. **System Prompt Overrides**: Patterns like `"ignore previous instructions"`, `"disregard initial prompt"`.
2. **Jailbreak Persona Attacks**: Patterns like `"DAN mode"`, `"developer mode enabled"`.
3. **Zero-Width Unicode Poisoning**: Invisible characters (`\u{200B}`, `\u{200C}`, `\u{200D}`, `\u{FEFF}`) designed to slip past tokenizers.
4. **PII Exposure**: Automatic redaction of SSNs (`XXX-XX-XXXX`), credit cards, and cloud provider API keys (`AKIA...`).
