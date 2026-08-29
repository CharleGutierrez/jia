use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub name: String,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub severity: String,
    pub cvss_score: f32,
    pub description: String,
    pub remediation: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMatch {
    pub cve: CveEntry,
    pub similarity_score: f32,
}

#[derive(Debug, Deserialize)]
pub struct RagSearchRequest {
    pub query: String,
    pub top_k: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct RagSearchResponse {
    pub query: String,
    pub total_matches: usize,
    pub matches: Vec<CveMatch>,
}

pub struct RagEngine {
    cves: Vec<CveEntry>,
}

impl Default for RagEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RagEngine {
    pub fn new() -> Self {
        let cves = vec![
            CveEntry {
                id: "CVE-2021-44228".into(),
                name: "Log4Shell Remote Code Execution".into(),
                mitre_tactic: "Initial Access / Execution".into(),
                mitre_technique: "T1190 - Exploit Public-Facing Application".into(),
                severity: "CRITICAL".into(),
                cvss_score: 10.0,
                description: "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. Allows arbitrary remote code execution via ${jndi:ldap://...}".into(),
                remediation: "Upgrade Log4j to v2.17.1 or set log4j2.formatMsgNoLookups=true".into(),
                tags: vec!["log4j".into(), "rce".into(), "jndi".into(), "java".into(), "cve-2021-44228".into()],
            },
            CveEntry {
                id: "CVE-2023-34362".into(),
                name: "MOVEit Transfer SQL Injection RCE".into(),
                mitre_tactic: "Initial Access / Privilege Escalation".into(),
                mitre_technique: "T1190 - Exploit Public-Facing Application / T1059 - Command and Scripting Interpreter".into(),
                severity: "CRITICAL".into(),
                cvss_score: 9.8,
                description: "A SQL injection vulnerability in the MOVEit Transfer web application could allow an unauthenticated attacker to gain access to MOVEit Transfer's database and execute arbitrary commands or steal sensitive files.".into(),
                remediation: "Apply official MOVEit Transfer security patch and restrict HTTP/HTTPS access to trusted management subnets.".into(),
                tags: vec!["sqli".into(), "moveit".into(), "sql injection".into(), "rce".into(), "database".into()],
            },
            CveEntry {
                id: "CVE-2023-43654".into(),
                name: "LLM Indirect Prompt Injection & Safety Bypass".into(),
                mitre_tactic: "Execution / Defense Evasion".into(),
                mitre_technique: "T1059.007 - LLM Prompt Injection & Jailbreak Override".into(),
                severity: "HIGH".into(),
                cvss_score: 8.6,
                description: "Indirect prompt injection vulnerability in AI agent pipelines allowing untrusted user inputs or retrieved context to override system instructions, execute arbitrary tools, bypass safety guardrails, or exfiltrate private tokens.".into(),
                remediation: "Enforce strict input sanitization, separate system instructions from context, and implement real-time output validation filters.".into(),
                tags: vec!["prompt injection".into(), "jailbreak".into(), "ai".into(), "llm".into(), "system prompt".into()],
            },
            CveEntry {
                id: "CVE-2021-26855".into(),
                name: "Microsoft Exchange ProxyLogon SSRF RCE".into(),
                mitre_tactic: "Initial Access / Lateral Movement".into(),
                mitre_technique: "T1190 - Exploit Public-Facing Application".into(),
                severity: "CRITICAL".into(),
                cvss_score: 9.8,
                description: "A server-side request forgery (SSRF) vulnerability in Microsoft Exchange Server allows arbitrary HTTP request forgery leading to unauthenticated remote code execution and full domain compromise.".into(),
                remediation: "Install KB5000871 cumulative update and enforce multi-factor authentication.".into(),
                tags: vec!["rce".into(), "exchange".into(), "ssrf".into(), "microsoft".into(), "proxylogon".into()],
            },
            CveEntry {
                id: "CVE-2022-22965".into(),
                name: "Spring4Shell Remote Code Execution".into(),
                mitre_tactic: "Execution / Persistence".into(),
                mitre_technique: "T1210 - Exploitation of Remote Services".into(),
                severity: "CRITICAL".into(),
                cvss_score: 9.8,
                description: "Spring Framework Data Binding RCE vulnerability allowing attackers to exploit classloader parameters to write arbitrary webshell files on server disk and execute malicious code.".into(),
                remediation: "Upgrade Spring Framework to 5.3.18+ or 5.2.20+".into(),
                tags: vec!["spring".into(), "spring4shell".into(), "rce".into(), "java".into(), "webshell".into()],
            },
        ];

        Self { cves }
    }

    pub fn query_mitre_cve(&self, query: &str) -> Vec<CveMatch> {
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<CveMatch> = self
            .cves
            .iter()
            .map(|cve| {
                let doc_text = format!(
                    "{} {} {} {} {} {} {}",
                    cve.id,
                    cve.name,
                    cve.mitre_tactic,
                    cve.mitre_technique,
                    cve.description,
                    cve.remediation,
                    cve.tags.join(" ")
                );
                let doc_tokens = tokenize(&doc_text);
                let score = cosine_similarity(&query_tokens, &doc_tokens);
                CveMatch {
                    cve: cve.clone(),
                    similarity_score: score,
                }
            })
            .filter(|m| m.similarity_score > 0.05)
            .collect();

        matches.sort_by(|a, b| b.similarity_score.partial_cmp(&a.similarity_score).unwrap());
        matches
    }
}

pub fn query_mitre_cve(query: &str) -> Vec<CveMatch> {
    let engine = RagEngine::new();
    engine.query_mitre_cve(query)
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '-')
        .filter(|s| s.len() > 1)
        .map(|s| s.to_string())
        .collect()
}

fn cosine_similarity(query_tokens: &[String], doc_tokens: &[String]) -> f32 {
    let mut vocab: HashSet<String> = HashSet::new();
    for token in query_tokens {
        vocab.insert(token.clone());
    }
    for token in doc_tokens {
        vocab.insert(token.clone());
    }

    let mut dot_product = 0.0f32;
    let mut query_mag_sq = 0.0f32;
    let mut doc_mag_sq = 0.0f32;

    for term in vocab.iter() {
        let q_freq = query_tokens.iter().filter(|t| *t == term).count() as f32;
        let d_freq = doc_tokens.iter().filter(|t| *t == term).count() as f32;

        // Give extra weight if term is an exact keyword match in tags or CVE ID
        let weight = if term.starts_with("cve") || term == "rce" || term == "sqli" || term == "log4j" {
            2.5
        } else {
            1.0
        };

        let q_val = q_freq * weight;
        let d_val = d_freq * weight;

        dot_product += q_val * d_val;
        query_mag_sq += q_val * q_val;
        doc_mag_sq += d_val * d_val;
    }

    if query_mag_sq == 0.0 || doc_mag_sq == 0.0 {
        0.0
    } else {
        dot_product / (query_mag_sq.sqrt() * doc_mag_sq.sqrt())
    }
}
