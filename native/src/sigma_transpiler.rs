use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SigmaTranspileRequest {
    pub sigma_rule_yaml: String,
}

#[derive(Debug, Serialize)]
pub struct SigmaTranspileResponse {
    pub success: bool,
    pub rule_title: String,
    pub mitre_tags: Vec<String>,
    pub generated_rhai_playbook: String,
    pub generated_yara_rule: String,
    pub message: String,
}

pub struct SigmaTranspiler;

impl SigmaTranspiler {
    pub fn transpile(yaml_str: &str) -> Result<SigmaTranspileResponse, String> {
        let lines: Vec<&str> = yaml_str.lines().collect();
        let mut title = "Untitled Detection Rule".to_string();
        let mut tags = Vec::new();
        let mut keywords = Vec::new();

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("title:") {
                title = trimmed.trim_start_matches("title:").trim().trim_matches('"').trim_matches('\'').to_string();
            } else if trimmed.starts_with("- attack.") {
                tags.push(trimmed.trim_start_matches("- attack.").trim().to_string());
            } else if trimmed.starts_with("Keywords:") || trimmed.starts_with("- '") || trimmed.starts_with("- \"") {
                let clean = trimmed.trim_start_matches('-').trim().trim_matches('"').trim_matches('\'');
                if !clean.is_empty() {
                    keywords.push(clean.to_string());
                }
            } else if trimmed.starts_with("CommandLine|contains:") || trimmed.starts_with("Image|endswith:") {
                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() > 1 {
                    keywords.push(parts[1].trim().trim_matches('"').trim_matches('\'').to_string());
                }
            }
        }

        if keywords.is_empty() {
            keywords.push("malicious_execution".to_string());
        }

        let clean_slug = title.to_lowercase().replace(|c: char| !c.is_alphanumeric(), "_");

        // 1. Generate Rhai SOAR Playbook
        let generated_rhai = format!(
            r#"// Auto-Transpiled Rhai Playbook from Sigma Rule: {title}
// Tags: {tags}
let ip_res = block_ip(target);
let jwt_res = revoke_jwt(target);
let worm_res = record_worm_log(target, reason, "SIGMA_AUTOMATED_QUARANTINE:{slug}");
log_warn("Sigma Rule '{title}' triggered automated containment for: " + target);
"SIGMA_RESPONSE_APPLIED: " + ip_res + " | " + jwt_res + " | " + worm_res
"#,
            title = title,
            tags = tags.join(", "),
            slug = clean_slug
        );

        // 2. Generate YARA Rule
        let mut yara_strings = String::new();
        for (i, kw) in keywords.iter().enumerate() {
            yara_strings.push_str(&format!("        $s{} = \"{}\" ascii wide nocase\n", i, kw));
        }

        let generated_yara = format!(
            r#"rule sigma_{slug} {{
    meta:
        description = "{title}"
        author = "Jia Sigma Transpiler"
        date = "{date}"
    strings:
{strings}
    condition:
        any of them
}}"#,
            slug = clean_slug,
            title = title,
            date = chrono::Utc::now().format("%Y-%m-%d"),
            strings = yara_strings
        );

        Ok(SigmaTranspileResponse {
            success: true,
            rule_title: title,
            mitre_tags: tags,
            generated_rhai_playbook: generated_rhai,
            generated_yara_rule: generated_yara,
            message: "Successfully transpiled Sigma detection rule to Rhai SOAR playbook and YARA rule.".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigma_transpiler() {
        let sample_sigma = r#"
title: Suspicious Ptrace Process Memory Injection
id: 4e941193-21b8-4d5a-a388-34857b28dbb3
status: experimental
description: Detects unauthorized ptrace memory manipulation
tags:
    - attack.t1055.008
    - attack.privilege_escalation
detection:
    selection:
        CommandLine|contains: 'ptrace_attach_inject'
    condition: selection
"#;
        let res = SigmaTranspiler::transpile(sample_sigma).expect("Should transpile sigma rule");
        assert!(res.rule_title.contains("Ptrace"));
        assert!(res.generated_rhai_playbook.contains("SIGMA_AUTOMATED_QUARANTINE"));
        assert!(res.generated_yara_rule.contains("rule sigma_"));
        assert!(res.generated_yara_rule.contains("ptrace_attach_inject"));
    }
}
