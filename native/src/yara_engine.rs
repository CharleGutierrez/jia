use yara::Compiler;
use std::sync::Arc;

pub struct YaraScanner {
    rules: Arc<yara::Rules>,
}

impl YaraScanner {
    pub fn new() -> Result<Self, String> {
        let mut compiler = Compiler::new().map_err(|e| format!("Failed to create YARA compiler: {}", e))?;
        
        // Define high-fidelity industry-standard malware and attack signatures
        let rules_str = r#"
        rule Suspicious_Shellcode {
            meta:
                description = "Detects common NOP sleds and syscall sequences"
                severity = "High"
            strings:
                $nop_sled = { 90 90 90 90 90 90 90 90 }
                $syscall = { 0F 05 }
            condition:
                $nop_sled and $syscall
        }

        rule WebShell_PHP {
            meta:
                description = "Detects generic PHP web shell execution vectors"
                severity = "Critical"
            strings:
                $php_eval = "eval($_"
                $php_system = "system($_"
                $php_exec = "exec($_"
                $php_base64 = "base64_decode($_"
            condition:
                any of them
        }

        rule SQL_Injection_Patterns {
            meta:
                description = "Detects common SQL injection data exfiltration patterns"
                severity = "High"
            strings:
                $union_select = /UNION\s+(ALL\s+)?SELECT/i
                $info_schema = "information_schema" nocase
                $waitfor = "WAITFOR DELAY" nocase
            condition:
                any of them
        }
        "#;

        compiler = compiler.add_rules_str(rules_str)
            .map_err(|e| format!("Failed to add YARA rules: {}", e))?;
            
        let rules = compiler.compile_rules()
            .map_err(|e| format!("Failed to compile YARA rules: {}", e))?;
            
        Ok(Self {
            rules: Arc::new(rules),
        })
    }

    /// Scans a payload string against the compiled YARA rules.
    /// Returns the name of the matched rules if any trigger.
    pub fn scan_payload(&self, payload: &str) -> Option<String> {
        if let Ok(matches) = self.rules.scan_mem(payload.as_bytes(), 5) {
            if !matches.is_empty() {
                let rule_names: Vec<String> = matches.iter().map(|m| m.identifier.to_string()).collect();
                return Some(format!("YARA Match: {}", rule_names.join(", ")));
            }
        }
        None
    }
}
