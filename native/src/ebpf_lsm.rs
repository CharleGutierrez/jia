use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsmPolicyRule {
    pub id: String,
    pub name: String,
    pub target_pattern: String,
    pub block_hash: Option<String>,
    pub action: String, // "DENY_EPERM", "DENY_EACCES", "MONITOR"
    pub error_code: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsmDecision {
    pub allowed: bool,
    pub error_code: i32,
    pub matched_rule: Option<String>,
    pub reason: String,
    pub in_kernel_blocked: bool,
}

#[derive(Debug, Deserialize)]
pub struct LsmEvaluateRequest {
    pub binary_path: String,
    pub sha256_hash: Option<String>,
    pub uid: Option<u32>,
    pub namespace_id: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct LsmEvaluateResponse {
    pub decision: LsmDecision,
    pub hook_type: String,
    pub timestamp: String,
}

pub struct EbpfLsmEngine {
    rules: Vec<LsmPolicyRule>,
}

impl Default for EbpfLsmEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfLsmEngine {
    pub fn new() -> Self {
        let rules = vec![
            LsmPolicyRule {
                id: "LSM-001".into(),
                name: "Block Compilable Shellcode / Memfd Injections".into(),
                target_pattern: "memfd_create".into(),
                block_hash: None,
                action: "DENY_EPERM".into(),
                error_code: -1, // -EPERM
                enabled: true,
            },
            LsmPolicyRule {
                id: "LSM-002".into(),
                name: "Block XZ Utils Backdoored Liblzma Binaries".into(),
                target_pattern: "liblzma.so.5.6.0".into(),
                block_hash: Some("4d0362f6b8b0e60d0092ad81ffc6198f6834d852cb7805128ff093952f9547d0".into()),
                action: "DENY_EACCES".into(),
                error_code: -13, // -EACCES
                enabled: true,
            },
            LsmPolicyRule {
                id: "LSM-003".into(),
                name: "Block Unauthorized Ptrace Debuggers on SecOps Daemon".into(),
                target_pattern: "ptrace_attach".into(),
                block_hash: None,
                action: "DENY_EPERM".into(),
                error_code: -1,
                enabled: true,
            },
            LsmPolicyRule {
                id: "LSM-004".into(),
                name: "Block Container Namespace Leaky FD Escape".into(),
                target_pattern: "/proc/self/fd".into(),
                block_hash: None,
                action: "DENY_EPERM".into(),
                error_code: -1,
                enabled: true,
            },
        ];

        Self { rules }
    }

    /// Evaluates Linux Security Module `bpf_lsm_bprm_check_security` hook before execve
    pub fn evaluate_bprm(&self, req: &LsmEvaluateRequest) -> LsmDecision {
        let path_lower = req.binary_path.to_lowercase();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let pattern_match = path_lower.contains(&rule.target_pattern.to_lowercase());
            let hash_match = match (&rule.block_hash, &req.sha256_hash) {
                (Some(expected), Some(actual)) => expected.eq_ignore_ascii_case(actual),
                _ => false,
            };

            if pattern_match || hash_match {
                return LsmDecision {
                    allowed: false,
                    error_code: rule.error_code,
                    matched_rule: Some(rule.id.clone()),
                    reason: format!("Blocked in-kernel by LSM hook '{}' (Error {})", rule.name, rule.error_code),
                    in_kernel_blocked: true,
                };
            }
        }

        LsmDecision {
            allowed: true,
            error_code: 0,
            matched_rule: None,
            reason: "Permitted by LSM security policy".into(),
            in_kernel_blocked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_lsm_pre_execution_blocking() {
        let engine = EbpfLsmEngine::new();

        // 1. Test allowed binary
        let req_safe = LsmEvaluateRequest {
            binary_path: "/usr/bin/curl".into(),
            sha256_hash: None,
            uid: Some(1000),
            namespace_id: None,
        };
        let dec_safe = engine.evaluate_bprm(&req_safe);
        assert!(dec_safe.allowed);
        assert_eq!(dec_safe.error_code, 0);

        // 2. Test blocked binary by pattern
        let req_memfd = LsmEvaluateRequest {
            binary_path: "/tmp/memfd_create_payload".into(),
            sha256_hash: None,
            uid: Some(1000),
            namespace_id: None,
        };
        let dec_memfd = engine.evaluate_bprm(&req_memfd);
        assert!(!dec_memfd.allowed);
        assert_eq!(dec_memfd.error_code, -1);
        assert!(dec_memfd.in_kernel_blocked);

        // 3. Test blocked binary by SHA-256 hash
        let req_xz = LsmEvaluateRequest {
            binary_path: "/usr/lib/liblzma.so.5".into(),
            sha256_hash: Some("4d0362f6b8b0e60d0092ad81ffc6198f6834d852cb7805128ff093952f9547d0".into()),
            uid: Some(0),
            namespace_id: None,
        };
        let dec_xz = engine.evaluate_bprm(&req_xz);
        assert!(!dec_xz.allowed);
        assert_eq!(dec_xz.error_code, -13);
    }
}
