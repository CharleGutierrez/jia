use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPatch {
    pub patch_id: String,
    pub target_symbol: String,
    pub vulnerability_cve: String,
    pub hook_type: String, // "EBPF_TRAMPOLINE", "RHAI_FILTER", "IN_MEMORY_DETOUR"
    pub active: bool,
    pub neutralized_exploit_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct ApplyPatchRequest {
    pub target_symbol: String,
    pub vulnerability_cve: String,
    pub hook_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApplyPatchResponse {
    pub success: bool,
    pub patch: DynamicPatch,
    pub zero_downtime: bool,
    pub memory_address: String,
    pub message: String,
}

pub struct DynamicPatcher;

impl DynamicPatcher {
    pub fn apply_hot_patch(req: &ApplyPatchRequest) -> DynamicPatch {
        let hook = req.hook_type.clone().unwrap_or_else(|| "EBPF_TRAMPOLINE".into());
        let clean_cve = req.vulnerability_cve.replace('-', "_");

        DynamicPatch {
            patch_id: format!("HOTPATCH-{}-{}", clean_cve, uuid::Uuid::new_v4().to_string()[..6].to_string()),
            target_symbol: req.target_symbol.clone(),
            vulnerability_cve: req.vulnerability_cve.clone(),
            hook_type: hook,
            active: true,
            neutralized_exploit_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_patcher_application() {
        let req = ApplyPatchRequest {
            target_symbol: "sys_execve_intercept".into(),
            vulnerability_cve: "CVE-2024-3094".into(),
            hook_type: Some("EBPF_TRAMPOLINE".into()),
        };

        let patch = DynamicPatcher::apply_hot_patch(&req);
        assert!(patch.active);
        assert!(patch.patch_id.starts_with("HOTPATCH-CVE_2024_3094"));
        assert_eq!(patch.hook_type, "EBPF_TRAMPOLINE");
    }
}
