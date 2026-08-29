use rhai::{Engine, Scope, AST};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};
use tracing::info;

use crate::WormAuditEntry;

#[derive(Debug, Deserialize)]
pub struct PlaybookExecutionRequest {
    pub playbook_name: String,
    pub target: String,
    pub reason: String,
    pub custom_script: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PlaybookResult {
    pub playbook_name: String,
    pub target: String,
    pub success: bool,
    pub actions_taken: Vec<String>,
    pub output: String,
    pub timestamp: String,
}

pub struct PlaybookEngine;

impl Default for PlaybookEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaybookEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn execute(
        &self,
        playbook_name: &str,
        target: &str,
        reason: &str,
        custom_script: Option<&str>,
        worm_logs: Arc<Mutex<Vec<WormAuditEntry>>>,
    ) -> Result<PlaybookResult, String> {
        let script = if let Some(script_content) = custom_script {
            script_content.to_string()
        } else {
            self.load_playbook_script(playbook_name)?
        };

        let actions_taken_arc = Arc::new(Mutex::new(Vec::<String>::new()));
        let actions_taken_clone1 = actions_taken_arc.clone();
        let actions_taken_clone2 = actions_taken_arc.clone();
        let actions_taken_clone3 = actions_taken_arc.clone();

        let worm_logs_clone = worm_logs.clone();

        let mut engine = Engine::new();

        engine.register_fn("log_info", |msg: String| {
            info!("📋 [Rhai Script Log]: {}", msg);
        });

        engine.register_fn("revoke_jwt", move |user_or_token: String| -> String {
            info!("🛡️ [Rhai Playbook] Revoking JWT / Session Token for target: {}", user_or_token);
            let res = format!("JWT_REVOKED:{}", user_or_token);
            actions_taken_clone1.lock().unwrap().push(res.clone());
            res
        });

        engine.register_fn("block_ip", move |ip: String| -> String {
            info!("🛡️ [Rhai Playbook] Adding IP firewall block rule for: {}", ip);
            let res = format!("IP_BLOCKED:{}", ip);
            actions_taken_clone2.lock().unwrap().push(res.clone());
            res
        });

        engine.register_fn("record_worm_log", move |tgt: String, rsn: String, act: String| -> String {
            let mut logs = worm_logs_clone.lock().unwrap();
            let id = logs.len() + 1;
            let prev_hash = logs
                .last()
                .map(|e| e.hash.clone())
                .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".into());

            let entry = WormAuditEntry::new(id, tgt.clone(), rsn, act.clone(), prev_hash);
            let hash = entry.hash.clone();
            logs.push(entry);

            let res = format!("WORM_LOGGED:{}:{}", tgt, hash);
            actions_taken_clone3.lock().unwrap().push(res.clone());
            res
        });

        let mut scope = Scope::new();
        scope.push("target", target.to_string());
        scope.push("reason", reason.to_string());

        let ast: AST = engine
            .compile(&script)
            .map_err(|e| format!("Failed to compile Rhai playbook '{}': {}", playbook_name, e))?;

        let eval_result: String = engine
            .eval_ast_with_scope(&mut scope, &ast)
            .map_err(|e| format!("Error executing Rhai playbook '{}': {}", playbook_name, e))?;

        let actions = actions_taken_arc.lock().unwrap().clone();

        Ok(PlaybookResult {
            playbook_name: playbook_name.to_string(),
            target: target.to_string(),
            success: true,
            actions_taken: actions,
            output: eval_result,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    fn load_playbook_script(&self, name: &str) -> Result<String, String> {
        let file_path = format!("playbooks/{}.rhai", name);
        if Path::new(&file_path).exists() {
            fs::read_to_string(&file_path)
                .map_err(|e| format!("Failed to read playbook file {}: {}", file_path, e))
        } else {
            // Default built-in embedded playbooks
            match name {
                "quarantine" | "quarantine.rhai" => Ok(r#"
let jwt_res = revoke_jwt(target);
let ip_res = block_ip(target);
let worm_res = record_worm_log(target, reason, "QUARANTINE_AUTOMATED_REMEDIATION");
log_info("Executed automated quarantine playbook for target: " + target);
"PLAYBOOK_QUARANTINE_SUCCESS: " + jwt_res + " | " + ip_res + " | " + worm_res
"#.trim().to_string()),

                "ip_block" | "ip_block.rhai" => Ok(r#"
let ip_res = block_ip(target);
let worm_res = record_worm_log(target, reason, "IP_FIREWALL_BLOCK");
log_info("Executed IP block playbook for IP: " + target);
"PLAYBOOK_IP_BLOCK_SUCCESS: " + ip_res + " | " + worm_res
"#.trim().to_string()),

                "revoke_jwt" | "revoke_jwt.rhai" => Ok(r#"
let jwt_res = revoke_jwt(target);
let worm_res = record_worm_log(target, reason, "JWT_REVOCATION");
log_info("Executed JWT revocation playbook for user/token: " + target);
"PLAYBOOK_JWT_REVOKE_SUCCESS: " + jwt_res + " | " + worm_res
"#.trim().to_string()),

                _ => Err(format!("Playbook '{}' not found and no embedded default exists.", name)),
            }
        }
    }
}
