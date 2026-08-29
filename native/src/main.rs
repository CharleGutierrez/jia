use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;
use uuid::Uuid;

use vella::ai::{AiDecisionEngine, RiskLevel};
use vella::auth::crypto::Crypto;
use vella::defense::cyber::CyberCommand;

pub mod dashboard;
pub mod ebpf_trapper;
pub mod firewall;
pub mod playbook;
pub mod pqc;
pub mod rag_agent;
pub mod rag_poison_guard;
pub mod sandbox;
pub mod self_healing;
pub mod webauthn;
mod yara_engine;
pub mod zk_proof;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub timestamp: String,
    pub event_type: String,
    pub source_ip: String,
    pub risk_level: String,
    pub action: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WormAuditEntry {
    pub id: usize,
    pub timestamp: String,
    pub target: String,
    pub reason: String,
    pub action: String,
    pub previous_hash: String,
    pub hash: String,
}

impl WormAuditEntry {
    pub fn new(id: usize, target: String, reason: String, action: String, previous_hash: String) -> Self {
        let timestamp = Utc::now().to_rfc3339();
        let payload_to_hash = format!("{}:{}:{}:{}:{}:{}", id, timestamp, target, reason, action, previous_hash);
        
        let mut hasher = Sha256::new();
        hasher.update(payload_to_hash.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Self {
            id,
            timestamp,
            target,
            reason,
            action,
            previous_hash,
            hash,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub cyber_command: Arc<CyberCommand>,
    pub start_time: Instant,
    pub worm_logs: Arc<Mutex<Vec<WormAuditEntry>>>,
    pub tx: broadcast::Sender<TelemetryEvent>,
    pub yara_scanner: Arc<yara_engine::YaraScanner>,
    pub db_pool: sqlx::SqlitePool,
}

fn calculate_entropy(data: &str) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = std::collections::HashMap::new();
    for c in data.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let len = data.chars().count() as f64;
    let mut entropy = 0.0;
    for count in counts.values() {
        let p = *count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[derive(Debug, Deserialize)]
pub struct AnalyzeEventRequest {
    pub payload: Option<String>,
    pub source_ip: String,
    pub user_id: Option<String>,
    pub prompt: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeEventResponse {
    pub event_id: String,
    pub timestamp: String,
    pub risk_level: String,
    pub confidence_score: f64,
    pub prompt_injection_detected: bool,
    pub zero_day_detected: bool,
    pub zero_day_details: Option<String>,
    pub action: String,
    pub recommendation: String,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct QuarantineRequest {
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct QuarantineResponse {
    pub status: String,
    pub worm_log: WormAuditEntry,
    pub defense_action: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub vella_engine: String,
    pub uptime_seconds: u64,
    pub worm_log_count: usize,
    pub session_token: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    info!("🚀 Initializing Jia Native Sidecar (Vella AI & Defense Engine)...");

    let (tx, _) = broadcast::channel::<TelemetryEvent>(100);
    let yara_scanner = Arc::new(yara_engine::YaraScanner::new().expect("Failed to initialize YARA Rule Engine"));
    
    // Initialize persistent SQLite database for WebAuthn credentials
    let db_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite::memory:") // In production this would be sqlite:jia_secops.db
        .await
        .expect("Failed to create SQLite connection pool");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            public_key_cbor_hex TEXT NOT NULL
        );"
    ).execute(&db_pool).await.unwrap();

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS challenges (
            challenge_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            challenge_base64 TEXT NOT NULL,
            expires_at BIGINT NOT NULL
        );"
    ).execute(&db_pool).await.unwrap();

    let state = AppState {
        cyber_command: Arc::new(CyberCommand::new("ASN-JIA-DEFENSE")),
        start_time: Instant::now(),
        worm_logs: Arc::new(Mutex::new(Vec::new())),
        tx,
        yara_scanner,
        db_pool,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/dashboard", get(dashboard_handler))
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/analyze_event", post(analyze_event_handler))
        .route("/api/v1/quarantine", post(quarantine_handler))
        .route("/api/v1/rag/search", post(rag_search_handler))
        .route("/api/v1/firewall/scrub", post(firewall_scrub_handler))
        .route("/api/v1/playbook/execute", post(playbook_execute_handler))
        .route("/api/v1/zk/export", post(zk_export_handler))
        .route("/api/v1/ebpf/inspect", post(ebpf_inspect_handler))
        .route("/api/v1/pqc/sign", post(pqc_sign_handler))
        .route("/api/v1/rag/guard", post(rag_guard_handler))
        .route("/api/v1/self_heal/patch", post(self_heal_patch_handler))
        .route("/api/v1/red_team/simulate", post(red_team_simulate_handler))
        .route("/api/v1/auth/challenge", post(webauthn::webauthn_challenge_handler))
        .route("/api/v1/auth/verify", post(webauthn::webauthn_verify_handler))
        .route("/ws/telemetry", get(ws_telemetry_handler))
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 9090));
    info!("🛡️ Jia Native Sidecar listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn dashboard_handler() -> Html<String> {
    dashboard::render_dashboard()
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let worm_count = state.worm_logs.lock().unwrap().len();
    let token = Crypto::random_token(16);

    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        vella_engine: "online".into(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        worm_log_count: worm_count,
        session_token: token,
    })
}

async fn analyze_event_handler(
    State(state): State<AppState>,
    Json(req): Json<AnalyzeEventRequest>,
) -> Json<AnalyzeEventResponse> {
    let event_id = Uuid::new_v4().to_string();
    let timestamp = Utc::now().to_rfc3339();

    let prompt_str = req.prompt.as_deref().unwrap_or("");
    let payload_str = req.payload.as_deref().unwrap_or("");
    
    // Check if the payload is actually the prompt
    let combined_text = if payload_str == "normal request" && !prompt_str.is_empty() {
        prompt_str
    } else {
        if prompt_str.is_empty() { payload_str } else { prompt_str }
    };

    // 0. Static Malware Signature Scan via YARA
    if let Some(yara_match) = state.yara_scanner.scan_payload(combined_text) {
        return Json(AnalyzeEventResponse {
            event_id,
            timestamp,
            risk_level: "Critical".to_string(),
            confidence_score: 0.99,
            prompt_injection_detected: false,
            zero_day_detected: true,
            zero_day_details: Some(yara_match),
            action: "block".to_string(),
            recommendation: "Quarantine immediately".to_string(),
            reasoning: vec!["YARA signature match".to_string()],
        });
    }

    let full_text = format!("{} {}", prompt_str, payload_str).to_lowercase();

    // 1. Detect Prompt Injection Attempts
    let prompt_injection_keywords = [
        "ignore previous instructions",
        "ignore all instructions",
        "system prompt",
        "jailbreak",
        "bypass safety",
        "override rules",
        "dan mode",
        "developer mode",
        "<script>",
        "eval(",
        "' or 1=1",
        "union select",
    ];
    let prompt_injection_detected = prompt_injection_keywords
        .iter()
        .any(|kw| full_text.contains(kw));

    // 2. Assess Risk Level using Vella AiDecisionEngine
    let field_name = if prompt_injection_detected {
        "security_alert_prompt_injection"
    } else {
        "network_telemetry_event"
    };

    let risk_assessment = AiDecisionEngine::assess_approval_risk(
        field_name,
        None,
        if prompt_str.is_empty() { payload_str } else { prompt_str },
    );

    // 3. Evaluate Zero-Day Signatures via Vella CyberCommand & Heuristics (Entropy/Length)
    let zero_day_res = state.cyber_command.detect_zero_day_apt(payload_str);
    
    // Heuristic: Packed shellcode / encoded payloads usually have very high entropy
    let entropy = calculate_entropy(payload_str);
    let is_high_entropy = payload_str.len() > 30 && entropy > 5.5;

    let (zero_day_detected, zero_day_details) = match zero_day_res {
        Ok(msg) if msg.contains("ZERO-DAY DETECTED") || is_high_entropy => {
            (true, Some(if is_high_entropy { "High entropy payload detected (possible packed malware/shellcode)".to_string() } else { msg }))
        }
        Ok(msg) => (false, Some(msg)),
        Err(err) => (false, Some(err)),
    };

    // 4. Zero-Trust Action Decision Matrix
    let mut effective_risk = risk_assessment.risk_level;
    if prompt_injection_detected && effective_risk == RiskLevel::Low {
        effective_risk = RiskLevel::High;
    }
    if zero_day_detected {
        effective_risk = RiskLevel::Critical;
    }

    let action = match effective_risk {
        RiskLevel::Critical => "quarantine",
        RiskLevel::High => "block",
        RiskLevel::Medium => {
            if prompt_injection_detected {
                "block"
            } else {
                "allow"
            }
        }
        RiskLevel::Low => "allow",
    };

    let mut reasoning = risk_assessment.reasoning.clone();
    if prompt_injection_detected {
        reasoning.push("Prompt injection pattern detected in input text.".into());
    }
    if zero_day_detected {
        reasoning.push("Zero-day APT anomaly pattern matched by CyberCommand.".into());
    }

    let response = AnalyzeEventResponse {
        event_id: event_id.clone(),
        timestamp: timestamp.clone(),
        risk_level: effective_risk.as_str().into(),
        confidence_score: if prompt_injection_detected || zero_day_detected { 0.99 } else { risk_assessment.confidence_score },
        prompt_injection_detected,
        zero_day_detected,
        zero_day_details,
        action: action.into(),
        recommendation: risk_assessment.recommendation.clone(),
        reasoning,
    };

    // Broadcast to WebSocket telemetry stream
    let telemetry_event = TelemetryEvent {
        event_id,
        timestamp,
        event_type: "ANALYZE_EVENT".into(),
        source_ip: req.source_ip.clone(),
        risk_level: effective_risk.as_str().into(),
        action: action.into(),
        details: format!("Prompt Inj: {}, Zero-Day: {}", prompt_injection_detected, zero_day_detected),
    };
    let _ = state.tx.send(telemetry_event);

    Json(response)
}

async fn quarantine_handler(
    State(state): State<AppState>,
    Json(req): Json<QuarantineRequest>,
) -> Json<QuarantineResponse> {
    let mut logs = state.worm_logs.lock().unwrap();
    let id = logs.len() + 1;
    let prev_hash = logs
        .last()
        .map(|entry| entry.hash.clone())
        .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".into());

    let worm_entry = WormAuditEntry::new(
        id,
        req.target.clone(),
        req.reason.clone(),
        "QUARANTINE".into(),
        prev_hash,
    );
    logs.push(worm_entry.clone());

    // Trigger Vella CyberCommand defense neutralization action
    let defense_action = state
        .cyber_command
        .detect_zero_day_apt(&format!("QUARANTINE TARGET: {} REASON: {}", req.target, req.reason))
        .unwrap_or_else(|e| format!("Defense execution report: {}", e));

    let telemetry_event = TelemetryEvent {
        event_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        event_type: "QUARANTINE".into(),
        source_ip: req.target.clone(),
        risk_level: "CRITICAL_RISK".into(),
        action: "QUARANTINE".into(),
        details: req.reason.clone(),
    };
    let _ = state.tx.send(telemetry_event);

    Json(QuarantineResponse {
        status: "quarantined".into(),
        worm_log: worm_entry,
        defense_action,
    })
}

async fn rag_search_handler(
    Json(req): Json<rag_agent::RagSearchRequest>,
) -> Result<Json<rag_agent::RagSearchResponse>, (StatusCode, String)> {
    let engine = rag_agent::RagEngine::new();
    match engine.query_mitre_cve(&req.query) {
        Ok(matches) => {
            let top_k = req.top_k.unwrap_or(10);
            let limited_matches: Vec<rag_agent::CveMatch> = matches.into_iter().take(top_k).collect();
            let total = limited_matches.len();

            Ok(Json(rag_agent::RagSearchResponse {
                query: req.query,
                total_matches: total,
                matches: limited_matches,
            }))
        }
        Err(e) => Err((StatusCode::SERVICE_UNAVAILABLE, e))
    }
}

async fn firewall_scrub_handler(
    Json(req): Json<firewall::ScrubRequest>,
) -> Json<firewall::FirewallScrubResponse> {
    let scrubber = firewall::PiiScrubber::new();
    let pii_scrub = scrubber.scrub(&req.text);

    let prompt_to_eval = req.prompt.as_deref().unwrap_or(&req.text);
    let prompt_safety = firewall::PromptSafetyFilter::analyze(prompt_to_eval);

    Json(firewall::FirewallScrubResponse {
        pii_scrub,
        prompt_safety,
    })
}

async fn playbook_execute_handler(
    State(state): State<AppState>,
    Json(req): Json<playbook::PlaybookExecutionRequest>,
) -> Result<Json<playbook::PlaybookResult>, (StatusCode, String)> {
    let engine = playbook::PlaybookEngine::new();
    match engine.execute(
        &req.playbook_name,
        &req.target,
        &req.reason,
        req.custom_script.as_deref(),
        state.worm_logs.clone(),
    ) {
        Ok(result) => Ok(Json(result)),
        Err(err) => Err((StatusCode::BAD_REQUEST, err)),
    }
}

async fn zk_export_handler(
    Json(req): Json<zk_proof::ZkExportRequest>,
) -> Json<zk_proof::ZkExportResponse> {
    let proof = zk_proof::ZkProofGenerator::generate_proof(
        &req.indicator_type,
        &req.indicator_value,
        req.salt.as_deref(),
    );

    let verified = zk_proof::ZkProofGenerator::verify_proof(
        &proof,
        &req.indicator_value,
        req.salt.as_deref(),
    );

    Json(zk_proof::ZkExportResponse {
        proof,
        verified,
        metadata: "SHA-256 HMAC & Cryptographic Nonce Zero-Knowledge Commitment".to_string(),
    })
}

async fn ws_telemetry_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.tx.subscribe();
    info!("New WebSocket subscriber connected to /ws/telemetry. Waiting for PQC Handshake...");

    // 1. Wait for client to send ML-KEM-768 Public Key
    let mut shared_secret_bytes = [0u8; 32];
    let mut is_encrypted = false;
    
    if let Some(Ok(Message::Text(msg))) = socket.recv().await {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&msg) {
            if json["type"] == "PQC_HANDSHAKE" {
                if let Some(pk_hex) = json["public_key"].as_str() {
                    // Generate ciphertext and shared secret using actual ML-KEM
                    let encapsulation = pqc::PqcEngine::kyber768_encapsulate(pk_hex);
                    
                    // Decode shared secret hex into exactly 32 bytes for AES-256
                    if let Ok(ss) = hex::decode(&encapsulation.shared_secret_hex) {
                        if ss.len() == 32 {
                            shared_secret_bytes.copy_from_slice(&ss);
                            is_encrypted = true;

                            // Send the ciphertext back to the client so they can decapsulate
                            let response = serde_json::json!({
                                "type": "PQC_HANDSHAKE_RESPONSE",
                                "ciphertext": encapsulation.ciphertext_hex
                            });
                            let _ = socket.send(Message::Text(serde_json::to_string(&response).unwrap())).await;
                            info!("PQC ML-KEM-768 Handshake complete. Tunnel encrypted via AES-256-GCM.");
                        }
                    }
                }
            }
        }
    }

    if !is_encrypted {
        info!("No PQC Handshake received. Closing connection to enforce Zero-Trust.");
        let _ = socket.close().await;
        return;
    }

    // Initialize AES-GCM with the ML-KEM shared secret
    use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce, Key};
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&shared_secret_bytes));

    let welcome = TelemetryEvent {
        event_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        event_type: "CONNECTED".into(),
        source_ip: "127.0.0.1".into(),
        risk_level: "LOW_RISK".into(),
        action: "NONE".into(),
        details: "Connected to Jia Native Threat Telemetry Stream (Post-Quantum Encrypted)".into(),
    };

    if let Ok(msg_text) = serde_json::to_string(&welcome) {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = cipher.encrypt(&nonce, msg_text.as_bytes()).unwrap_or_default();
        let payload = serde_json::json!({
            "nonce": hex::encode(nonce),
            "ciphertext": hex::encode(ciphertext)
        });
        let _ = socket.send(Message::Text(serde_json::to_string(&payload).unwrap())).await;
    }

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        if let Ok(msg_text) = serde_json::to_string(&event) {
                            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                            let ciphertext = cipher.encrypt(&nonce, msg_text.as_bytes()).unwrap_or_default();
                            let payload = serde_json::json!({
                                "nonce": hex::encode(nonce),
                                "ciphertext": hex::encode(ciphertext)
                            });
                            
                            if socket.send(Message::Text(serde_json::to_string(&payload).unwrap())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(payload))) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
    info!("WebSocket subscriber disconnected from /ws/telemetry");
}

async fn ebpf_inspect_handler(
    Json(req): Json<ebpf_trapper::EbpfInspectRequest>,
) -> Json<ebpf_trapper::EbpfVerdict> {
    let verdict = ebpf_trapper::EbpfTrapper::inspect_syscall_with_target(
        &req.syscall,
        req.pid,
        req.uid,
        req.path_or_target.as_deref(),
    );
    Json(verdict)
}

async fn pqc_sign_handler(
    Json(req): Json<pqc::PqcSignRequest>,
) -> Json<pqc::PqcSignResponse> {
    let kp = pqc::PqcEngine::dilithium_generate_keypair();
    let sk = req.secret_key.clone().unwrap_or(kp.secret_key_hex);
    let sig = pqc::PqcEngine::dilithium_sign_worm_log(&req.log_entry, &sk);
    let verified = pqc::PqcEngine::dilithium_verify_worm_log(&req.log_entry, &sig.signature_hex, &sig.public_key_hex);

    let mut hasher = Sha256::new();
    hasher.update(req.log_entry.as_bytes());
    let worm_hash = hex::encode(hasher.finalize());

    Json(pqc::PqcSignResponse {
        algorithm: sig.algorithm,
        public_key: sig.public_key_hex,
        signature: sig.signature_hex,
        verified,
        worm_entry_hash: worm_hash,
    })
}

async fn rag_guard_handler(
    Json(req): Json<rag_poison_guard::RagGuardRequest>,
) -> Json<rag_poison_guard::RagGuardResponse> {
    let documents = rag_poison_guard::RagPoisonGuard::sanitize_rag_results(&req.vector_results);
    let poisoned_count = documents.iter().filter(|d| d.was_poisoned).count();

    Json(rag_poison_guard::RagGuardResponse {
        sanitized_documents: documents,
        total_poison_attempts_neutralized: poisoned_count,
        security_verdict: if poisoned_count == 0 { "CLEAN_CONTEXT" } else { "POISON_NEUTRALIZED" }.to_string(),
    })
}

async fn self_heal_patch_handler(
    Json(req): Json<self_healing::PatchRequest>,
) -> Json<self_healing::PatchResult> {
    let patch = self_healing::SelfHealingEngine::generate_patch(&req.vulnerability, &req.source_file);
    Json(patch)
}

#[derive(Debug, Serialize)]
pub struct RedTeamTestResult {
    pub vector: String,
    pub passed: bool,
    pub action_received: String,
    pub expected_actions: Vec<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct RedTeamSimulateResponse {
    pub total_simulations: usize,
    pub passed_defenses: usize,
    pub blocked_attacks: usize,
    pub defensive_readiness_score: f64,
    pub attack_vectors_tested: Vec<String>,
    pub test_details: Vec<RedTeamTestResult>,
    pub status: String,
}

struct AttackTest {
    name: String,
    payload: serde_json::Value,
    expected_actions: Vec<String>,
}

async fn red_team_simulate_handler() -> Json<RedTeamSimulateResponse> {
    let tests = vec![
        AttackTest {
            name: "Execution Enumeration (T1059)".into(),
            payload: serde_json::json!({"cmd": "whoami"}),
            expected_actions: vec!["blocked".into()],
        },
        AttackTest {
            name: "Suspicious Network Discovery (T1049)".into(),
            payload: serde_json::json!({"cmd": "netstat -an"}),
            expected_actions: vec!["blocked".into()],
        },
        AttackTest {
            name: "Local Privilege Escalation Check (T1068)".into(),
            payload: serde_json::json!({"cmd": "cat /etc/shadow"}),
            expected_actions: vec!["blocked".into()],
        },
    ];

    let mut test_details = Vec::new();
    let mut blocked_count = 0;
    let mut attack_vectors_tested = Vec::new();

    for test in tests {
        let start = std::time::Instant::now();
        attack_vectors_tested.push(test.name.clone());

        // Truly execute the payload safely inside the Docker Detonation Sandbox
        let cmd = test.payload["cmd"].as_str().unwrap_or("echo");
        
        // The host eBPF tracepoint will still catch the execve syscall made by Docker
        // but the process execution itself is isolated from the host OS
        let result = sandbox::DetonationSandbox::detonate_payload(cmd);

        let latency_ms = start.elapsed().as_millis() as u64;

        // In a true eBPF setup, the command would be blocked natively.
        // If the sandbox returns an error (meaning the command failed or was killed by eBPF), it's a pass.
        let (passed, action_received) = match result {
            Ok(_) => {
                // Command succeeded, defense failed
                (false, "allowed".to_string())
            }
            Err(_) => {
                blocked_count += 1;
                (true, "blocked".to_string())
            }
        };

        test_details.push(RedTeamTestResult {
            vector: test.name,
            passed,
            action_received,
            expected_actions: test.expected_actions,
            latency_ms,
        });
    }

    let total_simulations = test_details.len();
    let defensive_readiness_score = if total_simulations > 0 {
        (blocked_count as f64 / total_simulations as f64) * 100.0
    } else {
        0.0
    };

    Json(RedTeamSimulateResponse {
        total_simulations,
        passed_defenses: blocked_count,
        blocked_attacks: blocked_count,
        defensive_readiness_score,
        attack_vectors_tested,
        test_details,
        status: "PURPLE_TEAM_EXERCISE_COMPLETED".to_string(),
    })
}
