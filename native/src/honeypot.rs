use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{AppState, TelemetryEvent, WormAuditEntry};

pub const HONEYPOT_ENDPOINTS: &[&str] = &[
    "/api/v1/admin/db_backup",
    "/config/env",
    "/root/ssh_keys",
];

pub fn is_honeypot_endpoint(path: &str) -> bool {
    HONEYPOT_ENDPOINTS.contains(&path)
}

#[derive(Debug, Deserialize)]
pub struct HoneypotPayload {
    pub payload: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HoneypotTrapResponse {
    pub status: String,
    pub error: String,
    pub message: String,
    pub quarantined: bool,
    pub target_ip: String,
    pub worm_log_id: usize,
    pub worm_hash: String,
}

pub async fn honeypot_handler(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Option<Json<HoneypotPayload>>,
) -> impl IntoResponse {
    let path = uri.path();
    let source_ip = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .or_else(|| headers.get("x-real-ip").and_then(|h| h.to_str().ok()))
        .unwrap_or("127.0.0.1")
        .trim()
        .to_string();

    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown Bot/Scanner")
        .to_string();

    let bot_payload = body
        .and_then(|b| b.payload.clone())
        .unwrap_or_else(|| format!("Bot unauthorized scan request to trap endpoint '{}'", path));

    // 1. Log WORM Audit Entry
    let mut logs = state.worm_logs.lock().unwrap();
    let id = logs.len() + 1;
    let prev_hash = logs
        .last()
        .map(|entry| entry.hash.clone())
        .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".into());

    let reason = format!(
        "Honeypot trap triggered on endpoint '{}' (UA: {}, Payload: {})",
        path, user_agent, bot_payload
    );

    let worm_entry = WormAuditEntry::new(
        id,
        source_ip.clone(),
        reason.clone(),
        "HONEYPOT_QUARANTINE".into(),
        prev_hash,
    );
    logs.push(worm_entry.clone());

    // 2. Neutralize attack via Vella CyberCommand
    let _ = state.cyber_command.detect_zero_day_apt(&format!(
        "HONEYPOT TRAP TRIGGERED: target={} endpoint={} payload={}",
        source_ip, path, bot_payload
    ));

    // 3. Broadcast telemetry event to active WebSocket subscribers
    let telemetry = TelemetryEvent {
        event_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        event_type: "HONEYPOT_TRAP".into(),
        source_ip: source_ip.clone(),
        risk_level: "CRITICAL_RISK".into(),
        action: "QUARANTINE".into(),
        details: format!("Decoy trap triggered on '{}': {}", path, reason),
    };
    let _ = state.tx.send(telemetry);

    (
        StatusCode::FORBIDDEN,
        Json(HoneypotTrapResponse {
            status: "quarantined".into(),
            error: "Access Denied".into(),
            message: "Decoy trap triggered. Target IP has been placed into immediate quarantine.".into(),
            quarantined: true,
            target_ip: source_ip,
            worm_log_id: worm_entry.id,
            worm_hash: worm_entry.hash,
        }),
    )
}
