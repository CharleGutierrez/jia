use axum::{
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::process::Command;
use uuid::Uuid;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    pub block_details: String,
}

pub fn is_ip_safe_to_block(ip: &str) -> bool {
    if ip.trim().is_empty() {
        return false;
    }
    
    // Parse IP
    let parsed_ip: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    match parsed_ip {
        IpAddr::V4(ipv4) => {
            if ipv4 == Ipv4Addr::new(127, 0, 0, 1) || ipv4 == Ipv4Addr::new(0, 0, 0, 0) {
                return false;
            }
            let octets = ipv4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return false;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                return false;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            if ipv6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1) || ipv6 == Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) {
                return false;
            }
            true
        }
    }
}

pub fn block_ip_with_iptables(ip: &str) -> Result<String, String> {
    let mut messages = Vec::new();

    // Check IP type
    let is_ipv6 = ip.contains(':');
    let cmd_name = if is_ipv6 { "ip6tables" } else { "iptables" };

    let check_cmd = Command::new(cmd_name)
        .args(&["-C", "INPUT", "-s", ip, "-j", "DROP"])
        .output();
    
    let mut block_success = false;

    if let Ok(output) = check_cmd {
        if output.status.success() {
            messages.push(format!("IP {} is already blocked in {}", ip, cmd_name));
            block_success = true;
        } else {
            let add_cmd = Command::new(cmd_name)
                .args(&["-A", "INPUT", "-s", ip, "-j", "DROP"])
                .output();
            if let Ok(add_output) = add_cmd {
                if add_output.status.success() {
                    messages.push(format!("Successfully blocked {} using {}", ip, cmd_name));
                    block_success = true;
                } else {
                    messages.push(format!("Failed to block {} using {}: permission denied or error", ip, cmd_name));
                }
            } else {
                messages.push(format!("Failed to execute {} -A", cmd_name));
            }
        }
    } else {
        messages.push(format!("Failed to execute {} -C", cmd_name));
    }

    if !block_success {
        // Fallback to writing to /tmp/jia_blocked_ips.txt
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/jia_blocked_ips.txt")
        {
            if let Err(e) = writeln!(file, "{}", ip) {
                messages.push(format!("Failed to fallback write to /tmp/jia_blocked_ips.txt: {}", e));
                return Err(messages.join("; "));
            } else {
                messages.push(format!("Fallback: wrote {} to /tmp/jia_blocked_ips.txt", ip));
            }
        } else {
            messages.push("Failed to open /tmp/jia_blocked_ips.txt for fallback".to_string());
            return Err(messages.join("; "));
        }
    }

    // Try Redis blocking
    let client = redis::Client::open("redis://127.0.0.1:6379/");
    if let Ok(client) = client {
        if let Ok(mut con) = client.get_connection() {
            let _: redis::RedisResult<()> = redis::cmd("SADD").arg("jia:blocked_ips").arg(ip).query(&mut con);
            messages.push("Added to redis jia:blocked_ips".to_string());
        } else {
            messages.push("Could not connect to Redis".to_string());
        }
    } else {
        messages.push("Could not create Redis client".to_string());
    }

    Ok(messages.join("; "))
}

pub fn unblock_ip_with_iptables(ip: &str) -> Result<String, String> {
    let is_ipv6 = ip.contains(':');
    let cmd_name = if is_ipv6 { "ip6tables" } else { "iptables" };

    let output = Command::new(cmd_name)
        .args(&["-D", "INPUT", "-s", ip, "-j", "DROP"])
        .output();
    
    match output {
        Ok(out) => {
            if out.status.success() {
                Ok(format!("Successfully unblocked {} using {}", ip, cmd_name))
            } else {
                Err(format!("Failed to unblock {}: {}", ip, String::from_utf8_lossy(&out.stderr)))
            }
        }
        Err(e) => Err(format!("Failed to execute {} -D: {}", cmd_name, e)),
    }
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

    let block_result = if is_ip_safe_to_block(&source_ip) {
        block_ip_with_iptables(&source_ip)
    } else {
        Err("Skipping block: IP is loopback or private".to_string())
    };
    // Log the result
    tracing::warn!("Honeypot IP block result for {}: {:?}", source_ip, block_result);
    let block_details = match block_result {
        Ok(msg) => msg,
        Err(err) => err,
    };

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
            block_details,
        }),
    )
}
