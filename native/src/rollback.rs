use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sqlx::{SqlitePool, Row};

use crate::{AppState, TelemetryEvent, WormAuditEntry};

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    pub target_version: Option<usize>,
    pub target_hash: Option<String>,
    pub reason: Option<String>,
    pub admin_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RollbackResponse {
    pub status: String,
    pub restored_version: usize,
    pub previous_logs_count: usize,
    pub current_logs_count: usize,
    pub restored_hash: String,
    pub message: String,
    pub rollback_audit_entry: WormAuditEntry,
}

pub struct WormDatabase {
    pub pool: SqlitePool,
}

impl WormDatabase {
    pub async fn connect(path: &str) -> Result<SqlitePool, sqlx::Error> {
        init_worm_db(path).await
    }
}

pub async fn init_worm_db(db_path: &str) -> Result<sqlx::SqlitePool, sqlx::Error> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(&format!("sqlite:{}?mode=rwc", db_path))
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS worm_audit_log (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            target TEXT NOT NULL,
            reason TEXT NOT NULL,
            action TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        );"
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

pub async fn persist_worm_entry(pool: &SqlitePool, entry: &WormAuditEntry) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO worm_audit_log (id, timestamp, target, reason, action, previous_hash, hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(entry.id as i64)
    .bind(&entry.timestamp)
    .bind(&entry.target)
    .bind(&entry.reason)
    .bind(&entry.action)
    .bind(&entry.previous_hash)
    .bind(&entry.hash)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn load_worm_entries_from_db(pool: &SqlitePool, up_to_id: usize) -> Vec<WormAuditEntry> {
    let rows = sqlx::query(
        "SELECT id, timestamp, target, reason, action, previous_hash, hash
         FROM worm_audit_log
         WHERE id <= ?
         ORDER BY id ASC"
    )
    .bind(up_to_id as i64)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    rows.into_iter().map(|row| {
        WormAuditEntry {
            id: row.get::<i64, _>("id") as usize,
            timestamp: row.get::<String, _>("timestamp"),
            target: row.get::<String, _>("target"),
            reason: row.get::<String, _>("reason"),
            action: row.get::<String, _>("action"),
            previous_hash: row.get::<String, _>("previous_hash"),
            hash: row.get::<String, _>("hash"),
        }
    }).collect()
}

pub async fn rollback_handler(
    State(state): State<AppState>,
    Json(req): Json<RollbackRequest>,
) -> impl IntoResponse {
    let mut logs = state.worm_logs.lock().unwrap();
    let prev_count = logs.len();

    if prev_count == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "status": "error",
                "message": "Cannot perform rollback on empty WORM audit log store."
            })),
        )
            .into_response();
    }

    // Determine target version from requested target_version or target_hash
    let target_idx = if let Some(target_ver) = req.target_version {
        if target_ver == 0 || target_ver > prev_count {
            prev_count - 1
        } else {
            target_ver - 1
        }
    } else if let Some(ref hash) = req.target_hash {
        logs.iter()
            .position(|entry| entry.hash == *hash)
            .unwrap_or_else(|| if prev_count > 1 { prev_count - 2 } else { 0 })
    } else {
        if prev_count > 1 {
            prev_count - 2
        } else {
            0
        }
    };

    // 1-Click Time-Travel State Restoration: Truncate WORM audit log state back to target snapshot
    logs.truncate(target_idx + 1);

    // After truncating the Vec, reload from DB to restore real state
    if let Ok(pool) = WormDatabase::connect("worm_audit.db").await {
        let restored = load_worm_entries_from_db(&pool, target_idx + 1).await;
        if !restored.is_empty() {
            *logs = restored;
        }
    }

    let restored_version = logs.len();
    let restored_hash = logs.last().map(|e| e.hash.clone()).unwrap_or_default();

    // Document the disaster recovery rollback event in the WORM chain
    let rollback_reason = req.reason.unwrap_or_else(|| {
        format!("1-Click Time-Travel Rollback executed to snapshot version {}", restored_version)
    });
    let rollback_id = restored_version + 1;

    let rollback_audit_entry = WormAuditEntry::new(
        rollback_id,
        "SYSTEM_STATE".into(),
        rollback_reason.clone(),
        "TIME_TRAVEL_ROLLBACK".into(),
        restored_hash.clone(),
    );
    logs.push(rollback_audit_entry.clone());

    if let Ok(pool) = WormDatabase::connect("worm_audit.db").await {
        let _ = persist_worm_entry(&pool, &rollback_audit_entry).await;
    }

    // Broadcast disaster recovery telemetry
    let telemetry = TelemetryEvent {
        event_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        event_type: "DISASTER_RECOVERY_ROLLBACK".into(),
        source_ip: "127.0.0.1".into(),
        risk_level: "HIGH_RISK".into(),
        action: "ROLLBACK_SUCCESS".into(),
        details: format!(
            "Rolled back system state from {} logs to snapshot version {}",
            prev_count, restored_version
        ),
    };
    let _ = state.tx.send(telemetry);

    (
        StatusCode::OK,
        Json(RollbackResponse {
            status: "success".into(),
            restored_version,
            previous_logs_count: prev_count,
            current_logs_count: logs.len(),
            restored_hash,
            message: format!("State successfully restored to snapshot version {}.", restored_version),
            rollback_audit_entry,
        }),
    )
        .into_response()
}
