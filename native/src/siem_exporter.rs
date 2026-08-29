use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{AppState, TelemetryEvent};

#[derive(Debug, Deserialize)]
pub struct SiemExportQuery {
    pub format: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SiemExportResponse {
    pub format: String,
    pub total_events: usize,
    pub cef_events: Option<Vec<String>>,
    pub syslog_events: Option<Vec<String>>,
    pub raw_export: String,
}

pub struct SiemExporter;

impl SiemExporter {
    /// Formats a single TelemetryEvent into ArcSight / Splunk Common Event Format (CEF)
    pub fn to_cef(event: &TelemetryEvent) -> String {
        let severity = match event.risk_level.as_str() {
            "CRITICAL_RISK" | "CRITICAL" => 10,
            "HIGH_RISK" | "HIGH" => 7,
            "MEDIUM_RISK" | "MEDIUM" => 5,
            _ => 2,
        };
        let escaped_details = event.details.replace('|', "\\|").replace('\n', " ");
        format!(
            "CEF:0|Jia|Jia-Native|0.1.0|{}|{}|{}|src={} act={} outcome={} msg={}",
            event.event_type,
            event.event_type,
            severity,
            event.source_ip,
            event.action,
            event.risk_level,
            escaped_details
        )
    }

    /// Formats a single TelemetryEvent into RFC 5424 / Datadog / Elastic Syslog format
    pub fn to_syslog(event: &TelemetryEvent) -> String {
        let pri = match event.risk_level.as_str() {
            "CRITICAL_RISK" | "CRITICAL" => 131, // Alert
            "HIGH_RISK" | "HIGH" => 132,         // Error
            "MEDIUM_RISK" | "MEDIUM" => 133,     // Warning
            _ => 134,                            // Notice
        };
        format!(
            "<{}>1 {} localhost jia - - - [telemetry@32473 event_id=\"{}\" source_ip=\"{}\" risk_level=\"{}\" action=\"{}\"] {}",
            pri,
            event.timestamp,
            event.event_id,
            event.source_ip,
            event.risk_level,
            event.action,
            event.details
        )
    }
}

pub async fn siem_export_handler(
    State(state): State<AppState>,
    Query(query): Query<SiemExportQuery>,
) -> impl IntoResponse {
    let logs = state.worm_logs.lock().unwrap();
    let limit = query.limit.unwrap_or(50);
    let requested_format = query.format.unwrap_or_else(|| "cef".into()).to_lowercase();

    // Map existing WORM log entries into telemetry events for SIEM export
    let mut events: Vec<TelemetryEvent> = logs
        .iter()
        .rev()
        .take(limit)
        .map(|entry| TelemetryEvent {
            event_id: format!("worm-{}", entry.id),
            timestamp: entry.timestamp.clone(),
            event_type: entry.action.clone(),
            source_ip: entry.target.clone(),
            risk_level: if entry.action.contains("QUARANTINE") || entry.action.contains("HONEYPOT") {
                "CRITICAL_RISK".into()
            } else {
                "MEDIUM_RISK".into()
            },
            action: entry.action.clone(),
            details: entry.reason.clone(),
        })
        .collect();

    // If logs are empty, generate synthetic initial system health telemetry event
    if events.is_empty() {
        events.push(TelemetryEvent {
            event_id: "sys-init-1".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: "SYSTEM_INITIALIZED".into(),
            source_ip: "127.0.0.1".into(),
            risk_level: "LOW_RISK".into(),
            action: "ALLOW".into(),
            details: "Jia Native SIEM Telemetry exporter active.".into(),
        });
    }

    let total = events.len();
    let (cef_vec, syslog_vec, raw_out) = match requested_format.as_str() {
        "syslog" => {
            let sys: Vec<String> = events.iter().map(SiemExporter::to_syslog).collect();
            let raw = sys.join("\n");
            (None, Some(sys), raw)
        }
        "all" => {
            let cef: Vec<String> = events.iter().map(SiemExporter::to_cef).collect();
            let sys: Vec<String> = events.iter().map(SiemExporter::to_syslog).collect();
            let raw = format!(
                "--- CEF LOGS ---\n{}\n\n--- SYSLOG LOGS ---\n{}",
                cef.join("\n"),
                sys.join("\n")
            );
            (Some(cef), Some(sys), raw)
        }
        _ => {
            let cef: Vec<String> = events.iter().map(SiemExporter::to_cef).collect();
            let raw = cef.join("\n");
            (Some(cef), None, raw)
        }
    };

    (
        StatusCode::OK,
        Json(SiemExportResponse {
            format: requested_format,
            total_events: total,
            cef_events: cef_vec,
            syslog_events: syslog_vec,
            raw_export: raw_out,
        }),
    )
}
