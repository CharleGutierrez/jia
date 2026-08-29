import gleam/list
import gleam/option.{type Option, None, Some}

pub type HoneypotTrap {
  HoneypotTrap(
    path: String,
    source_ip: String,
    user_agent: String,
    payload: Option(String),
  )
}

pub type HoneypotResult {
  HoneypotResult(
    is_trap: Bool,
    action: String,
    target_ip: String,
    reason: String,
  )
}

pub const honeypot_endpoints = [
  "/api/v1/admin/db_backup",
  "/config/env",
  "/root/ssh_keys",
]

pub fn is_honeypot_path(path: String) -> Bool {
  list.contains(honeypot_endpoints, path)
}

pub fn evaluate_honeypot_trap(trap: HoneypotTrap) -> HoneypotResult {
  case is_honeypot_path(trap.path) {
    True -> {
      let payload_str = case trap.payload {
        Some(p) -> p
        None -> "No payload"
      }
      let reason =
        "Honeypot trap triggered on endpoint: "
        <> trap.path
        <> " (UA: "
        <> trap.user_agent
        <> ", Payload: "
        <> payload_str
        <> ")"
      HoneypotResult(
        is_trap: True,
        action: "quarantine",
        target_ip: trap.source_ip,
        reason: reason,
      )
    }
    False ->
      HoneypotResult(
        is_trap: False,
        action: "allow",
        target_ip: trap.source_ip,
        reason: "Normal path",
      )
  }
}
