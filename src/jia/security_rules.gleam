import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

pub type RiskClassification {
  LowRisk
  MediumRisk
  HighRisk
  CriticalRisk
}

pub type ActionType {
  Allow
  Block
  Quarantine
}

pub type SecurityLog {
  SecurityLog(
    source_ip: String,
    payload: String,
    prompt: Option(String),
    user_id: Option(String),
  )
}

pub type AnalysisReport {
  AnalysisReport(
    risk_level: RiskClassification,
    prompt_injection: Bool,
    anomaly_score: Float,
    zero_trust_action: ActionType,
    rule_triggers: List(String),
  )
}

pub fn risk_to_string(risk: RiskClassification) -> String {
  case risk {
    LowRisk -> "LOW_RISK"
    MediumRisk -> "MEDIUM_RISK"
    HighRisk -> "HIGH_RISK"
    CriticalRisk -> "CRITICAL_RISK"
  }
}

pub fn action_to_string(action: ActionType) -> String {
  case action {
    Allow -> "allow"
    Block -> "block"
    Quarantine -> "quarantine"
  }
}

pub fn detect_prompt_injection(text: String) -> Bool {
  let lower = string.lowercase(text)
  let patterns = [
    "ignore previous instructions",
    "ignore all instructions",
    "ignore all previous instructions",
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
    "drop table",
  ]
  list.any(patterns, fn(pattern) { string.contains(lower, pattern) })
}

pub fn score_anomaly(payload: String) -> Float {
  let len = string.length(payload)
  let lower = string.lowercase(payload)
  
  let len_score = case len {
    _ if len > 2048 -> 0.6
    _ if len > 512 -> 0.3
    _ -> 0.0
  }

  let hex_score = case string.contains(lower, "0xdeadbeef") || string.contains(lower, "\\x90\\x90") {
    True -> 0.9
    False -> 0.0
  }

  let sql_score = case string.contains(lower, "select") || string.contains(lower, "exec") || string.contains(lower, "system") {
    True -> 0.4
    False -> 0.0
  }

  let total = len_score +. hex_score +. sql_score
  case total >. 1.0 {
    True -> 1.0
    False -> total
  }
}

pub fn classify_event(log: SecurityLog) -> AnalysisReport {
  let prompt_text = case log.prompt {
    Some(p) -> p
    None -> ""
  }
  let combined_text = prompt_text <> " " <> log.payload

  let prompt_inj = detect_prompt_injection(combined_text)
  let anomaly = score_anomaly(log.payload)

  let mut_triggers = []
  let mut_triggers = case prompt_inj {
    True -> ["RULE_PROMPT_INJECTION_DETECTED", ..mut_triggers]
    False -> mut_triggers
  }
  let mut_triggers = case anomaly >. 0.5 {
    True -> ["RULE_ANOMALOUS_PAYLOAD_STRUCTURE", ..mut_triggers]
    False -> mut_triggers
  }
  let mut_triggers = case string.contains(string.lowercase(log.payload), "0xdeadbeef") {
    True -> ["RULE_ZERO_DAY_EXPLOIT_SIGNATURE", ..mut_triggers]
    False -> mut_triggers
  }

  let risk = case prompt_inj && anomaly >. 0.3, anomaly >. 0.8, prompt_inj {
    True, _, _ -> CriticalRisk
    _, True, _ -> CriticalRisk
    _, _, True -> HighRisk
    _, _, _ -> case anomaly >. 0.4 {
      True -> MediumRisk
      False -> LowRisk
    }
  }

  let action = case risk {
    CriticalRisk -> Quarantine
    HighRisk -> Block
    MediumRisk -> Block
    LowRisk -> Allow
  }

  AnalysisReport(
    risk_level: risk,
    prompt_injection: prompt_inj,
    anomaly_score: anomaly,
    zero_trust_action: action,
    rule_triggers: list.reverse(mut_triggers),
  )
}

pub type StrideCategory {
  Spoofing
  Tampering
  Repudiation
  InformationDisclosure
  DenialOfService
  ElevationOfPrivilege
}

pub type StrideThreat {
  StrideThreat(
    category: StrideCategory,
    threat_name: String,
    detected: Bool,
    description: String,
  )
}

pub type StrideReport {
  StrideReport(
    threats: List(StrideThreat),
    total_detected: Int,
    is_compliant: Bool,
  )
}

pub fn stride_category_to_string(category: StrideCategory) -> String {
  case category {
    Spoofing -> "SPOOFING"
    Tampering -> "TAMPERING"
    Repudiation -> "REPUDIATION"
    InformationDisclosure -> "INFORMATION_DISCLOSURE"
    DenialOfService -> "DENIAL_OF_SERVICE"
    ElevationOfPrivilege -> "ELEVATION_OF_PRIVILEGE"
  }
}

pub fn verify_stride_threats(
  log: SecurityLog,
  request_count: Int,
  body_size_bytes: Int,
) -> StrideReport {
  let prompt_str = case log.prompt {
    Some(p) -> p
    None -> ""
  }
  let combined = prompt_str <> " " <> log.payload
  let lower_combined = string.lowercase(combined)

  // 1. Spoofing check: missing/invalid source IP or spoofed forwarding header
  let spoofing_detected =
    log.source_ip == "" || string.contains(lower_combined, "x-forwarded-for: 127.0.0.1")
  let spoofing_threat =
    StrideThreat(
      category: Spoofing,
      threat_name: "SPOOFED_IDENTITY_OR_IP",
      detected: spoofing_detected,
      description: "Source IP missing or spoofed identity header present",
    )

  // 2. Tampering check: prompt injection or payload anomaly / SQL injection
  let tampering_detected =
    detect_prompt_injection(combined) || score_anomaly(log.payload) >. 0.5
  let tampering_threat =
    StrideThreat(
      category: Tampering,
      threat_name: "UNAUTHORIZED_PAYLOAD_TAMPERING",
      detected: tampering_detected,
      description: "Prompt injection, SQL injection, or malicious payload modification detected",
    )

  // 3. Repudiation check: unauthenticated high-risk action missing user_id
  let repudiation_detected = case log.user_id {
    None -> string.length(log.payload) > 100 || tampering_detected
    Some("") -> True
    Some(_) -> False
  }
  let repudiation_threat =
    StrideThreat(
      category: Repudiation,
      threat_name: "UNATTRIBUTED_CRITICAL_ACTION",
      detected: repudiation_detected,
      description: "High-risk operation performed without authenticated user identity for audit trail",
    )

  // 4. Information Disclosure check: prompt leak, env dump, PII patterns
  let info_disc_detected =
    string.contains(lower_combined, "system prompt")
    || string.contains(lower_combined, "dump")
    || string.contains(lower_combined, "password")
    || string.contains(lower_combined, "/config/env")
    || string.contains(lower_combined, "ssn")
    || string.contains(lower_combined, "api_key")
  let info_disc_threat =
    StrideThreat(
      category: InformationDisclosure,
      threat_name: "SENSITIVE_INFORMATION_LEAK",
      detected: info_disc_detected,
      description: "System prompt leak, secret exfiltration, or PII disclosure attempt",
    )

  // 5. Denial of Service check: rate limit exceed (> 300) or oversized payload (> 2MB)
  let dos_detected =
    request_count > 300 || body_size_bytes > 2_097_152 || string.length(log.payload) > 100_000
  let dos_threat =
    StrideThreat(
      category: DenialOfService,
      threat_name: "RESOURCE_EXHAUSTION_DOS",
      detected: dos_detected,
      description: "Request flood rate or oversized payload body triggering Denial of Service condition",
    )

  // 6. Elevation of Privilege check: DAN mode, safety bypass, privilege escalation
  let eop_detected =
    string.contains(lower_combined, "dan mode")
    || string.contains(lower_combined, "bypass safety")
    || string.contains(lower_combined, "admin")
    || string.contains(lower_combined, "ptrace")
    || string.contains(lower_combined, "sudo")
  let eop_threat =
    StrideThreat(
      category: ElevationOfPrivilege,
      threat_name: "PRIVILEGE_ESCALATION_JAILBREAK",
      detected: eop_detected,
      description: "DAN jailbreak, administrative bypass, or kernel ptrace privilege escalation attempt",
    )

  let all_threats = [
    spoofing_threat,
    tampering_threat,
    repudiation_threat,
    info_disc_threat,
    dos_threat,
    eop_threat,
  ]

  let detected_count =
    list.fold(all_threats, 0, fn(acc, threat) {
      case threat.detected {
        True -> acc + 1
        False -> acc
      }
    })

  StrideReport(
    threats: all_threats,
    total_detected: detected_count,
    is_compliant: detected_count == 0,
  )
}

