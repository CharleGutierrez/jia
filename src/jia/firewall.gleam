import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/regexp
import gleam/string

pub type ScrubResult {
  ScrubResult(
    original_text: String,
    scrubbed_text: String,
    redactions_count: Int,
    detected_pii_types: List(String),
  )
}

pub type GuardrailResult {
  GuardrailResult(
    is_safe: Bool,
    detected_threats: List(String),
    sanitized_prompt: String,
  )
}

pub type FirewallEvaluation {
  FirewallEvaluation(
    pii_scrub: ScrubResult,
    guardrail: GuardrailResult,
    is_allowed: Bool,
  )
}

pub fn scrub_pii(text: String) -> ScrubResult {
  let ssn_re = case regexp.from_string("\\b\\d{3}-\\d{2}-\\d{4}\\b") {
    Ok(re) -> re
    Error(_) -> panic as "Invalid SSN regex pattern"
  }

  let card_re = case regexp.from_string("\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b") {
    Ok(re) -> re
    Error(_) -> panic as "Invalid Credit Card regex pattern"
  }

  let api_key_re = case regexp.from_string("(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk_[a-zA-Z0-9]{24,})") {
    Ok(re) -> re
    Error(_) -> panic as "Invalid API key regex pattern"
  }

  let email_re = case regexp.from_string("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}") {
    Ok(re) -> re
    Error(_) -> panic as "Invalid email regex pattern"
  }

  let ssn_matches = regexp.scan(ssn_re, text)
  let card_matches = regexp.scan(card_re, text)
  let api_matches = regexp.scan(api_key_re, text)
  let email_matches = regexp.scan(email_re, text)

  let ssn_count = list.length(ssn_matches)
  let card_count = list.length(card_matches)
  let api_count = list.length(api_matches)
  let email_count = list.length(email_matches)

  let total_count = ssn_count + card_count + api_count + email_count

  let types = []
  let types = case ssn_count > 0 {
    True -> ["SSN", ..types]
    False -> types
  }
  let types = case card_count > 0 {
    True -> ["CREDIT_CARD", ..types]
    False -> types
  }
  let types = case api_count > 0 {
    True -> ["API_KEY", ..types]
    False -> types
  }
  let types = case email_count > 0 {
    True -> ["EMAIL_ADDRESS", ..types]
    False -> types
  }

  let text1 = regexp.replace(ssn_re, text, "[REDACTED_PII]")
  let text2 = regexp.replace(card_re, text1, "[REDACTED_PII]")
  let text3 = regexp.replace(api_key_re, text2, "[REDACTED_PII]")
  let scrubbed = regexp.replace(email_re, text3, "[REDACTED_PII]")

  ScrubResult(
    original_text: text,
    scrubbed_text: scrubbed,
    redactions_count: total_count,
    detected_pii_types: list.reverse(types),
  )
}

pub fn check_prompt_guardrails(prompt: String) -> GuardrailResult {
  let lower = string.lowercase(prompt)
  let patterns = [
    #("ignore previous instructions", "SYSTEM_INSTRUCTION_OVERRIDE"),
    #("ignore all instructions", "SYSTEM_INSTRUCTION_OVERRIDE"),
    #("ignore all previous instructions", "SYSTEM_INSTRUCTION_OVERRIDE"),
    #("system prompt", "SYSTEM_PROMPT_LEAK"),
    #("jailbreak", "JAILBREAK_ATTEMPT"),
    #("bypass safety", "SAFETY_BYPASS"),
    #("dan mode", "DAN_JAILBREAK"),
    #("<script>", "XSS_INJECTION"),
    #("eval(", "CODE_INJECTION"),
    #("' or 1=1", "SQL_INJECTION"),
  ]

  let threats =
    list.filter_map(patterns, fn(pair) {
      let #(kw, threat) = pair
      case string.contains(lower, kw) {
        True -> Ok(threat)
        False -> Error(Nil)
      }
    })

  let is_safe = list.is_empty(threats)

  let sanitized = list.fold(patterns, prompt, fn(acc, pair) {
    let #(kw, _) = pair
    case string.contains(string.lowercase(acc), kw) {
      True -> {
        let pattern_str = case kw {
          "eval(" -> "eval\\("
          "' or 1=1" -> "' or 1=1"
          other -> other
        }
        case regexp.from_string("(?i)" <> pattern_str) {
          Ok(re) -> regexp.replace(re, acc, "[FILTERED_PROMPT_INJECTION]")
          Error(_) -> acc
        }
      }
      False -> acc
    }
  })

  GuardrailResult(
    is_safe: is_safe,
    detected_threats: threats,
    sanitized_prompt: sanitized,
  )
}

pub fn evaluate_payload_and_prompt(
  prompt: Option(String),
  payload: String,
) -> FirewallEvaluation {
  let prompt_str = case prompt {
    Some(p) -> p
    None -> ""
  }
  let full_input = prompt_str <> " " <> payload

  let pii_res = scrub_pii(full_input)
  let guardrail_res = check_prompt_guardrails(full_input)

  let is_allowed = guardrail_res.is_safe && pii_res.redactions_count == 0

  FirewallEvaluation(
    pii_scrub: pii_res,
    guardrail: guardrail_res,
    is_allowed: is_allowed,
  )
}
