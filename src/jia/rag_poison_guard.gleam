import gleam/list
import gleam/string
import jia/firewall

pub type SanitizedDoc {
  SanitizedDoc(
    original_index: Int,
    sanitized_text: String,
    stripped_threats: List(String),
    was_poisoned: Bool,
  )
}

pub type RagGuardResult {
  RagGuardResult(
    sanitized_documents: List(SanitizedDoc),
    total_poison_attempts_neutralized: Int,
    is_safe: Bool,
  )
}

/// Sanitizes RAG vector search documents by stripping zero-width exfiltration characters
/// and neutralizing indirect prompt injection overrides.
pub fn sanitize_rag_context(documents: List(String)) -> RagGuardResult {
  let zero_width_chars = ["\u{200B}", "\u{200C}", "\u{200D}", "\u{FEFF}", "\u{202E}"]

  let results =
    list.index_map(documents, fn(doc, idx) {
      let #(clean_doc, zw_found) =
        list.fold(zero_width_chars, #(doc, False), fn(acc, zwc) {
          let #(current, found) = acc
          case string.contains(current, zwc) {
            True -> #(string.replace(current, each: zwc, with: ""), True)
            False -> #(current, found)
          }
        })

      let guardrail = firewall.check_prompt_guardrails(clean_doc)
      let threats = guardrail.detected_threats
      let threats = case zw_found {
        True -> ["ZERO_WIDTH_STEGANOGRAPHY", ..threats]
        False -> threats
      }

      let was_poisoned = !list.is_empty(threats)

      SanitizedDoc(
        original_index: idx,
        sanitized_text: guardrail.sanitized_prompt,
        stripped_threats: threats,
        was_poisoned: was_poisoned,
      )
    })

  let total_neutralized =
    list.fold(results, 0, fn(acc, res) {
      case res.was_poisoned {
        True -> acc + 1
        False -> acc
      }
    })

  let is_safe = total_neutralized == 0

  RagGuardResult(
    sanitized_documents: results,
    total_poison_attempts_neutralized: total_neutralized,
    is_safe: is_safe,
  )
}
