import gleam/int
import gleam/list
import gleam/string

pub type ThreatIndicator {
  ThreatIndicator(
    source_ip: String,
    ttp: String,
    anomaly_weight: Float,
    observed_endpoint: String,
    timestamp: String,
  )
}

pub type CorrelatedAttackCampaign {
  CorrelatedAttackCampaign(
    campaign_id: String,
    adversary_ip: String,
    confidence_score: Float,
    attack_chain_length: Int,
    mitre_techniques: List(String),
    suggested_rhai_playbook: String,
    containment_status: String,
  )
}

pub type HunterReport {
  HunterReport(
    total_indicators_analyzed: Int,
    campaigns_discovered: List(CorrelatedAttackCampaign),
    highest_threat_score: Float,
    recommended_action: String,
  )
}

pub fn correlate_events(indicators: List(ThreatIndicator)) -> HunterReport {
  // Group indicators by adversary IP
  let distinct_ips =
    indicators
    |> list.map(fn(i) { i.source_ip })
    |> list.unique

  let campaigns =
    list.filter_map(distinct_ips, fn(ip) {
      let matching = list.filter(indicators, fn(i) { i.source_ip == ip })
      let count = list.length(matching)

      case count >= 2 {
        True -> {
          let techniques = list.map(matching, fn(m) { m.ttp })
          let total_weight =
            list.fold(matching, 0.0, fn(acc, m) { acc +. m.anomaly_weight })
          let confidence = { total_weight /. int.to_float(count) } *. 100.0

          let playbook =
            "// Auto-synthesized Threat Hunter containment playbook for: "
            <> ip
            <> "\nlet ip_res = block_ip(\""
            <> ip
            <> "\");\nlet worm_res = record_worm_log(\""
            <> ip
            <> "\", \"Correlated Multi-Stage APT Attack\", \"AUTONOMOUS_HUNT_QUARANTINE\");\nlog_error(\"Autonomous Threat Hunter isolated APT adversary: "
            <> ip
            <> "\");"

          Ok(
            CorrelatedAttackCampaign(
              campaign_id: "CAMP-" <> string.slice(ip, 0, 8),
              adversary_ip: ip,
              confidence_score: confidence,
              attack_chain_length: count,
              mitre_techniques: list.unique(techniques),
              suggested_rhai_playbook: playbook,
              containment_status: "AUTOMATED_CONTAINMENT_PENDING",
            ),
          )
        }
        False -> Error(Nil)
      }
    })

  let highest_score =
    list.fold(campaigns, 0.0, fn(acc, c) {
      case c.confidence_score >. acc {
        True -> c.confidence_score
        False -> acc
      }
    })

  HunterReport(
    total_indicators_analyzed: list.length(indicators),
    campaigns_discovered: campaigns,
    highest_threat_score: highest_score,
    recommended_action: case campaigns != [] {
      True -> "EXECUTE_AUTONOMOUS_CONTAINMENT"
      False -> "MONITORING_CLEAN"
    },

  )
}
