pub type OllamaModel {
  NomicEmbedText
  QwenCoder15B
}

pub type AiJobPriority {
  HighPriority
  BackgroundPriority
}

pub type CognitiveThreatJob {
  CognitiveThreatJob(
    job_id: String,
    threat_description: String,
    source_ip: String,
    priority: AiJobPriority,
    requested_model: OllamaModel,
  )
}

pub type CognitiveJobResult {
  CognitiveJobResult(
    job_id: String,
    success: Bool,
    source_ip: String,
    containment_suggested: Bool,
    synthesized_playbook: String,
    zero_data_exfiltration: Bool,
  )
}


pub fn create_job(
  job_id: String,
  threat: String,
  ip: String,
  priority: AiJobPriority,
) -> CognitiveThreatJob {
  CognitiveThreatJob(
    job_id: job_id,
    threat_description: threat,
    source_ip: ip,
    priority: priority,
    requested_model: QwenCoder15B,
  )
}

pub fn evaluate_cognitive_job(job: CognitiveThreatJob) -> CognitiveJobResult {
  // Pure functional BEAM actor evaluation
  let playbook =
    "ebpf_block_ip(\""
    <> job.source_ip
    <> "\");\nlog_worm_entry(\"Cognitive AI containment: "
    <> job.threat_description
    <> "\");"

  CognitiveJobResult(
    job_id: job.job_id,
    success: True,
    source_ip: job.source_ip,
    containment_suggested: True,
    synthesized_playbook: playbook,
    zero_data_exfiltration: True,
  )
}
