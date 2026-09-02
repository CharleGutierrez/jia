import gleam/list
import gleam/string

pub type HoneyTokenType {
  DecoyAwsKey
  DecoyJwt
  DecoyDbRow
  DecoySshKey
  CanaryMemoryPointer
}

pub type HoneyToken {
  HoneyToken(
    token_id: String,
    token_type: HoneyTokenType,
    token_value: String,
    planted_location: String,
    tripwire_action: String,
    created_at: String,
  )
}

pub type TripwireResult {
  TripwireResult(
    tripped: Bool,
    token_id: String,
    adversary_ip: String,
    token_type_name: String,
    containment_action: String,
    severity: String,
  )
}

pub fn generate_standard_tokens() -> List(HoneyToken) {
  [
    HoneyToken(
      token_id: "HT-AWS-001",
      token_type: DecoyAwsKey,
      token_value: "AKIAIOSFODNN7CANARYKEY",
      planted_location: "/config/aws/credentials",
      tripwire_action: "CLUSTER_IMMEDIATE_QUARANTINE",
      created_at: "2026-09-02T12:00:00Z",
    ),
    HoneyToken(
      token_id: "HT-JWT-002",
      token_type: DecoyJwt,
      token_value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.canary_admin_token.fake_sig",
      planted_location: "Authorization: Bearer <canary>",
      tripwire_action: "REVOKE_AND_BLOCK_IP",
      created_at: "2026-09-02T12:00:00Z",
    ),
    HoneyToken(
      token_id: "HT-SSH-003",
      token_type: DecoySshKey,
      token_value: "-----BEGIN CANARY RSA PRIVATE KEY-----",
      planted_location: "/root/.ssh/id_rsa_decoy",
      tripwire_action: "KERNEL_PRE_EXEC_BLOCK",
      created_at: "2026-09-02T12:00:00Z",
    ),
    HoneyToken(
      token_id: "HT-MEM-004",
      token_type: CanaryMemoryPointer,
      token_value: "0xdeadbeef_canary_0x9090",
      planted_location: "process_heap_offset_0x7ffe",
      tripwire_action: "EBPF_KILL_PROCESS",
      created_at: "2026-09-02T12:00:00Z",
    ),
  ]
}

pub fn evaluate_tripwire(
  tokens: List(HoneyToken),
  accessed_value: String,
  adversary_ip: String,
) -> TripwireResult {
  let matched_token =
    list.find(tokens, fn(tok) {
      string.contains(accessed_value, tok.token_value)
      || string.contains(tok.token_value, accessed_value)
    })

  case matched_token {
    Ok(tok) -> {
      let type_name = case tok.token_type {
        DecoyAwsKey -> "DECOY_AWS_SECRET_KEY"
        DecoyJwt -> "DECOY_JWT_TOKEN"
        DecoyDbRow -> "DECOY_DATABASE_ROW"
        DecoySshKey -> "DECOY_SSH_PRIVATE_KEY"
        CanaryMemoryPointer -> "CANARY_MEMORY_POINTER"
      }

      TripwireResult(
        tripped: True,
        token_id: tok.token_id,
        adversary_ip: adversary_ip,
        token_type_name: type_name,
        containment_action: tok.tripwire_action,
        severity: "CRITICAL_INSIDER_THREAT",
      )
    }
    Error(Nil) ->
      TripwireResult(
        tripped: False,
        token_id: "",
        adversary_ip: adversary_ip,
        token_type_name: "CLEAN_TRAFFIC",
        containment_action: "ALLOW",
        severity: "NONE",
      )
  }
}
