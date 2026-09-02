use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrosegPolicy {
    pub policy_id: String,
    pub source_workload: String,
    pub destination_workload: String,
    pub port: u16,
    pub protocol: String, // "TCP", "UDP", "TLS_1_3"
    pub allowed_alpn: Option<Vec<String>>,
    pub action: String, // "ALLOW", "DENY_DROP", "DENY_REJECT"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketFlowCheckRequest {
    pub source_workload: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub dest_port: u16,
    pub protocol: String,
    pub requested_alpn: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SocketFlowDecision {
    pub allowed: bool,
    pub matched_policy_id: Option<String>,
    pub action: String,
    pub reason: String,
    pub latency_us: u32,
}

pub struct MicrosegmentationEngine {
    policies: Vec<MicrosegPolicy>,
}

impl Default for MicrosegmentationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MicrosegmentationEngine {
    pub fn new() -> Self {
        let policies = vec![
            MicrosegPolicy {
                policy_id: "SEG-001".into(),
                source_workload: "api-gateway".into(),
                destination_workload: "vella-secops-engine".into(),
                port: 9090,
                protocol: "TCP".into(),
                allowed_alpn: Some(vec!["http/1.1".into(), "h2".into()]),
                action: "ALLOW".into(),
            },
            MicrosegPolicy {
                policy_id: "SEG-002".into(),
                source_workload: "beam-actor-cluster".into(),
                destination_workload: "vella-secops-engine".into(),
                port: 9090,
                protocol: "TCP".into(),
                allowed_alpn: None,
                action: "ALLOW".into(),
            },
            MicrosegPolicy {
                policy_id: "SEG-003".into(),
                source_workload: "untrusted-external".into(),
                destination_workload: "internal-database".into(),
                port: 5432,
                protocol: "TCP".into(),
                allowed_alpn: None,
                action: "DENY_DROP".into(),
            },
        ];

        Self { policies }
    }

    pub fn evaluate_socket_flow(&self, req: &SocketFlowCheckRequest) -> SocketFlowDecision {
        // Direct deny rule for untrusted -> internal DB
        if req.source_workload.contains("untrusted") && (req.dest_port == 5432 || req.dest_port == 6379 || req.dest_port == 22) {
            return SocketFlowDecision {
                allowed: false,
                matched_policy_id: Some("SEG-003".into()),
                action: "DENY_DROP".into(),
                reason: "Zero-Trust Microsegmentation violation: Untrusted workload prohibited from accessing internal database / management ports".into(),
                latency_us: 12,
            };
        }

        for p in &self.policies {
            if p.source_workload == req.source_workload && p.port == req.dest_port {
                if let (Some(allowed_alpns), Some(req_alpn)) = (&p.allowed_alpn, &req.requested_alpn) {
                    if !allowed_alpns.contains(req_alpn) {
                        return SocketFlowDecision {
                            allowed: false,
                            matched_policy_id: Some(p.policy_id.clone()),
                            action: "DENY_REJECT".into(),
                            reason: format!("ALPN mismatch: '{}' is not authorized under policy {}", req_alpn, p.policy_id),
                            latency_us: 15,
                        };
                    }
                }

                let is_allow = p.action == "ALLOW";
                return SocketFlowDecision {
                    allowed: is_allow,
                    matched_policy_id: Some(p.policy_id.clone()),
                    action: p.action.clone(),
                    reason: format!("Matched microsegmentation rule {}", p.policy_id),
                    latency_us: 10,
                };
            }
        }

        // Default Zero-Trust Stance: Deny if not explicitly whitelisted
        SocketFlowDecision {
            allowed: false,
            matched_policy_id: None,
            action: "DEFAULT_DENY".into(),
            reason: "Default Zero-Trust stance: No explicit ingress policy matched".into(),
            latency_us: 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_microsegmentation_flow_evaluation() {
        let engine = MicrosegmentationEngine::new();

        // 1. Authorized API gateway to Secops engine
        let req_auth = SocketFlowCheckRequest {
            source_workload: "api-gateway".into(),
            source_ip: "10.0.1.10".into(),
            dest_ip: "10.0.2.20".into(),
            dest_port: 9090,
            protocol: "TCP".into(),
            requested_alpn: Some("http/1.1".into()),
        };
        let dec_auth = engine.evaluate_socket_flow(&req_auth);
        assert!(dec_auth.allowed);
        assert_eq!(dec_auth.action, "ALLOW");

        // 2. Untrusted workload to database
        let req_db = SocketFlowCheckRequest {
            source_workload: "untrusted-external".into(),
            source_ip: "198.51.100.22".into(),
            dest_ip: "10.0.3.50".into(),
            dest_port: 5432,
            protocol: "TCP".into(),
            requested_alpn: None,
        };
        let dec_db = engine.evaluate_socket_flow(&req_db);
        assert!(!dec_db.allowed);
        assert_eq!(dec_db.action, "DENY_DROP");
    }
}
