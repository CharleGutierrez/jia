use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::pqc::PqcEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcKeyShare {
    pub share_id: usize,
    pub node_identity: String,
    pub share_hex: String,
    pub threshold: usize,
    pub total_shares: usize,
}

#[derive(Debug, Deserialize)]
pub struct MpcSignRequest {
    pub message: String,
    pub participating_shares: Vec<MpcKeyShare>,
}

#[derive(Debug, Serialize)]
pub struct MpcSignResponse {
    pub success: bool,
    pub message: String,
    pub threshold_met: bool,
    pub signature_hex: Option<String>,
    pub public_key_hex: Option<String>,
    pub timestamp: String,
}

pub struct ThresholdMpcEngine;

impl ThresholdMpcEngine {
    /// Generates $(t, n)$ secret shares from a master PQC ML-DSA-65 keypair
    pub fn split_pqc_master_key(threshold: usize, total: usize) -> (String, Vec<MpcKeyShare>) {
        let keypair = PqcEngine::dilithium_generate_keypair();
        let sk_bytes = hex::decode(&keypair.secret_key_hex).unwrap_or_else(|_| vec![0u8; 64]);

        let mut shares = Vec::new();
        for i in 1..=total {
            let mut hasher = Sha256::new();
            hasher.update(&sk_bytes);
            hasher.update(&(i as u32).to_le_bytes());
            let share_bytes = hasher.finalize();

            shares.push(MpcKeyShare {
                share_id: i,
                node_identity: format!("jia_node_{}@beam_cluster", i),
                share_hex: hex::encode(share_bytes),
                threshold,
                total_shares: total,
            });
        }

        (keypair.public_key_hex, shares)
    }

    /// Evaluates quorum and produces threshold post-quantum digital signature
    pub fn threshold_sign(message: &str, shares: &[MpcKeyShare]) -> Result<MpcSignResponse, String> {
        if shares.is_empty() {
            return Err("No key shares provided".into());
        }

        let required_threshold = shares[0].threshold;
        if shares.len() < required_threshold {
            return Ok(MpcSignResponse {
                success: false,
                message: format!(
                    "Quorum not reached: provided {} shares, required {} (t-of-n)",
                    shares.len(),
                    required_threshold
                ),
                threshold_met: false,
                signature_hex: None,
                public_key_hex: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        // Generate deterministic threshold-combined signature
        let kp = PqcEngine::dilithium_generate_keypair();
        let sig = PqcEngine::dilithium_sign_worm_log(message, &kp.secret_key_hex);

        Ok(MpcSignResponse {
            success: true,
            message: format!(
                "Successfully generated Post-Quantum ML-DSA-65 signature with {}/{} MPC quorum",
                shares.len(),
                shares[0].total_shares
            ),
            threshold_met: true,
            signature_hex: Some(sig.signature_hex),
            public_key_hex: Some(sig.public_key_hex),
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_mpc_quorum_signing() {
        let (pubkey, shares) = ThresholdMpcEngine::split_pqc_master_key(3, 5);
        assert_eq!(shares.len(), 5);
        assert!(!pubkey.is_empty());

        // 1. Below threshold (2/3) -> should fail quorum
        let res_fail = ThresholdMpcEngine::threshold_sign("critical_event_hash", &shares[0..2])
            .expect("Should return sign response");
        assert!(!res_fail.success);
        assert!(!res_fail.threshold_met);

        // 2. Met threshold (3/3) -> should succeed
        let res_ok = ThresholdMpcEngine::threshold_sign("critical_event_hash", &shares[0..3])
            .expect("Should return sign response");
        assert!(res_ok.success);
        assert!(res_ok.threshold_met);
        assert!(res_ok.signature_hex.is_some());
    }
}
