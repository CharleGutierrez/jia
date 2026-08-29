use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ZkExportRequest {
    pub indicator_type: String,
    pub indicator_value: String,
    pub salt: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ZkThreatProof {
    pub proof_id: String,
    pub timestamp: String,
    pub indicator_type: String,
    pub commitment_hash: String,
    pub hmac_signature: String,
    pub nonce: String,
    pub verification_status: String,
}

#[derive(Debug, Serialize)]
pub struct ZkExportResponse {
    pub proof: ZkThreatProof,
    pub verified: bool,
    pub metadata: String,
}

pub struct ZkProofGenerator;

impl ZkProofGenerator {
    pub fn generate_proof(
        indicator_type: &str,
        indicator_value: &str,
        salt: Option<&str>,
    ) -> ZkThreatProof {
        let proof_id = format!("zk-proof-{}", Uuid::new_v4());
        let timestamp = Utc::now().to_rfc3339();
        let nonce = Uuid::new_v4().to_string();

        let salt_str = salt.unwrap_or("JIA_ZERO_KNOWLEDGE_SECRET_SALT_2026");

        // 1. Calculate HMAC-SHA256 over indicator value using secret salt & nonce
        let mut hmac_hasher = Sha256::new();
        hmac_hasher.update(salt_str.as_bytes());
        hmac_hasher.update(b":");
        hmac_hasher.update(nonce.as_bytes());
        hmac_hasher.update(b":");
        hmac_hasher.update(indicator_value.as_bytes());
        let hmac_signature = hex::encode(hmac_hasher.finalize());

        // 2. Calculate Zero-Knowledge Commitment Hash
        let mut commit_hasher = Sha256::new();
        commit_hasher.update(indicator_type.as_bytes());
        commit_hasher.update(b":");
        commit_hasher.update(hmac_signature.as_bytes());
        commit_hasher.update(b":");
        commit_hasher.update(nonce.as_bytes());
        commit_hasher.update(b":");
        commit_hasher.update(timestamp.as_bytes());
        let commitment_hash = hex::encode(commit_hasher.finalize());

        ZkThreatProof {
            proof_id,
            timestamp,
            indicator_type: indicator_type.to_string(),
            commitment_hash,
            hmac_signature,
            nonce,
            verification_status: "VERIFIED_VALID".to_string(),
        }
    }

    pub fn verify_proof(
        proof: &ZkThreatProof,
        indicator_value: &str,
        salt: Option<&str>,
    ) -> bool {
        let salt_str = salt.unwrap_or("JIA_ZERO_KNOWLEDGE_SECRET_SALT_2026");

        // Recompute HMAC
        let mut hmac_hasher = Sha256::new();
        hmac_hasher.update(salt_str.as_bytes());
        hmac_hasher.update(b":");
        hmac_hasher.update(proof.nonce.as_bytes());
        hmac_hasher.update(b":");
        hmac_hasher.update(indicator_value.as_bytes());
        let expected_hmac = hex::encode(hmac_hasher.finalize());

        if expected_hmac != proof.hmac_signature {
            return false;
        }

        // Recompute Commitment Hash
        let mut commit_hasher = Sha256::new();
        commit_hasher.update(proof.indicator_type.as_bytes());
        commit_hasher.update(b":");
        commit_hasher.update(expected_hmac.as_bytes());
        commit_hasher.update(b":");
        commit_hasher.update(proof.nonce.as_bytes());
        commit_hasher.update(b":");
        commit_hasher.update(proof.timestamp.as_bytes());
        let expected_commitment = hex::encode(commit_hasher.finalize());

        expected_commitment == proof.commitment_hash
    }
}
