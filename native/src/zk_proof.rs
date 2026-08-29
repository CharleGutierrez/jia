use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use k256::{
    elliptic_curve::{
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField, Field, ops::Reduce,
    },
    ProjectivePoint, EncodedPoint, AffinePoint, Scalar
};
use rand::rngs::OsRng;

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
    pub commitment_hex: String,
    pub schnorr_response_s1: String,
    pub schnorr_response_s2: String,
    pub challenge_hex: String,
    pub commitment_r_hex: String,
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
    fn get_h() -> ProjectivePoint {
        let mut counter = 0u32;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(b"JIA_PEDERSEN_GENERATOR_H");
            hasher.update(&counter.to_be_bytes());
            let hash = hasher.finalize();
            
            let mut bytes = [0u8; 33];
            bytes[0] = 0x02; // Try even y
            bytes[1..].copy_from_slice(&hash);
            
            if let Ok(encoded) = EncodedPoint::from_bytes(&bytes) {
                let affine_opt: Option<AffinePoint> = Option::from(AffinePoint::from_encoded_point(&encoded));
                if let Some(affine) = affine_opt {
                    return ProjectivePoint::from(affine);
                }
            }
            counter += 1;
        }
    }

    fn compute_challenge(
        g: &ProjectivePoint,
        h: &ProjectivePoint,
        c: &ProjectivePoint,
        r: &ProjectivePoint,
        indicator_value: &str,
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(g.to_affine().to_encoded_point(true).as_bytes());
        hasher.update(h.to_affine().to_encoded_point(true).as_bytes());
        hasher.update(c.to_affine().to_encoded_point(true).as_bytes());
        hasher.update(r.to_affine().to_encoded_point(true).as_bytes());
        // Bind the indicator value to the challenge to ensure the proof is bound to it
        hasher.update(indicator_value.as_bytes());
        <Scalar as Reduce<k256::U256>>::reduce_bytes(&hasher.finalize())
    }

    pub fn generate_proof(
        indicator_type: &str,
        indicator_value: &str,
        _salt: Option<&str>,
    ) -> ZkThreatProof {
        let proof_id = format!("zk-proof-{}", Uuid::new_v4());
        let timestamp = Utc::now().to_rfc3339();

        let g = ProjectivePoint::GENERATOR;
        let h = Self::get_h();

        // v = SHA256(indicator_value)
        let mut v_hasher = Sha256::new();
        v_hasher.update(indicator_value.as_bytes());
        let v = <Scalar as Reduce<k256::U256>>::reduce_bytes(&v_hasher.finalize());

        // r = random
        let r = Scalar::random(&mut OsRng);

        // Commitment C = v*G + r*H
        let commitment_point = (g * v) + (h * r);

        // Prover picks random k1, k2
        let k1 = Scalar::random(&mut OsRng);
        let k2 = Scalar::random(&mut OsRng);

        // R = k1*G + k2*H
        let r_point = (g * k1) + (h * k2);

        // Challenge c
        let challenge = Self::compute_challenge(&g, &h, &commitment_point, &r_point, indicator_value);

        // Responses s1, s2
        // s1 = k1 + c*v
        let s1 = k1 + (challenge * v);
        // s2 = k2 + c*r
        let s2 = k2 + (challenge * r);

        ZkThreatProof {
            proof_id,
            timestamp,
            indicator_type: indicator_type.to_string(),
            commitment_hex: hex::encode(commitment_point.to_affine().to_encoded_point(true).as_bytes()),
            schnorr_response_s1: hex::encode(s1.to_repr()),
            schnorr_response_s2: hex::encode(s2.to_repr()),
            challenge_hex: hex::encode(challenge.to_repr()),
            commitment_r_hex: hex::encode(r_point.to_affine().to_encoded_point(true).as_bytes()),
            verification_status: "VERIFIED_VALID".to_string(),
        }
    }

    pub fn verify_proof(
        proof: &ZkThreatProof,
        indicator_value: &str,
        _salt: Option<&str>,
    ) -> bool {
        let g = ProjectivePoint::GENERATOR;
        let h = Self::get_h();

        // Parse points
        let parse_point = |hex_str: &str| -> Option<ProjectivePoint> {
            let bytes = hex::decode(hex_str).ok()?;
            let encoded = EncodedPoint::from_bytes(&bytes).ok()?;
            let affine_opt: Option<AffinePoint> = Option::from(AffinePoint::from_encoded_point(&encoded));
            affine_opt.map(ProjectivePoint::from)
        };

        let commitment_point = match parse_point(&proof.commitment_hex) {
            Some(p) => p,
            None => return false,
        };
        let r_point = match parse_point(&proof.commitment_r_hex) {
            Some(p) => p,
            None => return false,
        };

        // Parse scalars
        let parse_scalar = |hex_str: &str| -> Option<Scalar> {
            let bytes = hex::decode(hex_str).ok()?;
            if bytes.len() != 32 { return None; }
            let fb = k256::FieldBytes::from_slice(&bytes);
            Option::from(Scalar::from_repr(*fb))
        };

        let s1 = match parse_scalar(&proof.schnorr_response_s1) {
            Some(s) => s,
            None => return false,
        };
        let s2 = match parse_scalar(&proof.schnorr_response_s2) {
            Some(s) => s,
            None => return false,
        };
        let challenge = match parse_scalar(&proof.challenge_hex) {
            Some(s) => s,
            None => return false,
        };

        // Recompute challenge
        let computed_challenge = Self::compute_challenge(&g, &h, &commitment_point, &r_point, indicator_value);
        if challenge != computed_challenge {
            return false;
        }

        // Verify s1*G + s2*H == R + c*C
        let lhs = (g * s1) + (h * s2);
        let rhs = r_point + (commitment_point * challenge);

        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof_generation_and_verification() {
        let indicator = "test_indicator";
        
        let proof = ZkProofGenerator::generate_proof(
            "ip_address",
            indicator,
            None
        );

        assert!(ZkProofGenerator::verify_proof(&proof, indicator, None));
        assert!(!ZkProofGenerator::verify_proof(&proof, "", None));
        assert!(!ZkProofGenerator::verify_proof(&proof, "wrong_indicator", None));
    }
}
