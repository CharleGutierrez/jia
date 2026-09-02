use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::WormAuditEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofNode {
    pub hash: String,
    pub is_left: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInclusionProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub leaf_hash: String,
    pub root_hash: String,
    pub proof_path: Vec<MerkleProofNode>,
    pub quantum_root_signature: String,
    pub quantum_public_key: String,
    pub timestamp: String,
}

#[derive(Debug, Deserialize)]
pub struct MerkleProofRequest {
    pub log_id: usize,
}

#[derive(Debug, Serialize)]
pub struct MerkleProofResponse {
    pub success: bool,
    pub proof: Option<MerkleInclusionProof>,
    pub verified: bool,
    pub message: String,
}

pub struct MerkleWormTree {
    leaves: Vec<String>,
    levels: Vec<Vec<String>>,
}

impl MerkleWormTree {
    pub fn new(entries: &[WormAuditEntry]) -> Self {
        if entries.is_empty() {
            let empty_leaf = Self::hash_leaf("EMPTY_WORM_ROOT");
            return Self {
                leaves: vec![empty_leaf.clone()],
                levels: vec![vec![empty_leaf]],
            };
        }

        let leaves: Vec<String> = entries.iter().map(|e| e.hash.clone()).collect();
        let levels = Self::build_tree_levels(&leaves);

        Self { leaves, levels }
    }

    pub fn root_hash(&self) -> String {
        self.levels
            .last()
            .and_then(|lvl| lvl.first().cloned())
            .unwrap_or_else(|| "0000000000000000000000000000000000000000000000000000000000000000".into())
    }

    pub fn generate_inclusion_proof(&self, leaf_index: usize) -> Option<MerkleInclusionProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let leaf_hash = self.leaves[leaf_index].clone();
        let root_hash = self.root_hash();
        let mut proof_path = Vec::new();
        let mut idx = leaf_index;

        for level in &self.levels[0..self.levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < level.len() {
                proof_path.push(MerkleProofNode {
                    hash: level[sibling_idx].clone(),
                    is_left: sibling_idx < idx,
                });
            } else {
                // Odd leaf duplicated on right
                proof_path.push(MerkleProofNode {
                    hash: level[idx].clone(),
                    is_left: false,
                });
            }
            idx /= 2;
        }

        // Sign Merkle Root with Post-Quantum ML-DSA-65 Signature
        let kp = crate::pqc::PqcEngine::dilithium_generate_keypair();
        let sig = crate::pqc::PqcEngine::dilithium_sign_worm_log(&root_hash, &kp.secret_key_hex);

        Some(MerkleInclusionProof {
            leaf_index,
            total_leaves: self.leaves.len(),
            leaf_hash,
            root_hash,
            proof_path,
            quantum_root_signature: sig.signature_hex,
            quantum_public_key: sig.public_key_hex,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn verify_proof(proof: &MerkleInclusionProof) -> bool {
        let mut current_hash = proof.leaf_hash.clone();

        for node in &proof.proof_path {
            current_hash = if node.is_left {
                Self::combine_hashes(&node.hash, &current_hash)
            } else {
                Self::combine_hashes(&current_hash, &node.hash)
            };
        }

        if current_hash != proof.root_hash {
            return false;
        }

        // Verify quantum ML-DSA signature over Merkle root
        crate::pqc::PqcEngine::dilithium_verify_worm_log(
            &proof.root_hash,
            &proof.quantum_root_signature,
            &proof.quantum_public_key,
        )
    }

    fn hash_leaf(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"LEAF_PREFIX:");
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn combine_hashes(left: &str, right: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"NODE_PREFIX:");
        hasher.update(left.as_bytes());
        hasher.update(right.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn build_tree_levels(leaves: &[String]) -> Vec<Vec<String>> {
        let mut levels = Vec::new();
        let mut current_level = leaves.to_vec();
        levels.push(current_level.clone());

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    next_level.push(Self::combine_hashes(&chunk[0], &chunk[1]));
                } else {
                    next_level.push(Self::combine_hashes(&chunk[0], &chunk[0]));
                }
            }
            levels.push(next_level.clone());
            current_level = next_level;
        }

        levels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_inclusion_proof_verification() {
        let entries = vec![
            WormAuditEntry::new(1, "192.168.1.1".into(), "SQLi".into(), "QUARANTINE".into(), "0000".into()),
            WormAuditEntry::new(2, "192.168.1.2".into(), "RCE".into(), "BLOCK".into(), "1111".into()),
            WormAuditEntry::new(3, "192.168.1.3".into(), "PromptInj".into(), "QUARANTINE".into(), "2222".into()),
            WormAuditEntry::new(4, "192.168.1.4".into(), "APT".into(), "BLOCK".into(), "3333".into()),
            WormAuditEntry::new(5, "192.168.1.5".into(), "Rootkit".into(), "QUARANTINE".into(), "4444".into()),
        ];

        let tree = MerkleWormTree::new(&entries);
        assert!(!tree.root_hash().is_empty());

        for i in 0..entries.len() {
            let proof = tree.generate_inclusion_proof(i).expect("Should generate proof");
            assert_eq!(proof.leaf_index, i);
            assert!(MerkleWormTree::verify_proof(&proof), "Proof should verify for index {}", i);
        }
    }
}
